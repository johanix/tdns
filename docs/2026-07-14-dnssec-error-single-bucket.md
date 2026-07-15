# `DnssecError` is a single bucket: cross-owner clobber, stuck errors, and a self-block

**Date:** 2026-07-14
**Branch context:** analysis of `feature/zone-snapshot-correctness` (the running
tdns-auth tree). Applies equally to `main` — this is pre-existing structural
debt, not snapshot-specific.
**Status:** design only — **no code written**. Implementation deferred until the
snapshot branch merges (see *Deferral & branch strategy*). Read-only
investigation.

This doc grew out of the `falcon.pq.axfr.net` "dns: bad private key" diagnosis
(a FALCON1024 codepoint renumber orphaned the stored KSK). The operational fix
there was a key regen. But that investigation surfaced a deeper, separate
problem: **when a zone silently fails to sign, the operator gets no signal** —
`tdns-cli auth zone list` reports the zone as healthy while it serves unsigned.
Wiring a `zd.SetError()` into the signing-failure path looks like a one-liner,
but it isn't, because of how the `DnssecError` category is structured today.

---

## TL;DR

`DnssecError` is one flat entry in the per-zone error registry, but it is
**written by three unrelated concerns** and **cleared unconditionally by one of
them**:

1. **Policy resolution** — missing/unusable DNSSEC policy (`SetError`, never
   cleared).
2. **Sig-validity floor** — `UpdateSigValidityFloor()` (`SetError` on violation,
   `ClearError` when the floor is fine).
3. **Signing execution** (proposed, not yet wired) — the zone can't actually
   sign (bad key, keystore/codepoint mismatch).

Because they share one bucket:

- **(P1) Clobber.** `UpdateSigValidityFloor()` calls `ClearError(DnssecError)`
  whenever *its* floor check passes — erasing an unrelated policy or signing
  error. parseconfig runs the floor check on every parse pass, right after
  signing setup, so on reload a signing error would be cleared the instant it's
  set.
- **(P2) Stuck error.** The policy-missing `DnssecError` is **never cleared** by
  anyone (there is no `ClearError(DnssecError)` on the "policy became usable"
  path). A zone that recovers keeps showing the error until UpdateSigValidityFloor
  happens to run and blanket-clears it — i.e. it's cleared by accident, by the
  wrong owner.
- **(P3) Self-block.** `SignZone`/`ResignZone` refuse to run if
  `HasError(DnssecError)`. So a signing-execution error, once set, would block
  the *next* signing attempt — including the operator's fix. The only thing that
  clears it is the same floor check from (P1). Circular.

The fix is to give each concern an independent lifecycle. This doc lays out the
alternatives and recommends one, but **defers the implementation**.

---

## Background: the zone error registry today

`ZoneData` carries a small error registry (`v2/enums.go`):

```go
type ZoneError struct { Type ErrorType; Msg string }

// zd.Errors is keyed by ErrorType — at most ONE entry per category.
func (zd *ZoneData) setErrorLocked(errtype ErrorType, errmsg string, ...) {
    zd.Errors[errtype] = ZoneError{Type: errtype, Msg: ...}
    zd.recomputeDerivedErrorFieldsLocked() // -> zd.Error, zd.ErrorType, zd.ErrorMsg
    Zones.Set(zd.ZoneName, zd)
}
```

The `ErrorType` enum (`v2/enums.go:248`) has: `ConfigError`, `RefreshError`,
`AgentError`, **`DnssecError`**, plus warnings (`DnssecPolicyWarning`,
`ConfigWarning`, rollover categories, …).

Classification is by slice + helper, so **call sites don't grow** when the set
of categories changes:

- `serviceImpactingErrors = {ConfigError, AgentError, DnssecError}`
  (`enums.go:348`) → `HasServiceImpactingError()`; the query/NOTIFY/UPDATE
  handlers `SERVFAIL` when true.
- CLI already renders it: `ListZones` collapses a service-impacting row to
  `ERROR` (`v2/cli/zone_cmds.go:636`); `VerboseListZone` prints
  `State: ERROR ErrorType: DnssecError ErrorMsg: …` (`:689`).

So the **surfacing chain is complete** — an unsigned/broken zone would render as
`ERROR` the moment a `DnssecError` is set. The problem is purely that the
signing-failure path never sets one, and that the `DnssecError` bucket is
overloaded so we can't just add a set/clear without collateral damage.

### Who writes `DnssecError` today

| Concern | Site | Sets? | Clears? |
|---|---|---|---|
| Policy unusable | `parseconfig.go:765`, `refreshengine.go:237`, `:614` | yes | **never** |
| Sig-validity floor | `UpdateSigValidityFloor()` (`ksk_rollover_validation.go` ~448/497) | on violation | **on any pass — unconditionally** |
| Signing execution | — (proposed) | — | — |

### Where signing failures go today (nowhere)

The falcon failure is logged three times and recorded **nowhere**:

- `SignZone` → logs, returns err (`sign.go:766`)
- `SetupZoneSigning` → logs "SignZone failed", returns err (`zone_utils.go:1104`)
- the `OnFirstLoad` closure → logs "SetupZoneSigning failed", **returns void —
  error dropped** (`parseconfig.go:960-969`)

---

## The core defect in detail

### (P1) Cross-owner clobber

`UpdateSigValidityFloor()` ends with, in effect:

```go
if len(hardMsgs) == 0 {
    clearErr(DnssecError)          // <-- clears the WHOLE category
} else {
    setErr(DnssecError, "sig-validity floor: %s", ...)
}
```

It treats `DnssecError` as *its* private flag. But parseconfig invokes it on
**every parse pass**, immediately after registering/executing signing setup
(`parseconfig.go:974-977`). So the reload ordering is:

```
SetupZoneSigning(...)          // (proposed) would setErr(DnssecError, "signing failed")
UpdateSigValidityFloor(...)    // floor is fine -> clearErr(DnssecError) -> ERROR ERASED
```

Any naive `SetError(DnssecError, "signing failed")` is wiped out on the next
reload — and at runtime the floor check's `maxObservedTTL == 0` early path clears
it outright.

### (P2) Stuck policy error

There is **no** `ClearError(DnssecError)` on the policy-resolution success path.
Grep confirms the only clears live in `UpdateSigValidityFloor`. So a zone whose
policy was fixed on reload keeps its `DnssecError` until — again — the floor
check happens to run and blanket-clears it. The error's lifecycle is owned by
the *wrong* concern.

### (P3) Self-block / precondition-vs-outcome

`SignZone` and `ResignZone` both start with (`sign.go:758`, `:584`):

```go
if zd.HasError(DnssecError) {
    return 0, fmt.Errorf("...has DNSSEC error: %s", zd.ErrorMsg)
}
```

This guard conflates two fundamentally different kinds of DNSSEC error:

- **Precondition errors** — *don't even attempt to sign.* Missing policy; a
  sig-validity floor that would produce dangerous RRSIG lifetimes. Gating
  `SignZone` entry on these is **correct**.
- **Outcome errors** — *an attempt just failed.* Bad key material, keystore /
  codepoint mismatch. These are the **result** of signing, not a precondition.
  Gating the next attempt on them is **wrong**: the error you set to *report* the
  failure prevents the operator's fix from ever running (deadlock, since the only
  clearer is the floor check from P1).

So the guard was never really "any `DnssecError`" — it is "any *precondition*
`DnssecError`." Expressing that requires distinguishing the two, which is the
crux of every option below.

---

## Requirements for a correct design

1. A signing-execution failure must be **recorded on the zone** (so `zone list` /
   `zone status` shows `ERROR`), not just logged.
2. Independent set/clear per concern: the floor check must not clear a signing
   or policy error, and vice versa. (Fixes P1.)
3. Each concern clears its **own** error on its **own** recovery. (Fixes P2.)
4. The `SignZone`/`ResignZone` entry guard must gate on **preconditions only**,
   so an outcome error doesn't self-block recovery. (Fixes P3.)
5. Serving is **fail-closed**: a zone that is supposed to be signed but can't sign
   should `SERVFAIL`, not serve unsigned. (Decided — see below.)
6. Don't let the classifier logic sprawl into `||`-chains at call sites.

---

## Design alternatives

### Option A — flat new categories

Add `DnssecSigningError`, `DnssecValidityFloorError`, `DnssecPolicyError` as
peer `ErrorType`s; retire the umbrella `DnssecError`.

- **Pros:** No change to the registry shape — the existing
  `map[ErrorType]ZoneError` already gives each its own slot, so independent
  set/clear falls out for free (fixes P1/P2). Classification stays slice-based
  (`serviceImpactingErrors` gains the three; a new `signingPreconditionErrors`
  slice backs the guard) so **call sites don't grow** — P3's guard becomes
  `HasSigningPreconditionError()`, one call.
- **Cons:** Enum proliferation; three names where one concept ("this zone's
  DNSSEC is unhealthy") lived. Report-order (`errorTypeReportOrder`), the
  string map, and every classification slice must list all three. If more DNSSEC
  sub-failures appear (DS-push, keygen, rollover-precondition) the enum keeps
  growing. Loses the natural "all DNSSEC problems" category for serving
  semantics (must be reconstructed as a slice).

### Option B — subtype under `DnssecError`

Keep the umbrella `DnssecError` category; add a `DnssecErrorSubtype`
(`SubPolicy`, `SubValidityFloor`, `SubSigning`). Multiple subtypes can coexist
and are cleared independently.

- **Pros:** One category for serving semantics — `HasServiceImpactingError()`
  stays "any DNSSEC subtype → fail closed" with no change (satisfies req 5
  trivially). Independent set/clear per subtype fixes P1/P2. The guard becomes
  `HasBlockingDnssecPrecondition()` = subtype ∈ {policy, validityfloor} — one
  call site, backed by a subtype set, so no `||` sprawl (req 6). Matches the
  operator's mental model ("DnssecError, subtype signing: bad private key").
  Extensible — new sub-failures are new subtype constants, not new categories.
- **Cons:** The registry key must become `(Type, Subtype)` so two `DnssecError`
  subtypes can coexist; today it's keyed by `Type` alone. That's an API change to
  `SetError`/`ClearError`/`HasError`. Two ways to absorb it:
  - **B1 (uniform):** change the key to `(Type, Subtype)` everywhere.
    Future-proof (subtypes will recur — per-scheme `RolloverParentBlocker`,
    per-primary `ConfigWarning`), but touches ~79 call sites (60 `SetError`, 12
    `ClearError`, 7 `HasError`), almost all mechanically passing `SubNone`.
  - **B2 (minimal):** leave the flat `map[ErrorType]ZoneError` for the other 11
    categories; give `DnssecError` a subtype dimension only (nested map, or a
    composite `DnssecError:<subtype>` key handled inside the DNSSEC paths).
    Touches only the ~5 existing `DnssecError` sites + the new signing site.
    Slightly asymmetric, but contained and low-risk.

### Option C — keep the single bucket, make the floor clear surgical

Leave `DnssecError` flat; change `UpdateSigValidityFloor()` to clear the error
**only if it owns it** (e.g. tag the stored `Msg`/a source field and clear only
when `source == validityfloor`).

- **Pros:** Smallest diff; no enum or key change.
- **Cons:** A hack — encodes ownership in the message string or a side field
  rather than the type system. Still can't represent a floor error **and** a
  signing error at once (they'd overwrite in the single slot), so it fails req 2
  for coexistence. Doesn't address P3 (guard still gates on the whole bucket).
  Effectively a worse B2 with the same touch points. **Not recommended.**

### Cross-cutting (all options): the precondition/outcome guard

Independent of A/B/C, req 4 needs the `SignZone`/`ResignZone` entry guard changed
from "any `DnssecError`" to "precondition only." Under A that's a
`signingPreconditionErrors` slice; under B a subtype predicate. Without this,
recovery self-blocks (P3) no matter how the error is categorised.

---

## Serving policy (decided): fail-closed

A zone configured for online/inline signing that cannot sign should return
`SERVFAIL`, not serve unsigned data. `DnssecError` is already in
`serviceImpactingErrors`, so any option that records the signing failure under
`DnssecError` (B) — or lists the new signing category as service-impacting (A) —
gets this for free. Concretely, `falcon.pq.axfr.net` would `SERVFAIL` until it
can sign again, instead of serving an unsigned SOA with zero DNSKEY/RRSIG.

Rationale: a resolver holding the zone's DS `SERVFAIL`s anyway once the RRSIGs
are missing; serving unsigned NOERROR to non-validators is actively misleading
about the zone's health. Fail-closed also makes the outage loud, which is the
whole point of this exercise.

---

## Recommendation

**Option B, variant B2 (minimal-footprint subtype under `DnssecError`)**, plus
the precondition/outcome guard split, plus fail-closed serving.

- B keeps one operator-facing category with clean serving semantics and models
  "several DNSSEC sub-failures, cleared independently" directly — which is
  exactly the shape of this problem and the next ones (DS-push, keygen).
- B2 over B1 because this lands on a must-not-destabilise tree; the surgical
  version fixes this bug **and** the two latent ones (P1 clobber, P2 stuck
  policy error) with ~6 touched sites instead of ~79. Generalise to B1 later if
  a second category genuinely grows subtypes.

Sketch of the end state (illustrative, not final):

```go
// set at the SignZone failure return; covers load, reload, resigner uniformly
zd.SetDnssecError(SubSigning, "bad private key: %v", err)
// cleared at the SignZone success return
zd.ClearDnssecError(SubSigning)

// entry guard: preconditions only, so an outcome error doesn't self-block
if zd.HasBlockingDnssecPrecondition() { return ... }   // {SubPolicy, SubValidityFloor}

// floor check clears only its own subtype
clearErr(DnssecError, SubValidityFloor)

// policy-usable branch finally clears its own subtype (fixes P2)
zd.ClearDnssecError(SubPolicy)
```

Open sub-question to settle at implementation time: whether the signing set/clear
belongs in `SignZone` (covers whole-zone re-sign) alone, or also in the
per-query RRset signing path — needs a check of `SignRRset` vs `SignZone` call
sites so we don't set the error at the wrong granularity or thrash it per query.

---

## Deferral & branch strategy

**Implementation is deferred until the snapshot branch merges.** The snapshot
branch already reworked `SetError` (locked variants `setErrorLocked` /
`clearErrorLocked`, added for the SignZone self-deadlock fix). Doing a competing
`SetError`/subtype redesign off `main`-now would collide badly with that rework.

The pivotal question, to answer post-merge: does snapshot's already-reworked
error API suffice to layer subtypes on cleanly (→ do it on the snapshot branch /
post-merge main), or does the subtype key change warrant its own pass (→
sequence it after)? Either way, do **not** open a parallel `SetError` redesign
on `main` before the merge.

A small, low-coupling **Part 1** can proceed independently of this doc's
redesign — and, revised 2026-07-14, **entirely tdns-side, with NO fork change**
(the maintainer does not want to diverge the `johanix/dns` fork further):

- The failure the operator actually hit (`falcon` "dns: bad private key") comes
  from tdns's own decode call `rr.NewPrivateKey(privkey)` in
  `v2/readkey.go:285` (`PrepareKeyCache`), which fails *first* with a vague
  error. tdns already HAS the right check — the algorithm-mismatch guard at
  `v2/keystore.go:894` (`pkc.Algorithm != alg` → "algorithm mismatch: stored=%d
  parsed=%d") — but it runs *after* `PrepareKeyCache` has already returned the
  vague error, so it never fires.
- **Fix:** run the algorithm-consistency check *before* the decode (compare the
  stored DNSKEY's algorithm against the expected one up front), so tdns emits a
  clear "stored key is algorithm X but the zone wants Y — codepoint renumber;
  regenerate" itself. Uses the *current* `SetError`; no subtype work needed; no
  fork change. The fork's `PrivateKeyString` "" swallow is a harmless latent
  wart we can push upstream to miek later — we simply stop depending on it.

So the next codepoint renumber can't fail silently even before the full
propagation redesign lands, and it costs zero fork divergence.

See also: `docs/2026-07-13-unsigned-publish-window.md`, the falcon
codepoint-renumber diagnosis, and the SignZone self-deadlock fix (why
`setErrorLocked` exists).
