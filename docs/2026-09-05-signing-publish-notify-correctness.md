# Signing, publishing and NOTIFY — one version, one signing pass, one NOTIFY

**Status:** **frozen — implement from here.** §3 is the specification, §9 is the patch list
against the parked branch. Convergence assessed 2026-09-05
(`reviews/2026-09-05-tdns-signing-and-refresh-convergence.md`): the shape has not moved since
review 1, and further review of the shape is how churn continues. Re-open this only if the
punch list cannot be applied as written, or to change a rule in §1 or the order in §6.
**Base:** `main` @ `d833c683`, re-verified against `2a211c4a`. `v2/` tree only.
**Reviews:** `reviews/2026-09-05-tdns-signing-publish-notify-correctness-{review,rereview,rereview-2}.md`
— all three *approve with should-fix*; every finding is folded into §3. §0 records what each
round changed.
**Issue:** [#512](https://github.com/johanix/tdns/issues/512) — the C1 defect. Text in §8.
**Companion:** `2026-09-05-refresh-engine-redesign-364-502.md` — the refresh-engine
concurrency work, separately reviewed. The commit order across both documents is §6.

---

## 0. Review history

What each round changed, for anyone diffing this against an earlier copy. The design in §3
is stated as the target; nothing below is needed to implement it.

**Review 1.** First load must not be refused when the policy has not bound (option A;
binding keys earlier, option B, rejected because it reopens the PR-2 "no bind before Ready"
decision). The NOTIFY predicate must be `ZoneTransferOut`'s admission test verbatim rather
than a paraphrase. The extraction must not generate the NSEC chain. An inbound IXFR must not
trigger a full-zone sign — promoted from a note to the design, and the change with the widest
effect. Steady-state signing failure is `DnssecError`, service-impacting, with the last good
version left published.

**Review 2.** The first-load skip predicate is *"keys cannot be resolved"*, not *"the policy
pointer is nil"* — the latter skips signing on every **restart**, and nothing downstream
recovers it once C5 removes `SetupZoneSigning`. Nothing flips `Ready` after the policy-apply
publish, so gating the existing flips would leave a correctly signed zone permanently
invisible; `publishWorkingSetLocked` becomes the writer. The owner filter belongs in
`signWorkingSetLocked`'s signature from the start.

**Convergence assessment.** No change of shape; one leftover of the same root cause found in
the tree and added as §9 item 9 — the SOA re-sign, the NSEC restitch and the ZONEMD gate carry
the same retired `DnssecPolicy == nil` test that C1 stopped using. Both documents marked
frozen.

**Review 3.** The `Ready` flip cannot reuse the NOTIFY predicate, which tests `Ready` first
and is therefore circular — every zone would stay not Ready, silently. Split into a content
half and a full test. `InstallInitialSnapshot` must notify only when *it* flipped Ready, or a
restart emits two NOTIFYs for one serial. Only the deferred-bind error is skippable; a KeyDB
fault is a real fault, and matching it needs a sentinel the code does not yet have.

---

## 1. The rules this is built on

Settled with Johan, 2026-09-05:

1. **NOTIFY is sent only as the final step of cutting a new snapshot** — including first
   load. Never two NOTIFYs for the same SOA serial.
2. **A given version of a zone is signed exactly once.**
3. **NOTIFY does not belong in the refresh-engine path at all**, other than at the
   snapshot-cutting end of it.
4. **`force` is a tool for special circumstances, not for steady state.** If forced
   re-signing is needed in normal operation, the signing semantics are wrong somewhere.

And the constraint that bounds the work: the snapshot machinery itself — atomic swap,
generation guard, durable-before-visible ordering, the IXFR chain — is believed correct and is
**not** reopened. Everything below changes what the working set *contains* at the moment of
the swap, and who calls publish. It does not change how a swap happens.

---

## 2. What is wrong today

### 2.1 A refresh publishes a version that cannot validate (the defect)

`applyRefreshReplacementLocked` stages freshly transferred data and publishes it
(`zone_mutation.go:725`). For a zone that signs its own content but receives it unsigned — in
practice an **inline-signing secondary** — that snapshot contains:

| | at that snapshot |
|---|---|
| SOA | **signed** — `resignWorkingSetSOAIfSigned` (`zone_mutation.go:227`) runs on every publish |
| NSEC chain | **signed** — `restitchNsecLocked` resolves `dak` and signs (`nsec_restitch.go:118`) |
| ZONEMD | **signed** — `updateZonemdLocked` |
| every transferred RRset | **unsigned** |

The zone is already `Ready` in steady state, so that version is served:

- queries return unsigned RRsets **alongside a signed NSEC chain** — the worst combination
  available to a validator;
- `ZoneTransferOut`'s fail-closed guard inspects only the apex SOA's RRSIG
  (`dnsutils.go:490`), which is signed, so a downstream can AXFR it.

The window lasts until `SetupZoneSigning` → `SignZone` publishes again — the duration of a
full signing pass, seconds and up, considerably more with PQ algorithms. It is not a race; it
is a state the server sits in after every changed refresh.

Not affected: the DDNS path signs each RRset as it stages it (`zone_updater.go:1156` then
`:1161`) and publishes once. Nor a primary reloading an already-signed file. Nor an unsigned
zone.

### 2.2 Signing is a second publish

`SignZone` ends with `zd.publishLocked(...)` (`sign.go:969`), and `publishLocked` is
`publishWorkingSetLocked(gen, true)` (`zone_mutation.go:346`) — bumpSerial *true*, with
`nextOutboundSerial` returning `CurrentSerial + 1` (`zone_utils.go:1576`). Every signing pass
therefore publishes a new serial and, at `zone_mutation.go:601`, sends a NOTIFY.

One upstream change to an inline-signing secondary:

| serial | published by | NOTIFY |
|---|---|---|
| S | refresh (`applyRefreshReplacementLocked`, bumpSerial=false) | yes |
| S+1 | `SetupZoneSigning` → `SignZone` → `publishLocked` | yes |
| S+2 | `ResignerEngine` → `resignNow` → `SignZone(force=true)` → `publishLocked` | yes |
| S+2 | the refresh engine's own tail call (`:912` / `:1237`) | yes |

Three serials and four NOTIFYs for one upstream change; a downstream can transfer three times.
Rules 1 and 2, both broken.

First load has the same shape: publish (pre-Ready) → `InstallInitialSnapshot` → policy sync,
which on the not-yet-backfillable path calls `applyZonePolicyTransactional` →
`SignZone(kdb, true)` → publish + NOTIFY (`zone_policy_apply.go:215`) → replay →
`drainAndRunOnFirstLoad` → `SetupZoneSigning` → publish + NOTIFY.

### 2.3 NOTIFY is emitted from the refresh engine as well as from publish

`NotifyDownstreams` is the last statement of `publishWorkingSetLocked`
(`zone_mutation.go:601`) — NOTIFY already *is* a step of cutting a snapshot, as rule 1 wants.
The refresh engine then calls it again three times over: `refreshengine.go:240` (inside
`initialLoadZone`), `:1237` (ticker tail) and `:912` (async tail, via `NotifyQ`).

Two further problems with the publish-path call itself:

- It runs **under `zd.mu`** — every caller holds it — and `NotifyDownstreams` uses
  `dns.Exchange` (`zone_utils.go:1382`), not `ExchangeContext`. So two seconds per
  unreachable downstream is spent holding the zone's own lock, blocking every reader of that
  zone, with no deadline or cancellation able to reach it.
- It fires for the pre-Ready first-load publish, the one publish that must not notify: a
  downstream acting on it is refused (`dnsutils.go:457`).

### 2.4 `force` is doing steady-state work, with the wrong tool

`SetupZoneSigning` signs inline (`zone_utils.go:2006`) **and** enqueues to `ResignQ` (`:2018`);
`ResignerEngine` then calls `resignNow` → `SignZone(kdb, true)` (`resigner.go:82`). `force` is
not a hint: `shouldSign = force || NeedsResigning(...)` (`sign.go:196`), so the second pass
re-signs every RRset the first pass just signed.

Two defects behind that:

- **The queue has no verb.** `ResignQ` carries a bare `*ZoneData`. "Data changed" and "key
  state changed" arrive on the same channel and the resigner cannot tell them apart, so it
  forces both.
- **`force` is the wrong tool for the case it was written for.** `resignNow`'s comment
  justifies force by the post-rollover case — RRSIGs valid but made by the wrong key. But
  `SignZone` is *additive*: `SignRRset`'s own comment says RRSIGs by no-longer-active keys are
  left in place, and that replacing them belongs to `ResignZone` — which exists
  (`sign.go:617`) for exactly that, stripping and re-signing per RRset so readers never
  observe an unsigned intermediate. The forced pass adds the right signatures and leaves the
  wrong ones in place.

---

## 3. Design

### 3.1 C1 — sign replacement content before the swap

The rule is already established inside publish, for every *derived* record. From
`restitchNsecLocked`'s justification (`zone_mutation.go:432`):

> *"The chain must describe the snapshot about to be published, so it is repaired HERE —
> before the delta is computed and before the swap... Doing it in a later pass would publish a
> second serial and leave a window in which the served chain contradicts the served zone."*

Authored content that arrived unsigned is the one input that never got the same treatment.

**The staged scope is a set, not a boolean.** An inbound IXFR must not trigger a full-zone
pass: `ixfrTouchedOwners` and `materializeForIxfr` (`ixfr_in.go:208`, `:254`) deep-copy only
the owners a delta reaches and share every other owner with the published snapshot, precisely
so a small delta does not cost O(zone).

```go
// wsNeedsFullSign: every authored owner needs signing -- an AXFR, or a file
// reload of a zone that signs its own content. Nothing we hold was signed by us.
wsNeedsFullSign bool

// wsSignOwners: only these owners need signing -- an inbound IXFR, where the
// delta names what changed and materializeForIxfr already deep-copied exactly
// that set. nil, with wsNeedsFullSign false, means there is nothing to sign.
wsSignOwners map[string]bool
```

`applyRefreshReplacementLocked` stages one or the other:

| replacement | staged |
|---|---|
| AXFR, or file reload, of a zone that signs its own content | `wsNeedsFullSign = true` |
| inbound IXFR into such a zone (`new_zd.ixfrDerived`) | `wsSignOwners = <touched>` |
| a zone that does not sign its own content | neither |

`ixfrTouchedOwners` already computes the set and already includes the apex unconditionally
(the bracket SOAs delimit the sequences rather than appearing inside them, so nothing else
marks the name `replaceApexSOA` rewrites). Carry it on the transfer scratch zone beside
`ixfrDerived`.

**Why a full pass on an IXFR is wrong is worth stating precisely, because the obvious reading
is not the cost.** It is not 100k signatures: `SignRRset` short-circuits on `NeedsResigning`
when `force` is false, and an IXFR carries untouched owners over with the valid RRSIGs they
already had. The cost is the walk — the pass stages every RRset it visits, signed or not, and
`stageRRsetLocked` goes through `cloneOwner`, which allocates a fresh `OwnerData` and
`RRTypeStore` per owner and copies each RRset in. A two-record delta into a 100k-RRset zone
would re-materialise the whole zone, which is the work `materializeForIxfr` shares owners to
avoid. Anyone who later measures RRSIGs written, finds the count small and concludes the full
pass was harmless is measuring the wrong thing.

**Scoping the pass does not make an IXFR publish O(delta).** `restitchNsecLocked` walks every
working owner (`nsec_restitch.go:105`) and a ZONEMD digest covers the whole zone by
construction. Both run on every publish today, so neither is a regression here — but the
scoping must not be sold as end-to-end cheapness. Making the restitch incremental is a
separate and harder question: the NSEC chain links neighbours, so a delta changes chain
entries for names it never mentions.

**Where it runs.** In `publishWorkingSetLocked`, in this slot:

```
  resignWorkingSetSOAIfSigned()          // existing
+ sign the staged scope                  // NEW: authored data
  ensureZonemdPresenceLocked()           // existing
  restitchNsecLocked()                   // existing -- signs the NSECs it writes
  updateZonemdLocked()                   // existing -- signs the ZONEMD
  ... persist, chain, swap, Ready, notify
```

Authored data first, then the derived records, each still signed by the step that generates
it. Nothing moves; one step is inserted.

**Do not widen the pass beyond the staged scope.** For an IXFR the untouched owners share
their `RRTypeStore` with the snapshot being served. `stageRRsetLocked` clones an owner before
writing — `cloneOwner`'s comment says why ("applyClampToRRset assigns Header().Ttl in place,
so a shared RR would have its TTL changed underneath a snapshot that is being served right
now") — but the clone happens *inside* staging, after `SignRRset` has run on the RRset.
Scoping to the touched owners avoids the question, because those are the ones
`materializeForIxfr` deep-copied.

### 3.2 The extraction, the lock, and the keys

`SignZone` cannot be called from inside publish: it takes `zd.mu` itself (`sign.go:871`) and
`publishWorkingSetLocked` already holds it, and its unlocked prologue resolves keys with
`EnsureActiveDnssecKeys(kdb, false)` (`sign.go:836`), which under the lock self-deadlocks via
`PublishDnskeyRRs`. The tree has paid for that once (`6e090a9`), and both
`resignWorkingSetSOAIfSigned` (`zone_mutation.go:264`) and `restitchNsecLocked`
(`nsec_restitch.go:118`) already pre-resolve `dak` with `zdLocked=true` for the same reason.

```go
// signWorkingSetLocked signs the staged working set with keys and clamp the
// CALLER resolved. Caller MUST hold zd.mu; dak MUST be non-nil.
//
// Does not lock, does not resolve keys, does not publish -- those are the three
// steps that re-enter zone locking. A nil dak would send SignRRset into its own
// EnsureActiveDnssecKeys call and deadlock against the caller's lock, so it is
// refused rather than tolerated.
//
// signNsec: sign each owner's NSEC property. True for SignZone; FALSE for the
// publish path, where restitchNsecLocked regenerates and signs the chain a few
// lines later.
// owners: nil signs every owner; otherwise only these (§3.1).
func (zd *ZoneData) signWorkingSetLocked(
        dak *DnssecKeys, clamp *ClampParams, force, signNsec bool, owners map[string]bool,
) (newRRSIGs int, maxObservedTTL uint32, err error)
```

Contents: DNSKEY publication (`publishDnskeyRRsLocked` — a zone transferred from an upstream
that does not sign carries no DNSKEY RRset, and both callers need it), the owner walk, the
delegation and glue rules, the ZONEMD skip, and the per-owner NSEC property when `signNsec`.

`GenerateNsecChainWithDak` stays in `SignZone`, outside the extraction, for the same reason
`signNsec` exists.

Callers:

- `SignZone`: resolve `dak` + `clamp` unlocked → `zd.mu.Lock()` → `GenerateNsecChainWithDak` →
  `signWorkingSetLocked(..., signNsec: true, owners: nil)` → `publishLocked` → unlock.
- `publishWorkingSetLocked`, already locked: resolve with `EnsureActiveDnssecKeys(kdb, true)`
  and `ClampParamsForZone`, then `signWorkingSetLocked(..., signNsec: false, owners: <staged>)`.

### 3.3 Failure, first load, and who sets `Ready`

**Steady state — an already-signed zone whose re-sign fails.** Do not swap; keep serving the
previous snapshot; set **`DnssecError`**.

`DnssecError` is service-impacting (`enums.go:445`), so the zone renders as an ERROR and the
query, NOTIFY and UPDATE handlers refuse. That is intended: a signed zone whose signing is
broken is broken, and should say so rather than quietly serving an ageing snapshot while the
operator believes all is well. The last good version stays published — refusing the swap is
what guarantees that. `publishWorkingSetLocked` already refuses in three cases (apex-less
working set, unrepairable NSEC chain, delta-persist failure), each keeping the previous
snapshot, so this is the established shape.

**First load — keys cannot be resolved yet.** Publish unsigned, stay **not Ready**, set no
error.

The predicate is *"the keys cannot be resolved"*, **not** *"`zd.DnssecPolicy` is nil"*. Those
differ exactly on a restart. `EnsureActiveDnssecKeys` raises its deferred-bind error only when
keys are *missing*:

```go
if (len(dak.KSKs) == 0 || !hasRealZSK) && zd.DnssecPolicy == nil {   // sign.go:520
```

A zone that has run before has its keys, so on a restart that call returns them with a nil
policy — and the policy is nil at **every process-start publish**, because binding is
post-Ready. Skipping on the pointer would skip signing on every restart of every
inline-signing secondary, and nothing downstream recovers it: the policy sync's Branch 1
rebinds without `SignZone` (`zone_policy_apply.go:459`), and Branch 0's backfill needs an apex
SOA RRSIG that was never written, because `resignWorkingSetSOAIfSigned` carries the same
condition. `SetupZoneSigning` papers over it today, and C5 deletes exactly that.

So resolve first, decide second:

```go
dak, err := zd.EnsureActiveDnssecKeys(zd.KeyDB, true)
switch {
case errors.Is(err, ErrDnssecPolicyNotBound):
    // Ordinary first load, not a fault: publish unsigned, stay not Ready, and
    // let the policy apply produce the first servable version.
    return nil
case err != nil:
    return err          // a real fault -- refuse the swap, DnssecError
}
// Keys exist: sign, bound policy or not. A nil policy means no TTL clamp, not
// no signing.
```

`ErrDnssecPolicyNotBound` does not exist yet — `sign.go:521` returns a bare `fmt.Errorf`, so
there is nothing to match on. Add the sentinel and wrap it there. Without it, a KeyDB failure
on first load is mistaken for a deferred policy bind and published unsigned.

**Do not add "and the zone has an NSEC chain" as a third `Ready` predicate.** It looks like
the belt-and-braces answer to the paragraph above and it deadlocks a restart: the policy
sync's Branch 1 rebinds without re-signing, so nothing would ever build the chain the gate is
waiting for, and the zone would stay not Ready forever. Resolve the keys once and let the
restitch run; that is what produces the chain.

Option B — mint or bind keys before the first refresh publish so C1 can sign it — is rejected
rather than left open: it reopens the PR-2 "no bind before Ready" decision, which exists so a
restart cannot hide applied≠intent.

**`Ready` is what makes the unsigned first snapshot safe.** `GetOwner` gates queries on it
(`zone_utils.go:1236`) and `ZoneTransferOut` gates transfers on it, so a not-Ready zone is
invisible. Today `Ready` is set unconditionally in `InstallInitialSnapshot` (both branches,
`:976` and `:995`) and in `applyRefreshReplacementLocked` (`:834`, gated `!firstLoad`), and a
signing zone must not become Ready on a snapshot whose apex SOA carries no RRSIG.

**And something has to set it.** `publishWorkingSetLocked` never sets `Ready`, nor does
`SignZone` → `publishLocked`, and `completeFirstZonePolicyAndLoad` calls
`InstallInitialSnapshot` *before* the policy apply and never again. Gate the existing sites
without adding a writer and a correctly signed zone becomes permanently invisible. So
`publishWorkingSetLocked` sets `Ready` when the snapshot it has just stored qualifies.

**Two predicates, one shared half.** The NOTIFY test cannot be reused for the flip: it tests
`Ready` first, so with `Ready` false it returns false for every zone, signed or not — nothing
would ever be flipped and nothing would ever serve. Silent, and total.

| use | test |
|---|---|
| may this snapshot become `Ready`? | **content half only** — `!signsItsOwnContent()`, or the apex SOA carries an RRSIG |
| may we NOTIFY about it? | `Ready` **and** the content half, evaluated *after* the flip |

**One key resolution per publish, consumed by every step that needs it.** The nil-policy
predicate is not only C1's: `resignWorkingSetSOAIfSigned` (`zone_mutation.go:249`),
`zoneMaintainsItsOwnChain` (`nsec_restitch.go:78`) and `zonemdSignableLocked`
(`zonemd_publish.go:109`) each test `zd.DnssecPolicy == nil` independently, and each therefore
skips on a restart for the same wrong reason. Left alone, a restart of an inline-signing
secondary would sign its authored data (C1 resolves keys), flip `Ready` because the apex SOA
now has an RRSIG, and serve **with no denial chain at all**, because the restitch skipped.
Signed positive answers, absent negative ones — the C1 defect again, at process start.

Applying "resolve keys, don't inspect the pointer" to each of them separately is the wrong
shape, and `zonemdSignableLocked`'s own comment says why: *"EnsureActiveDnssecKeys is not a
predicate — it mints a zone's first keys as a side effect"*, and that gate runs before the
restitch, where its answer decides whether the apex NSEC bitmap lists ZONEMD.

So `publishWorkingSetLocked` resolves once, at the top, and hands the result down:

```
  resolve dak + clamp once (§3.3), or ErrDnssecPolicyNotBound -> skip all four
  resignWorkingSetSOAIfSigned(dak, clamp)
  sign the staged scope     (dak, clamp)
  ensureZonemdPresenceLocked(signable = dak != nil)
  restitchNsecLocked        (dak, clamp)
  updateZonemdLocked        (dak, clamp)
```

One resolution, one predicate, no side effect in a predicate position, and no way for the four
steps to disagree about whether this publish can sign.

`publishWorkingSetLocked` therefore runs: resolve → the four signing steps → persist and
chain → store the snapshot → set `Ready` if the content half holds → notify (§3.4). A first-ever unsigned load stays not Ready and silent; a policy apply,
and a restart with keys, flip and notify in the same publish.

### 3.4 C2 — NOTIFY only about a version a downstream can take

The last statement of `publishWorkingSetLocked` becomes a gated, non-blocking hand-off.

**The gate is `ZoneTransferOut`'s admission test**, expressed as it is there rather than
paraphrased: `Ready`, and if `signsItsOwnContent()` (`ixfr_in.go:821`) then the pinned apex SOA
carries an RRSIG. Call the helper rather than inlining the option test, so the two predicates
cannot drift. Notifying about a version we would then refuse to transfer only burns the
downstream's retry budget.

**The request is built under the lock.** Zone name, serial and targets are read while `zd.mu`
is held, and `peerAddrs` copies the targets into a fresh slice, so nothing is re-read from the
live `ZoneData` afterwards. A hand-off that captured a `*ZoneData` and let the sender read
`zd.Notify` later could notify the wrong set, or nil.

**The send is non-blocking, so no network I/O runs under the lock.** A `NotifyRequest` goes to
`NotifyQ` with a `select`/`default` send; a full queue drops and counts. NOTIFY is
best-effort — a downstream that misses one refreshes on its SOA timer — and blocking a publish
on a serial consumer is how the stall gets rebuilt somewhere new.
`publishWorkingSetLocked` cannot drop a lock its callers own, and does not need to: a
non-blocking send cannot block, which is the property the old inline `dns.Exchange` loop
lacked. `NotifyQ` depth goes from 10 to 100 (`main_initfuncs.go:216`), matching `DnsNotifyQ`.

**`InstallInitialSnapshot` notifies only when that call flipped `Ready` from false to true.**
After §3.3 the refresh publish already flips and notifies on a restart, so an unconditional
emission here would be a second NOTIFY for one serial. The case that still needs it is the
backfill: the snapshot was published pre-Ready, the policy sync re-signs nothing and publishes
nothing, and without this the zone would serve a new serial no downstream is told about.

`NotifyDownstreams` — the blocking `dns.Exchange` loop — survives C2 and is deleted in **C3**,
which removes its last callers.

### 3.5 C3 — delete the refresh engine's NOTIFYs

`refreshengine.go:240`, `:912` and `:1237` go, and `NotifyDownstreams` with them. One
behaviour goes deliberately: the async tail notifies on `updated || force`, commented *"Force
typically means config reload-zones, so we want to notify even if unchanged"*. Under rule 1
that is a NOTIFY for an unchanged serial.

That removal is covered **by construction rather than by a test**: after C3 the refresh engine
emits nothing — no `NotifyQ` send, no inline exchange — and `NotifyDownstreams` no longer
exists. It still *maintains* `zd.Notify` from config, which is its job (`refreshengine.go:603`,
`:706`, `:962`) and reads it once for a debug log (`:811`); what it no longer does is act on
it. Driving a forced-but-unchanged refresh through `RefreshEngine` to count sends
would need the whole engine harness — channels, config, a live zone registry — for an
assertion the absent code already makes. The positive half (one NOTIFY per changed serial) is
tested at the publish level, which is now the only emitter.

### 3.6 C4 — give `ResignQ` a verb, and use the right tool

```go
type ResignRequest struct {
	Zd     *ZoneData
	Reason ResignReason // ResignKeyStateChanged | ResignPeriodic | ResignPolicyApplied
}
```

| reason | what the resigner does |
|---|---|
| `ResignKeyStateChanged` (rollover, key removal) | `ResignZone` — replacement, which is what the case needs |
| `ResignPeriodic` | watchlist registration only; the ticker's `SignZone(force=false)` decides when a pass is due |
| data changed | **nothing** — never enqueued; C1 signed it at publish |

A third reason, `ResignPolicyApplied`, was sketched and **not implemented**: no producer needs
it. The policy apply signs directly through `applyZonePolicyTransactional` →
`SignZone(kdb, true)` rather than going through the queue, so the constant would have had no
sender.

The channel type change makes a missed producer a compile error. The producer to convert is
`triggerResign` (rollovers, `key_state_worker`, the API), which already drops on a full queue
and keeps that behaviour, plus `SetupZoneSigning`'s enqueue (§3.7). The periodic ticker keeps
calling `SignZone(force=false)` and is **not** routed through `ResignZone`: replacement is for
a key-state change, ageing signatures are not one.

`force` then survives only where it belongs — a policy binding change, via
`applyZonePolicyTransactional` → `SignZone(kdb, true)` (`zone_policy_apply.go:215`).

**The tool swap is now pinned by test, not by argument.** `TestResignZoneRemovesSignaturesByARetiredKey`
rolls a ZSK out and asserts no signature by the retired key survives;
`TestForcedSignZoneLeavesSignaturesByARetiredKey` runs the same scenario through
`SignZone(force=true)` and asserts the stale signature **does** survive. The second test is the
one that matters: it demonstrates the additive contract rather than restating it, so "force is
stronger, surely it is safer" cannot quietly come back. It skips with an explanation rather
than failing if that contract ever changes, since at that point the resigner's choice should be
revisited rather than the test patched.

### 3.7 C5 — `SetupZoneSigning` becomes a registration

With C1 the two post-refresh call sites (`refreshengine.go:870`, `:1232`) have nothing to do
and are deleted. The three `OnFirstLoad` registrations (`parseconfig.go:1477`,
`dynamic_primary.go:430`, `refreshengine.go:1034`) still need the zone signed once after the
policy binds, but that signing is the policy path's job. What remains is watchlist
registration:

```go
func (zd *ZoneData) registerForPeriodicResign(resignq chan<- ResignRequest) error
```

No inline sign, no forced re-sign, no second publish.

Nothing signs there any more because by the time it runs something already has: a refresh
signs its content before the swap (C1), a policy apply signs when it binds, and a restart signs
at the refresh publish because the keys resolve even with the policy unbound (§3.3). What the
call was actually protecting was never the signing — it was a zone quietly falling off the
renewal list.

### 3.8 First load and restart, step by step

**First-ever load** — no keys, no policy:

| step | today | after |
|---|---|---|
| refresh publishes | unsigned data, signed SOA/NSEC/ZONEMD, **NOTIFY** | unsigned (no keys yet), **not Ready**, **no NOTIFY** |
| `InstallInitialSnapshot` | flips Ready unconditionally | flips Ready only if the content half holds; **NOTIFY** when it does |
| policy sync — apply | forced sign + publish + **NOTIFY** | forced sign + publish; this publish makes the zone servable, so Ready flips and **one NOTIFY** goes out |
| replay | may publish + **NOTIFY** | may publish + NOTIFY — a real content change |
| `OnFirstLoad` → `SetupZoneSigning` | sign + publish + **NOTIFY**, then the resigner force-signs + publish + **NOTIFY** | registration only |

**Restart** — keys present, policy nil until the sync:

| step | after |
|---|---|
| refresh publishes | **signed** (keys resolve), Ready flips, **one NOTIFY** |
| `InstallInitialSnapshot` | Ready already true — no second NOTIFY |
| policy sync — backfill or Branch 1 rebind | no publish, no NOTIFY |

Up to five NOTIFYs across three-plus serials today, down to one per version that actually
changed — and none at all until there is a version a downstream could take.

### 3.9 Not in scope, but noticed

- `NameExists` reads `publishedSnapshot()` with no `Ready` check (`zone_utils.go:1230`), and
  the query path reads *other* zones' snapshots directly for signal and parent data
  (`queryresponder.go:560`, `:698`). Both bypass `GetOwner`'s gate. Harmless once C1 and the
  §3.3 gate land, but the `Ready` invariant is relied on in more places than it is enforced.
- A nil `KeyDB` panics several paths below `EnsureActiveDnssecKeys` —
  `LoadRolloverZoneRow(nil, …)` (`ksk_rollover_zone_state.go:130`), `loadDnssecKeysFromDB`
  (`signing_keys_snapshot.go:147`). The publish path guards it at the single resolution (§9),
  and the engine sets `KeyDB` on every `ZoneData` it builds, so this is latent rather than
  reachable — but it is guarded by callers rather than by the accessors.

---

## 4. Risk assessment

| # | risk | likelihood | impact | mitigation | detection |
|---|---|---|---|---|---|
| R1 | Self-deadlock re-locking `zd.mu` during the in-publish signing pass | **high** if §3.2 is not followed exactly — the tree has done this before (`6e090a9`) | severe: the zone's publisher wedges and the zone stops updating | pre-resolved `dak` with `zdLocked=true`, non-nil into every `SignRRset`; the extract neither locks nor resolves | hangs immediately; a publish test on a signed zone catches it in CI |
| R2 | The `Ready` flip reuses the NOTIFY predicate | **high** — the predicates share a name and half their body | severe and **silent**: every zone stays not Ready, so nothing serves | §3.3's two-predicate table; the flip takes the content half only | a first-load test that asserts the zone becomes Ready |
| R3 | A full-zone sign fires on an inbound IXFR | **certain** if §3.1 stages a bare boolean | severe at scale: the whole zone re-materialised per delta | stage `wsSignOwners` from `ixfrTouchedOwners` for an `ixfrDerived` replacement | **not** signature counters, which stay low either way — assert untouched owners were not cloned |
| R4 | `Ready` flips on a signing zone holding an unsigned snapshot | certain without the §3.3 gate | severe: queries answered unsigned from a Ready zone — C1's defect at first load | gate every site on the content half | first-load test |
| R5 | Signing under `zd.mu` lengthens the lock hold on every changed refresh | certain | moderate: readers of that zone stall for the pass | signing already happened under `zd.mu` (`sign.go:871`) — the hold moves, it does not grow; C2 takes `dns.Exchange` off the same lock | publish latency per zone |
| R6 | A KeyDB fault on first load is mistaken for a deferred policy bind | high without the sentinel | moderate: a real fault published as an unsigned zone | `ErrDnssecPolicyNotBound` + `errors.Is`, not `err != nil` | a test with a broken KeyDB asserting refusal |
| R7 | `InstallInitialSnapshot` double-notifies after the publish flip | high if it notifies unconditionally | low: a second NOTIFY for one serial, which is rule 1 | emit only when this call changed `Ready` | NOTIFY count across a restart |
| R8 | A zone freezes at its last good version on a persistent signing failure | low | moderate, and intended (§3.3) | `DnssecError` set and surfaced | the zone is an ERROR row on `zone list` |
| R9 | `wsNeedsFullSign` / `wsSignOwners` set on an incremental path | low | low–moderate: a full walk per DDNS update | one setter, in `applyRefreshReplacementLocked` | a DDNS test asserting no full pass |
| R10 | Dropping notify-on-force surprises an operator relying on `reload-zones` | medium | low: downstreams refresh on their own timers | documented as deliberate (§3.5) | operator report |
| R11 | The `ResignRequest` migration misses a producer, so a rollover stops re-signing | medium | severe: the zone goes bogus after a rollover | the channel type changes, so every producer is a compile error | compile |
| R12 | `ResignZone` differs from `SignZone(force=true)` in some case the rollover path depended on | medium | moderate | `ResignZone` is the documented tool and is strictly more correct (it removes stale RRSIGs); rollover tests run against it before C4 lands | rollover integration test |

**Rollback.** C1 is one staged scope and one call; reverting it restores the old two-publish
behaviour. C2–C5 are independent of it and of each other.

---

## 5. LOC estimate

| commit | file | added | removed | net |
|---|---|---|---|---|
| C1 | `sign.go` — extract `signWorkingSetLocked`, add `ErrDnssecPolicyNotBound` | 55 | 25 | +30 |
| C1 | `zone_mutation.go` — staged scope, key resolution, sign step, `Ready` flip, refusal | 110 | 5 | +105 |
| C1 | `structs.go` — `wsNeedsFullSign`, `wsSignOwners` | 14 | 0 | +14 |
| C1 | `ixfr_in.go` — carry the touched set on the scratch zone | 10 | 0 | +10 |
| C2 | `zone_mutation.go` — `notifyIfServable`, the `InstallInitialSnapshot` flip test | 60 | 2 | +58 |
| C2 | `main_initfuncs.go` — queue depth | 2 | 2 | 0 |
| C3 | `refreshengine.go` — delete three notify sites | 0 | 30 | −30 |
| C3 | `zone_utils.go` — delete `NotifyDownstreams` | 0 | 25 | −25 |
| C4 | `resigner.go` — `ResignRequest`, reason switch, `ResignZone` for key state | 60 | 25 | +35 |
| C4 | `triggerResign` and its call sites | 25 | 20 | +5 |
| C5 | `zone_utils.go` — `SetupZoneSigning` → `registerForPeriodicResign` | 20 | 35 | −15 |
| C5 | `refreshengine.go`, `parseconfig.go`, `dynamic_primary.go` — call sites | 12 | 20 | −8 |
| | **total** | **368** | **189** | **+179** |

Tests: roughly 450 lines across publish-signing, IXFR scoping, NOTIFY-once, first-load/restart
and resign-intent files (§7).

---

## 6. Commit order

Across both documents, on one branch:

| # | commit | doc |
|---|---|---|
| 1 ✅ | **#502 probe deadline** — bound the SOA probe, name the unreachable upstream ✅ implemented (`fix/refresh-probe-deadline-502`) | engine doc, S0 |
| 2 ✅ | **C1** — sign replacement content before the swap | here, §3.1–3.3 |
| 3 ✅ | **C2** — NOTIFY only about a servable version | here, §3.4 |
| 4 ✅ | **C3** — delete the refresh engine's NOTIFYs | here, §3.5 |
| 5 ✅ | **C4** — `ResignQ` intent; `ResignZone` for key-state changes | here, §3.6 |
| 6 ✅ | **C5** — `SetupZoneSigning` becomes a registration | here, §3.7 |
| 7.. | the refresh-engine work | engine doc, S1–S5 |

S0 goes first because the lab is exposed to #502 today and it is small and self-contained. C1
comes before the NOTIFY work because once the refresh publishes signed data, C2's gate has one
kind of publish to reason about instead of two.

---

## 7. Testing

- **The defect, as a test:** an inline-signing secondary transfers a zone; assert that *every*
  snapshot ever stored has RRSIGs on its authored RRsets — no intermediate is observable.
  Fails today.
- **An inbound IXFR signs only what it touched.** A two-record delta into a large signed zone
  signs those owners and the apex and no others, and — the assertion that actually catches a
  regression — untouched owners are not cloned: their `RRTypeStore` pointer is still the one
  the served snapshot holds.
- **One serial per change**, and **one NOTIFY per changed serial**, counted across a full
  first load and a subsequent changed refresh.
- **First load stays invisible until it is servable:** no keys, no policy — publishes unsigned,
  not Ready, answers no queries, emits no NOTIFY; the policy apply then signs, publishes, flips
  Ready and emits exactly one.
- **Restart with keys signs at the refresh publish**, flips Ready, emits one NOTIFY, and
  `InstallInitialSnapshot` does not emit a second.
- **A primary file reload of an already-signed zone is a no-op pass:** the scope is staged, the
  pass runs, and `force=false` writes no new RRSIGs.
- **DDNS is untouched:** an update publishes once, signed, and triggers no full pass.
- **Signing failure:** the previous snapshot is still served, `DnssecError` is set. **A KeyDB
  fault on first load refuses** rather than publishing unsigned.
- **Rollover:** a key-state change re-signs via `ResignZone` and leaves no RRSIG by a
  no-longer-active key.
- Run all three test modules — `go test ./...` from `v2/` skips `v2/cli` and `v2/cache`.

---

## 8. The C1 defect, written up

Filed as [#512](https://github.com/johanix/tdns/issues/512). Kept free of deployment detail,
since the repository is public.

---

**Title:** A signing secondary serves unsigned records for the length of a signing pass after
every changed refresh

A zone that signs its own content but receives it unsigned — an inline-signing secondary —
publishes the transferred data first and signs it afterwards, in a second publish. Between the
two, the snapshot being served holds:

| | |
|---|---|
| apex SOA | signed — `resignWorkingSetSOAIfSigned` runs on every publish |
| NSEC chain | signed — `restitchNsecLocked` regenerates and signs it during the publish |
| ZONEMD | signed — computed and signed during the publish |
| every transferred RRset | **unsigned** |

The zone is `Ready`, so that version is served. A validating resolver asking for a name during
the window gets an unsigned answer alongside a signed denial chain. `ZoneTransferOut`'s
fail-closed guard does not stop a downstream taking it either: the guard inspects the apex
SOA's RRSIG, and the apex SOA is signed.

The window is not a race. It lasts from the refresh publish until the signing publish — a full
signing pass over the zone, after every changed refresh, and considerably longer with PQ
algorithms.

**Where**

- `applyRefreshReplacementLocked` publishes the replacement (`v2/zone_mutation.go:725`).
- `SetupZoneSigning` → `SignZone` signs and publishes again (`v2/zone_utils.go:2006`,
  `v2/sign.go:969`), with `bumpSerial=true`.

**Also visible from outside**, same cause: one upstream change produces more than one published
serial, so downstreams transfer more than once for it, and the refresh engine emits a NOTIFY of
its own on top of the one each publish already sends.

**Not affected**

- Dynamic updates: `ApplyZoneUpdateToZoneData` signs each RRset as it stages it and publishes
  once (`v2/zone_updater.go:1156`).
- A primary reloading an already-signed file: the RRSIGs arrive with the data.
- Zones that do not sign their own content.

**Fix**

Sign the staged content before the snapshot is stored, in the same publish — the argument
`restitchNsecLocked` already makes for the NSEC chain, applied to authored data. Design:
`docs/2026-09-05-signing-publish-notify-correctness.md`, C1.

---

## 9. Implementation status

**S0** (engine doc) is implemented and reviewed on `fix/refresh-probe-deadline-502`.

**C1 and C2 are implemented on `fix/sign-before-publish`, stacked on that branch, and the
nine-item punch list below has been applied.** They were written before this document was
reviewed — the ordering was wrong, and is recorded here rather than tidied away. Their settled mechanics match §3 and should be kept: the
`signNsec` flag, the staged scope cleared only on success, a nil `dak` refused,
`EnsureActiveDnssecKeys(..., true)` under the lock, `GenerateNsecChainWithDak` left in
`SignZone`, and the NOTIFY request built under the lock.

Nine things had to change before that branch un-parked, and have (✅):

| # | change | § |
|---|---|---|
| 1 | `wsNeedsFullSign = zd.signsItsOwnContent()` becomes the two-way staging, and `signWorkingSetLocked` gains the `owners` filter | §3.1, §3.2 |
| 2 | the refusal sets `DnssecError`, not `DnssecPolicyWarning` | §3.3 |
| 3 | `Ready` is gated on the content half in `InstallInitialSnapshot` (both branches) and `applyRefreshReplacementLocked` | §3.3 |
| 4 | `snapshotIsServableLocked` calls `signsItsOwnContent()` rather than inlining the option test | §3.4 |
| 5 | the skip becomes `errors.Is(err, ErrDnssecPolicyNotBound)` after resolving keys, **and** `publishWorkingSetLocked` sets `Ready` on the content half | §3.3 |
| 6 | `InstallInitialSnapshot` notifies only when that call flipped `Ready` | §3.4 |
| 7 ✅ | add `ErrDnssecPolicyNotBound` at `sign.go:521` and wrap it there | §3.3 |
| 8 ✅ | restore `refuseUnrepairableChainLocked`'s doc comment, which the C1 patch inserted new functions in front of | — |
| 9 ✅ | resolve the signing material **once** in `publishWorkingSetLocked` and pass it to the SOA re-sign, the C1 pass, the ZONEMD gate and the restitch, replacing the three independent `DnssecPolicy == nil` tests | §3.3 — without it a restart serves signed answers with no denial chain |

Three tests changed with them, and one pre-existing test changed its *mechanism*:

- `TestPublishRefusesAReplacementItCannotSign` — both assertions inverted (item 2).
- `TestPublishDoesNotNotifyBeforeReady` and `…AnUnsignedVersionOfASignedZone` — both premises
  were retired by items 5 and 3. A publish of a servable snapshot now flips `Ready`, so "before
  Ready" is no longer a state one leaves you in; and a zone with keys and a nil policy now
  *signs*, which is the whole point of the corrected predicate. Replaced by
  `TestPublishStaysInvisibleWhenItCannotSign` and `TestPublishSignsAndBecomesReadyOnARestart`,
  which are the two cases §3.8 distinguishes.
- `TestAbandoningTheZonemdRefusesThePublishWhenTheChainCannotBeRepaired` — it forced its
  failure by closing the keystore, which worked while `restitchNsecLocked` resolved its own
  keys. Item 9 moved the resolution earlier, so closing the store now fails the publish before
  the restitch is reached. It injects a key-less `signingMaterial` instead, which puts the
  failure where the test is aiming.

Added: `TestPublishSignsOnlyTheOwnersAnIxfrTouched` (verified to fail when the scope is
ignored), `TestInstallInitialSnapshotDoesNotReadyAnUnsignedSigningZone`, and
`TestPublishTreatsAnUnboundPolicyAsNotYetRatherThanAFault`.

**One thing the punch list did not anticipate.** `resolveSigningMaterialLocked` has to guard a
nil `KeyDB` explicitly. The KeyDB accessors do not check their receiver all the way down —
`loadDnssecKeysFromDB` dereferences it — so reaching them with nil is a SIGSEGV in the publish
path. The retired `DnssecPolicy == nil` test happened to shield that; the corrected predicate
does not. `zonemdSignableLocked` had always tested `KeyDB != nil` alongside the policy, so the
guard restores an invariant the tree already held rather than inventing one.
