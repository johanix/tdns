# ZSK algorithm rollover — cleanup punch-list

Status: PLANNING / punch-list (2026-07-01). Prioritized cleanups for the
as-merged relaxed-mode ZSK algorithm rollover (FIFO model, PR #263) and
its follow-ups. Grounded in a read of the current tree on branch
`feat/tsig-first-class` (contains all merged rollover work). Code
references are `file:line` into `v2/`.

Several of these are **prerequisites for the KSK algorithm rollover work**
(`2026-07-01-ksk-alg-rollover-parallel-fifo-design.md`) under the
clean-then-generalize sequencing — see §0.

Feature commits + follow-ups this covers: `5f95388` (automate ZSK rollover
from lifetime), `64dc39b` (completeness knob), `db693db` (step 2 —
relaxed-mode ZSK alg rollover), `3c6f7d3` (change-policy re-entrancy fix),
`5581bf6` (flagged the unordered-standby FIFO bug), `5ba805c` (CodeRabbit
review), `6e6c4aa`/`81dcb2d`/`a817dfa` (status header), `7ef4cef` (`when`
schedule).


## What is confirmed sound (no action)

The merged feature is fundamentally correct; the cleanups below are
hardening, not rescue.

- **FIFO ordering is fixed.** `GetDnssecKeysByState` orders
  `published_at ASC, keyid ASC` on both the all-zones and per-zone query
  (`keystore.go:1201,1204`); every FIFO consumer relies on it (promotion,
  the cap tail-delete, the next-to-promote pick). The `5581bf6`
  "unordered-standby FIFO bug" is resolved and pinned by
  `TestT4cFifoOrderingByPublishedAt` (`zsk_alg_rollover_test.go:298`).
- **Role-only counting + total cap is correct** and algorithm-agnostic
  (`key_state_worker.go:290-402`); the total-count cap replaces
  algorithm-based deletion for relaxed same-role ZSK keys
  (`sign.go:365-368`). No off-by-one found.
- **Reconcile relaxed branch is correct**: relaxed does NOT retire the
  wrong-alg active ZSK (no-op, `sign.go:329-336`); strict REFUSES
  (`:329-332`); KSK REFUSES in both modes (`:312-317`); CSK early-returns
  (`:296`).
- **The re-entrancy fix (`3c6f7d3`) is clean**: measuring against the
  *bound* `curZSKAlg` (not the target) is the right predicate, tested by
  `TestReentrancyFreshZoneNotInFlight` /
  `TestChangePolicyFreshZonePassesReentrancyGuard`.


## 0. Clean-then-generalize prerequisites (do these first)

These four are the shared primitives the KSK parallel-FIFO work
generalizes; landing them first means the KSK work builds on them instead
of duplicating ZSK-shaped code. Ordered:

1. **P0-2 → implement as the D3 invariant.** The single-active guard the
   punch-list wants is exactly the KSK design's **"one active per
   (role, algorithm)"** invariant. Implement it once, for both roles, in
   the same commit — it closes the ZSK gap and enables the KSK alg-roll
   overlap. (See KSK design §4.)
2. **P0-4 + generalize `zskAlgRollInFlight`** into a **role-generalized
   in-flight / `FromAlg` predicate** — the re-entrancy guard both roles
   need (KSK design §8, corner "re-entrancy").
3. **P2-1** — the `256`/`257` **flag constants** (touched heavily by the
   FIFO work).
4. **P2-4** — a **`firstKeyOfRole` helper** (collapses the repeated
   role-scan idiom the FIFO work would otherwise duplicate).

**P0-6 is a fifth member of this sensitive cluster** — not a prerequisite
(it does not *unblock* the KSK work), but it must be **co-designed** with
P0-2 and the KSK double-sign, because all three change how the old-alg
key's RRSIGs are handled during an alg roll and share the signer's
strip/resign path. Land it in the same coordinated change.

The remaining items (P0-1, P0-3, P0-5, all P1, P2-2/3/5) are independent
ZSK hygiene and can land whenever.


## P0 — correctness / latent bugs

**P0-1 — no invariant enforces non-NULL `published_at` on a standby key.**
FIFO promotion sorts `published_at ASC`; a standby that somehow lands with
NULL `published_at` sorts *first* and would be promoted out of order. The
ordering fix (`keystore.go:1201/1204`) assumes standbys always have a
`published_at`, but nothing enforces it.
→ *Fix direction:* a cheap guard in `RolloverKey`'s standby selection —
skip/warn when `PublishedAt == nil` — or a NOT-NULL story at the
published→standby transition.

**P0-2 — `RolloverKey` retires the first role-matching active key with no
single-active guard** (`keystore.go:1358`). The loop `break`s on the first
active of the role; if two actives ever exist (e.g. a double promotion),
it silently retires one and keeps the other, masking the invariant
violation instead of failing loud. The whole "atomic swap, never two
active" model is unchecked at the one place it is assumed.
→ *Fix direction:* implement as the **D3 invariant** (§0.1): collect
role-matching actives and, if `> 1` for the same `(role, algorithm)`,
return an error. (For the KSK this permits one active *per algorithm*
during an alg-roll overlap; for the ZSK it means one active, full stop.)

**P0-3 — TOCTOU in `changeZonePolicy`** (`apihandler_zone.go:487-554`).
The source algorithm / re-entrancy / mode guards run against a snapshot
read under `zd.mu`, which is released before the rebind re-acquires
`zd.mu`. A concurrent policy change in that window can move
`zd.DnssecPolicy`, so the guards validate one source algorithm while the
rollback captures a different `oldPol`. `5ba805c` fixed the narrower
`oldName`/`oldPol` pairing but not this wider window.
→ *Fix direction:* hold one lock (or a per-zone change-policy lock) across
guard + rebind, matching the pattern the rollover `asap` handlers use with
`AcquireRolloverLock`.

**P0-4 — `zskAlgRollInFlight` collapses multiple in-flight algorithms to
one `FromAlg`** (`zsk_rollover.go:240`, `if fromAlg == 0 { fromAlg =
k.Algorithm }` captures only the first-seen non-target algorithm). The
boolean guard stays safe, but the operator-facing error and the status
header (`AlgTransitionInfo.FromAlg`) can name the wrong source algorithm
during a multi-algorithm state.
→ *Fix direction:* collect the distinct set of non-target algorithms;
render joined, or explicitly report ">1 old algorithm present." Fold into
the role-generalized predicate (§0.2).

**P0-5 (watch, not a bug today) — generate/cap non-oscillation rests on an
unstated invariant.** The tick order (`key_state_worker.go:110-124`)
`rolloverZsksForAllZones → transitionRetiredToRemoved → maintainStandbyKeys`
never oscillates *only because* `maintainStandbyKeysForType` mints into
`published` (via `GenerateAndStageKey`) while `capStandbyZsksByCount`
counts `standby` only (`:296-297`, `:360-361`). If a future change staged
generated keys directly into `standby`, generate-then-cap would churn every
tick.
→ *Fix direction:* a one-line assertion/comment at the generate call
("must stage to published, not standby, or the relaxed cap oscillates"),
or make cap+generate share a single counting pass over both states.

**P0-6 — a relaxed ZSK alg roll must REPLACE old-alg RRSIGs, not
accumulate them (remove the accidental double-signature).** During a
relaxed-mode ZSK algorithm roll the uniformly-additive signer generates
new-alg RRSIGs over each RRset but does **not** strip the old-alg RRSIGs —
they linger until the old-alg key is removed (the signer never strips
others' RRSIGs, `sign.go:180-185`; the strip happens only at
`retired → removed`, `key_state_worker.go:239-241`). The result is a
whole-zone double-signature across the entire drain window — but an
*accidental, partial, unguaranteed* one (an RRset carries both only if it
happened to be re-signed while both keys existed), so it delivers no real
double-sign guarantee, only the cost. This is a remnant of the earlier
assumption that ZSK alg rolls need double-signature; the dual-model design
(`2026-06-27-zsk-alg-rollover-dual-model-design.md`) explicitly **rejected**
conservative whole-zone double-signing for the ZSK in favour of relaxed
FIFO / alg-split — one valid RRSIG per RRset suffices (RFC 6840 §5.11).
→ *Fix direction:* during a relaxed ZSK alg roll, the new-alg key's RRSIG
should **replace** the old-alg key's RRSIG per RRset — strip old-alg ZSK
RRSIGs as the zone is re-signed, not at key removal. The old-alg ZSK
**DNSKEY stays published** until *cached* old-alg RRSIGs drain (the existing
removal margin `propagationDelay + max_ttl` still governs the DNSKEY); only
the *served* RRSIGs are replaced immediately. Net: one new-alg RRSIG per
RRset, no whole-zone double-sign, drain via the retained DNSKEY.

> **⚠ Sensitive — this is the exact opposite of the KSK decision; co-design
> with P0-2.** Keeping both old- and new-alg RRSIGs is precisely what we
> decided is *correct* for the **KSK** alg roll (the deliberate
> double-signature over the DNSKEY RRset —
> `2026-07-01-ksk-alg-rollover-parallel-fifo-design.md` §5, FACT 3). The
> signer is uniformly additive today; the KSK design *relies* on
> additive-keep (FACT 3) while this item wants the ZSK alg roll to strip.
> So the strip/resign behaviour must become **role/mode-aware**: **strip**
> old-alg RRSIGs for a *relaxed ZSK alg roll*, **keep** them for a *KSK alg
> roll* (double-sign) and for *same-alg drains*. Implement P0-6, P0-2 (the
> D3 invariant), and the KSK double-sign as **one coordinated change** — a
> naive edit to the strip/active logic for either role will break the other.


## P1 — test gaps

**P1-1 — no test asserts the no-double-active invariant across an alg
roll.** T5 (`zsk_alg_rollover_test.go:403-406`) only checks
`len(active) != 0` at the end. The core "never two active" property (P0-2)
is untested.
→ Assert exactly one active ZSK after each `RolloverKey` step.

**P1-2 — removal margin (sum `propagationDelay + max_ttl`) is only
unit-tested on the helper**, not on the worker path.
`TestZskRemovalMargin` (`zsk_rollover_test.go:29-38`) checks
`zskRemovalMargin` arithmetic; nothing tests that
`transitionRetiredToRemoved` (`key_state_worker.go:216-229`) actually
holds a retired ZSK for that margin. The sum-vs-max distinction is the
whole safety margin; a regression to `propagationDelay`-only would strip
still-cached RRSIGs unnoticed.
→ Table test: retired ZSK at `now-(margin-ε)` stays, `now-(margin+ε)`
removed; assert `LoadZoneSigningMaxTTL` participates.

**P1-3 — T5 bypasses the real worker path** (`zsk_alg_rollover_test.go:325-407`
drives `kdb.RolloverKey` directly and hand-simulates published→standby),
so `rolloverZskForZone`'s gating (`zskRollDue`, `haveStandby` wait, the
manual-request clear-on-commit, lock acquisition) is never exercised in
the FIFO alg-roll scenario.
→ One end-to-end test driving `rolloverZskForZone` + `maintainStandbyKeys`
+ `transitionPublishedToStandby` across a full old→new drain.

**P1-4 — no test for `asap --zsk` mid-drain, and the intentional KSK
asymmetry is undocumented.** The ZSK `asap` handler has no
`RolloverInProgress` guard (`apihandler_rollover.go:106-119`), unlike the
KSK path (`:128-137`) — by design (asap *is* the throttle), but untested
and unspecified.
→ Test that asap mid-drain promotes the next FIFO standby without
skip/duplicate; document that ZSK asap has no in-progress refusal
(asymmetry with KSK is intentional).

**P1-5 — no direct over-mint-prevention assertion during the drain
window.** T3/T3b cover the endpoints (role-only count generates nothing;
generate-on-drain uses the new alg) but not the middle — with N old
standbys and asap firing faster than propagation, does anything over-mint?
(Reading says no: generate is gated on `standbyCount < standbyKeyCount`
AND `publishedCount == 0`.)
→ A direct assertion of the middle case.


## P2 — hygiene / naming / dead code

**P2-1 — magic `256`/`257` flag literals vs `dns.SEP`, mixed within the
same function.** `reconcileActiveKeyAlgorithms` uses `Flags != 256`
(`sign.go:323`) and `Flags&dns.SEP != 0` (`:357`) side by side; bare
literals also at `key_state_worker.go:290,306,370`;
`zsk_rollover.go:232,292,310,408,429,455`; `sign.go:426,436,514`;
`keystore.go:1345,1347`. One typo away from a role confusion in
security-critical key selection.
→ Introduce `flagsZSK uint16 = 256` / `flagsKSK uint16 = 257` (or
standardize on `Flags&dns.SEP` role tests) and use consistently.
**Prerequisite for the FIFO work (§0.3).**

**P2-2 — `resolveCompletenessMode` is misfiled** in `large_ksk.go:91-102`;
the `CompletenessStrict/Relaxed` constants are in `config.go:112-113`. The
completeness feature is scattered across `config.go`, `large_ksk.go`,
`parseconfig.go`.
→ Move `resolveCompletenessMode` (and its test) into a small
`completeness.go` next to the constants.

**P2-3 — `AlgTransitionInfo.Done/Total` progress is misleading during the
drain window** (`zsk_rollover.go:235-237`). `Total` counts standby ∪ active
∪ retired (any alg); `Done` counts target-alg. Retired old-alg keys inflate
`Total` while draining, so `Done/Total` can appear to regress. Cosmetic
(status header only).
→ Exclude `retired` from the denominator, or relabel to make the
drain-window semantics explicit.

**P2-4 — KSK vs ZSK rollover duplication.** The
role-matching-scan-then-break idiom
(`for i := range keys { if Flags==… { … break } }`) is repeated ~8× across
`zsk_rollover.go`, `keystore.go`, `sign.go`, mirroring the KSK equivalents
in `ksk_rollover_automated.go`.
→ Extract `firstKeyOfRole(keys, flags)` / `filterByRole` in `keystore.go`;
migrate call sites. **Prerequisite for the FIFO work (§0.4)** — the
parallel-FIFO code would otherwise add more copies.

**P2-5 — `retiredAny` naming residue.** `5ba805c` renamed the
reconcile's `retired`→`removed` semantics and fixed the stale comment
(`sign.go:271-294`), but the `retiredAny` return variable
(`sign.go:338,380,384`) still reads "retired" though it now means "removed
a non-active leftover."
→ Rename `retiredAny`→`removedAny`.

**P2-6 — pre-existing `XXX/FIXME` in the blast-radius files** (not from
#263): `keystore.go:92` ("add should also add to TrustStore"),
`keystore.go:946` ("use this once we've found all the bugs in the sqlite
code"), `sign.go:232/746/859`. Flagged only; out of scope for this
cleanup unless bundled.


## Sequencing

1. **§0 prerequisites** (P0-2 as the D3 invariant, P0-4 + generalized
   predicate, P2-1 flag constants, P2-4 role helper) — these unblock the
   KSK parallel-FIFO work. **P0-6 (ZSK RRSIG replacement) is co-designed
   here** — same signer strip/resign path as P0-2 and the KSK double-sign,
   opposite direction; one coordinated change.
2. **Independent ZSK hardening** (P0-1, P0-3, P0-5) — any time.
3. **Test gaps** (P1-1…P1-5) — ideally alongside the correctness items
   they cover (P1-1 with P0-2, P1-2 with the margin path); add a P0-6 test
   asserting the served zone carries exactly one (new-alg) RRSIG per RRset
   mid-roll, with the old-alg DNSKEY still published.
4. **Remaining hygiene** (P2-2/3/5) — low priority, opportunistic.
