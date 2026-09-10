# KSK algorithm rollover — implementation-ready plan

Status: BUILD PLAN (2026-09-08). Successor to
`2026-07-01-ksk-alg-rollover-parallel-fifo-design.md` (the model) and
`2026-06-21-ksk-algorithm-rollover-plan.md` (the scaffolding). This
document settles the one question the 2026-07-01 design left open (its §7),
corrects two of its claims, and turns the model into a commit-by-commit
build order with a test matrix.

Amended 2026-09-10: §3/F1 carries amendment A1 — two caveats on the
soundness of the widened margin. No decision, estimate or commit in the
build order changes.

Code references are `file:line` into `v2/` at `f4bea22` (main), verified
2026-09-08. Cross-references of the form "(fifo §N)" point at the
2026-07-01 design; "(K-N)" at the 2026-06-21 plan; "(P0-N)" at
`2026-07-01-zsk-alg-rollover-cleanups.md`.


## 0. Executive summary

The engine needed for a KSK algorithm rollover is ~85% present. What is
missing is not a second engine but **one alternate ordering** through the
existing per-zone phase machine: mint the new-algorithm KSK straight into
`active` so it signs the apex DNSKEY RRset **before** its DS is pushed
(double-signature), instead of the multi-DS ordering that pushes the DS
first (`ksk_rollover_ds_push.go:107` selects `created` keys precisely so
the DS can precede the DNSKEY).

The 2026-07-01 design's headline conclusion — multi-DS cannot carry an
algorithm rollover, double-signature must — is correct and unchanged. Its
**modelling** overshot: it proposed per-FIFO rollover-state rows and FIFO
instantiation machinery. That is not needed. §2 below shows the sequence
is strictly linear (the old-algorithm FIFO is frozen and does nothing but
drain), so the existing per-zone phase machine carries it end to end with
**no new phase and no new table** — four nullable columns on
`RolloverZoneState`, and the FIFO stays a derived view rather than a
stored entity.

Two genuinely new findings, both correctness-level, are in §3:

- **F1 — the retire→remove margin must additionally cover the parent DS
  TTL** for a double-signature roll. The 2026-07-01 design (§5, "On the
  DS-drain wait") argued the wait is subsumed because `DS(A)` and `DS(B)`
  are co-published. That argument covers resolvers that fetch the parent
  DS RRset *after* the push; it does not cover one holding the *pre-push*
  RRset, which contains `DS(A)` alone. Multi-DS is safe here by
  construction and double-signature is not — this is the one place the
  two methods genuinely differ in required margin.
- **F2 — the rollover engine's withdraw phase never strips the removed
  key's RRSIGs** (`ksk_rollover_automated.go:565-622`). Every other
  retired→removed path in the tree does (`key_state_worker.go:237-252`,
  `keystore.go:793`, `:836`). Pre-existing, latent for same-algorithm
  rolls; a blocker for the algorithm roll, where the residue is a dangling
  old-algorithm RRSIG over a DNSKEY RRset that no longer contains the
  old-algorithm key.

Scope is also materially smaller than the 2026-07-01 estimate because two
things it bundled are decoupled: generalizing double-signature to
*same-algorithm* rolls (its D1/D2) is **not** a prerequisite (§4, D-3),
and the ZSK RRSIG-replacement cleanup (P0-6) is a co-design *constraint*,
not a dependency (§4, D-9).


## 1. What exists today (verified)

### 1.1 The pieces the algorithm roll reuses unchanged

| Piece | Where | Why it just works |
|---|---|---|
| Additive signer | `sign.go:171-231` | `signingkeys = dak.KSKs` for the DNSKEY RRset, where `dak.KSKs` is *every* active SEP key, with no algorithm predicate. Two active KSKs of different algorithms both sign, with zero signer change. |
| DNSKEY RRset assembly | `ops_dnskey.go:23-24,36-108` | active ∪ published ∪ standby ∪ retired. Algorithm-blind. |
| DS target set | `ksk_rollover_ds_push.go:101-159` | states `created,ds-published,standby,published,active,retired`. A `retired` key keeps its DS — exactly what the drain window needs. |
| DS confirm matcher | `ksk_rollover_parent_poll.go:42-90` | canonical DS comparison (keytag + alg + digest type + digest). A mixed-algorithm expected set works with no change. |
| Push / observe / softfail machine | `ksk_rollover_automated.go:275-564` | algorithm-agnostic; drives whatever `ComputeTargetDSSetForZone` returns. |
| Withdraw margin phase | `ksk_rollover_automated.go:565-622` | holds `retired` SEP keys for `effective_margin` from `retired_at`, then `removed`. |
| Delegation-sync DS interlock | `delegation_utils.go:650-670`, `zone_updater.go:1839` | `rolloverOwnsDS()` suppresses the childsync/UPDATE DS opinion whenever `rollover_in_progress` or `phase != idle`. Keeps `DSIntentForZone` (which excludes `retired`, `ds_intent.go:44-53`) from withdrawing `DS(A)` mid-drain. **Load-bearing for this work** — see §7.3. |
| Generic retired→removed | `key_state_worker.go:195-199` | already skips SEP keys in rollover-managed zones. |

### 1.2 The two refusals to replace

- `apihandler_zone.go:780` — `change-policy` refuses a KSK-only algorithm
  change ("route via the auto-rollover engine — not yet built").
- `sign.go:320-325` — `reconcileActiveKeyAlgorithms` refuses any active
  KSK whose algorithm ≠ policy, in both completeness modes. This is the
  backstop that stops a background re-sign from running the legacy
  synchronous retire.

### 1.3 The prerequisites from the 2026-07-01 sequencing: none landed

Verified absent at `f4bea22`: no `firstKeyOfRole`/`filterByRole`, no
`flagsZSK`/`flagsKSK` constants, `pickActiveSEPTx`
(`ksk_rollover_atomic.go:157-184`) still hard-errors on >1 active SEP,
`RolloverKey` (`keystore.go:1581-1607`) still takes the first
role-matching active with no guard, `zskAlgRollInFlight`
(`zsk_rollover.go:222`) is still ZSK-only. §6 folds the two that matter
into the build order; the two cosmetic ones (P2-1, P2-4) are optional.


## 2. Settling fifo §7: no per-FIFO state, no new phase

The 2026-07-01 design named this "the first thing to settle before
build". The answer is that the premise was wrong: **there is no
concurrency between the two KSK FIFOs to model.**

Walk the sequence and ask what the *old-algorithm* FIFO is doing at each
step:

| Step | New-alg FIFO (B) | Old-alg FIFO (A) |
|---|---|---|
| 1. spawn | mint into `active`, signs DNSKEY | frozen: head stays `active`, orphan standbys deleted |
| 2. wait propagation | waiting | nothing |
| 3. push `{DS(A),DS(B)}` | pushing | nothing |
| 4. observe / confirm | observing | nothing |
| 5. retire A | — | `active → retired`, still signing |
| 6. hold margin | steady | waiting on the clock |
| 7. remove A | steady | `retired → removed`; FIFO empty |

The old FIFO holds **no phase**. It has a per-*key* state (`active`, then
`retired` with a `retired_at`), and the existing `pending-child-withdraw`
phase already drives exactly that clock. Everything that advances is the
new FIFO, and it advances through the phases the machine already has.

**DECISION D-1 — the per-zone phase machine is retained unchanged. No
per-FIFO phase rows, no new phase constant.** The mapping is:

```
spawn                        → phase = pending-child-publish   (existing)
wait prop + DNSKEY_TTL       → pending-child-publish handler   (existing, longer wait)
push {DS(A),DS(B)}           → pending-parent-push             (existing)
observe until both confirmed → pending-parent-observe          (existing)
confirm ⇒ retire A           → pending-child-withdraw          (existing)
hold margin, remove A        → pending-child-withdraw handler  (existing, wider margin)
DS shrinks to {DS(B)}        → idle branch re-arms a push      (existing)
```

**DECISION D-2 — the per-zone DS index range needs no change either.**
`RolloverZoneState.last_ds_{submitted,confirmed}_index_{low,high}` is an
aggregate over the one physical parent DS RRset, which is what it should
be. `rollover_index` is a single per-zone counter
(`nextRolloverIndexTx`, `ksk_rollover_zone_state.go:209`), so B's index
simply follows A's; the `[low,high]` interval spans both algorithms
naturally. Holes left by the frozen standbys are harmless: the interval is
only used to select which `created` keys to advance
(`confirmDSAndAdvanceCreatedKeysTx`, `:636`), and an algorithm roll has no
`created` keys.

**DECISION D-3 — a FIFO is a derived view, not a stored entity.**
Introduce one helper and no table:

```go
// keyFifo returns the (role, algorithm) succession for a zone in
// promotion order: published_at ASC, keyid ASC, terminal states excluded.
func keyFifo(kdb *KeyDB, zone string, sep bool, alg uint8) ([]DnssecKeyWithTimestamps, error)
```

What *does* need persisting is small, per-zone, and roll-scoped: that the
current rollover is an algorithm roll, and which algorithms it is between.
Four nullable columns (§5.1).

**Consequence for the 2026-07-01 estimate.** "FIFO instantiation" (its
corner (c)) collapses to one transactional function, `SpawnKskAlgRollover`
(§5.2). "Per-FIFO rollover state" (its §7) disappears. "Generalizing the
double-signature method" (its D1/D2) is decoupled — see D-4.


## 3. Two corrections to the 2026-07-01 design

### F1 — the withdraw margin must cover the parent DS TTL

The 2026-07-01 design, §5:

> since `DS(A)` and `DS(B)` were co-published in one RRset from step 4, no
> resolver holds `DS(A)` without `DS(B)`, so the instant A vanishes the
> orphaned `DS(A)` is simply skipped and `DS(B) → B` carries the chain. So
> the separate DS-drain wait is **subsumed by the existing
> `retired → removed` margin**, not a new step. (Verify: … but confirm
> this holds for the same-algorithm multi-DS case too …)

The verification the doc asked for fails, and asymmetrically.

A resolver that fetched the parent DS RRset **before** step 4 holds
`{DS(A)}` alone, and keeps holding it for up to `DS_TTL` after the push.
If A reaches `removed` inside that window, that resolver sees a DS RRset
with one record, pointing at a key no longer in the child's DNSKEY RRset,
and no other DS to fall back on. That is a bogus delegation, not a
skipped-orphan.

Multi-DS is immune by construction: it pre-positions each key's DS long
before that key becomes active, so any DS RRset old enough to predate the
current push already contains the *incoming* key's DS. Double-signature
publishes `DS(B)` for the first time at step 4 — the property multi-DS
relies on does not exist yet.

**Fix.** For an algorithm roll only, widen the withdraw margin:

```
effective_margin(alg-roll) = max( clamping.margin,
                                  max_observed_ttl,
                                  parent_DS_TTL + rollover.ds-publish-delay )
```

measured from `retired_at`, which under D-1 is stamped at DS-confirm time
— exactly the moment from which the `DS_TTL` clock should run. The parent
DS TTL is already observed and cached on every poll
(`recordParentDSTTLObservation`, `ksk_rollover_validation.go:328`; read
via `resolveDSTTL`, `:105`). When it is unknown, **defer the removal and
log** rather than guess: the cost of deferring is that A keeps signing an
RRset it is entitled to sign, which is harmless.

The same-algorithm multi-DS path keeps today's
`max(clamping.margin, max_observed_ttl)` — do not widen it, or every
existing rollover slows down for no reason.

**Amendment A1 (2026-09-10) — two caveats on F1's soundness.** The formula
and the conclusion above are unchanged; these are the two things a reader
has to know before implementing them. Code references verified at
`efb6dcd3` (main).

**A1(a) — "confirmed" is a single-agent observation, and
`ds-publish-delay` is the term that covers the gap.** Both confirm call
sites issue one `QueryParentAgentDS(ctx, zone, agent)` against a single
parent-agent address (`ksk_rollover_automated.go:371` in the observe
branch, `:462` in the softfail-recovery twin; the helper itself takes one
`agentAddr`, `ksk_rollover_parent_poll.go:96`, and so does
`PollParentDSUntilMatch`, `:129`). Confirmation therefore establishes that
*one* parent server was seen serving the mixed DS RRset — not that every
parent nameserver has it. A lagging parent NS can still be answering with
the pre-push `{DS(A)}` at the instant `retired_at` is stamped, and that
server's `DS_TTL` clock has not started yet.

That is what the `+ rollover.ds-publish-delay` addend is doing: it is
defined as the parent-propagation approximation `parent_prop`
(`ksk_rollover_validation.go:213-216`), and here it pads `retired_at`
forward to cover a parent whose own fan-out has not finished. The formula
is correct as written, but for a reason the text above does not state.
Record the rationale at the implementation site (§5.3, in the
`effectiveMarginForRoll` doc comment); otherwise the term reads as
double-counting a delay the confirm already waited out, and a later
cleanup will reduce it to `parent_DS_TTL` alone and silently reintroduce
the F1 hazard for every multi-nameserver parent. KT-7 (§8) should pin the
addend explicitly, not only the `DS_TTL` term.

**A1(b) — "defer and log" is the normal path after a restart, not an
exceptional one.** `ParentDSTTLObserved` is a field on the in-memory
`ZoneData` (`structs.go:236`), not a persisted column, so any daemon
restart mid-drain zeroes it. `resolveDSTTL` then reports unknown,
`effectiveMarginForRoll` returns `ok=false`, and the withdraw phase
defers — until the `ObserveParentDSTTL` goroutine started at zone load
(`parseconfig.go:1522`) records a fresh observation, or a `ttls.parent-ds`
override supplies one. The behaviour is right and fails in the safe
direction (A keeps signing an RRset it is entitled to sign), but two
consequences follow:

- Word the deferral log line as an expected transient rather than an
  alarm. It fires on every restart that lands inside a drain window, and
  for a PQ-sized rollover that is a wide target.
- E13 (§5.7) must be a `RolloverPolicyWarning` and never an error, for the
  same reason. Its text should distinguish "not yet observed since
  startup" from "no parent DS TTL is observable at all"; only the second
  is operator-actionable (set `ttls.parent-ds`).

Neither caveat changes the build order, the effort estimate, or any
decision in §4.

### F2 — the withdraw phase leaves orphan RRSIGs behind

`ksk_rollover_automated.go:596-614` marks a retired SEP key `removed` and
calls `triggerResign`. It never strips the key's RRSIGs. `SignRRset` is
purely additive and removes an RRSIG only when it is re-signing with that
same key (`sign.go:182-202`), so the removed key's RRSIG over the apex
DNSKEY RRset **persists indefinitely**.

Every other retired→removed path in the tree strips first, with the
reasoning spelled out at `key_state_worker.go:231-236`:

> Strip the key's RRSIGs from the served zone BEFORE marking it removed,
> so a strip failure leaves the key in 'retired' and the worker retries
> the whole sequence next tick.

For a same-algorithm roll the residue is cosmetic-ish (a stale RRSIG by a
same-algorithm key that is no longer published — validators ignore an
RRSIG whose keytag matches no DNSKEY, and a valid RRSIG by the current key
sits alongside it). For an **algorithm** roll it is not: the residue is an
RRSIG in algorithm A over a DNSKEY RRset that contains no algorithm-A key,
while the parent's DS RRset advertises only algorithm B. That is precisely
the shape a strict RFC 4035 §2.2 validator is entitled to treat as a
downgrade artefact, and it is visible on the wire forever.

**Fix.** Port the `key_state_worker.go:237-252` strip-then-transition
block into the withdraw branch, same fail-soft semantics (strip error ⇒
leave the key `retired`, count it as still-waiting, retry next tick).
Land it as its own commit ahead of the feature (§6, commit 1) since it
fixes existing behaviour.


## 4. Design decisions

**D-4 — the algorithm roll uses double-signature ordering regardless of
`rollover.method`.** A zone configured `method: multi-ds` does *not* have
to be reconfigured to roll its KSK algorithm; the algorithm roll simply
takes a different path through the same engine. This decouples the work
from fifo D1/D2 (generalizing double-signature to *same-algorithm*
rollovers), which stays unimplemented and optional. `method: none` refuses
the roll — there is no engine to carry it. `method: double-signature`
zones still early-return for their *same-algorithm* cadence
(`ksk_rollover_automated.go:79-81`) but must be allowed into the
algorithm-roll branch; restructure the tick's guard as:

```go
if pol.Rollover.Method == RolloverMethodNone { return nil }
algRoll, err := LoadKskAlgRollState(kdb, zone)          // nil ⇒ not rolling
if algRoll == nil && pol.Rollover.Method == RolloverMethodDoubleSignature {
    return nil   // same-alg double-signature: still 4E, unimplemented
}
```

**D-5 — `change-policy` binds and gates; the engine tick spawns.** Exactly
the ZSK shape ("This command does NOT perform the roll",
`apihandler_zone.go:836`). The alternative — spawning inside
`change-policy` — fights `applyZonePolicyTransactional`, which re-signs
mid-transaction and would hit the reconcile backstop with the new policy
bound and no roll marker yet, reverting the whole apply. Detecting the
mismatch in the tick is crash-safe, idempotent, self-healing after a
failed bind, and symmetric with the ZSK path.

**D-6 — the new-algorithm KSK is minted straight into `active`.** It is a
bootstrap (fifo corner (a)): a new FIFO's head has no same-FIFO
predecessor to pre-position a DS against. Minting into `active` puts the
DNSKEY *and* its RRSIG into the zone in one change, so a single
propagation wait covers both. Adding B to the DNSKEY RRset cannot break a
resolver holding the older RRset — it still validates `DS(A) → A →
RRSIG(A)`.

**D-7 — one wait before the DS push: `kasp.propagation-delay +
effective_DNSKEY_TTL`.** This is the invert-FACT-2 gate. `DS(B)` must not
appear at the parent while any resolver can still be holding a DNSKEY
RRset without B in it. `propagation-delay` covers the secondaries; the
served DNSKEY TTL covers resolver caches. `effectiveServedDnskeyTTL`
(`ksk_rollover_automated.go:1400`) already computes the latter; when it
returns `!ok`, defer the phase advance and log, matching
`transitionDsPublishedToPublishedForZone`'s handling of the same
condition (`:1071-1076`).

**D-8 — pipeline-fill is suspended for the duration of an algorithm
roll.** This supersedes K-6a (which proposed bumping
`CountKskWithDSAtParent`'s target to `NumDS + 1` during the roll). The
counters are algorithm-blind (`ksk_rollover_pipeline.go:142-167`), so
during the roll they would happily mint *new-algorithm* keys into slots
belonging to the frozen old FIFO — defeating the freeze and re-creating
exactly the mint-target-vs-cap oscillation the ZSK work fixed. Suspending
is one condition, cannot oscillate, and the fill resumes automatically at
`completeRolloverWithdraw` to refill the new-algorithm FIFO to `num_ds`.

**D-9 — the invariant becomes "at most one active key per (role,
algorithm)" (fifo D3), and P0-6 is a constraint, not a dependency.** The
KSK algorithm roll needs the signer's *additive-keep* behaviour, which is
today's behaviour — so P0-6 (make a relaxed ZSK algorithm roll *replace*
old-algorithm RRSIGs) is not a prerequisite. It is a hazard: whenever P0-6
lands, its strip predicate must be scoped to **non-SEP RRSIGs over
non-DNSKEY RRsets**, or it will strip the KSK double-signature this design
depends on. Record that as a comment at the strip site and a test (§8,
KT-12).

**D-10 — completeness mode does not gate the KSK roll** (K-1, unchanged).
A KSK signs one RRset, already TCP-transported; strict and relaxed are
effectively identical here. The knob keeps gating the *ZSK* roll only.

**D-11 — one role at a time, enforced against both roles.** A KSK
algorithm roll is refused while a ZSK algorithm roll is in flight and vice
versa, in addition to the existing both-roles-in-one-policy refusal
(`apihandler_zone.go:770-777`). Two simultaneous algorithm transitions
would put three algorithms in the DNSKEY RRset with two independent drain
clocks; nothing needs it.

**D-12 — abort is only offered before DS confirmation.** Before the mixed
DS RRset is confirmed at the parent, `DS(B)` is not relied upon by anyone:
aborting means removing B, clearing the roll state, and letting the idle
branch re-push the shrunken DS set. After confirmation, "abort" is a
*reverse algorithm roll* — refuse it, and tell the operator to let the
roll finish and then `change-policy` back. Surfaced as `auto-rollover
cancel -z <zone> --ksk --alg-roll` (§5.6).


## 5. The implementation

### 5.1 Schema

Four nullable columns on `RolloverZoneState` (`db_schema.go:139-171`),
added via `dbMigrateSchema` `ALTER TABLE` so existing databases upgrade —
follow the `ZonePolicyOverride.applied_*` precedent documented at
`db_schema.go:196-202`:

```sql
alg_roll_from_alg        INTEGER,  -- NULL ⇒ no algorithm roll in flight
alg_roll_to_alg          INTEGER,
alg_roll_started_at      TEXT,     -- RFC3339
alg_roll_new_head_keyid  INTEGER   -- the spawned FIFO head (B)
```

`alg_roll_from_alg IS NOT NULL` is the single authoritative "an algorithm
roll is in flight" predicate. Cleared by `completeRolloverWithdraw` and by
abort.

No `RolloverKeyState` change: a key's FIFO membership is
`(flags & SEP, algorithm)`, already columns of `DnssecKeyStore`.

Load/save go in `ksk_rollover_zone_state.go` next to their peers — extend
`RolloverZoneRow` (`:13-73`) and the `LoadRolloverZoneRow` column list
(`:115-127`), plus:

```go
type KskAlgRollState struct {
    FromAlg, ToAlg uint8
    StartedAt      time.Time
    NewHeadKeyID   uint16
}
func LoadKskAlgRollState(kdb *KeyDB, zone string) (*KskAlgRollState, error)  // nil ⇒ not rolling
func setKskAlgRollTx(tx *Tx, zone string, st KskAlgRollState) error
func clearKskAlgRollTx(tx *Tx, zone string) error
```

### 5.2 The spawn — `ksk_rollover_alg.go` (new file)

```go
// SpawnKskAlgRollover starts a KSK algorithm rollover for a zone whose
// bound policy KSK algorithm differs from its active KSK's. Single
// transaction; on commit the zone double-signs its apex DNSKEY RRset
// with both algorithms.
func SpawnKskAlgRollover(conf *Config, kdb *KeyDB, zone string,
                         fromAlg, toAlg uint8) (newKid uint16, err error)
```

In one `kdb.Begin("SpawnKskAlgRollover")`:

1. Re-read `rollover_in_progress` and `alg_roll_from_alg` inside the tx
   and bail if either is set (mirrors `AtomicRollover`'s in-tx recheck,
   `ksk_rollover_atomic.go:60-68`).
2. Assert exactly one active SEP key and that its algorithm is `fromAlg`.
   Call it A. (Uses the D-9 `pickActiveSEPByAlgTx`.)
3. Mint B: `kdb.GenerateKeypair(zone, "ksk-alg-roll", DnskeyStateActive,
   dns.TypeDNSKEY, toAlg, "KSK", tx)` — the in-tx generate seam
   `GenerateKskRolloverCreated` already uses
   (`ksk_rollover_pipeline.go:32`).
4. `insertRolloverKeyStateTx(tx, zone, B, nextRolloverIndexTx(tx, zone),
   RolloverMethodDoubleSignature)`; then `setRolloverKeyActiveAtTx`,
   `setRolloverKeyActiveSeqTx(nextActiveSeqTx)`, `stampRolloverStateAtTx`
   — the same four writes `AtomicRollover` does for its promoted key
   (`:111-126`).
5. **Freeze the old FIFO**: every SEP key with `algorithm = fromAlg` in
   `created | ds-published | published | standby` → `removed`. These keys
   have never signed, so there are no RRSIGs to orphan; `removed` drops
   them from both the DNSKEY RRset (`ops_dnskey.go:24`) and the DS target
   set (`ksk_rollover_ds_push.go:107`). The active head is untouched.
6. `setRolloverInProgressTx(true)`, `setRolloverPhaseTx(
   rolloverPhasePendingChildPublish)`.
7. `setKskAlgRollTx({fromAlg, toAlg, now, B})`.

Post-commit: `republishSigningKeysForZone` then `triggerResign` — the same
tail as `AtomicRollover` (`:141-151`). The re-sign is what puts `RRSIG(B)`
over the DNSKEY RRset.

Note the ordering guarantee: because the phase is set to
`pending-child-publish` in the *same* transaction that makes B active, the
idle branch's `kskIndexPushNeeded` (`ksk_rollover_automated.go:47-65`)
can never see the enlarged DS target set and arm an early push. B's DS is
in the target set from the instant of the spawn, but the push is gated by
the phase.

### 5.3 The tick — `ksk_rollover_automated.go`

Reorder the head of `RolloverAutomatedTick` so the row is loaded before
pipeline-fill (today it is loaded at `:184`, after). New shape:

```
 …existing lock / EnsureRolloverZoneRow / healBootstrapActiveAt / kStepScheduler…

 row   := LoadRolloverZoneRow(...)
 phase := row.RolloverPhase (default idle)
 algRoll := LoadKskAlgRollState(...)

 // NEW: detect and spawn (D-5)
 if algRoll == nil && phase == idle && !row.RolloverInProgress {
     if from, to, need := kskAlgRollNeeded(kdb, zone, pol); need {
         SpawnKskAlgRollover(conf, kdb, zone, from, to)
         reload row, phase, algRoll
     }
 }

 // pipeline-fill — suspended during an algorithm roll (D-8)
 if algRoll == nil { …existing fill loop… }

 …existing rollover_due / AtomicRollover block, unchanged
    (unreachable during a roll: rollover_in_progress is true)…

 switch phase { … }
```

`kskAlgRollNeeded` is the trigger predicate: the zone has exactly one
active SEP key, its algorithm ≠ `pol.KSKAlgorithm`, no roll of either role
is in flight, and `!zd.HasAutoRolloverImpactingError()`.

Per-phase changes, all guarded on `algRoll != nil`:

**`pending-child-publish`** (`:260-274`) — use the longer wait (D-7):

```go
wait := propagationDelay
if algRoll != nil {
    ttl, ok := effectiveServedDnskeyTTL(kdb, zone, pol)
    if !ok { log "deferring DS push: DNSKEY TTL not yet observable"; return nil }
    wait += ttl
}
```

**`pending-parent-push` / `pending-parent-observe` / softfail** — no
change. They push and confirm whatever `ComputeTargetDSSetForZone`
returns, which is `{DS(A), DS(B)}` (§1.1).

**confirm** — the confirmed branch (`:399-426`, and the softfail-recovery
twin at `:479-495`) currently calls `confirmDSAndAdvanceCreatedKeysTx` and
falls back to `idle`. Add the algorithm-roll fork:

```go
if algRoll != nil {
    // Retire the old-algorithm head and hand off to the withdraw phase,
    // in one transaction with the confirmed-range write.
    advanced, err = confirmDSAndRetireOldAlgHeadTx(kdb, zone, low, high, oldKid, now)
} else {
    advanced, err = confirmDSAndAdvanceCreatedKeysTx(kdb, zone, low, high, now)
}
```

`confirmDSAndRetireOldAlgHeadTx` is a sibling of the existing function
(deliberately separate, so no edit can regress the same-algorithm path):
`saveLastDSConfirmedRangeTx` + `UpdateDnssecKeyStateTx(oldKid, Retired)` +
`stampRolloverStateAtTx` + `clearObserveScheduleTx` +
`setRolloverPhaseTx(pendingChildWithdraw)`.

A retires but **keeps signing** — `sign.go` only strips an RRSIG when
re-signing with that key, and `PublishDnskeyRRs` still publishes `retired`
DNSKEYs. This is the drain-window double-signature, inherited from the
same-algorithm machinery (fifo FACT 3).

**`pending-child-withdraw`** (`:565-622`) — two changes:

1. Margin (F1). Replace `effectiveMarginForZone(kdb, zone, pol)` with

```go
func effectiveMarginForRoll(zd *ZoneData, kdb *KeyDB, zone string,
        pol *DnssecPolicy, algRoll *KskAlgRollState) (time.Duration, bool, error)
```

   returning `ok=false` (⇒ defer, log, retry next tick) when `algRoll !=
   nil` and `resolveDSTTL` reports the parent DS TTL unknown.

2. Strip (F2). Before each `UpdateDnssecKeyState(..., DnskeyStateRemoved)`,
   run the `key_state_worker.go:237-252` block verbatim: strip that
   keytag's RRSIGs, and on error `stillWaiting++; continue` rather than
   advancing the state.

**`completeRolloverWithdraw`** (`:1654-1678`) — add `clearKskAlgRollTx` to
the existing transaction, so the roll marker, `rollover_in_progress` and
the phase all clear atomically. Pipeline-fill resumes on the next tick and
refills the new-algorithm FIFO to `num_ds`; the idle branch's
`kskIndexPushNeeded` arms the push that shrinks the parent DS set to
`{DS(B)}`.

### 5.4 The invariant (D-9) — `ksk_rollover_atomic.go`, `keystore.go`

`pickActiveSEPTx` (`:157-184`): group the found keyids by algorithm.

- 0 actives → `(0, nil)`, unchanged.
- exactly one algorithm with exactly one active → return it, unchanged.
- one algorithm with >1 active → error, unchanged wording.
- two algorithms → error `"zone %s has active SEP keys of %d algorithms;
  a same-algorithm rollover is refused while an algorithm rollover is in
  flight"`. `AtomicRollover` is its only caller and is already gated by
  `rollover_in_progress`, so this is defence in depth.

Add `pickActiveSEPByAlgTx(tx, zone, alg)` for the spawn's step 2.

`RolloverKey` (`keystore.go:1581-1590`) — P0-2: collect the role-matching
actives instead of `break`ing on the first, and error when more than one
shares an algorithm. For the ZSK this means "one active, full stop"; for
the KSK it permits the algorithm-roll overlap. One rule, both jobs.

### 5.5 The entry layer

**`reconcileActiveKeyAlgorithms`** (`sign.go:303-393`). The KSK loop
(`:320-325`) becomes:

```go
for _, ksk := range dak.KSKs {
    if ksk.DnskeyRR.Algorithm == zd.DnssecPolicy.KSKAlgorithm { continue }
    if algRoll != nil && ksk.DnskeyRR.Algorithm == algRoll.FromAlg {
        // the draining old-algorithm head; the engine owns it
        continue
    }
    if zd.DnssecPolicy.Rollover.Method == RolloverMethodNone {
        return false, fmt.Errorf("KSK algorithm rollover requires an auto-rollover "+
            "policy (rollover.method is none) for zone %s …", zd.ZoneName)
    }
    // mismatch with an engine configured but no roll yet: the tick will
    // spawn one. Log and no-op — never the legacy synchronous retire.
    lgSigner.Info("active KSK algorithm differs from policy; the rollover engine "+
        "will spawn an algorithm roll on the next tick", …)
}
```

This mirrors the relaxed-ZSK branch (`:341-343`) exactly: no-op + log, with
the refusal retained only for the case nothing can carry the transition.
The leftover sweep below (`:357-390`) already defers KSK removals while
`rolloverInProgress`; extend the skip to cover `algRoll.FromAlg` keys
explicitly so the intent is readable rather than incidental.

**`changeZonePolicy`** (`apihandler_zone.go:733-843`). Replace the refusal
at `:778-781` with gates, then let the bind proceed:

```go
if kskChanged {
    if pol.Rollover.Method == RolloverMethodNone { refuse "no auto-rollover policy" }
    if row.RolloverInProgress || row.RolloverPhase != idle {
        refuse "a KSK rollover is already in progress; wait or cancel"      // K-3
    }
    if st := kskAlgRollInFlight(kdb, zone, curKSKAlg); st.InFlight {
        refuse "a KSK algorithm rollover is already in progress (%s→%s)"    // K-3 drain half
    }
    if st := zskAlgRollInFlight(kdb, zone, curZSKAlg); st.InFlight {
        refuse "a ZSK algorithm rollover is in progress; roll one role at a time"  // D-11
    }
    if zd.HasAutoRolloverImpactingError() { refuse with the error list }
}
```

and symmetrically add the KSK-in-flight check to the existing ZSK branch
(D-11). The success message mirrors the ZSK wording: bound, will roll
`from → to` via double-signature, this command does not perform the roll,
watch it with `auto-rollover status`.

`kskAlgRollInFlight` is the KSK twin of `zskAlgRollInFlight`
(`zsk_rollover.go:222-251`) with the K-3 additions. Implement both through
one role-generalized core (P0-4 / fifo §10.2):

```go
type AlgRollState struct {
    InFlight bool
    Role     string   // "KSK" | "ZSK"
    FromAlgs []uint8  // distinct non-target algorithms present (fixes P0-4)
    ToAlg    uint8
    Done, Total int
}
func algRollInFlight(kdb *KeyDB, zone string, sep bool, targetAlg uint8) (AlgRollState, error)
```

with the KSK wrapper OR-ing in `rollover_in_progress`, `phase != idle`,
and `alg_roll_from_alg IS NOT NULL`. `FromAlgs` as a set closes P0-4's
"names the wrong source algorithm" bug for both roles at once.

**`resetZonePolicy`** (`apihandler_zone.go:~860`) — unchanged in
behaviour, but its dry-run text should now say that a KSK algorithm change
has a supported gradual path (`policy-change`) and that `policy-reset` is
still the destructive shortcut that breaks the parent DS.

### 5.6 API, status, CLI

**`AlgTransitionInfo`** (`messages_rollover.go:230-236`) already carries
`Role`; its comment says "currently always ZSK". Populate a KSK instance
from `kskAlgRollInFlight` in `ComputeRolloverStatus`
(`rollover_api_funcs.go:86`). Make the field a slice —
`AlgTransitions []AlgTransitionInfo` — keeping `AlgTransition` as a
deprecated alias for one release so the CLI bump is not lockstep (the file
header at `:5-7` commits to name stability).

Add to `RolloverStatus`, all `omitempty`:

```go
AlgRollFromAlg   string `json:"algRollFromAlg,omitempty"`
AlgRollToAlg     string `json:"algRollToAlg,omitempty"`
AlgRollStartedAt string `json:"algRollStartedAt,omitempty"`
AlgRollHeadKeyID uint16 `json:"algRollHeadKeyid,omitempty"`
```

**Status rendering** (`cli/ksk_rollover_cli.go`, `status`) — the KSK key
table already prints `Algorithm` (`messages_rollover.go:167-170`), so the
overlap is visible for free. Add a header line above it:

```
KSK alg rollover: ED25519 → MAYO5 (double-signature), started 2026-09-08T10:14:02Z
  phase pending-parent-observe — DS {12345 ED25519, 56789 MAYO5} submitted, awaiting parent
```

**`headlineForPhase` / `hintForState`** (`rollover_api_funcs.go:515-563`)
— add algorithm-roll-aware hints, in particular for the two "waiting is
correct" states: waiting on `propagation-delay + DNSKEY_TTL` before the
push, and holding the old-algorithm key for `DS_TTL`-inclusive margin.

**`ComputeRolloverWhen`** (`:326`) — during an algorithm roll the KSK
schedule is not "the next lifetime roll"; report
`Status = "alg-rollover-in-progress"` with the projected completion
(`retired_at + effective_margin`) rather than a misleading `NextScheduled`.

**`asap --ksk`** — already refuses on `RolloverInProgress`
(`apihandler_rollover.go:132-135`), which is correct: an algorithm roll has
no standby to promote and drives itself. Improve the message to say so
during an algorithm roll instead of the generic "rollover already in
progress".

**Abort** (D-12) — extend `RolloverCancelRequest` with `AlgRoll bool`.
When set and `alg_roll_from_alg` is non-NULL and
`last_ds_confirmed_index_high` does not yet cover B's index: in one
transaction mark B `removed`, `clearKskAlgRollTx`,
`setRolloverInProgressTx(false)`, `setRolloverPhaseTx(idle)`; post-commit
republish + resign. The next idle tick re-pushes the shrunken DS set.
After confirmation, refuse with the "let it finish, then change-policy
back" guidance.

### 5.7 Validation invariants

`EvaluateRolloverPolicyInvariants` (`ksk_rollover_validation.go:36`) —
E5/E10/E11 are policy-shape checks and stay as they are. Add one
algorithm-roll-specific check, evaluated only while a roll is in flight:

- **E13** — `clamping.margin` (or the observed `max_observed_ttl`) plus
  the parent `DS_TTL` must be finite and observed, else the withdraw phase
  will defer indefinitely. Surface as a `RolloverPolicyWarning` naming
  `DS_TTL unknown — old-algorithm key hold is deferred until the parent DS
  TTL is observed`, so a stalled drain is diagnosable from `status` rather
  than only from logs.

Also confirm (K-9a, no change needed, note it so nobody "fixes" it): the
DS digest stays SHA-256 for both algorithms. The roll changes the DNSKEY
algorithm, not the DS digest type.


## 6. Build order

Each commit builds, tests green, and is independently revertible. Commits
1–3 are hardening that stands on its own merit; the feature is 4–8.

**1. `rollover: strip a removed KSK's RRSIGs before withdrawing it`**
(F2). Port the strip block into the withdraw branch. Fixes existing
same-algorithm behaviour. Test: KT-11.
*1 file, ~30 lines. Low risk.*

**2. `keystore: one active key per (role, algorithm)`** (D-9 / P0-2).
`pickActiveSEPTx` grouping + `pickActiveSEPByAlgTx` + the `RolloverKey`
guard. Tests: KT-10, P1-1.
*2 files, ~90 lines. Low risk, load-bearing.*

**3. `rollover: role-generalize the algorithm-roll in-flight predicate`**
(P0-4 + fifo §10.2). `algRollInFlight` core, `zskAlgRollInFlight` and
`kskAlgRollInFlight` as wrappers, `FromAlgs` as a set. Pure refactor plus
the P0-4 fix. Tests: existing ZSK re-entrancy tests must stay green;
KT-2d.
*3 files, ~120 lines. Low risk.*

**4. `rollover: persist KSK algorithm-roll state`**. Schema columns,
migration, `RolloverZoneRow` fields, `LoadKskAlgRollState` /
`setKskAlgRollTx` / `clearKskAlgRollTx`. No behaviour change.
*2 files, ~110 lines. Low risk.*

**5. `rollover: spawn a new-algorithm KSK FIFO`** — `ksk_rollover_alg.go`:
`kskAlgRollNeeded`, `SpawnKskAlgRollover`, and the tick reordering + spawn
call + pipeline-fill suspension (D-8). The engine can now enter the roll
but not yet finish it (the confirm branch still falls back to idle, which
leaves the zone double-signing with a mixed DS at the parent — safe, and a
good testbed checkpoint). Tests: KT-3, KT-3b, KT-4, KT-13.
*3 files, ~260 lines. **Highest-risk commit; testbed checkpoint here.***

**6. `rollover: retire the old-algorithm KSK on DS confirmation`** — the
longer `pending-child-publish` wait (D-7),
`confirmDSAndRetireOldAlgHeadTx`, the confirm fork in both the observe and
softfail-recovery branches, `effectiveMarginForRoll` (F1), and
`clearKskAlgRollTx` in `completeRolloverWithdraw`. The roll now completes.
Tests: KT-6, KT-7, KT-8, KT-14.
*2 files, ~200 lines. High risk.*

**7. `rollover: route a KSK algorithm change through the engine`** — the
`change-policy` gates (D-11 included) and the `reconcileActiveKeyAlgorithms`
hand-off. This is the commit that flips the two refusals
(`apihandler_zone.go:780`, `sign.go:322`) and makes the feature reachable.
Tests: KT-1, KT-2b, KT-2c, KT-2d, KT-9.
*2 files, ~150 lines. Medium risk — a wrong branch yields a refused or
stuck roll, never a bogus zone, because the synchronous retire is gone
entirely.*

**8. `rollover: surface the KSK algorithm rollover`** — status/when/hints,
`AlgTransitions`, the CLI header, the abort path (D-12), E13. Tests: KT-5,
KT-when, KT-abort.
*5 files, ~280 lines. Low risk.*

**Optional follow-ups, not required:** P2-1 flag constants, P2-4
`firstKeyOfRole`, P0-1/P0-3/P0-5 ZSK hygiene, and fifo D1/D2
(same-algorithm double-signature, the `AtomicRollover` "4E" deferral at
`ksk_rollover_atomic.go:18`).

### 6.1 Effort

Diff lines (added + modified), excluding comments-only churn. The
"modified" column is existing code touched in place — the two refusals
deleted, the tick reordered, the withdraw branch rewritten.

| # | Commit | New | Modified | Files |
|---|---|---|---|---|
| 1 | withdraw strip (F2) | 25 | 5 | 1 |
| 2 | one active per (role, algorithm) | 60 | 30 | 2 |
| 3 | role-generalized in-flight predicate | 85 | 35 | 3 |
| 4 | persist algorithm-roll state | 105 | 5 | 2 |
| 5 | spawn the new-algorithm FIFO | 215 | 45 | 3 |
| 6 | retire on confirm, margin, complete | 155 | 45 | 2 |
| 7 | route the change through the engine | 110 | 40 | 2 |
| 8 | status / when / CLI / abort / E13 | 240 | 40 | 5 |
| | **production total** | **995** | **245** | **~14** |

**~1240 lines of production diff**, of which ~1000 is new code. The two
riskiest commits (5 and 6) are ~460 of it.

Tests: the matrix in §8 is ~25 cases, several driving a full engine
sequence against fake time. Calibrating against `zsk_alg_rollover_test.go`
(751 lines for ~16 cases of a simpler, parent-free roll):

| File | Lines |
|---|---|
| `ksk_alg_rollover_test.go` (entry, spawn, sequence, KT-6/13/14/16) | ~750 |
| margin + strip table tests (KT-7, KT-11) | ~160 |
| invariant + hazard tests (KT-10, KT-12) | ~130 |
| status / when / abort (KT-5, KT-when, KT-abort) | ~170 |
| **test total** | **~1210** |

**Grand total ≈ 2450 lines.** Materially below the 2026-07-01 doc's
"materially larger than ~17–29 h" estimate, because per-FIFO state, FIFO
instantiation machinery, and the double-signature generalization all fell
away (§2, D-4). The count excludes the optional follow-ups (P2-1, P2-4,
P0-1/3/5, fifo D1/D2) and the testbed work (TB-1…TB-3), which is
observation rather than code.


## 7. Interactions to hold in mind

### 7.1 The DNSKEY RRset during the overlap

`{ KSK-A(active), KSK-B(active), ZSK(active) }` with `RRSIG(A)` and
`RRSIG(B)` over it. When one algorithm is post-quantum (MAYO5, SNOVA) this
RRset is large and TCP-only — which is the alg-split steady state
`dnssec.large-algorithms` / `large_ksk.go` already targets (K-9e). Verify
on the testbed at commit 5, do not pre-emptively change transport code.

### 7.2 CDS

`ComputeTargetCDSSetForZone` derives from the same
`loadTargetKSKsForRollover` rows as the DS set (`ksk_rollover_ds_push.go:
93-96` states this is a requirement), so a NOTIFY-scheme push publishes a
mixed CDS matching the mixed DS with no change. `cleanupCdsAfterConfirm`
fires on confirmation as usual.

### 7.3 Delegation-sync must stay hands-off for the whole roll

`rolloverOwnsDS()` (`delegation_utils.go:650-670`) returns true whenever
`rollover_in_progress` **or** `phase != idle`, and both
`AnalyseZoneDelegation` (`:190`) and `computeNewDS`
(`zone_updater.go:1839`) defer to it. This matters more here than for a
same-algorithm roll, because `DSIntentForZone` classifies `retired` as
"DS does not belong at the parent" (`ds_intent.go:44-53`) — the exact
opposite of what the drain window needs. As long as the roll keeps
`rollover_in_progress = true` from spawn through
`completeRolloverWithdraw` (it does, §5.2 step 6 and §5.3), the interlock
holds. **Any future change that clears `rollover_in_progress` early would
silently withdraw `DS(A)` mid-drain.** Add a test (KT-15) that pins it.

### 7.4 `transitionRetiredToRemoved` and the generic worker

`key_state_worker.go:195-199` skips SEP keys in zones with a rollover
method — so the generic worker will not remove the draining
old-algorithm KSK behind the engine's back, and will not apply the
narrower `propagationDelay` margin to it. Unchanged, but it is the reason
F1's wider margin is actually honoured.

### 7.5 States that must not select B

The multi-DS-only transitions
(`TransitionRolloverKskDsPublishedToPublished` `:1029`,
`TransitionRolloverKskPublishedToStandby`) are gated on
`Rollover.Method == RolloverMethodMultiDS` *and* select only
`ds-published` / `published` keys. B is minted straight into `active`, so
it is invisible to both regardless of method. No change needed; assert it
(KT-13).

### 7.6 Not in scope

CSK algorithm rollover (still refused at the entry layer); both-role
rollover in one window (refused, D-11); multiple DS digest types (K-9a);
multi-provider (`OptMultiProvider`) zones, which have their own key-state
worker and keystore and are skipped by every path touched here.


## 8. Test matrix

New file `ksk_alg_rollover_test.go`, modelled on `zsk_alg_rollover_test.go`
(real on-disk `KeyDB` via `newTestKeyDB`, `sign_reconcile_test.go:93`;
package-global `Conf`; a fake-time `deps.Now`). Parent DS observation uses
the injected-observed-set seam the existing KSK engine tests use
(`ksk_rollover_parent_poll_test.go`).

**Entry layer**

- **KT-1** — reconcile with active KSK alg ≠ policy and an engine
  configured: does NOT retire, does NOT refuse (logs, no-ops). Both
  completeness modes identical (D-10).
- **KT-1b** — same, but `rollover.method: none`: REFUSES.
- **KT-2b** — a CSK algorithm change refused at entry; no key churn.
- **KT-2c** — a both-role target refused BEFORE any override write.
- **KT-2d** — re-entrancy, four sub-cases: (i) a second `change-policy`
  mid-DS-dance (`rollover_in_progress`), (ii) mid-drain (old-alg key still
  `retired`), (iii) a KSK change while a ZSK alg roll drains, (iv) a ZSK
  change while a KSK alg roll drains. All refused (D-11).

**Spawn**

- **KT-3** — `change-policy` + one tick mints exactly ONE new-algorithm
  KSK, straight into `active`; the old-algorithm active KSK is untouched.
- **KT-3b** — the minted key carries the NEW algorithm and gets a
  `RolloverKeyState` row with `active_at`, `active_seq`, and a
  `rollover_index` above the old head's.
- **KT-4** — freeze: old-algorithm `created`/`published`/`standby` keys go
  to `removed` at spawn; the active head does not.
- **KT-13** — pipeline-fill mints nothing while the roll is in flight
  (D-8), and the multi-DS-only transitions do not select B (§7.5).
- **KT-16** — the signer double-signs: after the spawn's re-sign, the apex
  DNSKEY RRset carries exactly two RRSIGs, one per algorithm, and no
  other RRset gained a second RRSIG.

**Sequence**

- **KT-6 (full sequence)** — bind → spawn → double-sign → wait → mixed DS
  push → parent confirms BOTH → retire A → margin → remove A → DS shrinks
  to `{DS(B)}` → `alg_roll_*` cleared, `rollover_in_progress` false, phase
  idle. Assert at **every** step: at least one complete DS→DNSKEY→RRSIG
  chain exists, and the "one active per (role, algorithm)" invariant holds.
- **KT-8** — mixed-alg DS confirm: `ObservedDSSetMatchesExpected` confirms
  only when both DSes are present; either alone does not.
- **KT-14** — the DS push does not fire before
  `propagation-delay + DNSKEY_TTL` has elapsed from the spawn (D-7); and
  when the DNSKEY TTL is not yet observable, the phase defers rather than
  advancing.
- **KT-7 (margin, F1)** — table test on `effectiveMarginForRoll`: the
  retired old-algorithm KSK is NOT removed before
  `max(clamping.margin, max_observed_ttl, DS_TTL + ds-publish-delay)`
  elapses from `retired_at`; is removed just after; and the removal is
  DEFERRED (not advanced with a smaller margin) when the parent DS TTL is
  unknown. Assert the same-algorithm path keeps the narrower margin.
- **KT-11 (strip, F2)** — after a retired KSK reaches `removed` via the
  withdraw phase, no RRSIG by that keytag remains in the served zone; and
  a strip failure leaves the key `retired` for retry.
- **KT-9** — a `zone reload` (re-parse + re-sign) mid-roll does not retire
  the old-algorithm active KSK and does not clear the roll state.
- **KT-15 (§7.3)** — while the roll is in flight, `computeNewDS` and
  `AnalyseZoneDelegation` claim no authoritative DS set; a resolver-visible
  `DS(A)` withdrawal is impossible from the childsync path.

**Invariant / hazard**

- **KT-10 (D-9)** — `pickActiveSEPTx` returns the single active per
  algorithm, errors on two same-algorithm actives, and errors distinctly
  on two different-algorithm actives; `RolloverKey` errors rather than
  silently retiring one of two same-algorithm actives (P0-2 / P1-1).
- **KT-12 (D-9 hazard)** — a guard test that fails loudly if a future
  strip/resign change removes an active KSK's RRSIG from the apex DNSKEY
  RRset. This is the tripwire for P0-6 landing wrong.

**Operator surface**

- **KT-5** — `auto-rollover status` shows the KSK algorithm transition
  (from/to, phase, both keys with their algorithms) throughout the roll,
  derived from the shared in-flight predicate.
- **KT-when** — `auto-rollover when --ksk` reports
  `alg-rollover-in-progress` with a projected completion rather than a
  misleading next-scheduled; `asap --ksk` is refused with the
  algorithm-roll-specific message.
- **KT-abort (D-12)** — cancel before confirmation removes B and returns
  to idle; cancel after confirmation is refused with the
  finish-then-reverse guidance.

**Testbed (not unit-testable)**

- **TB-1** — commit 5 checkpoint: a live zone enters the double-signed
  state with a mixed DS at a real parent, and stays valid throughout.
- **TB-2** — one algorithm large (MAYO5): the overlap-window apex DNSKEY
  and CDS RRsets transport correctly over TCP (K-9e).
- **TB-3** — a parent advertising no usable DSYNC scheme: the roll stalls
  in `child-config:waiting-for-parent` softfail indefinitely and the zone
  stays valid (the "blocked, safely" mode). Verify the status hint says
  so.


## 9. Open questions

1. **Should `change-policy` warn at bind time when the parent advertises
   no DSYNC scheme?** Cheap, and otherwise the roll silently sits in
   softfail (TB-3). Recommend yes, as a warning in the bind response.
2. **`num_ds` after the roll.** Pipeline-fill resumes and refills the
   new-algorithm FIFO to `num_ds` one key at a time, each via a DS push.
   For `num_ds: 3` that is two extra push/confirm cycles after the roll
   completes. Acceptable, but worth confirming the operator expects the
   post-roll settling period.
3. **Does the roll need a wall-clock ceiling?** Nothing currently
   time-limits the double-signed state — a parent that never confirms
   leaves the zone double-signing indefinitely (safe, but invisible unless
   someone reads `status`). A `RolloverPolicyWarning` after, say,
   `2 × confirm-timeout` in the roll would surface it. Recommend adding it
   with E13 in commit 8.
4. **`policy-reset` wording** (§5.5). Confirm the operator-facing text
   change is wanted now that a gradual KSK path exists.


## 10. Risk and blast radius

### 10.1 The dominant safety property

Every failure mode of a wrong branch is **"refused" or "stuck", never
"bogus zone"**, because the legacy synchronous retire is *deleted* rather
than rerouted. There is no code path in this plan that retires a KSK
without either (a) the parent having confirmed a DS for its successor, or
(b) the successor already signing the apex DNSKEY RRset. A mis-implemented
gate yields a roll that does not start, or one that sits in a phase
forever with the zone fully valid and double-signed — both visible in
`auto-rollover status`, neither resolver-visible.

### 10.2 Additive vs. in-place

Roughly 80% of the diff is additive — new file, new sibling functions,
nullable columns — and cannot regress anything by construction:

`ksk_rollover_alg.go` (whole file), `confirmDSAndRetireOldAlgHeadTx` (a
deliberate sibling of `confirmDSAndAdvanceCreatedKeysTx`, not an edit to
it), `LoadKskAlgRollState` / `setKskAlgRollTx` / `clearKskAlgRollTx`,
`keyFifo`, `pickActiveSEPByAlgTx`, and the four `ALTER TABLE` columns.

The in-place edits are the whole regression surface, ranked:

| Edit | Fan-in | Why it is / is not risky |
|---|---|---|
| `pending-child-withdraw`: F2 strip + margin signature | every rollover zone | **Highest.** The strip changes shipped same-algorithm behaviour (intentionally — it is the bug fix). Fail-soft by design: a strip error leaves the key `retired` and retries. |
| `RolloverAutomatedTick` head reordering | every rollover zone, every tick | **Structural but verified pure** — see 10.3. |
| `reconcileActiveKeyAlgorithms` KSK branch | 35 upstream call sites via `EnsureActiveDnssecKeys` | Hottest path touched, but the change is refusal → no-op+log: strictly *fewer* failures. Adds **no query** — the function already calls `LoadRolloverZoneRow` (`sign.go:311`), so the four new columns ride along free. |
| confirm branches (observe + softfail-recovery) | every rollover zone | Forked on `algRoll != nil`; the same-algorithm arm calls the existing function unchanged. Note there are **two** call sites (`:403`, `:479`) — missing the second is the likeliest slip. |
| `pending-child-publish` wait | every rollover zone | Guarded; same-algorithm path byte-identical. |
| `RolloverKey` single-active guard | 2 callers | See R2. |
| `pickActiveSEPTx` grouping | 1 caller (`AtomicRollover`) | Negligible. |
| `changeZonePolicy` KSK branch | — | Currently an unconditional refusal, so nothing depends on it succeeding. |

### 10.3 The tick reordering, verified

Moving `LoadRolloverZoneRow` above the pipeline-fill loop is the most
structurally invasive edit. It is safe because **pipeline-fill writes
nothing that `RolloverZoneRow` carries**: its only `RolloverZoneState`
write is `next_rollover_index` (via `nextRolloverIndexTx`,
`ksk_rollover_zone_state.go:209`), and that column is *not* in
`LoadRolloverZoneRow`'s SELECT list (`:115-127`) nor in the struct
(`:13-73`). The fields the phase switch reads — phase, phase_at, observe
schedule, softfail, DS ranges — are untouched by the fill. The fill's
DnssecKeyStore writes are re-read fresh by `ComputeTargetDSSetForZone` in
the idle branch, not from `row`.

Pin this with a test, because a future field added to `RolloverZoneRow`
that pipeline-fill *does* write would silently reintroduce staleness.

### 10.4 Regression surfaces found while scoping this section

Four items, none in §5–§8 as originally written. R1 and R2 are required
work, not optional.

**R1 — the config-reload guardrail refuses the whole reload.**
`policyAlgStrandsActiveKeys` (`config_reload_guardrail.go:96`) encodes, in
code and in its doc comment, "A KSK/CSK algorithm change is a strand in
either mode (no automatic KSK-algorithm rollover exists)", and
`detectStrandingPolicyChanges` (`:158`) **refuses the WHOLE reload
atomically** on a finding (`:22`). Its CLI-side twin `missingRoleAlgs`
(`cli/config_check_cmds.go:1322`) predicts the same. After commit 7 both
are wrong: a KSK algorithm change made in YAML would still be refused at
reload, making the feature reachable only via `policy-change`. Both must
be updated in commit 7, mirroring how they already special-case the
relaxed-mode ZSK roll as "not a strand". **Add to commit 7: ~40 lines,
2 files, plus a guardrail test.**

**R2 — the manual `keystore rollover` path.** `RolloverKey` has a second
caller at `keystore.go:647` (the `rollover` keystore operation), which
accepts `keytype: "KSK"`. During the overlap the zone has two active SEP
keys of different algorithms, and that path takes "the first
role-matching active" — arbitrary between A and B. The D-9 guard as
specified (error only on >1 active sharing an *algorithm*) would not
catch it. Add an explicit refusal when an algorithm roll is in flight:
"manual KSK rollover refused while a KSK algorithm rollover is in
progress". **Add to commit 2: ~15 lines.**

**R3 — JSON wire-contract skew.** `messages_rollover.go:3-7` states the
field names lock the API contract and must not be renamed without a
coordinated CLI bump. Turning `AlgTransition` into `AlgTransitions`
crosses that line. The plan's deprecated-alias approach handles it, but
the ordering matters: ship the server emitting **both** fields for one
release, and only drop the singular once the CLI floor moves. An old CLI
against a new daemon otherwise silently stops showing ZSK algorithm
transitions.

**R4 — `EffectiveMarginForZone` is exported with zero in-repo callers**
(`ksk_rollover_automated.go:1626`, "the exported alias used by the
auto-rollover…"). It is either dead or consumed out-of-tree (tdns-mp is
the likely candidate). **Do not change its signature.** Add
`effectiveMarginForRoll` alongside and leave the exported alias
delegating to the existing two-argument form.

### 10.5 The feature is dormant until commit 7

Commits 1–6 cannot start a rollover, because the state that triggers one
— an active KSK whose algorithm differs from the bound policy's — is
unreachable while `changeZonePolicy` (`apihandler_zone.go:780`) and
`reconcileActiveKeyAlgorithms` (`sign.go:322`) still refuse it, and the
reload guardrail (R1) blocks the YAML route. So 1–6 can be merged and
soaked in production ahead of the switch, and commit 7 is a small,
revertible flip.

**One caveat, and a pre-flight check.** If a zone is *already* in the
mismatch state — hand-edited keystore, or stranded before the guardrail
existed — commit 5 would spawn a roll on it at the next tick. Such a zone
is one the signer is currently refusing to sign, so it is not healthy
either way, but the spawn should not be a surprise. Before deploying
commit 5, run:

```sql
SELECT k.zonename, k.keyid, k.algorithm
FROM DnssecKeyStore k
WHERE k.state = 'active' AND (CAST(k.flags AS INTEGER) & 1) = 1;
```

and compare each against its zone's bound `KSKAlgorithm`. Expect zero
rows to differ.

### 10.6 Baseline and coverage

Measured on `f4bea22`, 2026-09-08: `go test ./...` passes, 1522 test
functions in the `v2` package. Across 8 consecutive runs, 7 were clean and
the first failed somewhere in the AXFR / zone-transfer tests (`up.example.`
transfers on random ports) — **the suite carries at least one timing
flake**, which matters here only because it makes a failure harder to
attribute to a change. Worth isolating before commit 6.

The uncomfortable asymmetry: the KSK engine is the **least**-covered thing
this plan modifies most.

| Area | Test funcs |
|---|---|
| ZSK algorithm rollover (`zsk_alg_rollover_test.go`) | 19 |
| Reconcile (`sign_reconcile_test.go`) | 5 |
| Reload guardrail | 5 |
| KSK standby-time / DNSKEY-TTL / softfail / api-gate | 8 |
| **KSK automated engine (`ksk_rollover_automated_test.go`)** | **1** |

The withdraw phase, the confirm branches and the tick head — the three
most invasive edits in 10.2 — sit behind that single test. **Commits 1
and 2 should each land with their own tests before the feature commits
build on them** (KT-11 and KT-10 respectively); they are the cheapest
place to add coverage to code that currently has almost none, and they
are useful regardless of whether the rest of this plan is built.
