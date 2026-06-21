# Algorithm rollover via the auto-rollover engine

Status: DESIGN + IMPLEMENTATION PLAN — FINAL, ready to implement. Three
independent review passes complete; pass 3 verdict "implement §8 as
written." Nothing implemented yet. §0–§7 are the design/rationale; §8 is
the turnkey build order for the first step (relaxed-mode ZSK algorithm
rollover), with resolved mechanical decisions (D1–D5), test cases, and
success criteria. Remaining §6 open items (CSK handling, multi-ds vs
double-signature, strict-mode alg rollover, large-zone secondary
propagation) are LATER steps, out of scope for the first.

Branch context: dnssec-policy-change-phase1-2. Builds on the per-role
KSK/ZSK algorithm work (PR #259) and the policy-change work documented in
`2026-06-16-dnssec-policy-change-handling.md`.

This work is EXPERIMENTAL. The goal is a correct, safe algorithm rollover
for the alg-split / post-quantum transition; it is not constrained by what
currently-deployed validators happen to tolerate.


## 0. Goal

Support an ALGORITHM rollover — changing a zone's DNSSEC signing algorithm
(KSK or ZSK) — that coordinates correctly with the parent-side DS RRset.

Two existing subsystems are relevant:

1. `auto-rollover` — automatic KSK rollover that coordinates with the
   parent DS RRset (publish new DS, confirm it appeared at the parent,
   then retire the old key).
2. Dynamic policy change (`zone set-policy`, reconcile on reload) — can
   change a zone's signing algorithm, but only zone-side, with no parent
   coordination.

The design: route algorithm changes into the auto-rollover engine. The
only change to the rollover machinery is the ALGORITHM the key generator
mints. No new key state, no new promotion logic, no parent special-casing.


## 1. The auto-rollover engine today

A parent-aware KSK rollover engine (multi-ds method), built around the key
lifecycle `created → ds-published → standby → active → retired → removed`.

Phase machine:

```
idle
  → pending-child-publish      (wait propagation_delay)
  → pending-parent-push        (send DS UPDATE and/or publish CDS)
  → pending-parent-observe     (POLL parent until DS actually appears)
  → idle                       (on confirm: advance keys)
     | parent-push-softfail    (on timeout: long-term retry, keeps polling)
  → pending-child-withdraw     (wait cache TTLs before removing old keys)
```

Two properties matter for algorithm rollover:

**The standby gate.** A key reaches `standby` only when it is fully
propagated — for a KSK that means its DS is confirmed present at the
parent (the engine polls the parent agent via `PollParentDSUntilMatch` /
`ObservedDSSetMatchesExpected` and compares against `last_ds_confirmed_*`,
parent reality, not `last_ds_submitted_*`). `AtomicRollover`
(`ksk_rollover_atomic.go:79-95`) only ever promotes a `standby` key. So
the old key is never retired until the new key's full chain is live and
propagated.

**Algorithm-blindness.** The pipeline never inspects key algorithm:
- `loadTargetKSKsForRollover` (`ksk_rollover_ds_push.go:83`) selects all
  SEP keys by state, no algorithm filter; `ComputeTargetDSSetForZone`
  `ToDS()`-es each. A DS RRset spanning two algorithms is computed
  identically to a single-algorithm one.
- The pipeline counters and circuit breaker
  (`ksk_rollover_pipeline.go:142,158`) count by SEP flag and state, not
  algorithm.
- Promotion (`ksk_rollover_atomic.go:86`) picks the next `standby` by
  oldest `published_at` — a FIFO, algorithm-independent.

The one thing tied to algorithm: pipeline-fill mints new keys with
`pol.KSKAlgorithm` (`ksk_rollover_automated.go:176`). And the trigger
(`rolloverDue`, `ksk_rollover_automated.go:1534`) fires only on KSK
lifetime expiry or manual ASAP — there is no algorithm-change trigger.


## 2. Why the policy-change reconcile cannot do a KSK algorithm rollover

`reconcileActiveKeyAlgorithms` (`sign.go:286`) handles an algorithm change
zone-side: retire the old-alg active KSK (keeping its DNSKEY published and
RRSIGs served), generate a new-alg KSK straight into `active`, double-sign,
and let the KeyStateWorker later remove the old key and strip its RRSIGs.

For a ZSK this is sound — ZSKs have no parent dependency. For a KSK it
produces a bogus zone:

- The new-alg KSK is activated immediately, bypassing the `standby` gate —
  its DS is never pushed to or confirmed at the parent.
- After propagation_delay the old-alg KSK goes retired → removed and its
  RRSIGs are stripped.
- The parent's only DS is now the old-alg one, whose key and signature are
  being removed, with no confirmed new-alg DS to fall back to → no working
  DS→DNSKEY chain → bogus.

The defect is the bypassed standby gate, not the zone-side mechanics. The
fix is to route the KSK algorithm change through the engine so the gate
applies — not to add DS handling to the reconcile.


## 3. Design

### 3.1 The change

The rollover engine is a FIFO pipeline and is algorithm-blind at every
step (§1). An algorithm rollover is: the key generator starts minting new
keys with the new algorithm. The new-alg key enters the pipeline,
propagates, reaches `standby`, and is promoted in FIFO order when its turn
comes; the old-alg key retires and drains normally.

The DS RRset at the parent is mixed-algorithm (old-alg DS + new-alg DS)
for the duration of the window. The engine computes, pushes, observes, and
shrinks it exactly as for a single-algorithm rollover.

The key lifecycle is `active → retired → removed` — no `semi-active` or
other new state, no algorithm-aware promotion, no parent-side
special-casing. What differs from a same-algorithm roll is how long the
old-alg key stays `active`: in strict-completeness mode it stays active
(signing) through the drain window; in relaxed mode it retires when the
switch happens (§3.2). Promotion and DS handling are identical in both.

### 3.2 The overlap window: two constraints in tension

Two hard constraints govern the old-alg key while it is being phased out.

- DRAIN. A key MUST remain in the apex DNSKEY RRset until all RRSIGs it
  made have expired from every cache. A resolver fetches RRsets and the
  DNSKEY RRset on independent TTL schedules; if it holds a cached RRset
  with an old-alg RRSIG but fetches a fresh DNSKEY RRset from which the
  old-alg DNSKEY is already gone, that cached RRSIG references an absent
  key → bogus. This is what `retired` is for: the DNSKEY stays published
  and the old RRSIGs stay served (the additive signer never strips a
  non-active key's signature, `sign.go:180-197`) for propagation_delay +
  max served TTL (`zskRemovalMargin`, `key_state_worker.go:209-222`), then
  removed + strip.

- COMPLETENESS (RFC 4035 §2.2). While an algorithm is present in the apex
  DNSKEY RRset, every covered RRset MUST carry a fresh RRSIG by that
  algorithm.

Together they conflict for a ZSK: drain keeps the old-alg DNSKEY published
through the whole drain window, and completeness then demands the zone keep
carrying FRESH old-alg RRSIGs over everything that key signed for that
whole window. "Fresh" means maintained — a `retired` key does not sign, so
its RRSIGs expire mid-drain and completeness fails. Under strict §4035,
there is no way out: the old-alg ZSK must stay ACTIVE and signing the whole
zone for the entire drain. That is the maintained double-signature, and it
is intrinsic to a ZSK algorithm rollover under strict completeness — not an
artifact of this design.

The escape is the key observation that **completeness binds the signer,
not the validator**. A validator needs one usable RRSIG per RRset and one
working DS→DNSKEY chain (RFC 6840 §5.11, §5.9); it does NOT enumerate the
DNSKEY algorithms and require coverage for each. So a zone that serves
only new-alg RRSIGs over its RRsets while the old-alg DNSKEY is still
present (draining) VALIDATES correctly at every resolver — it merely
violates the §4035 signer-side MUST, which no validator enforces. This is
exactly what draft-johani-dnsop-dnssec-alg-split formalizes (§4.3).

### 3.2.1 Two signer modes

The signer therefore supports two completeness modes, and the algorithm
rollover behaves differently in each. Mode is a configuration/policy
choice (§4.4).

- STRICT mode (honors RFC 4035 §2.2). The old-alg key stays ACTIVE and
  signing for the full drain window (maintained double-signature), then
  active → retired → removed. Interoperable with a strict validator or
  zone checker; the traditional behavior.
- RELAXED mode (alg-split semantics). The old-alg key goes straight to
  `retired` when it stops signing — no maintained double-signature. Drain
  is satisfied (DNSKEY stays published, old RRSIGs stay served through
  `retired`); completeness is deliberately not honored, because no
  validator needs it. No new key state.

Per-role cost:

- KSK-alg roll: the KSK signs only the apex DNSKEY RRset, so even strict
  mode adds at most one maintained RRSIG on one RRset (TCP-transported
  regardless). The two modes are effectively the same here — cheap either
  way. The DS dimension is governed by the standby gate (§1) in both.
- ZSK-alg roll: the ZSK signs the whole zone. STRICT = whole-zone
  maintained double-signature for the full drain (expensive). RELAXED =
  drain-only, no double-signature (cheap). This is the case the two modes
  diverge on, and the case alg-split exists to make cheap. Under the
  alg-split regime the common PQ transition is a KSK-only roll, avoiding
  the ZSK whole-zone cost entirely.

In RELAXED mode the old-alg key's drain state is plain `retired`, verified
to work as-is: `FetchZoneDnskeysSql` keeps `retired` DNSKEYs in the served
RRset, the additive signer preserves their already-made RRSIGs without
refreshing them, and the retired→removed worker holds the key for
propagation_delay + max TTL before stripping. No new state, no change to
the drain path.

### 3.3 Why it is safe

The safety rests on the entry gate (the new algorithm is fully propagated
before the old key stops being primary — DS confirmed at the parent via
the standby gate for a KSK, DNSKEY propagated for a ZSK) and two facts
about how the zone is served:

- A parent DS with no matching working key is harmless. RFC 6840 §5.9: a
  validator needs only one working DS→DNSKEY chain; a DS that does not
  resolve to a usable key is skipped, not treated as failure. Likewise a
  validator needs only one usable RRSIG per RRset, not one per algorithm
  (RFC 6840 §5.11).

- `retired` drains correctly: a retired key's DNSKEY stays in the apex
  RRset (`ops_dnskey.go:24`) and its already-made RRSIGs stay served (the
  additive signer never strips a non-active key's signature) for
  propagation_delay + max TTL, so every cached old signature can be
  validated against the still-present DNSKEY until it expires; then the
  key is removed and its signatures stripped.

The new-alg chain is complete and propagated before the old key is
demoted, so it validates every RRset on its own throughout — that holds in
both modes, and is the core invariant. The modes differ only in what the
old algorithm contributes during drain:

- STRICT: the old-alg key stays active and keeps signing, so the served
  zone honors §4035 completeness at every instant (both algorithms cover
  every RRset). A restart/ResignZone is harmless — both keys are active
  and re-emit both signatures.
- RELAXED: the old-alg key is `retired`; the served zone carries only
  new-alg RRSIGs over its RRsets while the old-alg DNSKEY drains. Every
  resolver still validates (new-alg coverage is complete; old-alg RRSIGs
  still resolve cached data against the still-present old-alg DNSKEY). The
  §4035 completeness MUST is not honored, by design (§3.2). A
  restart/ResignZone is harmless — the new-alg chain alone validates
  everything.

In neither mode is there an instant with zero working chains, and in
neither does a cached old-alg RRSIG ever reference an absent DNSKEY (drain
guarantees the DNSKEY outlives its signatures).

For the KSK, this is the multi-DS (double-DS) rollover of RFC 7583:
publish the new DS and confirm it at the parent, promote, then withdraw
the old DS and drain. Pre-publishing the DS (a hash) without yet serving
the DNSKEY also shrinks the window in which the new key's public value is
exposed — the reason multi-DS is the natural shape for a post-quantum KSK
rollover.

### 3.4 Trigger, the policy override, and reconcile

- TRIGGER: an operator command modelled on `auto-rollover asap`:
  `auto-rollover policy-change -z <zone> -p <policy>`, which tells the
  engine to roll the zone toward the new policy's algorithm.
  (Trigger-surface alternatives in §6.)
- POLICY OVERRIDE (DB): `change-policy` writes the zone→target-policy
  mapping into the SAME `ZonePolicyOverride` table that `set-policy` uses
  (`db_zone_policy_override.go`), at the START of the roll. This is
  required, not incidental: the bound policy (resolved via
  `EffectiveDnssecPolicyName` at zone load/refresh, `refreshengine.go:212,
  340,531`) is what makes future-generated keys carry the NEW algorithm
  (§4.6, the KISS FIFO model — note: with role-only counting, no new key
  is generated until the count actually drops; the override does NOT
  trigger eager minting) and what lets a mid-roll restart resume toward
  the right target instead of reverting to the old policy and stalling the
  roll. The override stores ONLY the target policy name — never an
  intermediate "both algorithms" policy (there is none; §4.1 / mode is
  global, §4.4).
- "ROLL IN PROGRESS" is derived from KEY STATE (an active key whose
  algorithm ≠ the bound policy's algorithm), NOT from override≠YAML —
  because `set-policy` already legitimately leaves override≠YAML after a
  COMPLETED manual change. No new table or in-progress column is needed.
- RECONCILE: `change-policy` is essentially `set-policy` MINUS the
  synchronous reconcile. `set-policy` today writes the override, rebinds
  `zd.DnssecPolicy`, and calls `SignZone(force)` which synchronously
  retires old / generates new (the §2 unsafe path for an algorithm
  change). `change-policy` writes the override and rebinds in-memory (so
  the running standby maintainer sees the new policy at once), but hands
  off to the engine instead of the synchronous swap.
  `reconcileActiveKeyAlgorithms` no longer performs the immediate active →
  retired swap on an algorithm mismatch; it hands the rollover to the
  engine (§3.5, §4.4 relaxed mode).

These three land TOGETHER. Writing the override without gating the
synchronous reconcile gives the unsafe immediate swap; gating the reconcile
without writing the override gives a roll that does not survive restart
(future keys would still be minted with the old algorithm).

### 3.5 Ownership

The engine owns all KSK state transitions. The reconcile only ever acts on
ZSKs, and on a KSK whose algorithm differs it hands off to the engine and
otherwise leaves the key alone.

This matters because the two are not symmetric subsystems. auto-rollover
is the automated production path. The policy-change reconcile is a manual
operator action and, in practice, a testing tool — it runs when an
operator abruptly flips a zone from policy A to policy B without staging,
which is not a production workflow. It must not race the engine for KSK
state.


## 4. Design decisions

### 4.1 One algorithm role at a time

An algorithm rollover rolls exactly one role at a time — either the KSK
algorithm or the ZSK algorithm, never both in one window. A policy change
whose target differs in both roles is rejected with a diagnostic; the
operator issues two rolls in sequence.

The two rolls have disjoint constraint structures:

- KSK-alg roll: parent-coupled, zone-cheap. The work is the external DS
  dance (push → confirm-at-parent → withdraw); the zone cost is one extra
  RRSIG over the apex DNSKEY RRset during the overlap, and that RRset is
  expected to go over TCP regardless.
- ZSK-alg roll: parent-free, zone-heavy in strict mode. No parent
  interaction; in strict-completeness mode the whole zone is double-signed
  for the drain window (§3.2), in relaxed mode it is not. Either way a
  purely local operation — the zone owns all TTLs and RRSIG lifetimes — so
  the window can be trimmed tightly.

Rolling one role at a time keeps each roll in its own regime, with a single
locus of mixed-algorithm state, and avoids interleaving (e.g. a stuck
parent DS push holding the whole-zone double-sign open). It costs little:
the KSK roll's clock is dominated by external parent-DS + cache TTL, the
ZSK roll's by local TTLs; combining them does not shorten the dominant
pole. The two single-role rolls are independent in correctness, so order
is the operator's choice (KSK-first is a reasonable convention).

### 4.2 Mixed-algorithm CDS at the parent

During a KSK-alg roll the CDS RRset (NOTIFY path) spans both algorithms.
The parent must accept a multi-algorithm CDS and apply the union, and the
eventual old-alg DS withdrawal must be driven through CDS withdrawal as
well as UPDATE. In the experimental setup the parent is under our control,
so this is a parent-side requirement to satisfy, not an external
constraint.

### 4.3 Algorithm completeness and the two signer modes

RFC 4035 §2.2 requires a zone to be signed with every algorithm in the
apex DNSKEY RRset — a signer-side MUST that no validator enforces (§3.2).
draft-johani-dnsop-dnssec-alg-split relaxes it for an algorithm used
solely by a KSK, making a distinct KSK algorithm an intended steady state
(PQ KSK over EC ZSK), not a transient. A KSK-only algorithm roll is
therefore a first-class scenario.

The signer supports two completeness modes (§3.2.1): STRICT (honors §4035;
maintained double-signature through drain) and RELAXED (alg-split; drain
only, no maintained double-signature). The rollover is valid at every
instant in both. The mode is a GLOBAL config choice (§4.4).

### 4.4 Mode selection — global

DECISION: completeness mode is a GLOBAL setting,
`dnssec.completeness: strict|relaxed`, default `strict`. It sits in the
`dnssec:` block alongside `split_algorithms` / `large_algorithms`, which
are likewise deployment-wide.

It is NOT per-zone or per-policy, for two reasons:

- It is a property of "which validators must we satisfy" — a
  deployment-wide fact (the same validator population resolves all of an
  operator's zones), not something a zone acquires from the policy it
  happens to roll into.
- A per-policy knob is incoherent for the rollover itself: the mechanic
  operates DURING the transition between a source and a target policy, so
  it cannot depend on either policy's setting without an ill-defined case
  (source strict, target relaxed → which mechanic?). The mode must be
  constant across the transition, i.e. a property of the signer/deployment.

Strict is the conservative default and the only mode that produces
§4035-conformant zones a strict checker accepts; relaxed is the
alg-split/PQ-transition mode that makes the ZSK-alg roll cheap. KSK-alg
rolls are effectively identical in both modes (§3.2.1), so the mode
matters in practice only for the ZSK-alg roll.

The mode also selects the STANDBY-COUNTING DISCIPLINE, which is the
structural difference between the two modes for a ZSK roll — not merely a
reconcile-retire detail:

- RELAXED: completeness does not require per-algorithm coverage, so the
  zone needs `standby_zsk_count` standby ZSKs in TOTAL, regardless of
  algorithm. Count standbys BY ROLE (flags), algorithm-agnostic. The
  result is ONE FIFO pipeline that merely spans algorithms during a
  transition (§3.1, §4.6). This is the NEW code.
- STRICT: completeness requires every RRset signed by every algorithm in
  the DNSKEY RRset, so during a transition the zone needs active + standby
  ZSKs of EACH algorithm at once (the maintained double-signature). Count
  standbys BY (ROLE, ALGORITHM) — which is exactly what today's
  `maintainStandbyKeysForType` / `countKeysByFlagsAndAlg` already do
  (key_state_worker.go:269,318). So STRICT inherits today's counting; the
  per-alg counting that today's code does is the STRICT shape, not a bug.

So the knob selects three things together: (1) the reconcile-retire
behavior (§8.3), (2) the standby-counting discipline (role vs role+alg),
and (3) the sweep rule (§8.3). Strict reuses today's per-alg behavior;
relaxed is the role-only branch.

Default vs. implemented: the knob lands with the first step (§8), default
`strict`, but in step 1 only the RELAXED path performs an algorithm roll.
Strict-mode algorithm rollover (maintained whole-zone double-signature
through drain) is NOT implemented in step 1, so an algorithm change
requested while the global mode is `strict` is REFUSED with a clear "not
implemented" error rather than silently running the unsafe synchronous
swap. The default is therefore safe-but-restrictive: relaxed must be
opted into to perform an alg roll. (Strict-mode alg rollover is later
work.)

### 4.5 CSK mode — reject until supported

`reconcileActiveKeyAlgorithms` early-returns on CSK mode (`sign.go:287`),
so a CSK algorithm change is currently a SILENT NO-OP that reports
success — a footgun. A CSK is SEP-flagged and has a parent DS, so a real
CSK algorithm change is a parent-coordinated rollover (engine work, like
KSK), out of scope for the first step.

DECISION: until CSK alg rollover is built, a CSK-mode algorithm change is
HARD-REJECTED with a clear "not implemented" error, in both modes. Because
`reconcileActiveKeyAlgorithms` early-returns on CSK (sign.go:287) and never
sees the keys, the rejection lives at the ENTRY layer (the
`set-policy`/`change-policy` handler and/or `EnsureActiveDnssecKeys`), NOT
in the reconcile — see the CSK note in §8.3. Supporting it via the engine
is later work.

### 4.6 First step: relaxed-mode ZSK-alg roll (the KISS FIFO model)

The relaxed-mode ZSK algorithm roll is the recommended FIRST
implementation step: no parent/DS coordination, no maintained
double-signature, no new key state. An algorithm rollover is NOT a panic
maneuver — it is a scheduled, controlled change — so the design is the
simplest possible: ONE thing changes.

THE MODEL: the ZSK pipeline is a strict FIFO that drains in order. A
relaxed ZSK alg roll changes exactly one thing — newly-GENERATED keys
carry the new algorithm. Everything else rides the existing machinery:

- Existing old-alg keys (active, standbys, retired) are LEFT ALONE. They
  promote active→retired→removed in their normal FIFO order, on their
  normal timers. No sweeping of legitimate pipeline members, no deletion
  in the middle, no out-of-order promotion.
- The new algorithm enters the pipeline only when the maintainer would
  NATURALLY generate the next key (a standby was promoted, count dropped
  below `standby_zsk_count`). That key — and every key after it — is the
  new algorithm.
- Promotion stays FIFO (oldest `published_at` first, `keystore.go:1353`):
  old-alg standbys promote first (in turn) and drain; new-alg standbys
  promote only when their turn comes. The transition completes naturally
  as the FIFO turns over.

THE THROTTLE: with N standbys + 1 active, a fully-natural roll takes N+1
`ZSK.Lifetime` periods (e.g. ~6 weeks at 2-week lifetime, N=2). The
operator accelerates with `asap` (§8.1): each `asap` promotes the NEXT
FIFO standby now. Because the existing same-alg standbys are already fully
propagated (parallel propagation), successive `asap`s execute back-to-back
(bounded only by max(propagation_delay, DNSKEY TTL) for the retire/drain
side, not by lifetime). So the operator dials the speed — ride the
cadence, or `asap` through the old-alg spares to reach the new algorithm
in roughly one propagation/TTL window plus the time for a fresh new-alg
key to reach standby. `asap` IS the trigger; `change-policy` only sets the
algorithm of future keys. No separate alg-roll trigger exists.

WHY THIS INVERTS THE EARLIER "FALLS OUT FOR FREE" FRAMING: today's
`maintainStandbyKeysForType` counts standbys BY (role, algorithm)
(`countKeysByFlagsAndAlg`, key_state_worker.go:269,318). With N old-alg
standbys present and the policy now new-alg, it would see ZERO new-alg
standbys and EAGERLY generate N new-alg keys immediately — bloating the
DNSKEY RRset to old+new sets at once. That eager per-alg behavior is the
STRICT-mode shape (§4.4), and it is exactly the anti-pattern relaxed mode
must avoid. Relaxed mode requires NEW code: count standbys BY ROLE only
(algorithm-agnostic) — "have N standby ZSKs? generate nothing" — and
stamp the new algorithm only when generation actually happens.

What is actually needed (all in §8):

- POLICY OVERRIDE WRITE (§3.4): `change-policy` writes the zone→target row
  into the existing `ZonePolicyOverride` table and rebinds
  `zd.DnssecPolicy`, so future generation uses the new algorithm and a
  restart resumes toward the target. Reuse, not a new table.
- ROLE-ONLY STANDBY COUNTING in relaxed mode (the inversion above): the
  maintainer counts standby ZSKs by role, not (role, alg).
- DELETION RULE, corrected for relaxed mode: today there is NO count cap —
  the existing loop (sign.go:338-375) deletes standby/published keys by
  ALGORITHM mismatch. In relaxed mode, SKIP that algorithm-based deletion
  for same-role ZSK keys (an old-alg standby is a legitimate FIFO member),
  and ADD a new total-count cap (keep oldest N, delete youngest surplus,
  never by algorithm), sharing one role-total count with the maintainer
  (§8.3). Strict mode keeps today's algorithm-based deletion.
- FIFO PROMOTION GUARANTEED (pre-existing latent bug — REQUIRED fix): the
  standby-selection query is currently UNORDERED, so promotion is not
  actually FIFO. Add `ORDER BY published_at` (§8.3). Without this the whole
  in-order-drain model is unsound.
- RELAXED-MODE RECONCILE BRANCH (§8.3): the reconcile does NOT retire the
  wrong-alg active ZSK; it lets the FIFO carry the roll.
- ZSK `asap`/`cancel` at KSK parity (D1, §8.1) — the throttle.
- GLOBAL MODE KNOB (§4.4) + CLI/API for `change-policy`.

NOT needed (drop from earlier drafts): immediate new-alg generation;
out-of-order/algorithm-aware promotion ("standby-pick refinement");
deleting old-alg standbys to make room. FIFO + role-only count + `asap`
make these unnecessary.

Rough cost: ~120–220 source LOC + ~120–180 test LOC, ~3–5 agent-hours,
PLUS the step-0 ZSK-manual-parity prerequisite (D1, §8.1). Build order,
decisions, and tests in §8.


## 5. Summary

- The rollover engine is the foundation: the standby gate guarantees the
  new-alg chain is confirmed at the parent and propagated before the old
  key is demoted, and the pipeline is already algorithm-blind in DS
  computation, counters, and promotion.
- The change to the rollover machinery is the algorithm the key generator
  mints, plus an entry gate (new algorithm fully propagated before the old
  is demoted). Promotion stays FIFO and algorithm-agnostic — but FIFO must
  first be MADE correct: the standby-selection query is unordered today, so
  promotion is currently arbitrary; adding `ORDER BY published_at` is a
  required fix (§8.3, a pre-existing latent bug). DS handling unchanged
  (already alg-blind); the mixed-algorithm DS window falls out for free. No
  new key state.
- Completeness (RFC 4035 §2.2) binds the signer, not the validator. The
  signer runs in one of two modes (§3.2.1, §4.3): STRICT keeps the old-alg
  key active and double-signing through the drain window; RELAXED retires
  it at the switch (drain only, no double-sign — sound because no validator
  requires per-algorithm coverage). Both validate at every instant.
- Per-role: the KSK-alg roll is cheap in both modes (one RRset). The
  ZSK-alg roll is the divergence — whole-zone double-sign in strict,
  cheap in relaxed. alg-split makes the common PQ transition a KSK-only
  roll, avoiding the ZSK cost.
- The policy-change reconcile stops swapping KSKs and hands KSK/CSK
  algorithm changes to the engine; the engine owns KSK state transitions.
- One role per roll (§4.1). Mode is a GLOBAL config choice
  (`dnssec.completeness`, default strict — §4.4). CSK alg change is
  hard-rejected until engine support exists (§4.5).
- Recommended first step: relaxed-mode ZSK-alg roll — the KISS FIFO model
  (§4.6): `change-policy` only changes the algorithm of future-generated
  keys; the FIFO drains in order and `asap` is the throttle. Relaxed mode
  counts standbys by role (not by alg) and caps the standby total by
  deleting the youngest surplus — the inverse of today's per-alg
  maintainer/sweep, which is the strict-mode shape. Build order, resolved
  decisions (incl. D5), and tests in §8.


## 6. Open items

1. RESOLVED (§4.5, §8.3) — CSK algorithm change is HARD-REJECTED (replacing
   today's silent no-op) until engine support exists. Supporting it via the
   engine is later work.
2. RESOLVED (§8.3) — two distinct commands, not one "trigger": explicit
   `auto-rollover policy-change` BINDS the target policy (sets the algorithm
   of future-generated keys, reusing set-policy's override write), and the
   ZSK `asap` command (§8.1) is the THROTTLE that promotes the next FIFO
   standby. The relaxed-mode reconcile (D3) makes the roll gradual rather
   than a synchronous swap. Keeps the manual/automated boundary clean
   (§3.5). See §4.6 for the change-policy-then-asap operator workflow.
3. multi-ds vs double-signature — multi-ds is attractive for PQ KSKs
   (§3.3, Shor's-window), so the KSK pipeline extends multi-ds rather than
   implementing the (currently unimplemented) double-signature method. The
   ZSK-alg roll has no parent/DS dimension and is double-signature-shaped
   on the zone side regardless.
4. RESOLVED (§4.4) — mode selection is GLOBAL (`dnssec.completeness`,
   default strict), not per-policy/per-zone.
5. ZSK-alg roll, large zones: the new-alg coverage must reach secondaries
   (AXFR/IXFR + propagation) before the old-alg key can be demoted. The
   standby gate handles "wait for propagation" for the KSK/DS; the ZSK
   switch needs the analogous "new-alg coverage propagated to secondaries"
   wait. Implementation detail for the plan, not a design hole.


## 7. Code reference index

| Concern | File:line |
|---|---|
| Rollover phases | ksk_rollover_automated.go:15-22 |
| Rollover tick (orchestrator) | ksk_rollover_automated.go:67 |
| Pipeline-fill — the seed point; alg arg is the one change | ksk_rollover_automated.go:140-182 |
| Circuit breaker ceiling (counts by SEP+state, alg-blind) | ksk_rollover_automated.go:155 |
| rolloverDue (trigger) | ksk_rollover_automated.go:1534 |
| kskIndexPushNeeded (confirm vs submit) | ksk_rollover_automated.go:47 |
| AtomicRollover (promotes standby, retires active) | ksk_rollover_atomic.go:60-134 |
| FIFO promotion (oldest published_at, alg-blind) | ksk_rollover_atomic.go:86 |
| Target DS set (algorithm-blind) | ksk_rollover_ds_push.go:205 |
| loadTargetKSKsForRollover (no alg filter) | ksk_rollover_ds_push.go:83 |
| DS push dispatcher | ksk_rollover_ds_push.go:255 |
| Parent DS poll/observe (standby gate's confirm step) | ksk_rollover_parent_poll.go |
| GenerateKskRolloverCreated (alg arg = flip point) | ksk_rollover_pipeline.go:13 |
| SignRRset — additive, preserves non-active-key sigs | sign.go:180-197 |
| DNSKEY RRset = published∪standby∪retired∪active | ops_dnskey.go:24 |
| reconcileActiveKeyAlgorithms (must hand off, not swap) | sign.go:286 |
| EnsureActiveDnssecKeys (calls reconcile) | sign.go:385-411 |
| StripZoneRRSIGs | sign.go:694 |
| KeyStateWorker retired→removed + strip | key_state_worker.go:~232 |
| Standby maintainer (per-alg count today = strict shape; relaxed→role-only) | key_state_worker.go:253,279-313 |
| countKeysByFlagsAndAlg (matches flags AND alg) | key_state_worker.go:318 |
| Algorithm-based standby/published deletion (NOT a count cap) | sign.go:338-375 |
| ZSK roll due + RolloverKey (same-alg today) | zsk_rollover.go:17,59; keystore.go:1318 |
| RolloverKey standby pick (first by flags — see next) | keystore.go:1352-1358 |
| GetDnssecKeysByState — UNORDERED query (FIFO bug; needs ORDER BY) | keystore.go:1178,1183,1186 |
| KSK active_at self-heal (mirror for ZSK — §8.1) | ksk_rollover_automated.go:1690 |
| ZSK active_at lives in DnssecKeyStore (not RolloverKeyState) | keystore.go:1075,1189,1293,1393 |
| DnssecKeyStore schema (add ZSK active_seq column here — §8.1) | db_schema.go:68-83 |
| KSK active_seq pattern to mirror (MAX(seq)+1) | ksk_rollover_zone_state.go:306-325 |
| ZonePolicyOverride table (zone→target name, reuse) | db_zone_policy_override.go |
| EffectiveDnssecPolicyName (override else config) | db_zone_policy_override.go:80 |
| Override resolved into bound policy at load/refresh | refreshengine.go:212,340,531 |
| set-policy (override write + synchronous reconcile) | apihandler_zone.go:240 |
| Policy-change design (zone-side only) | docs/2026-06-16-dnssec-policy-change-handling.md |

Spec references: RFC 7583 (DNSSEC key timing — multi-DS / double-DS
rollover); RFC 6840 §5.9 (a parent DS with no matching working key is
skipped, not fatal — one working chain suffices); RFC 4035 §2.2 / §5.2
(algorithm completeness — relaxed by draft-johani-dnsop-dnssec-alg-split).


## 8. Implementation plan — relaxed-mode ZSK algorithm rollover

This section is the turnkey spec for the FIRST implementation step. §0–§7
are the design/rationale; this is the build order, the resolved
mechanical decisions, and the verification. Follow the project rules in
CLAUDE.md (gofmt after edits; build with `cd tdns/cmdv2 && GOROOT=
/opt/local/lib/go make` before committing; show diff + update this doc's
step status before committing each step; no testbed access — verify by
build + `go test -race`).

### 8.0 Resolved decisions (do not re-litigate)

- D1 — Prerequisite: bring ZSK MANUAL-TRIGGER plumbing to KSK parity
  FIRST (§8 step 0). Automatic, lifetime-driven ZSK rollover is complete
  (`zsk_rollover.go`), but ZSK has NO manual/on-demand trigger — the
  KSK-only `manual_rollover_*` columns, `SetManualRolloverRequest`,
  `APIRolloverAsap`, `asap`/`cancel` CLI have no ZSK equivalent. The
  alg-roll trigger IS a manual on-demand ZSK roll, so build the general
  capability (a ZSK `asap`/`cancel`) before the alg-roll-specific piece,
  rather than a one-off. This is a real prerequisite: do not start the
  alg-roll trigger on top of a ZSK subsystem with no manual control.
- D2 — Mode knob (§4.4): add `dnssec.completeness: strict|relaxed`,
  default `strict`. Implement ONLY the relaxed ZSK-only alg-roll path now.
  Everything else is REFUSED with a clear "not implemented" error (never
  the silent synchronous swap): any ZSK alg change under `strict`, and any
  KSK or CSK alg change in EITHER mode (a SAFETY gate, not just scoping).
  The KSK and strict-ZSK refusals live in `reconcileActiveKeyAlgorithms`;
  the CSK refusal lives at the ENTRY layer because the reconcile
  early-returns on CSK and never sees the keys (§8.3). Only a ZSK-only alg
  change under `relaxed` proceeds.
- D3 — change-policy refactor = Alt A: put the relaxed behavior INSIDE
  `reconcileActiveKeyAlgorithms`, mode-driven. In relaxed mode the
  reconcile does NOT retire the wrong-alg active ZSK (it hands off to the
  rollover machinery). `change-policy` then reuses the existing
  `setZonePolicy` path (override write + in-memory rebind + SignZone),
  and the relaxed reconcile naturally no-ops the dangerous synchronous
  retire. Consequence (intended): under relaxed mode, `set-policy` on an
  alg change is ALSO gradual — correct, since the synchronous swap is
  exactly the §2 unsafe behavior. (Alt B = a `gradual bool` parameter on
  a shared apply function; Alt C = a separate thin change-policy that
  skips SignZone. Both rejected as more code / two paths to keep correct.)
- D4 — "Roll in progress" is derived from KEY STATE (an active ZSK whose
  algorithm ≠ the bound policy's ZSK algorithm), NOT from override≠YAML
  (§3.4). No new in-progress table/column. (The re-entrancy guard, §8.3,
  uses a FULLER predicate that also covers the drain window.)
- D5 — KISS FIFO model (§4.6): a relaxed ZSK alg roll changes ONLY the
  algorithm of newly-generated keys; the FIFO drains in order, `asap` is
  the throttle, nothing is generated eagerly and no legitimate pipeline
  key is deleted out of order. This requires, in RELAXED mode: (a)
  standby maintenance counts standbys BY ROLE (flags) only, not
  (role, alg); (b) the existing algorithm-based standby/published deletion
  (sign.go:338-375) is SKIPPED for same-role ZSK keys, and a NEW
  total-count cap is ADDED — keep the oldest `standby_zsk_count` standby
  ZSKs (any algorithm), delete the YOUNGEST surplus, NEVER by algorithm
  alone (there is no count cap today — see §8.3); (c) maintainer and cap
  share ONE role-total count (else they oscillate); (d) FIFO promotion is
  GUARANTEED by adding `ORDER BY published_at` to the standby selection —
  a pre-existing latent bug (the query is currently unordered), REQUIRED
  to fix (§8.3). STRICT mode keeps today's per-alg counting and per-alg
  deletion unchanged. There is NO immediate new-alg generation, NO
  algorithm-aware promotion, NO deletion of old-alg standbys to make room.

### 8.1 Step 0 — ZSK manual-trigger parity (prerequisite)

Bring ZSK to KSK parity for on-demand rolling. Model on the KSK manual
mechanism (`apihandler_rollover.go` `APIRolloverAsap`/cancel;
`SetManualRolloverRequest`/`ClearManualRolloverRequest`; the
`manual_rollover_*` columns).

DECISION — ZSK manual state lives in a NEW small table, e.g.
`ZskRolloverState (zone TEXT PRIMARY KEY, manual_rollover_requested_at
TEXT, manual_rollover_earliest TEXT)`. Do NOT reuse `RolloverZoneState`:
that table is overwhelmingly KSK/DS-specific (it has `zone` as its sole
PK plus `last_ds_*`, `rollover_phase`, `observe_*`, `*_push_at`,
`parent_advertises_*`, CDS index columns — all parent-DS machinery a ZSK
has no part in, db_schema.go:109-141). Reusing it with a key-type
discriminator would force a composite PK change and entangle ZSK state
with the KSK rollover-phase machine — strictly more work and worse
coupling than a 3-column sibling table. Mirror `RolloverZoneState`'s
helpers (`Set*`/`Clear*`) for the new table.

`zskRollDue` (`zsk_rollover.go:17`) gains a manual-request check (roll due
when a manual request is set even if lifetime has not elapsed), mirroring
KSK `rolloverDue` (`ksk_rollover_automated.go:1559`).

REQUIRED — ZSK `active_at` self-heal (a real pre-existing bug, observed in
production): a ZSK whose `active_at` is unstamped (NULL) makes both the
lifetime-driven roll AND the manual roll undecidable — `zskRollDue` reads
`activeZSK.ActiveAt`, and a nil `active_at` means "lifetime can't be
evaluated," so the roll never fires. (Seen live: cpt.p.axfr.net's active
ZSK sat with `active_at: unknown (not stamped yet)` and was stuck — no
automatic recovery, and no manual override since ZSK has no `asap`.) KSK
has a self-heal for exactly this (`healBootstrapActiveAt`,
ksk_rollover_automated.go:1690); ZSK has none.

Add the ZSK analog, and note it is SIMPLER than the KSK one: ZSK
`active_at` lives directly in `DnssecKeyStore.active_at` (read by
`GetDnssecKeysByState`, stamped by the standby→active UPDATE at
keystore.go:1075/1293/1393), NOT in `RolloverKeyState`. So the heal is a
direct stamp into `DnssecKeyStore.active_at` for any ACTIVE ZSK (flags=256)
whose `active_at` is NULL — no `RolloverKeyState`/`ZskRolloverState`
involvement, no new helper beyond an UPDATE. Use "first observation"
semantics like the KSK heal (stamp now; recoverable, not perfectly
accurate) and stamp only when currently NULL (never overwrite a real
timestamp, or every restart would push the roll forward). Run it on the
KeyStateWorker tick alongside the ZSK roll check.

ZSK `active_seq` — a monotonic per-key roll counter for operator feedback.
KSK has `active_seq` ("n-th active KSK in this zone's history",
RolloverKeyState); ZSK has none (the status shows `-`). Add the ZSK analog
so an operator gets immediate confirmation a roll progressed (the active
ZSK's number ticks up each roll).

DECISION (KISS, operator-confirmed): store it as a new `active_seq INTEGER`
column on `DnssecKeyStore` (NOT RolloverKeyState, NOT a new table — the
seq travels with the key row, no NULL-DS-column bloat, no per-key ZSK
table). Stamp it at the standby→active transition (`RolloverKey`,
keystore.go), in the SAME transaction as `active_at`, as
`MAX(active_seq)+1` over that zone's ZSK rows (`flags & 256` — KSK and ZSK
seqs are independent per-role counters). The self-heal above should also
stamp a missing `active_seq` for a healed active ZSK.

Purge semantics (accepted): `MAX(active_seq)+1` survives NORMAL purges —
retired→removed and policy-cleanup delete the OLDEST (low-seq) keys, never
the newest, so MAX is always held by the most-recent key and the counter
keeps climbing. It resets only if ALL ZSK rows are deleted (`clear`),
which is the intended "wipe and start over" semantics — a restarted seq
after `clear` is correct, not a bug. (Note: the KSK `MAX(active_seq)+1`
over RolloverKeyState has the same property; this mirrors it.)

Display: fill the ZSK key table's `active_seq` column (currently always
`-`) from `DnssecKeyStore.active_seq`, and optionally show the active
ZSK's number in the ZSK status header.

CLI/API: `auto-rollover asap`/`cancel` gain ZSK support (today they are
KSK-oriented), or add ZSK-typed variants. Keep it symmetric with KSK.

REQUIRED persistence semantics: a manual `asap` request MUST persist
until the roll actually COMMITS (clear it only after `RolloverKey`
succeeds — mirror the KSK path, which clears `manual_rollover_*` only
after the swap), NOT on the first "roll due but no standby yet" no-op.
This matters whenever an operator `asap`s while no standby is ready (e.g.
right after a fresh key was generated but has not yet reached `standby`):
the first worker ticks legitimately find no standby. If the request
cleared on that no-op, the `asap` would fire once and silently stall,
never rolling. The request must survive those ticks and fire when a
standby appears. (This is general ZSK-asap correctness; it also matters
for the alg roll when the operator asaps through to the new-alg key.)

Verify: T0.1–T0.6 (§8.4). This step is independently valuable and
independently testable — it completes ZSK rollover to KSK parity
(manual trigger + asap/cancel + active_at self-heal) regardless of the
alg-roll work.

### 8.2 Step 1 — global completeness knob

Add `dnssec.completeness: strict|relaxed` (default `strict`) to
`DnssecConf` (config.go), parse in `parseDnssecConfig` (parseconfig.go),
expose via `Conf.Internal` where the reconcile reads it. Sample config +
doc. Per D2, only relaxed is wired to do an alg roll; strict refuses.

Verify: T2 (§8.4) + a parse test (good/bad values, default).

### 8.3 Step 2 — relaxed-mode ZSK alg roll

Reconcile branch (D3) — `reconcileActiveKeyAlgorithms` (sign.go:286)
becomes mode-aware. There are FOUR cases for an active-key algorithm
mismatch, and step 2 must handle ALL of them, not just the ZSK one:

- ZSK mismatch, RELAXED mode: do NOT retire — return without the
  synchronous swap so the standby maintainer + ZSK roll carry it. (The
  step-1 happy path.)
- ZSK mismatch, STRICT mode: REFUSE with the D2 "strict-mode algorithm
  rollover not implemented" error. Do NOT run the legacy synchronous
  retire for an algorithm change.
- KSK mismatch, EITHER mode: REFUSE with a clear "KSK algorithm rollover
  not implemented (route via the engine — not yet built)" error. THIS IS A
  SAFETY REQUIREMENT, NOT POLISH. The current KSK loop (sign.go:310-322)
  retires the wrong-alg active KSK immediately → the §2 bogus-zone path.
  §8.6 excludes KSK from SCOPE, but excluding from scope does NOT stop the
  existing code from running — under relaxed mode a
  `set-policy`/`change-policy` that changes the KSK algorithm would
  otherwise silently run the unsafe synchronous swap. The KSK refusal goes
  IN this function (it is reached for ksk-zsk mode): detect the KSK
  mismatch at the top of the KSK loop and return the error instead of
  retiring.

NOTE ON CSK (different layer — read carefully): `reconcileActiveKeyAlgorithms`
EARLY-RETURNS on CSK mode (sign.go:287) — it never reaches any key loop for
a CSK zone. So a CSK alg change is NOT a "retire the KSK" path here; it is
today a SILENT NO-OP (the early return), which reports success while
nothing happens — its own footgun. The CSK refusal therefore CANNOT live
in this function; put it at the ENTRY layer — validate in the
`set-policy`/`change-policy` handler (and/or in `EnsureActiveDnssecKeys`
before calling the reconcile) that the zone's mode is not CSK for an
algorithm change, returning "CSK algorithm rollover not implemented." Do
NOT add a CSK check inside `reconcileActiveKeyAlgorithms` — it would never
fire. (See §4.5.)

So: only a ZSK-only algorithm change under relaxed mode proceeds.
Everything else is refused with zero key-state change — KSK mismatch (any
mode) and strict-mode ZSK mismatch in the reconcile; CSK mismatch (any
mode) at the entry layer. Non-algorithm reconcile behavior the function
legitimately handles is preserved.

Both-role guard (validate BEFORE writing the override): a policy whose
target differs in BOTH the KSK and ZSK algorithm is rejected at the
`change-policy`/`set-policy` entry with a "roll one role at a time" error
(§4.1) — before any override write or rebind, so the zone is never left
half-changed. (The KSK/CSK refusal above is the reconcile-layer backstop;
this is the operator-facing front-door check.)

Re-entrancy guard (validate BEFORE writing the override): a
`change-policy` for a zone that ALREADY has a ZSK algorithm rollover in
flight is REFUSED with "an algorithm rollover is already in progress for
this zone; wait for it to complete (or cancel it)". This is a distinct,
FULLER notion of "in progress" than D4 — D4 (`active ZSK alg ≠ bound
policy alg`) is for the RECONCILE's decision and reads false during the
DRAIN window (after promotion the new key is active and matches the
policy, while the old key is still `retired`/draining). For the
re-entrancy guard, "in flight" means ANY of:
  (a) an active ZSK whose algorithm ≠ the target's ZSK algorithm
      (pre-promotion), OR
  (b) a ZSK of an algorithm other than the target's present in any of
      `standby` / `active` / `retired` (drain not yet complete).
Rationale: without this, a second `change-policy` mid-roll silently
rebinds the policy and re-arms the trigger, abandoning or tangling the
in-flight roll — and the back-to-original-alg sub-case lands exactly in
D4's drain-window blind spot, where the reconcile would mis-read the
zone as "not rolling." Refusing is the safe, predictable behavior for
step 1. (A deliberate "supersede the in-flight roll" semantics is
possible later but is NOT step-1 scope; refuse for now. An operator who
genuinely wants to change course uses ZSK `cancel` (§8.1) first, then
re-issues `change-policy`.) The fuller in-progress predicate here is the
ZSK analog of the KSK post-promotion composite-in-progress item the
review carried to later steps — but for ZSK it is needed NOW, for this
guard.

Role-only standby counting (D5): in RELAXED mode, standby maintenance
counts standby ZSKs BY ROLE (flags), NOT (role, alg). Change
`maintainStandbyKeysForType`/`countKeysByFlagsAndAlg`
(key_state_worker.go:269,318) so that in relaxed mode "do I have
`standby_zsk_count` standby ZSKs?" ignores algorithm — N old-alg standbys
satisfy the count and NOTHING is generated. Only when the count actually
drops (a standby was promoted) does the maintainer generate, and that new
key carries the new algorithm. STRICT mode keeps today's per-alg counting.
(This is the inversion described in §4.6: today's per-alg behavior is the
strict shape; relaxed is the new role-only branch.)

Sweep — understand what exists first, then change it (D5): there is NO
count-based cap today. The loop at sign.go:338-375 inside
`reconcileActiveKeyAlgorithms` removes standby/published keys PURELY on
ALGORITHM MISMATCH (delete any standby/published key whose alg ≠ policy
alg; KSK case respects `rolloverInProgress`). It is not a
`standby_zsk_count` cap and has no notion of "surplus." So the relaxed
change is two distinct things, NOT "adjust the cap":

1. SKIP the algorithm-based deletion for same-role ZSK keys in RELAXED
   mode — an old-alg standby/published ZSK is a legitimate FIFO member
   during a roll, not a leftover; deleting it by algorithm would break the
   roll. (In strict mode this algorithm-based deletion STAYS — there a
   wrong-alg standby genuinely is a leftover.)
2. ADD a new TOTAL-COUNT CAP (this does not exist yet) as the
   DNSKEY-RRset-bloat safety valve relaxed mode still needs: keep the
   oldest `standby_zsk_count` standby ZSKs (by `published_at`, ANY
   algorithm), delete the YOUNGEST surplus, never by algorithm. Put it
   wherever fits cleanly (in the maintainer, or a small dedicated pass) —
   but the maintainer's generate-count and this cap MUST use ONE shared
   role-total definition of "how many standby ZSKs exist," or they
   oscillate (generate→delete→generate).

Net: relaxed mode trades an algorithm-based deletion (removed for
same-role ZSK) for a count-based cap (added). Strict mode is unchanged.

Coordination guard: with the relaxed reconcile no-op for ZSK, the ZSK
roll worker is the sole actor. Assert this; add a guard only if a path
can still double-fire.

FIFO PROMOTION MUST BE GUARANTEED — pre-existing latent bug to FIX
(REQUIRED, not optional): the KISS model depends on standbys promoting
OLDEST-FIRST. The current code does NOT guarantee this. `RolloverKey`
(keystore.go:1352-1358) promotes the FIRST standby returned by
`GetDnssecKeysByState`, and that query (keystore.go:1183,1186) has NO
`ORDER BY` clause — SQLite row order is unspecified (today it is
incidentally insertion order, but that is not guaranteed and can change
with indexes/query plan/vacuum). So promotion is effectively ARBITRARY,
not FIFO. This is a latent bug in the EXISTING same-alg ZSK rollover too,
and it is fatal to an alg roll: an out-of-order promotion could activate a
NEW-alg standby before the OLD-alg ones have drained, defeating the whole
gradual model.

SCOPE: this is a ZSK-path bug only. The KSK promotion path
(`AtomicRollover` → `listRolloverStandbyKeysTx`, ksk_rollover_zone_state.go:
493) ALREADY orders by `published_at ASC, keyid ASC` — it is correctly
FIFO. Do NOT touch the KSK path. The fix is confined to the ZSK selection.

FIX: add an explicit `ORDER BY published_at ASC` (tie-break by keyid) to
the ZSK standby selection — either in `GetDnssecKeysByState` (broadest
fix; check callers tolerate ordered results — they should) or in
`RolloverKey`'s standby pick specifically. Oldest `published_at` =
furthest through propagation = correct next-to-promote. After the fix,
promotion is FIFO by construction. Do NOT add algorithm-aware standby
selection — ordering alone gives the correct old-then-new drain. (Per the
"fix pointed-out bugs in the same PR" rule, fix this even though it
predates the alg-roll work.)

change-policy is set-the-future-algorithm; `asap` is the throttle (D5):
`auto-rollover policy-change -z <zone> -p <policy>` writes the
`ZonePolicyOverride` target + in-memory rebind (reuse
`setZonePolicy`/`SetZonePolicyOverride`) so future-generated keys carry
the new algorithm and a restart resumes toward the target. It does NOT
generate keys, retire anything, or "start a roll" synchronously. The roll
then advances on the normal ZSK cadence, OR the operator accelerates it
with the step-0 ZSK `asap` (each `asap` promotes the next FIFO standby
now; successive `asap`s run back-to-back because the existing standbys are
already propagated). CLI + API + wire field for `change-policy`, modeled
on set-policy; `asap` is the step-0 command, reused unchanged.
CLI help requirement: `change-policy`'s help/output must make the
two-command workflow explicit — e.g. after binding the policy, print
"policy bound; the algorithm will roll over the next ZSK cadence, or run
`auto-rollover asap -z <zone>` to accelerate." An operator must not have to
read this doc to discover that `change-policy` alone does not perform the
roll.

Rapid-asap drain transient (accepted, no throttle): `asap`-ing faster
than the retire/drain side clears can transiently hold MULTIPLE retired
old-alg ZSKs in the DNSKEY RRset at once (each draining on its own
max(propagation_delay, DNSKEY TTL) timer). This is SAFE (retired keys
staying published is the drain contract) and self-clearing; it is the
operator's explicit choice to go fast. Do NOT add a throttle (the KSK
asap path does not either). Note it for operators.

Status display — transition line (already-landed groundwork + step-2 add):
the `auto-rollover status` display already shows (landed separately) the
effective policy + per-role algorithms in the header (always), and a
per-key `alg` column under `-v`. Step 2 ADDS an algorithm-transition line
to the header when a roll is in flight, e.g.
`ZSK alg rollover:  ED25519 → MAYO5  (in progress)` — and, if cheap, a
progress count (`N of M promotions done`). Derive "in flight" from the
SAME predicate the re-entrancy guard uses (active/standby/retired ZSK of
an algorithm ≠ the effective-policy ZSK algorithm), so the detection logic
is shared, not duplicated. Plumb it via a new `RolloverStatus` field
(e.g. `AlgTransition *AlgTransitionInfo` with from/to alg + progress). The
override-divergence half (effective policy ≠ config base) can reuse the
`ZonePolicyOverride` lookup already used by `zone list -v`. This is the
deferred "(a) Part 2" from the status-display work — it belongs here
because the in-flight detection is step-2 logic.

Existing-test migration: introducing relaxed mode changes
`reconcileActiveKeyAlgorithms` behavior, so
`TestReconcileActiveKeyAlgorithms` (which today asserts IMMEDIATE retire
of a wrong-alg ZSK) must be updated — split into strict-mode (refuse/keep
current) and relaxed-mode (no-op) variants. Do this as part of step 2,
not as a surprise at build time.

Verify: T1, T2b, T2c, T2d, T-timing, T3, T3b, T4, T4b, T4c, T5–T9 (§8.4).

### 8.4 Test cases (unit/integration, `go test -race`)

Model on `sign_reconcile_test.go`, `db_zone_policy_override_test.go`.
Drive the worker / fake time where a sequence is needed.

Step 0 (ZSK manual parity):
- T0.1 — ZSK manual `asap` request persists and reads back; `cancel`
  clears it.
- T0.2 — ZSK roll-due returns true when a manual request is set even
  though `ZSK.Lifetime` has not elapsed.
- T0.3 — manual ZSK roll with a standby present swaps
  standby→active / active→retired; with NO standby present it warns and
  no-ops (no key loss).
- T0.4 — PERSISTENCE: a manual request set while no standby exists is NOT
  cleared by the no-standby no-op tick(s); once a standby appears the roll
  fires and the request is cleared only then (asserts §8.1 persistence).
- T0.5 — active_at SELF-HEAL: an active ZSK with NULL `active_at` gets
  stamped (first-observation) so `zskRollDue` becomes decidable and the
  roll can fire; an active ZSK that already has a real `active_at` is NOT
  overwritten (idempotent across restarts). Mirrors the KSK heal.
- T0.6 — active_seq COUNTER: each ZSK roll stamps the newly-active ZSK
  with `MAX(active_seq)+1` over the zone's ZSK rows, so the active key's
  seq increments by one per roll (1, 2, 3, …). A normal purge of the
  oldest (removed) keys does NOT regress the counter (MAX still held by
  the newest key). After `clear` (all ZSK rows deleted) the seq restarts
  (accepted, §8.1). KSK and ZSK seqs are independent (scoped by flags).

Step 1 (mode knob):
- T2 — ZSK alg change requested while global mode is `strict`: refused
  with "not implemented"; NO synchronous swap, NO key state change.

Step 2 (relaxed alg roll):
- T2b — SAFETY: a KSK-only (and, separately, a CSK) algorithm change under
  RELAXED mode is REFUSED with "not implemented"; NO active KSK/CSK retire,
  NO key churn (asserts the §8.3 KSK/CSK refusal — without this the §2
  bogus path runs).
- T2c — a policy change whose target differs in BOTH KSK and ZSK algorithm
  is rejected at the entry with a "one role at a time" error, BEFORE any
  override write or rebind (§4.1).
- T2d — RE-ENTRANCY: a second `change-policy` issued while a ZSK alg roll
  is in flight is REFUSED ("already in progress"), with no override
  rewrite / no rebind. Cover BOTH in-flight phases: (i) pre-promotion
  (active ZSK still old-alg), and (ii) drain window (new-alg ZSK promoted
  to active, old-alg ZSK still `retired`/draining) — the latter is D4's
  blind spot, so the guard must use the fuller predicate (§8.3). Include
  the back-to-original-alg sub-case in the drain window.
- T-timing — a `change-policy` to a policy with the SAME algorithms but
  different timings (e.g. shorter `ZSK.Lifetime`): does NOT trigger an
  algorithm roll, does NOT error; the override is written and the new
  timings take effect. Separately assert that if the active ZSK has
  already outlived the new shorter lifetime, the existing same-alg
  lifetime-driven roll fires normally on the next tick (not the alg-roll
  path).
- T1 — relaxed-mode reconcile with active ZSK alg ≠ policy alg: does NOT
  retire the active ZSK (the §2 unsafe path is gated off).
- T3 — ROLE-ONLY COUNT (D5): standby_zsk_count=2, two OLD-alg standbys
  present, policy ZSK alg changed to new. The maintainer generates
  NOTHING (role-only count sees 2 standbys ≥ 2) — assert NO new-alg key is
  minted and the two old-alg standbys are untouched. (Inverts the earlier
  draft, which asserted immediate new-alg minting.)
- T3b — GENERATE-ON-DRAIN (D5): from T3's state, after one standby is
  promoted (count drops to 1), the maintainer generates ONE key and it is
  the NEW algorithm. The old-alg standby that remains is untouched.
- T4 — SWEEP CAP (D5): with standby_zsk_count=2 and THREE standby ZSKs
  present (e.g. a stray extra), the relaxed sweep deletes the YOUNGEST one
  (back to 2), keeps the oldest two regardless of algorithm; it does NOT
  delete an old-alg standby merely for being old-alg. Assert maintainer +
  sweep agree on the count (no generate→sweep oscillation across ticks).
- T4b — NO out-of-order promotion (D5): with an old-alg standby (older)
  and a new-alg standby (younger) both present, a roll promotes the
  OLD-alg one (FIFO oldest-first), not the new-alg one. (Will FAIL against
  the current unordered query — see T4c.)
- T4c — FIFO ORDERING FIX (pre-existing bug): with multiple same-role
  standbys created in a known order, `RolloverKey` promotes the one with
  the OLDEST `published_at`, deterministically, regardless of row/insertion
  order. Asserts the `ORDER BY published_at` fix (§8.3). Independent of
  algorithm — also covers same-alg rollover correctness.
- T5 — full sequence via asap (standby_zsk_count=2): change-policy (new
  alg) → maintainer generates nothing (T3) → `asap` promotes old-alg
  standby#1 → active (old active → retired, draining); `asap` again
  promotes old-alg standby#2 → active immediately (already propagated) →
  now count=0 standbys → maintainer generates 2 NEW-alg keys → once
  propagated, `asap` promotes a new-alg key → zone now signs new alg;
  old-alg keys finish draining (retired → removed + RRSIGs stripped).
  Assert: no instant with zero valid ZSK coverage; FIFO order preserved
  throughout; DNSKEY RRset never holds more than active + 2 standby +
  draining-retired.
- T6 — `change-policy` writes the override to the TARGET + rebinds; a
  simulated restart (re-resolve via `EffectiveDnssecPolicyName`) rebinds
  to the target, not the old policy.
- T7 — override≠YAML but active-alg == bound-policy-alg (a COMPLETED
  prior change): engine does NOT treat a roll as in progress (D4).
- T8 — relaxed roll does NOT maintain a whole-zone double-signature:
  after switch+drain only new-alg RRSIGs remain; old-alg RRSIGs are not
  refreshed.
- T9 — reload mid-roll: a `zone reload` (which re-parses dnssec + triggers
  a resign) while the active ZSK is still old-alg must NOT retire it — the
  T1 invariant holds through reload (D3: reload goes through the same
  relaxed reconcile path). Cheap to unit-test with fake time.

### 8.5 Success criteria

- Step 0: ZSK has `asap`/`cancel` at KSK parity, with request persistence
  the `active_at` self-heal, and the `active_seq` roll counter per §8.1;
  T0.1–T0.6 green; build clean.
- Step 1: knob parses, defaults strict; T2 green.
- Step 2: a relaxed-mode `change-policy` to a different-ZSK-algorithm
  policy gradually rolls the ZSK (new-alg standby → active, old-alg
  retired → removed + stripped) with the zone validatable throughout; AND
  a KSK/CSK, both-role, or re-entrant alg change is safely refused (no key
  churn); AND a same-alg/timing-only change applies without a roll; AND
  the roll proceeds by FIFO drain + `asap` with no eager new-alg
  generation and no out-of-order promotion (D5); AND the pre-existing
  unordered-standby-selection bug is fixed (FIFO `ORDER BY published_at`);
  T1, T2b, T2c, T2d, T-timing, T3, T3b, T4, T4b, T4c, T5–T9 green;
  `go test ./... -race` clean; full `make` builds all binaries. Testbed
  validation is operator-gated (not part of agent done-ness).

### 8.6 Explicitly OUT of scope for this step

NOT BUILT (but SAFELY REFUSED, not left to run unsafely — §8.3):
- KSK algorithm rollover (parent DS / multi-ds — §1, §3.3).
- CSK algorithm change (§4.5).
- Strict-mode algorithm rollover (maintained whole-zone double-signature —
  §3.2.1).
A request for any of these returns a clear "not implemented" error with no
key-state change. The distinction from "out of scope" in earlier drafts:
these are not merely unaddressed, they are actively GATED, because the
existing reconcile code would otherwise run the §2 unsafe path.

NOTED, not built (no gating needed this step):
- Large-zone secondary-propagation wait for the ZSK switch (§6 item 5):
  `transitionPublishedToStandby` uses `propagation_delay` only. Document
  the limitation in operator docs; do not build the secondary-observation
  wait now.
- `policy-cleanup` during an in-progress relaxed roll: after promotion the
  old-alg ZSK is `retired`; `policy-cleanup` would strip its RRSIGs
  immediately, unsafe while resolvers may still cache old-alg answers. Do
  not build a guard now, but WARN in operator docs (and ideally refuse
  cleanup when `active alg ≠ policy` or a wrong-alg `retired` ZSK exists —
  cheap, optional).
- Multi-provider zones (`OptMultiProvider`) are skipped by the ZSK roll
  worker (`zsk_rollover.go:46`); document the exclusion.

Keep the step to relaxed-mode ZSK only.
