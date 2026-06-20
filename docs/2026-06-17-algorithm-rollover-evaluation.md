# Algorithm rollover via the auto-rollover engine

Status (2026-06-17): DESIGN. Nothing implemented. Open items flagged in
§6 (CSK handling, trigger surface, multi-ds vs double-signature) await a
decision; the rest is settled.

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

### 3.4 Trigger and reconcile

- TRIGGER: an operator command modelled on `auto-rollover asap`:
  `auto-rollover policy-change -z <zone> -p <policy>`, which tells the
  engine to mint the next pipeline key(s) with the new algorithm.
  (Trigger-surface alternatives in §6.)
- RECONCILE: `reconcileActiveKeyAlgorithms` no longer performs the KSK
  active → retired swap. On a KSK (or CSK) algorithm mismatch it hands the
  rollover to the engine. It retains responsibility for ZSK algorithm
  changes, driving those through the pipeline as well rather than
  retiring and regenerating in place.

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
instant in both. The mode is a configuration/policy choice (§4.4).

### 4.4 Mode selection — config/policy

Strict vs relaxed completeness is a signer mode selected by configuration
(zone- or policy-level). Strict is the conservative default and the only
choice that produces §4035-conformant zones a strict checker accepts;
relaxed is the alg-split/PQ-transition mode that makes the ZSK-alg roll
cheap. Exact knob (global default, per-policy, per-zone) is an
implementation detail; the design requirement is only that BOTH modes
exist and the rollover honors the selected one. KSK-alg rolls are
effectively identical in both modes (§3.2.1), so the mode matters in
practice only for the ZSK-alg roll.

### 4.5 CSK mode — OPEN

`reconcileActiveKeyAlgorithms` early-returns on CSK mode (`sign.go:287`). A
CSK is SEP-flagged and has a parent DS, so a CSK algorithm change is a
parent-coordinated rollover. Decision needed: support it via the engine
(same as KSK), or reject the change with an error until supported.


## 5. Summary

- The rollover engine is the foundation: the standby gate guarantees the
  new-alg chain is confirmed at the parent and propagated before the old
  key is demoted, and the pipeline is already algorithm-blind in DS
  computation, counters, and promotion.
- The change to the rollover machinery is the algorithm the key generator
  mints, plus an entry gate (new algorithm fully propagated before the old
  is demoted). Promotion unchanged (FIFO); DS handling unchanged (already
  alg-blind); the mixed-algorithm DS window falls out for free. No new key
  state.
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
- One role per roll (§4.1). Mode is a config choice (§4.4). CSK handling
  is open (§4.5).


## 6. Open items

1. §4.5 — CSK algorithm change: support via the engine, or reject until
   supported?
2. Trigger surface — an explicit `auto-rollover policy-change` command, or
   automatic hand-off from `set-policy` when the target algorithm differs?
   The explicit command keeps the manual/automated boundary clean (§3.5).
3. multi-ds vs double-signature — multi-ds is attractive for PQ KSKs
   (§3.3, Shor's-window), so the KSK pipeline extends multi-ds rather than
   implementing the (currently unimplemented) double-signature method. The
   ZSK-alg roll has no parent/DS dimension and is double-signature-shaped
   on the zone side regardless.
4. §4.4 — mode selection knob: global default, per-policy, or per-zone?
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
| Policy-change design (zone-side only) | docs/2026-06-16-dnssec-policy-change-handling.md |

Spec references: RFC 7583 (DNSSEC key timing — multi-DS / double-DS
rollover); RFC 6840 §5.9 (a parent DS with no matching working key is
skipped, not fatal — one working chain suffices); RFC 4035 §2.2 / §5.2
(algorithm completeness — relaxed by draft-johani-dnsop-dnssec-alg-split).
