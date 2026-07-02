# Dual-model ZSK algorithm rollover: FIFO and double-signature

Status: DESIGN / DECISION-PENDING. This is a design and cost
assessment, not an approved build plan. It exists to support the
decision of whether to implement a second ZSK-algorithm-rollover model
(double-signature) alongside the FIFO model that is already built.

Companion docs:
- `2026-06-17-algorithm-rollover-evaluation.md` — the as-built FIFO
  (relaxed-completeness) ZSK algorithm rollover. This doc does NOT
  re-derive that; it builds on it.
- `2026-06-21-ksk-algorithm-rollover-plan.md` — KSK side (out of scope
  here; KSK alg rollover is parent-coordinated and unaffected).
- Draft `draft-johani-dnsop-dnssec-alg-split-01` — the IETF draft this
  code is measured against. The relevant tension is between the draft's
  Part 1 (|Z|>1) text and the code's FIFO behaviour.


## 0. The two models in one paragraph each

FIFO (built, gated behind `dnssec.completeness: relaxed`). ZSKs form a
single-file queue. A ZSK algorithm change is incidental: ZSK n+1 simply
carries a different algorithm than ZSK n. At the roll, the new ZSK
becomes active and the old one is retired in the same atomic step
(`kdb.RolloverKey`). Old-algorithm RRSIGs are kept only until they age
past validity, then drop. There is NO instant at which every non-DNSKEY
RRset is guaranteed to carry both algorithms' signatures.

Double-signature (not built; this doc specs it). A ZSK algorithm change
runs as a conventional RFC 6781 conservative rollover: the new-algorithm
ZSK is promoted to active ALONGSIDE the old one, the zone is re-signed so
that every non-DNSKEY RRset carries an RRSIG from BOTH algorithms, and
only after that completion is reached is the old-algorithm ZSK retired.
At every instant during the window, completeness within Z holds.

The draft's Part 1 |Z|>1 text describes the double-signature model
("every non-DNSKEY RRset carries a signature from each old and new ZSK
algorithm during the rollover window"). The code implements FIFO. That
is the divergence this doc is about.


## 1. Is FIFO safe? (summary of the prior analysis)

Yes, for the intended deployment, and no weaker than the draft's own
stated guarantees for the transitional deployment. Two properties:

a. Validation correctness — unconditionally preserved. The invariant
   FIFO maintains is: every RRSIG in the zone is covered by a ZSK
   currently in the apex DNSKEY RRset, and a signing key's RRSIGs are
   not dropped until past their validity. A resolver validates with any
   single supported Z algorithm (RFC 6840 §5.11). FIFO never produces
   bogus/SERVFAIL.

b. Forgery resistance — the only thing double-sig adds is a transient
   window in which a both-algorithm-aware validator could DEMAND the
   stronger Z algorithm on a given RRset. The draft's own Part 2 /
   Security Considerations argue that this demand-the-stronger fallback
   is gone in steady state (|Z|=1) anyway, and that the split's safety
   rests on the K-over-Z structural asymmetry (identical under both
   models) plus bounded ZSK rotation, NOT on Z-internal redundancy.
   FIFO merely extends "can't demand the stronger Z on every RRset"
   from steady state into the rollover window.

The one genuine difference: in a classical-ZSK → PQ-ZSK transition,
double-sig gives a both-algorithm-aware validator PQ coverage of bulk
data immediately at roll start; FIFO reaches it after ~one max-TTL drain.
The draft already concedes the transitional case provides no long-term
bulk-data integrity and bounds exposure by ZSK lifetime; a one-TTL
convergence delay is negligible against a ZSK-lifetime-scale window.

Conclusion: FIFO is safe. Double-sig buys a transient redundancy the
draft argues is unnecessary, at the cost of a second permanent model.


## 2. Why FIFO is FIFO: the load-bearing primitive

`rolloverZskForZone` (zsk_rollover.go:469) rolls via
`kdb.RolloverKey(zone, "ZSK", nil)` (keystore.go:1341), which ATOMICALLY
does old-active → retired and standby → active. One in, one out, never
two algorithms active at once. This atomicity IS the FIFO model.

Double-signature needs the opposite shape: standby → active WITHOUT
retiring the old active (additive promote), then a DEFERRED retire once
the zone is fully double-signed. So double-sig is not a branch inside the
existing roll; it is a second rollover path that sits beside
`RolloverKey`. `PromoteDnssecKey(zone, keyid, oldstate, newstate)`
(keystore.go:1036) already provides the additive promote primitive —
call it standby→active and simply do NOT retire the old active.


## 3. The completion gate: the only genuinely new concept

FIFO never asks "is the zone fully re-signed under the new algorithm
yet?" — it doesn't need to. Double-sig's correctness depends on NOT
retiring the old-algorithm active ZSK until that is true. This gate has
no equivalent in the current code.

Definition (cheapest correct form). For a zone in double-sig-in-progress
with old-algorithm active ZSK O and new-algorithm active ZSK N, the old
active O MAY be retired when BOTH hold:

1. Coverage: every non-DNSKEY authoritative RRset in the zone now
   carries an RRSIG from algorithm(N). In an inline/online signer this
   is guaranteed once a full re-sign pass has completed after N became
   active — so the gate can be expressed as "a re-sign pass has run to
   completion with N active" rather than walking every RRset.

2. Drain: every RRSIG made by O is now past its validity (so no resolver
   holds a cached O-signature it still needs O in the DNSKEY RRset to
   validate). Equivalently: at least max(RRSIG validity remaining at roll
   start) has elapsed, OR the zone has been fully re-signed AND the old
   RRSIGs purged.

Note the asymmetry with FIFO: FIFO can drop O's DNSKEY as soon as O's
RRSIGs have aged out, because nothing replaced them mid-flight. Double-sig
must additionally ensure N's coverage is complete first — otherwise
retiring O could strand an RRset that N has not yet signed. Condition (1)
is the part FIFO never needed.

Where it runs: a per-zone check each KeyStateWorker tick for zones whose
state is double-sig-in-progress; on success, the deferred retire of O.
This requires a small amount of persistent per-zone state to mark
"double-sig in progress, old active = O, started at T" — the natural home
is the existing rollover zone-state row (ksk_rollover_zone_state.go),
reused for ZSK, or a sibling ZSK row. (FIFO keeps no such state; this is
new.)


## 4. Per-site change map and LOC

Selection is the EXISTING `dnssec.completeness: strict|relaxed` knob
(2026-06-17 doc, STEP 1). `relaxed` → FIFO (built). `strict` → currently
REFUSES a ZSK alg roll (sign.go:329-332); double-sig fills in that branch
so `strict` MEANS double-sig instead of "unsupported".

| # | Site | File | Today | Change | LOC |
|---|------|------|-------|--------|-----|
| 1 | reconcile strict branch | sign.go:329-336 | returns error | detect double-sig-in-progress; don't refuse; let both actives flow | 30-50 |
| 1b| leftover sweep | sign.go:349-382 | relaxed skips old-alg ZSK | add strict case: old-alg active mid-double-sig is legit, not leftover | (incl above) |
| 2 | additive promote | keystore.go | `PromoteDnssecKey` exists | thin caller: standby→active, no retire of old | 10-20 |
| 3 | double-sig rollover fn | zsk_rollover.go | `rolloverZskForZone` (FIFO) | sibling: on roll-due in strict, additive-promote instead of `RolloverKey`; factor shared lock/heal/due/standby checks | 50-70 |
| 4 | completion gate + deferred retire + wiring | zsk_rollover.go / key_state_worker.go | none | §3 gate, per-tick check, retire-O-on-complete | 60-90 |
| 5 | persistent in-progress state | ksk_rollover_zone_state.go (reuse) or new | none for ZSK | mark/clear double-sig-in-progress + old-active | 20-40 |
| 6 | standby maintenance | key_state_worker.go:282-299 | already per-(role,alg) for strict | guard so new-alg standby is staged before the roll | 0-15 |
| 7 | config selection | — | knob exists, routed | none / trivial | 0-10 |

Production subtotal: ~170-295 LOC. (PromoteDnssecKey existing trims #2;
the new persistent-state line #5 is the offsetting addition vs the
earlier estimate — net roughly the same band.)

Tests. `zsk_alg_rollover_test.go` is already 750 lines for the FIFO
(T1-T9) matrix. Double-sig needs a PARALLEL matrix asserting the OPPOSITE
invariants — both actives present mid-roll, every RRset double-signed, O
NOT retired before the gate, O retired AFTER. These cases do not reuse the
FIFO assertions (they often contradict them). Realistically ~400-700 LOC
of new tests.

All-in: ~170-295 LOC production + ~400-700 LOC tests ≈ 600-1000 LOC,
concentrated in sign.go, zsk_rollover.go, the keystore, the rollover
zone-state, and a new test file.


## 5. The cost that is not LOC

The LOC is modest. The durable cost is two permanently-live correctness
models sharing one signing/key-state path: `SignRRset`, `RolloverKey` and
its additive sibling, the standby cap, the KSK rollover interaction, and
`asap` manual rolls. Every future change to that path must be reasoned
under BOTH models, and BOTH test matrices must stay green forever. The
in-progress-state machine (§3/§5-row) is the easiest place for a subtle
retire-too-early bug — exactly the bug class that produces (1a) failures.

This ongoing maintenance tax, not the ~600-1000 LOC, is the real price.
It is the cost the project's "no dual-format / keep it simple" convention
is pointed at.


## 6. Recommendation

Given (a) FIFO is safe, (b) the draft's own Part 2 / Security argument
says Z-internal redundancy is unnecessary, and (c) the two-model tax in
§5 — the recommended path is to keep FIFO as the SINGLE model and revise
the draft's |Z|>1 language to permit (or prefer) a sequential
ZSK-algorithm rollover, justified from the bounded-rotation argument the
draft already makes in Part 2. That resolves the draft's internal tension
and keeps the code simple.

Build double-sig in parallel only for a concrete external reason FIFO
cannot satisfy:
- a reviewer/operator constituency that insists on RFC 6781 conservative
  semantics for the rollover window; or
- a real classical→PQ transitional deployment that needs IMMEDIATE PQ
  coverage of bulk data at roll start rather than after one max-TTL.

If such a reason exists, this doc is the build plan: the scaffolding
(`completeness` knob, per-(role,alg) standby counting, `PromoteDnssecKey`,
the rollover zone-state row) is largely in place; the genuinely new work
is the completion gate (§3) and its in-progress state (§5-row). If no such
reason exists, building double-sig pays the §5 tax to satisfy a property
the draft itself says is moot.


## 7. Open questions

- Completion gate, coverage condition (§3.1): is "a full re-sign pass has
  completed with N active" a sound proxy for "every RRset carries an N
  RRSIG" in BOTH the inline and online signing paths? Online signing has
  no zone-wide pass — coverage there is per-query-lazy, which weakens the
  proxy. Needs confirmation before this is buildable for online signers.
- Should double-sig reuse the KSK rollover zone-state row (§5) or get a
  ZSK-specific sibling? Reuse risks coupling two state machines that are
  otherwise independent (KSK alg roll is parent-coordinated; ZSK is not).
- Interaction with `asap --zsk` during an in-progress double-sig roll: a
  manual roll mid-window must not promote a THIRD active ZSK. The FIFO
  manual path (zsk_rollover.go:439-479) needs a guard under double-sig.
