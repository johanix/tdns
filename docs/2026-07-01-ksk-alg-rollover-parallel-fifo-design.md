# KSK algorithm rollover: the parallel-FIFO / double-signature design

Status: DESIGN (concluded 2026-07-01). This supersedes the **method** of
`2026-06-21-ksk-algorithm-rollover-plan.md` — its premise that a KSK
algorithm rollover "rides the existing multi-DS engine unchanged" is
retired here. The 2026-06-21 doc's build-step *scaffolding* (entry-layer
dispatch, safety refusals, trigger UX, test matrix) still applies; §9
re-rates each step against this model.

Code references are `file:line` into `v2/` on branch `feat/tsig-first-class`
(contains all merged rollover work). Cross-references of the form
"(eval §N)" point at `2026-06-17-algorithm-rollover-evaluation.md`.

This work is EXPERIMENTAL, consistent with the alg-split / PQ-transition
goal (draft-johani-dnsop-dnssec-alg-split). The parent is under our
control in the testbed, so a mixed-algorithm CDS/DS at the parent is a
requirement to satisfy, not an external constraint.


## 0. One-paragraph summary

A KSK algorithm rollover cannot use multi-DS (§1). It must use
**double-signature**: the new-algorithm KSK signs the apex DNSKEY RRset
*before* its DS is pushed to the parent. We model this as **parallel
FIFOs**: a zone already runs one KSK FIFO and one ZSK FIFO in parallel,
jointly emitting the DNSKEY RRset (§2); a KSK algorithm rollover
transiently **spawns a second, new-algorithm KSK FIFO** alongside the
old one. The old-algorithm FIFO keeps its key **active** (still the
load-bearing chain) until the new-algorithm DS is confirmed at the
parent, then drains and is dropped. The governing invariant becomes
**one active key per (role, algorithm)** (§4), which also closes the ZSK
single-active gap (cleanup punch-list P0-2). Double-signature is promoted
to a first-class, general KSK rollover method (§3) — likely the KSK
*default*, since its only cost is one extra RRSIG on an already-large,
already-TCP RRset.


## 1. Why multi-DS does not work for algorithm rollovers

Multi-DS pre-positions the **DS at the parent while the key is a
non-signing standby** — the DS goes up (a hash, PQ-opaque) while the
DNSKEY stays out of the zone (`loadTargetKSKsForRollover` selects
`state IN ('created','ds-published',…)`, `ksk_rollover_ds_push.go:85`;
rationale spelled out at `ksk_rollover_automated.go:991-997`: "DS hashes
are post-quantum-opaque, but DNSKEYs reveal the public key").

For a **same-algorithm** rollover this is safe: the algorithm is already
signing the DNSKEY RRset via the active key, so the pre-positioned DS
points into a chain that already works.

For an **algorithm** rollover it is not. During the pre-positioning
window the parent advertises:

```
parent DS RRset   = { DS(oldK, algA), DS(newK, algB) }
child DNSKEY RRset = { oldK(A), newK(B), ZSK(A) }, signed by A only
```

The parent asserts "this zone uses algorithm B," but **nothing in the
child signs with B** — not even the DNSKEY RRset. `DS(newK, B)` is an
orphan: it points to a key that signs nothing. And because B is a whole
new *algorithm*, that state is indistinguishable from an
algorithm-stripping downgrade attack — exactly what the completeness
requirement (RFC 4035 §2.2; the DS→DNSKEY chain rule) exists to detect.

The underlying rule: *a DS is only useful if the key it points to is in
the DNSKEY RRset **and signs it**.* Multi-DS deliberately publishes the DS
before that second half is true. A same-algorithm rollover forgives it; a
new algorithm does not.

**Conclusion:** for an algorithm rollover the new-algorithm KSK must be
**signing the apex DNSKEY RRset before its DS is trusted at the parent.**
That is the double-signature invariant.

(The relaxed/alg-split assumption — validators accept one valid chain and
do not require algorithm B to sign the *whole zone*, RFC 6840 §5.11 — is
what makes an *independent* KSK-only algorithm rollover legal at all. But
even alg-split does not bless a DS for algorithm B with *zero* B
signatures; the DS→DNSKEY chain for B must be complete the instant B's DS
is visible. That is a stronger, more fundamental requirement than the
whole-zone completeness alg-split relaxes.)

### Why the ZSK gets away with a single relaxed FIFO and the KSK does not

The ZSK has **no DS**. Its algorithm is only signalled by the DNSKEY RRset
and its own RRSIGs, so a ZSK algorithm rollover can use a single relaxed
FIFO (PR #263): the new-algorithm ZSK becomes the single active, the
old-algorithm RRSIGs drain out of caches, one active at all times. There
is nothing at the parent that must stay consistent with a second live
algorithm.

The KSK's DS is exactly that constraint. It forces both algorithms to be
simultaneously live and self-consistent during the overlap — old-algorithm
chain still validating, new-algorithm chain already complete — which is
double-signature, which needs two simultaneously-signing KSKs, which is
two parallel FIFOs. The parent DS is the single variable that decides
parallel-vs-in-queue. (Double-signing the KSK is cheap — one RRset; this
is precisely why the dual-model doc *rejected* conservative double-signing
for the whole-zone ZSK but it is fine for the KSK.)


## 2. The N-FIFO model

The engine already runs **two FIFOs in parallel** — the KSK FIFO and the
ZSK FIFO — that **jointly** manage the shared apex DNSKEY RRset. Each owns
its slice; `PublishDnskeyRRs` unions across them (`published ∪ standby ∪
retired`, `ops_dnskey.go:23-24`, with active fetched separately and
merged), and the signer is additive (below). So the real abstraction is:

> A zone holds a **set of FIFOs**, each keyed by **(role, algorithm)**,
> each managing its own keys within the shared DNSKEY RRset; they compose.

Steady state: **N = 2** (one KSK-algA FIFO, one ZSK-algA FIFO). A KSK
algorithm rollover transiently makes **N = 3** (KSK-algA + KSK-algB +
ZSK-algA) and returns to 2 when the old KSK FIFO drains. This is a
generalization of an existing pattern, not a new mechanism — we are going
from 2 to 3, not from 1 to 2.

A "FIFO" is the ordered succession of same-(role,algorithm) keys
(`published_at ASC, keyid ASC`), with at most one active head, keys
retiring in order. Same-algorithm rollover advances *within* a FIFO. An
algorithm rollover *spawns a new* FIFO.


## 3. Two methods: multi-DS and double-signature

Both are RFC 7583 KSK rollover methods; they differ only in the **order of
the DS push relative to the swap**:

| | Multi-DS (DS-first) | Double-signature (sign-first) |
|---|---|---|
| Order | pre-position DS → confirm → swap | swap/activate → sign → push DS → confirm → drain old |
| New DNSKEY | hidden until activation (PQ-opaque) | published + signing during the overlap |
| Rollover latency | instant (DS already at parent) | one DS round-trip |
| FIFO shape | single FIFO, in-place succession | new key's activation is a **bootstrap** (§5, corner a) |
| Algorithm rollover | **impossible** (§1) | **required** |

DECISION D1 — **double-signature becomes a first-class, general KSK
rollover method**, not an algorithm-rollover-only special case. For a
same-algorithm KSK rollover it is a valid alternative to multi-DS
(swap-early — §4); for an algorithm rollover it is the only option.

DECISION D2 — **double-signature is likely the KSK default.** Its only
cost is one extra RRSIG on the apex DNSKEY RRset, which is already large
and already TCP-transported. Multi-DS's advantages — hidden DNSKEY (PQ
opacity), instant rollover, no early key exposure — earn their keep on the
ZSK and on large standby pipelines, far less on a single KSK RRset. The
existing scaffolded-but-unimplemented `double-signature` method (enum +
`num-ds==2` validation at `ksk_rollover_policy.go:53,225-233`, engine
early-return at `ksk_rollover_automated.go:79-81`, `AtomicRollover`
deferral "4E" at `ksk_rollover_atomic.go:18`) is the natural home for this.


## 4. The invariant: one active per (role, algorithm)

Today `pickActiveSEPTx` (`ksk_rollover_atomic.go:152-178`) hard-errors on
**> 1 active SEP KSK**. Under parallel FIFOs the correct scoping is:

DECISION D3 — the invariant becomes **at most one active key per
(role, algorithm)**. This is not a weakening — it is the same
"one active head" rule, scoped to the FIFO. It permits exactly the states
the model needs:

- **Same-algorithm rollover** (multi-DS or double-signature): one FIFO,
  one active KSK of that algorithm. Unchanged from today.
- **Algorithm rollover overlap**: two active KSKs, one per algorithm
  (KSK-algA active + KSK-algB active). Permitted; this *is* the
  double-signature state.

**Unification with the ZSK cleanup.** The ZSK punch-list (P0-2) wants a
single-active guard added to `RolloverKey` (which today retires "the first
active" with no guard). "One active per (role, algorithm)" *is* that
guard: it catches a same-algorithm ZSK double-active bug and permits the
KSK alg-roll overlap. One rule, both jobs. The ZSK never uses its "second
algorithm slot" (its relaxed FIFO does an atomic swap, always one active).

Same-algorithm double-signature stays within one FIFO via **swap-early**:
the old key goes `active → retired` (honestly superseded — a same-algorithm
successor now exists) but keeps signing through the drain (§5, FACT 3).
Only the *algorithm* rollover keeps the old key active in a *separate*
FIFO, because the old-algorithm key is genuinely still the load-bearing
chain until the new-algorithm DS confirms.


## 5. The algorithm rollover, end to end

Three code facts ground the sequence (verified 2026-07-01):

- **FACT 1 — only active KSKs sign the DNSKEY RRset.**
  `signingkeys = dak.KSKs` where `dak.KSKs = GetDnssecKeys(zone, Active)`,
  purely state-driven, no algorithm predicate (`sign.go:171-175`,
  `keystore.go:942-943`). Standby keys are *in* the RRset but do not sign.
- **FACT 2 — the DS is pushed while the pipeline key is a non-signing
  `created`/`ds-published` key** (`loadTargetKSKsForRollover`,
  `ds_push.go:85`). This is the ordering the algorithm case must invert.
- **FACT 3 — a retiring KSK keeps its RRSIG until `retired → removed`.**
  The signer is additive — `SignZone` never strips other keys' RRSIGs
  (`sign.go:180-185`); the strip happens only at `removed`, gated on
  `effective_margin = max(clamping.margin, max_observed_ttl)`
  (`ksk_rollover_automated.go:1637`; withdraw loop `:565-612`). At
  `removed`, the key's DNSKEY, its DS (the DS target query excludes
  `removed`), and its RRSIG all drop together. **The engine already
  maintains a drain-window double-signature for the same-algorithm case;
  the algorithm case inherits it.**

The sequence (waits italicised):

1. **Trigger.** `change-policy` binds the new KSK algorithm. Refuse if:
   a same-role roll is already in flight (re-entrancy), both roles' algorithms
   differ (one role per roll, eval §4.1), or it is a CSK (eval §4.5).
2. **Spawn the new-algorithm FIFO; bootstrap its head.** Mint new-alg KSK
   B, publish its DNSKEY, make it **active** so it signs the DNSKEY RRset
   (double-signing alongside old-alg active A). Because both A and B are
   active-and-different-algorithm, D3 permits it and the additive signer
   double-signs with **zero signer change**. Meanwhile the old-alg FIFO
   **freezes**: A stays active, and A's orphaned standby keys are
   **deleted and their DSes withdrawn** (we are rolling away from algA).
3. *Wait for B's DNSKEY + its RRSIG to propagate* (child propagation +
   effective DNSKEY_TTL). This is the invert-FACT-2 gate: **B's DS is not
   pushed until B is signing and propagated.**
4. **Push DS(B).** Parent DS RRset becomes the mixed set
   `{ DS(A), DS(B) }`.
5. **Observe** the parent until the mixed set is confirmed. Throughout
   1–5 the zone validates via `DS(A) → A → A's RRSIG`; B is signing but not
   yet a relied-upon chain. No gap.
6. **Retire the old-alg FIFO's head.** Only now (new-alg DS confirmed)
   `A: active → retired`. A keeps signing (FACT 3). B is now the sole
   active KSK. The old-alg FIFO has one draining key left.
7. *Hold A for `effective_margin`* (existing withdraw phase). During this
   window `DS(A)` is still at the parent and A still signs — resolvers with
   cached `DS(A)` keep validating.
8. **`A: retired → removed`** — DNSKEY(A), DS(A) and RRSIG(A) drop
   together. The old-alg FIFO is now empty → **drop it**. N returns to 2.

**On the DS-drain wait we discussed earlier.** In a hand-written
double-signature sequence one is tempted to *remove DS(A), then* unsign A —
which leaves A **present-but-unsigned** while `DS(A)` may still be cached,
a SERVFAIL for any resolver holding only `DS(A)`. The engine's
decomposition **avoids this entirely**: A stays fully in force (active →
retired, *signing*, DS at parent) through the margin, then DNSKEY+DS+RRSIG
drop **together** at `removed`. A is never present-but-unsigned; and since
`DS(A)` and `DS(B)` were co-published in one RRset from step 4, no resolver
holds `DS(A)` without `DS(B)`, so the instant A vanishes the orphaned
`DS(A)` is simply skipped and `DS(B) → B` carries the chain. So the
separate DS-drain wait is **subsumed by the existing `retired → removed`
margin**, not a new step. (Verify: `effective_margin` need not cover the
parent DS_TTL here, because the co-published `DS(B)` is the fallback — but
confirm this holds for the same-algorithm multi-DS case too, which relies
on the same property.)


## 6. What is reused vs. what is new

**Reused, unchanged:**
- The **additive signer** — two active KSKs of different algorithms both
  sign the DNSKEY RRset automatically (`sign.go:180-226`). No signer change.
- **`AtomicRollover`** — stays the same-algorithm in-FIFO swap.
- **FACT-3 retired-signing drain** — the old-alg FIFO's tail
  (`retired → removed` over `effective_margin`) is the existing withdraw
  machinery.
- **Bootstrap-activation** — the new FIFO's head is a bootstrap (corner a).
  Reuse the shape of `RegisterBootstrapActiveKSK` / `healBootstrapActiveAt`
  (which already do activate-then-DS for a zone's first key).

**New:**
- **The invariant change** — `pickActiveSEPTx` → "one active per
  (role, algorithm)" (D3). Small but load-bearing; every "the active SEP
  key" caller must tolerate one-per-algorithm during a roll.
- **FIFO instantiation** (corner c) — allocate/spawn a parallel FIFO,
  bootstrap its head alongside the existing FIFOs, freeze + drain + drop
  the old one.
- **Per-FIFO rollover state** (§7) — the one genuinely new modelling piece.
- **The DS-push gate** — hold the new-alg DS until its key is signing +
  propagated. In this model it falls out of the bootstrap ordering (B is
  active-and-signing *before* step 4), but the DS-target query still needs
  to not select B while it is pre-active.
- **Generalizing double-signature** to same-algorithm rollovers (D1/D2):
  filling in the scaffolded method so it is not algorithm-roll-only.

**Caution — the signer's strip behaviour must become role/mode-aware.**
The KSK alg roll *keeps* both algorithms' RRSIGs over the DNSKEY RRset
(additive, FACT 3 — no KSK-side signer change; the double-signature is
required). But the **ZSK relaxed alg roll must do the opposite** — *replace*
old-alg RRSIGs rather than accumulate them (ZSK cleanups P0-6; the
accidental double-sign there is the conservative whole-zone double-sign the
dual-model doc rejected). Both flow through the same uniformly-additive
signer today, so the strip/resign logic must distinguish: **keep** for a
KSK alg roll and same-alg drains, **strip** for a relaxed ZSK alg roll.
Co-design this with ZSK cleanups P0-6 and P0-2 (the D3 invariant) as one
coordinated change — see `2026-07-01-zsk-alg-rollover-cleanups.md` P0-6.


## 7. The open design question: per-FIFO state vs. the shared DS range

Today `RolloverZoneState` is per-**zone**: one `rollover_phase`, one
submitted/confirmed DS index range. Parallel FIFOs want **per-FIFO
phase/progress** (old = "draining", new = "establishing"), naturally keyed
**(zone, role, algorithm)** — one row in steady state, two during a roll.

But there is exactly **one physical DS RRset at the parent**, holding every
FIFO's DSes. So the submitted/confirmed DS range is most naturally
**per-zone** (an aggregate), while each FIFO tracks its own key's DS
status. Reconciling per-FIFO phase with the shared per-zone DS range is
the main thing to design; everything else in §6 is wiring over existing
primitives. Options to weigh when we spec this:

- per-(zone, role, algorithm) rollover-state rows + a shared per-zone DS
  range row; or
- keep the DS range per-key (each FIFO's head/members carry their own
  submitted/confirmed markers) and derive the parent DS set as their union.

This is the first thing to settle before build.


## 8. Corner cases (the four that motivated this design)

- **(a) The new FIFO's first key is different — it is a bootstrap.** Every
  FIFO's first key is inherently sign-first (no same-FIFO predecessor to
  pre-position a DS against). This is identical to bootstrapping a zone's
  initial chain, run alongside an existing one — reuse that machinery
  rather than inventing an algorithm-roll special case. Multi-DS's
  "DS-first" is a steady-state optimization that only works once a FIFO
  already has an active key.
- **(b) Double-signature must be general, not algorithm-roll-only.**
  Handled by D1/D2 — it becomes a first-class method and the likely KSK
  default. The algorithm rollover is then "double-signature where the new
  FIFO's key differs in algorithm."
- **(c) FIFO instantiation is the new machinery.** Spawn (allocate
  identity, bootstrap head), run in parallel, freeze + drain + drop.
  Freezing means **deleting the old FIFO's orphaned standbys and
  withdrawing their DSes**, not letting them sit.
- **(d) We already have two parallel FIFOs.** KSK + ZSK. This design
  generalizes N from 2 to 3, jointly managing the DNSKEY RRset — extending
  the existing pattern.

**Re-entrancy.** An algorithm roll must be refused while a same-algorithm
roll is in flight on that FIFO, so the old FIFO is always in a clean
one-active state when it freezes (2026-06-21 §5.3 / K3 predicate; measure
against the bound algorithm, per `3c6f7d3`).


## 9. Re-rating the 2026-06-21 build steps

The 2026-06-21 plan assumed the engine carries the roll unchanged and the
only real change was a pipeline-counting bump (its K-3). Under this model:

- **K-1 (entry-layer dispatch + refusals)** — unchanged and still valid.
  Reuses the ZSK `change-policy` guards; adds the KSK role branch.
- **K-2 (reconcile hand-off)** — **changes meaning.** It is no longer
  "turn the refusal into a no-op and let the multi-DS engine carry it"
  (multi-DS cannot — §1). It becomes "route the KSK-algorithm mismatch into
  the **double-signature / FIFO-spawn** path." The two refusals to flip are
  still `apihandler_zone.go:517` (entry) and `sign.go:314` (reconcile
  backstop). Risk profile from the earlier re-grounding still holds: the
  synchronous retire is *deleted*, so a wrong branch yields a stuck/refused
  roll, not a bogus zone.
- **K-3 (pipeline-fill bump)** — **replaced** by **FIFO instantiation**
  (§6, corner c). This is larger than a counting bump: spawning a parallel
  FIFO, bootstrapping its head, and the per-FIFO state (§7). Still the
  highest-risk engine change; still a separate, testbed-checkpointed commit.
- **New steps** not in the 2026-06-21 plan:
  - the **invariant change** (D3, `pickActiveSEPTx`) — pairs with the ZSK
    single-active guard (clean-then-generalize prerequisite);
  - **generalizing the double-signature method** (D1/D2) — the same-algorithm
    double-signature path, which the algorithm roll builds on;
  - **per-FIFO rollover state** (§7).
- **K-4 (trigger UX + status)** — unchanged in spirit; status must now show
  two KSK FIFOs during a roll (old draining, new establishing).
- **K-5 (full-sequence + timing tests)** — unchanged in spirit; the
  full-sequence test now drives the spawn → double-sign → confirm → drain →
  drop lifecycle, and asserts the invariant (one active per (role,algorithm))
  and no-zero-chain at every step.

**Effort:** materially larger than the 2026-06-21 estimate (~17–29 h),
which assumed "rides multi-DS unchanged." A real breakdown belongs in a
follow-up once §7 is settled; the new weight is the double-signature method
generalization + FIFO instantiation + per-FIFO state.


## 10. Sequencing (clean-then-generalize)

Per the ZSK cleanup punch-list
(`2026-07-01-zsk-alg-rollover-cleanups.md` §0), land the
generalization-enabling cleanups **first**, so this work builds on shared
primitives instead of duplicating KSK-shaped code:

1. The **single-active guard** (punch-list P0-2) — implement it directly as
   the **"one active per (role, algorithm)"** invariant (D3), so the ZSK fix
   and the KSK enabler are the same commit.
2. A **role-generalized in-flight / `FromAlg` predicate** (P0-4 +
   generalizing `zskAlgRollInFlight`) — the re-entrancy guard both roles need.
3. The `256/257` **flag constants** (P2-1) and a **`firstKeyOfRole` helper**
   (P2-4) — touched heavily by the FIFO work.

Then: generalize the double-signature method (same-algorithm) → build FIFO
instantiation → wire the algorithm rollover on top.


## 11. Summary

- Multi-DS cannot do a KSK algorithm rollover: pre-positioning a
  new-algorithm DS with nothing signing that algorithm is an orphan DS /
  downgrade signature (§1). The parent DS is what forces double-signature.
- Model it as **parallel FIFOs keyed (role, algorithm)**, generalizing the
  KSK+ZSK pair already present (§2). A KSK algorithm rollover spawns a
  parallel new-algorithm FIFO; the old-algorithm FIFO keeps its key active
  until the new-algorithm DS confirms, then drains and is dropped.
- **Double-signature** becomes a first-class, general method — likely the
  KSK default (§3).
- Invariant: **one active per (role, algorithm)** (§4), which also closes
  the ZSK single-active gap.
- Most primitives are reused (additive signer, `AtomicRollover`, FACT-3
  drain, bootstrap-activation); the new work is the invariant change, FIFO
  instantiation, per-FIFO state, and generalizing the double-signature
  method (§6).
- The one genuinely open modelling question is per-FIFO rollover state vs.
  the shared per-zone DS range (§7); settle it before build.
