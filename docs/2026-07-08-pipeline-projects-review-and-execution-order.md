# Pipeline projects — alignment review & recommended execution order

**Date:** 2026-07-08
**Status:** review for discussion — no code or docs changed
**Scope:** three in-pipeline projects, reviewed for (1) doc↔code alignment and
(2) the best order to execute them, relative to the in-flight #275/#257 PRs.

Projects reviewed (scope as confirmed with the author):
- **(a)** Zone-mutation **snapshot correctness** — immutable snapshot + transaction
  log + `atomic.Pointer` version switch. *(IXFR = separate later project;
  outbound-transfer hardening = already done — both out of scope here.)*
- **(b)** **KSK algorithm rollover** via two parallel FIFOs. *(ZSK dual-model = out
  of scope.)*
- **(c)** **tdns-mp ↔ tdns-transport registry consolidation** — collapse the
  duplicated per-peer registries down to one `transport.Peer` registry in
  tdns-transport, and clean the interface between the two.

Baseline: tdns working tree on `feature/alg-registry-generator` (#275); each plan
cross-checked against actual code (not doc-trusted). File:line anchors below were
code-verified.

---

## TL;DR

- **All three plans are still in line with the code.** Drift is cosmetic
  (shifted line anchors, a couple of stale status lines) — no structural rot.
- **Readiness differs sharply:**
  - **(a)** is *implementation-ready* (review signed off, prerequisite already
    met, ~0% built) — and fixes a **real, reproducible correctness bug**.
  - **(c)** is *~70–80% done* by hard-effort; the inventive half is finished and
    testbed-verified, the rest is largely mechanical deletion.
  - **(b)** is *design-strong but not build-ready*: one open modelling question
    (§7) must be settled, and it sits behind **#275 + the ZSK cleanups**.
- **Recommended order:** **land #275 → finish (c) → land (a) → do (b).**
  (a)'s tdns-*core* work can run in parallel with (c); (a)'s tdns-mp leg must land
  *after* (c). The DNSSEC track (ZSK cleanups → (b)) is independent and can run
  concurrently once #275 is in.
- **(a)/(c) coordination (not a hard constraint):** both are significant tdns-mp
  efforts, so avoid running them at once — and don't interrupt (c)'s risky Phase 1.
  *(The `tdns.SliceZone` reference in tdns-mp is NOT a real forcing function — the
  author confirms tdns-mp doesn't need SliceZone, it merely references it; the
  cleanup is trivial and already known. Earlier draft over-weighted it.)*

---

## Per-project findings

### (a) Zone-mutation snapshot correctness

**The bug is real.** `GetOwner` returns a copy of the map *value*, but `RRtypes`
is a pointer, so the copy shares the live `*RRTypeStore`
(`v2/zone_utils.go:442-457`). Query-path write-backs (apex re-sign, SOA serial
stamps, positive-answer `Set`-after-sign) mutate *published* data while the SOA
serial is bumped separately — so two secondaries can serve different content
under the same serial. Confirmed at `v2/queryresponder.go:108/115/339-340/775`
and the ~15 mutator sites the plan enumerates.

**Status: ~0% built.** No `ZoneSnapshot`, `atomic.Pointer[ZoneSnapshot]`,
`workingSet`, `publish()` anywhere in `v2/` or `tdns-mp/v2/`. The only partial
convergence is per-RRset atomicity in `ResignZone`/`StripZoneRRSIGs`
(`v2/sign.go:560-580`) — narrower than the plan's zone-level, serial-boundary
guarantee.

**Alignment: sound, light anchor-refresh needed.** All named structs/funcs exist;
`structs.go` line anchors have shifted ~5-6 lines (`ZoneData` now :105, `IxfrChain`
:135, `Ixfr` :504). The plan's headline prerequisite — "Project A step 0 retires
SliceZone; store becomes map-only" — is **already satisfied** (`ZoneStore` is only
`XfrZone`+`MapZone`; `SliceZone` survives only in a test). The adversarial review
(`…-review.md`) is signed off "no blockers"; open items are doc nits (N1-N3 stale
milestone labels) foldable at implementation time.

**Dependencies & blast radius.** No conflict with #275 or #257 (zone-data layer is
untouched by both). Blast radius **large and correctly self-assessed**: it reshapes
the core served type on the hottest path (~2000-2400 LOC), and **it ripples into
tdns-mp**, which embeds `*tdns.ZoneData` and mutates zone data directly in
`mp_signer.go`/`combiner_utils.go` (9+ `Set` sites) — those must route through the
new staging API, cross-repo, landing compatibly.

**Readiness: implementation-ready** (after a ~30-min anchor-refresh pass).

### (b) KSK algorithm rollover — parallel FIFO

**Mechanism.** Multi-DS *cannot* do an algorithm rollover (a pre-positioned
`DS(newalg)` with nothing yet signing under that algorithm is an orphan DS,
indistinguishable from a downgrade). The design does a double-signature roll: the
engine already runs a KSK FIFO and a ZSK FIFO in parallel that jointly emit the
apex DNSKEY RRset; an alg roll transiently **spawns a second, new-algorithm KSK
FIFO** (N:2→3), keeps the old-alg KSK active until the new-alg DS confirms, then
drains and drops it.

**Status: engine is single-track today.** Nothing multi-FIFO exists; the
`double-signature` method is **scaffolded but unimplemented**
(`v2/ksk_rollover_policy.go:53/231/407`). The single-active-SEP guard the design
must rescope (to *one active per (role, algorithm)*) is present and hard-errors
today (`v2/ksk_rollover_atomic.go:152-178`). Per-zone rollover state
(`v2/ksk_rollover_zone_state.go:19`) exists and is exactly what §7 must extend to
per-FIFO.

**Alignment: sound; registry-agnostic.** Minor drift (filename shorthand
`ds_push.go`→`ksk_rollover_ds_push.go`; doc cites `feat/tsig-first-class` line
numbers, resolve anyway). Crucially, the FIFO engine keys everything on `uint8`
codepoints and does **not** import `v2/algorithms`, so #275's registry rework does
*not* invalidate it. The one real touch-point is policy validation:
`validateRoleCapabilities` (`v2/large_ksk.go:130-153`, new on #275) now gates a
target algorithm's role via `CapsReal`/`ForKSK`/`ForZSK` — which is precisely the
correct substrate for minting a `ForKSK && !ForZSK` PQ KSK. The design predates
that function; it doesn't conflict, but should adopt it.

**Not build-ready — one open design question.** §7 (per-FIFO rollover state keyed
`(zone, role, algorithm)` vs. the single physical per-zone DS RRset at the parent)
is explicitly "settle before build." Plus a self-flagged margin-correctness check
(§5) and a role/mode-aware signer-strip change that must be co-designed with ZSK
cleanup P0-6 (§6).

**Dependencies (firm, and they drive ordering):**
1. **#275 must land first** — the role-capability model (`ForKSK`/`ForZSK`) is the
   substrate for alg-split policies.
2. **ZSK cleanups first** (`docs/2026-07-01-zsk-alg-rollover-cleanups.md`): the D3
   invariant unifies with **P0-2**, the signer-strip logic co-designs with **P0-6**,
   the in-flight predicate generalizes via **P0-4**. Starting (b) before these
   duplicates KSK-shaped code the cleanups are meant to share.
3. Then: generalize double-signature (same-alg) → FIFO instantiation → alg roll.

**Readiness: needs one focused design pass (§7)**, then it's the most-gated of the three.

### (c) tdns-mp ↔ tdns-transport registry consolidation

**End state.** Two peer-state stores joined only by `PeerID`:
`transport.PeerRegistry` (identity/address/per-mechanism state/liveness/crypto/stats)
as the sole source of truth, and one nearly-empty MP `AgentRegistry` view. Transport
speaks an opaque `{Scope, TypeToken, Payload}` vocabulary; no MP body types in
transport. (Collapsing to a single Go map is provably impossible across the package
boundary — the real target is "one allocation, two typed views, no bridge.")

**Status: ~70–80% done by hard-effort; at end of A3d-END.1 (E1.a).** The inventive
half — making `transport.Peer` canonical without breaking the live beat/hello state
machine — is **done and testbed-verified**: `AgentDetails.State` has **zero**
functional writers, the hsync engine reads `transport.Peer`
(`hsync/hello.go:24/98`), decay-on-read lives on transport (`peer.go:269`), and
`Agent` embeds `*hsync.Peer` (`agent_structs.go:84-97`). What remains (E1.b bridge
teardown → delete `AgentDetails` → crypto rehome → discovery relocate → inbound
collapse) is largely **compiler-checkable deletion**. Est. ~3.5–6.5 sessions to the
single-registry end state. *(Stage C — the reusable-library "opaque seam" — is a
separate ~5-7 sessions at 0%, and is downstream of the consolidation.)*

**Open issues: both already resolved in code.** The a3d-end0 testbed regression was
properly retired by D2.5 (engine repointed at `transport.Peer`; `hsync/d25_test.go`
guards it). The peer-state/discovery "truth-fix" (4 bugs) landed and has operator
sign-off. The doc status lines that still say "regression found" are stale history.

**Alignment: no structural drift.** `2026-06-14-road-to-stage-C-plan.md` is the doc
that best matches reality (it supersedes v3 for the END/A5/discovery work); **v3
remains authoritative for Stage C and D/E/F**. Only cosmetic nits (a stale
`peer.go:85` "legacy fields canonical" comment; the stale status line above).

**Dependencies: self-contained — with one latent collision.** Phases 1–3 need **no
tdns core changes** and #275 is already absorbed (Gate-2 pinned the shared
`johanix/dns` fork). Project (a) does **not** collide with the transport/peer work
(orthogonal). **But:** `tdns-mp/v2/hsync_utils.go:1189-1190` still references
`tdns.SliceZone` / `mpzd.Owners`, both **deleted by the already-merged Project A**.
tdns-mp is insulated *today* only because it pins tdns/v2 at 2026-06-11 (pre-Project-A).
The moment tdns-mp advances that pin, the build breaks there (one-line fix).

**Readiness: executable as-is** on the road-to-C plan. Biggest risk: Phase 1 (E1.b)
— universal pointer-sharing + collapsing to one mutex per peer + bridge teardown, all
at once on the live state machine ("riskiest commit of the stage"). **Do not interrupt
it mid-flight.**

---

## Cross-project dependency & collision map

```
#275 (alg registry, lands soon) ──┬─► (b) role-capability substrate  [HARD PREREQ]
                                  └─► already absorbed by (c) (Gate-2) [settled]

ZSK cleanups (P0-2/4/6) ─────────────► (b)  [HARD PREREQ — shared invariant/strip]

(b) §7 design pass ──────────────────► (b) build  [must settle first]

Project A (SliceZone deleted, MERGED) ─► latent break in (c)'s repo (tdns-mp:1189)
                                          triggered by any tdns-dep bump

(a) staging API (tdns core) ─────────► forces tdns-mp dep bump ─► trips the
                                          SliceZone break + needs Set-site routing
                                          ⇒ (a)'s tdns-mp leg must land on a STABLE
                                            tdns-mp ⇒ after (c) consolidates

(a) ⟂ (b): different subsystem, no interaction.
(c) ⟂ (b): different subsystem, no interaction.
#257 (imr transport): independent of all three; own schedule; gates nothing here.
```

The only genuine entanglement is **(a) ↔ (c) via tdns-mp**: both are significant
tdns-mp efforts, and (a)'s dep bump trips (c)'s dormant SliceZone break. They don't
share files, but running two large tdns-mp refactors at once (one near a delicate
concurrency commit) is the thing to avoid.

---

## Rough effort estimates (LOC)

LOC is a **misleading cross-project unit here** — (a) is additive new machinery on
the hottest path, (b) is an additive state-machine, **(c) is mostly deletion**
(net-negative). Read the "net" column, not the total.

| Project | Impl | Test | Total (gross) | Net | Confidence |
|---|---|---|---|---|---|
| **(a)** snapshot correctness | ~1400–1800 | ~600 | **~2000–2400** | additive | **high** — author's revised §6 |
| **(b)** KSK parallel-FIFO *proper* | — | — | **~1200–2200** | additive | **low** — design defers it (§7) |
| **(b)** prereq: ZSK cleanups (P0-2/4/6 + P2-1/4 helpers) | — | — | **~300–600** | additive | med-low |
| **(c)** → one registry (Phases 1–3) | deletion-dominant | | **~800–1500 gross, NET negative** | removes code | med; already ~70–80% done |
| **(c)** Stage C seam (separate, downstream, 0%) | — | | ~1500–3000 gross (reorg) | moves code | low |

- **(a) ~2000–2400 LOC** (~20–40 h): firmest figure — the plan's own revised §6
  estimate; reviewer judged it "credible, if anything on the low side."
- **(b) ~1500–2800 LOC end-to-end** incl. the ZSK-cleanup prerequisite — the
  **softest** number: the design doc explicitly defers a real breakdown until §7 is
  settled. Anchored on the older "rides multi-DS unchanged" estimate (~630–1000 LOC /
  17–29 h), scaled up for the "materially larger" parallel-FIFO machinery.
- **(c)** don't read its low/negative net LOC as "small effort." It's ~70–80% done;
  the tail is deletion (strip `AgentDetails` fields from a 427-line file, tear down
  the 148-line copy-bridge, slim the 331-line bridge wiring) + one risky rewrite
  (Phase 1 E1.b concurrency) + a net-zero discovery move. Plan measures it as
  **~3.5–6.5 sessions** to the single-registry end state; LOC understates progress and
  overstates remaining effort.

**Remaining-effort ranking:** (a) ≳ (b) > (c-remaining). **Risk ranking:** (a)'s
hot-path rewrite and (c)'s Phase 1 concurrency are the spiky ones; (b)'s risk is the
§7 model + DS-coordination correctness.

## Recommended execution order

**Primary spine:**

1. **Land #275** (imminent; already decided). Unblocks (b)'s prerequisites and the
   already-built `large-alg-prefix` follow-on.

2. **Finish (c) to its single-registry end state** (Phases 1–3), keeping tdns-mp's
   tdns/v2 dep **pinned** throughout. *Why first:* it's furthest along, fully
   self-contained, momentum-sensitive (don't interrupt the risky Phase 1), and
   finishing it lands tdns-mp in a clean, consolidated state that makes (a)'s
   cross-repo leg far easier.

3. **Land (a) snapshot correctness.** Start the **tdns-core** work (B1→B2→B3) now —
   it's independent and can run *in parallel with (c)* since it's a different repo
   area. Prefer to land the **tdns-mp leg** (dep bump + route the 9+ `Set` sites
   through the staging API) **after (c) consolidates**, so tdns-mp isn't carrying
   two big refactors at once — but this is a soft preference, not a hard gate.
   *(The `tdns.SliceZone` reference tripped by the dep bump is a trivial known
   one-liner, not a blocker.)*

4. **Do (b) KSK parallel-FIFO** — naturally last. After #275: run the **ZSK
   cleanups**, then the **§7 design pass**, then build (generalize double-signature →
   FIFO instantiation → alg roll). This whole DNSSEC track is independent of (a)/(c)
   and can proceed on its own thread whenever attention allows.

**If you parallelize** (two independent threads):
- *Thread α — zone-data / tdns-mp:* (c) → (a). (a)'s tdns-core work overlaps (c).
- *Thread β — DNSSEC:* [#275] → ZSK cleanups → (b) §7 design → (b).

**If you serialize** (strictly one thing at a time):
`#275 → (c) → (a) → ZSK cleanups → (b) §7 design → (b)`.

**Judgment call to flag:** (a) fixes a *live correctness bug* (cross-secondary serial
divergence), whereas (c) is consolidation/quality. If that bug is actually biting in
production, (a)'s **tdns-core** portion can jump the queue immediately (it needs
nothing from (c)); only its tdns-mp leg should still wait for (c). Momentum otherwise
favors finishing (c) first.

**#257 note:** it's on its own track (phase2 already prepped), slower, and gates
nothing here — merge it whenever it's ready, independent of this sequence.

---

## Coordination checkpoints & watch-items

1. **No reason to bump tdns-mp's tdns/v2 dep mid-(c).** Keeping it pinned avoids
   dragging unrelated tdns churn into the refactor. When (a)'s tdns-mp leg does bump
   it, the `tdns.SliceZone` reference (`tdns-mp/v2/hsync_utils.go:1189`) needs a
   trivial one-line cleanup — known and expected, not a blocker.
2. **Don't interrupt (c) Phase 1 (E1.b).** It's the highest-risk single commit
   (one-mutex-per-peer + bridge teardown on the live state machine); it wants a clean
   run with `-race` + a testbed checkpoint, not a context switch.
3. **(b) is not "start now."** It needs #275 landed, the ZSK cleanups done, and the
   §7 design settled — in that order. Doing the §7 pass early (it's cheap, ~1 session)
   is the highest-leverage prep.
4. **Doc hygiene (cheap, do opportunistically):** re-pin (a)'s `structs.go` anchors
   and fold review nits N1-N3; clear (c)'s two stale status lines
   (`a3d-end0` "regression found", `peer.go:85` "legacy fields canonical"); note in
   (b)'s doc that `validateRoleCapabilities` (post-#275) is now the role-capability gate.

---

## One-line verdict per project

| Project | Doc↔code | Built | Ready to start? | Gated by |
|---|---|---|---|---|
| **(a)** snapshot correctness | in line (anchor drift) | ~0% | **yes** (core now; tdns-mp leg after (c)) | — |
| **(b)** KSK parallel FIFO | in line; registry-agnostic | ~0% (scaffold only) | **no** — needs §7 design | #275 + ZSK cleanups |
| **(c)** registry consolidation | in line (road-to-C is live) | ~70–80% | **in progress — finish it** | — (keep dep pinned) |
