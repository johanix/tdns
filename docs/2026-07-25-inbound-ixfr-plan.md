# Project C2 — Inbound IXFR (RFC 1995)

**Date:** 2026-07-25
**Status:** AGREED — firmed up against main @ 138c9ce (which has #328 outbound
IXFR merged), and both open forks decided 2026-07-25 (F1: `request-ixfr`,
default ON; F2: materialize+swap for v1). **Re-audited 2026-08-29 against main
@ `ea391786`**: the design survives, the line numbers in §2 are refreshed, and
§4.1 is rewritten — the refresh path does SOA-probe before
`FetchFromUpstream`, which the earlier text denied, and since
`2026-08-28-secondary-serve-until-expire.md` Stage 2 that probe carries the
zone's SOA EXPIRE clock. Implementing the old
§4.1 literally would have taken stable zones dark against healthy primaries.
Ready to implement once §4.1's choice is made.
Onward-relay of inbound deltas to further downstreams is now **in scope for the
non-signing case** — the serial-mirror fix in [[secondary-zones-immutable]]
collapses the inbound/outbound serial spaces, making an inbound delta a verbatim
outbound-chain link (§5). Only the *signing*-secondary relay (staging-apply)
stays deferred (§7 F2-follow-up, §8 PR-2).
**Depends on:** `2026-07-25-secondary-zones-immutable.md` — **landed**, whatever
that document's own status line still says: `v2/zone_origination.go`
(`zoneMayOriginateContent`), the `SuppressedOptions` plumbing and the
serial-mirror drift check at `v2/zone_mutation.go:598` are all on main. The
prerequisite is cleared. `2026-08-28-secondary-serve-until-expire.md` has also
landed since this was written, and constrains §4.1.
**Companion / base:** `2026-07-02-ixfr-support.md` (Project C). #328 delivered
the outbound half (retention + serving); this is the deferred C2 half — the
secondary side that *requests and consumes* incremental transfers.

---

## 1. Motivation & the one hard invariant

A tdns secondary currently always pulls a full AXFR on every refresh, even when
one record changed. Inbound IXFR lets it pull just the delta.

The blast-radius asymmetry from the original sketch decides the whole shape of
this project: **an inbound IXFR bug corrupts only this server's own copy, and
self-heals by re-pulling a full AXFR.** An outbound bug ships a wrong delta to
downstreams (silent divergence) — which is why #328 was built first and
carefully. Inbound is lower-risk, but only if we hold the invariant that made it
so:

> **AXFR fallback is always available; IXFR-in is never a correctness
> dependency.** Any doubt — IXFR disabled, no baseline, up-to-date, a server
> that answers with a full zone, a malformed/non-contiguous/short difference
> stream, an out-of-zone record, a serial that doesn't line up — resolves to a
> full AXFR (or a no-op). The worst case of any inbound bug is a wasteful full
> transfer, never a corrupt local zone.

## 2. Verified state of main (2026-07-25, re-audited 2026-08-29)

Re-audited against `main` @ `ea391786`, ~450 commits past the `138c9ce` this
was first written for. Every structural claim below survived; the line numbers
did not, and are updated. One design paragraph did not survive at all — see
§4.1, which now has to account for work that landed in the interval.

- `FetchFromUpstream` (`v2/zone_utils.go:749`) is the sole refresh path. It
  builds a fresh `new_zd`, calls `new_zd.ZoneTransferIn(ctx, up,
  zd.IncomingSerial, "axfr", conf)` with the transfer type **hardcoded to
  `"axfr"`** (:792), then swaps the result in wholesale via
  `applyRefreshReplacementLocked` (`v2/zone_mutation.go:611`). The no-op check
  is now factored out as `shouldDiscardUnchangedTransfer` (:818), which
  compares serials for EQUALITY -- wrap-safe, and unaffected by the RFC 1982
  change described in §4.5.
- `ZoneTransferIn` (`v2/dnsutils.go:157`) already *can* emit an IXFR query — it
  has the `ttype == "ixfr"` branch calling `msg.SetIxfr(zd.ZoneName, serial,
  ".", ".")` (root MNAME/RNAME, fixed in #328). But it feeds **every** received
  RR through `SortFunc` (`:852`, driven from `:119`), which records only the
  *first* SOA (`if !firstSoaSeen`)
  and blindly appends every other RR into `Data`. Feeding it a difference
  stream would silently corrupt the zone (deleted records get *added*, bracket
  SOAs dropped). **So the request path exists; the response path does not.**
- `IsIxfr(rrs []dns.RR)` (`v2/zone_utils.go:1253`) returns true iff `rrs[0]` and
  `rrs[1]` are both SOA — exactly the RFC 1995 §4 "this is a delta, not a full
  zone" test. It is **currently unused**; C2 is its first caller.
- The johanix/dns fork's `Transfer.In`/`inIxfr` (v1.1.72-johanix.2) already
  drives the IXFR request and streams the response envelopes. Its client-side
  behavior, verified:
  - up-to-date (`qser >= serverSerial`): delivers a single `SOA(serverSerial)`
    envelope and closes — our collector sees exactly `[SOA]`;
  - otherwise: delivers **all** Answer RRs verbatim (it counts SOAs only to know
    when to stop reading; it does NOT parse difference sequences). So the
    difference-sequence parsing is unambiguously *our* job.
- Apply/swap machinery from Project B is intact: `applyRefreshReplacementLocked`
  (`v2/zone_mutation.go`) does the atomic wholesale swap and (post-#328) sets
  `wsIxfrEpochReset = true`, resetting the *outbound* chain on every refresh
  replacement (see §5). Helpers `cloneRRset`, `NewRRTypeStore`, and the RRSIG
  routing pattern in `SortFunc` are all reusable.
- `zd.XfrType` (`"axfr"|"ixfr"`) exists but is vestigial for *driving* transfer
  type — set to `"axfr"` in `ParseZoneFromReader` (`v2/dnsutils.go:845`),
  carried into `new_zd`, never
  read to choose a transfer type. (#328's outbound doc flagged it "wire or
  delete.") C2 is where it's decided — see F1.

## 3. Guiding principles

1. **The AXFR path is untouched.** `ttype == "axfr"` keeps streaming through
   `SortFunc` exactly as today. IXFR is a new, parallel path; a bug in it can
   never regress AXFR. This is the single most important structural rule.
2. Attempt IXFR only when it can possibly help: IXFR is enabled for the zone AND
   a baseline exists (`IncomingSerial != 0` and we currently serve data).
3. Any classification/parse/apply failure logs loudly and re-pulls a full AXFR
   in the same refresh cycle (self-heal). A zone is never left half-applied.
4. The delta is applied to an off-line copy and swapped in atomically via the
   existing `applyRefreshReplacementLocked` — never mutated on the live served
   view (preserves Project B's no-torn-reads guarantee).

## 4. Design

### 4.1 Attempt decision (`FetchFromUpstream`)

Per upstream attempt, choose the transfer type:

```
useIxfr := zd.requestIxfr()            // F1: per-zone option, default per fork
          && zd.IncomingSerial != 0    // have a serial to ask from
          && zd.publishedSnapshot() != nil  // have a baseline to apply onto
```

`--via axfr` behavior is the current code path, unchanged. When `useIxfr`, take
the new path in §4.2–4.4; on ANY failure there, fall back to a plain AXFR
attempt against the *same* upstream before advancing to the next upstream
(fallback is not a per-upstream failure — the upstream answered, we just
couldn't use the delta).

**The refresh path DOES SOA-probe before `FetchFromUpstream`, and the probe now
carries the zone's expire clock.** The earlier version of this paragraph said
the opposite and proposed dropping the probe, on the reasoning that an IXFR
query carries our serial and lets the server decide. That reasoning is still
sound about transfers and wrong about everything else the probe does now.

`Refresh`'s `Secondary` branch calls `DoTransfer` (`v2/zone_utils.go:214`),
which is an SOA probe, and only calls `FetchFromUpstream` when the serial
moved. Since `2026-08-28-secondary-serve-until-expire.md` Stage 2,
`DoTransfer`'s two usable-SOA returns (`:378`, `:381`) hold two of the three
`noteSuccessfulRefresh` calls in the tree -- and they are the **only** source of
confirmation for the steady state: serial unchanged, nothing transferred,
primary demonstrably alive.

Remove the probe without replacing what it feeds and a stable zone stops
re-confirming. `LatestRefresh` freezes at the last transfer, and once SOA
EXPIRE elapses the secondary SERVFAILs every query while its primary is healthy
and answering. That is the exact failure the expire work exists to prevent,
reintroduced from the other side, and no test in the suite would catch it --
nothing waits out an expire interval.

So C2 has a choice, and it must make it explicitly:

- **Keep the probe** (smallest change). `DoTransfer` runs as today and decides
  whether to transfer; C2 changes only what the transfer itself is. The IXFR
  request then re-asks a question already answered, which is one wasted round
  trip per changed zone and no correctness cost.
- **Fold the probe into the IXFR request** (what the original paragraph wanted).
  Then the up-to-date reply -- a single SOA from the primary -- IS a usable SOA
  and **must** call `noteSuccessfulRefresh`, as must the delta path once the
  stream is accepted. Nothing else in the expire design needs to change: the
  stamp is about the primary being alive, not about how we asked.

Either is defensible. What is not defensible is dropping the probe and leaving
the stamp behind, which is what implementing the previous text literally would
have done. Whichever is chosen, the acceptance sketch (§10) needs a case for it:
a zone whose serial never moves must still re-confirm, and must still be
answering after more than one SOA EXPIRE has passed.

### 4.2 Client-side classification

`ZoneTransferIn` gains an IXFR branch that, instead of feeding `SortFunc`,
**collects** the flat RR stream from all envelopes into `[]dns.RR`, then
classifies (this buffering is IXFR-only; AXFR keeps streaming):

| Observed | Meaning | Action |
|---|---|---|
| exactly 1 RR, an SOA | up-to-date (server serial ≤ ours) | no-op refresh |
| `!IsIxfr(rrs)` (SOA, then non-SOA … SOA) | server fell back to a full zone (RFC 1995 §4) | apply as AXFR: run the collected RRs through `SortFunc` into `new_zd.Data`, then the normal swap |
| `IsIxfr(rrs)` (SOA, SOA, …) | real delta | parse §4.3, apply §4.4 |

The full-zone case means a non-tdns (or unwilling) primary answered our IXFR
with an AXFR — fully RFC-compliant and requiring zero delta logic: it reuses the
existing apply verbatim. This is the most important fallback and the cheapest to
get right.

### 4.3 Difference-sequence parser

Input (delta case), matching #328's own outbound emission and RFC 1995:

```
SOA(S)                                   leading, S = server's current serial
  SOA(from_1) del_1…  SOA(to_1) add_1…   difference sequence 1
  SOA(from_2) del_2…  SOA(to_2) add_2…   difference sequence 2 (from_2 == to_1)
  …
SOA(S)                                   trailing bookend, to_last == S
```

`parseIxfrDeltas(rrs, clientSerial) → ([]ixfrStep, error)`:

- `rrs[0]` and `rrs[len-1]` must both be `SOA(S)`; else error.
- Between them, alternate: an SOA opens a **delete** section (its serial =
  `from`), non-SOA RRs accumulate until the next SOA which opens the **add**
  section (its serial = `to`), non-SOA RRs accumulate until the next SOA. That
  next SOA is either the following sequence's `from`-SOA or, at the final index,
  the trailing bookend (positional disambiguation — clean and unambiguous).
- Each `ixfrStep{from, to, removed []dns.RR, added []dns.RR}`.
- Validate: `from_1 == clientSerial`; `to_k == from_{k+1}` (contiguous);
  `to_last == S`; every owner name in `added` is in-bailiwick. Any violation →
  error → AXFR fallback.
- Condensed responses (a single sequence `clientSerial → S`) parse naturally —
  no special case, and no need to *produce* condensation (that's an outbound
  concern we already declined).

RRSIG RRs are ordinary members of the del/add sections (routed by
`TypeCovered`, exactly as `SortFunc` does) — no special handling beyond correct
routing at apply time.

### 4.4 Apply model (v1: materialize → apply → swap)

The delta must be applied onto our *current* content, but the existing refresh
builds `new_zd` from scratch. v1 bridges cleanly (F2 records the alternative):

1. Materialize the current published snapshot into `new_zd.Data`: for every
   owner, a fresh `OwnerData` with `cloneRRset`'d RRsets (so applying deltas
   never mutates the live, shared, immutable snapshot stores).
2. For each `ixfrStep` in order: apply `removed` (delete the exact matching RR
   from its owner/type RRset; drop the RRset when empty — RFC 1995 delete is
   RFC 2136 §2.5.4 delete-exact-RR semantics, reusing `RRset.RemoveRR`), then
   apply `added` (append the RR, routing RRSIGs to `.RRSIGs`). Advance the
   running serial to `step.to`.
3. Set `new_zd.IncomingSerial = new_zd.CurrentSerial = S`, then hand `new_zd` to
   the **same** `applyRefreshReplacementLocked` the AXFR path uses. Snapshot
   correctness, re-signing (for signing secondaries), persistence, and the
   Ready flip all come for free and identically to AXFR.

An apply that references a record that isn't present (delete of a non-existent
RR, or an add that duplicates) is a divergence signal → abort → AXFR fallback,
rather than best-effort patching. Correctness over cleverness.

**Check `RemoveRR`'s handling of RRSIGs before relying on step 2.**
`core.RRset.RemoveRR` (`v2/core/rrset_utils.go:256`) does not only remove the
matched RR: on a successful removal it also clears the RRset's entire signature
list (`rrset.RRSIGs = []dns.RR{}`). For a delta that deletes one RR from a
signed RRset and re-adds the rest with fresh RRSIGs that is fine — the add
section carries the replacements. For a delta that deletes without re-signing
in the same sequence, the RRset is left unsigned and the zone is served with a
hole in its DNSSEC coverage.

Worth calling out separately because §1's invariant HIDES it. A wrong delete
aborts to AXFR and self-heals loudly; silently dropping signatures aborts
nothing, so the failure surfaces as validation failures at resolvers rather
than as a fallback in our own logs. Decide during implementation whether the
apply path re-attaches signatures itself or refuses a sequence that would leave
an RRset unsigned.

The matching itself is fine: `RemoveRR` compares through `core.IsDuplicate` →
`dns.IsDuplicate`, which is canonical and case-insensitive, and was unaffected
by the case-insensitive-names work in #425.

### 4.5 Serial handling

We send `zd.IncomingSerial` as the "have" serial. On success `IncomingSerial`
and `CurrentSerial` advance to `S` (the server's serial), identical to the AXFR
path's post-transfer assignment. The up-to-date case leaves both unchanged and
triggers the existing `new_zd.IncomingSerial == zd.IncomingSerial` no-op branch.

## 5. Interaction with the merged outbound chain (#328) — and why onward relay is nearly free in the immutable case

A tdns secondary can itself be a primary to further-downstreams. The naive
materialize+swap does `wsIxfrEpochReset = true`, which would reset this server's
outbound IXFR chain on every inbound refresh, so downstreams would get an AXFR
across each boundary — correct and safe, but not optimal.

**But for the common case — a non-signing tdns-auth secondary (immutable,
[[secondary-zones-immutable]] `2026-07-25-secondary-zones-immutable.md`) —
retaining inbound deltas as outbound deltas is nearly free, and this plan folds
it in rather than deferring it.** The enabler is the secondary-immutable
**serial-mirror fix**: once a non-signing secondary mirrors the upstream serial
(`CurrentSerial = IncomingSerial`), the outbound and inbound serial spaces
**collapse into one**. An inbound IXFR delta (upstream serial N→N+1) is then
*verbatim* a valid outbound delta (our serial N→N+1) — identical FromSerial /
ToSerial, identical RRs, and its bracket SOAs equal our served SOAs (we mirror
them). And #328 already ships the whole `IxfrChain` machine (the `Ixfr` link
struct, append, byte-budget trim, contiguity-checked serving). So retention
reduces to: **build an `Ixfr` link from the parsed inbound difference sequence
and append it (reusing #328's trim), instead of epoch-resetting the chain.** No
staging API, no serial translation, no re-derivation.

Safety rests directly on immutability: because we serve a faithful mirror, the
retained inbound delta is guaranteed consistent with our served content, so
relaying it cannot ship a wrong delta. Boundaries and edges are already handled:
an inbound **AXFR** (first load / fallback / gap) is an epoch-reset point (no
delta to append); and a **multi-upstream / cross-signer** seam is caught by
#328's serve-time contiguity check, which falls a downstream back to AXFR when
its serial isn't in the contiguous chain — safe and self-healing, just not
delta-efficient at that seam.

**Scope of the fold-in:** this applies to the **non-signing** secondary only. A
**signing** secondary re-signs, so its served content ≠ the inbound delta's
content; it would have to *build* fresh outbound deltas from its re-signed data —
the harder staging-apply variant, which stays deferred (§7 F2-follow-up, §8
PR-2). So: non-signing onward-relay is in scope for this project; the
signing/staging-apply variant remains a later PR.

## 6. Tests

- **Parser (table, unit):** single-step; multi-step contiguous; condensed
  single-sequence; up-to-date single SOA; AXFR-shaped (`IsIxfr` false);
  malformed (odd SOAs, non-contiguous serials, missing bookend, out-of-zone
  add) → error.
- **Apply (unit):** materialize a base zone, apply a delta, assert the resulting
  `Data` equals an independently-built expected zone (adds present, deletes
  gone, RRSIGs routed, RRset dropped when emptied).
- **End-to-end (loopback), the payoff test:** stand up a tdns primary (which
  now serves outbound IXFR, #328), bump it through a few serials, point a tdns
  secondary at it with IXFR enabled, and assert the secondary converges to
  byte-identical content via delta — then assert it also converges when the
  primary is forced to AXFR-fallback. This exercises #328 and C2 together and is
  the real acceptance gate.
- **Fallback (integration):** malformed/truncated delta and a non-contiguous
  chain both drive a clean AXFR re-pull and correct convergence; a plain AXFR
  primary (IXFR unsupported) works unchanged.
- **Onward-relay (non-signing, §5):** primary → tdns secondary (non-signing) →
  tdns edge, all IXFR-enabled. Bump the primary; assert the secondary applies
  the inbound delta AND appends it to its own outbound `IxfrChain`, and that the
  edge then pulls the change from the secondary *as a delta* (not AXFR) and
  converges byte-identically. Plus: after an inbound AXFR/gap boundary, the edge
  correctly falls back to AXFR (chain reset).
- Gate: full `v2` `-race`; gofmt; cmdv2 binaries build via gmake.

## 7. Design forks

- **F1 — IXFR-in enablement & default. DECIDED (2026-07-25): default ON.**
  A per-zone `request-ixfr` option (template-gap-filled and config-parsed like
  the others), default ON — BIND parity, the AXFR fallback makes it safe, and it
  is symmetric with #328's default-on retention. The vestigial `XfrType` field
  is retired in the same PR.
- **F2 — apply model. DECIDED (2026-07-25): v1 = materialize+swap (§4.4).**
  Simple, reuses the whole refresh path, obviously correct — at the accepted
  cost of a full-zone copy per delta. (The copy cost, not chain continuity, is
  now the only downside — see F2-follow-up.)
- **F2-follow-up — retain inbound deltas in the outbound chain. SPLIT
  (2026-07-25):**
  - **Non-signing secondary — IN SCOPE for this project (§5).** Once the
    serial-mirror fix ([[secondary-zones-immutable]]) collapses the serial
    spaces, an inbound delta *is* a valid outbound delta, so we append it to
    #328's existing `IxfrChain` instead of epoch-resetting — near-trivial, no
    staging API. Folded into PR-1 (§8).
  - **Signing secondary — still DEFERRED.** A re-signing secondary's served
    content ≠ the inbound delta, so it must *build* fresh outbound deltas from
    re-signed data via the staging API (`stageRRsetLocked`/`stageDeleteLocked`
    + `publishLocked`). More entangled with locking and publish cadence; a pure
    optimization on top of a correct v1. Later PR (§8 PR-2).
- **F3 — outbound-chain continuity across inbound refresh. UPDATED (2026-07-25):**
  a non-signing secondary now *preserves* continuity (relays deltas, per the F2
  fold-in); a signing secondary, and any AXFR/gap boundary, falls downstreams
  back to AXFR — safe and self-healing via #328's contiguity check. Not a
  correctness issue either way.
- **F4 — full-zone-fallback detection.** Use `IsIxfr` on the collected slice
  (SOA-then-SOA ⇒ delta; SOA-then-non-SOA ⇒ full zone). Decided; `IsIxfr`
  already exists and is exactly this test.
- **F5 — condensation.** Accept condensed responses (parse naturally); do not
  require or produce them. Decided.

## 8. Phasing

- **PR-1 — parser + apply + AXFR fallback + non-signing onward-relay, behind the
  option (default per F1).** The difference-sequence parser, the
  materialize+apply, the classification and AXFR-fallback wiring in
  `FetchFromUpstream`/`ZoneTransferIn`, the new `request-ixfr` option, `XfrType`
  retirement, **plus appending each inbound delta to the outbound `IxfrChain`
  for a non-signing secondary** (§5 / F2-follow-up — cheap once the serial-mirror
  fix lands, reusing #328's chain). Depends on [[secondary-zones-immutable]]
  landing first (serial mirror is the enabler). Parser + apply unit tests, the
  end-to-end loopback convergence test, and a relay test (secondary re-serves an
  inbound delta downstream as a delta).
- **PR-2 (optional, later) — signing-secondary onward-relay via staging-apply**
  (the deferred half of F2-follow-up): build fresh outbound deltas from
  re-signed data so a *signing* cascaded secondary also relays deltas. Agreed as
  a possibility, not scheduled.

## 9. Deferred / out of scope

- Signing-secondary staging-apply relay (F2-follow-up second half, §5, §8 PR-2).
- IXFR over UDP-in (we always use TCP for transfers; non-issue).
- Any change to outbound IXFR (#328 is done).

## 10. Acceptance sketch

- A secondary with `request-ixfr` on, pointed at a tdns primary, converges to
  byte-identical zone content via multi-step delta across several primary
  serial bumps; SOA serial tracks the primary.
- The same secondary converges when the primary answers with a full zone
  (AXFR-fallback), when the delta is malformed (re-pull), and when pointed at an
  AXFR-only primary (unchanged behavior).
- up-to-date IXFR is a clean no-op (no swap, no serial change, status restored).
- AXFR-only zones and the existing AXFR path show zero behavioral change.
- **A zone whose serial never moves keeps re-confirming.** Point a secondary at
  a primary that answers up-to-date every cycle, and it must still be answering
  after more than one SOA EXPIRE has elapsed — i.e. each up-to-date cycle
  advanced `LatestRefresh`. This is the case §4.1 can break silently: if the
  SOA probe is folded into the IXFR request and the up-to-date reply does not
  stamp, the zone goes dark against a primary that is healthy and answering.
  Not covered by convergence testing, because nothing converges — the serial
  never moves.

## 11. Size

Estimated 2026-08-29 from §4 and §6; no code written. LOC is first-cut
production vs test, counted the way the other briefs in this tree count.

Calibration: #328 delivered the outbound half in 413 production + 725 test
lines (`v2/ixfr.go`, `v2/ixfr_test.go`), having built the `IxfrChain`, its trim
and the serving path from nothing. C2 reuses all of that and adds a parser and
an apply model, so landing a little above it is the expected shape.

| | item | files | impl | test |
|---|---|---|---|---|
| **4.3** | `parseIxfrDeltas` + `ixfrStep`, bookend/contiguity/in-bailiwick validation | new `v2/ixfr_in.go` | 140 | 200 |
| **4.2** | IXFR branch in `ZoneTransferIn`: collect the flat stream, three-way classify | `dnsutils.go` | 60 | 100 |
| **4.4** | materialize snapshot → apply del/add with RRSIG routing → existing swap | `v2/ixfr_in.go`, `zone_mutation.go` | 110 | 150 |
| **4.1** | attempt decision + same-upstream AXFR fallback | `zone_utils.go` | 60 | 150 |
| **F1** | `request-ixfr` per-zone option + config plumbing, `XfrType` retirement | `structs.go`, `parseconfig.go`, `enums.go` | 70 | 100 |
| **§5** | onward relay: build an `Ixfr` link from the inbound sequence, append instead of epoch-reset | `ixfr.go`, `zone_mutation.go` | 70 | 250 |
| | **Total** | | **~510** | **~950** |

**~510 production, ~950 test, ~1460 all in**, as one PR — §8 already says the
feature is not meaningfully splittable without shipping something half-usable.

Two things widen that band, and both are cheaper to resolve before writing code
than after:

**~~§2 needs re-verification.~~** *Done 2026-08-29*, against `main` @
`ea391786`. Every structural claim held; the line numbers are updated in place.
It did not move the table — but it did cost §4.1, which had to be rewritten: the
refresh path DOES SOA-probe before `FetchFromUpstream`, and since the
serve-until-expire work that probe carries the zone's expire clock. See §4.1
for the choice C2 now has to make explicitly, and the row below for what the
second option costs.

**~~The delete-exact-RR semantics are unassessed against the name-comparison
work.~~** *Retracted 2026-08-29.* This said `RRset.RemoveRR`'s exact matching
might have been broken by #425 and should be checked first. It was not:
`RemoveRR` compares through `core.IsDuplicate` → `dns.IsDuplicate`, canonical
and case-insensitive, and never went through tdns's own comparison helpers. The
claim was made on plausibility rather than by reading the function.

**What is worth checking first is in §4.4 instead:** `RemoveRR` clears an
RRset's whole RRSIG list on any successful removal. That is the failure mode
§1's self-healing invariant genuinely hides — a wrong delete aborts to AXFR and
heals loudly, whereas dropped signatures abort nothing and surface as
validation failures at resolvers.

**If §4.1's probe is folded into the IXFR request, add the expire wiring.**
Stamping `noteSuccessfulRefresh` on the up-to-date and delta paths is a handful
of production lines; the tests are not. Proving that a zone whose serial never
moves still re-confirms, and still answers after more than one SOA EXPIRE has
passed, needs a fixture the suite does not have. Budget ~20 production / ~120
test on top of the table. Keeping the probe costs nothing here.

The largest and least certain single number is the §5 onward-relay test: three
tdns instances (primary → non-signing secondary → edge), asserting that the
edge pulls a *delta* rather than an AXFR and converges byte-identically, plus
the chain-reset boundary. It is the most elaborate fixture in this plan.

Do not count the signing-secondary staging-apply relay (§9). Do not count any
outbound change (§9).

**Sequencing.** [[secondary-serve-until-expire]]
`2026-08-28-secondary-serve-until-expire.md` (~175 production /
~630 test) should land first, and its §5 records why: this project sends
`zd.IncomingSerial` as the "have" serial, that field is set from the zone file's
SOA by `ParseZoneFromReader`, and until a restarted secondary loads its
persisted copy the serial is 0 — so the first transfer after every restart is a
full AXFR no matter how good the delta path is. That brief's Stage 2.1 is what
gives this one a base to ask from.
