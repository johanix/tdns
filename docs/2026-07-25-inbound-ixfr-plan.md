# Project C2 — Inbound IXFR (RFC 1995)

**Date:** 2026-07-25
**Status:** AGREED — firmed up against main @ 138c9ce (which has #328 outbound
IXFR merged), and both open forks decided 2026-07-25 (F1: `request-ixfr`,
default ON; F2: materialize+swap for v1). Ready to implement as a single PR.
The one deferred idea — retaining inbound deltas in the outbound chain so a
cascaded secondary re-serves them as deltas — is an explicit later-PR candidate
(§5, §7 F2, §8 PR-2).
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

## 2. Verified state of main (2026-07-25)

- `FetchFromUpstream` (`v2/zone_utils.go:262`) is the sole refresh path. It
  builds a fresh `new_zd`, calls `new_zd.ZoneTransferIn(up, zd.IncomingSerial,
  "axfr", conf)` with the transfer type **hardcoded to `"axfr"`** (:299), then
  swaps the result in wholesale via `applyRefreshReplacementLocked`. The no-op
  check is `new_zd.IncomingSerial == zd.IncomingSerial` (:313).
- `ZoneTransferIn` (`v2/dnsutils.go:57`) already *can* emit an IXFR query — it
  has the `ttype == "ixfr"` branch calling `msg.SetIxfr(zd.ZoneName, serial,
  ".", ".")` (root MNAME/RNAME, fixed in #328). But it feeds **every** received
  RR through `SortFunc`, which records only the *first* SOA (`if !firstSoaSeen`)
  and blindly appends every other RR into `Data`. Feeding it a difference
  stream would silently corrupt the zone (deleted records get *added*, bracket
  SOAs dropped). **So the request path exists; the response path does not.**
- `IsIxfr(rrs []dns.RR)` (`v2/zone_utils.go:609`) returns true iff `rrs[0]` and
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
  type — set to `"axfr"` in `ParseZoneFromReader`, carried into `new_zd`, never
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

No separate SOA probe: the IXFR query carries our serial and the server decides
(single-SOA if up-to-date). This is strictly better than today's
"AXFR-then-compare-serials". (Implementation note: confirm the refresh engine
does not already SOA-probe before `FetchFromUpstream`; today it does not.)

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

### 4.5 Serial handling

We send `zd.IncomingSerial` as the "have" serial. On success `IncomingSerial`
and `CurrentSerial` advance to `S` (the server's serial), identical to the AXFR
path's post-transfer assignment. The up-to-date case leaves both unchanged and
triggers the existing `new_zd.IncomingSerial == zd.IncomingSerial` no-op branch.

## 5. Interaction with the merged outbound chain (#328)

A tdns secondary can itself be a primary to further-downstreams. Because v1
applies inbound deltas via `applyRefreshReplacementLocked` — which sets
`wsIxfrEpochReset = true` — **each inbound refresh resets this server's own
outbound IXFR chain.** Consequence: this server's downstreams get an AXFR (not a
delta) across each inbound-refresh boundary. That is *correct and safe*, just
not optimal, and it is the direct trade-off of the simple materialize+swap
model. Removing it is exactly what the F2-follow-up "retain inbound deltas in
the outbound chain" work buys (applying inbound deltas through the staging API
would let them flow straight into the outbound chain and re-serve as deltas) —
agreed as a later-PR possibility (§7 F2-follow-up, §8 PR-2), deferred because it
is more entangled with locking and is a pure optimization on top of a correct
v1.

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
- Gate: full `v2` `-race`; gofmt; cmdv2 binaries build via gmake.

## 7. Design forks

- **F1 — IXFR-in enablement & default. DECIDED (2026-07-25): default ON.**
  A per-zone `request-ixfr` option (template-gap-filled and config-parsed like
  the others), default ON — BIND parity, the AXFR fallback makes it safe, and it
  is symmetric with #328's default-on retention. The vestigial `XfrType` field
  is retired in the same PR.
- **F2 — apply model. DECIDED (2026-07-25): v1 = materialize+swap (§4.4).**
  Simple, reuses the whole refresh path, obviously correct — at the accepted
  cost of a full-zone copy per delta and the outbound-chain reset (§5). The
  alternative (staging-apply, which avoids the copy and keeps the outbound chain
  intact) is explicitly deferred to a later PR — see the F2-follow-up note
  below and §8 PR-2.
- **F2-follow-up (later PR, agreed as a possibility) — retain inbound deltas in
  the outbound chain.** Applying inbound deltas via the live staging API
  (`stageRRsetLocked`/`stageDeleteLocked` + `publishLocked`, the UPDATE
  machinery) instead of the wholesale swap would let a received delta flow
  straight into this server's *outbound* `IxfrChain`, so a cascaded secondary
  re-serves it to its own downstreams as a delta rather than forcing an AXFR at
  each refresh boundary (§5). Deferred, not dropped: it is a pure optimization
  on top of a correct v1, and more entangled with locking and publish cadence.
- **F3 — outbound-chain continuity across inbound refresh. DECIDED by F2:**
  v1 accepts AXFR-at-the-boundary for downstreams (§5). Not a correctness issue.
- **F4 — full-zone-fallback detection.** Use `IsIxfr` on the collected slice
  (SOA-then-SOA ⇒ delta; SOA-then-non-SOA ⇒ full zone). Decided; `IsIxfr`
  already exists and is exactly this test.
- **F5 — condensation.** Accept condensed responses (parse naturally); do not
  require or produce them. Decided.

## 8. Phasing

- **PR-1 — parser + apply + AXFR fallback, behind the option (default per F1).**
  The difference-sequence parser, the materialize+apply, the classification and
  AXFR-fallback wiring in `FetchFromUpstream`/`ZoneTransferIn`, the new
  `request-ixfr` option, `XfrType` retirement. Parser + apply unit tests + the
  end-to-end loopback convergence test. This is the whole feature; it is not
  obviously splittable further without shipping something half-usable.
- **PR-2 (optional, later) — retain inbound deltas in the outbound chain**
  (F2-follow-up): apply inbound deltas via the staging API so a cascaded
  secondary re-serves them to its own downstreams as deltas instead of AXFR at
  each refresh boundary. Agreed as a possibility, not scheduled.

## 9. Deferred / out of scope

- Staging-apply / outbound-chain continuity (F2, §5).
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
