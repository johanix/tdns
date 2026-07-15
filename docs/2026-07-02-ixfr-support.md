# Project C — IXFR Support (RFC 1995)

**Status:** design sketch — **scheduled after Project B**; details firm up once B
lands (the snapshot/publish/chain foundation determines the specifics).
**Date:** 2026-07-02
**Depends on:** Project B (`…-zone-mutation-snapshot-correctness.md`) — the
immutable snapshot, `publish()` (which already *computes* per-publish deltas), and
the per-zone publish path. **Uses:** Project A's TCP-AXFR-over-TSIG test harness
(`…-outbound-transfer-hardening.md`).
**Reference:** the sibling POP already does outbound IXFR the same way —
`tapir/docs/2026-06-02-pop-149-snapshot-concurrency-design.md` (POP §4 for the
chain + downstream tracker). Anchors as of 2026-07-02.

> This doc is intentionally not polished to implementation-ready detail: the exact
> shapes depend on how B's `publish()`/`ZoneSnapshot` land. Revisit and detail it
> when B is done.

---

## 1. Current state (dead scaffolding to reuse)
IXFR is ~5% present: `Ixfr{FromSerial,ToSerial uint32; Removed,Added []core.RRset}`
(structs.go:509), `IxfrChain` (structs.go:140), `XfrType` (structs.go:132) —
declared, never used. `ZoneTransferIn` (dnsutils.go:54) can emit an IXFR request
(`SetIxfr`, :63) but `FetchFromUpstream` hardcodes AXFR (zone_utils.go:312).
`IsIxfr()` (zone_utils.go:668) exists, unused. Dispatch sends both AXFR and IXFR
to `ZoneTransferOut` (queryresponder.go:813-816), ignoring the client serial.
**Reuse all of it.**

## 2. Guiding principle — blast radius
- An **inbound** IXFR bug corrupts only this server's copy → self-heals by
  re-pulling AXFR.
- An **outbound** IXFR bug ships a bad delta to downstreams → silent divergence.

So: build inbound first, outbound last, and hold one hard invariant —
**AXFR fallback is always available; IXFR is never a correctness dependency.** Any
doubt (unknown/too-old serial, non-contiguous chain, audit mismatch) ⇒ full AXFR.
Worst case of any bug is a slower transfer, never a wrong delta.

## 3. Phases (rough)

### C1 — Chain retention + serial-space spec + downstream tracker  [needs B]
- **Retain** the delta `publish()` already computes into the snapshot's
  **byte-bounded** `IxfrChain` (append + front-trim; config knob; **one canonical
  order — newest-last —** with prune and serve agreeing). Reload / full-AXFR flip
  and API zone-replace (`ModifyDynamicZone`, dynamic_zones.go:960-981) = **epoch
  reset** (clear chain, new baseline — no `zoneDiff`).
- **`downstreamTracker`** (POP §4): downstream last-seen serials, written by DNS
  goroutines, get a **dedicated small mutex**; chain prune is a **pure function the
  writer runs while building the next snapshot** (reads `tracker.lowest()`), never
  mutating shared state from a request goroutine.
- **Serial-space spec:** chain serials are `CurrentSerial`; inbound apply sets
  `IncomingSerial` to the upstream `ToSerial`; response/transfer SOA always
  `CurrentSerial`; publish advances `CurrentSerial` once (no double-advance).
- **Audit oracle spec:** canonical RRset key + cheap full-zone snapshot for tests
  + NSEC/RRSIG-churn collapsing; `served == baseline + Σ retained deltas`.

### C2 — Inbound IXFR (low blast radius)  [needs B, C1]
- `FetchFromUpstream` requests IXFR with `IncomingSerial` when a baseline exists;
  `ZoneTransferIn` parses RFC 1995 difference sequences (reuse miekg's
  envelope-stream semantics, not just `IsIxfr` on RR slices) into deltas, applies
  each via `publish()`, advancing `IncomingSerial` stepwise.
- **AXFR fallback** on upstream-AXFR / gap / malformed; audit-oracle reconcile ⇒
  drop + re-pull AXFR + log loudly. Verify `SetIxfr("",..)` produces a valid
  Authority SOA for upstreams that want MNAME/RNAME.

### C3 — Outbound IXFR  [needs B complete, C1, A]
- Detect IXFR (`Qtype==IXFR` + client SOA in `r.Ns`); walk `snap.IxfrChain` in
  `CurrentSerial` space (RFC 1982 arithmetic — reuse `year68` dnsutils.go:25 /
  cache/rrset_validate.go:1028-1040, don't reinvent). Contiguous ⇒ **concatenate**
  per-step difference sequences with RFC 1995 bracketing
  `SOA(begin)→dels→adds→SOA(end)` — a **distinct emission driver that reuses
  Project A's batcher size machinery** (not AXFR's leading-apex/trailing-SOA
  shape). Else ⇒ **AXFR fallback**. Signed IXFR reuses the per-envelope TSIG path.
- Enable only once B guarantees the chain is complete (every mutator publishes).

## 4. Design decisions (carried from the combined plan)
- **Concatenate, don't condense** (v1) — concatenation is RFC 1995 canonical;
  condensation is the optional optimization and a *merge* step (an outbound-bug
  risk) we skip. The byte-bounded chain caps the worst-case concatenated response;
  RRSIG-churn replay is the amplifier, bounded by the chain budget.
- **Chain bounded by bytes** (primary knob; count secondary).
- Deferred: condensation; `XfrType`-driven policy (wire or delete the field).

## 5. Rough risk / effort / LOC (refine after B)
| Phase | Risk | Effort (agent) | LOC (impl+test) |
|---|---|---|---|
| C1 chain + serial/audit + tracker | medium | ~1–1.5 h | ~360 |
| C2 inbound IXFR | medium (self-heals) | ~1.5–2.5 h | ~470 |
| C3 outbound IXFR | medium | ~1.5–2.5 h | ~500 |

Total ~1330 LOC, ~4–6 h — but re-estimate once B's `publish()`/snapshot shapes are
known.
