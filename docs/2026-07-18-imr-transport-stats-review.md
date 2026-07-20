# Implementation review — imr per-server transport statistics

**Reviewed:** 2026-07-18  
**Design:** [`2026-07-18-imr-transport-stats-design.md`](2026-07-18-imr-transport-stats-design.md)  
**Branch:** `feature/imr-transport-stats` @ `8f39373`  
**Commits:** `eb2d4ce` (Phases 1–2), `65f40fb` (Phase 3), `8f39373` (Phase 4)  
**Method:** Compare the design’s Q1–Q3 / Phases 1–4 and open decisions against the `v2/` tree. Anchors are symbol names; re-locate if lines drift.

---

## Executive summary

Phases 1–4 are **implemented and aligned with the design’s correctness core**: TC=1-only wire reporting, four counters per server, one snapshot + one formatter (incl. `Do53TCP`), and remote access that reuses that formatter. The two design open decisions were resolved as recommended (TC=1-only; per-server truncation). Phase2 co-design items (bypass attribution, unified large-ksk remote surface) are correctly deferred.

Main gaps: test depth on the real `ExchangeWithResult` path and `tryServer` wiring; a few doc/API naming mismatches; REPL↔remote signal presentation drift.

**Verdict:** Ready for PR / review of the landed work. No blocking correctness bugs found against the design mappings. Follow-ups below are polish and test coverage, not rework of the data model.

---

## Phase status

| Phase | Design | Status | Notes |
|-------|--------|--------|-------|
| **1 — Exchange enabler** | Surface `{wire, truncated}` | **Done** | Via `ExchangeWithResult` + `ExchangeResult`; plain `Exchange` kept as wrapper |
| **2 — Collection** | `attempted`/`used`/`failed`/`truncated` | **Done** | Mappings match design; `attempted` = old `TransportCounters` |
| **3 — Presentation** | One snapshot + formatter; fix Do53TCP/total | **Done** | REPL paths updated; weights shown alongside |
| **4 — Remote** | API verb + CLI + same formatter | **Done** | Shape differs from design sketch (see M1) |
| **Phase2 relationship** | Bypass attribution; unified large-ksk surface | **Deferred** | Explicitly out of this branch’s commits |

---

## What matches the design

### Phase 1 — Exchange enabler

`core.ExchangeResult` + `DNSClienter.ExchangeWithResult` (`v2/core/dnsclient.go`):

```go
type ExchangeResult struct {
	WireTransport Transport // transport that carried the returned response
	Truncated     bool      // a Do53/UDP response had TC=1 and was retried over TCP
}
```

| Wire case | Result | Matches design? |
|-----------|--------|-----------------|
| Clean Do53/UDP | `{Do53, Truncated:false}` | Yes |
| TC=1 → TCP | `{Do53TCP, Truncated:true}` | Yes (open decision #1: TC=1-only) |
| Transient UDP error → TCP | `{Do53TCP, Truncated:false}` | Yes — not counted as truncation |
| ForceTCP | `{Do53TCP}` (no Truncated) | Yes |
| DoT/DoH/DoQ | wire = that transport | Yes |

`Exchange` remains a thin discard-wrapper so existing callers are untouched.

### Phase 2 — Collection

`AuthServer` (`v2/cache/authserver.go`):

| Design counter | Field / accessor | Thread-safe |
|----------------|------------------|-------------|
| `attempted[t]` | `TransportCounters` / `IncrementTransportCounter` | `mu` |
| `used[t]` | `UsedCounters` / `IncrementUsedCounter` | `mu` |
| `failed[t]` | `FailedCounters` / `IncrementFailedCounter` | `mu` |
| `truncated` | `TruncatedCount` / `IncrementTruncated` | `mu` |

Snapshot: `TransportStats` + `SnapshotTransportStats()` (Attempted aliases the old map).

`tryServer` (`v2/dnslookup.go`) order is correct:

1. Finalize `eff` (incl. `forceTCP` → Do53TCP)  
2. `IncrementTransportCounter(eff)` → attempted  
3. `ExchangeWithResult`  
4. if `xres.Truncated` → `IncrementTruncated()`  
5. on err → `IncrementFailedCounter(eff)`  
6. on success → `IncrementUsedCounter(xres.WireTransport)`

Design mappings hold:

- Capability fail then Do53: `attempted[DoQ]++`, `failed[DoQ]++`; then `attempted[Do53]++`, `used[Do53]++`
- Size upgrade: `attempted[Do53]++`, `used[Do53TCP]++`, `truncated++`, `failed` untouched
- Increments sit after `eff` is finalized (ready for a later phase2 bypass re-pick)

### Phase 3 — Presentation

- One order list: `transportDisplayOrder` includes `Do53TCP`
- One formatter: `formatTransportStats` / `formatTransportCountMap` (totals include Do53TCP) — fixes P3
- Live path: `formatTransportCounters(server)` → snapshot + format
- REPL: `auth-transports`, `printAuthServerVerbose`, dump verbose all use it
- OOTS weights shown alongside (`renderSignal` / `formatTransportWeights`)

### Phase 4 — Remote

- API verb `imr-transport-stats` in `APIimr()` walks `ServerMap`, optional zone filter
- Wire type `ImrServerTransportStats` (zone, server, signal, attempted/used/failed, truncated)
- CLI: `tdns-cli imr stats transport-stats [zone]`
- Same formatter: `formatTransportStats(imrServerStatsToTransportStats(rec))`

### Open decisions — resolved

| Decision | Choice | Where |
|----------|--------|-------|
| Truncation precision | **TC=1-only** (recommended) | `ExchangeWithResult` sets `Truncated` only on the TC bit path |
| Truncation granularity | **Per-server** (not per-qtype) | `TruncatedCount uint64` on `AuthServer` |

---

## Findings (mismatches, gaps, risks)

### M1 — API envelope differs from the design sketch (non-blocking)

Design sketched `ImrRequest`/`ImrResponse` fields in `api_structs.go`. Implementation uses the existing `AgentMgmtPost` / `AgentMgmtResponse.Data` path already used by other `/imr` verbs, with `ImrServerTransportStats` defined in `apihandler_imr.go`.

This is the right fit for the current mgmt API. Update the design doc’s Q3 wording to match, or leave as “implemented via AgentMgmt*”.

### M2 — CLI path nesting

Design: `tdns-cli imr transport-stats [zone]`  
Code: `tdns-cli imr stats transport-stats [zone]` (under `ImrStatsCmd`)

Sensible grouping next to `imr stats large-ksk`. Comment in `formatTransportStats` still says `tdns-cli imr transport-stats` — minor doc drift.

### M3 — Signal presentation drift (REPL vs remote)

| Path | Signal shown |
|------|----------------|
| REPL `auth-transports` | `renderSignal(server)` over `TransportWeights` |
| Remote `transport-stats` | raw `server.TransportSignal` |

Same server can look different remotely vs in-process. Prefer one of: (a) send both raw + rendered weights, or (b) render weights on the CLI side from a weights map in the API record.

### M4 — `tryServer` still returns `eff`, not wire transport

On success after TC=1 upgrade, counters correctly use `xres.WireTransport`, but the function still `return …, eff, nil`. Callers that treat the returned transport as “what carried the answer” (hooks / `lastTransport`) still see the *requested* transport. Design focused on counters; this is a latent semantic footgun, not a stats bug.

### M5 — TC=1 then TCP also fails

`truncated++` is recorded even if the TCP retry errors; then `failed[eff]++`. Correct as “truncation happened,” but it blurs the clean story “`failed[Do53]=0` ⇒ size upgrade.” Rare; document the edge case for operators.

### M6 — `used[Do53TCP]` is not truncation alone

`used[Do53TCP]` also increments on:

- transient UDP→TCP (Truncated=false)
- proactive `forceTCP`

Operators must use **`truncated`**, not `used[Do53TCP]` alone, as the PQ truncation signal. Design already implies this; worth a one-liner in CLI help / REPL header.

### M7 — Phase2 items deferred (expected)

| Design ask | Status |
|------------|--------|
| Bypass attribution (`dnskeyBypass`) | Not present — `tryServer` still takes `forceTCP bool` |
| Unified remote surface for large-ksk + transport stats | Not done — `large-ksk` remains in-process / separate |
| Counters after `eff` finalized | Done — merge-friendly |

No change needed on this branch; track when phase2 lands.

---

## Test coverage vs design test plan

| Design item | Coverage | Gap |
|-------------|----------|-----|
| Exchange reports Do53TCP + Truncated on TC=1 | Fake only (`exchange_result_test.go`) | Real `DNSClient` TC test (`TestExchange_Do53_TCBitFallback`) asserts answer content via `Exchange`, **not** `ExchangeResult` |
| Plain Do53 otherwise | Fake covered | Real client: no `ExchangeResult` assert |
| Transient→TCP keeps Truncated=false | Code path exists | Untested for `ExchangeResult` |
| Counter increments (success/error/TC=1) | Manual increments in `authserver_stats_test.go` | No `tryServer` ↔ `ExchangeWithResult` integration test |
| Formatter renders Do53TCP + correct total | Untested | Add a small table-driven unit test |
| Live / CLI round-trip | Untested in tree | Manual OOTS/PQ testbed still needed |

---

## Recommended follow-ups (priority order)

1. **P1 tests:** Assert `ExchangeWithResult` on the real Do53 TC=1 path (`WireTransport=Do53TCP`, `Truncated=true`) and on the transient-fallback path (`Truncated=false`).  
2. **P1 tests:** Table-driven `formatTransportStats` covering Do53TCP inclusion and total.  
3. **P2 polish:** Align REPL and remote signal fields (M3).  
4. **P2 polish:** Fix the stale “`imr transport-stats`” comment; optionally note that `truncated` is the truncation metric (M6).  
5. **P3 (phase2 land):** Bypass attribution + fold large-ksk into the remote stats umbrella.  
6. **Optional:** Have `tryServer` return `xres.WireTransport` on success (M4), or rename the return so callers don’t assume “wire.”

---

## Files touched (implementation)

| Area | Paths |
|------|--------|
| Exchange | `v2/core/dnsclient.go`, `dnsclient_fake.go`, `exchange_result_test.go`; interface consumers (`chase_test.go`, etc.) |
| Counters | `v2/cache/authserver.go`, `authserver_stats_test.go` |
| Collection | `v2/dnslookup.go` (`tryServer`) |
| Presentation | `v2/cli/imr_dump_cmds.go`, `imr_cmds.go` |
| Remote | `v2/apihandler_imr.go`, `v2/cli/imr_transport_stats_cmd.go` |

---

## Bottom line

The implementation delivers what the design asked for in Phases 1–4, with the recommended truncation semantics. Remaining work is test hardening and small presentation consistency fixes — not a redesign.
