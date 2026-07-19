# Design & plan — imr per-server transport statistics (collection, presentation, remote access)

**Status:** design agreed (scope confirmed 2026-07-18); ready to turn into an implementation plan.
**Base:** branch off `main` (≥ `76c3ff6`, the merge of OOTS draft-03 #293). Work in the **`v2/` tree only**.
**Relationship to OOTS:** this is **separate from and orthogonal to** the OOTS draft-03 feature (#293, merged). OOTS delivered the `oots` wire format + weight-honoring transport *selection*; this project is about *measuring* what transports were actually used per auth server. The two share the same subject (per-server transport) but no code path is entangled.

Anchors below are symbol names first; line numbers drift (they shifted with the #293 merge and the PrefTransport cleanup) — **re-locate by symbol**.

## Motivation

Two parallel workstreams need accurate per-server transport statistics:

1. **OOTS testing (intensifying):** we need to confirm the imr distributes queries across transports in proportion to the advertised `oots` weights, and that encrypted transports are actually *carrying* answers (not just being attempted and failing back to Do53).
2. **Large PQ-safe DNSSEC algorithms:** big DNSKEY/RRSIG responses overflow UDP and force TCP. **Tracking DNS truncation is a first-class goal** for these projects — we want to see, per server, how often UDP responses are truncated and upgraded to TCP.

The current stats are inadequate for both (see below).

## Current state (what exists today)

- **Data model:** `AuthServer.TransportCounters map[core.Transport]uint64` — one counter per transport (`v2/cache/authserver.go`). Thread-safe accessors: `IncrementTransportCounter`, `SnapshotTransportCounters`/`SnapshotCounters`.
- **Collection:** the *only* increment is in `tryServer` (`v2/dnslookup.go`), `server.IncrementTransportCounter(eff)`, fired **before** `c.Exchange`. So it counts **attempts**, keyed by `eff` (the *requested* transport). `eff = Do53TCP` only when the imr *proactively* forced TCP (`forceTCP && Do53`, e.g. DNSKEY queries); a `TC=1`-driven UDP→TCP upgrade happens **inside `c.Exchange`, invisibly** (`tryServer` returns `eff` on both success and error paths).
- **Interactive presentation (in `tdns-imr`'s in-process REPL, direct cache access):**
  - `formatTransportCounters` + `printAuthServerVerbose` (`v2/cli/imr_dump_cmds.go`).
  - the `auth-transports` counter dump (`v2/cli/imr_cmds.go`), reading `Conf.Internal.RRsetCache.ServerMap` directly.
- **Remote plumbing (already exists, unused for stats):** `tdns-imr` runs a daemon with a mgmt API — `SetupSimpleAPIRouter` exposes `/api/v1/{ping,command,config,debug,imr}` (API-key auth, `v2/apirouters.go`). `tdns-cli imr …` POSTs to `/imr` via `api.RequestNG` (`v2/cli/imr_mgmt.go`), dispatched by `APIimr()` on a `Command` field (`ImrRequest`/`ImrResponse`, `v2/api_structs.go`). Topology: `tdns-cli` is a **separate binary** that sends API requests to the server apps, exactly parallel to `tdns-cli auth … → tdns-auth`.

## Problems

- **P1 — attempts only, no "used".** A DoT attempt that fails and falls back to Do53 increments *both* (separate `tryServer` calls down the tuple list). The metric is biased: it inflates encrypted transports precisely when they fail. There is no record of which transport actually *carried* each answer.
- **P2 — wire transport hidden.** `TC=1` UDP→TCP upgrades happen inside `c.Exchange` and are never surfaced, so a Do53 answer delivered over TCP counts as Do53. Truncation is currently **unmeasurable**.
- **P3 — `Do53TCP` dropped from presentation.** All the display `order` lists hardcode `{DoQ, DoT, DoH, Do53}` and omit `Do53TCP` (`formatTransportCounters` and both loops in `imr_cmds.go`). Proactive-forceTCP `Do53TCP` counts are invisible *and* excluded from the "total", so the total is wrong whenever TCP was forced. Two/three hardcoded formatters can also drift.
- **P4 — no remote access.** Stats are only reachable inside the `tdns-imr` REPL; there is no `tdns-cli imr` command to read them from a running daemon.

## The two "failure" kinds (they are different, and the code already treats them so)

1. **`TC=1` size upgrade (Do53/UDP → Do53TCP):** NOT a failure. `c.Exchange` retries over TCP and returns **success**. It is a successful Do53 query whose response needed TCP — a property of that response's size. We *want to count it* (truncation metric), but it is not a transport failure.
2. **Capability failure (e.g. DoQ announced but unreachable):** a real failure. `c.Exchange` returns an **error**; the loop advances to a different tuple (Do53) via a separate `tryServer` call. This is the OOTS-meaningful "announced-but-didn't-deliver" signal.

## Design

### Q1 — collection: four counters per server

- **`attempted[t]`** — per `tryServer` call, keyed by `eff` (what we initiated). (Keep the existing counter; this is it.)
- **`used[t]`** — on `tryServer` **success**, keyed by the **actual wire transport**.
- **`failed[t]`** — on `tryServer` **error**, keyed by `eff` (capability failures).
- **`truncated`** — count of `TC=1`-driven UDP→TCP upgrades (per-server; see open decision on granularity).

**Enabler (required):** `core`'s `DNSClient.Exchange` must **surface `{actual wire transport, truncated bool}`** instead of hiding the internal Do53 UDP→TCP fallback. Today it returns `(msg, rtt, err)` and `tryServer` returns `eff`; it must instead let `tryServer` learn (a) whether the answer came over UDP or TCP, and (b) whether the upgrade was `TC=1`-driven. This single interface change unblocks both `used[]` completeness and truncation counting.

Mapping the two cases onto the counters:
- Capability failure: `attempted[DoQ]++`, `failed[DoQ]++`; then `attempted[Do53]++`, `used[Do53]++`.
- Size upgrade: `attempted[Do53]++`, `used[Do53TCP]++`, `truncated++`, `failed` untouched.
- Clean separation: `failed[X] > 0` ⇒ capability failure; `used[Do53TCP]` from a Do53 attempt with `failed[Do53] = 0` ⇒ size upgrade.

### Q2 — interactive presentation

- Render the **full matrix** including `Do53TCP`; fix the total.
- **Consolidate** the two/three hardcoded `order` lists and formatters into **one** formatter that takes a stats snapshot struct.
- Show `attempted` / `used` / `failed` (and `truncated`) side by side, alongside the advertised `oots` weights (so "advertised DoT:10 but used 0" is visible).

### Q3 — remote access via `tdns-cli imr`

- Define a **stats snapshot struct** (JSON) — per server: name, advertised weights/signal, and the four counters per transport.
- Add a `transport-stats` **`Command` verb** to `APIimr()` that walks `Conf.Internal.RRsetCache.ServerMap`, snapshots each server, and returns it in a new `ImrResponse` field.
- Add a `tdns-cli imr transport-stats [zone]` subcommand that POSTs the request and renders the response with the **same formatter as Q2** (so REPL and remote output cannot drift).

### Shared code principle

One snapshot struct + one formatter, consumed by both the in-process REPL path (snapshot from the live cache) and the remote path (snapshot deserialized from JSON). This guarantees consistency and means the `Do53TCP`/matrix fixes apply to both for free.

## Open decisions (need Johan's call before/within implementation)

1. **Truncation precision.** `c.Exchange` falls back to TCP on *both* `TC=1` and a UDP transient error. Count truncation as `TC=1`-only (precise; requires Exchange to report the reason), or as any-UDP→TCP-upgrade (simpler; conflates truncation with packet-loss retries)? *Recommendation: `TC=1`-only — truncation rate is the whole point for the PQ work.*
2. **Truncation granularity.** Per-server truncation count, or per-`(server, qtype)` (so "which record types overflow UDP for this server" is directly visible — most useful for PQ)? *Per-qtype is a larger data-model step; decide whether it's in-scope now or a follow-up.*

## Phased implementation plan

- **Phase 1 — Exchange enabler.** Change `core.DNSClient.Exchange` (and callers) to surface `{wire transport, truncated}`. Smallest self-contained change; everything else depends on it. Unit-test the UDP→TCP-on-`TC=1` path reports correctly.
- **Phase 2 — collection.** Add `used`/`failed`/`truncated` counters to `AuthServer` (thread-safe, mirroring `TransportCounters`); wire increments in `tryServer` (used on success by wire transport, failed on error by eff, truncated on the reported flag). Keep `attempted` as-is.
- **Phase 3 — presentation (Q2).** One snapshot struct + one formatter; fix `Do53TCP`/total; update both REPL commands to use it.
- **Phase 4 — remote (Q3).** `APIimr` verb + `ImrResponse` field + `tdns-cli imr transport-stats` command reusing the Phase-3 formatter.

Phases 1–2 are the correctness core; 3–4 are presentation/access. Each is independently reviewable and can be its own PR.

## Working rules

- Branch off `main`; GPG-sign every commit (`-S`, never `--no-gpg-sign`); no `Co-Authored-By`/AI byline.
- Build/test env: `GOROOT=/opt/local/lib/go CGO_ENABLED=1`; `go build`/`vet`/`go test -race` green on affected modules (`v2`, `v2/core`, `v2/cache`, `v2/cli`, `cmdv2/imr`) before each commit.
- Implement → commit → push → open PR → **stop** (do not merge).

## Test plan

- Unit: `Exchange` reports `Do53TCP` + `truncated` on a `TC=1` response; reports plain Do53 otherwise. Counter increments: success→`used[wire]`, error→`failed[eff]`, `TC=1`→`truncated`. Formatter renders `Do53TCP` and a correct total.
- Live (on `127.0.0.1#5354` / the OOTS testbed): drive queries at a server advertising mixed weights; confirm `used[]` proportions track the weights and Do53 fallback appears; force truncation with a large-PQ zone and confirm `truncated`/`used[Do53TCP]` increment; read the same numbers back via `tdns-cli imr transport-stats`.

## Relationship to `imr-transport-selection-phase2`

`imr-transport-selection-phase2` (surveyed 2026-07-18; ~65 own commits, ~60 behind main) adds a `DNSKEYTransportPolicy` (`dnskeyTransport`: `UseDSSignal`/`ForceUDP`/`TryEncrypted`/`ForceEncrypted`) that, for DNSKEY queries whose cached parent DS uses a large (PQ) algorithm, **bypasses the oots weight distribution** and picks a transport by a fixed preference `DoQ > DoT > DoH > Do53TCP` (never UDP) via `preferredDNSKEYTransport`. It also ships its own telemetry (`v2/imr_large_ksk_metrics.go`: `DSEncounteredTotal`/`DSEncounteredLarge`/`DNSKEYLookupBypassed`, package-global atomics) and an in-process REPL stats command (`v2/cli/imr_stats_large_ksk.go`), plus the unified design `docs/2026-06-12-transport-selection-policy.md`.

Impact on this stats design:

- **Direct code overlap at `tryServer` (coordination point).** phase2 changes `tryServer`'s signature (`forceTCP bool` → `dnskeyBypass bool`) and re-picks `eff` *inside* `tryServer` via `preferredDNSKEYTransport` when bypassing. This design also modifies `tryServer` (consume the new `Exchange` `{wire transport, truncated}` return; increment `used`/`failed`/`truncated`). **These will conflict** — whichever lands second integrates the other. Practically: the `attempted`/`used` increments must sit *after* `eff` is finalized (including any bypass re-pick) so the counters reflect the transport actually dialed.
- **Attribution (semantic).** phase2 introduces a per-query `dnskeyBypass` signal — policy-forced DNSKEY traffic that does **not** follow the oots weights. This design should **use that flag to separate bypassed-DNSKEY traffic from weight-distributed traffic**, so the OOTS-distribution view isn't polluted by policy-forced queries. This attribution feature only becomes meaningful once phase2 lands; the four base counters are phase2-independent.
- **Truncation (complementary, not duplicate).** phase2's purpose is to *proactively prevent* truncation (escalate large-DNSKEY queries before sending); this design's `truncated` counter measures *residual/reactive* `TC=1` truncation. Together: phase2's `DSEncounteredLarge`/`DNSKEYLookupBypassed` (proactive) + this design's `truncated`/`used[Do53TCP]` (reactive) tell the full story. They must coexist under one telemetry surface, not re-implement each other.
- **Presentation/access (this design subsumes a phase2 gap).** phase2's large-ksk metrics are **in-process only** (`LargeKskImrMetricsSnapshot`, no API) and global (not per-server); `APIimr` does not expose them. This design's Q3 (stats over `/api/v1/imr` + `tdns-cli imr`) is the remote surface phase2 lacks — so Q3 should be built to expose **both** the per-server transport stats and the global large-ksk metrics under one "imr stats" umbrella/formatter, rather than a parallel one.
- **Convergence.** Align with `docs/2026-06-12-transport-selection-policy.md` (the unified `TransportPolicy` both OOTS and `DNSKEYTransportPolicy` feed).

Sequencing: the four base counters (Phase 1–2 here) are **independent of phase2** and can land first (delivering OOTS-testing value now); `tryServer` is the shared edit point, and phase2 is doing a large forward-merge catch-up regardless, so it can absorb the signature change. Bypass-attribution and the unified stats surface are the parts that must be co-designed with phase2.
