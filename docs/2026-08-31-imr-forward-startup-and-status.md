# IMR: forward-aware startup, upstream probing, and status observability

**Date:** 2026-08-31
**Status:** IMPLEMENTED (branch `feature/imr-forward-status`)
**Follows:** `2026-08-30-imr-forwarding-design.md` (the forwarding feature, #433)
**Addresses:** the observability half of #436

## 1. The problem

Verified live on 2026-08-31: a forward-everything resolver still hard-depended
on root priming. `InitImrEngine` → `PrimeWithHints` ends with a live `. NS`
fetch whose failure aborts init — and the engine supervisor merely LOGS an
engine's error, so a forward-all resolver whose upstream was down at boot
came up as a husk: process alive, management API answering, **no DNS
listeners, no retry**, one log line as the only trace. The priming fetch
bought nothing in that configuration: with a forward zone covering the root,
the hint-seeded root server map is never consulted (the forward outranks it
in every lookup).

Separately, none of the resolver's state was observable: `tdns-cli imr
config` had no `status` subcommand, the `/config status` payload carried
nothing IMR-specific, and the embedded resolver in tdns-auth/tdns-agent was
equally invisible.

## 2. Decisions

| Question | Decision |
|---|---|
| Priming under a root forward | Skip the live `. NS` fetch: `PrimeFromHintsOnly` seeds the hints offline and marks the cache primed. Queries resolve lazily. Iterative mode keeps the live fetch (`PrimeWithHints`), unchanged. |
| Upstream verification | Probe every forward upstream once at startup (recursive `. NS`, in parallel, after the listeners start). Failures WARN and register a server error — deliberately **not** fatal: hard-failing would recreate the boot-order race the probe exists to make visible. |
| Error surfacing | New `ErrCatUpstream` category in the server-error registry: `ImrForward` (aggregate of currently-unreachable forward upstreams, recomputed on every reachability transition — probe or live query — cleared when none is failing) and `ImrPriming` (IMR init failed; the daemon is running without DNS listeners). Both mark `config status` DEGRADED. |
| Reachability semantics | "Reachable" = a DNS response arrived, whatever its rcode; only transport-level failures (error / nil response) count. |
| Status surface | `ConfigResponse.Imr` (`ImrStatus`): primed + how + when, stub zones, forward zones with per-upstream transport, reachability, query/failure counters, last success/error. Populated from `Globals.ImrEngine` wherever a resolver runs — tdns-imr and the embedded resolver in tdns-auth/tdns-agent alike. New `tdns-cli imr config status` command; `auth`/`agent config status -v` render the same block. |
| CLI trees | `tdns-cli {imr,auth imr,agent imr} {forward,stub} {list,status,probe}` over the `/imr` API (wire commands `imr-forward-list/-status/-probe`, `imr-stub-list/-status/-probe`; probes take an optional zone). `forward status` carries the per-upstream counters; `stub status` carries the per-server transport counters (attempted/used/failed/truncated) and active (address, transport) backoffs. |
| Probe side effects | Deliberately asymmetric. `forward probe` is the same exchange as live traffic and RECORDS (counters, unreachable flag, the DEGRADED aggregate) — an operator can confirm a recovery by probing. `stub probe` (RD=0 SOA per server/address/transport, reporting rcode + AA + RTT) is strictly REPORT-ONLY: recording a probe failure into the AuthServer backoff would let a diagnostic poison resolution, the exact 2026-08-11 failure mode. Guarded by a test asserting a probe of a dead address leaves no backoff and no counters. |

## 3. Where it sits

- `v2/cache/rrset_cache.go` — `PrimeWithHints` split into `seedFromHints`
  (offline parse + cache/ServerMap seeding) + the live fetch; new
  `PrimeFromHintsOnly` reuses the seed and skips the fetch.
- `v2/imrengine.go` — `InitImrEngine` picks the priming mode via
  `forwardZoneFor(".")` and records `PrimedVia`/`PrimedAt`; `ImrEngine`
  registers `ImrPriming` on init failure and launches the probe after the
  listeners.
- `v2/imr_forward.go` — per-upstream reachability state on
  `ForwardUpstream` (mutex-guarded counters + failing flag, fed by
  `forwardQuery` and the probe), `ProbeForwardUpstreams`, and the aggregate
  recomputation on transitions.
- `v2/imr_status.go` — `ImrStatus` et al. and `(*Imr).StatusReport()`.
- `v2/servererror.go` — `ErrCatUpstream`, `ErrSubImrPriming`,
  `ErrSubImrForward`, and their owned helpers.
- `v2/apihandler_funcs.go` — `/config status` populates `resp.Imr`.
- `v2/cli/config_cmds.go` (`renderImrStatus`, shared) and
  `v2/cli/config_imr_cmds.go` (`imr config status`).

## 4. Verification

Unit: `TestForwardRootPrimingSkipsFetch` (hints-only priming sends nothing to
the upstream, root server map still seeded, queries forward afterwards) and
`TestProbeForwardUpstreams` (dead upstream → unreachable + one aggregate
`Upstream/ImrForward` entry naming it; live upstream → reachable; resolver
serves while DEGRADED; a later successful exchange clears the error).

Live, same dead-upstream config that produced the husk: the daemon now
starts, serves SERVFAIL, and `/config status` reports
`primed_via: "hints-only (root forwarded)"` plus the aggregate error naming
the upstream with its actual timeout error. With a live upstream: clean
status, upstream reachable, zero failures.

## 5. Left open

- The `ImrPriming` error is boot-scoped: iterative-mode priming failure
  still leaves the daemon without listeners (now visibly DEGRADED, but not
  retried). Making iterative priming best-effort-with-retry is a separate
  decision.
- Reload for stubs/forwards remains open in #436; per-upstream backoff and
  RTT preference remain #438.
