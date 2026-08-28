# Review: make zone refresh and transfer cancellation-aware (#390)

**Superseded for merge readiness** by
[`2026-08-25-pr390-refresh-context-rereview.md`](2026-08-25-pr390-refresh-context-rereview.md)
(against `710ba934`). This file is the review of `1ce1786e`.

**Date:** 2026-08-25
**PR:** [#390](https://github.com/johanix/tdns/pull/390)
**Branch:** `feature/refresh-context-threading` @ `1ce1786e`
**Base:** `main`
**Size:** 11 files, +506 / −78
**Lens:** safety, correctness, and possible improvements. Not a security
audit: this is a shutdown-path change, and `ctx` is the process context
shared with DnsEngine.

Commits:

1. `e3db3fe4` — thread `ctx` through `Refresh` → fetch / transfer; extract
   `drainTransferEnvelopes`.
2. `1ce1786e` — close the transfer conn on cancel and drain the reader
   (CodeRabbit: abandoning an unbuffered send leaked the goroutine and
   socket); stop walking remaining upstreams; check `ctx` in
   `FetchFromFile`.

---

## Verdict

**Request changes.** The leak fix in the second commit is the right shape
for `dns.Transfer.inAxfr`'s unbuffered send, and a cancelled AXFR does not
publish a partial zone. One real defect remains on the AXFR path: a
cancelled `FetchFromUpstream` leaves the zone in `loading`, which
`ZoneTransferOut` refuses. `FetchFromFile` already restores status; the
AXFR path should do the same.

This is a clean-shutdown improvement, not a leak or correctness fix for
steady-state operation. The refresh engine already left *between*
refreshes. The new behaviour is stopping mid-AXFR of a large zone.

| # | Finding | Severity | Nature |
|---|---------|----------|--------|
| 1 | Cancelled AXFR leaves the zone in `loading` | **Must fix** | Outbound AXFR refused; `FetchFromFile` already got this right |
| 2 | Cancel-after-parse can skip the next file read | Should fix | `forgetZoneFileStat` not called; shutdown-only `ctx` today |
| 3 | `FetchFromUpstream` still ranges the live `zd.Upstreams` | Should fix | Same race `DoTransfer` just copied to avoid |
| 4 | Stale comments on `drainTransferEnvelopes` | Should fix | Godoc sits on the wrong function; contradicts the abort |

Non-blocking: `transfer.In` / `dialTransferConn` still ignore `ctx`; a
cancelled `ExchangeContext` is treated as “try next primary”; cancelled
refresh is logged as `RefreshError`; the engine shutdown test does not
exercise this PR.

---

## FINDING 1 — Cancelled AXFR leaves the zone in `loading` (must fix)

`FetchFromFile` restores `prevStatus` on cancel. `FetchFromUpstream` does
not.

```go
prevStatus := zd.GetStatus()
zd.SetStatus(ZoneStatusLoading)
// ...
for _, up := range zd.Upstreams {
    if cerr := ctx.Err(); cerr != nil {
        return false, fmt.Errorf("AXFR of %s: %w", zd.ZoneName, cerr)
    }
```

`ZoneTransferOut` refuses anything that is not `Ready`:

```go
if zd.GetStatus() != ZoneStatusReady {
    // ...
    return zd.refuseTransfer(w, r)
}
```

Same `ctx` cancels DnsEngine, so this is a shutdown window, not a
permanent outage. It is still wrong: a cancelled refresh of a zone that
already served data should keep serving it. The all-failed path restores
status; this early return does not — so it only bites when there is
another upstream left to try.

**Fix:** restore `prevStatus` on that return, and on any other cancel
return after `SetStatus(ZoneStatusLoading)`.

`FetchFromUpstream` also never re-checks `ctx` before the hard flip and
callbacks. `FetchFromFile` does, for the same “don’t publish into a
daemon on its way out” reason. Add the same gate after a successful
transfer, before `OnZonePreRefresh`.

---

## FINDING 2 — Cancel-after-parse can skip the next file read (should fix)

`FetchFromFile` records the file stat, then may return cancelled without
adopting the file, and does not call `forgetZoneFileStat()`. The
failed-publish path already documents why that cache must be dropped: the
next refresh sees an “untouched” file and never loads it.

Harmless if `ctx` only means process death (the in-memory stat dies with
the process). Wrong if `Refresh` ever gets a per-operation timeout.

**Fix:** drop the stat on the cancel-after-parse return, same as the
persist-failure path.

---

## FINDING 3 — `FetchFromUpstream` still ranges the live `zd.Upstreams` (should fix)

`DoTransfer` copied under `zd.mu` because the refresh engine mutates that
slice (`refreshengine.go` assigns `zd.Upstreams` under the lock). The
AXFR walk did not. Same race, live path.

**Fix:** copy under `zd.mu` here too, matching `DoTransfer` /
`ProbeUpstreamSerials`.

Related, pre-existing, not this PR: `Refresh` itself writes
`zd.Upstreams = res.Resolved` *without* `zd.mu`, so it races with the
engine’s locked writer. Out of scope here; worth a follow-up if the copy
in `DoTransfer` is the start of hardening that path.

---

## FINDING 4 — Stale comments on `drainTransferEnvelopes` (should fix)

The `ZoneTransferIn` godoc (“AXFR/IXFR over Do53, or over TLS…”) is still
sitting on the helper. The helper still says the library’s reader
goroutine and socket are left to finish on their own. That is the
opposite of the abort+drain the second commit added.

Easy to “clean up” the abort later because the comment says it is
intentional.

**Fix:** move the `ZoneTransferIn` docs back onto `ZoneTransferIn`;
describe abort-then-drain on the helper.

---

## Improvements (non-blocking)

### `ZoneTransferIn` / dial still ignore `ctx` until the drain loop

`FetchFromUpstream` checks before the call, but TLS setup,
`dialTransferConn`, and `transfer.In()` (dial + `WriteMsg`) still run.
`dialTransferConn` uses `context.Background()` with a 2s timeout, so a
shutdown that lands in a bound-source dial waits that full timeout.

Passing `ctx` into the dial is the remaining latency. Not blocking: the
PR already rejected adding `InContext` to the johanix/dns fork, and the
drain loop is where a large zone actually spends time.

### `DoTransfer` treats a cancelled `ExchangeContext` as “try next primary”

The next iteration then hits `ctx.Err()` and returns. Harmless extra
continue; `errors.Is(err, context.Canceled)` right after the exchange
would be clearer.

### Cancelled refresh is logged as `RefreshError`

The in-flight `go func` in `RefreshEngine` does
`zd.SetError(RefreshError, ...)` for any error, including cancel. At
process death this does not matter; if `ctx` is ever used for a single
refresh, it would mark a healthy zone failed.

Skip `SetError` when `errors.Is(err, context.Canceled)`.

### `TestRefreshEngineExitsOnRootCancel` does not exercise this PR

It starts the engine with empty channels, cancels, and checks it
returns. That select already exited on `ctx.Done()` before this change.
The goroutine delta (`after > before+2`) is also a flake risk under
`-race` or a dirty test binary.

The drain tests are the ones that actually pin the new behaviour —
especially `TestDrainReleasesReaderOnCancellation`.
`TestDrainStopsOnCancellation` still says the channel is never closed;
`abort` closes it. The leak test is the one that models the real reader.

---

## What looks right

- Closing the conn, then draining until the reader’s deferred `close(c)`,
  matches `inAxfr`: unbuffered `c <- &Envelope{...}`, so abandoning the
  receive parks the reader forever. Stopping without that drain is worse
  than not cancelling. `transferDrainGrace` plus the warning is the right
  failure mode if `Close()` does not unblock a stuck TLS read.
- Scratch zone + error return means a cancelled AXFR does not publish a
  partial zone. `SortFunc` writes into the scratch `Data`, not the live
  zone.
- `TsigMaterialForPeer` in the snapshot / `StampTsigForPeer` at send time
  is the correct split for sequential probes. A timestamp taken in phase 1
  could fall outside the fudge window by the time a later probe goes out.
- `confMu` is not held across network I/O. Same shape as
  `ProbeUpstreamSerials`.
- Drain tests fail if the `ctx.Done()` branch is removed. That is the
  right bar; the first version of these tests passed with the fix
  removed because they never reached the drain loop.
- Envelope-error path does not need abort: `inAxfr` sends the error
  envelope and returns, and its deferred `t.Close()` / `close(c)` run.
  Cancellation is different because the reader is still trying to send
  more data.
- No cross-repo break: zero callers in tdns-mp / tdns-nm / tdns-es.
  `OnZonePreRefresh` / `OnZonePostRefresh` signatures are untouched.

---

## Scope the PR already declined (agree)

- No `InContext` on the johanix/dns fork. Every fork line is re-applied
  on every upstream sync, against a benefit that only shows at shutdown.
- No `ctx` through `ReadZoneFile` / `ParseZoneFromReader`. That is a
  change to the parser and its callers, well outside this PR. The
  post-parse gate in `FetchFromFile` is the right bound.
- gofmt-dirty files on `main` (`delegation_coherence.go`,
  `delegation_utils.go`, `structs.go`) left alone.

The remaining uncancellable `transfer.In()` dial/write is the same fork
trade-off. Do not block on it.
