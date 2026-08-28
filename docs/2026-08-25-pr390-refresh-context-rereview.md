# Re-review: #390 refresh-context threading

**Later pass:** [`2026-08-25-pr390-refresh-context-recheck.md`](2026-08-25-pr390-refresh-context-recheck.md) (against `180a91c8`).

**Date:** 2026-08-25 (second pass)
**Prior review:** [`2026-08-25-pr390-refresh-context-review.md`](2026-08-25-pr390-refresh-context-review.md) (against `1ce1786e`)
**PR:** [#390](https://github.com/johanix/tdns/pull/390)
**Branch:** `feature/refresh-context-threading` @ `710ba934`
**Base:** `main`
**Size:** 12 files, +590 / −86
**Lens:** did the four findings from the first pass actually close, and did
the follow-up commits introduce anything new.

New commits since `1ce1786e`:

3. `47d9e5f6` — restore `prevStatus` on cancelled AXFR; `ctx.Err()` gate
   immediately before `applyRefreshReplacementLocked` on both paths.
4. `710ba934` — remaining findings from the external review, plus the
   non-blocking items.

---

## Verdict

**Approve.** Finding 1 (the must-fix) is closed and mutation-tested.
Findings 3 and 4 are closed. Finding 2 is closed on the post-callback
gate and left open on an earlier gate in the same function — a one-liner,
same hazard, narrower window. Take it if you are already touching the
file; do not hold the PR for it.

The leak fix, abort+drain, TSIG stamp-at-send, and `confMu` snapshot are
unchanged and still look right.

| # | First-pass finding | Now |
|---|--------------------|-----|
| 1 | Cancelled AXFR leaves the zone in `loading` | **Closed.** Restored on every cancel return. `TestCancelledRefreshDoesNotStrandZoneStatus` fails if the restore is dropped. Pre-flip gate added on both paths. |
| 2 | Cancel-after-parse can skip the next file read | **Mostly closed.** `forgetZoneFileStat` on the post-callback gate. The earlier post-parse gate still does not. |
| 3 | `FetchFromUpstream` ranges live `zd.Upstreams` | **Closed.** Copy under `zd.mu`, same as `DoTransfer`. |
| 4 | Stale comments on `drainTransferEnvelopes` | **Closed.** Godoc is back on `ZoneTransferIn`; helper describes abort-then-drain. |

Non-blocking items from the first pass: taken except `transfer.In` itself
(already rejected) and two leftovers listed below.

---

## Finding 1 — closed

`FetchFromUpstream` restores `prevStatus` on the mid-loop cancel return
and on the pre-flip gate after callbacks. The all-failed path already
restored. `TestCancelledRefreshDoesNotStrandZoneStatus` drives an
already-cancelled `FetchFromUpstream` against a `Ready` zone and asserts
the status is unchanged.

The pre-flip `ctx.Err()` gate is after `OnZonePreRefresh`, immediately
before `applyRefreshReplacementLocked`, on both the file and upstream
paths. That is the right place: the callbacks can take real time, and a
gate only before them would still publish if cancel landed during them.
Cancelled callbacks mutate the scratch `new_zd`, which is discarded.

---

## Finding 2 — leftover one-liner

`FetchFromFile` now has two post-parse cancel gates:

```go
// after parse, before callbacks — restores status, does NOT forget the stat
if cerr := ctx.Err(); cerr != nil {
    zd.SetStatus(prevStatus)
    return false, fmt.Errorf("FetchFromFile %s: %w", zd.ZoneName, cerr)
}
// ... OnZonePreRefresh ...
// after callbacks, before the hard flip — restores AND forgets
if cerr := ctx.Err(); cerr != nil {
    zd.forgetZoneFileStat()
    zd.SetStatus(prevStatus)
    return false, fmt.Errorf("FetchFromFile %s: %w", zd.ZoneName, cerr)
}
```

The first-pass finding was the first of those two. `710ba934` put
`forgetZoneFileStat` on the second. If cancel lands after
`recordZoneFileStat` and before the callbacks, the next refresh still
sees an untouched file and skips a change that was never adopted.

Same hazard as the persist-failure path documents; narrower window than
before. Harmless while `ctx` only means process death. Call
`forgetZoneFileStat` on the first gate too.

---

## Findings 3 and 4 — closed

`FetchFromUpstream` copies `zd.Upstreams` under `zd.mu` before the walk.

`drainTransferEnvelopes` no longer carries `ZoneTransferIn`'s godoc, and
no longer says the reader is left to finish on its own. The abort+drain
requirement and the unbuffered send are now on the helper, where a
future reader would look before deleting the abort.

---

## Non-blocking leftovers

These were taken in spirit. Two are incomplete; neither is a merge
blocker.

**`dialTransferConn` still does not cancel the TCP/TLS dial.** The
derived `ctx` is passed to `pickTransferSrc` (hostname lookup). The
actual connect is still `net.Dialer.Dial` / `tls.DialWithDialer`, which
do not observe `parent`. For an IP-literal upstream — the common case —
`pickTransferSrc` does not use `ctx` at all, so a shutdown that lands in
the dial still waits out the 2s timeout. `DialContext` (and a
`tls.Dialer` handshake under the same `ctx`) would make the comment
true.

**`RefreshError` skip is only on the `RefreshZoneCh` goroutine.** The
ticker path (`refreshengine.go` around the periodic `zd.Refresh`) and
`initialLoadZone` callers still `SetError(RefreshError, ...)` for a
cancelled refresh. The ticker refresh is synchronous in the engine loop,
so shutdown *can* land there. Harmless at process death; same “wrong if
`ctx` bounds a single refresh” argument as before. Mirror the
`errors.Is(err, context.Canceled)` branch.

**Not taken, agreed:** no `InContext` on the johanix/dns fork.

**Tests:** `TestRefreshEngineExitsOnRootCancel` now says it is a
shutdown regression guard, not evidence for this PR. The goroutine-count
delta is gone. `TestDrainStopsOnCancellation` no longer claims the
channel is never closed.

---

## What still looks right

Unchanged from the first pass, verified still present at `710ba934`:

- Abort then drain, bounded by `transferDrainGrace`, with a warning if
  the reader does not exit. `TestDrainReleasesReaderOnCancellation`
  still models the unbuffered send and still fails against the pre-fix
  drain.
- Scratch zone: cancelled AXFR does not publish a partial zone.
- `TsigMaterialForPeer` in the snapshot, `StampTsigForPeer` at send time.
- `confMu` not held across network I/O.
- Envelope-error path does not need abort (`inAxfr` already closes).
- No cross-repo callers; callback signatures untouched.
