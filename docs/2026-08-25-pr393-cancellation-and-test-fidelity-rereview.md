# Re-review: #393 cancellation and test fidelity

**Date:** 2026-08-25 (second pass)
**Prior review:** [`2026-08-25-pr393-cancellation-and-test-fidelity-review.md`](2026-08-25-pr393-cancellation-and-test-fidelity-review.md) (against `cc0af7f1`)
**PR:** [#393](https://github.com/johanix/tdns/pull/393)
**Branch:** `fix/cancellation-and-test-fidelity` @ `e4050d45`
**Lens:** did the three findings close, and did the fix commits introduce
anything new.

New commits since `cc0af7f1`:

- `e2d46430` — cancelled UPDATE actually stops, and reports abandoned.
- `2a799f8c` — mid-flight test bound and cancel cause.
- `a65d7515` — delete the alias test that inlined the copy.
- `e4050d45` — `ReadZoneFile` closes the file it opens.

---

## Verdict

**Approve.** All three findings are closed in the code, not only in the
commit messages. The UPDATE fix is stronger than asked: `ExchangeContext`
does not watch `ctx.Done()`, so a shutdown with no deadline was still
waiting out the 2s client timeout. `exchangeCancellable` closes the
connection. The tests now fail independently if either the watcher or
the `ctx.Err()` check is reverted. No new correctness hole.

| # | First-pass finding | Now |
|---|--------------------|-----|
| 1 | One-address cancel reported “all targets failed” | **Closed.** Mid-exchange `ctx.Err()` returns abandoned, wrapping the cause. |
| 2 | Mid-flight test would pass without `ExchangeContext` | **Closed.** 500ms from cancel; requires `errors.Is(..., context.Canceled)` and `"abandoned"`. |
| 3 | Alias test still inlined the copy | **Closed.** Deleted. `TestPublishedDsyncRRs` still drives the helper. |

The file-close leftover from the first pass is also done. They did not
ship a descriptor-count test that would skip-as-green.

---

## Finding 1 — closed

```128:145:v2/childsync_utils.go
		res, _, err := exchangeCancellable(ctx, client, msg, dst)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return 0, ur, fmt.Errorf("UPDATE to %s abandoned mid-exchange with %s: %w",
					zonename, dst, cerr)
			}
			lgDns.Warn("error from dns.Exchange, trying next address", ...
			continue
		}
```

A real transport error still tries the next address. A cancel does not.

`exchangeCancellable` dials with `DialContext`, then a watcher closes
the conn on `ctx.Done()` so a read already in progress unblocks. The
watcher exits on `finished` when the exchange returns, so a successful
send does not leak a goroutine. Double-close on the conn is the
interrupt, not a bug.

---

## Finding 2 — closed

Both subtests require `errors.Is(err, context.Canceled)`. Mid-flight
measures from `cancel()`, not from the start of the call, and fails if
that is over 500ms (the 2s client timeout would trip it). The 5s
select is only a hang watchdog.

The already-cancelled path still pins the pre-loop check (no dial).

---

## Finding 3 — closed

`TestPublishedDsyncSliceIsCopiedNotAliased` is gone.
`TestPublishedDsyncRRs` / `"result is a copy"` still appends to the
helper’s result and checks the published RRset and backing array.

---

## Extra, looks right

`ReadZoneFile` `defer f.Close()`. `ParseZoneFromReader` consumes the
reader inside the call. Log line now says `ReadZoneFile`, not
`ReadZoneData`. No test, for the reason in the commit: a skip that
prints `ok` is the defect this branch exists to remove.

---

## Nothing new that should block

`SendUpdate`’s godoc still says the exchange goes through
`ExchangeContext` (`childsync_utils.go:81–85`). It does not; that is
what `exchangeCancellable` exists to replace. Same class as the #390
comment that was later restored. Not a behaviour bug.

The commented-out old `SendUpdate` signatures now sit immediately above
`exchangeCancellable`, so they become its godoc prefix. Harmless.
