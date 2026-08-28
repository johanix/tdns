# Review: cancellation on parse and UPDATE, plus two tests (#393)

**Superseded for merge readiness** by
[`2026-08-25-pr393-cancellation-and-test-fidelity-rereview.md`](2026-08-25-pr393-cancellation-and-test-fidelity-rereview.md)
(against `e4050d45`). This file is the review of `cc0af7f1`.

**Date:** 2026-08-25
**PR:** [#393](https://github.com/johanix/tdns/pull/393)
**Branch:** `fix/cancellation-and-test-fidelity` @ `cc0af7f1`
**Base:** `main` (already has [#390](https://github.com/johanix/tdns/pull/390) and [#343](https://github.com/johanix/tdns/pull/343))
**Size:** 17 files, +309 / −79
**Lens:** safety, correctness, and possible improvements. Same bar as
[#390](https://github.com/johanix/tdns/pull/390): this is a shutdown-path
change. A cancelled UPDATE or parse must not look like a transport
failure, and a test that cannot fail for the reason it names is the
defect this PR exists to remove.

Commits:

1. `9ff5ca4f` — `deferForImr` returns a done channel; the cancellation
   test waits on that worker, not `runtime.NumGoroutine()`.
2. `3079a97d` — `publishedDsyncRRs` extracted; owner-lookup tests drive
   the function `PublishDsyncRRs` calls.
3. `2718169c` — `ParseZoneFromReader` checks `ctx` every 2048 records;
   `ReadZoneData` stays on `context.Background()`.
4. `cc0af7f1` — `SendUpdate` takes `ctx` and uses `ExchangeContext`.

---

## Verdict

**Request changes.** Three of the four commits are the right shape.
`deferForImr` now tests the worker it started. `publishedDsyncRRs` is
what production calls. A cancelled `FetchFromFile` still restores
`prevStatus` and does not publish a partial parse. The UPDATE commit
stops the exchange, but then treats that stop as “this address failed,
try the next one”, and the test that claims to pin mid-flight cancel
would still pass if `ExchangeContext` were reverted to `Exchange`.

That is the same class of hole the PR’s first two commits close, on the
commit that is supposed to make shutdown abandon an UPDATE.

| # | Finding | Severity | Nature |
|---|---------|----------|--------|
| 1 | Cancelled `SendUpdate` with one address is “all targets failed” | **Should fix** | Walk reports every scheme failed, not abandoned |
| 2 | Mid-flight cancel test cannot fail for the reason it names | **Should fix** | 5s wait vs 2s `dns.Client` default timeout; error ignored |
| 3 | `TestPublishedDsyncSliceIsCopiedNotAliased` still inlines the copy | Improvement | The new `publishedDsyncRRs` test is the one that can fail |

No path publishes a partial zone. No credential change. CLI callers
correctly pass `context.Background()`.

---

## FINDING 1 — One-address cancel looks like a transport failure (should fix)

`SendUpdate` checks `ctx` before each address, then on `ExchangeContext`
error logs “trying next address” and `continue`s:

```87:103:v2/childsync_utils.go
		if cerr := ctx.Err(); cerr != nil {
			return 0, UpdateResult{}, fmt.Errorf("UPDATE to %s abandoned: %w", zonename, cerr)
		}
		res, _, err := client.ExchangeContext(ctx, msg, dst)
		if err != nil {
			lgDns.Warn("error from dns.Exchange, trying next address", "dst", dst, "err", err)
			ur.TargetStatus[dst] = TargetUpdateStatus{
				Error:      true,
				ErrorMsg:   err.Error(),
				...
			}
			continue
		}
```

The pre-check only sees a cancel that happened *between* addresses. A
cancel *during* the exchange — the case this commit exists for — comes
back as `err`. With one address (the usual DSYNC target, and the test
setup) the loop ends and the function returns:

```131:131:v2/childsync_utils.go
	return 0, ur, fmt.Errorf("all target addresses %v responded with errors or were unreachable", addrs)
```

`context.Canceled` is not wrapped. `walkSyncPlan` then treats it as a
runtime failure of UPDATE. If UPDATE is the only candidate, the walk
returns “every available sync scheme failed”, which is the diagnosis
the plan comments say not to emit for a shutdown
(`delegation_sync_plan.go`: remaining transports were never tried).
With a later candidate the next `ctx.Err()` check does abandon, but
only after recording a fake UPDATE failure.

**Fix:** after `ExchangeContext` returns an error, if `ctx.Err() != nil`
return the abandoned error (wrap `cerr`). Do not continue. The
mid-flight test should require `errors.Is(err, context.Canceled)` (or
the abandoned text plus the cause), the way the parse test already
does.

---

## FINDING 2 — Mid-flight test would pass without `ExchangeContext` (should fix)

`TestSendUpdateHonoursCancellation` / “cancelled mid-flight”:

- listener accepts and never answers
- `SendUpdate` on a one-address list
- cancel after 150ms
- succeed if the call returns within 5s
- error value ignored (`_, _, _ = SendUpdate(...)`)

`dns.Client{Net: "tcp"}` leaves `Timeout` at 0.
`github.com/johanix/dns` then uses `dnsTimeout` = 2s for the read
deadline (`client.go:16`, `getTimeoutForRequest`). `Exchange` (no
context) returns in about 2s. The 5s bound does not distinguish that
from a cancelled `ExchangeContext`.

The PR body says reverting `ExchangeContext` → `Exchange` fails this
subtest. Against this client it does not. The already-cancelled
subtest *does* pin the pre-loop `ctx.Err()` check (returns in well
under a second). It does not pin the on-the-wire path.

**Fix:** require the cancel cause (finding 1), and a bound tighter than
the 2s client timeout (e.g. 500ms). Then a revert to `Exchange` fails.

---

## FINDING 3 — Old alias test still restates the copy (improvement)

`TestPublishedDsyncRRs` / “result is a copy” drives `publishedDsyncRRs`
and would fail if it returned the live slice. That is the test the
commit promised.

`TestPublishedDsyncSliceIsCopiedNotAliased` still does:

```go
working := append(make([]dns.RR, 0, len(published)), published...)
```

and never calls `publishedDsyncRRs`. Same inline restatement the commit
message says is worse than no test. Delete it, or point it at the
helper.

---

## What looks right

**Parse cancel.** `FetchFromFile` already had `ctx`. Threading it into
`ReadZoneFile` → `ParseZoneFromReader` is the missing stretch. On error
it restores `prevStatus` (`zone_utils.go:433–436`) and does not copy
the scratch zone, so a cancelled parse of a large file does not leave
the zone in `loading` and does not publish a prefix. The post-parse
gates already call `forgetZoneFileStat`. Checking every 2048 records is
a stated tradeoff; the 20k-record test actually hits it. `ReadZoneData`
on `context.Background()` is a real scope boundary, documented at the
function, not a missed call site. Production `ReadZoneFile` callers in
`v2/` are the one `FetchFromFile` site plus tests.

**`deferForImr`.** Returning `<-chan struct{}` closed in a `defer` is
the right handle. Production ignores it. The cancellation test waits on
that channel and still asserts the queue stays empty. Removing the
`ctx.Done()` arm fails it.

**`publishedDsyncRRs`.** Nil owner, nil `RRtypes`, TXT-only, and a real
DSYNC RRset are all driven through the helper. The copy uses a new
backing array (`append(make(...), existing.RRs...)`), which is the
aliasing property that mattered.

**Call sites.** Six of seven `SendUpdate` callers already had `ctx`.
`SyncZoneDelegationViaUpdate` takes it from `walkSyncPlan`. CLI uses
`context.Background()`. Signature change is complete in `v2/` (the
legacy `tdns/` tree is out of this PR).

---

## Non-blocking

- `ReadZoneFile` still does not `Close` the `os.File` it opens
  (pre-existing; cancel returns before EOF, same leak as success until
  GC).
- Parse does not check `ctx` until record 2048; an already-cancelled
  small zone still finishes. Documented.
- `sig0_utils.go` error string now contains the literal `ctx` (`error
  from SendUpdate(ctx, %v)`). Harmless.
