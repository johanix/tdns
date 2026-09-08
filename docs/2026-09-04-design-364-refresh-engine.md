# Fix design: #364 - refresh engine (and #502, which it causes)

Not committed. Written 2026-09-04 for review 2026-09-05.

The issue already carries measurements and a suggested order, and I am not
arguing with either. This document adds what it does not: what "done" means for
the training lab, how to stage it so each piece is separately reviewable and
revertable, and the two decisions that need Johan rather than a patch.

## Why this is first on the shortlist

#502 - "a secondary whose upstream is unreachable at boot never finishes
provisioning, and blocks every zone behind it" - is this issue's part 3 as it
presents in the lab. It is what cost us the morning of 2026-09-04: the master
served nothing, the symptom read as "DNS is down", and the cause was one
off-site zone whose primary was unreachable.

So the acceptance criterion is not a benchmark. It is:

> One unreachable upstream must not prevent any other zone from being served,
> and the affected zone must say what is wrong with it.

Everything below is in service of that. The scaling numbers are a separate,
real, and much less urgent benefit.

## Stage 1 - jitter the initial refresh counters

`initialLoadZone` sets `CurRefresh: refresh`, so zones sharing a SOA refresh
value - the normal case for template-provisioned lab zones - come due on the
same tick.

Set the initial counter to a random value in `[1, refresh]` instead. Small,
no concurrency risk, and it spreads the probes in stage 3's problem as a side
effect.

Two details worth getting right:

- **Do not jitter a zone that has never loaded.** A zone still waiting for its
  first successful transfer should retry on its retry interval, not be pushed
  out by up to a full refresh interval.
- **Jitter at load, not at every reset.** After a successful refresh the
  counter should go back to the zone's real refresh interval; re-jittering
  every cycle makes the effective interval drift and makes bug reports
  irreproducible.

## Stage 2 - make a tick proportional to what is due

`refreshCounters.Items()` copies the whole map every second. `IterCb` removes
the copy for one line of change and is worth taking immediately.

The real fix is a due-time structure - a min-heap keyed by next-refresh time,
or a timing wheel - so a tick touches only what is due. That is a bigger change
and it is **not** on the critical path for the lab: 11.55 ms/s at 100k zones is
irrelevant at lab scale. Recommend taking `IterCb` now and deferring the heap
until there is a deployment that needs it, rather than bundling it with stage 3
and making that harder to review.

## Stage 3 - get the network probe off the engine goroutine

This is the one that matters, and the one that fixes #502.

**Shape.** The engine goroutine stops calling `zd.Refresh` for secondaries and
instead dispatches to a bounded worker pool. The operator-triggered branch
already does this and carries an `XXX: Should do refresh in parallel` comment;
this makes the ticker path agree with it.

**Pool size.** Well above core count - the work is network-bound. Start at
something like 32 and make it configurable, because the right number depends on
how many secondaries with slow primaries a deployment has, and nobody will
guess it correctly in advance.

**Per-zone exclusion is mandatory, not an optimisation.** Two concurrent
refreshes of one zone race on the `FirstZoneLoad` read-then-apply in
`FetchFromFile`/`FetchFromUpstream` and on the recorded zone file stat. The
window is narrow today only because the ticker is serial - removing the serial
ticker widens it to certainty. A per-zone `TryLock` that skips (rather than
queues) a zone already refreshing is the right primitive: a zone whose refresh
is still running does not need a second one queued behind it, and skipping
keeps the pool free for zones that can make progress.

**Deepen `NotifyQ`.** It is `make(chan NotifyRequest, 10)`. N parallel
refreshers sending NOTIFY will block on it, which would reintroduce exactly the
stall this stage removes, in a new place.

**Do not parallelise the database work.** `KeyDB` serializes on one mutex, so
the win is the parse, the digest and the network wait. Trying to get more will
produce contention and no throughput.

## The two decisions that are not mine

**1. What should a zone with an unreachable upstream do?**

Today it stalls the engine forever. The options:

- **Bounded attempt, then degraded.** The zone is marked with an error, keeps
  serving whatever it has (which #413's fix already permits until SOA EXPIRE),
  and retries on its retry interval. The engine never waits for it.
- **Bounded attempt, then quarantined.** As above but the zone stops being
  retried until an operator intervenes. Cheaper, but a transient outage then
  needs a human.

I recommend the first: it is what a secondary is supposed to do, and it is what
the lab wants - a student whose primary is down should see their secondary
serving stale data and complaining, not the whole master stop.

**2. What is the per-attempt timeout?**

`dns.Client`'s default 2s, times upstreams, is the current cost of one
unreachable primary. Once the probe is off the engine goroutine that stops
being a global stall, but it still decides how long a worker is tied up. This
wants a config knob with a sane default rather than the library default
inherited by accident.

## What I would NOT do

- Bundle stages 2 and 3. The due-time heap and the worker pool are independent,
  and reviewing them together makes both harder.
- Treat this as a performance issue. The lab has tens of zones, not 100k. The
  reason it is ranked first is availability, and stage 3 alone delivers that.
- Close #502 when this lands without checking it against the lab. The
  provisioning path is what actually failed, and "the engine no longer stalls"
  is necessary but perhaps not sufficient for "the zone finishes provisioning".

## Testing

- **The #502 reproduction, as a test:** a secondary whose upstream is a
  blackholed address, plus a second healthy zone; assert the healthy zone is
  served while the first is still failing. That test fails today and is the one
  that matters.
- **Per-zone exclusion:** two concurrent refresh triggers for one zone, assert
  one runs and one is skipped, and that `FirstZoneLoad` handling is not
  corrupted.
- **Jitter:** assert initial counters for N zones with identical SOA refresh
  are distributed, not identical.
- Keep the existing serial behaviour available behind a config value for one
  release if that is cheap - a training lab is a bad place to discover a
  concurrency regression, and being able to turn it off is worth more than the
  elegance lost.

---

## Amendment, 2026-09-08: committed, and superseded in detail

"Not committed" above was true when written. This document was committed
2026-09-08 in [#581](https://github.com/johanix/tdns/pull/581).

Its design was superseded by
`2026-09-05-refresh-engine-redesign-364-502.md`, which is the frozen one to
implement from. This is kept for the framing it established — that #502 is a
consequence of #364 rather than a separate bug.

[#364](https://github.com/johanix/tdns/issues/364) and
[#502](https://github.com/johanix/tdns/issues/502) are both still **open**; the
implementation is on PR #514 and the lab close-out in the redesign's §9 is what
remains.
