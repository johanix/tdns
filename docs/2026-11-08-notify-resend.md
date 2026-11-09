# Resending an unanswered NOTIFY, and per-target NOTIFY state

**Written 2026-11-08.** For #1007, with the `zone desc` half of #528. Line
references are to main at `0cc79ba3`.

**Status:** implemented on `claude/1007-notify-resend`, stacked on the #1008
branch (the SOA in NOTIFY(SOA)), whose message building it reuses.

## The problem

`SendNotify` (`v2/notifier.go:112`) sent one NOTIFY per target over UDP with a
5-second timeout, logged a failure and moved on (`v2/notifier.go:182`). Nothing
tried again and there was no TCP. One lost packet left a secondary stale until
its SOA refresh timer, which can be hours. RFC 1996 §3.6 says the primary
should resend. The maintainer ruled the missing resend a bug.

Two more things made it worse. The Notifier was one goroutine sending to each
target in turn, so one unreachable downstream held every other zone's NOTIFY
for the timeout. And publishes handed their NOTIFY over with a non-blocking
send that dropped it when the queue was full (`v2/zone_mutation.go:910`).

## The decisions

Taken with the maintainer on 2026-11-08:

1. Resend 5 times (RFC 1996's suggested maximum), the first after 10 s and each
   later one twice as long: 10, 20, 40, 80 and 160 s. Settable per zone and
   server-wide. The RFC's flat 60 s would make one lost packet cost a minute.
2. Retry only requests no caller is waiting on. The KSK rollover's NOTIFY(CDS)
   waits for the answer with a deadline and retries on its own schedule.
3. One immediate TCP retry after an ICMP port unreachable on UDP, and nothing
   more.
4. Replace the drop-on-full queue for downstream NOTIFYs with a per-zone pending
   set.
5. #528's `zone desc` block goes in the same PR.

## The design

**Per-target state** (`v2/notifier_tracker.go`). The `NotifyTracker` keeps, per
(zone, target, NOTIFY type): the attempts for the version being notified, when
the next resend is due, whether a send is in flight, the last attempt, the last
answer, the last error and the consecutive unanswered sends. Only no answer at
all schedules a resend; any reply ends the tries, REFUSED included, because
asking again gets the same reply. A newer version for a target supersedes a
pending resend: if a send is in flight, the new version goes out when it
returns, from attempt one. When the tries run out, one Warn line says so; the
next answer logs one Info line. Per-attempt lines are Debug: the log gets the
edges and `zone desc` the state, which is what #528 asked for.

**Sends beside the loop.** The Notifier launches each send in its own
goroutine, at most 16 on the wire at once, and gets the outcome back on a
channel. Its loop only dispatches: requests from the queue, the pending set when
woken, outcomes, and a timer for the earliest resend.

**Who resends.** A request with a `Response` channel is sent once per target and
answered with the same any-success-wins aggregate as before (`notifyAggregate`),
from a goroutine so a caller whose deadline passed cannot stall the loop.
Everything else is tracked and resent: downstream NOTIFY(SOA), and the
fire-and-forget NOTIFY(CSYNC/CDS) to a parent and NOTIFY(DNSKEY) to a
multi-signer controller.

**Each attempt is built afresh** (`notifyOneOver`): a new TSIG time stamp, since
a reused one goes stale (BADTIME), and the SOA as served at that moment.

**TCP.** An error that unwraps to `syscall.ECONNREFUSED` on UDP is followed at
once by the same NOTIFY over TCP, inside the same attempt.

**The pending set.** `notifyIfServableLocked` calls `NotifyTracker.Mark`, which
stores the request as the zone's latest and wakes the Notifier. It never blocks
and never drops; a burst of publishes becomes one NOTIFY carrying the latest
SOA. A daemon without a tracker keeps the queue.

**Settings.** `notify-retries` and `notify-retry-interval` in a zone, and the
same keys under `authengine`. The zone's win; the server's are read when the
Notifier starts.

**`zone desc`.** `ZoneConf.DownstreamNotifies` carries the tracker's rows for
the zone, and the CLI prints a "Downstream notifies" block beside "Upstream
serials": per target, its state, the attempt it is on, when it last answered,
the unanswered sends in a row and the last error.

## Tests

`v2/notifier_resend_test.go`: resent until answered, given up after the
retries, REFUSED not resent, TCP after refused UDP, a waiting caller's request
sent once, the pending set coalescing per zone, a publish handing its NOTIFY to
the tracker, and the zone's settings winning. `v2/cli/zone_notify_display_test.go`
covers the `zone desc` block.

## Changes from the first review (2026-11-09)

CodeRabbit's first round led to these changes:

- **Bounded dispatch.** At most `notifyMaxInFlight` (16) sends run at once.
  The rest wait in the Notifier's own queues as jobs, not as goroutines. A job
  whose caller waits for the answer goes ahead of the tracked ones, since that
  caller has a deadline. A tracked target has at most one job queued or
  running, so the queue never holds more jobs than there are targets.
- **Resends in time order.** The tracker keeps its scheduled resends in a
  min-heap, so finding the next one no longer scans every target after each
  event. An entry is not removed when its resend is taken or cancelled; one
  that no longer matches its target's due time is dropped when it reaches the
  top. A per-zone index serves `zone desc` and `retire`.
- **State is released.** Each tracked request carries the zone's whole
  downstream set, so a target missing from it is dropped. Every ten minutes
  the Notifier drops the resting state of zones it no longer serves, or that
  are served by a new ZoneData. A send in flight, or a resend already
  scheduled, is left to run its course; the retry limit bounds it.
- **A superseding NOTIFY uses the new ZoneData,** the one the newer version
  came with, not the one the finished send used.
- **Smaller fixes:**
  - a request with a waiting caller and no target is answered at once;
  - an answer nobody takes is dropped after a minute instead of waiting until
    shutdown;
  - a negative `notify-retries` is logged and ignored;
  - a retry interval set longer than an hour is honoured;
  - `zone desc` shows "cannot sign" when the TSIG setup fails, and "retrying"
    ahead of an old "given up";
  - an API-provisioned primary gets its template's resend settings.

`v2/notifier_tracker_test.go` covers these.

## Changes from the later reviews (2026-11-09)

CodeRabbit's second and third rounds, and the project owner's rulings on them:

- **A removed downstream stops getting NOTIFYs.** State from a publish's
  NOTIFY is tagged as downstream state. When a publish finds no downstreams
  left, it hands the tracker an empty request, which retires them all. It
  does so only if the tracker holds downstream state for the zone or has a
  request for it not yet taken (the project owner asked for that last part:
  cheap, and it closes the window). State from CDS and CSYNC NOTIFYs to the
  parent does not count, since an empty request cannot retire it. The ten-minute
  prune also drops downstream state for targets the zone no longer lists,
  which covers a configuration reload with no publish since.
- **A daemon without a tracker** sends a publish's NOTIFY through the queue,
  and the request says it names the downstream set, so the same retiring
  applies.
- **A caller's deadline cancels its queued sends.** `NotifyRequest.Ctx`
  carries the waiting caller's context; a send still queued when it is done
  is not made, and the batch is answered as failed. The KSK rollover's DS
  push sets it.
- **Declined: a cap on the queue of jobs whose caller waits.** It holds one
  job per target of each waiting request, and those callers are the
  rollover's DS pushes, one per zone in flight. The caller's deadline is the
  better refusal (accepted by the project owner, 2026-11-09).
- **`zone desc` shows "rejected"** for a target that answered with anything
  but NOERROR. It is still not resent: a refusal is not a lost packet.
- **A dynamic zone keeps its resend settings across a restart.** The
  refresher that brings a persisted dynamic zone back carries them, and so
  does every config-bearing reload.
- **Declined: resolving the parent outside the Notifier loop.** A CDS or
  CSYNC NOTIFY with no cached parent looks it up in the loop. That is not new
  (before this change the Notifier did everything in order), the answer is
  cached, and such NOTIFYs are rare. Moving it out while keeping requests in
  order is a change of its own.
- **Declined: stopping resends on a reply that fails TSIG.** Such a reply does
  not show the target got the NOTIFY, and stopping on it would let a forged
  reply suppress the resends. The target's last error shows the TSIG failure.
