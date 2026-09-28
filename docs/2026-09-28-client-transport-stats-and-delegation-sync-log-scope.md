# Scope: per-client transport counters in the resolver, and a delegation-sync log on the parent

2026-09-28. Status: scope, r2, amended. Part 0 is implemented and merged
(#802, merge dd7de680). Part 2 (#804) and part 1 (#805) are implemented and
not yet merged. Base of r2: `main` at 700b15ef.

**Revisions**
- **r1:** the scope.
- **r2**, the same day, after an external review whose verdict was "sound":
  - its five pins are written in: S1 in part 0, S2–S3 in part 1, S4–S5 in part 2;
  - its four considerations are decided where they apply (C1–C4);
  - a second DoH/DoQ defect found while implementing part 0 is added, as part 0b.
- **Amended** the same day, after the reviews of the three implementations:
  [A1–A5](#amendments-2026-09-28) at the end. The text above them is r2 as
  reviewed, unchanged.

## Summary

Two small observability additions, plus two small fixes to the DoH and DoQ
writers. The first addition needs one of those fixes.

| Part | What | Default | Production | Tests |
|---|---|---|---|---|
| 0 | DoH reports the real client address instead of a fixed one (0a); DoH and DoQ no longer report an unchecked TSIG as verified (0b) | always | 40–70 | 80–130 |
| 1 | Resolver: per-client transport counters, with API and CLI | **off** | 350–550 | 350–550 |
| 2 | Parent: delegation-sync log, with API and CLI | **on** | 340–510 | 350–550 |

**Neither addition costs a production server anything that matters.**
- **Part 1** has no check at all on the query path when it is off. The handler
  is wrapped once, at listener setup, and only when it is enabled.
- **Part 2** records rare events (a delegation change, a scan, an UPDATE), never
  one per query. Its memory is one bounded ring.
- **Both are runtime options,** not build tags. Build tags would mean two binary
  flavours and a test setup that no longer runs the binary that ships, for no
  gain: neither part pulls in a dependency.

**Order:**
1. Part 0 on its own. It is small, and it has a security side (see below).
2. Part 2, with no hot path involved, and the most use to operators.
3. Part 1.

Each is its own PR.

---

## 0. Prerequisite: DoH reports a fixed client address

**The defect.**
- `dohResponseWriter` (v2/doh.go:226–260) answers `RemoteAddr()` and
  `LocalAddr()` with `dummyAddr{}`, whose `String()` is `"127.0.0.1:443"`.
- So everything downstream of the DoH engine sees every DoH client as
  127.0.0.1.

**Why it matters beyond the counters.** Two authorization checks take the
source address from `w.RemoteAddr()`. tdns-auth serves DoH with the same
handler as Do53 (v2/do53.go:292).
- **`authorizeInboundNotify`** (v2/notifyresponder.go:129).
  - A NOTIFY sent over DoH from anywhere is judged as coming from 127.0.0.1.
  - It therefore passes an `allow-notify` entry for 127.0.0.1 with no key. That
    is a common entry when a signer and its primary share a host.
- **`authorizeTransfer`** (v2/downstream_auth.go:99) has the same exposure for a
  `downstreams` entry that allows 127.0.0.1.
  - Not checked: whether an AXFR or IXFR over the buffer-backed DoH writer
    actually delivers zone data.

**The fix (0a).**
- **The client's address.** Carry the `http.Request`'s `RemoteAddr`, the peer of
  the DoH connection, into `dohResponseWriter`.
  - Parse `host:port`, IPv6 included, into an address type of the DoH writer's
    own. Its `String()` is `host:port`, which `peerIP` already understands.
  - Do not assume `*net.TCPAddr`. HTTP/2 runs on TCP today; HTTP/3 would not.
- **The listener's address,** from the request context, becomes `LocalAddr`.
- **A peer that cannot be parsed** gets a stand-in that is *not* loopback and
  that `peerIP` refuses. Authorization by address then fails, through the
  existing "unparseable source" path.
  - A stand-in that reads as 127.0.0.1 would be the same hole again, for that
    one request (S1).
- **Never `X-Forwarded-For`.** Trusting a proxy's header is a separate, explicit
  setting, or it is an ACL bypass.
- **Tests:**
  - a DoH request's handler sees the HTTP peer, IPv4 and IPv6;
  - a NOTIFY over DoH from a non-loopback address is refused by an
    `allow-notify` that lists only 127.0.0.1;
  - an unparseable peer does not match a 127.0.0.1 ACL.
- **What part 0 does not change (C1).** NOTIFY(CDS) and NOTIFY(CSYNC) to a
  parent are not gated by `allow-notify`. They are gated by parenthood and the
  advertised DSYNC schemes, and that model stays as it is.

**0b: DoH and DoQ report an unchecked TSIG as verified.** Found while
implementing 0a.
- **The defect.** The DoH and DoQ writers are not miekg `dns.Server`s, so no
  `TsigProvider` runs on their requests. Their `TsigStatus()` was a stub that
  returned nil, and nil is what "the MAC verified" looks like.
  - `checkInboundTSIG` (v2/tsig_peer.go) and the transfer ACL
    (`matchedDownstreams`, v2/downstream_auth.go) trust exactly that.
  - So over DoH or DoQ, a request that names an approved key, with any MAC at
    all, passed both: an inbound NOTIFY, and a transfer request for a zone
    whose `downstreams` entry requires that key.
  - Do53 and DoT are not affected: their `dns.Server`s have the provider.
- **The fix.** `TsigStatus()` fails closed: a request that carried a TSIG
  reports an "unverified" error. Unsigned requests report nil, as miekg does.
  - A TSIG-authenticated operation over DoH or DoQ is then refused, where it
    used to be accepted unchecked.
  - Verifying TSIG on these transports stays a TODO.
- **Tests:**
  - `TsigStatus` of a signed request over DoH and over DoQ;
  - `checkInboundTSIG` refuses an unchecked TSIG under the approved key;
  - the transfer ACL refuses an AXFR over DoH that only names the key.

---

## 1. Resolver: per-client transport counters

*Amended: [A4](#amendments-2026-09-28) (the CLI command), A5 (`max-clients`).*

### What it records

For each client address, and each of the five transports it can use to reach
the resolver (Do53 over UDP, Do53 over TCP, DoT, DoQ, DoH):
- the number of queries since startup or the last reset;
- when that transport was last used.

The store also keeps:
- the time the counters started (startup or reset);
- the number of clients evicted, and their counts, so that totals stay honest
  when the cap is reached.

It records no query names and no answers.

### Where it hooks in, and why it is free when off

- **One handler for every listener.** The resolver builds one query handler
  (`imr.createImrHandler`, v2/imrengine.go:1808) and gives the same handler to
  every listener:
  - Do53: one `dns.Server` per address and network, all sharing `imrMux`
    (v2/imrengine.go:1815–1830);
  - DoT, DoH and DoQ: `DnsDoTEngine`, `DnsDoHEngine`, `DnsDoQEngine`
    (v2/imrengine.go:1899–1925).
- **When enabled,** the handler each listener gets is wrapped by
  `clientStats.wrap(handler, transport)`:
  - Do53 gets two muxes instead of one, for UDP and for TCP;
  - the three encrypted engines get the wrapped handler.
- **The wrapper** records `w.RemoteAddr()`'s address and the transport, then
  calls the handler.
- **When disabled** (the default), nothing is wrapped. The query path is exactly
  today's: no branch and no nil check.
- **The transport is known per listener.** It cannot be read from the response
  writer: DoT's writer and Do53/TCP's both report a TCP address. That is why
  the wrapper is chosen per listener.

### The store

- A mutex-protected map from `netip.Addr` to a small struct: 5 counts, 5
  last-seen times, the latest of those (`lastAny`), first seen.
- **The key is `netip.Addr.Unmap()`** (S2). A client seen over Do53 as
  192.0.2.10 and over DoH as ::ffff:192.0.2.10 is one machine, and one row.
- **A cap on clients** (`max-clients`, default 4096), with eviction of the
  least recently seen *on any transport* (`lastAny`), through an LRU list,
  O(1). A transport a client never used must not make it look old.
- **Evicted clients' counts** are added to an "evicted" aggregate, never lost
  from the totals.
- **Reset** clears the whole store: the map, the aggregate and `since` (S3).
- **Cost when enabled:** one map lookup and two writes under a mutex per query.
  A benchmark measures it. It can be sharded later if it ever shows up in
  profiles.

### Config

```yaml
imrengine:
  client-stats:             # per-client transport counters. Diagnostic: it records
    enabled: false          # client addresses, so it is off by default.
    max-clients: 4096
```

Added to `ImrEngineConf` (v2/config.go:400), with validation.

**`enabled` takes effect when the listeners are set up**, that is at startup. A
config reload that flips it does not wrap or unwrap running listeners: changing
it needs a restart, and the documentation says so (S3).

### API

A new command on the resolver's API, `imr-client-stats`, next to the existing
`imr-transport-stats` (v2/apihandler_imr.go:458).

| Request field | Meaning |
|---|---|
| `clients` | addresses or prefixes; empty means all. It only filters what is returned. |
| `reset` | after reading, clear the **whole** store (every client, the evicted aggregate, `since`), whatever `clients` says (S3) |

A reset of only the filtered clients would be a trap: the operator would think
they had zeroed one prefix.

The response holds:
- `since`, the start or reset time;
- one row per client: counts and last-seen per transport;
- the evicted aggregate.

When the feature is off, the command answers "client-stats not enabled".

### CLI

```
tdns-cli imr client-stats [-c <addr|prefix>]... [--sort total|last|addr] [--reset] [--json]
```

Output:

```
Client transport counters since 2026-09-28 09:14:02 (startup), 37 clients, 0 evicted

CLIENT            DO53/UDP  DO53/TCP   DOT   DOQ   DOH   TOTAL  LAST SEEN
192.0.2.10              12         0   340     0     0     352  09:41:13 (DoT)
2001:db8::53             0         0     0   118     0     118  09:40:58 (DoQ)
…
TOTAL                 1520        14   902   118    36    2590
```

- **"All or these clients":** `-c`, repeatable, takes an address or a prefix.
  It also works for "which transports did these clients use recently", read
  from the last-seen column.
- **"Since startup or reset":** the header states which, and `--reset` starts a
  new period for every client, not only the ones selected with `-c`.

### Tests

- **Store:**
  - counts, last-seen, prefix filtering;
  - eviction at the cap, with the aggregate;
  - concurrent recording under `-race`;
  - the same client as IPv4 and as IPv4-mapped IPv6 is one row (S2);
  - eviction uses the latest last-seen across transports (S2);
  - `-c 192.0.2.0/24 --reset` returns the filtered snapshot and then zeroes
    every row (S3).
- **Wiring:**
  - off: the listeners get the unwrapped handler, and nothing is counted;
  - on: a query over each of the five transports lands in the right column.
    DoH depends on part 0.
- **API and CLI:** a round trip, and table formatting.
- **Benchmark:** the handler with the feature on, against off.

### Size

| Piece | Production | Tests |
|---|---|---|
| Store: counts, LRU cap, snapshot with filter, reset | 150–220 | 150–220 |
| Wiring in the listener setup, and config | 45–80 | 60–100 |
| API command | 40–70 | 40–60 |
| CLI command | 100–150 | 30–60 |
| Benchmark | – | 30–50 |
| **Total** | **≈ 350–550** | **≈ 350–550** |

**Not in scope:**
- **tdns-auth's own listeners** (v2/do53.go:284–298). The same wrapper would
  take one call site each, when someone needs it.
- **The embedded resolver's loopback debug window (C2).** It is a separate
  handler, on loopback, for the resolver inside other daemons. It is not
  wrapped, the five-transport test does not cover it, and the documentation
  says so.

---

## 2. Parent: delegation-sync log

*Amended: [A1](#amendments-2026-09-28) (polls), A2 (`queued`), A3 (no
full-queue refusal).*

### What it records

One event per thing that happens to a child's delegation at the parent:
- **the time, the parent and the child;**
- **the mechanism:** UPDATE, NOTIFY(CDS), NOTIFY(CSYNC), scan(CDS),
  scan(CSYNC) (a poll), or API;
- **the outcome:**
  - **applied:** the zone changed. Nothing else is called applied (S4);
  - **apply failed:** the change was decided but did not land;
  - **no change;**
  - **not processed;**
  - **refused;**
- **the details:**
  - adds and removes by type: DS, NS, glue;
  - glue that was skipped;
  - the rcode and EDE of a refusal;
  - the reason text, for example "child nameservers not in sync for SOA".

That reason is what the parent logs today at Info, and nothing more.

### Where it hooks in

All four places already hold the information.

| Place | Covers | Information there |
|---|---|---|
| `scanChildAndApply` (v2/scanner_apply.go:~60–118) | scans started by a poll (`poll != nil`, mechanism `scan(…)`) and by a NOTIFY (`poll == nil`, mechanism `NOTIFY(…)`), for CDS and for CSYNC | `ScanTupleResponse`: adds and removes, `Error`/`ErrorMsg`, `ValidationReason`, `GlueSkipped`; and the result of the CHILD-UPDATE it leads to |
| `UpdateResponder` (v2/updateresponder.go:126–~410): the answer the child gets | a DNS UPDATE from a child (CHILD-UPDATE and key material) | rcode, `RejectionEDE` (e.g. from `ApproveChildUpdate`, :619–:800), the update's counts |
| `DsyncApiPostDelegation` (v2/dsync_api_delegation.go): POST only (C3) | the DSYNC API scheme | the status it returns: 200 applied; 400, 403 or 409 refused, with the reason |
| `NotifyResponder`: each terminal refusal of a NOTIFY(CDS) or NOTIFY(CSYNC) that does not start a scan (S5) | NOTIFYs that never became a scan: unknown parent, not a child, the DSYNC scheme not advertised, the zone in error, a full scanner queue | the refusal reason |

**Pins from the review:**
- **The scan hook records the outcome of the change, not of the scan (S4).**
  `logScanResult` runs before `OnDelegationChange`. A "change" there only
  means the scan decided to update, and the CHILD-UPDATE that
  `applyScanChildUpdate` queues can still fail or time out. So:
  - a change is recorded once its result is known: **applied** if it landed,
    **apply failed** with the reason if not;
  - a scan that decides nothing is recorded at once: no change, or not
    processed.
- **Refused NOTIFYs are required, not optional (S5).** They are what an operator
  looks up when a child says it notified and the parent did nothing. A NOTIFY
  that is accepted and starts a scan is recorded only by the scan hook: one line
  per event, never two.
- **The scanner's own CHILD-UPDATE is not recorded again.** It goes to the zone
  updater through `UpdateQ`, not through `UpdateResponder`, and it must stay
  that way. Otherwise every scan apply would be two events.
- **DSYNC API GETs are not logged (C3).** They change nothing.

### Gate and memory

- **Config:** the childsync block (`ChildSyncConf`,
  v2/config_delegationsync.go:149): `sync-log: 10000`, the number of events
  kept.
- **Default 10000, so it is on.** 0 disables it: the recorder is then nil, and
  each hook is `if l := syncLog(); l != nil { l.Add(ev) }`.
- **The events are rare** (per change, scan or UPDATE), so the cost is
  negligible either way.
- **Memory** is one ring for the whole server, never a store per child.
  10,000 small events is a few MB at most, and it is allocated as events arrive.
  A server that never syncs a delegation keeps nothing.
- **A `dropped` counter (C4).** It counts the events the ring has overwritten,
  and is reported next to `since`. It tells a gap in the log apart from a
  quiet parent.

### API and CLI

- **API:** a `sync-log` command on the existing `/delegation` endpoint
  (v2/apirouters.go:113, `APIdelegation`), with filters `child`, `since` and
  `limit`, newest first.
  - It is behind the operator API key. The DSYNC API's registrant credentials
    cannot read it.
  - With `sync-log: 0` it answers that the log is off.
- **CLI**, under the existing `delegation` group (v2/cli/zone_delegation_cmds.go:28):

  ```
  tdns-cli zone delegation sync-log [-z <parent>] [--child <zone>] [--since 10m] [--limit 50] [--json]
  ```

  One line per event:

  ```
  09:41:07  example.  child.example.  NOTIFY(CSYNC)  applied        ns +1 -0, glue +2 -0
  09:38:52  example.  child.example.  scan(CSYNC)    not processed  child nameservers not in sync for SOA
  09:12:03  example.  other.example.  UPDATE         refused        REFUSED, EDE: SIG(0) key known but not yet trusted
  ```

### Tests

- **Ring:** order, bound, the `dropped` count, filters, concurrent `Add` under
  `-race`.
- **Each hook:** one test per mechanism, using the existing scanner, UPDATE and
  DSYNC API test harnesses (`dsync_api_delegation_test.go`, the `scanner_*`
  tests). An applied change and a refusal each produce the event expected. Plus:
  - a NOTIFY-started scan and a poll give different mechanisms (S4);
  - a scan that finds a change whose CHILD-UPDATE then fails or times out is
    not recorded as applied (S4);
  - a NOTIFY(CSYNC) refused because the DSYNC record does not advertise NOTIFY
    gives one refused line and no scan line (S5);
  - an accepted NOTIFY that leads to an applied scan gives one line, not two
    (S5);
  - a DSYNC API GET adds nothing; a POST that gets 403 adds a refused line (C3).
- **Off (`sync-log: 0`):** the hooks record nothing and do not panic, and the
  API says the log is off.
- **API and CLI:** a round trip, and formatting.

### Size

| Piece | Production | Tests |
|---|---|---|
| Event type and ring, query with filters | 80–120 | 80–120 |
| Four hooks, mapping each path's result to an event; the NOTIFY refusals; waiting for the apply result | 110–170 | 200–320 |
| Config | 15–25 | – |
| API command | 40–70 | 40–60 |
| CLI command | 90–140 | 30–50 |
| **Total** | **≈ 340–510** | **≈ 350–550** |

---

## Not in scope

- **A per-child history that survives a restart.** The ring is in memory by
  design.
- **Exporting either as metrics** (Prometheus or similar). The shapes allow it
  later.
- **Rate limiting of NOTIFY**, which is a separate open issue.

---

## Amendments (2026-09-28)

Where the implementations differ from r2, or r2 was wrong, as found in the
reviews of #804 and #805. Each describes the code as implemented.

**A1. Part 2: polls are quiet** (#804). r2 said a scan that decides nothing is
recorded at once, as *no change* or *not processed*.
- **A NOTIFY-started scan** is recorded every time, *no change* included.
- **A poll** that finds no change is not recorded. With many children polled
  every round, those lines would be most of the ring.
- **A poll's *not processed*** is recorded. A repeat with the same reason, for
  the same child and mechanism, is recorded at most once an hour.
- **A change** is always recorded.
- **A scan that stops before it reads the child** is recorded as *not
  processed*, with the reason. That is either an earlier change to the child
  still queued at the zone updater, or a delegation that cannot be read. For a
  poll, the hourly rule above applies.

**A2. Part 2: `queued`** (#804). The outcome list gains **queued**: a change the
scan handed to the zone updater, with no answer yet when the scan stopped
waiting.
- When the answer comes, a second event records *applied* or *apply failed*,
  marked "answered late".
- The first event is not edited.
- r2's "recorded once its result is known" would have shown nothing during the
  wait.

**A3. Part 2: no full-queue refusal.** The hooks table lists "a full scanner
queue" among NOTIFY refusals. There is no such refusal: `NotifyResponder` waits
for room on the scanner queue. A non-blocking refusal, if one is added, needs
the refusal hook as well.

**A4. Part 1: the CLI command** (#805) is
`tdns-cli imr stats client-stats`, next to `transport-stats`, not
`tdns-cli imr client-stats`. The flags are as in r2.

**A5. Part 1: `max-clients`** (#805). A negative value is a config error, at
load and in `ValidateConfig`. 0 means the default, 4096.
