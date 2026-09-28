# Scope: per-client transport counters in the resolver, and a delegation-sync log on the parent

2026-09-28. Status: scope. Nothing is implemented. Base: `main` at 700b15ef.

## Summary

Two small observability additions, plus one small fix that the first one
needs.

| Part | What | Default | Production | Tests |
|---|---|---|---|---|
| 0 | DoH reports the real client address instead of a fixed one | always | 15–25 | 30–50 |
| 1 | Resolver: per-client transport counters, with API and CLI | **off** | 350–550 | 350–550 |
| 2 | Parent: delegation-sync log, with API and CLI | **on** | 300–450 | 300–480 |

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

**The fix.**
- Carry the `http.Request`'s `RemoteAddr` into `dohResponseWriter`, as a
  `*net.TCPAddr`, and the listener's address as `LocalAddr`.
- Keep `dummyAddr` only for an address that cannot be parsed.
- Test: a DoH request's handler sees the client's address. A NOTIFY over DoH
  from a non-loopback address is refused by an `allow-notify` that lists only
  127.0.0.1.

---

## 1. Resolver: per-client transport counters

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
  last-seen times, first seen.
- **A cap on clients** (`max-clients`, default 4096), with eviction of the
  least recently seen, through an LRU list, O(1).
- **Evicted clients' counts** are added to an "evicted" aggregate, never lost
  from the totals.
- **Reset** clears the map and the aggregate, and records the reset time.
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

### API

A new command on the resolver's API, `imr-client-stats`, next to the existing
`imr-transport-stats` (v2/apihandler_imr.go:458).

| Request field | Meaning |
|---|---|
| `clients` | addresses or prefixes; empty means all |
| `reset` | clear the counters after reading them |

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
  new period.

### Tests

- **Store:** counts, last-seen, prefix filtering, reset, eviction at the cap
  (with the aggregate), and concurrent recording under `-race`.
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

**Not in scope:** the same wrapper for tdns-auth's own listeners (v2/do53.go:284–298)
would take one call site each, when someone needs it.

---

## 2. Parent: delegation-sync log

### What it records

One event per thing that happens to a child's delegation at the parent:
- **the time, the parent and the child;**
- **the mechanism:** UPDATE, NOTIFY(CDS), NOTIFY(CSYNC), scan(CDS),
  scan(CSYNC) (a poll), or API;
- **the outcome:** applied, no change, not processed, or refused;
- **the details:**
  - adds and removes by type: DS, NS, glue;
  - glue that was skipped;
  - the rcode and EDE of a refusal;
  - the reason text, for example "child nameservers not in sync for SOA".

That reason is what the parent logs today at Info, and nothing more.

### Where it hooks in

All four places already hold the information. Each gets one call.

| Place | Covers | Information there |
|---|---|---|
| `scanChildAndApply` (v2/scanner_apply.go:~60–118), right after `logScanResult` | scans started by a poll (`poll != nil`) and by a NOTIFY (`poll == nil`), for CDS and for CSYNC | `ScanTupleResponse`: adds and removes, `Error`/`ErrorMsg`, `ValidationReason`, `GlueSkipped` |
| `UpdateResponder` (v2/updateresponder.go:126–~410), where the final rcode for a CHILD-UPDATE is set | UPDATE from a child | rcode, `RejectionEDE` (e.g. from `ApproveChildUpdate`, :619–:800), the update's counts |
| `DsyncApiPostDelegation` (v2/dsync_api_delegation.go) | the DSYNC API scheme | the result it returns |
| The parent's NOTIFY(CDS/CSYNC) handling, where a NOTIFY is dropped before a scan starts (optional) | NOTIFYs that never became a scan | the drop reason |

### Gate and memory

- **Config:** the childsync block (`ChildSyncConf`,
  v2/config_delegationsync.go:149): `sync-log: 10000`, the number of events
  kept.
- **Default 10000, so it is on.** 0 disables it: the recorder is then nil, and
  each hook is `if l := syncLog(); l != nil { l.Add(ev) }`.
- **The events are rare** (per change, scan or UPDATE), so the cost is
  negligible either way.
- **Memory** is one ring for the whole server, never a store per child.
  10,000 small events is a few MB at most.

### API and CLI

- **API:** a `sync-log` command on the existing `/delegation` endpoint
  (v2/apirouters.go:113, `APIdelegation`), with filters `child`, `since` and
  `limit`, newest first.
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

- **Ring:** order, bound, filters, concurrent `Add` under `-race`.
- **Each hook:** one test per mechanism, using the existing scanner, UPDATE and
  DSYNC API test harnesses (`dsync_api_delegation_test.go`, the `scanner_*`
  tests). An applied change and a refusal each produce the event expected.
- **Off (`sync-log: 0`):** the hooks record nothing and do not panic.
- **API and CLI:** a round trip, and formatting.

### Size

| Piece | Production | Tests |
|---|---|---|
| Event type and ring, query with filters | 80–120 | 80–120 |
| Four hooks, mapping each path's result to an event | 70–110 | 150–250 |
| Config | 15–25 | – |
| API command | 40–70 | 40–60 |
| CLI command | 90–140 | 30–50 |
| **Total** | **≈ 300–450** | **≈ 300–480** |

---

## Not in scope

- **A per-child history that survives a restart.** The ring is in memory by
  design.
- **Exporting either as metrics** (Prometheus or similar). The shapes allow it
  later.
- **Rate limiting of NOTIFY**, which is a separate open issue.
