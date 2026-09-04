# Do53 UDP Performance: Where tdns-auth's Query Throughput Goes

Measured 2026-08-29. All numbers are from real `tdns-auth` serving a real
zone, not microbenchmarks, unless explicitly labelled otherwise.

## Summary

1. **A single UDP socket is a hard throughput ceiling.** miekg/dns serves each
   socket from one goroutine (`serveUDP` does one `ReadUDP` at a time), so
   packet *reception* is serialised per socket even though handlers run
   concurrently. On Linux that ceiling is ~180k qps; on NetBSD ~50k.

2. **Several `SO_REUSEPORT` sockets lift it — on Linux.** `udp-sockets: 4`
   took tdns-auth from 180k to 280k qps (+48%) and roughly doubled CPU
   utilisation. On NetBSD it changes nothing, because NetBSD does not
   distribute across such sockets (see the platform matrix below).

3. **tdns-auth then hits a second ceiling at ~280k qps / ~7 cores**, flat at
   4, 8 and 16 sockets. This is not the load generator: the same harness
   drove NSD to 815k on the same box.

4. **NSD, BIND and Knot all reach 660k-815k** on the identical test. tdns-auth
   is at roughly 40% of that. All three use one socket per worker with
   `SO_REUSEPORT`; the architecture `udp-sockets` adds is the right one.

5. **A CPU profile puts ~40% of tdns-auth's time in Go runtime overhead** —
   goroutine stack growth, allocation, GC and scheduling — against 17.6% in
   the recvfrom/sendto syscalls. Very little is DNS logic.

## Method

Everything below uses the same inputs, so numbers are comparable across
platforms and across servers:

- **Zone**: generated with `tdns-zonegen bigzone --count 100000 --unsigned
  --types A,AAAA,MX,TXT --max-labels 2`, giving **137,381 records** in an
  8.3 MB zone file, zone `perftest.example`. Unsigned, so no signing cost is
  in the measurement.
- **Queries**: the 34,426 distinct owner names carrying an A RR, extracted
  from the generated zone. Every query gets a real answer — a load test that
  returns NXDOMAIN measures the denial path instead.
- **Generator**: `dnsperf -c 48 -T 4 -l 20 -q 400` over loopback.
- **Verification**: every result quoted here was 100% NOERROR unless stated.

Hardware (kept generic; these were lab machines):

| label | description |
|---|---|
| L16 | 16-core Linux/Xen dom0, x86-64 |
| N12 | 12-vCPU NetBSD 10.1/Xen dom0, idle |
| N8 | 8-vCPU NetBSD 10.1 PV domU |

### Reproducing

```
tdns-zonegen bigzone --zone perftest.example. --count 100000 --unsigned \
    --types A,AAAA,MX,TXT --max-labels 2 --outfile perftest.example.zone
awk '$4=="A" {print $1}' perftest.example.zone | sed 's/\.$//' | sort -u \
    | awk '{print $1" A"}' > queries.txt
dnsperf -s 127.0.0.1 -p <port> -d queries.txt -c 48 -T 4 -l 20 -q 400
```

Measure server CPU by CPU-*time* delta (`ps -o time=` sampled over a fixed
interval), not `%CPU`, which is an average since process start and misleads
badly on a freshly started server. Under Xen, `xl vcpu-list <dom>` deltas give
the same answer from the hypervisor's side.

**Interleave A/B runs.** Sequential "all of A, then all of B" measurements on
these machines drifted by ~2% between sessions, which is the same order as the
effects being chased. Two conclusions in this work were initially wrong for
exactly that reason (see Negative Results).

## Results

### Socket scaling (L16, real tdns-auth)

| `udp-sockets` | qps | server CPU (of 16 cores) |
|---|---|---|
| 1 | 180,371 | ~349% (3.5 cores) |
| 2 | ~277,500 | |
| 4 | 267,566 | ~630% (6.3 cores) |
| 8 | 280,975 | ~699% |
| 16 | 280,322 | ~700% |

The jump happens at 2 sockets and is complete by 4. Beyond that it is flat
while 9 of 16 cores stay idle, so something other than the socket is the
limit past ~280k.

At 1 socket the server also produced **SERVFAILs under load** (0.12% in one
run) — the single receive queue overflowing. Every multi-socket run was 100%
NOERROR.

### Platform matrix: does `SO_REUSEPORT` distribute inbound UDP?

Tested directly: N sockets bound to one address with `SO_REUSEPORT`, datagrams
sent from 200 distinct source ports (a single source port always hashes to one
socket on Linux and proves nothing).

| OS | duplicate bind | distributes across sockets |
|---|---|---|
| Linux 6.1 | yes | **yes** (4-tuple hash; even split, no loss) |
| NetBSD 10.1 | yes | no — one socket received everything |
| macOS 26.3 | yes | no — one socket received everything |

Linux is the outlier. On NetBSD the single receiving socket also *dropped 46%*
of the offered datagrams, while Linux's four sockets lost none.

Consequence: on NetBSD and macOS, `udp-sockets: N` is a harmless no-op. To get
more than one receive queue there, use several **listen addresses** — tdns
already creates one socket per address, so N addresses gives N sockets. That
was measured at ~2.9x on NetBSD (27k to 78k over a network path).

### NetBSD vs Linux, same code

| | qps | CPU |
|---|---|---|
| N12 (NetBSD dom0, idle) | 50,438 | 285% |
| N8 (NetBSD PV domU) | 39,265 | ~240% |
| L16 (Linux dom0) | 180,371 | 349% |

~3.6x, with confounds controlled: not the generator (NetBSD gets *slower* with
more dnsperf threads: 43.9k / 40.9k / 37.9k at -T 2/4/8), not memory pressure,
not host load, and not domU-vs-dom0. Both platforms plateau using under 3.5
cores, so neither is CPU-starved — it is per-packet cost in the kernel UDP
path.

A separate loopback measurement of a ~90-line miekg/dns responder with a
hardcoded answer (no zone lookup at all) gave ~150k qps on Linux versus
~57k on NetBSD, i.e. the same ~2.6x gap with tdns removed from the picture.

### Comparison with other authoritative servers (all on L16)

| server | config | sockets | qps |
|---|---|---|---|
| NSD 4.6.1 | `server-count 16` + `reuseport yes` | 16 | **815,028 / 701,308** |
| BIND 9.18.49 | defaults | 16 | **687,790 / 709,239** |
| Knot 3.2.6 | defaults | 16 | **661,085 / 676,042** |
| tdns-auth | `udp-sockets` 4-16 | 4-16 | ~280,000 |
| tdns-auth | `udp-sockets: 1` | 1 | 180,371 |
| NSD 4.6.1 | defaults (`server-count 1`) | 1 | 202,611 |
| NSD 4.6.1 | `server-count 16`, `reuseport no` | **1** | 56,829 / 62,935 |

Two things worth noting.

**NSD demonstrates this document's thesis by accident.** Sixteen worker
processes sharing one socket run at 57k — *worse than a single worker* — and
that is NSD's default (`reuseport` defaults to no). Turning `reuseport: yes`
on takes the same 16 workers to 815k. A 14x swing from one config line, purely
about how many receive queues exist.

**BIND and Knot ship one socket per thread by default**, 16 each on this box.
The design `udp-sockets` adds to tdns is what the rest of the field already
does.

## Where tdns-auth's CPU actually goes

30s CPU profile at 57k qps sustained, 79.74s of samples:

| | cumulative | share |
|---|---|---|
| `Syscall6` (recvfrom/sendto) | 14.00s | 17.6% |
| `runtime.copystack` (goroutine stack growth) | 13.82s | 17.3% |
| `runtime.mallocgc` | 7.63s | 9.6% |
| `runtime.gcDrain` | 6.21s | 7.8% |
| `runtime.schedule` | 4.13s | 5.2% |

**~40% of CPU is Go runtime overhead**, against 17.6% doing the actual
syscalls. DNS logic proper (`packDomainName` and friends) is a rounding error.

The stack-growth entry is the interesting one. `runtime.newstack` accounts for
19.4%, triggered by `DefaultQueryHandler` (43%), `mapaccess2` (34%) and
`UnpackDomainName` (23%). miekg/dns spawns a **fresh goroutine per packet**
with a 2 KB stack, and the handler chain is eight frames deep:

```
serveUDPPacket -> serveDNS -> ServeMux -> HandlerFunc -> TsigSigningHandler
  -> udpTruncate -> createAuthDnsHandler -> DefaultQueryHandler -> QueryResponder
```

so essentially every query pays for a stack copy. NSD, BIND and Knot all use
long-lived workers, whose stacks are grown once.

Profiling is available via `service.pprof-address`, unset by default:

```
go tool pprof -seconds 30 http://127.0.0.1:6060/debug/pprof/profile
```

**Loopback only, and refused otherwise.** A non-loopback value -- including the
`:6060` from every pprof tutorial, which listens on *every* interface -- is a
config error and the daemon will not start. pprof has no authentication in
front of it and serves goroutine stacks, heap contents and the command line, so
on a nameserver it is a route to private keys and TSIG secrets. Use
`127.0.0.1:6060` or `[::1]:6060`, and forward a port over ssh if you need to
profile a remote host.

## Negative results

These were measured and did **not** help. Recorded so the work is not repeated.

### Several read loops on one shared socket: no effect

Before `SO_REUSEPORT` was understood, `udp-sockets` was first implemented as N
`dns.Server`s sharing a single `PacketConn`, i.e. N goroutines each calling
`ReadUDP` on the same socket. A microbenchmark confirmed the datagrams *do*
spread across the readers. Throughput did not move:

| readers on one socket | 1 | 2 | 4 | 8 |
|---|---|---|---|---|
| qps (NetBSD) | 27,095 | 28,111 | 26,519 | 27,607 |

The serialisation is the socket's receive queue in the kernel, not the
userspace read goroutine. Only *more sockets* helps.

### Lock-free zone snapshot (`RRTypeStore`): no effect

`RRTypeStore` wraps a sharded-`RWMutex` concurrent map whose sharding function
is the rrtype itself, so every A query lands on one shard and takes one mutex.
In isolation this is genuinely bad and gets worse with cores:

| goroutines | ConcurrentMap.Get | plain map read |
|---|---|---|
| 1 | 26 ns/op (38.1 Mops/s) | 12 ns/op (84.7 Mops/s) |
| 4 | 86 ns/op (11.6 Mops/s) | 16 ns/op (64.0 Mops/s) |

Published snapshots are immutable (every mutation goes through `cloneOwner`,
which builds a fresh `OwnerData`), so the lock is unnecessary on the serving
path. This was verified empirically, not just from the comment: instrumenting
every write to a frozen store and running the full test suite found **12
violations, all in test helpers, none in production paths**.

Switching published snapshots to a plain map nevertheless changed nothing:
27.4k vs 27.1k at one socket, 79.7k vs 79.5k at four. At ~10 RRtypes lookups
per query and ~80k qps that is ~800k lookups/s against an 11.6 Mops/s
contended ceiling — about 1% of query cost. The change was dropped.

The *finding* is still worth keeping: if per-query cost ever falls far enough,
this becomes the next ceiling, and sharding on `uint32(qtype)` means the
sharding does nothing useful for query traffic.

### Guarding hot-path `Debug` logging: no effect (slightly negative)

There are ~45 unguarded `Debug` calls on the query path and almost no
`Enabled()` guards in the tree, and a profile showed `convTstring` (string to
`any` boxing) at 16% of allocations — so this looked promising. Wrapping all
45 in `if lg.Enabled(nil, slog.LevelDebug)`:

| | unguarded | guarded |
|---|---|---|
| L16, interleaved, mean of 3 | 281,727 | 275,235 |
| smaller Linux box, interleaved, mean of 3 | 61,716 | 61,797 |

No gain, and slightly *slower* on the faster box. The likely reason: Go's
`slog` checks the level early inside `log()`, and the variadic `args` slice
does not escape when it returns early, so it is stack-allocated and nearly
free. An explicit `Enabled()` call just adds an interface call per site.

An earlier sequential (non-interleaved) A/B suggested +7.4% for this change.
That was measurement drift, not signal.

## Recommendations

1. **Set `udp-sockets` to roughly the core count on Linux.** It is the single
   largest available win (+48%) and costs nothing elsewhere.

2. **On NetBSD and macOS, use several listen addresses instead**, one socket
   each, since `SO_REUSEPORT` will not distribute there.

3. **Attack the goroutine-per-packet model.** ~19% of CPU is stack growth
   because every datagram gets a new 2 KB-stack goroutine that must grow
   through an eight-frame handler chain. A pool of long-lived workers — as
   NSD, BIND and Knot all use — addresses the largest single line in the
   profile. This is a change in the miekg/dns fork, not in tdns proper.

4. **Then reduce per-query allocation** (`newobject` is 59% of allocations;
   malloc plus GC together are 17% of CPU).

5. **Measure, do not infer.** Of the three optimisations in this document that
   looked obviously correct from reading the code, all three measured zero.
   The one large win came from a mechanism nobody had suspected.
