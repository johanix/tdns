# Recorded runs

## 2026-09-29: stage 1, clock-free set

- **tdns-imr:** main at `a62d9585`, a classical-only static Linux build (no
  `algs.list`).
- **Deckard:** `e51f539`.
- **Host:** Debian 12, Linux 6.1, 2 vCPU, 2 GiB.
- **Set:** `SET=clock-free`, 40 scenarios. Each runs twice, with and without
  QNAME minimisation, unless it pins the setting.

**Unmodified tdns-imr: every scenario fails at start-up.**
- Deckard starts the resolver, waits up to 5 s for TCP on port 53, and starts
  the scenario's servers only after that.
- tdns-imr primes before it opens its listeners. With no server to answer,
  the priming query goes out of Deckard's black-hole default route: its
  source is `169.254.1.2`, and it gets no reply.
- tdns-imr retries after 5 s, by which time Deckard has given up
  (`server does not accept connections on TCP port 53`).

**With the priming switch** (S4 in the design, now #828:
`imrengine.testing.priming: false` seeds the cache from the hints through
`PrimeFromHintsOnly`): 59 runs passed, 17 failed and 4 were skipped, in 62 s.
That is 31 of the 40 scenarios passing. This run used the same change,
uncommitted.

The 9 that fail do so the same way every time:

| Scenario | Step | Expected | tdns-imr |
|---|---|---|---|
| `iter_cname_nx.rpl` | 10 | NXDOMAIN | SERVFAIL |
| `iter_cycle.rpl` | 20 | SERVFAIL | no answer within Deckard's 5 s (timeout) |
| `iter_donotq127.rpl` | 10 | SERVFAIL | no answer within 5 s (timeout) |
| `iter_lame_noaa.rpl` | 200 | NOERROR | SERVFAIL |
| `iter_lame_nosoa.rpl` | 20 | NOERROR | SERVFAIL |
| `iter_ns_badglue.rpl` | 10 | NOERROR | SERVFAIL |
| `iter_pcnamech.rpl` | 71 | NOERROR | SERVFAIL |
| `iter_req_qname.rpl` | 10 | SERVFAIL | NOERROR |
| `iter_unexpectedrrtype.rpl` | 2 | NOERROR | SERVFAIL |

**What did not happen.** No failure came from an unscripted query or from a
header flag under `MATCH all`, the two classes the design expected. Every
failure is an answer tdns-imr got wrong, or took too long to give. Each needs
a look at its scenario before it becomes an issue or a skip-list line.

### What the 9 failures are

Each scenario was re-run alone, with the resolver's `engine` and `dns`
subsystems at debug level, and its scenario, log and capture were read against
the code.

| Scenario | Cause | Outcome |
|---|---|---|
| `iter_lame_noaa`, `iter_lame_nosoa`, `iter_ns_badglue` | a lame server's NS RRset for the zone being queried is taken as a referral, and the loop check aborts the lookup | #829 |
| `iter_pcnamech` | an authoritative NODATA carrying only the apex NS RRset: the same misreading, and no path for a NODATA without an SOA | #829, #830 |
| `iter_cname_nx` | an NXDOMAIN without an SOA is not accepted as a negative answer | #830 |
| `iter_donotq127` | loopback nameserver addresses from glue are queried | #831 |
| `iter_unexpectedrrtype` | the reply answers only another type. tdns-imr rejects it and tries other servers; the scenario expects Unbound's scrubbing to NODATA. A defensible difference | `skip.txt` |
| `iter_cycle`, `iter_req_qname` | analysed | follow-up pending |

