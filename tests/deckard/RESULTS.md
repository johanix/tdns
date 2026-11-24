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


## 2026-11-17: QNAME minimisation, the switch wired

- **tdns-imr:** `feature/imr-qname-minimisation`. Before: `d74bc374`, with
  the switch added to the template by hand. After: `393f220b`, which has the
  loop fix and the switch. The commits after it change tests and docs only.
  Both are classical-only static Linux builds (no `algs.list`).
- **Deckard:** `e51f539`. **Host:** as above.
- **Set:** `SET=all`, 171 scenarios. The switch is the template's `QMIN`
  mapping (design `docs/2026-10-22-imr-qname-minimisation.md` §11). In this
  set, 78 scenarios do not pin it and run twice, once with minimisation
  and once without. Before the switch, those two runs were the same.

| | Before | After |
|---|---|---|
| Runs failed / passed / skipped | 55 / 196 / 91 | 57 / 194 / 91 |
| Scenarios failing only with minimisation on | 10 | 11, of which 2 are flakes |

**`world_cz_rhybar`.** Before: a timeout in 3 runs of 3 with minimisation
on, and a pass with it off. Validating a child-signed negative answer from
the parent's servers re-queried without bound. After: it passes in 7 of 8
runs on its own. The other run, and its run in the full set, failed on
Deckard's own `OSError: [Errno 99] Cannot assign requested address` while
binding an IPv6 address, a known flake of the `world_cz_*` scenarios.

**Flakes.** `iter_timeouted_ns` (minimisation on) and
`val_minimal_baddnskeyflags` (off) failed once each in the full set, and
passed in 3 of 3 and 2 of 2 reruns.

**Nine scenarios fail only with minimisation on, before and after.** In
each one, Deckard has no answer for a probe of type `A`:

| Scenario | Client query | Unscripted probe | The scenario scripts that name for |
|---|---|---|---|
| `iter_ns_badglue.rpl` | `www.foo.com. A` | `foo.com. A` | `NS` |
| `val_cname_new_signer.rpl` | `www.example.com. A` | `sub.example.com. A` | `NS`, `DS`, `DNSKEY` |
| `val_nsec3_nods_badsig.rpl` | `www.sub.example.com. A` | `sub.example.com. A` | `NS`, `DS`, `DNSKEY` |
| `world_cz_turris_api.rpl` | `api.turris.cz. AAAA` | `turris.cz. A` | `NS`, `DS`, `DNSKEY` |
| `world_cz_vutbr_www.rpl` | `www.vutbr.cz. A` | `ro.vutbr.cz. A` | `NS`, `DS`, `DNSKEY` |
| `val_deleg_nons.rpl` | `foo.www.example.com. A` | `www.example.com. A` | `DS` |
| `val_nsec3_b2_nodata.rpl` | `ns1.example. MX` | `ns1.example. A` | `MX` |
| `val_nsec3_b3_optout_noce.rpl` | `mc.c.example. MX` | `mc.c.example. A` | `MX` |
| `val_nsec3_b3_optout_nonc.rpl` | `mc.c.example. MX` | `mc.c.example. A` | `MX` |

- The first six probe an intermediate name. The scenarios script that name
  only for the types Knot Resolver asks for: `NS` for its probes, and `DS`
  and `DNSKEY` for validation. The scripts do not cover an `A` probe.
- The last three probe the full name. tdns-imr sends the full name as `A`
  before the original type to servers that are not known to hold the name
  (design §2, "Original QTYPE"). The scenarios script only the original
  type.

**The five scenarios that pin the switch on** stay in `skip.txt`. Run one
at a time, with `allow-loopback-nameservers` added (the `iter_minim_*`
scenarios put the root on `127.0.0.10`), they fail before and after the
same way:

| Scenario | Step | Expected | tdns-imr | Unscripted |
|---|---|---|---|---|
| `iter_minim_a.rpl` | 10 | NOERROR | SERVFAIL | `com. A`, then the original `www.example.com. A` |
| `iter_minim_a_nxdomain.rpl` | 10 | NOERROR | SERVFAIL | `com. A`, then `sub.www.example.com. A` |
| `iter_minim_nonempty.rpl` | 10 | NOERROR | SERVFAIL | `com. A`, then `www.example.com. NS` |
| `iter_minim_ns.rpl` | 10 | `NS blackhole.` | empty answer | `com. A`, then `www.example.com. NS` |
| `val_ta_sentinel_insecure.rpl` | 112 | NOERROR | SERVFAIL | `unsigned. A` |

The first probe has no script, and Deckard answers SERVFAIL. When no
server completes a probe, tdns-imr sends the original query to the same
servers (design §4). That query has no script either.
