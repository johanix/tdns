# IXFR interop rig — tdns vs BIND9

Incremental zone transfer (RFC 1995) in **both directions and in cascade**. A
zone transfer that mutates the zone it carries is about as bad as a nameserver
bug gets: the damage is silent, it persists, and it propagates to anything
downstream. This rig exists to make that failure loud.

The oracle is the whole zone. After a long series of updates, every server in a
chain must hold **byte-for-byte the same zone**, at the same SOA serial, with
the same ZONEMD — and must have got there **incrementally**, not by quietly
falling back to AXFR.

## Running

```
./setup.sh
./run.sh start
./run.sh churn      # ROUNDS=24 updates per scenario, ~2 min
./run.sh verify     # 20 assertions; non-zero exit on failure
./run.sh stop
```

`./run.sh full` does start + churn + verify. `ROUNDS=n` changes the series
length. Requires `tdns-auth` and `tdns-cli` from `cmdv2/`, plus `named`,
`nsupdate` and `dig` (`NAMED=`, `NSUPDATE=`, `DIG=` override the paths).

| Daemon | Port | Role |
|---|---|---|
| tdns-auth | 5321 | primary for `a`, `c`, `casc` |
| tdns-auth | 5322 | secondary for `a`, `b`, `casc`; also serves `casc` onward |
| named | 5323 | primary for `b`; secondary for `c` and `casc` |

## The four scenarios

| Zone | Chain | What only this can catch |
|---|---|---|
| `a` | tdns → tdns | accumulation over a long chain of our own deltas |
| `b` | **BIND** → tdns | our INBOUND parse/apply against a foreign emitter |
| `c` | tdns → **BIND** | our OUTBOUND deltas, read by a foreign consumer |
| `casc` | tdns → tdns → **BIND** | deltas this implementation **relayed** rather than originated |

`a` alone is not enough, and that is the point of the other three: a matched
pair of bugs in our own inbound and outbound would cancel out and `a` would
still pass. `b` and `c` each put a foreign implementation on one side of the
wire. `casc` is the sharpest: since §5 of the inbound-IXFR plan, a tdns
secondary re-serves the deltas it received instead of resetting its chain, so a
bug there ships corruption to a third party rather than to itself.

## Why the primaries are driven the way they are

**tdns primary: management API, not the zone file.** A file rewrite goes
through `applyRefreshReplacementLocked`, which resets the outbound IXFR chain
by design — a wholesale replacement has no meaningful delta. A rig that churned
the zone file would therefore serve nothing but AXFR and pass every
whole-zone comparison while testing none of this code.

**BIND primary: `nsupdate`, not a file rewrite plus reload.** Dynamic update
gives BIND a journal, which is what lets it answer IXFR at all, and produces
exactly one delta per change rather than whatever `ixfr-from-differences` would
infer from a rewritten file.

## What the assertions actually check

**Section 0 comes first for a reason.** Every other assertion compares two
servers and passes when they agree, so if the comparison cannot report a
difference then every PASS below it is worthless. Section 0 proves the oracle
discriminates before anything relies on it.

**Zones are compared canonically, not as wire bytes.** RR order within an AXFR
is not guaranteed to match across implementations or even across runs, so
comparing the raw stream would report differences that are not differences.
`axfr_canon` sorts.

**ZONEMD is the strongest single check**, being a digest over the whole
canonicalised zone — but only where the primary is tdns, since BIND 9.20 has no
ZONEMD at all. It is meaningful here only because the secondary is a faithful
mirror: no signing options, `publish-zonemd` **off**, so the primary's digest is
transferred verbatim rather than recomputed. A secondary that recomputed it
would be testing our digest arithmetic instead of the transfer.

**The incremental counts are the assertion the rig turns on.** Every scenario
converges just as well over AXFR — the fallback is deliberate and works — so
without counting, a completely broken delta path shows nothing but green. The
tdns-side count is of difference **sequences**, not transfers: when the
secondary polls less often than the primary changes, one response carries
several sequences covering every serial step since it last asked. Counting
transfers would understate that, and the multi-sequence path is the one a
single-step test never reaches. Observed 2026-08-29: BIND delivered 24 sequences
across 12 transfers, so eleven of them were multi-step.

## Observed 2026-08-29

BIND 9.20.20, `ROUNDS=24`. All 20 assertions hold. Every scenario transferred
all 24 updates incrementally, and the cascade's BIND edge accepted 24
incremental transfers of deltas that tdns had relayed rather than originated.
