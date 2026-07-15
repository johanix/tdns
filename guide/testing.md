# Structured Aggressive Testing with tdns-debug

**tdns-debug is a developer tool, not an operator tool.** It is a
framework for *structured, aggressive, correctness testing* of a
running tdns server (or, where the test uses only standard DNS, any
authoritative implementation). It drives a target with configurable
barrages of operations while concurrently observing what the server
serves, and checks every observation against a model of what a correct
server *must* do. When an observation cannot be explained by any
correct server state, tdns-debug reports a violation.

It is deliberately not packaged for end users: it mutates a zone at
high rate, transfers and queries it under load, and is meant to be
pointed at a throwaway zone on a server you are actively developing or
regression-testing. Think of it as a load-bearing companion to the Go
unit tests — the unit tests prove a checker's *logic* in isolation;
tdns-debug proves the *running server* behaves, end to end, on the
hot path, under concurrency.

**It is a framework, and it is expected to grow.** Today it ships one
test family (`test churn`, below). The architecture — independent
*actors* feeding a shared *ledger* (the oracle) that *checkers*
consult — is built so new test families (high-rate dynamic updates,
recursive-resolver response correctness, DNSSEC-validation verdicts,
agent delegation-sync flows, primary/secondary convergence, A/B
differential testing) slot in as new compositions rather than
rewrites. New test commands are expected to be added over time.

## Why a separate tool

A correctness test like this is easy to *drive* and hard to *judge*.
The hard part is the bookkeeping: knowing exactly what the zone should
contain at every serial, and correlating three concurrent observation
streams — dynamic-update responses, zone transfers, and queries —
against that expectation. That is miserable in a shell script and
natural in Go, which is why tdns-debug exists as its own binary rather
than a wrapper around `tdns-cli` + `dig`.

## Architecture: actors, ledger, checkers

- **Actors** run on independent cadences, each a small goroutine:
  an update-sender (SIG(0)-signed RFC 2136), an AXFR poller, and a
  concurrent query hammer. (Future families add bump/resign/txlog
  actors.)
- **The ledger** is the oracle. It records every operation the tool
  sent, in acceptance order, and from that derives the set of *correct*
  served states: a served zone must equal the working set after some
  **prefix** of the accepted operation log. Content that matches no
  prefix is torn or mixed.
- **Checkers** consume the observation streams and evaluate a set of
  invariants (below), reporting any violation with full context —
  the observation, the ledger state(s) it was compared against,
  serials, and timestamps.

Every tdns-mgmt-API actor is *optional*: if the target lacks a
capability (older tdns, a non-tdns implementation, the API not
configured), tdns-debug disables that actor and the checks that need
it — reporting them as SKIPPED, never as a failure. That is what lets
the same tool run against a tdns branch, a tdns release, and BIND/NSD/
Knot alike.

## The `test churn` family

`test churn` is the zone-snapshot correctness test. It applies a slow,
steady barrage of dynamic updates (add/delete of uniquely-named TXT
records under a `_churn` label) while continuously transferring and
querying the zone, and checks that the server never serves torn
content — that every reader always sees a single, consistent zone
state, and that the SOA serial uniquely identifies the content served.

### Invariants checked

| # | Invariant | Bug class it catches |
|---|---|---|
| **I2** | No accepted update is visible before a publish boundary follows it | a write leaking past the atomic-publish boundary |
| **I3** | No permanently lost updates (end-of-run reconcile) | dropped/partial application |
| **I5** | Served serial is monotonic (RFC 1982, wrap-safe) | serial regression / snapshot rollback |
| **I6** | Same serial ⇒ same content | **tearing**: two reads at one serial disagree |
| **I7** | Every AXFR is self-consistent (open SOA == close SOA) | torn transfer |
| **I9** | Every observation is a single consistent prefix state | intra-response tearing / mixed content |

The checkers are engineered to be *false-positive-free*: a correct
server trips nothing. The tool ignores server-generated noise
(RRSIGs from online signing, apex records it did not create) and
compares only the ledger-owned `_churn` subtree plus the SOA serial.

### Sampling density matters

Tearing is a race, and catching it requires sampling densely relative
to how fast the server changes serials. A server that bumps the serial
on every update (~1–2/s) needs an AXFR poll *faster* than that, so that
multiple transfers land on the *same* serial and I6 has two reads to
compare. The default `--axfrcadence` is conservative; for aggressive
tearing hunts, drive it down (see the example).

## Setup and lifecycle

tdns-debug reads the **same YAML config as `tdns-cli`** (API base URL,
auth, TLS) — no new config format. On-disk state lives under
`--configdir` (default `/tmp/tdns-debug`): a `state.yaml` index and a
per-test `<id>/` directory of artifacts.

A test has an identity and three stages: **provision → run → cleanup**.

```
# 1. Probe what the target supports (side-effect-free)
tdns-debug probe --target tdns-auth --dns 127.0.0.1:5354

# 2. Provision: allocate a test identity, generate the SIG(0) keypair
#    locally, and emit a zone file + config snippet for the operator.
tdns-debug test churn --generate-config --base-zone test.axfr.net.

# 3. Install the emitted zone + config on the server, trust the key
#    (see the emitted operator to-do), reload/restart, then run:
tdns-debug test churn --test test001 --dns 127.0.0.1:5354 --qps 50 --duration 2m

# 4. Housekeeping
tdns-debug list-tests
tdns-debug cleanup --test test001 --rm
```

The generated SIG(0) key is named `_churn.<id>.<base-zone>` so that a
`selfsub` update policy grants it authority over exactly the churn
subtree (`<seq>._churn.<id>.<base-zone>`) and nothing else. The churn
zone needs `options: [ allow-updates ]`, an `updatepolicy` trusting
that key for TXT, and AXFR permitted to the tool.

## Worked example: catching (and confirming the fix for) a real tearing bug

This is the run that motivated the tool. The zone-snapshot correctness
work on tdns-auth exists to eliminate a class of tearing where the
query/publish paths mutate shared, already-published data — so two
secondaries could transfer *different content under the same SOA
serial*. The question is whether a fix actually closes that hole.

Two builds of `tdns-auth`, same config, an online-signed churn zone,
and **identical** aggressive load:

```
tdns-debug test churn --test test001 --dns 127.0.0.1:5354 \
    --qps 100 --axfrcadence 400ms --updatecadence 500ms --duration 60s
```

**Against the pre-fix build**, the tool reports tearing:

```
== tdns-debug report: churn (test001) zone test001.test.axfr.net. ==
  axfr.count          150
  updates.accepted    119
  query.count         5944
  publish.boundaries  119
result: 10 VIOLATION(S)
VIOLATION [I6] serial 199 served two different contents (tearing/rollback)
  serial=199 stream=axfr ... content={... 5._churn ... 16._churn ...} accepted-ops=20
VIOLATION [I6] serial 207 served two different contents (tearing/rollback)
  ...
```

Two AXFRs at serial 199 returned *different* `_churn` content — the
serial says "same zone", the bytes say otherwise. That is the tearing.

**Against the fixed build, with the same command and load:**

```
== tdns-debug report: churn (test001) zone test001.test.axfr.net. ==
  axfr.count          149
  updates.accepted    119
  query.count         5944
  publish.boundaries  119
result: OK — all evaluated invariants held
```

Same 119 updates, ~150 transfers, ~6000 queries, 119 publish
boundaries — and not a single inconsistency. The buggy build tears
under the exact load the fixed build sails through. That A/B pair is
the evidence: the tool catches the real defect, and the fix provably
closes it.

Note the earlier caveat the example bakes in: an *unsigned* churn zone
did **not** tear on the buggy build, because this defect lives on the
query-path re-sign that only runs with online signing. Choosing the
right stimulus (a signed zone) and sampling densely enough (`400ms`
AXFR) are both part of designing a test that can actually observe the
bug it is hunting.

## Interpreting results

- Exit code `0` — every evaluated invariant held (any SKIPPED checks
  are listed; a capability-limited-but-clean run still exits 0, with
  the skip list printed, so a green run against a limited target is
  never mistaken for full coverage).
- Exit code `1` — at least one violation; each is printed with the
  observation and the ledger state it contradicts.
- Exit code `2` — setup error (bad config, unreachable target, the
  zone/policy refusing the very first operation).
- `--json` emits a machine-readable report (capability matrix, stats,
  skips, violations) for CI.

## Adding a test family

New test families reuse the actor/ledger/checker framework in
`v2/debug/`. A family is a thin composition: define its actors and
their cadences, feed their observations into a ledger (the oracle for
that family), and write checkers that consult it. The design intent is
that broadening coverage means *adding* a command, not reworking the
engine.
