# tdns-debug

**A developer framework for structured, aggressive correctness testing
of a running tdns server** (or, for the pure-DNS parts, any
authoritative implementation). It is **not** an end-user or operator
tool: it mutates a zone at high rate, transfers and queries it under
concurrent load, and is meant to be pointed at a throwaway zone on a
server you are actively developing or regression-testing.

tdns-debug drives a target with configurable barrages of operations
while concurrently observing what the server serves, and checks every
observation against a model (a *ledger*) of what a correct server must
do. When an observation cannot be explained by any correct server
state, it reports a violation.

For the concepts, the invariants, a worked example (catching a real
tearing bug and confirming its fix), and how to add test families, see
the guide: [Structured Aggressive Testing with tdns-debug](../../guide/testing.md).

## Architecture

Independent **actors** (update-sender, AXFR poller, query hammer) run
on their own cadences and feed observations into a shared **ledger**
(the oracle: the set of correct served states) that **checkers**
consult. Every tdns-mgmt-API actor is optional — an absent capability
is reported as SKIPPED, never as a failure — which is what lets the
same tool run against a tdns branch, a tdns release, and BIND/NSD/Knot.

**This is a framework and it is expected to grow.** Today it ships the
`test churn` family; more (`test ddns`, recursive-resolver and
DNSSEC-validation families, differential A/B, agent flows) are planned
as additional compositions on the same engine.

## Commands

- **`tdns-debug probe --target <name> [--dns <addr:port>]`**
  Probe a target's capabilities (mgmt-API endpoints + command-level
  support for the optional actors, plus plain-DNS reachability),
  side-effect-free. Prints the capability matrix that would gate a run.

- **`tdns-debug test churn ...`** — the zone-snapshot correctness test.
  - `--generate-config --base-zone <zone>` provisions only: allocates a
    test identity, generates the SIG(0) keypair locally, and emits the
    zone file + config snippet + operator to-do (no server is touched).
  - `--test <id> --dns <addr:port>` runs it. Knobs: `--qps`,
    `--updatecadence`, `--axfrcadence`, `--duration`, `--delta`,
    `--seed`, `--json`.

- **`tdns-debug test policy-reload ...`** — the DNSSEC policy-reload
  no-re-sign/backfill test (A2). Proves that when the server first binds a
  signed, config-only zone with no applied-policy record it backfills
  `applied = intent` **without** re-signing the already-correct zone (the
  failure mode is a thundering-herd re-sign of every zone at startup). A
  re-sign is inferred from RRSIG inception — a re-sign stamps a fresh
  inception, a backfill leaves it untouched — so the tool snapshots the apex
  SOA and DNSKEY RRSIG inceptions per keytag before and after the trigger and
  flags any zone whose inception advanced.
  - `--phase before` snapshots and exits; restart the daemon; `--phase after`
    snapshots again and emits the verdict (the primary, restart-triggered mode).
  - `--reload` drives one `config reload` between the two snapshots in a single
    invocation (secondary mode; needs the mgmt API).
  - Zone set is enumerated from the mgmt API (signed zones) or given with
    `--zones a,b,c | @file`. Applied-policy readback (`applied_*` from the
    scoped `list-zones`, #301) and the reload drive are optional capabilities —
    an absent one is SKIPPED, which also lets the inception-only check run
    differentially against BIND/NSD. Knobs: `--tolerance` (coincidental
    background-resigner ticks), `--snapshot`, `--ready-timeout`, `--json`.

- **`tdns-debug list-tests`** — list known test identities and their
  stage history from the state file.

- **`tdns-debug cleanup --test <id> [--rm]`** — clean up a test's
  artifacts and print the operator's server-side removal list.

## Configuration and state

Reads the **same YAML config as `tdns-cli`** (`--config`, default
`/etc/tdns/tdns-cli.yaml`) — no new config format. On-disk state lives
under `--configdir` (default `/tmp/tdns-debug`): a `state.yaml` index
plus a per-test `<id>/` directory of artifacts (zone file, config
snippet, SIG(0) keypair).

## Build

```
make            # regenerates version.go, builds ./tdns-debug
```

Pure client: no C-backed algorithms are selected (no `algs.list`);
SIG(0) signing uses the standard algorithms miekg/dns provides
natively. Never linked into a production binary.
