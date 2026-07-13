# tdns-debug — a live churn/correctness test tool

**Date:** 2026-07-13
**Status:** DESIGN — agreed in discussion (rev 2, same day: phased TSIG scope,
multi-app scope, test identity/provisioning); implementation follows on this
branch (`feature/tdns-debug`, off `main`).
**Primary driver:** the live acceptance gate for the zone-mutation
snapshot-correctness branch (`feature/zone-snapshot-correctness`). Its eval
(`2026-07-08-snapshot-corrections-eval.md`) discharged all code defects but left
two merge conditions: human review of the C1/M1 read-path refactor, and **a live
smoke test of query + AXFR under concurrent publish**. This tool is that smoke
test, upgraded from "eyeball it" to machine-checked invariants.

**Long-term mission:** the tdns project's live test/debug instrument — a growing
family of structured test commands covering all tdns applications (tdns-auth
first; tdns-imr and tdns-agent test families planned) plus any standards-
compliant third-party implementation, replacing ad-hoc shell-and-`tdns-cli`
poking with repeatable, verdict-producing runs.

---

## 1. What it is

A new standalone binary **`tdns-debug`** (source: `cmdv2/debug`, library:
`v2/debug`) that drives a *running* DNS server with configurable barrages of
operations while concurrently observing its behavior, and verifies that every
observation is consistent with what a correct server must do.

Two principles shape everything below:

1. **Portability.** The mutation/observation core uses only standard DNS
   (RFC 2136 dynamic update, queries, AXFR/RFC 5936). The tool must therefore be
   usable against *any* authoritative implementation — BIND, NSD, Knot, tdns on
   `main`, tdns on a feature branch — not only a tdns that speaks the current
   mgmt API.
2. **Every tdns-mgmt-API actor is optional.** If an API endpoint or command is
   unavailable (older tdns, foreign implementation, API not configured), the
   tool must **not** give up: it notes the capability as absent, disables the
   actors and checks that need it, and runs everything else. Absent capability
   ⇒ SKIPPED in the report, never FAILED.

## 2. Scope, phasing, and non-goals

Everything below is in scope for the tool; urgency differs. Phases 1–2 are this
implementation push (milestones, §14); later phases are committed direction,
specified when their turn comes.

| Phase | Test family | Blocked on | Notes |
|---|---|---|---|
| **P1** | `test churn` — snapshot-correctness live gate | — | the urgent driver; details §10.1 |
| **P2** | `test ddns` — high-rate update correctness | — | §10.2 |
| **P3** | TSIG wire matrix — XFR/NOTIFY ACL behavior (`downstreams`, `allow-notify`: NOKEY/named-key/wrong-key/BLOCKED, signed NOTIFY both directions, RFC 8945 response signing) | — | server side merged; manual testing exists but a structured matrix is more complete and repeatable |
| **P4** | TSIG authorization for DNS UPDATE | **server-side implementation** (today tdns authorizes updates via SIG(0) only; a TSIG on an update is MAC-verified at transport but ignored for authorization) | tool side is a small delta on `test ddns`: key-known/unknown/wrong matrix × update-policy interaction |
| **P5** | tdns-imr family — response correctness against a tdns-debug-driven auth server (the churn ledger doubles as the recursive oracle); DNSSEC validation verdicts using generated correctly-signed **and deliberately-broken** zones (bad/expired RRSIG, missing DS); later: transport selection driven by auth-side DNS transport signaling (the natural instrument for the transport-redesign Stage C testbed debt) | — (transport part: transport redesign Stage C) | |
| **P6** | tdns-agent family — dsync proxy flows end-to-end (a long-deferred testing project precisely because the setup is complex; §6's provisioning machinery is what makes it tractable) | — | |
| — | `test diff` (A/B differential over a generated corpus), `test replicate` (primary→secondary convergence under churn), lifecycle scenarios (delete-mid-AXFR, reload) | — | unscheduled candidates |

**Non-goals (true ones):**

- **No server-side changes ride along in any phase.** Where a phase needs
  server work (P4), that is a separate project on its own branch; the tool
  phase waits for it.
- **tdns-debug is a CLI tool, not a server.** No daemon mode, no database;
  persistent state is one small YAML file (§6).
- **API-client library consolidation.** tdns-debug becomes the second consumer
  of the mgmt-API client code now scattered through `v2/cli`; aggregating those
  accessors into a designed, documented API library is a recognized future
  project — not this one. tdns-debug reuses existing `v2/cli` helpers where
  practical and accepts some duplication otherwise.
- IXFR (future project C), tdns-mp writers (future B-MP).

## 3. Git/merge strategy

- Branch **off `main`**, not off the snapshot branch, so the tool is usable
  against main-built servers immediately and merges independently.
- The snapshot branch's txlog API client side is implemented **faithfully but in
  tool-local mirror types inside `v2/debug`** — `api_structs.go` (and every
  other file the snapshot branch touches) stays unmodified on this branch, so
  the eventual merge is conflict-free by construction. Mirror decoding is also
  what makes graceful degradation natural: unknown/absent fields decode to
  zero values instead of breaking.
- Post-merge, switching to the canonical types is an optional five-minute
  cleanup; keeping the mirrors is equally defensible (a debug tool that
  tolerates version skew against its target is a feature).

Server-side txlog surface being mirrored (from `feature/zone-snapshot-correctness`):
`POST /api/v1/debug` with `Command: "zone-txlog"` → `DebugResponse.ZoneTxlog
*PendingChangesView{PublishedSerial, PublishQueued, Added []string,
Replaced/Deleted []PendingOwnerChangeJSON}` (built by `pendingChangesView()`,
`v2/zone_snapshot.go`).

## 4. Configuration and target selection

- Reads the **same YAML config as `tdns-cli`** (API base URL, auth, TLS) — no
  new config format. `--config <file>` selects among testbed instances;
  `--server <addr:port>` / `--api <url>` override individual targets, so one
  invocation can aim the DNS actors and the API actors at the right places in a
  multi-instance testbed.
- SIG(0) key sourcing is two-mode, matching the portability rule:
  `--sig0key <name>` fetches from the tdns keystore via the existing export
  API (`keystore … export` returns the unredacted PEM + KEY RR;
  `PrepareKeyCache` turns them into a signer — note tdns-cli itself never
  wired this: its ddns path is `--keyfile`-only, so tdns-debug is the first
  client-side consumer of the modern path), `--sig0keyfile <path>` reads a
  key file (any target). Tests provisioned via §6 use neither at run time:
  their SIG(0) keypair is generated **locally** and recorded in the state
  file — only the *public* key ever goes to the server (truststore), since
  validation is all the server needs; keystore export is for keys that must
  live server-side anyway (TSIG shared secrets, pre-existing zone keys).
- `--seed <n>` makes randomized op mixes replayable; the seed is always printed
  and included in the report.
- `--configdir <dir>` sets the base directory for all on-disk state (default
  `/tmp/tdns-debug`): the state file lives at `<configdir>/state.yaml` and each
  test's artifacts at `<configdir>/<id>/`. `--state <path>` overrides just the
  state-file location; `--out <dir>` overrides just one test's artifact dir.

## 5. Capability detection

At startup the tool probes the target once and prints a capability matrix; all
subsequent behavior is driven by it.

Two probe levels, because the mgmt API multiplexes:

1. **Endpoint level** — the built-in API walker (`tdns-cli auth daemon api`
   lists `POST /api/v1/zone`, `POST /api/v1/debug`, …). Cheap, but
   insufficient: many commands share one endpoint, distinguished by an inline
   `Command:` field.
2. **Command level** — send the actual command once and classify the response.
   tdns answers unknown multiplexed commands with a structured error
   (`Error: true`, `ErrorMsg: "Unknown zone command: …"` /
   `"Unknown command: …"`), which distinguishes "endpoint exists, command
   unknown" from transport failure and from success. HTTP 404/connection
   refused ⇒ endpoint (or whole API) absent.

Detection outcomes per capability: `available` / `absent` (clean detection) /
`degraded` (available at probe time, started failing mid-run — reported, and
the dependent checks are marked tainted rather than failed). A capability that
is absent never produces a violation; the report lists what was skipped and
why, so a green run against a limited target can't be mistaken for full
coverage (**no silent scope shrink**).

Baseline capability classes:

| Class | Examples | Needed by |
|---|---|---|
| Pure DNS (always on) | RFC 2136 UPDATE, QUERY, AXFR | update actor, query hammer, AXFR poller |
| tdns mgmt API, zone ops | `zone bump`, `zone resign-zone` | bump/resign actors |
| tdns mgmt API, debug | `debug zone-txlog` | txlog poller, txlog invariants |
| tdns mgmt API, keystore/truststore | key create/export/delete, trusted-key install | automated key provisioning (§6), `--sig0key` |

## 6. Test identity, provisioning, and lifecycle

A test is not one command invocation — it is **provision → run (×N) → cleanup**,
and the stages must correlate. Therefore every provisioned test gets an
**identity** that is woven into every artifact it creates.

### 6.1 Test IDs and naming

- IDs are short and sequential: `test056`, `test057`, … (next ID from the
  state file).
- The test zone is `<id>.<base-zone>` — e.g. `--base-zone test.axfr.net.`
  yields `test057.test.axfr.net.`. The base zone is operator-chosen; the
  invented child zone is disposable **by construction**, which is what makes
  arbitrary mutation safe.
- Keys are named under the test zone, so ownership is self-evident in the
  keystore and cleanup can never sweep up an unrelated key. The SIG(0) key is
  named `_churn.<id>.<base-zone>` — **exactly the label the churn records live
  under** — because tdns's `selfsub` update policy grants a signer authority
  over names *under the signer's own name* (`v2/updateresponder.go`,
  suffix-match): records at `<seq>._churn.<id>.<base-zone>` fall inside the
  grant, and the key can never touch anything outside the churn subtree.
  TSIG keys (later phases): `tsig.<id>.<base-zone>`.
- Exact generated names are recorded in the state file; later stages resolve
  everything from `--test <id>`.

### 6.2 The state file

`<configdir>/state.yaml` (default `/tmp/tdns-debug/state.yaml`; override:
`--state`). One small YAML document: per test ID — creation time, target(s),
zone name, key names and local key-file paths, what was auto-installed via API
vs emitted for the operator, stage history (provisioned / ran / cleaned).
Deliberately **not a database**: a flat file, human-readable and hand-editable,
best-effort locked. Losing it loses bookkeeping convenience, not correctness —
everything it names is also discoverable by its `<id>.` prefix.

### 6.3 `--generate-config`: provisioning without running

`tdns-debug test churn --generate-config --base-zone test.axfr.net. …` does
**not** run the test. It allocates an ID and produces everything the test
needs, split along what today's API can and cannot automate:

- **Automated when the target has the keystore/truststore capability:** the
  SIG(0) keypair is generated, its public key installed as trusted for the test
  zone, TSIG keys (for later phases) inserted into the keystore — all named
  per §6.1 and recorded for cleanup.
- **Emitted as artifacts for the operator (always):** the zone file (including
  SOA/NS boilerplate and the guard marker, §6.5) written under
  `<configdir>/<id>/`, and the exact config snippet to add to the server — a
  zone declaration whose `zonefile:` points **at that emitted file directly**
  (no copy step, nothing to keep consistent by hand), with a correct update
  policy (trusting the test's SIG(0) key for TXT under `_churn`),
  `publish-cadence`, and a `downstreams` entry for the tool's AXFRs. There is
  **no API today for provisioning a primary zone** (the dynamic-zone API
  provisions secondaries), so merging that snippet and reloading is an operator
  step by necessity, not by design. The companion design `2026-07-13-dynamic-primary-zones.md`
  (template-constrained API-provisioned primaries, sequenced after the
  snapshot merge) is exactly the API that graduates this half to automated.
- Later phases reuse the same mechanism with different generators: P5's
  DNSSEC-validation tests emit *signed* zones, including deliberately broken
  variants; P6 emits the multi-party dsync setup that has made agent testing
  painful to stand up by hand.

The provisioning report ends with the operator's to-do list ("add these lines
to `<config>`, place this zone file, reload — then run:
`tdns-debug test churn --test test057`").

### 6.4 `cleanup` and `list-tests`

- `tdns-debug cleanup --test test057` — deletes the test's keys from the
  keystore/truststore via API (where they were auto-installed), removes local
  key files, prints the operator's manual-removal list (zone file, config
  lines), and marks the test cleaned in the state file. Idempotent; tolerates
  a target that has already forgotten the keys.
- `tdns-debug list-tests` — the state file, human-readable: IDs, zones,
  targets, stage history, what's still awaiting cleanup.

### 6.5 Guard rails

Generated zone files include a marker record —
`_tdns-debug.<zone>. TXT "test-id=<id>"` — and the emitted config snippet
carries it too. **Destructive actors refuse to run against a zone that lacks
the marker** unless `--unsafe-zone` is given explicitly. Operator-supplied
zones (plain `--zone`, no provisioning) get the marker line included in the
documented setup snippet, so the normal path stays one flag simpler than the
dangerous one. This is cheap insurance against aiming a mutation barrage at a
production zone via typo.

## 7. Architecture: actors, ledger, checkers

```
                 ┌─────────────┐
   cadence ──▶   │   ACTORS    │ ──── DNS + API traffic ────▶  target server(s)
                 └─────┬───────┘
                       │ ops sent / results          observations
                       ▼                                  │
                 ┌─────────────┐   expected state    ┌────┴───────┐
                 │   LEDGER    │ ◀───────────────────│  POLLERS/  │
                 │  (oracle)   │ ────────────────▶   │  CHECKERS  │
                 └─────────────┘     verdicts        └────────────┘
```

**Actors** run on independent cadences, each a small goroutine with a common
interface (name, capability requirement, cadence, `Step(ctx)`):

- *update-sender* — RFC 2136, SIG(0)-signed; adds/deletes records per the
  scenario's op mix. Pure DNS.
- *bumper* — API `zone bump`. Optional.
- *resigner* — API `zone resign-zone`. Optional.
- *query-hammer* — `--qps N` concurrent readers issuing queries for
  ledger-known names (plus SOA). Pure DNS. This is the actor that catches
  *races*: torn responses only occur with reads in flight at the publish flip;
  the sequential pollers alone would rarely observe one.
- *AXFR-poller* — periodic full transfers. Pure DNS.
- *txlog-poller* — API `debug zone-txlog`. Optional.

**The ledger** is the oracle for the mutation-test families. It records every
op the tool sent (op kind, RR, timestamp, wall-clock + sequence, target
response), and from that derives the *expected zone content* as a function of
"which ops have been published". It tracks each op through a lifecycle:

```
sent → accepted (NOERROR) → visible-in-txlog (*) → published → [deleted …]
                                (*) txlog capability only
```

The oracle concept is per test family, not hard-wired to mutation: P5's imr
tests pair an expected-response/validation-verdict oracle with the same actor
and reporting machinery (and can use a tdns-debug-churned auth server as the
source of truth the recursive answers are checked against).

Records the tool did not create (SOA fields other than serial, apex NS,
RRSIG/NSEC produced by the resigner, …) are outside the ledger and excluded
from content comparison; the checkers compare the *ledger-owned subset* of
observed zone content, plus SOA serial. Signature churn from the resigner is
deliberate noise — it must never confuse the content checks.

**Record shape:** each add creates a TXT record at a unique owner under a
dedicated label — `<seq>._churn.<zone>` — with the payload carrying seq,
timestamp, and seed. Unique owners make add/delete tracking unambiguous,
keep RRset-merge semantics out of scope for `churn` (in scope for `ddns`,
which deliberately exercises add-to-existing-RRset and delete-RRset), and make
end-of-run cleanup a single delete-by-label sweep (`--cleanup`, default on).

**Checkers** consume observation streams (query responses, AXFR bodies, txlog
views) and evaluate the invariants below. Every violation is recorded with
full context: the observation, the ledger state(s) it was compared against,
serials, timestamps, and the actor timeline around the event.

## 8. The invariants

The heart of the tool. Notation: a *publish boundary* is an observed change of
the served SOA serial.

| # | Invariant | Requires | Bug class caught |
|---|---|---|---|
| **I1** | Every accepted update appears in the txlog before the next publish boundary | txlog | txlog omissions; lost staging |
| **I2** | No accepted update is visible in any query/AXFR **before** a publish boundary follows its acceptance | — | write leaking past the snapshot (the core B3 guarantee) |
| **I3** | At a publish boundary, **all** updates accepted before it become visible **atomically**, at exactly one new serial | — | partial batch application; lost updates |
| **I4** | After a publish boundary the txlog reports empty (until new ops arrive) | txlog | txlog not drained |
| **I5** | Served serial is monotonically non-decreasing across all observation streams | — | serial regressions, snapshot rollback |
| **I6** | Any two observations at the same serial show identical ledger-owned content | — | **C1-class tearing**: same serial, different content |
| **I7** | Every AXFR is self-consistent: opening SOA = closing SOA, body consistent with exactly that serial's ledger state | — | **M1-class torn transfers** |
| **I8** | ≤ 1 publish boundary per cadence window under a continuous update barrage; final content = ledger end state | cadence known | broken coalescing; lost updates |
| **I9** | Every individual response is internally consistent with **one** ledger state (never a mix of two) | — | intra-response tearing |

Notes:

- I2 + I3 together are the observable form of the txlog/publish state machine:
  updates accumulate invisibly (accepted, txlog grows, served zone bit-stable
  at a constant serial), then flip *en bloc*. The scenario's cadence split —
  updates much faster than publishes — is what makes both windows long enough
  to observe: with `publish-cadence` ~20s and 1 update/s, each cycle asserts
  ~20 ops invisible-then-atomically-visible.
- The checkers never predict exact serial values — publishes, `bump`, and
  `resign` all move the serial — only monotonicity (I5) and
  content-consistency-per-serial (I6).
- Serial arithmetic is RFC 1982 serial-number arithmetic (wrap-safe).
- Ops in flight *at* a boundary get linearizability treatment: an observation
  during the flip must be fully consistent with either the pre- or the
  post-publish ledger state — one of them, entirely (I9). The exact tolerance
  rule (an op accepted within a small δ of an observed flip may land in
  either batch, but must be present by the *following* flip; everything
  accepted clearly before must be in this one) is specified precisely in the
  checker code and locked by the synthetic-stream unit tests (§9.2) — it is
  checker-internal and changes no interface, invariant list, or CLI surface.
- `publish-cadence` is per-zone tdns config (`publish-cadence:` key, ≥1s,
  default applies when unset). The tool takes `--publishcadence` as an
  optional *hint*: if given, I8's timing bound is asserted; if not, cadence is
  inferred from observed boundaries and I8 degrades to "no lost updates".
- Against a target without the txlog capability, I1/I4 are SKIPPED and the
  rest still run — which is exactly what makes the tool usable against main,
  BIND, NSD, or Knot. (For non-tdns targets, I2/I3/I8 semantics depend on the
  implementation's own publish model; the pure consistency invariants
  I5/I6/I7/I9 are universal.)

## 9. Validation of the tool itself

Two obligations before its verdicts are trusted:

1. **It must be able to fail.** Run `test churn --qps …` against a
   **main-built tdns** first: main has the known, reproducible shared-pointer
   tearing defect this whole project fixes. The checkers (I6/I9, possibly I7)
   are expected to catch it under sufficient concurrent load. A checker that
   cannot detect main's known bug is too weak, and the load shape gets tuned
   until it can. Only then does a green run on the snapshot branch mean
   something.
2. **Unit tests for ledger + checkers** in `v2/debug`, driven by synthetic
   observation streams (including crafted torn observations, lost updates,
   serial regressions) — the checkers' own true/false-positive behavior is
   tested without any server.

## 10. Command surface

### 10.1 `test churn` — the snapshot-correctness gate (build first)

```
# provision (once)
tdns-debug test churn --generate-config --base-zone test.axfr.net.
#   → allocates e.g. test057, emits zone file + config snippet,
#     creates + installs keys where the API allows, records state

# run (repeatable)
tdns-debug test churn --test test057 \
    --updatecadence 1s --bumpcadence 5s --signcadence 15s \
    --qps 50 --duration 2m [--publishcadence 20s] [--seed N] [--report json]

# or against operator-provided infra, no provisioning:
tdns-debug test churn --zone test.example --sig0key churn.test.example ...
```

One update/s (mixed adds + deletes of previously-added records so the zone
doesn't grow monotonically), `zone bump` every 5s and `zone resign-zone` every
15s as secondary stressors *if the API capability is present*, AXFR + txlog
polling in between, `--qps` concurrent readers throughout. All invariants
evaluated continuously; run ends after `--duration` with a stats report.

### 10.2 `test ddns` — high-rate update correctness (second)

```
tdns-debug test ddns --test test058 \
    [--tsigkey <name>] --updatecadence 100ms --duration 2m [--seed N]
```

A 10/s barrage of mixed `add RR` / `delete RR` / `delete RRset` ops —
deliberately including same-owner RRset growth and whole-RRset deletion —
ledger-tracked, with the end-state check: after the final publish, the served
zone contains exactly the ledger's expected content (plus I5/I6/I7/I9
throughout). Keys come from the test's provisioning record (or
`--sig0key`/`--sig0keyfile`). `--tsigkey` signs updates with TSIG for
load-shape realism now, and becomes the P4 authorization matrix once the
server side exists — until then a TSIG confers no authorization (transport
MAC-check only) and SIG(0) remains the authorization mechanism under test.

### 10.3 Lifecycle commands

```
tdns-debug list-tests
tdns-debug cleanup --test test057
```

### 10.4 Later phases (specified when their turn comes)

- **P3 `test xfr-acl` / `test notify`** — the TSIG wire matrix: per-key
  AXFR-serve decisions (NOKEY / named key / wrong key / BLOCKED / no match),
  signed SOA-probe + AXFR from the secondary role, NOTIFY sign/verify both
  directions with RFC 8945 response signing.
- **P4 `test ddns --tsigkey`** gains authorization semantics (blocked on the
  server-side TSIG-update-auth project).
- **P5 `test imr-*`** — recursive response correctness against a churned auth
  server; DNSSEC validation verdicts over generated good/broken signed zones;
  transport-selection assertions (Stage C).
- **P6 `test agent-dsync`** — end-to-end dsync proxy flows over provisioned
  multi-party setups.
- Unscheduled: `test diff`, `test replicate`, lifecycle scenarios.

## 11. Reporting and exit codes

- Human-readable summary by default; `--report json` for CI.
- Stats: ops sent/accepted/rejected per actor; publish boundaries observed;
  latency distributions (accept→txlog-visible, accept→published); observation
  counts per stream; capability matrix; skipped checks and why; violations
  with full context.
- Exit codes: `0` all evaluated invariants held; `1` ≥1 violation; `2` setup
  error (bad config, target unreachable, zone/update policy refuses the very
  first op, guard-rail refusal). A capability-limited but violation-free run
  exits 0 *with* the skip list printed — CI wrappers that require full
  coverage can assert on the JSON capability matrix.

## 12. Package layout and hygiene

```
cmdv2/debug/            main; cobra tree (test churn, test ddns, cleanup, list-tests, …)
v2/debug/
    actor.go            actor interface + scheduler
    actors_dns.go       update-sender, query-hammer, axfr-poller
    actors_api.go       bumper, resigner, txlog-poller (all optional)
    capabilities.go     probe + capability matrix
    ledger.go           op log, lifecycle, expected-content derivation
    checkers.go         I1–I9
    provision.go        --generate-config: zone/config/key generation, guard marker
    state.go            state-file (test identities, stage history)
    txlog_view.go       tool-local mirror of the txlog wire types
    report.go           stats, JSON/text rendering, exit-code policy
    *_test.go           synthetic-stream checker tests (§9.2)
```

- `v2/debug` is its **own Go module** (`github.com/johanix/tdns/v2/debug`)
  wired by relative `replace` directives, and `cmdv2/debug` likewise — this
  is the repo's established per-tree pattern (`v2/cli` and every `cmdv2`
  binary are separate modules), not new machinery. "Never linked into
  production" is enforced mechanically: a CI check asserting no production
  binary's `go list -deps` includes `…/v2/debug` — same spirit as the
  snapshot branch's mutation grep gate.
- The tool needs zero server-side scaffolding, so production stays clean by
  construction, not just by link discipline.

## 13. Testbed prerequisites (for the snapshot campaign)

- A branch-built and a main-built `tdns-auth`; test zones and keys provisioned
  via `--generate-config` (§6.3): `publish-cadence: 20s` (snapshot-branch
  config key; emitted with a comment noting main ignores it), update policy
  `zone: {type: selfsub, rrtypes: [TXT]}` with the `_churn.<id>.<zone>` SIG(0)
  key trusted (§6.1 — the selfsub grant covers exactly the churn subtree),
  AXFR permitted to the tool (`downstreams` — NOKEY or a named TSIG key),
  mgmt API enabled, guard marker present.
- The campaign order: (1) validate checkers against main (§9.1); (2) `test
  churn` against the snapshot branch, escalating `--qps` and duration; (3) a
  long race-instrumented soak (branch server built with `-race`) under the
  same churn — a separate run because of the slowdown; (4) `test ddns`.
  Results feed the snapshot branch's merge decision alongside the human
  review of the C1/M1 refactor.

## 14. Implementation milestones

| M | Deliverable | Gate |
|---|---|---|
| **M1** | Scaffold: binary, config reuse, capability probe + matrix, report skeleton; test identity + state file; minimal `--generate-config` (zone file, config snippet, local keypair, guard marker, operator to-do) | probes a live tdns and a non-tdns server correctly; provisions a runnable churn setup |
| **M2** | update-sender + ledger + AXFR/query pollers + I2/I3/I5/I6/I7/I9 | `test churn` (DNS-only subset) runs vs main and **detects the known tearing** |
| **M3** | bump/resign actors, txlog poller + I1/I4/I8, `--qps` hammer tuning; keystore/truststore auto-install + `cleanup`/`list-tests` | full `test churn` green-capable vs snapshot branch; provision→run→cleanup round-trips |
| **M4** | `test ddns`, JSON report polish, checker unit tests complete | campaign of §13 executable end-to-end |

M2 is the earliest point the tool gates the snapshot branch; M3 completes the
agreed churn spec; `test ddns` deliberately trails so snapshot testing starts
ASAP. Phases P3–P6 follow as separate pushes on the same framework.
