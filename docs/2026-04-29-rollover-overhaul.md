# Rollover overhaul: softfail state machine + CLI-via-API

Author: Johan / Claude
Date: 2026-04-29
Status: implementation in progress on branch `rollover-overhaul`
        (phases 1–10 done; phase 11 next; phase 12 cleanup at end)

This document supersedes:

- `2026-04-28-rollover-cli-api-redesign.md` (CLI/API redesign)
- `2026-04-29-rollover-softfail-state-machine.md` (softfail state
  machine)

The two drafts converged on a single project: the softfail work
defines the new state model and status output, the API work defines
how that model is exposed to operators. They share the per-zone
lock infrastructure, the `RolloverStatus` shape, and the status
output rendering. Doing them sequentially means defining each
shared thing twice; merging them means one definition, used
everywhere it needs to be used.

## Background

Two related operational problems with the current `auto-rollover`
machinery, both surfaced during the 2026-04-28 fast-roller debug
session:

### 1. Stuck rollovers (state machine bug)

The post-push state machine treats observe-phase timeout as a
*permanent* failure. When the parent fails to confirm the published
DS RRset within `confirm-timeout`, `observeHardFail` fires —
`last_rollover_error` is stamped on the affected keys and the zone
returns to idle, but `last_ds_submitted_index_low/high` is left
populated. The next idle tick asks `kskIndexPushNeeded` whether a
re-push is needed; the comparison is against `LastSubmitted*`, not
against any notion of "what the parent actually has," so the answer
is no. The zone is stuck until an operator runs `auto-rollover
unstick`.

This is wrong on multiple axes:

- **Important infrastructure should self-heal.** A rollover that
  requires a human to nudge it past every parent-side hiccup will
  be a constant source of pages.
- **Bookkeeping conflates "I tried" with "it worked."**
  `LastSubmitted*` records the fact that we sent an UPDATE and got
  rcode NOERROR. It does NOT record that the parent applied the
  update. Treating those as equivalent is the root cause.
- **Production cadences are slow.** The testbed runs a 10-minute
  KSK lifetime to exercise the machinery quickly. Real production
  zones roll on a weekly cadence at fastest, monthly or quarterly
  is plausible. "Wait for the next rollover cycle to recover" —
  the implicit current behavior — could mean a week of no progress
  on a misconfigured parent.
- **Status visibility is poor.** `phase=idle` covers steady-state,
  post-success, and post-failure equally. An operator cannot tell
  whether the engine has given up or is about to retry.

### 2. CLI requires direct keystore access

Every `auto-rollover` subcommand opens the signer's sqlite file
directly via `openKeystoreForCli` in
`tdns/v2/cli/ksk_rollover_cli.go`. This forces:

- The CLI to load (and template-expand, and dnssec-policy-resolve)
  the daemon's full config just to discover `db.file`. When the
  daemon and the CLI invocation see different config files, the
  CLI silently reads from the wrong keystore. (This bit us during
  the same debug session — the CLI reported "no DNSSEC policy"
  because it was reading `tdns-cli.yaml` while the daemon ran from
  `tdns-auth.yaml`.)
- Filesystem-permission-based access control on the sqlite file
  to be load-bearing — same machine, same uid, etc.
- Writers (`reset`, `unstick`, `asap`) to race against the running
  daemon's tick loop. Today there's no lock, only sqlite's
  per-statement atomicity. The semantics of "I just cleared X"
  depend on the operator stopping the daemon first, which is
  undocumented.
- No path to remote operation against a signer in a lab or from a
  jump host.

The right shape: the CLI is a thin HTTP client, the signer exposes
`/api/v1/rollover/` endpoints, all keystore writes happen
in-process under the daemon's own per-zone lock.

## Why merge into one project

The two redesigns share critical surfaces:

- **`RolloverStatus` struct.** The API redesign defines it; the
  softfail state machine adds 8+ fields (hardfail count,
  last_softfail_*, expected-by, attempt-timeout, hint string).
  Defining it once means no API contract churn.
- **Status output computation.** Softfail redesigns rendering;
  API redesign moves rendering server-side. Doing both means
  building once, server-side, with the full final shape.
- **Per-zone mutex.** Softfail's narrowed `unstick` writes
  `next_push_at` (a column the tick also writes); API redesign's
  online write handlers race the tick. Both need the same lock.
- **`unstick` semantics.** Softfail rewrites what unstick does;
  API redesign exposes the function over HTTP. Sequencing them
  means renaming or re-shaping HTTP semantics later.

Doing them as one project lets every shared thing be defined
exactly once.

## Goals (acceptance criteria)

1. After one attempt's observation budget expires without
   confirmation, the engine re-pushes automatically — no operator
   intervention required.
2. After `max-attempts-before-backoff` consecutive failed
   attempts, the engine enters a `parent-push-softfail` long-term
   mode, sending one probe UPDATE per `softfail-delay` window.
   The fail counter does NOT reset to a fresh group on entering
   softfail — long-term mode is a stable state, one probe per
   window forever, until success or operator intervention.
3. During the entire post-push lifecycle (initial flurry AND
   softfail long-term mode), polling for the expected DS RRset
   continues uninterrupted. If DS appears at any point, the
   engine transitions directly to confirmed.
4. The engine records the *category* and *detail* of each
   failure. Status output renders this as plain-English diagnosis
   with wallclock-aware timing and explicit polling activity.
5. The parent-side response always carries enough information for
   the child operator to diagnose. Specifically: rejected UPDATEs
   return REFUSED (not NOERROR), and attach an EDE option with a
   policy-specific message.
6. Every `auto-rollover` subcommand has an HTTP endpoint on the
   signer API server. Read endpoints are GET; mutating endpoints
   are POST. Default CLI mode is "talk to the API server."
7. No CLI subcommand requires loading the daemon's full config in
   default (online) mode. The CLI in online mode needs only API
   server URL, API key, and the zone name on the command line.
8. Concurrency: a per-zone mutex serializes API mutating handlers
   against the rollover tick. An operator does not have to stop
   the daemon before running mutating subcommands.
9. Direct keystore access is preserved as an explicit `--offline`
   mode for postmortem use when the daemon is down.
10. `unstick` becomes a narrow operator override ("retry now,
    don't wait the rest of the softfail-delay"), not a recovery
    workaround for an engine bug.

## Out of scope

- Push beyond observe to confirmed. Once DS is confirmed, the
  existing `confirmDSAndAdvanceCreatedKeysTx` flow advances keys
  to ds-published unchanged.
- Per-zone alerting policy. Monitoring (Prometheus, alertmanager)
  consumes structured state and decides what to alert on.
- Multi-DS-algorithm rollover. Today's logic only emits SHA256 DS.
- ZSK rollover. Still informational only.
- Auto-detecting `ds-publish-delay` from observation. Operator
  declares it.
- Multi-tenant API ACLs. The single `X-API-Key` already gates
  `/zone` endpoints; reuse it for `/rollover/`.
- Rollover state for `tdns-mp-signerv2` and other roles that
  maintain their own state. Scoped to `tdns-auth`.

## Constraint: testbed continuity

Project-wide policy is normally "no user base, no backwards
compat." For this work there is a narrow but firm exception: two
testbeds run long-term frequent rollovers against the current
code. They must continue to work across the upgrade. Stop daemon
→ install new binary → start daemon → resume should be sufficient
for the operator. Specifically:

- **DB schema migration is mandatory.** Existing rows on
  `RolloverZoneState`, `RolloverKeyState`, and `DnssecKeyStore`
  must survive the upgrade with their data preserved. New columns
  must be added via the existing `dbMigrateSchema` mechanism in
  [db.go:117](tdns/v2/db.go:117) — `ALTER TABLE ADD COLUMN` with
  `dbColumnExists` idempotency check.
- **In-flight rollovers must finish coherently.** A testbed
  mid-observe (phase=`pending-parent-observe`) when stopped must,
  after upgrade, continue from that phase and reach a sensible
  conclusion under the new logic. No phase-name mismatches, no
  orphaned state.
- **Config file YAML is NOT covered by this constraint.** The
  testbed operators are the developers themselves. They update
  YAML manually after the upgrade if they want to use the new
  knobs. Until they do, defaults apply.
- **API contract has no installed base yet.** Nothing currently
  consumes `/api/v1/rollover/`, so no compat constraint there.

The schema additions are all NULL-or-zero-default columns, benign
for existing rows. The single behavioral wrinkle: Phase 3 alone
(the gate fix without Phase 5's softfail backoff) makes the
engine retry forever with no rate limit. Fine to *commit* in
isolation; should not *deploy* to a testbed without Phase 5 close
behind.

## Failure categorization

Every push attempt produces a categorized failure record. Four
categories the engine can distinguish:

| Category                | Trigger                                                                              | Operator action                                |
|-------------------------|--------------------------------------------------------------------------------------|------------------------------------------------|
| `child-config`          | No active SIG(0) key for zone; no DS to publish; ParentZone unresolvable             | Fix child keystore / zone config               |
| `transport`             | "no route to host"; i/o timeout; conn refused; DSYNC lookup empty; DNS resolve fail  | Network reachability / parent endpoint         |
| `parent-rejected`       | rcode REFUSED / NOTAUTH / FORMERR / SERVFAIL on UPDATE response (with EDE if any)    | Fix parent (policy, delegation, allow-list)    |
| `parent-publish-failure`| rcode NOERROR but observe phase times out — DS never appeared                        | Investigate parent's update→publish path       |

The fourth category — `parent-publish-failure` — is distinct from
`parent-rejected` because the parent's NOERROR response is a wire
protocol commitment that the update was accepted. A parent that
wants to refuse must return REFUSED (or some other negative
rcode), not NOERROR. So if NOERROR comes back and the DS never
appears, the failure is between the parent's accept and its
publication — not a hidden rejection. Causes range from a broken
update→publish pipeline, to a dropped internal queue, to a
parent-side policy bug that should have produced REFUSED but
didn't (Phase 11 below fixes the latter for tdns parents).

A single counter (`hardfail_count`) tracks failures of any
category. Category metadata is for operator visibility, not retry
differentiation. If category changes between attempts, that
itself is information for the operator; it does not reset the
counter.

## State machine

Phases (existing in **bold**, new phase <ins>underlined</ins>):

- **idle**
- **pending-child-publish**
- **pending-parent-push**
- **pending-parent-observe**
- <ins>**parent-push-softfail**</ins> (new)
- **pending-child-withdraw**

Transitions:

```
                                 +----------------------------------+
                                 |                                  |
              push success       v                                  |
  pending-parent-push  -----> pending-parent-observe                |
              ^                  |    |                              |
              | observe          |    | attempt-timeout reached      |
              | confirmed        |    | (hardfail_count++)           |
              | (advance keys)   |    v                              |
              |                  |  count < max_attempts             |
              |                  |  -> pending-parent-push (immediate)
              |                  |                                   |
              |                  +-> count >= max_attempts           |
              |                      next_push_at = now + softfail_delay
              |                      -> parent-push-softfail         |
              |                                                      |
              | DS observed at any time                              |
              | (polling never stops)                                |
              +------------------------------------------------------+

  parent-push-softfail (long-term mode):
    on tick: if now >= next_push_at:
                send ONE probe UPDATE
                start observe with attempt-timeout budget
                next_push_at = now + softfail_delay (with ±5min jitter)
                stay in parent-push-softfail (do NOT enter a fresh
                  group of max_attempts)
             observe-poll continues at confirm-poll-max cadence
             on confirmed observation: advance keys, reset state,
                go straight to idle (or pending-child-withdraw)
```

Crucial structural property: **long-term mode is one probe per
softfail-delay forever, not a new group of max_attempts every
softfail-delay.** Once the parent is broken-for-now (initial
flurry exhausted), the engine settles into a steady probe cadence
that any monitoring system can pick up.

Push-attempt failures (transport, child-config, parent-rejected
returned synchronously) increment the same counter as observe
timeouts.

Observe-poll failures *within a single attempt* (per-poll network
blip) do NOT increment `hardfail_count` — absorbed by
`scheduleNextObservePoll`'s exponential backoff. Only the
cumulative `attempt-timeout` cliff increments.

## kskIndexPushNeeded reformulation

Today:

```go
return int(row.LastSubmittedLow.Int64) != low ||
       int(row.LastSubmittedHigh.Int64) != high
```

After the fix:

```go
// Compare against confirmed (= what the parent actually has),
// not against submitted (= what we last tried to send).
if row == nil || !row.LastConfirmedLow.Valid || !row.LastConfirmedHigh.Valid {
    return true
}
return int(row.LastConfirmedLow.Int64) != low ||
       int(row.LastConfirmedHigh.Int64) != high
```

The single most important code change in the redesign.
Everything else flows from "compare against reality, not against
history."

## Polling during parent-push-softfail

Polling is **continuous from the moment of UPDATE through the rest
of the rollover lifecycle**, including all of softfail-delay. Poll
cadence is `confirm-poll-max` throughout.

If the operator fixes the parent at any point — even during dead
time between hourly probes — the next poll picks up the change
and the engine transitions directly to confirmed. No probe UPDATE
required, no operator intervention required. This is why polling
is cheap and important: a couple of DNS queries per minute against
the parent costs nothing, and the auto-recovery behavior it
enables is the entire point of the design.

## Configuration: three knobs, the rest is derived

```yaml
dnssecpolicies:
  fastroll:
    rollover:
      method: multi-ds
      ds-publish-delay: 5m              # default 5m (direct-publish parents)
      max-attempts-before-backoff: 5    # default 5
      softfail-delay: 1h                # default max(1h, ds-publish-delay)
```

`ds-publish-delay` declares the parent's expected publication
cadence — the time between "we sent the UPDATE and got NOERROR"
and "the new DS RRset is observable on the parent." Examples:

- A parent that publishes via direct DNS UPDATE pushes through to
  authoritative servers: ~5m. (Most modern setups.)
- A registry that batches publishes hourly (e.g. `.SE`): 1h.
- A registry with a daily publication cycle: 24h.

The name "ds-publish-delay" is somewhat a misnomer — for batched
parents this is more "publish cadence" than delay. Keeping the
name regardless.

Everything else is derived (with optional explicit overrides):

| Internal value     | Derivation                              | Why                                                                    |
|--------------------|-----------------------------------------|------------------------------------------------------------------------|
| `confirm-initial-wait` | always 2s                           | Early polls cheap and harmless                                         |
| `confirm-poll-max`     | clamp(`ds-publish-delay`/10, 30s, 5m) | Don't poll faster than meaningfully new info can arrive                |
| `attempt-timeout`      | `ds-publish-delay × 1.2`             | 20% safety margin beyond parent's normal cycle before declaring fail   |

These can be set explicitly in YAML to override.

## Persistent schema additions

New columns on `RolloverZoneState`:

```sql
hardfail_count          INTEGER DEFAULT 0,
next_push_at            TEXT,                  -- RFC3339 UTC, NULL = push allowed now
last_softfail_at        TEXT,
last_softfail_category  TEXT,                  -- one of the four enum values
last_softfail_detail    TEXT,                  -- "rcode=REFUSED EDE=18 'prohibited'" / "i/o timeout to ..."
last_success_at         TEXT,                  -- last time confirmed DS == target
last_attempt_started_at TEXT,                  -- start of current/most recent attempt
last_poll_at            TEXT,                  -- last parent-DS query
```

(`observe_next_poll_at` already exists; reuse for `next_poll`.)

`last_ds_submitted_index_low/high` stays populated for diagnostic
display, but **stops being a gate input** to `kskIndexPushNeeded`.
The new gate is `last_ds_confirmed_index_low/high` vs current
target.

`hardfail_count` resets to 0 on successful confirmation only —
not on entering softfail (long-term mode is a stable state).

## API endpoints

Mount under `/api/v1/rollover/`. Reuse the existing zone-API
style: JSON request/response bodies, existing X-API-Key middleware,
HTTP 200 with `{"error": true, ...}` for operationally-expected
failures, HTTP 4xx/5xx only for protocol-level problems.

| Subcmd     | Method | Path                  | Body                              | Response                                  |
|------------|--------|-----------------------|-----------------------------------|-------------------------------------------|
| `status`   | GET    | `/rollover/status`    | `?zone=cpt.p.axfr.net.`           | full `RolloverStatus` struct (see below)  |
| `when`     | GET    | `/rollover/when`      | `?zone=cpt.p.axfr.net.`           | `{earliest, fromIdx, toIdx, gates[]}`     |
| `asap`     | POST   | `/rollover/asap`      | `{"zone": "..."}`                 | `{requestedAt, earliest, fromIdx, toIdx}` |
| `cancel`   | POST   | `/rollover/cancel`    | `{"zone": "..."}`                 | `{cleared: bool}`                         |
| `reset`    | POST   | `/rollover/reset`     | `{"zone": "...", "keyid": 62999}` | `{cleared: bool}`                         |
| `unstick`  | POST   | `/rollover/unstick`   | `{"zone": "..."}`                 | `{cleared: bool}`                         |

GET-for-reads / POST-for-mutations lets ops folks `curl` `status`
and `when` without worrying about accidental writes.

## RolloverStatus struct (single definition, used everywhere)

Lives in `tdns/v2/core/messages.go` (or new `messages_rollover.go`)
so server and CLI import from one place. This is the merged shape —
existing fields from the API redesign draft, plus all softfail
fields the new state machine introduces.

```go
type RolloverStatus struct {
   Zone                string             `json:"zone"`
   CurrentTime         string             `json:"currentTime"`         // RFC3339 UTC, server's wallclock at response time
   Phase               string             `json:"phase"`
   PhaseAt             string             `json:"phaseAt,omitempty"`
   InProgress          bool               `json:"inProgress"`
   Headline            string             `json:"headline"`            // OK | ACTIVE | SOFTFAIL
   Hint                string             `json:"hint,omitempty"`      // plain-English diagnosis line

   // Submitted/confirmed DS index ranges
   Submitted           *DSRange           `json:"submitted,omitempty"` // diagnostic only
   Confirmed           *DSRange           `json:"confirmed,omitempty"` // gate input

   // Manual-rollover schedule (asap/cancel)
   ManualRequestedAt   string             `json:"manualRequestedAt,omitempty"`
   ManualEarliest      string             `json:"manualEarliest,omitempty"`

   // Active attempt (only populated in ACTIVE state)
   LastUpdate          string             `json:"lastUpdate,omitempty"`
   LastAttemptStarted  string             `json:"lastAttemptStarted,omitempty"`
   ExpectedBy          string             `json:"expectedBy,omitempty"`         // lastUpdate + ds-publish-delay
   AttemptTimeout      string             `json:"attemptTimeout,omitempty"`     // lastUpdate + attempt-timeout
   AttemptIndex        int                `json:"attemptIndex,omitempty"`       // 1..max
   AttemptMax          int                `json:"attemptMax,omitempty"`         // = max-attempts-before-backoff

   // Softfail (only populated in SOFTFAIL state)
   HardfailCount       int                `json:"hardfailCount,omitempty"`
   NextPushAt          string             `json:"nextPushAt,omitempty"`         // = next probe UPDATE time
   LastSoftfailAt      string             `json:"lastSoftfailAt,omitempty"`
   LastSoftfailCat     string             `json:"lastSoftfailCategory,omitempty"`
   LastSoftfailDetail  string             `json:"lastSoftfailDetail,omitempty"`

   // Polling activity (populated in ACTIVE and SOFTFAIL)
   LastPoll            string             `json:"lastPoll,omitempty"`
   NextPoll            string             `json:"nextPoll,omitempty"`

   // Last success — across all states
   LastSuccess         string             `json:"lastSuccess,omitempty"`

   // Per-key state
   KSKs                []RolloverKeyEntry `json:"ksks"`
   ZSKs                []RolloverKeyEntry `json:"zsks"`

   // Policy summary (verbose mode shows this)
   Policy              *PolicySummary     `json:"policy,omitempty"`
}

type DSRange struct {
   Low  int `json:"low"`
   High int `json:"high"`
}

type RolloverKeyEntry struct {
   KeyID            uint16 `json:"keyid"`
   ActiveSeq        *int   `json:"activeSeq,omitempty"`
   State            string `json:"state"`
   Published        string `json:"published,omitempty"`
   StateSince       string `json:"stateSince,omitempty"`
   LastRolloverErr  string `json:"lastRolloverError,omitempty"`
}

type PolicySummary struct {
   Name                     string        `json:"name"`
   Algorithm                string        `json:"algorithm"`
   KskLifetime              string        `json:"kskLifetime"`         // human-readable duration
   DsPublishDelay           string        `json:"dsPublishDelay"`
   MaxAttemptsBeforeBackoff int           `json:"maxAttemptsBeforeBackoff"`
   SoftfailDelay            string        `json:"softfailDelay"`
   ClampingMargin           string        `json:"clampingMargin,omitempty"`
}
```

CLI rendering stays a CLI concern; the server returns the full
struct with everything pre-computed (including the `Headline`
word and `Hint` string, since those depend on policy + current
time and are easier to compute server-side).

## Status output spec (CLI rendering)

### Always-first line: current time (from server's `CurrentTime`)

```
Current time:     14:35:23 UTC (Wed Apr 29 2026)
```

### Steady state (happy path)

```
Current time:     14:35:23 UTC
KSK rollover state for zone cpt.p.axfr.net.:
  status            OK — idle, in sync with parent
  last success      14:30:00 UTC (5m23s ago)
  next rollover     2026-04-29T15:30:00Z (in 54m37s)
  ds-publish-delay  5m
  ...
```

### Mid-attempt, within expected window

```
Current time:     14:35:23 UTC
KSK rollover state for zone cpt.p.axfr.net.:
  status            ACTIVE — observing parent for DS publication
  phase             pending-parent-observe
  attempts          1 / 5 in current group
  last UPDATE       14:30:00 UTC (5m23s ago)
  ds-publish-delay  1h (configured for this parent)
  expected by       15:30:00 UTC (in 54m37s)
  attempt timeout   15:42:00 UTC (in 1h6m37s)
  last poll         14:35:00 UTC (23s ago) — DS not yet observed
  next poll         14:36:00 UTC (in 37s)
  hint              within expected publish window — polling continues
```

### Mid-attempt, past expected window

```
Current time:     15:32:12 UTC
KSK rollover state for zone cpt.p.axfr.net.:
  status            ACTIVE — observing parent for DS publication
  phase             pending-parent-observe
  attempts          1 / 5 in current group
  last UPDATE       14:30:00 UTC (1h2m12s ago)
  ds-publish-delay  1h
  expected by       15:30:00 UTC (2m12s ago)
  attempt timeout   15:42:00 UTC (in 9m48s)
  last poll         15:31:55 UTC (17s ago) — DS not yet observed
  next poll         15:32:55 UTC (in 43s)
  hint              past expected publish time, polling continues — approaching timeout
```

### Long-term softfail mode

```
Current time:     14:35:00 UTC
KSK rollover state for zone cpt.p.axfr.net.:
  status            SOFTFAIL — in long-term retry mode
  phase             parent-push-softfail
  attempts          initial flurry (5/5) failed at 13:42:00 UTC
  last UPDATE       13:42:00 UTC (53m ago) — last failed attempt's push
  last failure      13:42:00 UTC (53m ago)
                    category: parent-publish-failure
                    detail:   rcode=NOERROR but observe timed out after 6m —
                              parent did not publish expected DS RRset
  next probe        14:42:00 UTC (in 7m)
  last poll         14:34:30 UTC (30s ago) — DS not yet observed
  next poll         14:35:00 UTC (in 0s)
  hint              parent fix will be auto-detected — polling never stops
                    use 'auto-rollover unstick --zone X' to skip the wait and probe now
```

### Status output principles

- First content line is one of: `OK`, `ACTIVE`, `SOFTFAIL`. The
  word is the headline; everything else is supporting detail.
- Every state shows when the *next* engine-driven thing happens.
  No silent waits.
- Failure categories use the four enum values verbatim.
- During any non-idle phase, `last poll` / `next poll` are visible
  so the operator sees the engine actively checking.
- `hint` collapses timing math into plain English. Three
  variations: within-expected, past-expected, in-softfail-mode.

## Three example schedules

### Fast direct-publish parent (default config)

`ds-publish-delay = 5m`, `max-attempts-before-backoff = 5`,
`softfail-delay = 1h`. Internal: `attempt-timeout = 6m`,
`confirm-poll-max = 30s`.

```
T+0:00     UPDATE sent, rcode NOERROR
T+0:00–T+0:06   poll every ~30s, no DS observed
T+0:06     attempt 1 timeout (6m × 1.2) → re-push
T+0:12     attempt 2 timeout → re-push
T+0:18     attempt 3 timeout → re-push
T+0:24     attempt 4 timeout → re-push
T+0:30     attempt 5 timeout → enter parent-push-softfail,
                                next_push_at = T+1:30
T+0:30–T+1:30   poll continues every 30s, no DS
T+1:30     softfail probe: UPDATE, attempt-timeout 6m
T+1:36     probe attempt timeout → stay in softfail,
                                next_push_at = T+2:30
T+2:30     softfail probe → fail → next_push_at = T+3:30
... forever, one probe per hour
```

Operator alarm-worthy state declared in 30 min, steady hourly
drumbeat after. Total UPDATEs to a permanently broken parent: 5
in first 30 min + 1/hour ≈ 25/day.

### Hourly-publish parent (e.g. `.SE`)

`ds-publish-delay = 1h`, defaults otherwise. Internal:
`attempt-timeout = 1h12m`, `confirm-poll-max = 5m`.

```
T+0:00     UPDATE sent
T+0:00–T+1:12   poll every 5m, no DS observed
T+1:12     attempt 1 timeout → re-push
T+2:24     attempt 2 timeout → re-push
T+3:36     attempt 3 timeout → re-push
T+4:48     attempt 4 timeout → re-push
T+6:00     attempt 5 timeout → enter parent-push-softfail,
                                next_push_at = T+7:00
T+6:00–T+7:00   poll continues every 5m
T+7:00     softfail probe → fail → next_push_at = T+8:00
... forever, one probe per hour
```

Initial flurry takes 6h, which is right ballpark — if `.SE`
missed the update across 5 publish cycles, that is a real outage
worth alarming on.

### Operator fixes parent during softfail (auto-recovery)

`ds-publish-delay = 5m`, parent broken for ~2h, operator fixes at
T+2:00. Continuous polling picks it up:

```
T+0:00 to T+0:30    initial flurry (5 attempts), all fail
T+0:30              enter softfail, next_push_at = T+1:30
T+1:30              softfail probe, fails, next_push_at = T+2:30
T+2:00              operator fixes parent's update-policy
T+2:00              parent's normal publish cycle picks up the
                    UPDATE that was sent at T+1:30
                    (still inside its 5m publish window)
T+2:00–T+2:05       parent publishes new DS RRset
T+2:05              next poll observes the new DS
                    → advance keys → reset state → idle
                    (no operator action needed — auto-recovery)
```

This is the whole point of "polling never stops." The operator
fix could have happened at any time and the system would have
self-healed at the next poll boundary.

## CLI in online vs offline mode

### Online mode (default)

Each subcommand is a thin HTTP client:

```go
func newAutoRolloverUnstickCmd() *cobra.Command {
   c := &cobra.Command{
      Use: "unstick",
      ...,
      Run: func(cmd *cobra.Command, args []string) {
         tdns.Globals.App.Type = tdns.AppTypeCli
         api := GetApiClient("auth", true)
         var resp tdns.RolloverUnstickResponse
         err := api.PostJSON("/api/v1/rollover/unstick",
            tdns.RolloverUnstickRequest{Zone: dns.Fqdn(zonename)},
            &resp)
         ...
      },
   }
   ...
}
```

`GetApiClient("auth", ...)` already exists; the CLI dials the
auth daemon's API server using credentials in the CLI's
`tdns-cli.yaml`. Does NOT load the daemon's zone or template
config.

### `--offline` fallback

Useful when the daemon is *down* (postmortem, recovering a wedged
signer):

- `status` — show what state the zone was left in.
- `unstick`, `reset` — manually edit the keystore so the next
  start doesn't immediately re-wedge.

```
tdns-cliv2 auth keystore dnssec auto-rollover unstick \
    --zone cpt.p.axfr.net. --offline
```

`--offline` is the only mode that requires `--config <daemon-config>`,
so the existing config-loading machinery stays scoped to that
flag. Default mode does not load the daemon config at all.

`when` and `asap` should NOT have an offline mode — they need a
running daemon to schedule against. `cancel` similarly is
online-only.

**Footgun mitigation:** `--offline` writers should refuse if a
tdns-auth process is currently running and holding the sqlite
file open (lockfile check, or a sentinel value the daemon writes
on startup). Otherwise an operator might think they're surgically
editing dead state when really they're racing a live writer.

## Per-zone lock infrastructure

The rollover tick and online mutating handlers must not interleave.
Solution: a per-zone `sync.Mutex` registry, taken by both:

```go
// rollover_lock.go
var (
    rolloverLocks   = make(map[string]*sync.Mutex)
    rolloverLocksMu sync.Mutex
)

func acquireRolloverLock(zone string) *sync.Mutex {
    rolloverLocksMu.Lock()
    defer rolloverLocksMu.Unlock()
    m, ok := rolloverLocks[zone]
    if !ok {
        m = &sync.Mutex{}
        rolloverLocks[zone] = m
    }
    return m
}
```

`RolloverAutomatedTick` takes the lock at the top of its
per-zone work; API mutating handlers (`asap`, `cancel`, `reset`,
`unstick`) take it before any DB write.

Read endpoints (`status`, `when`) do NOT take the lock — sqlite
WAL mode gives snapshot reads while writers are in flight, and
the API contract is "best-effort current state at response time"
which a lock-free snapshot satisfies.

Granularity: per-zone, not global. The current rollover tick is
fast (single-zone phase advance) so the lock is held for
milliseconds. If the tick ever grows long-running work under the
lock (e.g. inline DNS UPDATE retries), revisit and consider
moving to option-2-from-the-original-API-doc (request channel
into the rollover worker).

## Logging cadence

Per attempt (defaults):

- WARN on each individual failure: `"rollover: parent push
  failed (attempt N/M, category=X): detail"`
- WARN on entering softfail-delay: `"rollover: initial flurry
  exhausted, entering softfail long-term mode (probe every 1h)"`
- INFO on each softfail probe: `"rollover: softfail probe N
  (still failing, category=X)"`
- INFO on auto-recovery: `"rollover: parent recovered during
  softfail polling, advancing keys"`

Worst case (parent permanently broken, default config):

- 5 WARN lines in first 30 min
- 1 INFO line per hour thereafter

= roughly 25 log lines per day per stuck zone. Log volume
manageable; visible enough for grep-based ops.

For monitoring (implementation out of scope):

```
tdns_rollover_softfail_zones_total{category="parent-publish-failure"} 1
tdns_rollover_softfail_attempts_total{zone="cpt.p.axfr.net."}         7
```

## Parent-side EDE work

Operator response to a `parent-rejected` failure depends on the
parent saying *why*. Today the tdns parent codepath is broken on
this front:

In `tdns/v2/updateresponder.go` line 300-303:

```go
m = m.SetRcode(m, int(dur.Status.ValidationRcode))
w.WriteMsg(m)
```

Response rcode is set from validation, *before* `ApproveUpdate`
runs. When approval rejects the update later (line 313+), the
response is already on the wire with rcode NOERROR (because
validation succeeded) and no EDE attached. The child sees
"accepted" but never sees the DS appear — `parent-publish-failure`
from the child's perspective, even though the truth is "parent
rejected on policy."

Fix:

1. Move response write to *after* `ApproveUpdate`.
2. If `!us.Approved`, set rcode to REFUSED.
3. Attach EDE option (`edns0.AttachEDEToResponse`) explaining the
   specific policy reason. Codebase already has
   `edns0.EDEZoneUpdatesNotAllowed`; we need at least three more:
   - `EDEZoneUpdateRRtypeNotAllowed` ("DS not in update-policy.rrtypes")
   - `EDEZoneUpdateOwnerOutsidePolicy` ("owner outside self/selfsub")
   - `EDEZoneUpdateChildUpdatesNotAllowed` ("OptAllowChildUpdates false")
4. Keep existing structured WARN logs on the parent side.

Effect: every UPDATE rejection arrives at the child with a
specific EDE message; child records `parent-rejected` (not
`parent-publish-failure`); operator on the child side knows
exactly which knob on the parent needs attention. Crucially,
this collapses tdns-vs-tdns deployments out of
`parent-publish-failure` and into the more actionable
`parent-rejected` category.

This phase is independent of the child-side state-machine work
and can land in parallel.

## Narrowed role of `unstick`

After this redesign:

- **Old role:** the only way to recover from a stuck zone after
  `observeHardFail`. Operationally required.
- **New role:** an operator override that says "I just fixed the
  parent, please skip the rest of the softfail-delay and probe
  *right now*." Operationally optional — engine probes on its own
  when `next_push_at` elapses, and polling continues in the
  meantime so a fix is auto-detected regardless.

Implementation: `unstick` clears `next_push_at`. Next tick
advances out of softfail-delay immediately and sends one probe
UPDATE. `last_softfail_*` and `hardfail_count` stay populated for
diagnostic continuity.

## Implementation phases

Each phase = one or two commits. Implementation happens on
`rollover-overhaul` branched off `fast-roller-1`. Cherry-pickable
onto `fast-roller-mldsa44` once the full series is complete.

Status as of 2026-04-29:

| Phase | Title                                       | Commit       | State    |
|-------|---------------------------------------------|--------------|----------|
| 1     | per-zone lock infrastructure                | `54dc96d`    | done     |
| 2     | schema additions                            | `155d21c`    | done     |
| 3     | kskIndexPushNeeded reformulation            | `6b09dd4`    | done     |
| 4     | failure categorization                      | `f4ab81b`    | done     |
| 5     | softfail phase + counter logic              | `a6d2288`    | done     |
| 6     | config wiring                               | `af6a863`    | done (out of order; phase 5 needs the knobs) |
| 7     | narrowed `unstick` (function-only)          | `42345de`    | done     |
| 8     | RolloverStatus struct + compute             | `99095f6`    | done     |
| 9     | read endpoints + CLI conversion             | `0215580`    | done     |
| 10    | write endpoints + CLI conversion            | (see body)   | done (lockfile guard deferred to phase 12) |
| 11    | parent-side EDE (parallel)                  | —            | next     |
| 12    | cleanup                                     | —            |          |

Tangential fix landed alongside on `fast-roller-1`: `825cee8`
implemented the missing `ClampedDuration` helper that was blocking
test compilation in v2 (commit a5467e1 had added the test but not
the helper). Merged into `rollover-overhaul` via `b06a13b`.

### Phase 1 — per-zone lock infrastructure  (DONE — `54dc96d`)

1. Add `rollover_lock.go` with the per-zone mutex registry.
2. `RolloverAutomatedTick` takes the lock at the top of per-zone
   work.
3. Build (no behavior change yet — there are no API handlers to
   contend with the tick).

Tiny phase; one commit. Goes first because everything later
assumes the lock exists.

### Phase 2 — schema additions  (DONE — `155d21c`)

1. Add migration entries to the `migrations` slice in
   `dbMigrateSchema` ([db.go:117](tdns/v2/db.go:117)). One entry
   per new column, each `ALTER TABLE RolloverZoneState ADD COLUMN`
   with a NULL-safe default.
2. Update canonical `CREATE TABLE RolloverZoneState` in
   `db_schema.go` to include the new columns, so fresh DBs get
   them at table-creation time.
3. Extend `RolloverZoneRow` struct in `ksk_rollover_zone_state.go`.
4. Update `LoadRolloverZoneRow` to read the new columns.
5. Add accessor functions: `setSoftfail`,
   `incrementHardfailCount`, `resetHardfailCount`,
   `setLastSuccess`, `setLastPoll`.
6. Build (additive schema, no behavior change).
7. Verify against a copy of a testbed's `RolloverZoneState` table
   that all existing rows load cleanly with NULL/0 in the new
   columns.

### Phase 3 — kskIndexPushNeeded reformulation  (DONE — `6b09dd4`)

1. Change the gate to compare against `LastConfirmed*` instead of
   `LastSubmitted*`.
2. Add focused unit test (9 cases incl. the regression case).
3. After this phase: stuck zones recover, but engine retries
   forever with no rate limit. Phase 5 adds the backoff.

Independently shippable as a pure correctness fix, but should
NOT deploy to a testbed without Phase 5 close behind.

### Phase 4 — failure categorization  (DONE — `f4ab81b`)

1. Define `RolloverFailureCategory` enum (string consts:
   `child-config`, `transport`, `parent-rejected`,
   `parent-publish-failure`) in `ksk_rollover_categories.go`.
2. `KSKDSPushResult` gets a `Category` field; `PushWholeDSRRset`
   sets it at every error path.
3. Tick's pending-parent-push branch consumes the category and
   calls `setSoftfail(category, detail, now, zero)`. zero
   `next_push_at` means "no delay imposed yet" — phase 5 sets
   non-zero values when entering long-term mode.
4. `observeHardFail` calls `setSoftfail` with
   `parent-publish-failure` on observe timeout.

### Phase 5 — softfail phase + counter logic  (DONE — `a6d2288`)

1. Add `rolloverPhasePushSoftfail = "parent-push-softfail"`.
2. Wire transitions:
   - On any push or observe failure, increment `hardfail_count`
     and record category/detail.
   - If `hardfail_count >= max_attempts_before_backoff`: set
     `next_push_at = now + softfail_delay` (with ±5min jitter),
     transition to `parent-push-softfail`. Do NOT reset the
     count.
   - Otherwise: transition straight back to
     `pending-parent-push` (immediate retry).
3. Add tick handler for `parent-push-softfail`:
   - If `now >= next_push_at`: send ONE probe UPDATE, restart
     observe with `attempt-timeout` budget, set
     `next_push_at = now + softfail_delay (with jitter)`. Do NOT
     enter pending-parent-push as a fresh group.
   - Polling continues at `confirm-poll-max` cadence regardless.
4. On any successful confirmation, reset `hardfail_count` to 0
   and stamp `last_success_at`.

Uses Phase 1 lock.

### Phase 6 — config wiring  (DONE — `af6a863`)

Done before Phase 5 because Phase 5 needs the policy fields to
exist before it can read them; otherwise we'd churn between
hardcoded constants and policy reads.

1. Three new YAML fields on `DnssecPolicyRolloverConf`:
   `ds-publish-delay`, `max-attempts-before-backoff`,
   `softfail-delay`.
2. Three matching fields on `RolloverPolicy`.
3. Defaults: `defaultDsPublishDelay = 5*time.Minute`,
   `defaultMaxAttemptsBeforeBackoff = 5`,
   `defaultSoftfailDelayMinimum = time.Hour`.
4. Three derivation helpers in `ksk_rollover_policy.go`:
   `derivedPollMax(d) = clamp(d/10, 30s, 5m)`,
   `derivedAttemptTimeout(d) = d × 1.2`,
   `derivedSoftfailDelay(d) = max(1h, d)`.
   `confirm-poll-max` and `confirm-timeout` defaults now derive
   from `ds-publish-delay` instead of being fixed; existing YAMLs
   that pin them explicitly still win.
5. Cross-field validation rejects:
   - `max-attempts-before-backoff < 1`
   - `confirm-timeout < ds-publish-delay`
   - `softfail-delay < ds-publish-delay`

### Phase 7 — narrowed `unstick` (function-only)  (DONE — `42345de`)

1. Reimplement `UnstickRollover` to clear `next_push_at` only.
2. CLI help text update — narrowed role.

### Phase 8 — RolloverStatus struct + ComputeRolloverStatus  (DONE — `99095f6`)

1. Add `messages_rollover.go` with `RolloverStatus`, `DSRange`,
   `RolloverKeyEntry`, `PolicySummary`, request structs for each
   POST endpoint.
2. Implement `ComputeRolloverStatus(kdb, zone, pol, now) *RolloverStatus`
   in a new `rollover_api_funcs.go`. Reads everything from the
   DB and policy, computes derived fields (`Headline`, `Hint`,
   `ExpectedBy`, `AttemptTimeout`, etc.) server-side.
3. Implement `ComputeRolloverWhen` similarly — wraps existing
   `ComputeEarliestRollover`.

### Phase 9 — read endpoints + CLI conversion  (DONE — `0215580`)

1. Add `apihandler_rollover.go` with `/rollover/status` (GET),
   `/rollover/when` (GET) handlers calling Phase 8 functions.
2. Wire into `apirouters.go` under the existing X-API-Key
   subrouter.
3. Convert CLI `status` and `when` to HTTP-by-default. Keep the
   direct-DB code path behind `--offline`.
4. Smoke test against a lab signer.

After Phase 9, the painful "no DNSSEC policy" CLI failure mode
from the 2026-04-28 debug session is gone in default mode.

### Phase 10 — write endpoints + CLI conversion  (DONE — pending hash on commit)

1. Implement `/rollover/asap` (POST), `/rollover/cancel` (POST),
   `/rollover/reset` (POST), `/rollover/unstick` (POST). Each
   handler takes the per-zone lock from Phase 1.
2. Convert CLI `asap`, `cancel`, `reset`, `unstick` to
   HTTP-by-default, one subcommand per commit.
3. Add `--offline` to `unstick` and `reset` (the postmortem
   subcommands); `asap` and `cancel` are online-only.
4. Add the lockfile/sentinel check that prevents `--offline`
   writers from running while a daemon holds the sqlite file
   open.

### Phase 11 — parent-side EDE (parallel)  (NEXT)

Independent of phases 1-10. Can land any time after Phase 1.

1. Move response write in `updateresponder.go` to after
   `ApproveUpdate`.
2. Set REFUSED rcode on `!us.Approved`.
3. Add new EDE codes.
4. Attach EDE in each rejection branch of `ApproveAuthUpdate`
   and `ApproveChildUpdate`.
5. Targeted test: a policy-rejected UPDATE returns REFUSED + EDE.

### Phase 12 — cleanup

1. Remove `observeHardFail` (semantics no longer apply; the body
   is now a thin wrapper over `handleAttemptFailed`). Inline the
   per-key `last_rollover_error` stamp at the call site and drop
   the function. Rename `handleAttemptFailed` if it ends up the
   sole remaining helper.
2. Remove unused `last_rollover_error` write paths if any.
3. Audit `LastSubmitted*` references; demote to diagnostic-only.
4. Audit `openKeystoreForCli` callers. Anything outside
   `--offline` paths should be gone.
5. Verify the `[WARN/config] no config file specified` warning
   no longer fires in default CLI mode.
6. **Lockfile/sentinel guard for `--offline` writers.** Phase 10
   shipped the API mutating endpoints + CLI conversions but did
   *not* add the guard that prevents `--offline` writers from
   running while a daemon process is alive (the doc's Phase 10
   item 4). Today the operator is told in CLI help text to ensure
   the daemon is stopped, but nothing enforces it. Concrete plan:
   on daemon startup, write a sentinel row to a small meta table
   carrying daemon PID and start_time. On `--offline` writer
   invocation, read the sentinel and `kill -0` the PID; if alive,
   refuse with `--offline --force` available as an explicit
   override. Until this lands, `--offline` writers are footguny
   when run against a live daemon.
7. **Unit tests for the tick handler across all phase states.**
   The phase 5 commit added the new `parent-push-softfail` handler
   and rewired the failure decision through `handleAttemptFailed`,
   but tick-level test coverage is still thin — only the
   `kskIndexPushNeeded` truth table is unit-tested. Build out a
   table-driven test harness that, for each phase
   (idle, pending-child-publish, pending-parent-push,
   pending-parent-observe, parent-push-softfail,
   pending-child-withdraw), seeds a fake `KeyDB` row, drives one
   `RolloverAutomatedTick` call, and asserts the resulting state
   transitions and counter/timestamp side effects. The harness
   needs a fake/mock `*KeyDB` (or sqlite-in-memory) plus a way to
   stub `PushWholeDSRRset` / `QueryParentAgentDS` so the test
   doesn't actually hit the network. This is a non-trivial
   test-infrastructure investment — the right time to make it is
   after the state machine has stabilized, which is here.

## Risks / open questions

1. **Lock granularity.** Per-zone mutex held for milliseconds
   during a tick. Fine for current tick work. If the tick ever
   grows long-running operations (inline DNS UPDATE retries
   under the lock), revisit and consider a request-channel
   pattern instead.

2. **`--offline` write paths.** Footgun if daemon is up but
   unresponsive. Mitigation: lockfile check (Phase 10).
   Alternative: require `--offline --force` for writers and
   accept the operator owns the risk.

3. **API JSON contract.** Once external tooling consumes
   `/rollover/status`, the field names become a contract. Pick
   names carefully in Phase 8 and don't rename later. The struct
   above is the proposed final shape.

4. **Other roles.** `tdns-mp-signerv2` and any future signer role
   will need parallel endpoints. Out of scope here; the
   `messages_rollover.go` structs should not bake "auth" into
   field names.

5. **Forever-loop log volume on truly-broken parents.** Default
   config: ~25 log lines per day per stuck zone forever. For
   environments with many zones, scales into thousands.
   Mitigation: monitoring metric is the primary alerting signal,
   not log greps.

6. **Operator misconfigures `ds-publish-delay`.** Setting it too
   low (e.g. 5m for a parent that takes 1h) makes every rollover
   declare softfail at minute 30 even with a healthy parent. No
   good auto-detection — the error mode is operator
   misconfiguration, surfaced via the stuck-zone metric.
   Document `ds-publish-delay` clearly in the config reference.

## Estimated effort

Single developer, careful incremental commits:

- Phase 1 (lock): one to two hours
- Phase 2 (schema): half a day
- Phase 3 (gate fix): one to two hours, big payoff
- Phase 4 (categorization): half a day
- Phase 5 (softfail logic): one day
- Phase 6 (config wiring): half a day
- Phase 7 (narrowed unstick): one to two hours
- Phase 8 (status struct + compute): half a day
- Phase 9 (read endpoints + CLI): half a day
- Phase 10 (write endpoints + CLI): one day (4 conversions)
- Phase 11 (parent EDE): half a day, parallel
- Phase 12 (cleanup): one to two hours

Total: roughly 5 days of focused work, parallelizable across
phases 1-10 and 11. Each phase one or two commits.

When complete, merge `rollover-overhaul` to `fast-roller-1`,
then cherry-pick the merged sequence onto `fast-roller-mldsa44`.
