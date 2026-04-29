# Rollover state-machine redesign: never give up, always scream
# (parent-push-softfail phase)

Author: Johan / Claude
Date: 2026-04-29
Status: draft (no implementation work yet)

## Background

The existing automated KSK rollover state machine treats observe-phase
timeout as a *permanent* failure. When the parent fails to confirm
the published DS RRset within `confirm-timeout`, `observeHardFail`
fires — last_rollover_error is stamped on the affected keys and the
zone returns to idle, but `last_ds_submitted_index_low/high` is left
populated. The next idle tick then asks `kskIndexPushNeeded` whether
a re-push is needed; the comparison is against `LastSubmitted*`,
not against any notion of "what the parent actually has," so the
answer is no. The zone is stuck until an operator runs the freshly
added `auto-rollover unstick` command. See
[2026-04-28-rollover-cli-api-redesign.md][cli-redesign] for context.

This is operationally wrong for at least four reasons:

1. **Important infrastructure should be self-healing.** A KSK
   rollover that requires a human to nudge it past every parent-side
   hiccup will be a constant source of pages.
2. **The bookkeeping conflates "I tried" with "it worked."**
   `LastSubmitted*` records the fact that we sent an UPDATE and got
   rcode NOERROR. It does NOT record that the parent applied the
   update. Treating the two as equivalent is the root cause of the
   stuck state.
3. **Production cadences are slow.** Today's testbed runs a 10-minute
   KSK lifetime to exercise the machinery quickly. A real production
   zone is likely to roll on a weekly cadence at the slowest, monthly
   or quarterly is plausible. "Wait for the next rollover cycle to
   recover" — the implicit current behavior — could mean a week of
   no progress on a misconfigured parent.
4. **Status visibility is poor.** Today, an operator looking at
   `auto-rollover status` cannot tell whether the engine has given
   up forever or is about to retry in 30 seconds. The current
   `phase=idle` is ambiguous: it covers steady-state, post-success,
   and post-failure equally.

This doc redesigns the post-push state machine around three
principles:

- **Never permanently give up.** Critical infrastructure should
  retry forever, with monitoring-friendly cadence, until either
  the parent is fixed or an operator actively cancels the rollover.
- **Be loud about it.** Every transition into a non-happy state
  produces structured logs and exposes machine-readable state for
  monitoring. Status output makes the situation obvious in plain
  English.
- **Categorize failure.** "The parent didn't confirm" can mean four
  very different things, requiring different operator actions.
  The state record captures which category, with as much
  protocol-level detail as the parent gave us.

## Goals (acceptance criteria)

1. After `confirm-timeout` elapses without observation, the engine
   re-pushes automatically — no operator intervention required.
2. After `max-attempts-before-backoff` consecutive failed attempts,
   the engine enters a `parent-push-softfail` delay phase. After
   `softfail-delay` it resumes attempting; the failure counter
   resets only on success.
3. During the softfail delay, the observe loop continues polling
   the parent at `confirm-poll-max` cadence. If the DS appears
   (e.g. operator fixed the parent without telling us), the engine
   transitions directly to confirmed without waiting out the delay.
4. The engine records the *category* and *detail* of each failure.
   Status output renders this as plain-English diagnosis.
5. The parent-side response always carries enough information for
   the child operator to diagnose. Specifically: rejected UPDATEs
   return REFUSED (not NOERROR), and attach an EDE option with a
   policy-specific message.
6. `unstick` becomes a narrow operator override ("retry now,
   don't wait the rest of the softfail-delay"), not a recovery
   workaround for an engine bug.

## Out of scope

- Push beyond observe to confirmed: this doc is scoped to the
  push/observe loop. Once DS is confirmed, the existing
  `confirmDSAndAdvanceCreatedKeysTx` flow advances keys to
  ds-published unchanged.
- Per-zone alerting policy: monitoring (Prometheus, alertmanager,
  etc.) consumes the structured state and decides what to alert on.
- Multi-DS-algorithm rollover: today's logic only emits SHA256 DS
  records. That stays unchanged.
- ZSK rollover: still informational only. Same as today.

## Failure categorization

Every push attempt produces a categorized failure record. Four
categories the engine can distinguish:

| Category               | Trigger conditions                                                              | Operator action                          |
|------------------------|---------------------------------------------------------------------------------|------------------------------------------|
| `child-config`         | No active SIG(0) key for zone; no DS records to publish; ParentZone unresolvable | Fix child keystore / zone config         |
| `transport`            | "no route to host"; i/o timeout; connection refused; DSYNC lookup empty; DNS resolution of UPDATE target fails | Network reachability / parent endpoint   |
| `parent-rejected`      | rcode REFUSED / NOTAUTH / FORMERR / SERVFAIL on UPDATE response (with EDE if attached) | Fix parent (policy, delegation, allow-list) |
| `parent-silent-reject` | rcode NOERROR but observe phase times out — DS never appeared on parent         | Almost always parent policy bug          |

The fourth category — `parent-silent-reject` — is the case that bit
us during the 2026-04-28 fast-roller debugging session. It is
distinct from `parent-rejected` because the parent affirmatively
*said yes* and only later behavior contradicts that response. From
the operator's perspective: "the parent has a bug, or its policy
silently drops updates it should reject explicitly." Almost always
this is a missing EDE on the parent side (see Phase 5 below).

A single counter (`hardfail_count`) tracks failures of any category.
The category metadata is for operator visibility — *why* each
attempt failed — not for differentiated retry behavior. If category
changes between attempts (transport on attempt 3, parent-rejected
on attempt 4), that is itself information the operator should see;
it does not reset the counter.

## State machine

Phases (existing in **bold**, new phases underlined):

- **idle**
- **pending-child-publish**
- **pending-parent-push**
- **pending-parent-observe**
- <ins>**parent-push-softfail**</ins> (new)
- **pending-child-withdraw**

Transitions involving the new phase:

```
                                 +----------------------------------+
                                 |                                  |
              push success       v                                  |
  pending-parent-push  -----> pending-parent-observe                |
              ^                  |    |                              |
              | observe          |    | observe-timeout              |
              | confirmed        |    | (hardfail_count++)           |
              |  (advance keys)  |    v                              |
              |                  |  hardfail_count < max_attempts    |
              |                  |  -> pending-parent-push (immediate)
              |                  |                                   |
              |                  +-> hardfail_count >= max_attempts  |
              |                      next_push_at = now + delay      |
              |                      hardfail_count = 0              |
              |                      -> parent-push-softfail         |
              |                                                      |
              | DS observed                                          |
              | (parent fixed during softfail delay,                 |
              |  observe-poll picks it up)                           |
              +------------------------------------------------------+

  parent-push-softfail
    on tick: if now >= next_push_at -> pending-parent-push (resets)
             observe-poll continues at confirm-poll-max cadence
             on confirmed observation: skip directly to advance-keys path
```

Push-attempt failures (transport, child-config, parent-rejected
returned synchronously) increment the same counter. Push retries
follow the same `max_attempts` -> `softfail-delay` discipline as
observe-timeouts; they are not distinguished in retry behavior, only
in the recorded category.

Observe-poll failures *within a single attempt* (per-poll network
blip) do NOT increment `hardfail_count` — they are absorbed by
`scheduleNextObservePoll`'s exponential backoff, the way they are
today. Only the cumulative `confirm-timeout` cliff increments.

## Persistent schema additions

New columns on `RolloverZoneState`:

```sql
hardfail_count          INTEGER DEFAULT 0,
next_push_at            TEXT,                  -- RFC3339 UTC, NULL = push allowed now
last_softfail_at        TEXT,                  -- RFC3339 UTC
last_softfail_category  TEXT,                  -- 'child-config' | 'transport' | 'parent-rejected' | 'parent-silent-reject'
last_softfail_detail    TEXT,                  -- human-readable: "rcode=REFUSED EDE=18 'prohibited'" or "i/o timeout to 77.72.230.63:53"
last_success_at         TEXT,                  -- RFC3339 UTC, last time confirmed DS == target
```

`last_ds_submitted_index_low/high` stays for diagnostic display in
status output but **stops being a gate input** to
`kskIndexPushNeeded`. The new gate is whether `last_ds_confirmed*`
matches the current target (computed by
`ComputeTargetDSSetForZone`).

`hardfail_count` resets to 0 on successful confirmation.

## Config knobs

Added to `RolloverPolicy` (in `ksk_rollover_policy.go`):

```go
type RolloverPolicy struct {
    // existing
    ConfirmInitialWait time.Duration
    ConfirmPollMax     time.Duration
    ConfirmTimeout     time.Duration
    // new
    MaxAttemptsBeforeBackoff int           // default 5
    SoftfailDelay            time.Duration // default 1h
    // ...
}
```

YAML form:

```yaml
dnssecpolicies:
  fastroll:
    rollover:
      method: multi-ds
      confirm-initial-wait: 2s
      confirm-poll-max: 60s
      confirm-timeout: 1h
      max-attempts-before-backoff: 5    # new, default 5
      softfail-delay: 1h                # new, default 1h
```

Defaults baked into `defaultMaxAttemptsBeforeBackoff = 5` and
`defaultSoftfailDelay = time.Hour` constants alongside the existing
`defaultConfirm*` constants.

The fixed `softfail-delay` (no exponential growth) is deliberate:
exponential backoff makes sense when the receiver might be
load-shedding. A misconfigured parent does not get less
misconfigured over time, so a fixed cadence is more honest, more
predictable for monitoring, and easier to reason about.

## kskIndexPushNeeded reformulation

Today:

```go
func kskIndexPushNeeded(row *RolloverZoneRow, low, high int, indexOK bool, haveDS bool) bool {
    if !haveDS {
        return false
    }
    if !indexOK {
        return false
    }
    if row == nil || !row.LastSubmittedLow.Valid || !row.LastSubmittedHigh.Valid {
        return true
    }
    return int(row.LastSubmittedLow.Int64) != low || int(row.LastSubmittedHigh.Int64) != high
}
```

New:

```go
func kskIndexPushNeeded(row *RolloverZoneRow, low, high int, indexOK bool, haveDS bool) bool {
    if !haveDS {
        return false
    }
    if !indexOK {
        return false
    }
    // Compare against confirmed (= what the parent actually has),
    // not against submitted (= what we last tried to send). If those
    // diverge — e.g. submitted populated but confirmed empty after
    // a parent-side rejection — we still need to push.
    if row == nil || !row.LastConfirmedLow.Valid || !row.LastConfirmedHigh.Valid {
        return true
    }
    return int(row.LastConfirmedLow.Int64) != low || int(row.LastConfirmedHigh.Int64) != high
}
```

This is the single most important code change in the whole
redesign. Everything else flows from "compare against reality, not
against history."

## Polling during parent-push-softfail

While in `parent-push-softfail`, the observe-poll loop continues at
`confirm-poll-max` cadence. The rationale: a couple of DNS queries
per minute against the parent's IMR is cheap, and if the operator
fixes the parent during the softfail-delay window we can recover
without waiting the full hour. On any successful observation the
engine bypasses the delay, transitions through the standard
advance-keys path, and the softfail state evaporates.

This means parent-push-softfail and pending-parent-observe are not
mutually exclusive in behavior — softfail is a *push-side* delay,
not an observe-side suspension. Implementation note: the tick
handler for `parent-push-softfail` runs the same observe-poll logic
that `pending-parent-observe` runs, just without the retry-cliff
behavior (since we're already past the cliff in this group).

## Status output spec

Status output is the operator's primary diagnostic surface and must
make the engine's current intent obvious without code-diving. The
spec:

### Steady state (happy path)

```
KSK rollover state for zone cpt.p.axfr.net.:
  status            OK — idle, in sync with parent
  last success      14:38:21 UTC (12m11s ago)
  next rollover     2026-04-29T15:38:21Z (in 47m48s)
  ...
```

### Mid-attempt (push or observe in flight, no failures yet)

```
  status            ACTIVE — push in flight (attempt 1/5)
  phase             pending-parent-observe
  last attempt      14:43:21 UTC (3m11s ago) — UPDATE accepted, observing for confirmation
  next poll         14:46:32 UTC (in 0s)
  observe deadline  15:43:21 UTC (in 56m49s)
```

### Active retry mid-group (one or more softfails, no delay yet)

```
  status            SOFTFAIL — retrying parent push
  phase             pending-parent-push
  attempts          3 / 5 in current group
  last failure      14:38:00 UTC (2m11s ago)
                    category: transport
                    detail:   i/o timeout to 2a01:3f0:1:2::63:53
  next attempt      14:40:11 UTC (in 0s)
```

### In softfail-delay (max attempts reached, waiting before next group)

```
  status            SOFTFAIL — in delay before next attempt group
  phase             parent-push-softfail
  attempts          0 / 5 in next group; previous group: 5 / 5 failed
  last failure      13:43:21 UTC (47m12s ago)
                    category: parent-silent-reject
                    detail:   rcode=NOERROR but observe timed out after 1h —
                              parent did not publish expected DS RRset
  next attempt      14:43:21 UTC (in 47m48s)
  observe-polls continue at 60s cadence — parent fix will be auto-detected
```

### Operator-relevant principles

- The first line is always one of: `OK`, `ACTIVE`, `SOFTFAIL`. That
  word is the headline; everything else is supporting detail.
- Every state shows when the *next* engine-driven thing happens.
  No silent waits.
- Failure categories use the four enum values verbatim. Operators
  learning the system memorize four words, not a sliding scale.
- The `unstick` hint shows up in SOFTFAIL output:
  ```
  use 'auto-rollover unstick --zone X' to skip the delay and retry now
  ```

## Logging cadence

Per attempt (max-attempts-before-backoff = 5 by default):
- WARN on each individual failure: `"rollover: parent push failed (attempt N/M, category=X): detail"`
- WARN on entering softfail-delay: `"rollover: max attempts reached, entering 1h softfail delay"`
- INFO on resuming from softfail: `"rollover: softfail delay elapsed, resuming push attempts"`
- INFO on success during softfail: `"rollover: parent recovered during softfail delay, advancing keys"`

Worst case (parent permanently broken, default config): one WARN
per attempt = 5 WARNs per hour during active retry, then 1 WARN
when entering 1h delay, repeated. Roughly 30 WARN lines per day per
stuck zone. Manageable for log volume; visible enough for grep-based
ops.

For monitoring, a Prometheus-style metric:

```
tdns_rollover_softfail_zones_total{category="parent-silent-reject"}  1
tdns_rollover_softfail_attempts_total{zone="cpt.p.axfr.net."}        7
```

(Implementation of the metrics endpoint is out of scope here; this
is design intent for whoever wires it in later.)

## Parent-side EDE work (parallel item)

Even with the redesigned state machine, operator response to a
`parent-rejected` failure depends on the parent saying *why*.
Today the parent codepath is broken on this front:

In `tdns/v2/updateresponder.go` line 300-303:

```go
m = m.SetRcode(m, int(dur.Status.ValidationRcode))
w.WriteMsg(m)
```

Response rcode is set from validation, *before* `ApproveUpdate`
runs. When approval rejects the update later (line 313+), the
response has already been written with rcode NOERROR (because
validation succeeded) and no EDE attached. The child sees
"accepted" on the wire but never sees the DS appear — the
`parent-silent-reject` case.

The fix:

1. Move the response write to *after* `ApproveUpdate`.
2. If `!us.Approved`, set rcode to REFUSED.
3. Attach an EDE option (`edns0.AttachEDEToResponse`) explaining
   the specific policy reason. The codebase already has
   `edns0.EDEZoneUpdatesNotAllowed`; we need at least three more:
   - `EDEZoneUpdateRRtypeNotAllowed` ("DS not in update-policy.rrtypes")
   - `EDEZoneUpdateOwnerOutsidePolicy` ("owner name violates self/selfsub")
   - `EDEZoneUpdateChildUpdatesNotAllowed` ("OptAllowChildUpdates false")
4. Keep the existing structured WARN logs on the parent side so the
   parent operator also sees the rejection.

With those changes, every UPDATE rejection arrives at the child
with a specific EDE message, the child records it as
`parent-rejected` (not `parent-silent-reject`), and the operator on
the child side knows exactly which knob on the parent needs
attention.

This work is parallel to the child-side state-machine redesign and
should land roughly together — otherwise `parent-rejected` will
keep collapsing into `parent-silent-reject` for every policy-
rejected update, and the categorization becomes useless.

## Narrowed role of `auto-rollover unstick`

After this redesign, `unstick` becomes a much narrower tool:

- **Old role:** the only way to recover from a stuck zone after
  `observeHardFail`. Operationally required.
- **New role:** an operator override that says "I just fixed the
  parent, please skip the rest of the softfail-delay and retry
  *right now*." Operationally optional — the engine will retry on
  its own when `next_push_at` elapses.

Implementation: `unstick` clears `next_push_at` (and resets
`hardfail_count` to 0). Next tick advances out of softfail
immediately. The `last_softfail_*` columns stay populated for
diagnostic continuity.

The CLI help text changes accordingly to make the narrowed role
clear: this is a "skip the wait" command, not a "fix a wedged
zone" command.

## Implementation phases

### Phase 1 — schema + data model

1. Add new columns to `RolloverZoneState` schema. Schema migration
   per the codebase's existing migration convention.
2. Extend `RolloverZoneRow` struct in
   `ksk_rollover_zone_state.go`.
3. Update `LoadRolloverZoneRow` to read the new columns.
4. Add small accessor functions:
   `setSoftfail(kdb, zone, category, detail, nextPushAt)`,
   `incrementHardfailCount(kdb, zone)`,
   `resetHardfailCount(kdb, zone)`,
   `setLastSuccess(kdb, zone, at)`.
5. Build (no behavior change yet).

### Phase 2 — kskIndexPushNeeded reformulation

1. Change `kskIndexPushNeeded` to compare against `LastConfirmed*`
   instead of `LastSubmitted*`.
2. Verify test coverage. The function is small and load-bearing —
   add a focused unit test if one doesn't already exist.
3. At this point `observeHardFail` no longer leaves zones stuck:
   the next idle tick re-pushes naturally because confirmed still
   doesn't match target. This is technically a "fix without the
   softfail machinery" — the engine will retry forever, with no
   backoff, on every tick. That's not what we want long-term but
   it proves the gate fix is correct.

### Phase 3 — failure categorization

1. Define `RolloverFailureCategory` enum (string consts:
   `child-config`, `transport`, `parent-rejected`,
   `parent-silent-reject`).
2. Each push-failure path in `RolloverAutomatedTick` and
   `PushWholeDSRRset` records category + detail via `setSoftfail`.
3. `observeHardFail` records `parent-silent-reject`.

### Phase 4 — softfail phase + counter logic

1. Add `rolloverPhasePushSoftfail = "parent-push-softfail"`
   constant.
2. Wire transitions:
   - On any push or observe failure, increment `hardfail_count` and
     record category/detail.
   - If `hardfail_count >= max_attempts_before_backoff`: set
     `next_push_at = now + softfail_delay`, reset count to 0,
     transition to `parent-push-softfail`.
   - Otherwise: transition straight back to
     `pending-parent-push` (immediate retry).
3. Add tick handler for `parent-push-softfail`: if
   `now >= next_push_at`, transition to `pending-parent-push`;
   otherwise run observe-poll logic in case parent recovered.
4. On any successful confirmation, reset `hardfail_count` and
   stamp `last_success_at`.

### Phase 5 — status output overhaul

1. Restructure `auto-rollover status` rendering per the spec above.
2. Most of the data is now in `RolloverZoneRow`, plus computed
   "time until next attempt" and "time since last attempt"
   derivations.
3. Add the headline word (`OK` / `ACTIVE` / `SOFTFAIL`) computation.
4. Test against the four canonical states from the spec.

### Phase 6 — config wiring

1. Add `MaxAttemptsBeforeBackoff` and `SoftfailDelay` to
   `RolloverPolicy`.
2. YAML parsing in `parseconfig.go` for the new fields.
3. Defaults via `defaultMaxAttemptsBeforeBackoff` and
   `defaultSoftfailDelay`.
4. Validation: max-attempts >= 1; softfail-delay >= confirm-timeout
   (otherwise the delay is shorter than a single attempt window,
   which makes no sense).

### Phase 7 — narrowed unstick

1. Reimplement `UnstickRollover` to clear `next_push_at` and reset
   `hardfail_count` (instead of clearing `last_ds_submitted_*`,
   which is no longer the gate).
2. CLI help text update — narrowed role.

### Phase 8 — parent-side EDE (parallel)

This phase is independent of phases 1-7 and can land in parallel.

1. Move response write in `updateresponder.go` to after
   `ApproveUpdate`.
2. Set REFUSED rcode on `!us.Approved`.
3. Add new EDE codes (`EDEZoneUpdateRRtypeNotAllowed`, etc.).
4. Attach appropriate EDE in each rejection branch of
   `ApproveAuthUpdate` and `ApproveChildUpdate`.
5. Verify with a targeted test that a policy-rejected UPDATE now
   returns REFUSED + EDE on the wire.

### Phase 9 — cleanup

1. Remove `observeHardFail` (its semantics no longer apply).
2. Remove unused `last_rollover_error` write paths if any.
3. Audit `LastSubmitted*` references; demote to diagnostic-only.

## Risks / open questions

1. **Per-zone lock granularity.** Today `RolloverAutomatedTick`
   does not hold a lock; concurrent CLI writes can race. The
   CLI/API redesign (parallel doc) introduces a per-zone mutex.
   The softfail redesign assumes that lock exists — without it,
   a CLI `unstick` running concurrently with a tick advance can
   stomp on `next_push_at`. The two redesigns should land in
   compatible order: CLI/API doc Phase 1 (lock) before this doc's
   Phase 4.

2. **Schema migration.** Adding columns to a table that already
   has zone rows in production sqlite files requires the
   codebase's existing migration mechanism. Need to confirm this
   uses ALTER TABLE-based migrations and not "drop and recreate."
   (The fast-roller branches are pre-production so this is
   tractable; mainline lab signers may need explicit migration.)

3. **What if `softfail-delay < confirm-timeout`?** The delay
   would expire before the parallel observe loop's timeout,
   creating a confusing race. Phase 6 validation rejects this
   config.

4. **Forever-loop log volume on truly-broken parents.** With
   default config, a permanently broken parent generates about 30
   WARN log lines per day per zone forever. For an environment
   with many zones, that scales into thousands. Mitigation: the
   monitoring metric `tdns_rollover_softfail_zones_total` is the
   primary alerting signal, not log greps. Operators should
   alert on the metric and triage from status output, not from
   tail -f.

5. **Cross-zone fairness during a parent outage.** If `p.axfr.net.`
   is down, every child zone of it enters softfail and starts
   retrying every hour. They'll likely synchronize, producing a
   thundering-herd on the parent every hour. Mitigation: small
   per-zone jitter on `next_push_at` (e.g. ±5 min). Cheap, worth
   doing in Phase 4.

## Estimated effort

Single developer, no calendar pressure, careful incremental commits:

- Phase 1 (schema + data): half a day
- Phase 2 (kskIndexPushNeeded fix): one to two hours, big payoff
- Phase 3 (categorization): half a day
- Phase 4 (softfail phase + counter): one day
- Phase 5 (status output): half a day
- Phase 6 (config wiring): half a day
- Phase 7 (narrowed unstick): one to two hours
- Phase 8 (parent-side EDE): half a day, parallel
- Phase 9 (cleanup): one to two hours

Total: roughly 4 days of focused work, parallelizable across
phases 1-7 and 8.

Each phase is one or two commits, cherry-pickable across the
fast-roller branches. Phase 2 alone is a real correctness fix that
could ship ahead of the rest if circumstances demand it — it
removes the stuck-zone deadlock without yet adding the softfail
backoff machinery.

[cli-redesign]: 2026-04-28-rollover-cli-api-redesign.md
