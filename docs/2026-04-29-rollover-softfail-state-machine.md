# Rollover state-machine redesign: never give up, always scream
# (parent-push-softfail phase)

Author: Johan / Claude
Date: 2026-04-29
Status: draft (no implementation work yet)
Companion doc: [2026-04-28-rollover-cli-api-redesign.md][cli-redesign]

## Background

The existing automated KSK rollover state machine treats observe-
phase timeout as a *permanent* failure. When the parent fails to
confirm the published DS RRset within `confirm-timeout`,
`observeHardFail` fires — `last_rollover_error` is stamped on the
affected keys and the zone returns to idle, but
`last_ds_submitted_index_low/high` is left populated. The next idle
tick asks `kskIndexPushNeeded` whether a re-push is needed; the
comparison is against `LastSubmitted*`, not against any notion of
"what the parent actually has," so the answer is no. The zone is
stuck until an operator runs `auto-rollover unstick`.

This is operationally wrong for at least four reasons:

1. **Important infrastructure should be self-healing.** A KSK
   rollover that requires a human to nudge it past every parent-
   side hiccup will be a constant source of pages.
2. **The bookkeeping conflates "I tried" with "it worked."**
   `LastSubmitted*` records the fact that we sent an UPDATE and
   got rcode NOERROR. It does NOT record that the parent applied
   the update. Treating the two as equivalent is the root cause of
   the stuck state.
3. **Production cadences are slow.** Today's testbed runs a
   10-minute KSK lifetime to exercise the machinery quickly. Real
   production zones roll on a weekly cadence at fastest, monthly
   or quarterly is plausible. "Wait for the next rollover cycle to
   recover" — the implicit current behavior — could mean a week of
   no progress on a misconfigured parent.
4. **Status visibility is poor.** Today, an operator looking at
   `auto-rollover status` cannot tell whether the engine has given
   up forever or is about to retry in 30 seconds. The current
   `phase=idle` covers steady-state, post-success, and post-
   failure equally.

This doc redesigns the post-push state machine around three
principles:

- **Never permanently give up.** Critical infrastructure should
  retry forever, with monitoring-friendly cadence, until either
  the parent is fixed or an operator actively cancels the
  rollover.
- **Be loud about it.** Every transition into a non-happy state
  produces structured logs and exposes machine-readable state for
  monitoring. Status output makes the situation obvious in plain
  English.
- **Categorize failure.** "The parent didn't confirm" can mean
  several different things, requiring different operator actions.
  The state record captures which category, with as much
  protocol-level detail as the parent gave us.

## Goals (acceptance criteria)

1. After one attempt's observation budget expires without
   confirmation, the engine re-pushes automatically — no operator
   intervention required.
2. After `max-attempts-before-backoff` consecutive failed
   attempts, the engine enters a `parent-push-softfail` long-term
   mode, sending one probe UPDATE per `softfail-delay` window.
   The fail counter does NOT reset to a fresh group of N — long-
   term mode is genuinely long-term, one probe per window forever.
3. During the entire post-push lifecycle (initial flurry AND
   softfail long-term mode), polling for the expected DS RRset
   continues uninterrupted. If DS appears at any point, the
   engine transitions directly to confirmed.
4. The engine records the *category* and *detail* of each failure.
   Status output renders this as plain-English diagnosis with
   wallclock-aware timing.
5. The parent-side response always carries enough information for
   the child operator to diagnose. Specifically: rejected UPDATEs
   return REFUSED (not NOERROR), and attach an EDE option with a
   policy-specific message.
6. `unstick` becomes a narrow operator override ("retry now,
   don't wait the rest of the softfail-delay"), not a recovery
   workaround for an engine bug.

## Out of scope

- Push beyond observe to confirmed. Once DS is confirmed, the
  existing `confirmDSAndAdvanceCreatedKeysTx` flow advances keys
  to ds-published unchanged.
- Per-zone alerting policy. Monitoring (Prometheus,
  alertmanager, etc.) consumes the structured state and decides
  what to alert on.
- Multi-DS-algorithm rollover. Today's logic only emits SHA256 DS
  records. Unchanged.
- ZSK rollover. Still informational only.
- Auto-detecting `ds-publish-delay` from observation. Nice-to-
  have but error-prone — operator declares it.

## Constraint: testbed continuity

Project-wide policy is normally "no user base, no backwards
compat." For this work there is a narrow but firm exception: two
testbeds are running long-term frequent rollovers against the
current code. They must continue to work across the upgrade. Stop
daemon → install new binary → start daemon → resume should be
sufficient for the operator. Specifically:

- **DB schema migration is mandatory.** Existing rows on
  `RolloverZoneState`, `RolloverKeyState`, and `DnssecKeyStore`
  must survive the upgrade with their data preserved. New columns
  must be added via the existing `dbMigrateSchema` mechanism in
  [db.go:117](tdns/v2/db.go:117) — `ALTER TABLE ADD COLUMN` with
  `dbColumnExists` idempotency check.
- **In-flight rollovers must finish coherently.** A testbed that
  is mid-observe (phase=`pending-parent-observe`) when stopped
  must, after upgrade, continue from that phase and reach a
  sensible conclusion under the new logic. No phase-name
  mismatches, no orphaned state.
- **Config file YAML is NOT covered by this constraint.** The
  testbed operators are the developers themselves. They update
  YAML manually after the upgrade if they want to use the new
  `ds-publish-delay` / `max-attempts-before-backoff` /
  `softfail-delay` knobs. Until they do, defaults apply.

The schema additions in this doc are all NULL-or-zero-default
columns, which is benign for existing rows (no breaking change).
The single behavioral wrinkle is that Phase 2 alone (the gate
fix without Phase 4's softfail backoff) makes the engine retry
forever with no rate limit. For a testbed where the parent
periodically misbehaves, that's a regression. So Phase 2 and
Phase 4 should land **in the same release** to a testbed —
not Phase 2 in isolation. (Phase 2 alone is fine to *commit*; it
just shouldn't ship to a testbed without Phase 4 close behind.)

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

`ds-publish-delay` is the primary timing knob. It declares the
parent's expected publication cadence — the time between "we sent
the UPDATE and got NOERROR" and "the new DS RRset is observable on
the parent." Examples:

- A parent that publishes via direct DNS UPDATE pushes through to
  authoritative servers: ~5m. (Most modern setups.)
- A registry that batches publishes hourly (e.g. `.SE`): 1h.
- A registry with a daily publication cycle: 24h.

The name "ds-publish-delay" is somewhat a misnomer — for batched
parents this is more of a "publish cadence" than a delay. We're
keeping the name regardless; the field describes "how long should
we wait before getting concerned that the publication failed."

Everything else is derived (with optional explicit overrides for
operators who need them):

| Internal value     | Derivation                                        | Why                                                                    |
|--------------------|---------------------------------------------------|------------------------------------------------------------------------|
| `confirm-initial-wait` | always 2s                                     | Early polls are cheap and harmless                                     |
| `confirm-poll-max`     | clamp(`ds-publish-delay`/10, 30s, 5m)         | Don't poll faster than meaningfully new info can arrive                |
| `attempt-timeout`      | `ds-publish-delay × 1.2`                       | 20% safety margin beyond the parent's normal cycle before declaring fail |

These can be set explicitly in YAML to override the derivation if
needed (e.g. a known-bad parent where you want a tighter
attempt-timeout, or extremely chatty polling for testing). Default
behavior should be: operator sets only `ds-publish-delay`, the
rest follows.

## State machine

Phases (existing in **bold**, new phases <ins>underlined</ins>):

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
              |                                                      |
              | DS observed at any time                              |
              | (polling never stops)                                |
              +------------------------------------------------------+

  parent-push-softfail (long-term mode):
    on tick: if now >= next_push_at:
                send ONE probe UPDATE
                start observe phase with attempt-timeout budget
                next_push_at = now + softfail_delay
                stay in parent-push-softfail (do NOT enter a fresh
                group of max_attempts)
             observe-poll continues at confirm-poll-max cadence
             on confirmed observation: advance keys, reset state,
                go straight to idle (or pending-child-withdraw)
```

The crucial structural difference from earlier sketches:
**long-term mode is one probe per softfail-delay forever, not a
new group of max_attempts every softfail-delay.** Once we've
decided the parent is broken-for-now (by failing the initial
flurry), we don't re-try aggressively — we settle into a steady
hourly heartbeat that any monitoring system can pick up.

Push-attempt failures (transport, child-config, parent-rejected
returned synchronously) increment the same counter as observe
timeouts. They are not distinguished in retry behavior, only in
the recorded category.

Observe-poll failures *within a single attempt* (per-poll network
blip) do NOT increment `hardfail_count` — they are absorbed by
`scheduleNextObservePoll`'s exponential backoff. Only the cumulative
`attempt-timeout` cliff increments.

## Failure categorization

Every push attempt produces a categorized failure record. Four
categories the engine can distinguish:

| Category                | Trigger                                                                          | Operator action                                |
|-------------------------|----------------------------------------------------------------------------------|------------------------------------------------|
| `child-config`          | No active SIG(0) key for zone; no DS to publish; ParentZone unresolvable         | Fix child keystore / zone config               |
| `transport`             | "no route to host"; i/o timeout; conn refused; DSYNC lookup empty; DNS resolve fail | Network reachability / parent endpoint         |
| `parent-rejected`       | rcode REFUSED / NOTAUTH / FORMERR / SERVFAIL on UPDATE response (with EDE if any) | Fix parent (policy, delegation, allow-list)    |
| `parent-publish-failure`| rcode NOERROR but observe phase times out — DS never appeared                    | Investigate parent's update→publish path       |

The fourth category — `parent-publish-failure` — is the case that
bit us during the 2026-04-28 fast-roller debugging session. It is
distinct from `parent-rejected` because the parent's NOERROR
response is a wire-protocol commitment that the update was
accepted: a parent that wants to refuse the update is required to
return REFUSED (or some other negative rcode), not NOERROR. So if
we get NOERROR back and the DS never appears, the failure is
between the parent's accept and the parent's publication of the
updated RRset — *not* a hidden rejection. The cause might be a
broken parent-side update→publish pipeline, an internal queue
that dropped the change, an inconsistent provisioning chain, or a
parent-side policy bug that should have produced REFUSED but
didn't (see Phase 8 below — fixing that bug on tdns's parent side
is part of this work).

A single counter (`hardfail_count`) tracks failures of any
category. The category metadata is for operator visibility — *why*
each attempt failed — not for differentiated retry behavior. If
category changes between attempts (transport on attempt 3,
parent-rejected on attempt 4), that is itself information the
operator should see; it does not reset the counter.

## Persistent schema additions

New columns on `RolloverZoneState`:

```sql
hardfail_count          INTEGER DEFAULT 0,
next_push_at            TEXT,                  -- RFC3339 UTC, NULL = push allowed now
last_softfail_at        TEXT,
last_softfail_category  TEXT,                  -- one of the four enum values
last_softfail_detail    TEXT,                  -- "rcode=REFUSED EDE=18 'prohibited'" / "i/o timeout to ..."
last_success_at         TEXT,                  -- last time confirmed DS == target
last_attempt_started_at TEXT,                  -- start of the current/most recent attempt (for status display)
last_poll_at            TEXT,                  -- last parent-DS query (for status display)
-- next_poll_at already exists as observe_next_poll_at; reuse
```

`last_ds_submitted_index_low/high` stays populated for diagnostic
display in status output, but **stops being a gate input** to
`kskIndexPushNeeded`. The new gate is whether
`last_ds_confirmed_index_low/high` matches the current target.

`hardfail_count` resets to 0 on successful confirmation only —
not on entering softfail (long-term mode is a stable state, not
a fresh attempt group).

## kskIndexPushNeeded reformulation

Today:

```go
return int(row.LastSubmittedLow.Int64) != low ||
       int(row.LastSubmittedHigh.Int64) != high
```

After the fix:

```go
// Compare against confirmed (= what the parent actually has),
// not against submitted (= what we last tried to send). When
// these diverge — e.g. submitted populated but confirmed empty
// after a parent-side rejection — we still need to push.
if row == nil || !row.LastConfirmedLow.Valid || !row.LastConfirmedHigh.Valid {
    return true
}
return int(row.LastConfirmedLow.Int64) != low ||
       int(row.LastConfirmedHigh.Int64) != high
```

This is the single most important code change in the redesign.
Everything else flows from "compare against reality, not against
history."

## Polling during parent-push-softfail

Polling is **continuous from the moment of UPDATE through the rest
of the rollover lifecycle**, including all of softfail-delay
long-term mode. The poll cadence is `confirm-poll-max` throughout.

Concretely: after the initial flurry of 5 failed attempts, the
engine enters `parent-push-softfail`. Every `softfail-delay`
window (1h by default) it sends one probe UPDATE. Between probes,
parent-DS polls continue at the same cadence as during the initial
flurry. If the operator fixes the parent at any point — even
during the dead time between probes — the next poll picks up the
change and the engine transitions directly to confirmed. No probe
UPDATE required, no operator intervention required.

This is why polling is cheap and important: a couple of DNS queries
per minute against the parent costs nothing, and the auto-recovery
behavior it enables is the entire point of the design.

## Three example schedules

### Fast direct-publish parent (default config)

`ds-publish-delay = 5m`, `max-attempts-before-backoff = 5`,
`softfail-delay = 1h`. Internal: `attempt-timeout = 6m`,
`confirm-poll-max = 30s`.

```
T+0:00     UPDATE sent, rcode NOERROR
T+0:00–T+0:06   poll every ~30s, no DS observed
T+0:06     attempt 1 timeout (6m × 1.2) → re-push
T+0:06–T+0:12   poll, no DS
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
drumbeat thereafter. Total UPDATEs to a permanently broken parent:
5 in first 30 min + 1/hour ≈ 25/day.

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

Initial flurry takes 6h, which is in the right ballpark — if `.SE`
missed the update across 5 publish cycles, that is a real outage
worth alarming on. ~6 UPDATEs in first 6h, then 1/hour after.

### Operator fixes parent during softfail (auto-recovery)

`ds-publish-delay = 5m`, parent broken for ~2h, operator fixes at
T+2:00. The continuous polling picks it up immediately.

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

## Status output spec

Status output is the operator's primary diagnostic surface and
must make the engine's current intent obvious without code-diving.

### Always-first line: current time

The very first line of every `auto-rollover status` output:

```
Current time:     14:35:23 UTC (Wed Apr 29 2026)
```

Saves the operator running `date` in another window when comparing
status outputs taken minutes apart. Reference frame for everything
else.

### Steady state (happy path)

```
Current time:     14:35:23 UTC (Wed Apr 29 2026)
KSK rollover state for zone cpt.p.axfr.net.:
  status            OK — idle, in sync with parent
  last success      14:30:00 UTC (5m23s ago)
  next rollover     2026-04-29T15:30:00Z (in 54m37s)
  ds-publish-delay  5m
  ...
```

### Mid-attempt, within expected publish window

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

### Mid-flurry (one or more attempts have failed, retrying)

```
Current time:     14:42:11 UTC
KSK rollover state for zone cpt.p.axfr.net.:
  status            ACTIVE — retrying parent push
  phase             pending-parent-push
  attempts          3 / 5 in current group
  last failure      14:38:00 UTC (4m11s ago)
                    category: transport
                    detail:   i/o timeout to 2a01:3f0:1:2::63:53
  next attempt      14:42:11 UTC (in 0s)
  last poll         -
```

### Long-term softfail mode (broken parent, hourly probing)

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

- The first content line is always one of: `OK`, `ACTIVE`,
  `SOFTFAIL`. That word is the headline; everything else is
  supporting detail.
- Every state shows when the *next* engine-driven thing happens.
  No silent waits.
- Failure categories use the four enum values verbatim. Operators
  memorize four words.
- During any non-idle phase, the polling activity (`last poll` /
  `next poll`) is visible so the operator can see the engine is
  actively checking.
- The hint line collapses the timing math into plain English.
  Three hint variations:

| Condition                                | Hint                                                          |
|------------------------------------------|---------------------------------------------------------------|
| `elapsed < ds-publish-delay`             | "within expected publish window — polling continues"          |
| `elapsed > ds-publish-delay` but `< attempt-timeout` | "past expected publish time, polling continues — approaching timeout" |
| In softfail-delay long-term mode         | "parent fix will be auto-detected — polling never stops"      |

## Logging cadence

Per attempt (defaults):

- WARN on each individual failure: `"rollover: parent push failed
  (attempt N/M, category=X): detail"`
- WARN on entering softfail-delay long-term mode: `"rollover:
  initial flurry exhausted, entering softfail long-term mode
  (probe every 1h)"`
- INFO on each softfail probe attempt: `"rollover: softfail probe
  N (still failing, category=X)"`
- INFO on auto-recovery: `"rollover: parent recovered during
  softfail polling, advancing keys"`

Worst case (parent permanently broken, default config):

- 5 WARN lines in first 30 min
- 1 INFO line per hour thereafter (hourly probes)

= roughly 25 log lines per day per stuck zone. Manageable for log
volume; visible enough for grep-based ops.

For monitoring, a Prometheus-style metric (implementation out of
scope here):

```
tdns_rollover_softfail_zones_total{category="parent-publish-failure"} 1
tdns_rollover_softfail_attempts_total{zone="cpt.p.axfr.net."}         7
```

## Parent-side EDE work (parallel item, Phase 8)

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
`parent-publish-failure` case from the child's perspective, even
though the truth is "parent rejected on policy."

The fix:

1. Move the response write to *after* `ApproveUpdate`.
2. If `!us.Approved`, set rcode to REFUSED.
3. Attach an EDE option (`edns0.AttachEDEToResponse`) explaining
   the specific policy reason. The codebase already has
   `edns0.EDEZoneUpdatesNotAllowed`; we need at least three more:
   - `EDEZoneUpdateRRtypeNotAllowed` ("DS not in update-policy.rrtypes")
   - `EDEZoneUpdateOwnerOutsidePolicy` ("owner name violates self/selfsub")
   - `EDEZoneUpdateChildUpdatesNotAllowed` ("OptAllowChildUpdates false")
4. Keep the existing structured WARN logs on the parent side so
   the parent operator also sees the rejection.

With those changes, every UPDATE rejection arrives at the child
with a specific EDE message, the child records it as
`parent-rejected`, and the operator on the child side knows
exactly which knob on the parent needs attention. Crucially,
this collapses tdns-vs-tdns deployments out of the
`parent-publish-failure` category and into the much more
actionable `parent-rejected` category.

This work is parallel to the child-side state-machine redesign
and should land roughly together. Until both are in place,
tdns parents talking to tdns children will keep generating
`parent-publish-failure` for what are actually policy rejections.

## Narrowed role of `auto-rollover unstick`

After this redesign, `unstick` becomes a much narrower tool:

- **Old role:** the only way to recover from a stuck zone after
  `observeHardFail`. Operationally required.
- **New role:** an operator override that says "I just fixed the
  parent, please skip the rest of the softfail-delay and probe
  *right now*." Operationally optional — the engine will probe
  on its own when `next_push_at` elapses, and polling continues
  in the meantime so a fix is auto-detected regardless.

Implementation: `unstick` clears `next_push_at`. Next tick
advances out of softfail-delay immediately and sends one probe
UPDATE. The `last_softfail_*` columns and `hardfail_count` stay
populated for diagnostic continuity.

The CLI help text changes accordingly to make the narrowed role
clear: this is a "skip the wait" command, not a "fix a wedged
zone" command.

## Implementation phases

### Phase 1 — schema + data model

1. Add migration entries to the `migrations` slice in
   `dbMigrateSchema` ([db.go:117](tdns/v2/db.go:117)). One entry
   per new column, each `ALTER TABLE RolloverZoneState ADD COLUMN`
   with a NULL-safe default. The `dbColumnExists` check makes
   each entry idempotent — running migrations on a DB that has
   already been migrated is a no-op.
2. Update the canonical `CREATE TABLE RolloverZoneState` in
   `db_schema.go` to include the new columns, so fresh DBs get
   them at table-creation time without going through the
   migration code path.
3. Extend `RolloverZoneRow` struct in `ksk_rollover_zone_state.go`.
4. Update `LoadRolloverZoneRow` to read the new columns.
5. Add accessor functions: `setSoftfail`,
   `incrementHardfailCount`, `resetHardfailCount`,
   `setLastSuccess`, `setLastPoll`.
6. Build (no behavior change yet — pure additive schema).
7. Verify by pointing the binary at a copy of a testbed's
   `RolloverZoneState` table and confirming all existing rows
   load cleanly with NULL/0 in the new columns.

### Phase 2 — kskIndexPushNeeded reformulation

1. Change `kskIndexPushNeeded` to compare against
   `LastConfirmed*` instead of `LastSubmitted*`.
2. Add focused unit test.
3. At this point `observeHardFail` no longer leaves zones stuck:
   the next idle tick re-pushes naturally because confirmed
   still doesn't match target. This is "fix without the
   softfail machinery" — the engine will retry forever, with no
   backoff, on every tick. Not the long-term shape, but proves
   the gate fix is correct.

This phase is independently shippable as a pure correctness fix.

### Phase 3 — failure categorization

1. Define `RolloverFailureCategory` enum (string consts:
   `child-config`, `transport`, `parent-rejected`,
   `parent-publish-failure`).
2. Each push-failure path in `RolloverAutomatedTick` and
   `PushWholeDSRRset` records category + detail via
   `setSoftfail`.
3. `observeHardFail` records `parent-publish-failure`.

### Phase 4 — softfail phase + counter logic

1. Add `rolloverPhasePushSoftfail = "parent-push-softfail"`.
2. Wire transitions:
   - On any push or observe failure, increment `hardfail_count`
     and record category/detail.
   - If `hardfail_count >= max_attempts_before_backoff`: set
     `next_push_at = now + softfail_delay`, transition to
     `parent-push-softfail`. Do NOT reset `hardfail_count`.
   - Otherwise: transition straight back to
     `pending-parent-push` (immediate retry).
3. Add tick handler for `parent-push-softfail`:
   - If `now >= next_push_at`: send ONE probe UPDATE, restart
     observe with `attempt-timeout` budget, set
     `next_push_at = now + softfail_delay`. Do NOT enter
     pending-parent-push as a fresh group.
   - Polling continues at `confirm-poll-max` cadence regardless.
4. On any successful confirmation, reset `hardfail_count` to 0
   and stamp `last_success_at`.
5. Apply small per-zone jitter (±5 min) to `next_push_at` to
   avoid thundering-herd against a shared parent.

### Phase 5 — config wiring

1. Add `DsPublishDelay`, `MaxAttemptsBeforeBackoff`, `SoftfailDelay`
   to `RolloverPolicy`.
2. YAML parsing for the new fields.
3. Defaults: `DefaultDsPublishDelay = 5*time.Minute`,
   `DefaultMaxAttemptsBeforeBackoff = 5`,
   `DefaultSoftfailDelay = time.Hour`.
4. Compute derived values:
   `attemptTimeout = dsPublishDelay * 12 / 10`,
   `pollMax = clamp(dsPublishDelay/10, 30s, 5m)`.
5. Validation:
   - `max-attempts-before-backoff >= 1`
   - `softfail-delay >= ds-publish-delay`
   - explicit `attempt-timeout` (if set) `>= ds-publish-delay`

### Phase 6 — status output overhaul

1. Restructure `auto-rollover status` rendering per the spec
   above.
2. Add the "current time" first line.
3. Add the headline word (`OK` / `ACTIVE` / `SOFTFAIL`)
   computation.
4. Add the `expected by` / `attempt timeout` / `last poll` /
   `next poll` lines for ACTIVE.
5. Add the `next probe` line for SOFTFAIL.
6. Add the hint computation logic.
7. Test against the canonical states from the spec.

### Phase 7 — narrowed unstick

1. Reimplement `UnstickRollover` to clear `next_push_at` (only).
2. CLI help text update — narrowed role.

### Phase 8 — parent-side EDE (parallel)

This phase is independent of phases 1-7 and can land in parallel.

1. Move response write in `updateresponder.go` to after
   `ApproveUpdate`.
2. Set REFUSED rcode on `!us.Approved`.
3. Add new EDE codes.
4. Attach EDE in each rejection branch of `ApproveAuthUpdate`
   and `ApproveChildUpdate`.
5. Verify with a targeted test that a policy-rejected UPDATE now
   returns REFUSED + EDE on the wire.

### Phase 9 — cleanup

1. Remove `observeHardFail` (semantics no longer apply).
2. Remove unused `last_rollover_error` write paths if any.
3. Audit `LastSubmitted*` references; demote to diagnostic-only.

## Risks / open questions

1. **Per-zone lock granularity.** `RolloverAutomatedTick` does
   not currently hold a lock; concurrent CLI writes can race. The
   CLI/API redesign companion doc introduces a per-zone mutex.
   The softfail redesign assumes that lock exists — without it,
   a CLI `unstick` running concurrently with a tick advance can
   stomp on `next_push_at`. The two redesigns should land in
   compatible order: the CLI/API doc's Phase 1 (lock) before
   this doc's Phase 4.

2. **Forever-loop log volume on truly-broken parents.** With
   default config, a permanently broken parent generates ~25
   log lines per day per zone forever. For an environment with
   many zones this scales into thousands. Mitigation: the
   monitoring metric is the primary alerting signal, not log
   greps.

3. **Operator override for slow parents that don't know their
   own delay.** If an operator misconfigures `ds-publish-delay`
   too low (e.g. 5m for a parent that actually takes 1h), every
   rollover will declare softfail at minute 30 even when
   nothing is wrong. There is no good auto-detection — the
   error mode is operator misconfiguration, surfaced via the
   stuck-zone metric. Documenting `ds-publish-delay` clearly
   in the YAML config reference is important.

## Estimated effort

Single developer, careful incremental commits:

- Phase 1 (schema + data): half a day
- Phase 2 (gate fix): one to two hours, big payoff
- Phase 3 (categorization): half a day
- Phase 4 (softfail phase + counter): one day
- Phase 5 (config wiring): half a day
- Phase 6 (status output): half a day
- Phase 7 (narrowed unstick): one to two hours
- Phase 8 (parent-side EDE): half a day, parallel
- Phase 9 (cleanup): one to two hours

Total: roughly 4 days of focused work, parallelizable across
phases 1-7 and 8.

Each phase is one or two commits, cherry-pickable across the
fast-roller branches once the work is complete on
`fast-roller-1`. Phase 2 alone is a real correctness fix that
could ship ahead of the rest if circumstances demand it — it
removes the stuck-zone deadlock without yet adding the softfail
backoff machinery.

[cli-redesign]: 2026-04-28-rollover-cli-api-redesign.md
