# Testing Phase 4A: Automated Multi-DS Pipeline

**Status**: Draft
**Date**: 2026-04-24
**Scope**: How to exercise the Phase 4A implementation of the KSK
rollover project end-to-end against a real parent.
**Related**: `2026-04-23-automated-ksk-rollover.md` (design spec) —
this document assumes familiarity with §5 (policy), §6 (DS push),
§7 (parent confirmation), and §8 (worker tick).

## 1. What 4A Actually Exercises

Phase 4A implements the **pre-publication pipeline** end-to-end for
multi-DS rollover:

- Pipeline fill: keep `num-ds` SEP keys alive in the keystore
- Whole-RRset DS push to parent, SIG(0)-signed via DSYNC UPDATE target
- Confirmation via parent-agent DS query (§7.2 exponential backoff,
  §7.5 match algorithm)
- Two-range bookkeeping: submitted vs. confirmed (§6.1)
- Key-state advance `created → ds-published` (transactional, §9.4)
- Time-based advance `ds-published → standby` after
  `kasp.propagation_delay`
- Bootstrap promotion `standby → active` when no active SEP key
  exists

Testing 4A in anger surfaces issues that unit tests cannot: parent
misbehavior, propagation timing, SIG(0) key lifecycle, DSYNC
configuration, and the worker's handling of partial failures.

## 2. Topology

Minimum viable setup: two cooperating `tdns-authv2` processes plus
an IMR the child can use to look up the parent's DSYNC target and
to query parent-agent DS.

```
  child.example.  ─── signed by tdns-auth (rollover machinery)
                   │
                   │  DS UPDATE (SIG(0))  ─────▶  DSYNC UPDATE target
                   ▼
  example.        ─── signed by a separate tdns-auth (or any
                       authoritative server that supports accepting
                       SIG(0) DS updates and publishes DSYNC at the
                       delegation point)
```

Both zones served over localhost on different ports works fine.
The IMR needs to find both zones — either put stub delegations in
the IMR's config pointing at the right ports, or run IMR in a mode
that trusts the local zones.

A single-host lab, a pair of NetBSD VMs, or two separate hosts all
work. This document does not prescribe the lab topology; only the
behavior to look for.

## 3. Parent-Side Preconditions

Phase 4A assumes these; none of them are created or bootstrapped by
the rollover worker. §3.8 of the design spec lists the failure-mode
matrix if any is missing.

1. **Parent serves the parent zone** with a DSYNC RR published at
   the child delegation point, pointing at an UPDATE receiver:
   ```
   _dsync.example.  IN DSYNC  DS dns <port> <update-target>.
   ```
2. **Parent has the child's SIG(0) KEY** — either published under
   the agreed transport name in the child zone, or bootstrapped
   through the mechanism in
   `2026-03-07-delegation-sync-refresh-plan.md`.
3. **Parent authorizes the child's SIG(0) key** to modify the DS
   RRset at the child's delegation point. (Same delegation-sync
   machinery.)
4. **Parent-agent is resolvable and query-answering** — whoever
   the child is configured to ask for the DS RRset. For a first
   test, pointing `parent-agent` at the parent's own authoritative
   server is the simplest choice.

If any of these are missing, the worker will hard-fail or retry
cleanly per §3.8, but you'll learn more from exercising the
happy path first and then intentionally breaking each precondition.

## 4. Child-Side Configuration

Write a DNSSEC policy for the child zone. Keep `margin` and
`confirm-timeout` short for testing; production values would be
longer.

```yaml
dnssec-policies:
  multi-ds-test:
    mode:             ksk-zsk
    algorithm:        ECDSAP256SHA256
    ksk:
      lifetime:       24h
      sig-validity:   12h
    zsk:
      lifetime:       24h
      sig-validity:   12h
    rollover:
      method:         multi-ds
      num-ds:         3
      parent-agent:   parent-ns.example:53    # where child queries DS
      confirm-initial-wait: 2s
      confirm-poll-max:     60s
      confirm-timeout:      5m   # 1h is default; short for testing
      dsync-required:       true
    ttls:
      dnskey:         2h
    clamping:
      enabled:        true
      margin:         15m
```

Note on `lifetime: 24h`: 4A does not yet run scheduled
`atomic_rollover` (that's Phase 4B), so the lifetime value is recorded
but does not drive behavior yet.

Note on `clamping`: the parser accepts these fields, but 4A does
not yet wire clamping into the signing path. `clamping.enabled:
true` is safe to set now and will take effect when Phase 4D lands
`ComputeNextClampBoundary`.

Also adjust the global `KaspConf` so the `ds-published → standby`
transition runs on a testable timescale:

```yaml
kasp:
  propagation_delay: 30s
  check_interval:    10s
```

`propagation_delay` is what
`TransitionRolloverKskDsPublishedToStandby` waits for after the DS
is observed at the parent. `check_interval` controls how often the
`KeyStateWorker` (and thus the rollover tick) fires. Short values
make the pipeline observable in real time; production values would
be minutes to hours.

Finally, assign the named policy to the child zone in its zone
config.

## 5. Expected Happy-Path Sequence

Start `tdns-authv2` on both the parent and child sides. Tail the
`lgSigner` output on the child. The expected sequence, roughly in
order:

**1. Pipeline fill** (a few seconds after startup):
```
rollover: generated pipeline KSK  zone=child.example. keyid=<N>
```
Repeated up to `num-ds = 3` SEP keys in state `created`. If the
zone had no KSKs at startup, all three begin in `created`.

**2. Arming DS push** (next worker tick):
```
rollover: arming DS push  zone=child.example.
```
Phase transitions `idle → pending-parent-push`. No push on this
tick — arming counts as the advance.

**3. DS UPDATE sent** (next tick):
```
rollover: DS UPDATE accepted, arming observe  zone=child.example. first_poll_at=...
```
The whole DS RRset is constructed from the keystore, signed with
the child's active SIG(0) key, and sent. On NOERROR, the observe
schedule is armed with `first_poll_at = now + confirm-initial-wait`
(default 2s).

**4. Parent-agent DS query** (after `confirm-initial-wait` elapses):
On successful match:
```
rollover: parent DS observed, advanced created keys  zone=child.example. advanced=3
```
Every SEP key whose `rollover_index` is in the confirmed range
advances `created → ds-published` in one transaction. Phase resets
to `idle`. Observe schedule clears.

If the parent hasn't published yet, the query returns no match;
`observe_next_poll_at` doubles (2s → 4s → 8s → … capped at
`confirm-poll-max`).

**5. Propagation wait** (`kasp.propagation_delay` after
observation):
```
rollover: ds-published→standby  zone=child.example. keyid=<N>
```
SEP keys in `ds-published` advance to `standby` once
`now - ds_observed_at >= propagation_delay`.

**6. Bootstrap activation** (if the child had no active SEP key):
```
rollover: promoted standby KSK to active (no active KSK)  zone=child.example. keyid=<N>
```
The lowest-keytag standby SEP key becomes active. From this point
the child zone is signed by this KSK.

**7. Steady state.** Nothing further happens in 4A. The pipeline
has three KSKs: one active, two standby (or in whichever mix the
propagation timer produced). Advancing the active KSK to retired
and bringing the next standby into active is Phase 4B's `atomic_rollover`
and is NOT exercised here.

## 6. Database Inspection

State lives in the sqlite keydb. These queries reveal what the
worker is doing at any moment.

**Key states:**
```sql
SELECT zonename, keyid, flags, state
FROM DnssecKeyStore
WHERE zonename = 'child.example.';
```
Expect: SEP-flagged keys (flags = 257) in `created`, then
progressing through `ds-published`, `standby`, `active`.

**Per-key rollover bookkeeping:**
```sql
SELECT zone, keyid, rollover_index, rollover_method,
       rollover_state_at, ds_submitted_at, ds_observed_at,
       last_rollover_error
FROM RolloverKeyState
WHERE zone = 'child.example.';
```
Every new SEP key should have a monotonically increasing
`rollover_index`. `ds_observed_at` is set when the parent confirms.
`last_rollover_error` should be NULL on a healthy run.

**Per-zone rollover coordination:**
```sql
SELECT zone,
       last_ds_submitted_index_low, last_ds_submitted_index_high,
       last_ds_confirmed_index_low, last_ds_confirmed_index_high,
       rollover_phase, rollover_phase_at,
       observe_started_at, observe_next_poll_at, observe_backoff_seconds
FROM RolloverZoneState
WHERE zone = 'child.example.';
```
- Submitted range: what the child has pushed to the parent.
- Confirmed range: what the parent is observed to hold.
- `rollover_phase`: current position in the §8.8 sub-phase machine.
- Observe-schedule fields: only populated while phase is
  `pending-parent-observe`; cleared when phase returns to `idle`.

**Parent DS (from the child's perspective):**
Issue a manual query from any DNS tool:
```
dig +dnssec DS child.example. @<parent-agent>
```
Compare the answer RRset keytags against the child's
`RolloverKeyState.rollover_index` column. The match is what the
worker's observe phase checks.

## 7. Error-Path Tests

These matter at least as much as the happy path. Each exercises a
specific design decision in §3.5 (failure and recovery), §3.8
(preconditions), §7.2 (backoff), or §9.4 (two-store consistency).

### 7.1 Parent that NOERRORs but never publishes

Point `parent-agent` at an NS that does not have the child's DS
RRset (or run a stub that swallows UPDATEs). Keep
`confirm-timeout: 5m` so you see the failure quickly.

Expected behavior:
- DS push succeeds (NOERROR).
- Observe phase enters; backoff schedule runs: 2s, 4s, 8s, 16s,
  32s, 60s, 60s, ...
- After 5m (`confirm-timeout`), hard-fail:
  ```
  rollover: DS observation timed out; keys marked with last_rollover_error ...
  ```
- Each waiting SEP key has `last_rollover_error` set to an
  explanatory message.
- Zone phase resets to `idle`.

This exercises the §7.2 + §3.5 fix from the Phase 4A review.

### 7.2 Missing SIG(0) key

Delete the child's active SIG(0) key before (or during) the first
DS push.

Expected:
- `PushWholeDSRRset` fails cleanly (logged warning).
- Phase stays at `pending-parent-push`.
- Worker retries on next tick — still fails, same log.
- When the SIG(0) key is restored, the next tick succeeds and the
  observe schedule arms.

This exercises the SIG(0)-signing precondition (§3.8 R1).

### 7.3 DSYNC absent

Remove the DSYNC RR from the parent's zone while `dsync-required:
true`.

Expected:
- `PushWholeDSRRset` returns an error (DSYNC lookup returns
  NXDOMAIN or empty).
- Phase stays at `pending-parent-push` and retries each tick.
- Flip `dsync-required` to `false`, restart: worker logs and skips
  the zone on each tick without error.

This exercises §3.8 R3 (DSYNC-required fail-closed vs. retry).

### 7.4 DSYNC with non-UPDATE scheme

Publish a DSYNC that advertises a non-UPDATE scheme (e.g. `https`).

Expected:
- DSYNC lookup succeeds in the sense that records are returned.
- `PushWholeDSRRset` finds no usable UPDATE target and returns
  an error.
- Worker keeps retrying — this is a hard-fail class per §3.8 R4
  in the design, but 4A's implementation treats it as a transient
  retry. Worth noting and possibly flagging for Phase 4B's hard-fail
  handling (the precondition matrix in design-doc §3.8 says this
  should be a hard-fail; 4A treats it as a transient retry).

### 7.5 Foreign DS at parent

Inject a DS RR at the parent's delegation point whose keytag does
not match any of the child's managed keys. The match algorithm
(§7.5) says foreign DS records must be tolerated, not used as a
match failure.

Expected:
- Observe match succeeds as long as the child's expected DS RRs
  are all present.
- Child does NOT attempt to "clean up" the foreign record via
  subsequent UPDATE. (4A's target set is derived from the
  keystore only; foreign records are ignored by construction.)

This is a correctness test for §7.5, not a failure test.

### 7.6 Multiple digest types per key

Publish both SHA-256 and SHA-384 DS records at the parent for the
same keytag. Expected DS set from the child uses SHA-256 (default).

Expected:
- Match succeeds. The additional SHA-384 DS is foreign-by-digest
  and must not fail the match.
- No code-level support exists in 4A for the child to publish
  multiple digest types per key. That's a policy enhancement for
  later.

### 7.7 Restart mid-phase

Kill the child process during `pending-parent-observe` (before the
match is observed). Start it again.

Expected:
- Worker reads `rollover_phase = pending-parent-observe` from
  `RolloverZoneState`.
- `observe_started_at`, `observe_next_poll_at`,
  `observe_backoff_seconds` are persisted — polling resumes at
  the next scheduled poll time (or immediately if it's elapsed).
- If total elapsed since `observe_started_at` exceeds
  `confirm-timeout`, hard-fails on the first tick post-restart.

Restart-safety is a primary design goal (§12 R2). This test
exercises it.

### 7.8 Crash during observation match

Harder to test without code injection, but valuable: simulate a
crash between `saveLastDSConfirmedRangeTx` and
`UpdateDnssecKeyStateTx` inside
`confirmDSAndAdvanceCreatedKeysTx`. The transaction should roll
back; no change should be visible. On restart, the next tick
should re-query, re-match, and re-advance — the whole sequence
idempotently.

This exercises §9.4 two-store consistency. A panic-injection test
inside the TX would be the clean way to verify it.

## 8. What 4A Does NOT Let You Test

Be explicit about scope so you don't spend time looking for
behavior that isn't there yet.

- **Scheduled rollover.** `rollover_due()` time-based trigger is
  Phase 4B. The KSK `lifetime` value in policy is persisted but
  not acted on.
- **`atomic_rollover(z)`.** Phase 4B. There is no automatic
  `active → retired` transition in 4A. The bootstrap promotion is
  the only `standby → active` path; once a KSK is active, it
  stays active.
- **`pending-child-publish` / `pending-child-withdraw` phases.**
  Phase 4B. 4A implements only `idle`, `pending-parent-push`, and
  `pending-parent-observe`. The full §8.8 five-phase machine is 4B.
- **`rollover_in_progress` flag.** Phase 4B. The column exists,
  but 4A never sets or clears it. Import-during-rollover protection
  (§15.6) is therefore not active yet.
- **Manual-ASAP CLI** (`rollover when`, `rollover asap`, `rollover
  cancel`). Phase 4C. Also `rollover status` and `rollover reset`
  are 4C.
- **`ComputeEarliestRollover`.** Phase 4C.
- **Clamping effect on published RRSIGs and TTLs.** Phase 4D. The
  `clamping` policy subtree parses cleanly, but no code consults
  it yet. Clamping-enabled zones still publish the operator-
  configured TTLs and RRSIG validity verbatim.
- **Double-signature method.** Phase 4E. `method: double-signature`
  is valid config but `RolloverAutomatedTick` early-returns on it.
- **Import workflow.** Phase 5. `rollover import` CLI does not
  exist.

## 9. Useful Log-Filter Examples

The rollover machinery logs via `lgSigner` with structured fields.
Useful grep patterns when tailing:

```
rollover:                        # all rollover events for this zone
rollover.*pipeline               # key generation
rollover.*DS push                # submissions
rollover.*parent DS observed     # successful confirmations
rollover.*timed out              # hard-fail events
rollover.*arming                 # phase transitions
```

If running multiple zones, add `zone=<name>` to filter.

## 10. Test Scenario Matrix

Suggested order for a first-time walk-through:

| # | Scenario                     | Expected outcome             | Design reference |
| - | ---------------------------- | ---------------------------- | ---------------- |
| 1 | Happy-path end-to-end        | pipeline → active in ~30–60s | §5 in this doc   |
| 2 | Restart during observe       | Resumes at persisted poll    | §7.7             |
| 3 | Parent never publishes       | Hard-fail after 5m           | §7.1             |
| 4 | Missing SIG(0) key           | Retry loop until restored    | §7.2             |
| 5 | DSYNC absent                 | Retry loop; skip if !required | §7.3            |
| 6 | Foreign DS at parent         | Match succeeds, ignored      | §7.5             |
| 7 | Manual `RolloverKey` CLI     | Keystore changes, observe what worker does | §2 of spec |

Checking off 1–4 gives confidence the core mechanism is sound;
5–7 exercise edge cases.

## 11. Next Steps After Testing

If 4A holds up under this matrix:

- Identify any test gaps (R-reset semantics, foreign-DS digest
  variants, multi-digest-per-keytag) that the Phase 4A review
  flagged and consider adding unit tests.
- Document any parent behaviors you observed that the design did
  not anticipate — those are candidates for Phase 4B scope adjustment.
- Decide whether to start on Phase 4B (scheduled rollover backbone:
  `atomic_rollover` + child-side phases + scheduled trigger), or
  let 4A soak. Subsequent sub-phases (4C manual-ASAP CLI, 4D clamp
  wiring, 4E double-signature) build on 4B; see design doc §11
  "Phase 4 breakdown" for ordering and dependencies.

If 4A breaks:

- File issues tied to specific §§ of the design doc.
- Revisit the §3.8 precondition matrix — a "broken" run often
  indicates a missing precondition rather than a worker bug.
