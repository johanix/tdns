# Recovery: runaway 'created' KSKs (C29 hotfix)

## Symptom

`auto-rollover status --ksk` lists thousands of KSKs in state `created`. The
parent DS push fails with `dns: buffer size too small` and the zone is
stuck in `parent-push-softfail`. New `created` keys are added at roughly
the rate `key_state_worker` ticks (~1/sec).

```
SELECT state, COUNT(*) FROM DnssecKeyStore
WHERE zonename = '<zone>.' AND (CAST(flags AS INTEGER) & 1) != 0
GROUP BY state;
```

If `created` is in the thousands and other states are at their expected
levels (1 active, 0..1 standby, a few retired/removed) — this is the
condition.

## Root cause

C27 (`num_ds = DS at parent`, strict semantic) made
`CountKskWithDSAtParent` exclude `created` from the pipeline-fill count.
This is correct for the steady-state design (parent always holds N DS
records; engine maintains N+1 keys total, the +1 being the in-flight
`created` key).

But the pipeline-fill loop in `rolloverAutomatedForZone` only checked
this count. When DS publication is stalled (parent NOTIFY softfail,
parent unreachable, CDS-RRset too large to send, etc.), the in-flight
`created` key never advances to `ds-published`, the count stays at N-1,
and every tick generates another `created` key. The loop has no upper
bound.

C29 fixes this by adding a hard cap on total pipeline depth
(`CountKskInPipeline`, including `created`) at `num_ds + 1`.

## Recovery procedure

1. Stop tdns-authv2 on the affected node so the pipeline-fill loop
   doesn't keep generating keys while you clean up.

   ```
   service tdns-authv2 stop
   ```

2. Identify the cutoff time. The last successful rollover's `active_at`
   is the boundary; everything generated after that is the runaway.

   ```sql
   SELECT keyid, active_at, rollover_state_at
   FROM RolloverKeyState
   WHERE zone = '<zone>.' AND active_at IS NOT NULL
   ORDER BY active_at DESC LIMIT 5;
   ```

3. Purge the runaway `created` keys. Use the cutoff from step 2 (call it
   `<cutoff>`):

   ```sql
   -- Audit first — confirm the count matches what you expect.
   SELECT COUNT(*) FROM DnssecKeyStore
   WHERE zonename = '<zone>.' AND state = 'created'
     AND keyid IN (
       SELECT keyid FROM RolloverKeyState
       WHERE zone = '<zone>.' AND rollover_state_at > '<cutoff>'
     );

   -- Then purge.
   BEGIN;
   DELETE FROM DnssecKeyStore
   WHERE zonename = '<zone>.' AND state = 'created'
     AND keyid IN (
       SELECT keyid FROM RolloverKeyState
       WHERE zone = '<zone>.' AND rollover_state_at > '<cutoff>'
     );
   DELETE FROM RolloverKeyState
   WHERE zone = '<zone>.'
     AND keyid NOT IN (
       SELECT keyid FROM DnssecKeyStore WHERE zonename = '<zone>.'
     );
   COMMIT;
   ```

   The second DELETE removes orphaned `RolloverKeyState` rows for keys
   that are now gone from `DnssecKeyStore`. (`RolloverKeyState` rows for
   `removed` keys are intentionally retained as audit trail; only those
   matching purged-runaway keys are removed.)

4. Clear the parent-push softfail state so the engine immediately
   re-evaluates after restart:

   ```sql
   UPDATE RolloverZoneState
   SET rollover_phase = 'idle',
       rollover_in_progress = 0
   WHERE zone = '<zone>.';
   ```

5. Restart tdns-authv2. Verify with `auto-rollover status --ksk` that
   the pipeline shows the expected N+1 keys (one `created` if the
   engine is mid-pipeline-fill, plus N across `ds-published`,
   `published`, `standby`, `active`, `retired`).

## Why this is a hotfix, not a long-term concern

C29 prevents the runaway from happening on any future C27+ deployment.
The cap is a safety net; the design intent is unchanged. Operators with
healthy parent-publication paths will never observe the cap engaging —
the `created → ds-published` transition keeps the pipeline moving and
total stays at exactly `num_ds + 1`.
