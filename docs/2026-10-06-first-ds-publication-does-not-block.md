# The first DS publication does not block a KSK algorithm change

**Date:** 2026-10-06. Based on main `c062eb92`.
**Status:** implemented in #900 (branch `fix/policy-change-insecure-delegation`).

## 1. Problem

A zone signed under a multi-DS auto-rollover policy, with one active KSK
(lifetime `forever`) and **no DS at its parent**: an insecure delegation.
Validators may still trust the zone through a configured trust anchor.

The KSK rollover engine's idle branch (`RolloverAutomatedTick`,
`v2/ksk_rollover_automated.go`) sees a target DS set with no confirmed range
and starts the first DS publication: `pending-parent-push` (CDS and/or UPDATE,
NOTIFY(CDS)), `pending-parent-observe`, and after
`max-attempts-before-backoff` failures `parent-push-softfail`, probing and
polling from then on. `rollover_in_progress` stays false and no `alg_roll_*`
column is set.

That loop is correct and stays: the zone keeps asking for a DS at the parent.
But it never ends, and every rollover gate read "phase not idle" as "a
rollover is in progress":

1. `changeZonePolicy` refused a KSK algorithm change ("a KSK rollover is
   already in progress ... (phase pending-parent-observe)").
2. `syncZoneDnssecPolicyFromConfig` skipped a config-driven policy apply,
   logging at debug level only.
3. The engine spawned a KSK algorithm roll only from `idle`, which this zone
   never reaches.
4. Even once spawned, the roll would wait for the parent to serve DS(new)
   (`ObservedDSSetMatchesExpected` is false for an empty answer) and its
   withdraw step would hold without a parent DS TTL. It would end in softfail
   with two active KSKs.

## 2. The non-blocking state

`firstDSPublicationWithoutParentDS(row)` (`v2/ksk_rollover_parent_no_ds.go`)
is true when all of these hold:

- `rollover_in_progress` is false;
- no algorithm roll is recorded (`alg_roll_from_alg` is NULL);
- the phase is `pending-parent-push`, `pending-parent-observe` or
  `parent-push-softfail`;
- the engine's own last parent DS poll (`QueryParentAgentDS`, recorded by
  `setLastDsObserved`) returned no DS records: `last_ds_observed_at` is set
  and `last_ds_observed_keyids` is the empty string;
- no DS set has ever been confirmed at the parent (`last_ds_confirmed_*`
  NULL, `dsRangeEverConfirmed`).

A zone that has never polled does not qualify; it has learned nothing about
its parent. A DS push to a parent that does hold DS for the zone (multi-DS
pipeline maintenance, say) does not qualify either and still blocks: the
parent is part way through taking a DS set the zone has committed to.

Nor does a zone whose parent once held DS for it and no longer does (a
withdrawn DS, while the engine pushes a changed DS set). Validators may still
have that DS cached, for up to the parent DS TTL, and no poll of the parent
can see their caches: an insecure roll from there would remove the old KSK
on a margin that does not cover them. Such a zone keeps blocking as before;
see §11.

"No DS at the parent" is judged only from the engine's own parent-agent poll.
There is no validated (IMR) check of insecurity in this change.

## 3. Gates

`kskRolloverPolicyChangeBlock(zone, row)` returns `""` for idle and for the
non-blocking state, and otherwise a sentence saying what the engine is doing:

- a rollover of the zone's own (or an algorithm roll) in progress: the phase
  and what the engine waits for in it (DNSKEY propagation, the parent's
  publication, the drain before removal);
- a DS push to a parent that holds DS: the phase, and which key tags the
  parent served at the last poll;
- a DS push to a parent that served no DS at the last poll but held DS
  before: that, and that validators may still have the old DS cached;
- a DS push that has not polled the parent yet: that, and when the first poll
  is due, with the hint that a parent without DS is accepted once a poll has
  shown it.

Both policy paths use it:

- `changeZonePolicy` refuses with
  `change-policy: cannot change the KSK algorithm yet: <reason>`. When the
  zone is in the non-blocking state, the bind message says that the parent
  held no DS at the last poll and what the roll will do instead.
- `syncZoneDnssecPolicyFromConfig` skips only when the helper returns a
  reason, and now logs the skip at info level with the reason (it runs once
  per config load or reload, not per refresh).

`changeZonePolicy` now holds the per-zone rollover lock (`AcquireRolloverLock`,
the lock both rollover ticks take) from reading the current binding to the
end of the bind, so neither a tick nor a second change-policy can move the
zone out of the state the gate admitted. The lock is released before the
bind-time DSYNC lookup.

`policy-set` is not gated. It is the emergency escape hatch, by design.

## 4. The spawn

The tick now evaluates the algorithm-roll trigger (`kskAlgRollNeeded`) from
idle **or** from the non-blocking state. `SpawnKskAlgRollover` re-reads the
same fields inside its transaction (`loadRolloverSpawnStateTx`) and refuses
any other non-idle phase. From the non-blocking state it ends the first DS
publication in the same transaction (`endFirstDSPublicationTx`): the observe
schedule, `hardfail_count`, `next_push_at` and the `last_softfail_*` context
are cleared. Otherwise the roll's first push would inherit a hardfail count at
the backoff threshold and a probe time already due.

### The insecure-roll decision

The spawn records, once, whether the roll starts against a parent with no DS
(`kskAlgRollStartsInsecure`, persisted as `alg_roll_parent_insecure`):

- true from the non-blocking state (which itself requires that no DS range
  was ever confirmed);
- true from idle when the last poll showed no DS **and** no DS range has ever
  been confirmed (`last_ds_confirmed_*` NULL). This is the zone between the end of
  an earlier insecure roll and the tick that re-arms its first DS publication;
  a bind landing in that window must not start a roll that waits for the
  parent;
- false otherwise.

Deciding at the spawn, never later, is what keeps a transient empty answer
during a **secure** roll (a lagging parent nameserver) from ever being read as
an insecure delegation.

## 5. Step rules for an insecure roll

All child-side steps and waits are unchanged: the new KSK is minted into
active, the DNSKEY RRset is double-signed, the roll waits propagation-delay
plus the served DNSKEY TTL before the push, and the old KSK is drained before
removal. There is no immediate key swap.

| Step | Insecure roll | Ordinary roll |
|---|---|---|
| push | unchanged: target {DS(new)}, CDS and/or UPDATE, NOTIFY(CDS); the parent may ignore it | same |
| observe (`pending-parent-observe`, and the poll in `parent-push-softfail`) | answer with no DS: the parent step is confirmed through the ordinary confirm (`confirmDSAndStartOldHeadDrainTx`) into `pending-child-withdraw`; answer with any DS: the flag is cleared and the roll continues as an ordinary one | waits for {DS(new)} with DS(old) gone |
| withdraw | margin of §6, no parent DS TTL needed; one parent poll before any removal (§5.1) | parent-DS-TTL margin, holds until the TTL is known |

The insecure confirm differs from the ordinary one in what it records:

- the confirmed range is **cleared**, not saved, and no created key advances:
  the parent has confirmed nothing. An insecure roll only starts with no
  confirmed range, and gets none while it stays insecure, so this keeps it
  NULL rather than changing anything. With no confirmed range, the idle
  branch arms the first DS publication for the new KSK once the roll is done
  (§8);
- `last_success_at` is left alone;
- the hardfail count, softfail context and `next_push_at` are cleared, as at
  any confirm;
- the CDS the roll's push published is **not** withdrawn (§7).

Clearing the flag is one way. `clearKskAlgRollParentInsecure` sets it to 0;
an answer without DS later in the roll does not set it back. From then on the
roll waits for the parent to serve only DS(new) and drains for the parent DS
TTL, exactly as a roll that started secure.

The softfail branch applies the same observe rule to the poll it makes
anyway, so an insecure roll whose push the parent never takes (no usable
DSYNC scheme, for instance) still completes.

### 5.1 The check before removal

The insecure drain assumes there is still no DS at the parent. A DS that
appears after the confirm, for instance the old KSK's DS from the first DS
publication's request, taken late, would point resolvers at the key about to
go. So when the drain is over and a removal is due, the withdraw step polls
the parent once more (`insecureWithdrawMayProceed`), the way the observe step
does, and records the answer the same way. The drain itself makes no queries.

- **No DS:** the removal goes ahead.
- **The poll fails** (error, timeout), or no parent-agent is configured: the
  roll holds this tick and asks again on the next. Nothing is removed.
  A status warning names a missing parent-agent.
- **Any DS:** the old KSK is kept, and the roll goes back through the ordinary
  parent path (`reopenAlgRollParentStep`). In one transaction the insecure
  flag is cleared, the old head's drain clock (`alg_roll_old_head_retire_at`)
  is cleared, and the phase is set to `pending-parent-push`.

`pending-parent-push` is the step the parent now has to take: {DS(new)}
replacing what it serves. The child side was done long ago, so
`pending-child-publish` would only serve that wait again, and
`pending-parent-observe` would wait on a push the parent may have ignored
while it had no DS. From the push on, everything is the ordinary roll's:
`rollover_in_progress` is still set, the target set is still {DS(new)}, the
observe step insists DS(old) is gone, and the ordinary confirm restarts the
drain clock with the parent-DS-TTL margin. The clock is cleared, not kept,
because the ordinary drain counts from the moment DS(old) is seen gone. The
three writes cannot be split: with the flag cleared and the clock still set,
the next tick would withdraw on the ordinary margin measured from the
insecure confirm, while the parent still serves DS(old). With the clock
cleared the roll is again before its confirm, so it can be aborted again.

## 6. Margins

For an insecure roll (`insecureAlgRollMargin`):

    max( max(clamping.margin, max_observed_ttl),
         propagation-delay + max(served DNSKEY TTL, max_observed_ttl) )

measured from the confirm. No resolver can hold a DS RRset pointing at the
old KSK. What a validator can still hold, one that trusts the zone through a
configured trust anchor, is the zone's own data: the DNSKEY RRset served
before the confirm and the RRsets signed with the old KSK. The old KSK goes
once those have reached every secondary and expired. The first term is the
existing same-algorithm base margin; it is kept as a floor.

The served DNSKEY TTL is `effectiveServedDnskeyTTL` (policy TTLs, else the
zone's observed maximum); `max_observed_ttl` is the maximum RRset TTL the last
full signing pass recorded. When neither is known (a zone never signed, with
no TTLs in its policy) the withdraw holds, the same deferral the
`pending-child-publish` wait makes. It never holds for a missing parent DS
TTL.

`effectiveMarginForRoll` takes kasp.propagation-delay as a new argument; the
status and "when" projections pass it on.

## 7. CDS ordering

The rollover engine's claim on a CDS it published
(`last_published_cds_index_low/high`) is released by `releaseRolloverCDS`,
which re-derives the claimed CDS from the target key set and withdraws the
served CDS only when the two match. The spawn takes the old head out of that
set (its `ds` goes to 0 and the target-set loader filters it).

So the tick releases the claim **before** the spawn, while the old KSK is
still in the target set: the claimed CDS still matches and is withdrawn. That
is the right outcome; the zone no longer wants the old KSK's DS. The roll's
own push then publishes the CDS for the new KSK after the child-side wait.

Released after the spawn instead, the claimed range would match nothing, the
old KSK's CDS would read as someone else's, and the claim would be dropped
with that CDS left on the wire until the next CDS publication replaced it.
A test pins this behaviour, so the ordering comment cannot silently go stale.

A release that fails keeps its claim. Taking over from the first DS
publication, the spawn then **holds**: nothing else happens that tick (as
after a failed spawn) and the next tick tries again. The roll it would start
does not wait for the parent, so the old KSK could be removed while its CDS
was still served, asking the parent for a DS that would make the zone bogus.
From idle the spawn goes ahead: that roll waits for the parent to serve only
the new DS, and a NOTIFY push replaces the CDS RRset whole.

At the insecure confirm the CDS for the new KSK is kept: the parent has not
acted on it, so it is still the zone's standing request.

## 8. After the roll

When the drain completes the roll goes idle as before. The confirmed range is
NULL (§5), so the next idle tick arms the first DS publication for the new
KSK: the zone keeps asking for a DS at the parent, without end, and that loop
is again the non-blocking state for any later change.

## 9. Schema

New column `RolloverZoneState.alg_roll_parent_insecure INTEGER`, added to the
fresh schema (`v2/db_schema.go`) and to the column migrations
(`v2/db.go`), alongside the `alg_roll_*` columns. 1 = insecure roll, 0 =
cleared, NULL = no roll, or a roll recorded before the column existed (read as
secure). `setKskAlgRollTx` writes it with the rest of the roll record and
`clearKskAlgRollTx` NULLs it. `KskAlgRollState.ParentInsecure` and the status
field `algRollParentInsecure` expose it.

## 10. Status output

- The E13 warning (parent DS TTL unknown) is not raised for an insecure roll.
  A warning is raised instead when an insecure roll has no parent-agent to
  make the check before removal (§5.1).
- The hints and the CLI's algorithm-roll lines say that the parent holds no
  DS and that the roll does not wait for it.
- The projected removal of the old KSK uses the insecure margin.

## 11. Out of scope

- `policy-set`: deliberately ungated.
- IMR-validated insecurity: "no DS" comes from the engine's own parent-agent
  poll, which is the source every roll already trusts. The poll refuses an
  answer that cannot be the parent's (`checkParentAgentAnswer`): one without
  the AA bit, or an empty answer whose SOA is not a proper ancestor of the
  child -- the child's own server says "no DS" for every query. Either is a
  failed poll, which holds, so a misconfigured parent-agent shows as an error
  instead of an insecure parent.
- Zones with no parent DS path at all (the root, trust-anchor-only zones):
  the engine requires a parent-agent, so it cannot roll their KSK. That needs
  an explicit no-parent mode with RFC 5011 timing: #904.
- Ending the first DS publication loop: it continues indefinitely, by design.
- The config path takes no rollover lock: it runs on the refresh engine, and
  the rollover tick can hold the lock across a DS push. Its gate is a
  read-then-apply, as before.
- A zone whose parent once held DS for it, withdrew it, and is now being
  pushed a changed DS set: it does not count as the first DS publication
  (§2) and keeps blocking a KSK algorithm change until the parent publishes
  the DS set. Handling that case is tdns#903.
- A DS that appears at the parent after the insecure check before removal
  (§5.1) has nothing left to protect: the old KSK is gone by then, and a
  parent DS for it is the parent's error, like any stale DS. Withdrawing the
  old KSK's CDS at the spawn (§7) makes such a late pickup unlikely.

## 12. Tests

`v2/ksk_rollover_parent_no_ds_test.go`, driven through `RolloverAutomatedTick`
with an injected clock against a fake parent:

- `TestFirstDSPublicationPredicate`: the predicate, the insecure decision and
  the gate, row by row.
- `TestKskAlgRollParentInsecureRoundTrip`: the column round-trips, NULL reads
  as secure, the clear is one way, `clearKskAlgRollTx` NULLs it.
- `TestFirstDSPublicationDoesNotBlockChangePolicy`: accepted with no DS at the
  parent; refused for a rollover of the zone's own, for a DS push to a parent
  holding DS, for a parent that held DS before and holds none now (and the
  spawn refuses that case too), and before the first poll.
- `TestSpawnFromFirstDSPublicationRecordsAnInsecureRoll`: from
  `pending-parent-observe` and from `parent-push-softfail`; the attempt group
  ends in the spawn's transaction.
- `TestInsecureAlgRollCompletesWithoutParentDS`: the full roll; confirm on an
  empty answer; the old KSK stays until propagation + TTL, no poll during the
  drain, one poll at the removal (still no DS), and the KSK goes; no range is
  recorded as confirmed; the first DS publication re-arms and does not block
  a later change.
- `TestInsecureDrainFindsDSAndGoesBackToTheParent`: DS(old) appears at the
  parent during the insecure drain; the removal is blocked, the roll goes back
  to `pending-parent-push` as an ordinary roll, pushes {DS(new)}, waits while
  DS(old) is served, confirms on DS(new) and drains for the parent DS TTL.
- `TestInsecureDrainHoldsWhenTheParentCannotBeAsked`: a failed poll, and a
  missing parent-agent, hold the removal with the roll unchanged; the next
  answer without DS lets it go ahead.
- `TestInsecureAlgRollTurnsOrdinaryWhenTheParentShowsDS`: a DS mid-roll
  clears the flag; an empty answer no longer confirms; the drain is the
  parent-DS-TTL one.
- `TestSecureAlgRollIgnoresAnEmptyParentAnswer`: a roll that started secure
  is unchanged.
- `TestConfigReloadAppliesDuringFirstDSPublication`: the config path applies
  in the non-blocking state and still waits for a parent holding DS.
- `TestSpawnReleasesTheFirstDSPublicationCDSFirst`: the CDS ordering, with a
  running DS engine.
- `TestSpawnHoldsWhileTheFirstDSPublicationCDSCannotBeReleased`: the zone
  updater refuses the CDS withdrawal; no roll starts, the first DS
  publication, its claim and the old CDS are untouched; once the withdrawal
  succeeds the roll starts.

`TestKT7EffectiveMarginForRoll` gains the insecure-margin cases.
