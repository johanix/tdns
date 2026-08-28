# Review: serving a secondary until SOA expire

2026-08-28

**Plan under review:** [`2026-08-28-secondary-serve-until-expire.md`](2026-08-28-secondary-serve-until-expire.md)
(tdns PR #414, issue #413)

Checked against `DefaultQueryHandler`, `QueryResponder`, `GetSOA`,
`Refresh` / `DoTransfer` / `FetchFromUpstream`, `initialLoadZone`,
`ProvisionDynamicZone`, `LoadDynamicZoneFiles`, `applyRefreshReplacementLocked`,
`HasServiceImpactingError`, and `UpdateHandler`.

## Verdict

The live-process diagnosis is correct and the stage split is the right size.
The document is **not** complete enough to implement from: Stage 1 names the
wrong "have data" test, and Stage 2's restart story assumes a load path that
does not exist.

| | |
|---|---|
| Problem analysis | Correct for the running daemon; overstated for config-declared secondaries; wrong on restart |
| Scope | Right split; one missing prerequisite for Stage 2 |
| Safe to implement as written | No |

## Answers to the three questions

**Is the problem analysis correct?** Mostly, for the process that provisioned
the zone. One field really does back both query guards, it really is
incremented only in `initialLoadZone` inside `if updated {`, and an
API-provisioned secondary really does sit at `RefreshCount == 0` after a
successful AXFR. Symptom A (sub-apex SERVFAIL with a live apex) follows
directly from `defaultqueryhandlers.go:164`. Symptom B (apex goes dark on the
first `RefreshError`) follows only when that counter is still 0.

It is not true of config-declared secondaries that have completed
`initialLoadZone` with `updated == true`: theirs is `1`, so a later failed
refresh leaves both guards passing and the zone keeps answering. The opening
sentence ("a tdns-auth secondary stops answering as soon as one refresh
fails") is the API-provisioned case, not the general one.

RFC 1035 §3.3.13 is the right cite for EXPIRE. RFC 2308 §4 is not — that
section is negative answers from authoritative servers. The "successful
refresh includes an unchanged-serial SOA check" reading is still right
(RFC 1034 §4.3.5).

**Is it correctly scoped?** Yes on the stage split and on leaving retry
latency and the future of `RefreshCount` out. Expire is a different question
from "do we hold data", and mixing them would hide a small fix behind a
persistence design.

Two scope holes:

1. Stage 2 across restart requires the held copy to be in memory. Secondary
   `Refresh()` never reads the zone file; `LoadDynamicZoneFiles` sets
   `Force: true` and still AXFRs. If the primary is down at start, the file
   on disk is not loaded. Persisting a timestamp does not help a zone that
   was never adopted. That load-from-file-on-transfer-failure path is a
   prerequisite, not a sidecar detail.
2. `updateresponder.go:184` copies the `:103` guard. Stage 1 that only
   touches the query handler leaves UPDATE on the broken proxy.

**Is it complete enough to implement?** No. Stage 1 can be implemented once
the "have data" test is named correctly. Stage 2 cannot: sidecar location,
format, write atomicity, the chokepoint that stamps *every* successful
refresh (including `Refresh()` returning `(false, nil)`), secondary-only
application, and behaviour after expire (keep retrying? still NOTIFY?) are
all undecided.

## What the plan gets right

- The two guards, the single increment site, and `LatestRefresh` being
  write-only. Confirmed: `RefreshCount++` exists only at
  `refreshengine.go:154`. The periodic paths (`:799`, `:1123`) clear
  `RefreshError` on success and never touch either field.
- Why API-provisioned zones never increment: `ProvisionDynamicZone`
  pre-registers a `ZoneData` with `FirstZoneLoad` left false (zero value).
  The engine then takes the "EXISTING ZONE" branch and never calls
  `initialLoadZone`. The matching primary path
  (`provisionDynamicPrimary`) sets `FirstZoneLoad: true` on purpose, with a
  comment explaining why. The secondary add path does not. Restart of a
  persisted API zone is a *different* path (not pre-registered → engine
  creates with `FirstZoneLoad: true` → `initialLoadZone`), so
  `RefreshCount == 0` is "this process, after `zone add`", not "API zones
  forever".
- `serviceImpactingErrors` really excludes `RefreshError`. The `:103`
  extra clause is the thing that violates its own comment, and only when
  `RefreshCount == 0`.
- Rejecting zone-file mtime. The writes at `:849` / `:1205` are inside
  `if updated {`. Unchanged-serial success does not touch the file.
- Rejecting Option 4 (unknown ⇒ expired). That would make `storage:
  persistent` worse than it is today on a reachable primary.
- Option 3 as fallback is also what BIND does on restart (ISC: restarting
  a secondary with a zone file resets an expired zone and serves it).
- The NOTIFY reproduction (`dig -b <primary-addr> +opcode=notify`) is the
  right way to force a refresh without `zone modify` / restart. Those two
  really do re-provision.
- Staging: Symptom A is a wrong predicate; expire is a missing clock.
  They should not share a PR.

## What is wrong or incomplete

### 1. `GetSOA()` is not a "do we hold data" test

`GetSOA` (`zone_utils.go:1035`) returns a **synthetic** SOA when
`!zd.Ready && zd.ZoneType == Secondary && zd.IncomingSerial == 0` — the
never-transferred case — so the refresh engine can probe. That is the
opposite of the question Stage 1 asks.

`QueryResponder` already answers the real question
(`queryresponder.go:823`): `publishedSnapshot() == nil` → SERVFAIL. The
`:163` `RefreshCount == 0` guard is what stops an API zone that *has* a
snapshot from reaching that code.

Stage 1 as specified (`replace RefreshCount with zd.GetSOA()`) would let a
never-loaded secondary through the handler (synthetic SOA) and rely on
`QueryResponder` to SERVFAIL. The test plan's "never loaded → SERVFAIL"
would pass accidentally. The handler comment would claim a test the helper
does not perform.

The test to name is the published snapshot (and/or `zd.Ready`, which is
gated on one existing). Not `GetSOA()`.

A still-smaller Stage 1, equivalent for the two symptoms: drop the
`RefreshCount` clauses and keep `HasServiceImpactingError()`. Empty zones
already SERVFAIL in `QueryResponder`. That is worth considering before
inventing a new helper call.

### 2. Symptom B and §2.3 overclaim restart

§2.3 says the zone file is reloaded on restart and only the counter is
lost. Secondary `Refresh()` does not call `FetchFromFile`. Startup of a
persisted dynamic secondary enqueues `Force: true`, which still goes
`DoTransfer` then `FetchFromUpstream`. If that fails, `initialLoadZone`
returns, `noteRefreshFailure` fires, and the copy on disk is not adopted.

A restart that coincides with an unreachable primary is therefore not
"complete on disk and unservable because `RefreshCount` reset". It is
"never loaded, `RefreshError`, nothing to serve". Stage 1 does not fix
that. Stage 2's sidecar does not either, until something loads the file
when the transfer fails.

### 3. "SOA retry" is not what the ticker does

After a failed periodic refresh the engine sets `rc.CurRefresh = rc.SOARefresh`
(`refreshengine.go:1124`), the clamped refresh interval, not `SOA.RETRY`.
Initial-load failure uses 30s. The zone staying dark until NOTIFY is the
refresh interval plus the `RefreshCount` guard, not the retry timer. Out
of scope is still the right call; the mechanism is misnamed.

### 4. Stage 2 is a direction, not a spec

Still needed before anyone writes it:

- **Chokepoint.** Stamp the timestamp inside `ZoneData.Refresh` on every
  `err == nil` return, including `(false, nil)` when the serial is
  unchanged (`zone_utils.go:92-98`). Spreading writes across
  `initialLoadZone` and both loops will miss a path; that is how
  `RefreshCount` broke.
- **Secondary only.** Primaries do not expire. The query guard must not
  apply `SOA.Expire` to them.
- **After expire.** BIND/NSD SERVFAIL *and keep trying*. The ticker must
  not treat expire as `HasServiceImpactingError` (that would skip
  refresh). Unsaid.
- **Sidecar.** Path relative to the zone file / dynamic directory, on-disk
  format, atomic replace, what happens if the write fails (serve anyway?
  log and continue — should say), clock (wall-clock, so a step can expire
  or extend).
- **Which EXPIRE value.** The served copy's SOA, frozen at last success —
  not a synthetic GetSOA, not a later primary.
- **Config-declared secondaries** with a `zonefile:` as well as
  `storage: persistent` API zones. Same missing file-load-on-failure.

### 5. Missed call site

`updateresponder.go:181-184` is the same first-load guard as `:103`,
including the comment that it mirrors the query handler. Stage 1 that
does not mention it will leave UPDATE on `RefreshCount`.

## Implementation-shaped Stage 1 (if this doc is the brief)

1. In `DefaultQueryHandler`, both branches: SERVFAIL only on
   `HasServiceImpactingError()` or "no published snapshot" (not `GetSOA()`,
   not `RefreshCount`). Same change in `UpdateHandler`.
2. Comment that expire is not enforced; Stage 2 owns that.
3. Tests (Go, not only `dig`): API-shaped zone (`FirstZoneLoad == false`,
   snapshot present, `RefreshCount == 0`) answers sub-apex and NXDOMAIN;
   same zone with `RefreshError` still answers; never-published zone
   SERVFAILs; `GetSOA` synthetic case must not count as "have data".

Do not "fix" this by setting `FirstZoneLoad: true` on the secondary add
path alone. That would increment the counter for new provisions and hide
Symptom A without replacing the predicate, and it would not survive the
next person adding a pre-register path.

## Stage 2 before coding

Decide, in the doc, whether "load the persisted secondary from disk when
the first transfer fails" is in Stage 2 or a listed dependency. Without
that decision the persist-the-timestamp design does not meet its own
restart requirement.
