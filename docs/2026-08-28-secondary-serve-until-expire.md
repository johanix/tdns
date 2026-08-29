# A secondary should serve until SOA expire

**Date:** 2026-08-28
**Context:** tdns#413. An API-provisioned secondary answers nothing below its
apex, and the same zone goes entirely dark on the first failed refresh. Both
come from one field. A config-declared secondary that has completed initial
load does *not* go dark on a failed refresh — its counter is already 1.
**Question:** what has to exist before the query path can decide "this zone is
still authoritative for its current contents", and what does that cost?

---

## 1. The requirement

RFC 1035 §3.3.13 and RFC 1034 §4.3.5: a secondary serves the copy it holds
until the SOA **expire** interval has elapsed since the last *successful*
refresh. A successful refresh includes an unchanged-serial SOA check — that is
the proof the primary is alive. Refresh and retry govern how often it tries;
only expire governs when it gives up. A primary that is unreachable for ten
minutes must not take the zone dark.

tdns already agrees. `serviceImpactingErrors` (`v2/enums.go:393`) is
`{ConfigError, AgentError, DnssecError}` and its comment says so outright:

> RefreshError and the rollover-* categories never block serving — a zone with
> stale data or an unsafe upcoming rollover is still authoritative for its
> current contents.

So this is not a change of policy. It is making the code do what it already
says.

## 2. Verified current behaviour

Traced and reproduced 2026-08-28 against a running `tdns-auth` secondary.

Two guards in `v2/defaultqueryhandlers.go` decide whether a zone answers:

```go
// :106  exact zone name (Zones.Get path)
if zd.HasServiceImpactingError() ||
    (zd.HasError(RefreshError) && zd.RefreshCount == 0) { → SERVFAIL }

// :163  any name below the apex (FindZone path)
if zd.RefreshCount == 0 { → SERVFAIL }
```

`v2/updateresponder.go:185` copies the `:106` form, and its comment says it
mirrors the query handler. Stage 1 that only edits the query path leaves
UPDATE on the broken proxy.

Both rest on `RefreshCount`, whose declared purpose is exactly that
(`v2/structs.go:206`):

```go
RefreshCount int // number of times the zone has been sucessfully refreshed (used to determine if we have zonedata)
```

**`RefreshCount` is incremented in exactly one place** — `initialLoadZone`,
`v2/refreshengine.go:152-154`, inside `if updated {`:

```go
if updated {
    zd.LatestRefresh = time.Now()
    zd.RefreshCount++
```

The periodic refresh loops (`:799`, `:1123`) never touch either field. So both
are set at most **once**, on initial load, and never again however many
successful refreshes follow. `LatestRefresh` is additionally **read nowhere** —
it is write-only today.

Measured, on one host, **in the process that provisioned the zone**:

| zone kind | `RefreshCount` |
|---|---|
| config-declared (loaded via `initialLoadZone`, `updated == true`) | `1` |
| API-provisioned secondary, this process after `zone add` | `0` |

It is not "API zones forever". `ProvisionDynamicZone` pre-registers the
`ZoneData` with `FirstZoneLoad` left false (zero value). The refresh engine
then takes the "EXISTING ZONE" branch and never calls `initialLoadZone`. The
matching primary path (`provisionDynamicPrimary`) sets `FirstZoneLoad: true`
on purpose, with a comment explaining why; the secondary add path does not.

Restart of a persisted API zone is a different path: the zone is not
pre-registered, so the engine creates it with `FirstZoneLoad: true` and *does*
call `initialLoadZone`. After a successful transfer, `RefreshCount` becomes 1.
The live-process measurement is still the bug that answers for the apex and
nothing inside it.

Do not "fix" this by setting `FirstZoneLoad: true` on the secondary add path
alone. That would increment the counter for new provisions and hide Symptom A
without replacing the predicate, and it would not survive the next pre-register
path.

### 2.1 Symptom A — sub-apex queries never answer

With `RefreshCount == 0` the `:163` guard fires on **every** query below the
apex, unconditionally, with no error present:

```
dig @<secondary> <zone> SOA              → NOERROR      (Zones.Get path)
dig @<secondary> www.<zone> A            → SERVFAIL     (FindZone path)
dig @<secondary> nosuchname.<zone> A     → SERVFAIL     (should be NXDOMAIN)
dig @<primary>   www.<zone> A            → NXDOMAIN     (control)
```

An API-provisioned secondary, in the process that added it, therefore answers
for the zone name and nothing inside it. This is not an expire problem at all;
it is the same field failing a different question.

`QueryResponder` (`v2/queryresponder.go:823`) already SERVFAILs when
`publishedSnapshot() == nil`. The `:163` guard is what stops an API zone that
*has* a snapshot from reaching that code.

### 2.2 Symptom B — the first failed refresh ends service (when the counter is 0)

With `RefreshCount == 0`, the `:106` guard degenerates to
`if zd.HasError(RefreshError)`. Reproduced on a zone with `expire 604800`
whose content had transferred minutes earlier:

```
[ERROR/engine] zone refresh failed zone=<zone> error=SOA probe ... unreachable
[WARN/handler] zone in error state qname=<zone> errorType=refresh
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL
```

A config-declared secondary that completed `initialLoadZone` with
`updated == true` does **not** do this: `RefreshCount == 1`, so `RefreshError`
alone does not trip either query guard. Symptom B is the API-provisioned (this
process) case, and any other path that left the counter at 0.

The zone file was on disk throughout, complete and signed, `Provisioning:
ready`. It stayed dark after the primary came back, until a NOTIFY arrived.
That wait is the **clamped SOA refresh interval**, not RETRY: after a failed
periodic refresh the engine sets `rc.CurRefresh = rc.SOARefresh`
(`v2/refreshengine.go:1124`). Initial-load failure retries in 30s. Retry
latency is out of scope (§6); it is named here so it is not mistaken for
expire.

**Reproducing this needs care.** `zone modify` and a daemon restart both
re-provision the zone and reset the same state, so neither isolates the bug.
The clean trigger is a NOTIFY sourced from the primary's own address, which
forces a refresh attempt with no config change:

```
dig -b <primary-addr> +opcode=notify @<secondary> <zone> SOA
```

### 2.3 Persistence does not reload a secondary from disk

`dynamiczones` with `storage: persistent` exists so a provisioned secondary
survives a restart. The zone *file* is written (inside `if updated {`).
Secondary `Refresh()` never reads it: the `Primary` branch calls
`FetchFromFile`; the `Secondary` branch always `DoTransfer` then, if needed,
`FetchFromUpstream`. `LoadDynamicZoneFiles` sets `Force: true` with a comment
about loading from disk, and still AXFRs.

A restart that coincides with an unreachable primary is therefore not
"complete on disk and unservable because `RefreshCount` reset". It is "never
loaded, `RefreshError`, nothing to serve". Stage 1 does not fix that. A
persisted timestamp does not either, until first bind adopts the persisted copy
when the transfer fails. That load is Stage 2 step 1, and everything else in
Stage 2 depends on it.

## 3. What "serve until expire" actually requires

Four things, of which only the first is small.

**(a) A real "do we hold data" test.** `RefreshCount` is a proxy, and a broken
one. `zd.GetSOA()` (`v2/zone_utils.go:1048`) is **not** the replacement: for
`!Ready && Secondary && IncomingSerial == 0` it returns a synthetic SOA so the
refresh engine can probe. That is the never-transferred case, which must keep
SERVFAILing.

The question is whether a published snapshot exists:
`zd.publishedSnapshot() != nil`. `QueryResponder` already uses that. Stage 1
replaces `RefreshCount` in the query and UPDATE guards with the same test
(plus the existing `HasServiceImpactingError()`). An equivalent smallest form
is to drop the `RefreshCount` clauses entirely and let `QueryResponder`
SERVFAIL the empty zone; the explicit snapshot check is preferred because the
handler already logs "zone not yet refreshed" and UPDATE never reaches
`QueryResponder`.

**(b) A trustworthy last-successful-refresh timestamp.** Needed for expire, and
`LatestRefresh` cannot be used as it stands: same single assignment, same `if
updated {` gate.

The stamp means **a usable SOA was seen**, not `Refresh` returning `err ==
nil`. `DoTransfer` (`v2/zone_utils.go:282-286`) returns `(false, 0, nil)` when
at least one primary answered but none gave a usable SOA — all REFUSED,
NOERROR with an empty answer, NOERROR whose first RR is not a SOA. `Refresh`
then does `return false, nil` (`:91-97`), which is the same pair as "serial
unchanged". Stamping on `err == nil` would let a secondary whose primaries
have revoked its ACL refresh its own expire clock every cycle and never
expire.

`(bool, error)` cannot currently tell those two apart. Do not spread writes
across `initialLoadZone` and the loops — that is how `RefreshCount` broke —
but do not put the chokepoint on `Refresh`'s error return either.

One helper, `noteSuccessfulRefresh`, writes `LatestRefresh` and the persisted
stamp (§4).
Call it from `DoTransfer`'s two usable-SOA returns (serial unchanged, and
serial moved). Not from quiet backoff, not from all-unreachable (that already
returns an error). A usable SOA is the RFC proof the primary is alive, even
if the AXFR that follows then fails. First-bind file load with no subsequent
usable SOA is Option 3, not a stamp.

**(c) That timestamp has to survive a restart, which first requires the held
copy to be in memory.** See §4 and Stage 2 step 1.

**(d) The comparison, and what to return after it.** Secondary zones in
`tdns-auth` only. Primaries do not expire, and the expire guard is a statement
about authoritative service, which is the only thing `tdns-auth` is doing with
these zones — the same scoping [[secondary-zones-immutable]]
(`2026-07-25-secondary-zones-immutable.md` §1.1) treats as load-bearing, and
for the same reason. Fold the app-type test into the predicate rather than
repeating it at each call site.

That the guards do not agree about app type today is worth knowing before
touching them. `DefaultQueryHandler` refuses ordinary queries for
`AppTypeAgent` at `v2/defaultqueryhandlers.go:140`, which is *after* the
`Zones.Get` branch returns and *before* the `FindZone` branch's guard — so the
`:163` guard is unreachable for an agent while the `:106` one is reached by
every app type. Stage 1 does not care (its predicate is strictly more
permissive than what it replaces, in every app). Stage 2.3 does, which is why
the scope is stated here rather than discovered there.

Serve while `now <= lastSuccessfulRefresh + time.Duration(expire)
* time.Second`, using the **served copy's** SOA EXPIRE, not a synthetic
`GetSOA` and not a later primary. After it, SERVFAIL (BIND/NSD). Keep trying:
expire must **not** be folded into `HasServiceImpactingError()`, because that
list skips the refresh ticker. A later successful refresh, including an
unchanged-serial SOA check, un-expires the zone.

Nothing in the protocol stops a primary publishing an EXPIRE of 0, or one
below its own REFRESH. Taken literally, either makes the secondary expire
before it can ever refresh — the zone goes dark on a schedule, from data the
primary controls. Decide the floor here rather than in review: an EXPIRE below
`refresh + retry` is nonsensical (BIND warns about exactly this shape), so
clamp to that sum, serve, and log the clamp once per zone per load. An EXPIRE
of 0 is the same case and takes the same clamp. Do not treat a bad EXPIRE as a
`ConfigError` — the value is the primary's, and a zone that is otherwise fine
should not stop answering over it.

## 4. The decision: where does the confirmation timestamp live?

On restart the process has no idea when the copy was last confirmed fresh —
and, today, may not even have the copy in memory. The question is not really
"where does the clock come from". It is: where does per-zone *runtime* state
that has to outlive the process belong?

tdns already answers that, and the answer is the database.

**The database is not optional.** `InitializeKeyDB` (`v2/parseconfig.go:747`)
hard-fails when `db.file` is unset — "db.file is required but not set" — and
creates the file and its directory on first run (`:767-781`). There is no
DB-less `tdns-auth`, so a filesystem mechanism would be serving a deployment
that cannot exist.

**Half of what this needs is already there.** `ZoneFileState`
(`v2/db_schema.go:271`) records the identity of the zone file as tdns last read
or wrote it: `zone` (primary key), `serial`, ZONEMD `digest`, `scheme`,
`algorithm`, `digest_variant`, `updated_at`. Its own header makes the argument
this brief would otherwise have had to make from scratch:

> The serial alone cannot answer "is this the same file?". A zone file can be
> regenerated with the same serial, restored from a backup that reuses one, or
> reformatted without changing it at all

`CompareZoneFileState` (`v2/zone_file_state.go:236`) turns that into a verdict,
and `reconcileZoneFileWithJournal` already acts on it at
`v2/refreshengine.go:301`. The delta journal (`ZoneDelta`,
`v2/db_schema.go:281`) hangs off the same identity: the zone file is the base
that lags, the deltas are everything since. Inbound IXFR extends that model to
secondaries; it does not move the base off disk.

### What is actually missing

One fact: **when a usable SOA was last seen.** Everything else the expire
decision needs — the held copy's serial, its EXPIRE, whether the file on disk
is still the file we recorded — is already available by the time first bind has
loaded the zone.

`ZoneFileState.updated_at` is **not** that fact. It moves when the file
identity is recorded, i.e. when the file is read or written, which for a
secondary means only when the content changed. That is the mtime measure under
another name, and it fails the same way (Option 2).

### Where to put it

**A separate table, not a column on `ZoneFileState`.** Two reasons, one of
them a trap:

- `SetZoneFileState` (`v2/zone_file_state.go:69`) writes with
  `INSERT OR REPLACE` and names every column. A `last_confirmed` column added
  to that table would be silently reset to its default on every file-identity
  record — the write path most likely to run right after a refresh. The bug
  would look like an expire clock that keeps forgetting.
- They are different facts with different lifetimes. "This is the file we
  hold" changes when the file changes; "the primary was alive at T" changes on
  every confirmation, including the ones that change nothing. Keeping them in
  one row means every writer of either has to preserve the other.

Shape:

```sql
CREATE TABLE IF NOT EXISTS 'ZoneRefreshState' (
    zone           VARCHAR(255) NOT NULL PRIMARY KEY,
    last_confirmed DATETIME NOT NULL,
    serial         INTEGER NOT NULL  -- the copy that stamp describes
)
```

- Registered in `DefaultTables` (`v2/db_schema.go:11`), which `dbSetupTables`
  (`v2/db.go:105-111`) runs `CREATE TABLE IF NOT EXISTS` over at every startup,
  so an existing database picks the table up on the first run of the new
  binary. It does **not** go in the `dbMigrateSchema` list (`v2/db.go:198`):
  that exists for `ALTER TABLE ADD COLUMN` on tables that already ship, which
  is what `ZoneFileState.digest_variant` needed and a new table does not.
- Written by `noteSuccessfulRefresh` (usable SOA, §3b), which also sets
  `LatestRefresh` in memory. When the confirmation is part of a transfer, the
  write joins that transaction rather than standing alone.
- `serial` is what the stamp describes, so a stamp can be matched against the
  copy actually loaded. It is a cross-check, not a shortcut: the copy is loaded
  first regardless (§5, Stage 2 step 1), so nothing is skipped on the strength
  of it.
- Read once at first bind, after the copy is in memory.
- Deleted with the zone.
- Clock: `time.Now()` (wall clock), stored UTC. A step can expire a zone early
  or extend it; that is accepted rather than designed around. No injected
  clock: the expire tests set `LatestRefresh` in the past instead of sleeping
  (§8).

### Trusting the stamp

A timestamp is only as good as the identity of the copy it describes, and that
question already has a mechanism. At first bind, after the file is loaded:

- `CompareZoneFileState` says the file is the one we recorded, and the stamp's
  `serial` matches the loaded SOA → the expire budget is real, use it.
- Either check disagrees → the stamp describes something else (a hand-placed
  file, a restored backup, a zone re-created under a name that was used
  before). Discard it and fall back to Option 3.

No new comparison is needed for this; it is the verdict
`reconcileZoneFileWithJournal` is already computing on the same load.

**Deletion, and a pre-existing gap.** `RemoveDynamicZone`
(`v2/dynamic_zones.go:997`) removes the zone's files and its config entry — and
touches no DB rows at all. A zone's `ZoneFileState` and `ZoneDelta` rows
already survive its deletion today. That is currently harmless: re-creating a
zone of the same name produces a file whose digest does not match the stale
row, so the verdict rejects the journal rather than replaying it onto a base it
was not computed against. The digest is doing exactly the job it was built for.

`ZoneRefreshState` gets the same protection through the serial check above, but
it should still be deleted with the zone rather than relying on it, and the
existing orphans deserve a cleanup of their own (§6).

### Option 2 — the zone file's mtime

Attractive because it needs no new state. **Rejected:** the zone file is
written only inside `if updated {` (`v2/refreshengine.go:838` under `:818`, and
`:1194` under `:1179`), i.e. only when the content *changed*. A stable zone
refreshed hourly for a month has a month-old mtime and would be judged long
expired while being perfectly fresh. mtime tracks last change, not last
confirmation, and the difference is exactly what expire is about.
`ZoneFileState.updated_at` is the same measure and is rejected for the same
reason.

### Option 3 — treat unknown as "now"

On load with no usable stamp — no row, or one the identity check rejected —
start the expire clock at load time.

Lenient and trivial. It can serve past the true expire by up to one expire
interval after a restart: the server forgets how much of the interval it had
already used. For a secondary that restarts rarely this is a small deviation;
it is still a deviation from RFC 1034 §4.3.5, and it is silent unless logged.
BIND does this: restarting a secondary that has a zone file resets an expired
zone and serves it.

### Option 4 — treat unknown as expired

Strict, and defeats `storage: persistent` entirely: every restart would take
every zone dark until its first successful refresh, which is the failure this
work exists to remove. Rejected.

### Recommendation

**The DB row, with Option 3 as the fallback.** When no usable stamp exists —
an older deployment, a hand-placed zone file, a zone re-created under a
previously used name — start the clock at load and log that the zone's expire
budget is being restarted. Correct behaviour in the normal case, defined and
visible behaviour in the degraded one, and never the silent dark-zone of
Option 4.

### Why not the config file

Recorded because the earlier version of this brief chose otherwise, and the
reasoning still applies to anything tempted to follow it.
`zoneConfFromZoneData` (`v2/dynamic_zones.go:465`) ends:

> Note: We don't serialize Frozen, Dirty, Error, ErrorType, ErrorMsg,
> RefreshCount as these are runtime state, not configuration

That boundary is correct, and a confirmation timestamp sits squarely on the
runtime side of it. Widening `ZoneConf` to carry it would weaken a distinction
worth keeping. Reaching for a file *beside* the zone file instead — a sidecar —
keeps the boundary but answers the wrong question: it treats "not
configuration" as "therefore the filesystem", when the process already has a
transactional store for exactly this class of state, holding the zone's file
identity and its delta journal. A sidecar would also have needed its own
ordering rule against the zone file, its own removal path, its own orphan
handling, and its own absence semantics. Every one of those is either free or
already solved in the DB.

## 5. Staging

The two symptoms have very different sizes and should not travel together.

**Stage 1 — fix the "have data" test.** In `DefaultQueryHandler` (both
branches) and `UpdateHandler`: SERVFAIL only on `HasServiceImpactingError()` or
`publishedSnapshot() == nil`. Not `GetSOA()`, not `RefreshCount`. Fixes
Symptom A completely and Symptom B's worst edge (a zone that holds data no
longer SERVFAILs merely because a refresh failed). Small, self-contained,
testable without new persistence, and it touches nothing the rest of this
brief depends on.

Note what Stage 1 alone leaves: a secondary that serves its copy indefinitely,
because nothing yet enforces expire. That is strictly better than today —
today it serves for *less* than expire, which is the direction that loses data
— but it is not correct, and Stage 1 should say so in its own comments rather
than read as finished. Restart with the primary down is also still broken
(§2.3).

**Stage 2 — held copy across restart, timestamp, expire.** Three steps, one
PR, in this order, because (2) and (3) are pointless until (1):

1. **First bind of a secondary with no published snapshot: if the persisted
   zone file exists, `FetchFromFile` before `DoTransfer`.** Derive the path the
   way `zoneDataToZoneConf` (`v2/dynamic_zones.go:405-414`) already does:
   `zd.Zonefile` when set (config-declared `zonefile:`), otherwise
   `GetDynamicZoneFilePath` (`v2/dynamic_zones.go:76`) when `ShouldPersistZone`.
   On the restart path `zd.Zonefile` is already populated; the derivation also
   covers a persistable zone whose field is still empty. If the transfer then
   fails, the file copy remains and is served. If it succeeds, it replaces the
   file copy as today. Do not reload the file over a live snapshot on a later
   failed refresh — the file may be older than memory.

   **Assign the derived path onto `zd.Zonefile` before calling
   `FetchFromFile`.** That function takes no path argument — it reads the field
   directly (`os.Stat(zd.Zonefile)`, `ReadZoneFile(ctx, zd.Zonefile, true)`,
   `recordZoneFileStat`) — so a derivation that is not written back is not
   visible to it. Deriving without assigning would stat `""` on exactly the
   zones this brief is about: an API-managed secondary in the process that
   added it, where nothing sets the field (§4, and the same reason the stamp is
   not keyed on it). Config-declared `zonefile:` and the restart path already
   have it set, so the assignment is a no-op there.

   The rest of the machinery is favourable: `FetchFromFile` already computes
   `updated := force || zd.publishedSnapshot() == nil`
   (`v2/zone_utils.go:494`), so a zone with no snapshot adopts the file without
   forcing. The remaining fight, if there is one, is `FirstZoneLoad` /
   `completeFirstZonePolicyAndLoad` / Ready — the overrun §8 prices.

   This is also the step that makes the secondary load path look like the
   primary's: file, then journal. `replayZoneDeltasOnLoad`
   (`v2/refreshengine.go:289`, called from `:277`) and the
   `CompareZoneFileState` verdict it runs first are already there; a secondary
   reaching this path should use them rather than grow a parallel load.
2. `noteSuccessfulRefresh` on usable SOA (§3b): set `LatestRefresh` in memory
   and upsert `ZoneRefreshState`; Option 3 when the row is absent or the
   identity check rejects it. Delete the row with the zone.
3. Query and UPDATE guards: a secondary with a snapshot SERVFAILs when `now` is
   past last-confirmed + the served copy's clamped SOA EXPIRE (§3d). Ticker and
   NOTIFY keep trying. A usable SOA after expire un-expires.

### Ordering against Project C2 (inbound IXFR)

`2026-07-25-inbound-ixfr-plan.md` is unblocked: its stated prerequisite
(`2026-07-25-secondary-zones-immutable.md`) has landed —
`v2/zone_origination.go`, the `SuppressedOptions` plumbing and the serial-mirror
drift check at `v2/zone_mutation.go:598` are all on main, whatever that doc's
own status line still says. So the two projects are a genuine choice of order
rather than a dependency. **This one first**, for three reasons.

**Stage 2.1 is what makes C2 pay off across a restart.** C2 sends
`zd.IncomingSerial` as the "have" serial (`ZoneTransferIn`,
`v2/dnsutils.go:157`), and `IncomingSerial` is set from the SOA by
`ParseZoneFromReader` (`v2/dnsutils.go:823`) — i.e. by loading a copy. Today a
restarted secondary holds no copy, so the serial is 0 and the first transfer
after every restart is a full AXFR no matter how good the delta path is.
Stage 2.1 is precisely the step that gives it a base to ask from.

**Stage 1 is independent and small.** Three call sites in
`defaultqueryhandlers.go` and `updateresponder.go`, none of which C2 touches.
It fixes a live bug and should not queue behind a feature.

**The conflict surface is modest and asymmetric.** Stage 2.1 edits the
`Secondary` branch of `Refresh`; C2 edits `FetchFromUpstream` and
`ZoneTransferIn`. Adjacent functions in the same file, different bodies.
Landing the smaller change first is the cheaper rebase in either direction.

Nothing in §4 depends on C2. Its apply model (§4.4 there) materializes, applies
and swaps through the same `applyRefreshReplacementLocked` as the AXFR path, so
persistence stays wholesale: an inbound delta still rewrites the entire zone
file. Deltas retained by C2 go into #328's outbound `IxfrChain`, not into a
persistence model that spares a large secondary a full rewrite per change. If
that rewrite is the thing worth fixing, it is a third project, and it is the one
that would extend Stage 2.1's load path from file to file-plus-journal — which
is why step 1 above reuses `replayZoneDeltasOnLoad` rather than growing a
parallel load.

## 6. Out of scope

**Retry latency.** After a failed periodic refresh the engine waits the
clamped SOA **refresh** interval, not RETRY. A zone in `RefreshError` can stay
dark (today) or stale (after Stage 1) until that interval or a NOTIFY. Whether
a failed refresh should schedule a nearer retry is a real question and a
different one.

**`RefreshCount` itself.** Once neither guard consults it, it is a counter that
increments at most once and is reported over the API. Either fix it to count
refreshes or retire it; it should not stay as it is, being read as though it
meant something.

**Orphaned per-zone DB rows.** `RemoveDynamicZone` (`v2/dynamic_zones.go:997`)
removes the zone's files and its config entry and touches no DB rows, so
`ZoneFileState` and `ZoneDelta` rows outlive the zones they describe. Harmless
today — the digest verdict rejects a stale row rather than replaying its
journal onto an unrelated base — but it is accumulating state nothing prunes,
and a name reused after deletion carries its predecessor's row until the first
write. Stage 2 deletes `ZoneRefreshState` with the zone (§4) and should not
grow into a general cleanup; sweeping the existing tables is its own change.

## 7. Test plan

Stage 1, as Go tests (not only `dig`), against an API-shaped zone
(`FirstZoneLoad == false`, snapshot present, `RefreshCount == 0`):

- sub-apex query for an existing name → the record, not SERVFAIL
- sub-apex query for an absent name → NXDOMAIN, not SERVFAIL
- `RefreshError` set, primary unreachable: apex and sub-apex still answer
- never-published zone → SERVFAIL
- `GetSOA` synthetic case (`!Ready`, secondary, `IncomingSerial == 0`) must
  **not** count as "have data"
- UPDATE uses the same predicate as the query path

For Stage 2, additionally:

- first bind, zone file present, transfer fails → file copy is served
- first bind, zone file present, transfer succeeds → transferred copy is served
- later failed refresh does not replace a live snapshot from the file
- usable SOA, serial unchanged, advances the timestamp
- all primaries REFUSED (quiet backoff, `err == nil`) does **not** advance it
- API-managed zone with empty `zd.Zonefile` is found by the
  `GetDynamicZoneFilePath` derivation at first bind
- `SetZoneFileState` does not clobber the confirmation stamp (the
  `INSERT OR REPLACE` trap, §4)
- a stamp whose serial does not match the loaded copy is discarded, not used
- a stamp rejected by the `CompareZoneFileState` verdict is discarded, not used
- deleting a zone removes its `ZoneRefreshState` row
- re-creating a zone under a previously used name does not inherit the old
  stamp — in particular, an already-past-expire one must not take the new
  zone dark at first bind
- restart with a persisted timestamp preserves the remaining expire budget
- restart with no timestamp starts the clock and logs it
- past expire, queries and UPDATE SERVFAIL; the ticker still attempts refresh
- a usable SOA after expire un-expires
- served SOA EXPIRE of 0, and one below `refresh + retry`, clamp to
  `refresh + retry` and log rather than expiring the zone on a schedule
- primaries are not subject to the expire guard
- a non-`tdns-auth` app holding a secondary zone is not subject to it either
- the new table appears on a pre-existing database with no migration entry

The NOTIFY trick in §2.2 is what makes the "primary down" cases testable without
waiting out a refresh timer; both stages need it.

## 8. Size

LOC is first-cut production vs test, the way other briefs in this tree count.
Harness already exists: `testSnapshotZone`, `fakeRW`, `startTestSOAServer`.
Expire tests set `LatestRefresh` in the past rather than sleeping or injecting
a clock.

Extract one predicate (`publishedSnapshot() != nil`, named) and use it at all
three Stage 1 sites. Testing the helper plus driving `DefaultQueryHandler`
covers UPDATE if UPDATE calls the same helper; a separate `UpdateResponder`
trip is cheap insurance, not a second design.

| | item | files | impl | test |
|---|---|---|---|---|
| **S1** | Predicate + comments that expire is unenforced | `zone_utils.go` (or next to `HasServiceImpactingError`) | 15 | 40 |
| **S1** | Both query branches | `defaultqueryhandlers.go` | 20 | 120 |
| **S1** | UPDATE | `updateresponder.go` | 10 | 40 |
| | **Stage 1** | | **~45** | **~200** |
| **S2.1** | First-bind `FetchFromFile` before `DoTransfer` | `zone_utils.go` `Refresh` | 40 | 150 |
| **S2.2** | `noteSuccessfulRefresh` on usable SOA, not `err == nil`; `ZoneRefreshState` in `DefaultTables` (no `dbMigrateSchema` entry — §4), upsert + read + delete-with-zone | `zone_utils.go`, `db_schema.go`, `dynamic_zones.go` | 55 | 150 |
| **S2.3** | Secondary expire guard on query + UPDATE, with the EXPIRE clamp; ticker unchanged | same three call sites as S1 | 35 | 130 |
| | **Stage 2** | | **~130** | **~430** |
| | **Total** | | **~175** | **~630** |

**~175 production, ~630 test, ~805 all in.** Stage 1 is the small PR (~45 / ~200).
Stage 2 is larger because of tests, not because of production code.

The overrun, if there is one, is S2.1. `FetchFromFile` is a primary-shaped path
(digest, journal, `firstLoad` skips Ready until `InstallInitialSnapshot`).
Threading it under a secondary with no snapshot is the one place this brief
touches behaviour the current tests do not cover. If that fights
`completeFirstZonePolicyAndLoad`, S2.1 alone can double. S1, S2.2 and S2.3
should not.

Do not count retiring `RefreshCount` (§6). Do not count switching the ticker
to SOA RETRY (§6). Do not count sweeping the pre-existing orphan rows (§6);
S2.2 deletes only its own table's row. Expire is not an `ErrorType`, so the
ticker keeps trying with no extra engine code.

S2.2 shrank against an earlier estimate because the DB absorbs work a
filesystem artefact would have had to carry: no ordering rule against the zone
file, no atomic-rename path, no orphan-file handling, and the write joins a
transaction that is already being committed on the transfer path.
