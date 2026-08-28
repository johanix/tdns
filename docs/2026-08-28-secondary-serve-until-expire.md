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

tdns already agrees. `serviceImpactingErrors` (`v2/enums.go:389`) is
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
// :103  exact zone name (Zones.Get path)
if zd.HasServiceImpactingError() ||
    (zd.HasError(RefreshError) && zd.RefreshCount == 0) { → SERVFAIL }

// :163  any name below the apex (FindZone path)
if zd.RefreshCount == 0 { → SERVFAIL }
```

`v2/updateresponder.go:184` copies the `:103` form, and its comment says it
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

With `RefreshCount == 0`, the `:103` guard degenerates to
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
sidecar timestamp does not either, until first bind adopts the persisted copy
when the transfer fails. That load is Stage 2, not a sidecar detail.

## 3. What "serve until expire" actually requires

Four things, of which only the first is small.

**(a) A real "do we hold data" test.** `RefreshCount` is a proxy, and a broken
one. `zd.GetSOA()` (`v2/zone_utils.go:1035`) is **not** the replacement: for
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
nil`. `DoTransfer` (`v2/zone_utils.go:283-286`) returns `(false, 0, nil)` when
at least one primary answered but none gave a usable SOA — all REFUSED,
NOERROR with an empty answer, NOERROR whose first RR is not a SOA. `Refresh`
then does `return false, nil` (`:92-98`), which is the same pair as "serial
unchanged". Stamping on `err == nil` would let a secondary whose primaries
have revoked its ACL refresh its own expire clock every cycle and never
expire.

`(bool, error)` cannot currently tell those two apart. Do not spread writes
across `initialLoadZone` and the loops — that is how `RefreshCount` broke —
but do not put the chokepoint on `Refresh`'s error return either.

One helper, `noteSuccessfulRefresh`, writes `LatestRefresh` and the sidecar.
Call it from `DoTransfer`'s two usable-SOA returns (serial unchanged, and
serial moved). Not from quiet backoff, not from all-unreachable (that already
returns an error). A usable SOA is the RFC proof the primary is alive, even
if the AXFR that follows then fails. First-bind file load with no subsequent
usable SOA is Option 3, not a stamp.

**(c) That timestamp has to survive a restart, which first requires the held
copy to be in memory.** See §4 and Stage 2 step 1.

**(d) The comparison, and what to return after it.** Secondary only — primaries
do not expire. Serve while `now <= lastSuccessfulRefresh + time.Duration(expire)
* time.Second`, using the **served copy's** SOA EXPIRE, not a synthetic
`GetSOA` and not a later primary. After it, SERVFAIL (BIND/NSD). Keep trying:
expire must **not** be folded into `HasServiceImpactingError()`, because that
list skips the refresh ticker. A later successful refresh, including an
unchanged-serial SOA check, un-expires the zone.

## 4. The decision: where does the timestamp come from after a restart?

On restart the process has no idea when the copy was last confirmed fresh —
and, today, may not even have the copy in memory. Four options for the clock,
once the copy is loaded.

### Option 1 — persist it with the zone

Write the last-successful-refresh time alongside the persisted zone
configuration.

The obstacle is deliberate. `zoneConfFromZoneData` (`v2/dynamic_zones.go:465`)
ends:

> Note: We don't serialize Frozen, Dirty, Error, ErrorType, ErrorMsg,
> RefreshCount as these are runtime state, not configuration

That boundary is correct as stated, and this field genuinely sits on the wrong
side of it: it *is* runtime state. So Option 1 either widens `ZoneConf` to carry
runtime state — weakening a distinction worth keeping — or introduces a small
sidecar for per-zone runtime state that survives restart, next to the zone file.

A sidecar is the cleaner shape. It also gives a home to anything else that later
needs to outlive the process without becoming configuration.

**Shape (this is the spec, not a later decision):**

- Path: sibling of the file persistence actually writes, suffix
  `.last-refresh`. Derive that file the same way `zoneDataToZoneConf`
  (`v2/dynamic_zones.go:410-414`) already does: `zd.Zonefile` when it is set
  (config-declared `zonefile:`), otherwise `GetDynamicZoneFilePath` when
  `ShouldPersistZone` (`v2/dynamic_zones.go:76`). Do **not** key only on
  `zd.Zonefile`. API-managed zones never set that field;
  `WriteDynamicZoneFile` derives `<zonedirectory>/<zone>.zone` and does not
  write the path back onto the `ZoneData`, so a `Zonefile`-keyed sidecar
  would write nothing in the process that provisioned the zone (the class
  this work is about) and only start working after a restart, which falls
  back to Option 3.
- A zone with neither a `Zonefile` nor a persistable dynamic path has no
  sidecar (in-memory only; Option 3 on the next start that still has no
  file).
- Content: one line, RFC3339Nano UTC.
- Write: from `noteSuccessfulRefresh` (usable SOA, §3b), atomic
  create-and-rename. A failed write is logged and does **not** fail the
  refresh; the copy stays served.
- Read: at first bind, after the copy is in memory.
- Clock: `time.Now()` (wall clock). A step can expire or extend; that is
  accepted.

Cost: a new persisted artefact, its write path, and its absence handling.

### Option 2 — the zone file's mtime

Attractive because it needs no new state. **Rejected:** the zone file is written
only inside `if updated {` (`v2/refreshengine.go:849-856`, `:1205-1212`), i.e.
only when the content *changed*. A stable zone refreshed hourly for a month has
a month-old mtime and would be judged long expired while being perfectly fresh.
mtime tracks last change, not last confirmation, and the difference is exactly
what expire is about.

### Option 3 — treat unknown as "now"

On load with no persisted timestamp, start the expire clock at load time.

Lenient and trivial. It can serve past the true expire by up to one expire
interval after a restart — the server forgets how much of the interval it had
already used. For a secondary that restarts rarely this is a small deviation;
it is still a deviation from RFC 1034 §4.3.5, and it is silent. BIND does
this: restarting a secondary that has a zone file resets an expired zone and
serves it.

### Option 4 — treat unknown as expired

Strict, and defeats `storage: persistent` entirely: every restart would take
every zone dark until its first successful refresh, which is the failure this
work exists to remove. Rejected.

### Recommendation

**Option 1 with Option 3 as the fallback.** Persist the timestamp in the
sidecar above; when it is absent — an older deployment, a hand-placed zone
file, a corrupt sidecar, no zone file — start the clock at load and log that
the zone's expire budget is being restarted. That gives correct behaviour in
the normal case, a defined and visible behaviour in the degraded one, and never
the silent dark-zone of Option 4.

## 5. Staging

The two symptoms have very different sizes and should not travel together.

**Stage 1 — fix the "have data" test.** In `DefaultQueryHandler` (both
branches) and `UpdateHandler`: SERVFAIL only on `HasServiceImpactingError()` or
`publishedSnapshot() == nil`. Not `GetSOA()`, not `RefreshCount`. Fixes
Symptom A completely and Symptom B's worst edge (a zone that holds data no
longer SERVFAILs merely because a refresh failed). Small, self-contained,
testable without new persistence.

Note what Stage 1 alone leaves: a secondary that serves its copy indefinitely,
because nothing yet enforces expire. That is strictly better than today —
today it serves for *less* than expire, which is the direction that loses data
— but it is not correct, and Stage 1 should say so in its own comments rather
than read as finished. Restart with the primary down is also still broken
(§2.3).

**Stage 2 — held copy across restart, timestamp, expire.** Three steps, one
PR, in this order, because (2) and (3) are pointless until (1):

1. **First bind of a secondary with no published snapshot: if the persisted
   zone file exists (same path as §4), `FetchFromFile` before `DoTransfer`.**
   If the transfer then fails, the file copy remains and is served. If the
   transfer succeeds, it replaces the file copy as today. Same for
   config-declared secondaries with `zonefile:` and for `storage: persistent`
   API secondaries. On the restart path `zd.Zonefile` is already set; using
   the §4 derivation also covers a persistable zone whose field is still
   empty. Do not reload the file over a live snapshot on a later failed
   refresh — the file may be older than memory.
2. `noteSuccessfulRefresh` on usable SOA (§3b), persist the sidecar, Option
   3 on absence.
3. Query and UPDATE guards: a secondary with a snapshot SERVFAILs when
   `now` is past last-success + served SOA EXPIRE. Ticker and NOTIFY keep
   trying. A usable SOA after expire un-expires.

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
- API-managed zone with empty `zd.Zonefile` still writes the sidecar next to
  `GetDynamicZoneFilePath`
- sidecar write failure is logged and does not fail the refresh
- restart with a persisted timestamp preserves the remaining expire budget
- restart with no timestamp starts the clock and logs it
- past expire, queries and UPDATE SERVFAIL; the ticker still attempts refresh
- a usable SOA after expire un-expires
- primaries are not subject to the expire guard

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
| **S2.2** | `noteSuccessfulRefresh` on usable SOA, not `err == nil`; sidecar via §4 path | `zone_utils.go`, `dynamic_zones.go` | 85 | 170 |
| **S2.3** | Secondary expire guard on query + UPDATE; ticker unchanged | same three call sites as S1 | 25 | 100 |
| | **Stage 2** | | **~150** | **~420** |
| | **Total** | | **~195** | **~620** |

**~195 production, ~620 test, ~815 all in.** Stage 1 is the small PR (~45 / ~200).
Stage 2 is larger because of tests, not because of production code.

The overrun, if there is one, is S2.1. `FetchFromFile` is a primary-shaped path
(digest, journal, `firstLoad` skips Ready until `InstallInitialSnapshot`).
Threading it under a secondary with no snapshot is the one place this brief
touches behaviour the current tests do not cover. If that fights
`completeFirstZonePolicyAndLoad`, S2.1 alone can double. S1, S2.2 and S2.3
should not.

Do not count retiring `RefreshCount` (§6). Do not count switching the ticker
to SOA RETRY (§6). Expire is not an `ErrorType`, so the ticker keeps trying
with no extra engine code.
