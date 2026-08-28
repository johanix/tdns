# A secondary should serve until SOA expire

**Date:** 2026-08-28
**Context:** tdns#413. A tdns-auth secondary stops answering as soon as one
refresh fails, and an API-provisioned secondary answers nothing below its apex
at all. Both come from one field.
**Question:** what has to exist before the query path can decide "this zone is
still authoritative for its current contents", and what does that cost?

---

## 1. The requirement

RFC 1035 §3.3.13 and RFC 2308 §4: a secondary serves the copy it holds until the
SOA **expire** interval has elapsed since the last *successful* refresh. Refresh
and retry govern how often it tries; only expire governs when it gives up. A
primary that is unreachable for ten minutes must not take the zone dark.

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

Both rest on `RefreshCount`, whose declared purpose is exactly that
(`v2/structs.go:207`):

```go
RefreshCount int // number of times the zone has been sucessfully refreshed (used to determine if we have zonedata)
```

**`RefreshCount` is incremented in exactly one place** — `initialLoadZone`,
`v2/refreshengine.go:152-153`, inside `if updated {`:

```go
if updated {
    zd.LatestRefresh = time.Now()
    zd.RefreshCount++
```

The periodic refresh loops (`:799`, `:1123`) never touch either field. So both
are set at most **once**, on initial load, and never again however many
successful refreshes follow. `LatestRefresh` is additionally **read nowhere** —
it is write-only today.

Measured, on one host:

| zone kind | `RefreshCount` |
|---|---|
| config-declared (loaded via `initialLoadZone`) | `1` |
| API-provisioned dynamic zone | `0`, permanently |

The dynamic provisioning path does not go through `initialLoadZone`, so its
zones never leave 0 — verified after a successful AXFR, while serving correct
signed data, and again after a further NOTIFY-driven refresh.

### 2.1 Symptom A — sub-apex queries never answer

With `RefreshCount == 0` the `:163` guard fires on **every** query below the
apex, unconditionally, with no error present:

```
dig @<secondary> <zone> SOA              → NOERROR      (Zones.Get path)
dig @<secondary> www.<zone> A            → SERVFAIL     (FindZone path)
dig @<secondary> nosuchname.<zone> A     → SERVFAIL     (should be NXDOMAIN)
dig @<primary>   www.<zone> A            → NXDOMAIN     (control)
```

An API-provisioned secondary therefore answers for the zone name and nothing
inside it. This is not an expire problem at all; it is the same field failing a
different question.

### 2.2 Symptom B — the first failed refresh ends service

With `RefreshCount == 0`, the `:103` guard degenerates to
`if zd.HasError(RefreshError)`. Reproduced on a zone with `expire 604800` whose
content had transferred minutes earlier:

```
[ERROR/engine] zone refresh failed zone=<zone> error=SOA probe ... unreachable
[WARN/handler] zone in error state qname=<zone> errorType=refresh
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL
```

The zone file was on disk throughout, complete and signed, `Provisioning: ready`.
It stayed dark after the primary came back, until a NOTIFY arrived — the SOA
retry timer is the only other trigger.

**Reproducing this needs care.** `zone modify` and a daemon restart both
re-provision the zone and reset the same state, so neither isolates the bug. The
clean trigger is a NOTIFY sourced from the primary's own address, which forces a
refresh attempt with no config change:

```
dig -b <primary-addr> +opcode=notify @<secondary> <zone> SOA
```

### 2.3 Why persistence makes B worse

`dynamiczones` with `storage: persistent` exists so a provisioned secondary
survives a restart. The zone data does survive — it is reloaded from the written
zone file. Every in-memory counter does not. So a restart that coincides with an
unreachable primary yields a zone that is complete on disk and unservable, which
is the case persistence was added to prevent.

## 3. What "serve until expire" actually requires

Four things, of which only the first is small.

**(a) A real "do we hold data" test.** `RefreshCount` is a proxy, and a broken
one. The direct question is whether the zone has an apex SOA: `zd.GetSOA()`
(`v2/zone_utils.go:1035`) already answers it. Replacing both guards' use of
`RefreshCount` with that fixes Symptom A outright and is a small, isolated
change.

**(b) A trustworthy last-successful-refresh timestamp.** Needed for expire, and
`LatestRefresh` cannot be used as it stands: same single assignment, same `if
updated {` gate. It has to be set on every *successful* refresh — including one
that finds the serial unchanged, which is the common case and precisely the one
that proves the primary is alive. That means touching the periodic refresh paths
as well as `initialLoadZone`.

**(c) That timestamp has to survive a restart.** This is the design decision;
§4.

**(d) The comparison, and what to return after it.** Serve while
`now < lastSuccessfulRefresh + SOA.Expire`; refuse after. BIND returns SERVFAIL
for an expired secondary, which is also what the existing guards return, so
nothing new is needed there.

## 4. The decision: where does the timestamp come from after a restart?

On restart the zone data is reloaded from disk but the process has no idea when
that data was last confirmed fresh. Four options.

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

Cost: a new persisted artefact, its write path (every successful refresh), and
its absence handling.

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
interval after a restart — the server forgets how much of the week it had
already used. For a secondary that restarts rarely this is a small deviation; it
is still a deviation from RFC 2308, and it is silent.

### Option 4 — treat unknown as expired

Strict, and defeats `storage: persistent` entirely: every restart would take
every zone dark until its first successful refresh, which is the failure this
work exists to remove. Rejected.

### Recommendation

**Option 1 with Option 3 as the fallback.** Persist the timestamp in a runtime
sidecar; when it is absent — an older deployment, a hand-placed zone file, a
corrupt sidecar — start the clock at load and log that the zone's expire budget
is being restarted. That gives correct behaviour in the normal case, a defined
and visible behaviour in the degraded one, and never the silent dark-zone of
Option 4.

## 5. Staging

The two symptoms have very different sizes and should not travel together.

**Stage 1 — fix the "have data" test.** Replace `RefreshCount` in both guards
with an apex-SOA test. Fixes Symptom A completely and Symptom B's worst edge (a
zone that holds data no longer SERVFAILs merely because a refresh failed). Small,
self-contained, testable without new persistence.

Note what Stage 1 alone leaves: a secondary that serves its copy indefinitely,
because nothing yet enforces expire. That is strictly better than today — today
it serves for *less* than expire, which is the direction that loses data — but
it is not correct, and Stage 1 should say so in its own comments rather than
read as finished.

**Stage 2 — maintain and persist the timestamp, and enforce expire.** (b), (c)
and (d) together. Larger, and the only part that touches persistence.

## 6. Out of scope

**Retry latency.** Separately from expire, a zone that enters refresh error
waits out the SOA retry before trying again — observed staying dark after the
primary returned, until a NOTIFY. Whether a failed refresh should schedule a
nearer retry is a real question and a different one.

**`RefreshCount` itself.** Once neither guard consults it, it is a counter that
increments at most once and is reported over the API. Either fix it to count
refreshes or retire it; it should not stay as it is, being read as though it
meant something.

## 7. Test plan

For Stage 1, against a provisioned secondary:

- sub-apex query for an existing name → the record, not SERVFAIL
- sub-apex query for an absent name → NXDOMAIN, not SERVFAIL
- with the primary stopped and a refresh forced by NOTIFY: apex and sub-apex
  both still answer from the held copy
- a zone that has never loaded data → still SERVFAIL (the guard's real purpose)

For Stage 2, additionally:

- successful refresh with an unchanged serial advances the timestamp
- restart with a persisted timestamp preserves the remaining expire budget
- restart with no timestamp starts the clock and logs it
- past expire, the zone stops answering

The NOTIFY trick in §2.2 is what makes the "primary down" cases testable without
waiting out a refresh timer; both stages need it.
