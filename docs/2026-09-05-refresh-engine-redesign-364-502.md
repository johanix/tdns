# Refresh engine redesign — bounded concurrency and per-refresh deadlines (#364, #502)

**Status:** design. Not implemented.
Reviewed 2026-09-05 — `reviews/2026-09-05-tdns-refresh-engine-redesign-364-502-review.md`
(*approve with should-fix*) and `…-rereview.md` (**approve**). S1–S8 and C1–C6 of the first
review and N1–N4 of the re-review are folded in below; the resolution of S3 differs from its
recommendation, is argued in §3.3, and was accepted on re-review as D7.
**Ready to implement.** Start with S0 — and keep R4's probe-vs-transfer assertion in the
same commit as the bound.
**Base:** `main` @ `2a211c4a` (S0 implemented on `fix/refresh-probe-deadline-502`; the
design was written against `d833c683` and re-verified at this base). Work in the **`v2/` tree only** (`tdns/refreshengine.go` is
the legacy tree; the live engine starts at `v2/main_initfuncs.go:304` and `:344`).
**Issues:** [#364](https://github.com/johanix/tdns/issues/364) (engine does not scale: no
jitter, O(all zones) ticks, inline network probes),
[#502](https://github.com/johanix/tdns/issues/502) (a secondary with an unreachable
upstream never finishes provisioning and blocks every zone behind it).
**Companion:** `2026-09-05-signing-publish-notify-correctness.md`. That document owns
signing, publishing and NOTIFY; this one owns concurrency and deadlines. The engine's
three NOTIFY call sites and its two `SetupZoneSigning` calls are **deleted there**, not
here — see §3.2. **The commit order spans both documents and lives in the companion's §6**;
this doc's §4 covers only its own commits and assumes the companion's C1–C5 have landed.

**Supersedes** `docs/2026-09-04-design-364-refresh-engine.md` and the #502 section of
`docs/2026-09-04-shortlist-designs.md` — both written 2026-09-04 for review on the 5th, and
both now replaced by this document and its companion. They should be deleted or marked
superseded rather than left alongside; someone reading the 09-04 pair alone would implement
a single-envelope timeout (§3.7, R4) and a `broken=[...]` acceptance criterion (§2).

---

## 0. Summary

#502 is not a separate bug. It is #364's third symptom — inline network probes on the
engine goroutine — as it presented in the lab on 2026-09-04, where one off-site zone whose
primary was unreachable made the master serve nothing and read as "DNS is down".

The shape:

1. Bound the **SOA probe**, so one dead upstream cannot stall provisioning (ships first,
   alone).
2. Extract one post-refresh body from the two drifted copies.
3. Move every `zd.Refresh` call off the engine goroutine into a bounded worker pool, with a
   separate, much smaller cap on concurrent transfers.
4. Make the engine goroutine's own work non-blocking, without exception.
5. Jitter the initial counters; retry failures on SOA RETRY.

Estimated cost: **~820 production lines added, ~290 removed (net +531), plus ~570 test
lines** (§7), across six commits (§4).

---

## 1. What is actually wrong

`RefreshEngine` (`v2/refreshengine.go:535`) is a single goroutine running a four-case
select over `zonerefch`, `ticker.C`, `bumpch` and `ctx.Done()`. The function body is ~790
lines. Everything below is a consequence of work that blocks inside it.

### 1.1 The ticker branch refreshes inline

`v2/refreshengine.go:1180` calls `zd.Refresh(ctx, ...)` **directly in the select loop**,
inside a `for zone, rc := range refreshCounters.Items()` walk. While that call is in
flight:

- no other zone refreshes;
- `zonerefch` is not read — API zone-adds, `zone reload`, config reload and
  NOTIFY-triggered refreshes all queue behind it;
- `bumpch` is not read — serial bumps hang;
- `zone list` hangs, which is the observable that identified the stall on 2026-09-04.

Not scoped to secondaries: every zone in `refreshCounters` goes through it, and for a
`Primary` that means `FetchFromFile` (`v2/zone_utils.go:511`) — parsing a large zone file —
on the engine goroutine. Less dramatic, same class, and the reason the pool takes **all**
zone types rather than special-casing on `ZoneType`.

### 1.2 Nothing bounds a single refresh

All three `initialLoadZone` call sites (`:637`, `:1075`, `:1149`) pass the engine's own
long-lived context, which has no deadline. The context *is* threaded all the way down —
`Refresh` → `DoTransfer` → `ExchangeContext` (`v2/zone_utils.go:340`) → `openTransferStream`
→ `drainTransferEnvelopes` — so a deadline set at the top is honoured, including mid-stream
(`refresh_context_test.go:81`). That is why this is a deadline, not a plumbing exercise.

| step | site | bound today |
|---|---|---|
| SOA probe, per upstream | `zone_utils.go:340`, a bare `new(dns.Client)` | miekg's 2s dial + 2s read, per upstream, tried serially |
| AXFR stream | `dnsutils.go:212` `transfer.In` | 2s **per envelope**, nothing overall — a primary dribbling one envelope every 1.9s transfers forever |
| primary hostname resolution | `resolve_primaries.go:76` | `primaryResolveTimeout` — already bounded |
| whole refresh | — | **nothing** |

### 1.3 The operator path is async, unbounded, and has drifted

`refreshengine.go:841` spawns `go func(...)` per request, directly under the comment
`// XXX: Should do refresh in parallel`. No ceiling: a catalog with a few thousand members
re-firing is an unbounded fan-out of concurrent AXFRs.

Its post-refresh body (`:841`–`:960`) and the ticker's (`:1180`–`:1270`) are near-copies
that have diverged:

| post-refresh step | async path | ticker path |
|---|---|---|
| clear `RefreshError` on a success that changed **nothing** | **yes** — bare `else` (`:857`) | **no** — only inside `else if updated` (`:1184`) |
| outbound-soa-serial (unixtime / persist) | **no** | yes (`:1195`–`1226`) |
| `DeleteOutgoingSerial` for a mirroring secondary | **no** | yes |
| persist dynamic zone + config | yes, guarded by `zoneStillLive(zd, gen)` | yes, guarded by a **live** generation read |
| write to source file | yes | yes |
| catalog re-parse + auto-configure | yes | **no** |
| `SetupZoneSigning` | yes (`:870`) | yes (`:1232`) — both deleted by the companion doc |
| NOTIFY downstreams | `NotifyQ` (`:912`) | blocking `NotifyDownstreams()` (`:1237`) — both deleted by the companion doc |

Neither column is right. Whichever body the pool calls, some class of zone silently changes
behaviour — which makes unifying them a prerequisite commit, not a tidy-up.

**Row 1 is a live bug, not just duplication.** A secondary whose primary was unreachable and
has come back, but whose serial has not moved since, refreshes successfully with
`updated == false` — and on the ticker path keeps its `RefreshError` until the serial next
changes. It is a recovered zone that still reports as failed. The union takes the async
rule: clear on any successful refresh.

### 1.4 Counter scheduling

`initialLoadZone` sets `CurRefresh: refresh` (`:131`, `:145`), so zones sharing a SOA
REFRESH — the normal case for template-provisioned lab zones — come due on the same tick
and are then refreshed strictly serially by §1.1.

A *failed* refresh reschedules at the full SOA REFRESH: `rc.CurRefresh = rc.SOARefresh` at
`:1181` runs **before** the error check at `:1182`. The zone's SOA RETRY is never consulted
anywhere in the engine. First-load failures instead get fixed fallbacks — `CurRefresh: 30`
at `:643`/`:665`, then `SOARefresh: 300` from the same fallback.

`refreshCounters.Items()` (`:1122`) copies the whole map every second
(`v2/core/concurrent_map.go:286`); `IterCb` (`:305`) walks it without the copy.

### 1.5 One thing the pool exposes

Every updated persistable dynamic zone calls `AddDynamicZoneToConfig`
(`v2/dynamic_zones.go:636`), which rewrites the **entire** dynamic config file under a
global `dynamicConfigMutex`. Serially that is invisible; with N workers it is N whole-file
rewrites per cycle serialised on one mutex. Not a correctness problem — see §6/R6.

---

## 2. Acceptance criteria

Not a benchmark:

> One unreachable upstream must not prevent any other zone from being served, and the
> affected zone must say what is wrong with it — naming the upstream it could not reach,
> visible to an operator without reading the log.

Concretely:

1. One secondary pointed at a blackholed address plus one healthy zone: the healthy zone
   answers within seconds of startup and keeps answering.
2. The stuck zone is visible on `zone list`, annotated with a `RefreshError` **that names
   the upstream that could not be reached**.
3. `zone list` responds while the stuck zone is stuck.
4. The stuck zone recovers by itself when the upstream returns, with no operator action —
   including when its serial has not moved (§1.3, row 1).
5. A zone whose refresh is still running is never refreshed a second time concurrently.
6. Nothing writes a zone file for a zone deleted while its refresh was in flight.
7. A `Wait`-ing caller (`tdns-cli zone reload`) always gets a response, including when the
   refresh was skipped or the pool was saturated.

**Not** `broken=[...]`. That is `ParseZones`' config-reject list (`parseconfig.go:893`), and
`RefreshError` is deliberately not service-impacting (`enums.go:445`: the service-impacting
set is `ConfigError`, `AgentError`, `DnssecError`) — a zone serving stale data is still
authoritative for what it holds. The 2026-09-04 incident's empty `broken=[]` meant "the
config was fine, the engine was stuck", and adding refresh failures to that list would
recategorise a serving zone as a config failure to make one incident read better.

---

## 3. Design

### 3.1 The invariant

> **The engine goroutine performs no *unbounded* blocking operation** — nothing that can
> wait indefinitely on the network, on the filesystem, or on a full channel.

The one deliberate bounded exception is `initialLoadZone`, which stays on the engine
goroutine (§3.11) and is bounded by §3.7. Everything else — every steady-state refresh,
every transfer, every channel send the engine makes — is either off the goroutine or
non-blocking. That is what review should check.

### 3.2 One refresh body — `runZoneRefresh`

New file `v2/refresh_run.go`:

```go
type refreshOutcome struct {
	Zone    string
	Updated bool
	Err     error
}

// runZoneRefresh performs one complete refresh of zd and everything that must
// follow it. It is the only production caller of zd.Refresh outside first load,
// and must never run on the engine goroutine: every step in it can block.
//
// gen is the zone's generation snapshotted at DISPATCH time; the persist steps
// are gated on zoneStillLive(zd, gen) so a zone deleted or replaced mid-refresh
// is not resurrected on disk (B5b).
func runZoneRefresh(ctx context.Context, job refreshJob, conf *Config) (bool, error)
```

Body — the union of the two columns in §1.3, taking the correct value of each row:

1. `zd.Refresh(ctx, ..., job.gate)` — see §3.3 for the gate; on error `noteRefreshFailure`
   (which already treats `context.Canceled` as shutdown, not a sick zone — `:79`).
2. Clear `RefreshError` **on any successful refresh**, `updated` or not (§1.3 row 1). Other
   categories survive.
3. Outbound-soa-serial handling, including `DeleteOutgoingSerial` for a mirroring
   secondary. **From the ticker column** — the async path lacks it.
4. Persist: `WriteDynamicZoneFile` + `AddDynamicZoneToConfig` when
   `conf.ShouldPersistZone(zd) && zoneStillLive(zd, gen)`; else `WriteFile(zd.Zonefile)`
   when `refreshWritesZoneToSourceFile(zd)`. Primary-and-not-dirty skips, as today.
5. Catalog re-parse, then `AutoConfigureZonesFromCatalog` **dispatched to its own
   goroutine**, as `:939` already does. That call sends on `RefreshZoneCh`, and a worker
   blocked on a full engine channel is a deadlock: the engine is the only reader, and it is
   waiting on nothing else. Keep the goroutine (with its `recover`), or make the send
   non-blocking — not a direct call.
6. **Send `zr.Response` when the job carries a `Wait`-ing caller.** The worker owns this,
   not the engine: it is the only party that knows the outcome. Today the async goroutine
   does it at `:851` (error) and `:955` (success); that behaviour moves here unchanged.

**No signing step and no NOTIFY step.** Both leave the refresh path in the companion
document: once a refresh publishes already-signed data and publish emits the NOTIFY, there
is nothing for the tail to do.

`initialLoadZone` keeps its own body — first load is genuinely different (counter creation,
`tryPostpass`, `FirstZoneLoad` bookkeeping) and merging it here is a larger change.

### 3.3 The pool, the transfer gate, and the drain protocol

New file `v2/refresh_pool.go`:

```go
type refreshJob struct {
	zd    *ZoneData
	zone  string
	gen   uint64          // generation at dispatch (B5b)
	force bool
	gate  *transferGate   // the pool's transfer cap; nil means ungated
	zr    *ZoneRefresher  // nil for ticker jobs; carries Response when Wait is set
}

type refreshPool struct {
	jobs chan refreshJob
	done chan refreshOutcome
	gate *transferGate
	wg   sync.WaitGroup
}

func newRefreshPool(ctx context.Context, width, queue, transfers int, conf *Config) *refreshPool
func (p *refreshPool) TryDispatch(job refreshJob) bool
func (p *refreshPool) Done() <-chan refreshOutcome
func (p *refreshPool) Shutdown()   // close(jobs); wg.Wait()
```

**Width and dispatch.** `width` workers, each `for job := range p.jobs` → `runZoneRefresh` →
send the outcome. `TryDispatch` sends **non-blocking**
(`select { case p.jobs <- job: default: }`) and returns false when the queue is full; the
engine never blocks on dispatch. `queue` defaults to `4 × width`.

**The transfer gate, and why it is passed rather than acquired around `Refresh`.** The
review's S3 is right that the token must not be a property of `Refresh` acquired wherever
`Refresh` happens to run — a first-load AXFR on the engine goroutine would then block on a
full semaphore and violate §3.1. But its recommendation, "acquire the token in
`runZoneRefresh`, not inside `Refresh`", cannot be implemented as stated: `Refresh` performs
the probe **and** the transfer in one call (`DoTransfer` at `zone_utils.go:159`, then
`FetchFromUpstream` at `:170`), so the only span visible from `runZoneRefresh` is both of
them together. Acquiring there would mean 64 workers contending for 10 tokens *while doing
five-second SOA probes* — a worse bottleneck than the one being removed, and one that caps
probe concurrency at the transfer cap.

So the gate is **owned by the pool and passed down**:

```go
// transferGate caps concurrent inbound zone transfers. It is created and owned
// by the refresh pool and threaded to FetchFromUpstream, which is the only span
// worth capping: the probe is one query, the transfer is bandwidth, parse CPU
// and ~2x the zone in memory.
//
// A nil gate means ungated, which is what tests and the first-load path get.
// First load runs one zone at a time on the engine goroutine, so it cannot
// produce the concurrency the gate exists to bound -- and gating it there would
// block the engine on a full semaphore (review S3).
//
// So peak concurrent inbound transfers is transferconcurrency + 1, not
// transferconcurrency, for as long as a first load overlaps the pool (review
// N2). Sized for deliberately: the +1 is one zone, it ends when first load
// does, and it disappears entirely if first load ever moves into the pool.
type transferGate struct{ tokens chan struct{} }

// acquire blocks until a token is free or ctx ends, and returns ctx.Err() in
// the latter case -- context.Canceled on shutdown, which noteRefreshFailure
// already treats as a dying process rather than a sick zone (`:80`). Returning
// a bespoke error here would flag every zone waiting on the gate at shutdown
// as failed (review N4).
func (g *transferGate) acquire(ctx context.Context) error // nil gate => nil
func (g *transferGate) release()
```

`Refresh` and `FetchFromUpstream` take it as a parameter. Ownership stays with the pool —
the pool decides the cap and creates the tokens — while the *span* gated is the one that
should be. `Refresh` remains callable from tests and from first load with `nil`.

**The drain protocol** (review S5). Three requirements, all necessary together:

- `done` is buffered to `width`, **and** the worker's outcome send is
  `select { case p.done <- out: case <-ctx.Done(): }`. Either alone leaves a hole: an
  unbuffered `done` plus an engine that has stopped selecting on it wedges every worker on
  send, and `Shutdown` never returns.
- `Shutdown` closes `jobs` so each worker's `range` exits after its current job, then
  `wg.Wait()`s.
- The engine calls `Shutdown` before it returns, so no file write outlives the engine.

`TestRefreshEngineExitsOnRootCancel` (`refresh_engine_shutdown_test.go:22`) must pass
unchanged, and gains a variant with jobs in flight.

### 3.4 Per-zone exclusion is free — do not build a lock

Two concurrent refreshes of one zone are unsafe: `ZoneTransferIn` replaces `zd.Data`
wholesale (`v2/dnsutils.go:253`), and the `FetchFrom*` paths do a `FirstZoneLoad`
read-modify-write. The serial ticker keeps the window narrow today; a pool widens it to a
certainty.

**In production, `zd.Refresh` has exactly three call sites and all three are in
`refreshengine.go`** (`:97`, `:847`, `:1180`). Tests call it directly and legitimately —
the rule below is about production code, not about `_test.go`. After this change the only
dispatcher is the engine goroutine, so:

```go
inflight := map[string]struct{}{}   // owned by the engine goroutine; no mutex, ever
```

Set **after `TryDispatch` returns true**, cleared when the outcome is received — both on the
same goroutine, so the exclusion is correct by construction with no synchronisation. A zone
already in flight is skipped, not queued.

The order matters and "set at dispatch" is the wrong way to read it (review N1). Marking the
zone in flight and *then* attempting the send pins it forever whenever the queue is full:
nothing was dispatched, so no outcome ever arrives to clear the entry, and the zone is never
refreshed again for the life of the process. Either set the entry only on the true branch,
or clear it on the false one — not "set, then try".

**A skip must never strand a `Wait`-ing caller** (review S4). Today the operator path always
answers a `Wait` refresher (`:851` / `:955`). After the pool there are two new ways to
produce no answer at all — the zone is already in flight, or `TryDispatch` returned false —
and a silent skip hangs `tdns-cli zone reload`. So, on the engine goroutine, before
skipping:

| condition | response to a `Wait`-ing caller |
|---|---|
| zone already in flight | error: `refresh already in progress for zone X` |
| `TryDispatch` returned false | error: `refresh pool saturated; zone X will retry on its next tick` |
| dispatched | nothing here — the worker answers (§3.2 step 6) |

Load-bearing enough to state as a rule: **`zd.Refresh` must not acquire a new production
call site.** Anything wanting a zone refreshed sends a `ZoneRefresher` on `RefreshZoneCh`.
Worth a comment on `Refresh` itself.

### 3.5 Scheduling — counters stay loop-owned

`refreshCounters` stays a `ConcurrentMap` (other code reads it), but **only the engine
goroutine writes `rc`**. Workers never touch a counter. A fourth select case:

```go
case out := <-pool.Done():
	delete(inflight, out.Zone)
	if rc, ok := refreshCounters.Get(out.Zone); ok {
		if out.Err != nil {
			rc.CurRefresh = rc.SOARetry     // D1: degraded, on the zone's own retry timer
		} else {
			rc.CurRefresh = rc.SOARefresh
		}
	}
```

Reset **at completion**, not at dispatch. Today `rc.CurRefresh = rc.SOARefresh` at `:1181`
runs immediately after the inline refresh returns, so reset *is* completion by
construction; off-loop the choice becomes explicit, and reset-at-dispatch would silently
double the effective interval for exactly the slow zones that can least afford it.

**A zone that was not dispatched keeps its counter** (review S6). The ticker decrements and
fires at `<= 0` (`:1124`); an in-flight skip or a failed `TryDispatch` must **not** write
`CurRefresh`. Leaving it at or below zero is what makes the next tick retry, which is the
behaviour wanted in both cases.

### 3.6 D1 — a zone whose upstream is unreachable stays on its SOA RETRY

**Decided: degraded, not quarantined.** The zone is marked with an error, keeps serving
what it has until SOA EXPIRE (per #413's fix), and retries **on its SOA RETRY timer**. The
engine never waits for it, and no operator action is needed when connectivity returns.

That needs a value the engine does not currently read. `RefreshCounter` gains
`SOARetry uint32`, filled by a new `FindSoaRetry` — which must **not** be a copy of
`FindSoaRefresh` with one field changed:

- **Primaries.** `FindSoaRefresh` returns a flat `86400` for `Primary` (`:1338`–`:1342`),
  before any clamping and without consulting the SOA it just read, because a primary
  re-stats a file rather than probing a peer. `FindSoaRetry` needs the same special case:
  the SOA's RETRY field describes a secondary's behaviour toward a primary and is
  meaningless for the zone's own file. Use the same flat value.
- **Clamping.** Same floor and ceiling as REFRESH (`defaultMinRefresh` = 60 s, `MaxRefresh`),
  so a pathological RETRY cannot spin the pool. See §6/R11.
- **Adopted copies.** `initialLoadZone`'s adopted-persisted-copy path fills a counter
  directly (`:128`–`:132`) after a *failed* first transfer. It must set `SOARetry` too, or
  precisely the zones that failed their first transfer sit on the 300 s fallback forever —
  the case D1 exists to serve.
- **Never-loaded zones** have no SOA to read and keep the fixed fallback: `CurRefresh: 30`
  for the first attempt, then 300 s. One prompt retry after a boot-order failure is the
  case that heals itself fastest.

The failure path in §3.5 uses `SOARetry`; the success path uses `SOARefresh`. This is also
what makes the sizing arithmetic benign — §3.9.

### 3.7 D2 — split the probe and transfer deadlines, and apply them where they bite

**Decided: split.** A single generous bound has to cover both a 2 s SOA probe and a
legitimate slow AXFR of a large zone, and it forces the dead-zone worker cost (wants a small
timeout) to pay for the big-zone transfer budget (wants a large one).

The two bound different populations: **a transfer only happens when the SOA probe found a
higher serial — i.e. when the primary just answered.** Dead primaries never reach the
transfer stage; they die in the probe.

That decides *where* each deadline goes, and getting it wrong is how S0 becomes a
regression (review S2):

| bound | default | applied at |
|---|---|---|
| `probetimeout` | 5 s | **inside `DoTransfer`, per upstream attempt** — a `context.WithTimeout` around each `ExchangeContext` (`zone_utils.go:340`) |
| `transfertimeout` | 300 s | around the transfer only — `FetchFromUpstream` / `ZoneTransferIn` |

A single `context.WithTimeout(ctx, transfertimeout)` wrapped around `zd.Refresh` — the
obvious reading of "a deadline in `initialLoadZone`" — would make one blackholed primary
cost **300 seconds on the engine goroutine at boot**, serially, per zone. That is not a
stopgap, it is the same outage with a longer name. S0 is only worth shipping first because
the probe bound makes a dead primary cost 5 s × upstreams.

5 s rather than miekg's 2 s default: 2 s is tight for a slow-but-alive primary, and the cost
of the larger value is paid only by zones that are actually failing.

**Two things S0 found in the implementing, both load-bearing:**

- **The client's own `Timeout` has to be set, not just the context's deadline.** miekg
  *tightens* socket deadlines to the earlier of `Client.Timeout` and `ctx.Deadline()`, and
  with `Timeout` unset that is its 2 s default — so any `service.probetimeout` above 2 s
  would be silently inert and the knob would look like it did nothing.
- **The probe must go through `exchangeCancellable`** (`childsync_utils.go:53`), not
  `ExchangeContext`. The latter hands the context to the dial and then only tightens
  deadlines with it; it never watches `ctx.Done()`, so a read already in flight runs to the
  full budget regardless of cancellation. That was tolerable at 2 s and is not at 5 s: every
  shutdown would wait out an in-flight probe. `exchangeCancellable` closes the connection
  instead, and it honours `c.Dialer`, so the transfer-src binding (#409) and the XoT client
  survive the switch. `SendUpdate` already uses it for the same reason.

**The error must name the upstream** (review C5, acceptance criterion 2). `noteRefreshFailure`
records `"refresh error: %v"` (`:87`), and `DoTransfer`'s all-unreachable return names the
zone and the upstream *count* but only carries an address if the wrapped `lastErr` happens
to include one — which a bare `context.DeadlineExceeded` from the new probe bound does not.
S0 wraps the probe failure with the address actually tried (all of them, or the last),
before it reaches `SetError`.

### 3.8 The B5b generation snapshot

The async path snapshots `gen := zd.generation.Load()` at dispatch (`:846`) and gates the
persist on `zoneStillLive(zd, gen)` (`:879`). The ticker path passes
`zd.generation.Load()` **live** at `:1244` — correct only because, inline, it cannot drift.

Move that path off-loop unchanged and the check silently reduces to the identity test,
reopening the resurrection race B5b closed: a zone deleted mid-refresh gets its file
rewritten and its entry re-added to the dynamic config. Nothing fails loudly.

So `gen` is a field on `refreshJob`, snapshotted by the engine goroutine at dispatch. Same
commit as the pool, not a follow-up.

### 3.9 Sizing — width is an absorption number, not a throughput number

Steady-state occupancy is `N × RTT / I`. At the scale #364 cites — 100k zones, 1 h refresh,
20 ms RTT — that is **0.55 workers**. The lab needs 0.0003. In the healthy case one worker
does everything; the pool exists to absorb refreshes that are *stuck*.

With the in-flight map (§3.4), a hanging zone occupies at most one worker, and its cost is:

```
workers held  ≈  D × min(1, T / R)
```

*D* = simultaneously unreachable zones, *T* = probe timeout, *R* = that zone's retry
interval. With D1 (§3.6) making *R* the zone's SOA RETRY — typically 900–3600 s — and
*T* = 5 s, each dead zone costs under 1% of a worker. A never-loaded zone on the 300 s
fallback costs 1.7%. Width stops tracking D almost entirely, which is the point of taking
D1 and D2 together.

**Three resources, three answers.** Sizing one number for all of it is the mistake:

| work | cost | width |
|---|---|---|
| SOA probe | one query, a socket, ~4 KB of goroutine | wide is free |
| transfer | bandwidth, parse CPU, and ~2× that zone's memory while it runs — `ZoneTransferIn` rebuilds `zd.Data` (`dnsutils.go:253`) while the published snapshot still holds the serving copy | **narrow**, via the gate (§3.3) |
| signing | a full CPU pass; after the companion doc's C1 it happens inside publish, still under `zd.mu` | bounded by the zone lock, not by pool width |

Defaults:

| key | value | read |
|---|---|---|
| `service.refreshworkers` | **64** | once, at engine start — resizing a live pool is complexity for nothing |
| `service.transferconcurrency` | **10** | once, at engine start |
| `service.probetimeout` | **5 s** | `RuntimeConfig` (`runtime_config.go:29`), per refresh |
| `service.transfertimeout` | **300 s** | `RuntimeConfig`, per refresh |

64 workers cost ~256 KB of idle goroutines and absorb a 64-zone correlated failure even at
full duty. Not auto-sized from zone count: demand tracks *dead* and *due* zones, not total,
so a derived number would be confidently wrong in the case that matters.

`service.refreshworkers: 1` is the conservative setting and the rollback (§6) — serial, but
still **off** the engine goroutine, so the availability property survives. That is better
than keeping the old inline path behind a flag, which would preserve the bug and double the
code under test.

**The honest limit.** None of this survives a genuinely correlated failure — one primary
serving 5000 of our zones goes down and no width is enough. The fix for that is per-upstream
backoff: track failures keyed on the upstream *address* and skip the probe while the breaker
is open, so dead zones cost ~0 workers regardless of D. Named as the follow-up that
supersedes this whole question at scale; **not in this change.**

### 3.10 Jitter

In `initialLoadZone`, set the first counter to a random value in `[1, refresh]` instead of
`refresh`. Two details:

- **Do not jitter a zone that has never loaded.** It retries on its short fallback and must
  not be pushed out by up to a full refresh interval.
- **Jitter at load, not at every reset.** Re-jittering every cycle makes the effective
  interval drift and bug reports irreproducible.

Seed from a package-level `*rand.Rand` tests can replace.

### 3.11 What stays on the engine goroutine

Unchanged and all non-blocking: the `zonerefch` config-merge block (`:600`–`:800`),
`Zones.Set`/`Get`, counter arithmetic, `bumpch` (`BumpSerial` is in-memory), and response
sends on buffered or `select`-guarded channels.

`initialLoadZone` is the **one bounded exception** named in §3.1. It stays here because the
pre-registered-stub path is entangled with the config-merge block, and it is made safe by
the probe bound (§3.7) rather than by concurrency: first load is one zone at a time, so it
cannot produce the transfer concurrency the gate exists to bound, and it therefore runs with
a nil gate (§3.3). Moving first load into the pool would let §3.1 drop its exception
clause; it is a follow-up, not required by §2.

---

## 4. Staging

**This table is not the whole order.** The companion document's C1–C5 land between S0 and
S1 — see companion §6. §3.2 assumes they have: an implementer who extracts `runZoneRefresh`
with the signing and NOTIFY tails still in it will write code that C3 and C5 then delete.

| # | commit | what | LOC (§7) |
|---|---|---|---|
| S0 | `refresh: bound the SOA probe and name the upstream` | §3.7 — the **probe** bound inside `DoTransfer`, the transfer bound around the transfer, and a `RefreshError` carrying the address tried. The #502 stopgap. **Ships first, before the companion's C1.** ✅ **implemented** on `fix/refresh-probe-deadline-502` | 113 |
| S1 | `refresh: one post-refresh body` | Extract `runZoneRefresh` (§3.2) from the two drifted copies, including the `RefreshError`-clearing fix (§1.3 row 1) and the `Wait` response. §1.3 is the review checklist. | ~245 |
| S2 | `refresh: retry a failed refresh on SOA RETRY` | §3.6 — `FindSoaRetry` with the primary case, `RefreshCounter.SOARetry`, the adopted-copy fill, the failure path. | ~90 |
| S3 | `refresh: bounded worker pool` | §3.3 + §3.4 + §3.5 + §3.8: pool, transfer gate, `inflight`, `Wait` answers, drain protocol, dispatch-time `gen`. Fixes #502 properly. | ~275 |
| S4 | `refresh: jitter the first counter` | §3.10. | ~30 |
| S5 | `refresh: walk the counters without copying them` | `Items()` → `IterCb`. | ~10 |

`initialLoadZone` needed no wiring of its own: with both bounds inside `DoTransfer` and
`FetchFromUpstream`, every caller inherits them, and the address now travels in the error
that `noteRefreshFailure` already records as `RefreshError`.

S0 alone because it is small, obviously safe, and makes the lab survivable today. S1 before
S3 because dispatching to a pool that calls one of two drifted bodies is how a class of zone
silently loses its serial handling. S2 before S3 because the pool's completion case (§3.5)
is where the retry value is consumed.

---

## 5. Decisions — all settled

| # | question | decision |
|---|---|---|
| D1 | unreachable upstream: degraded or quarantined? | **Degraded**, retrying on the zone's SOA RETRY (§3.6) |
| D2 | one timeout or two? | **Two** — probe 5 s inside `DoTransfer`, transfer 300 s around the transfer (§3.7) |
| D3 | reset the counter at dispatch or completion? | **Completion**, and not at all on a skip (§3.5) |
| D4 | NOTIFY on a full queue: drop or block? | Moot here — NOTIFY leaves the refresh path entirely (companion §3.4/§3.5) |
| D5 | kill-switch shape | `service.refreshworkers: 1`, not a restored inline path (§3.9) |
| D6 | pool width / transfer cap | **64 / 10** (§3.9) |
| D7 | where the transfer cap is acquired | **Passed from the pool into `FetchFromUpstream`**, not acquired around `Refresh` (§3.3) |

---

## 6. Risk assessment

| # | risk | likelihood | impact | mitigation | how it shows up |
|---|---|---|---|---|---|
| R1 | Two concurrent refreshes of one zone corrupt zone data (`zd.Data` replaced wholesale; `FirstZoneLoad` read-modify-write) | **high** without the guard — the pool turns a narrow window into a certainty | **severe**: served zone is garbage or empty | `inflight` (§3.4) in the **same commit** as the pool; no new production call site for `zd.Refresh` | targeted test (§8); in the wild, a zone that empties after a reload during a transfer |
| R2 | B5b resurrection race reopens on the ticker path | **high** if §3.8 is skipped — it is a silent no-op, not a failure | moderate: a deleted zone reappears on disk and in the dynamic config | `gen` on `refreshJob`, snapshotted at dispatch | delete-mid-refresh test |
| R3 | Unifying the two tails silently changes behaviour for some class of zone | **medium** — they have drifted eight ways (§1.3) | moderate: e.g. a `unixtime` zone stops advancing its outbound serial | S1 lands alone; §1.3 is the checklist; per-row justification in the commit message | zone-type-matrix test |
| R4 | S0 implemented as one envelope around `Refresh` | **medium** — it is the obvious reading | **severe**: 300 s per dead zone on the engine goroutine at boot; the outage returns | §3.7 names the two application points explicitly; S0's test asserts a blackholed primary costs ~probe-timeout, not transfer-timeout | boot time with one dead primary |
| R5 | A `Wait`-ing caller is skipped and never answered | **medium** — the skip path is new | moderate: `tdns-cli zone reload` hangs, and the operator's next move is a restart | §3.4's response table; a test that reloads an in-flight zone | CLI hang |
| R6 | Shutdown wedges: workers blocked sending outcomes the engine no longer reads | **medium** if only one half of §3.3's drain protocol is implemented | moderate: the daemon does not exit | buffered `done` **and** `select`-with-`ctx` on send **and** `close(jobs)` | `TestRefreshEngineExitsOnRootCancel` with jobs in flight |
| R7 | `KeyDB` mutex contention — `noteSuccessfulRefresh` writes on every confirmation, one mutex for the whole DB | medium at width 64 | low: a throughput ceiling, not correctness | do not parallelise DB work; the win is parse + digest + network wait | refresh wall-time flat as width rises |
| R8 | Dynamic-config rewrite storm: N workers each rewriting the whole file under one mutex (§1.5) | medium with many persistable dynamic zones | low–moderate: I/O amplification | out of scope; if it bites, coalesce behind a dirty flag + single writer | file-write count per cycle |
| R9 | A worker writes a zone file after shutdown began | low | low | workers stop after the current job; `Shutdown` before the engine returns; `zoneStillLive` still gates | existing shutdown test |
| R10 | Jitter makes tests flaky | medium if unseeded | low | injectable `*rand.Rand` (§3.10) | CI |
| R11 | A zone whose SOA RETRY is pathologically small (say 60 s) with a 5 s probe still costs 8% of a worker each | low | low | RETRY clamped to the same floor as REFRESH (§3.6); per-upstream backoff (§3.9) is the real answer at scale | worker occupancy |
| R12 | 10 concurrent transfers overwhelm a small primary serving many of our zones | low–medium | moderate, and it is *their* outage | `service.transferconcurrency`, documented as per-server not per-primary | REFUSED bursts, upstream complaints |
| R13 | Merge pain — `RefreshEngine` is ~790 lines and S1/S3 move most of it | medium | low but annoying | land promptly; catch up with `git merge origin/main`, never rebase | conflicts |

**Rollback.** `service.refreshworkers: 1` restores serial refresh without restoring the
stall. If S3 must be reverted outright, S0–S2 stand alone and still deliver §2 in weakened
form — bounded, not concurrent.

**The three that matter.** R1 and R2 produce silent wrong behaviour rather than a visible
failure, and both are guards that must ship inside S3. R4 is the one that would make the
stopgap a regression while looking like a fix.

---

## 7. LOC estimate

`v2/` only. `refreshengine.go` is 1363 lines; the two post-refresh bodies are 120 and 91.

| stage | file | added | removed | net |
|---|---|---|---|---|
| S0 | `zone_utils.go` — budgets + helpers, per-attempt probe deadline, `exchangeCancellable`, per-attempt transfer deadline, upstream-naming error wrap | 103 | 10 | +93 |
| S0 | `runtime_config.go` — two scalars + viper reads | 4 | 0 | +4 |
| S0 | config samples (auth, agent) | 16 | 0 | +16 |
| S1 | `refresh_run.go` (new: `runZoneRefresh`, `refreshOutcome`) | 205 | 0 | +205 |
| S1 | `refreshengine.go` — both tails deleted, call sites rewired | 35 | 211 | −176 |
| S2 | `refreshengine.go` — `FindSoaRetry` (incl. primary case), `SOARetry`, adopted-copy fill, failure path | 85 | 8 | +77 |
| S3 | `refresh_pool.go` (new, incl. `transferGate` and the drain protocol) | 215 | 0 | +215 |
| S3 | `refreshengine.go` — pool lifecycle, 4th select case, `inflight`, `Wait` answers, dispatch ×2, `gen` | 115 | 48 | +67 |
| S3 | `zone_utils.go`, `dnsutils.go` — thread the gate into `Refresh` / `FetchFromUpstream` | 22 | 4 | +18 |
| S4 | `refreshengine.go` — jitter + injectable rand | 30 | 3 | +27 |
| S5 | `refreshengine.go` — `Items()` → `IterCb` | 6 | 4 | +2 |
| | **production total** | **822** | **291** | **+531** |

Tests:

| file | LOC |
|---|---|
| `refresh_pool_test.go` — dispatch, exclusion, saturation, transfer gate, `Wait` answers, drain with jobs in flight | 210 |
| `refresh_unreachable_upstream_test.go` — the #502 reproduction, plus the probe-vs-transfer bound assertion (R4) | 145 |
| `refresh_run_test.go` — the §1.3 matrix, including `RefreshError` cleared on an unchanged success | 105 |
| `refresh_retry_test.go` — SOA RETRY, the primary case, the adopted-copy fill, never-loaded fallback | 70 |
| `refreshengine_jitter_test.go` | 40 |
| **test total** | **570** |

**Overall: ~1690 lines touched, ~1100 net new.** The largest single piece is
`refresh_run.go`, and roughly half of that is comment carried over from the two bodies it
replaces — those annotations are the record of why each step is where it is, so they move
rather than being dropped.

Confidence: S1 and S3 are firm (the code being moved is countable). S0 grew from the first
estimate because the probe bound belongs inside `DoTransfer` rather than in one wrapper. The
test figures are the softest number and should be read as a floor.

---

## 8. Testing

- **#502 reproduction.** A secondary whose primary is a blackholed address (RFC 5737
  `192.0.2.1`, or a closed loopback port) plus a healthy zone. Assert the healthy zone
  answers within seconds of startup, the stuck zone shows a `RefreshError` **naming the
  upstream**, and `zone list` responds throughout. **Fails today.**
- **The stopgap is a stopgap (R4).** With one blackholed primary, boot cost is bounded by
  probe-timeout × upstreams, not by transfer-timeout. This test is what stops S0 being
  implemented as a single envelope.
- **Recovery without a serial change (§1.3 row 1).** A zone that failed, then refreshes
  successfully with `updated == false`, has its `RefreshError` cleared.
- **Per-zone exclusion.** Two triggers for one zone against a slow fake upstream; exactly
  one `Refresh` runs, `FirstZoneLoad` bookkeeping intact.
- **`Wait` is always answered.** Reload a zone that is already refreshing, and reload into a
  saturated pool: both return an error promptly rather than hanging.
- **B5b.** Delete a zone mid-refresh; no zone file written, no dynamic-config entry
  re-added.
- **§1.3 matrix.** One assertion per row, so the unification cannot quietly drop a
  behaviour.
- **Retry.** A failed refresh reschedules at SOA RETRY; a primary gets the flat value, not a
  RETRY read from its own file; an adopted copy gets a real `SOARetry`; a never-loaded zone
  keeps the 30 s-then-300 s fallback.
- **Saturation and the gate.** `width` slow zones plus one more: the extra is skipped, not
  queued, its counter is untouched, and it refreshes on the next tick. Separately,
  `transferconcurrency + 1` transferring zones: the extra waits on the gate, and the SOA
  probes of unrelated zones are **not** blocked by it.
- **Drain.** Cancel the root context with jobs in flight; the engine returns and no worker
  is left blocked on an outcome send.
- **Jitter.** N zones with identical SOA REFRESH get distributed initial counters.
- Must still pass unchanged: `TestRefreshEngineExitsOnRootCancel`,
  `TestCancelledRefreshDoesNotStrandZoneStatus`,
  `TestNoteRefreshFailureIgnoresCancellation`, and all of `refresh_context_test.go`.
- Run all three test modules — `go test ./...` from `v2/` skips `v2/cli` and `v2/cache`.

---

## 9. Out of scope

- **Per-upstream backoff / circuit breaking** (§3.9). The thing that makes width a
  non-question at scale, and the natural follow-up.
- **The due-time heap / timing wheel** (#364 stage 2 proper). 11.55 ms/s at 100k zones is
  irrelevant at lab scale; S5 takes the cheap half.
- **Moving first load into the pool** (§3.11) — which would let §3.1 drop its exception.
- **Coalescing dynamic-config rewrites** (R8).
- **Parallelising the Notifier** (`v2/notifier.go:45`) — see the companion doc.
- **IXFR.** Untouched.

Do not close #502 when this lands without re-running it against the lab: the provisioning
path is what actually failed, and "the engine no longer stalls" is necessary but may not be
sufficient for "the zone finishes provisioning".
