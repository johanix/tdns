# Resigner registration that cannot fail (tdns #1033): scope

**Date:** 2026-11-11
**Status:** SCOPED, and (1) built on branch `fix/1033-resigner-registration`, on main after #995. Johan's decisions of
2026-11-11 are in §6.
**Issue:** johanix/tdns#1033. Split out: the worker pool (johanix/tdns#1034), zones added at run time
(johanix/tdns#1035), and tdns-mp's `sendResignRequest` (johanix/tdns-mp#414).
**Read at:** tdns `origin/main` f26a5d73; tdns #995 at 072796b4 (before it merged);
tdns-mp `origin/main` 2ef19180.
**Touches:** `2026-09-05-signing-publish-notify-correctness.md` §C5 and the `ResignReason` table.
Both describe `ResignPeriodic` and `registerForPeriodicResign(resignq) error`, and both need
updating with the fix.

---

## 1. Paths that register a zone or depend on the watchlist

### Registration: a `ResignPeriodic` send that can time out

| # | Path | Where | On failure today |
|---|------|-------|------------------|
| R1 | Config zone, first load (OnFirstLoad) | `v2/parseconfig.go:1515` | Logs an Error. The zone is never renewed. |
| R2 | Zone built by the RefreshEngine: dynamic zones loaded at boot, catalog members | `v2/refreshengine.go:1161` | Same. |
| R3 | Dynamic primary, first load | `v2/dynamic_primary.go:431` | Same. |
| R4 | `StartSigning` (#995) | `v2/signing_role.go:227` at 072796b4 | Logs "signed but not registered". It waits holding `policyApplyMu`, which is released by a defer. |
| R5 | **tdns-mp** `SetupAgentAutoZone`: the agent's or auditor's identity zone | tdns-mp `v2/agent_setup.go:121-127` | Sends `ResignPeriodic` straight into `ResignQ` with a 5 s timeout, then **returns an error**, so identity setup fails outright. It skips `registerForPeriodicResign` on purpose, because that function returns early for `AppTypeAgent` (`zone_utils.go:2307`). |

`registerForPeriodicResign` is at `v2/zone_utils.go:2306`, and its timeout `resignRegisterTimeout` (2 s) is at
`:2304`.

R1–R3 run in `drainAndRunOnFirstLoad` (`refreshengine.go:301`). That is called from
`completeFirstZonePolicyAndLoad` (`:469`) and `finishFirstLoadPolicy` (`:363`), which the
RefreshEngine loop calls at `:127` (in `initialLoadZone`), `:848`, `:1216`, `:1306` and `:1329`. So
whenever the queue is full, each zone's first load holds up **the whole RefreshEngine** for 2 s:
loads, refreshes and NOTIFY-driven transfers all wait. At boot the 10 slots fill whenever more than
10 zones load during one replace or sweep.

### What reads the watchlist and the flags

- **Sweep.** `resigner.go:210-229` walks `ZonesToKeepSigned`, a map local to the goroutine.
  `resignSweepZone` (`:279`) skips a zone that has neither signing option, replaces signatures when
  `resignPending` is set, and then calls `RenewZoneSignatures`. That takes `zd.mu` for the whole pass
  (`sign_renew.go:76`), after resolving keys and clamp without the lock (`:57-71`).
- **Wake.** `nextResignWake(ZonesToKeepSigned)` (`:67`), plus `earlierResignWake` on every request
  (`:204`).
- **Partial recovery.** The `ResignKeyStateChanged` branch also adds the zone to the watchlist
  (`:194-199`).
- **`resignPending`.** `triggerResign` sets it before its non-blocking send (`key_state_worker.go:516`).
  The sweep honours it (`resigner.go:291`), **but only for zones on the watchlist**. A zone whose
  registration failed *and* whose trigger was dropped therefore has the flag set, and nothing reads it.
- **triggerResign producers.** About 25 call sites: rollovers, the key-state worker, the API, and
  `signing_keys_snapshot.go:131,137`. None of them block or fail, and this fix leaves them alone.
- **tdns-mp `sendResignRequest`** (`v2/signer_keydb.go:221`; callers `hsync_utils.go:1430`,
  `mp_key_lifecycle_engine.go:265`, `signer_acting.go:190`). It sends `ResignKeyStateChanged`, blocks
  up to 10 s, and on timeout loses the request without setting `resignPending`. This is not a
  registration, but it fails the same way. It should call `tdns.TriggerResign`
  (`key_lifecycle_owner.go:156`). See Q5.

### Watchlist hygiene on main (relevant to the options)

- **Nothing ever leaves `ZonesToKeepSigned`.** `Zones.Remove` at `dynamic_zones.go:1044`
  (RemoveDynamicZone), `config.go:1394` (zone dropped on reload), and `apihandler_catalog.go:170,225,350`
  (catalog zone, catalog auto-delete) all leave the detached ZoneData on the list. It is then renewed,
  and published when anything is due, for the life of the process.
- **`ModifyDynamicZone`** (`dynamic_zones.go:1124`) installs a new ZoneData (`:1285`) with
  `FirstZoneLoad` false and no OnFirstLoad, so the new ZoneData never registers. The watchlist keeps
  sweeping `oldZd`. The new ZoneData also carries no `DnssecPolicyName`, so whether it signs at all is
  a separate question (Q7).
- **Zones put into `Zones` at run time** by `AddDynamicZone` (`dynamic_zones.go:970`) and the catalog
  (`catalog.go:437`) don't take the OnFirstLoad path either. They register only after a restart, through R2.

## 2. Options for "registration cannot fail"

**A. Watchlist under its own lock.** The map moves out of the goroutine behind a mutex.
Registration writes to the map and pokes the engine.

**B. A flag on ZoneData; the sweep walks `Zones`.** Add `keepSigned atomic.Bool` next to
`resignPending` (`structs.go:276`). Registration runs today's gates, then
`if zd.keepSigned.CompareAndSwap(false, true) { log "adding zone to re-sign list"; poke }`.
The poke is a non-blocking send on a 1-slot `resignWake chan struct{}`, internal to tdns. The engine applies
`earlierResignWake` to it exactly as it does to a request today. If the slot is full, a wake is already
owed. Each pass takes `Zones.Items()` (a copy, `core/concurrent_map.go:304`). A zone is a candidate
when `keepSigned || resignPendingSet()`, and `resignSweepZone` is unchanged.

**Rejected:** a bigger buffer (moves the threshold), a blocking send (worse: it wedges the
RefreshEngine), and a goroutine per send (unbounded, and a late send of an old ZoneData can land after
the new one's).

| Concern | A: locked watchlist | B: flag + walk `Zones` |
|---|---|---|
| Locking against the sweep | One new mutex. The sweep must copy under it and release it before taking any `zd.mu`. | Nothing new. The flag is atomic, `Zones` has its own lock, and the sweep holds one `zd.mu` at a time, as now. |
| Zone replacement (`ModifyDynamicZone`) | Keyed by name, last writer wins. The new ZoneData never registers, so `oldZd` stays. Needs a `Zones.Get(name) == zd` check in the sweep. | Always the ZoneData that is live under the name. A new one is renewed once its own registration runs. Before that, nothing of ours is there to renew. The rollback (`dynamic_zones.go:1299`) restores `oldZd` with its flag still set. |
| Zone removed while registered | Needs deregistration at five `Zones.Remove` sites, or the same liveness check. | Out of `Zones` means out of the sweep. A zone removed during a pass is renewed at most once more (on main: forever). |
| 2 s stall in OnFirstLoad | Gone. | Gone. |
| Dropped trigger on a zone not on the list | Still lost, unless the map also takes pending zones. | Picked up: `resignPending` makes a zone a candidate. That is what a delivered trigger does today. |
| #995 relayed copies (inline-signing arrives from upstream) | Safe: explicit registration. | Safe: the flag is the explicit "signs here now" gate. Deriving candidacy from the options alone would renew an upstream's copy, so keep the flag. |

With the liveness check A needs anyway, A amounts to B plus a map to keep in step. **Recommendation:
B.**

What B changes:

- `registerForPeriodicResign` loses `ctx`, the channel and the error return. `resignRegisterTimeout`
  goes away, and so do the error branches at R1–R4.
- An exported setter without the gates (e.g. `zd.KeepRenewed()`) is for tdns-mp's identity zone (R5).
  `registerForPeriodicResign` becomes "gates, then `KeepRenewed()`".
- A policy apply that signs the zone (`applyZonePolicyTransactionalLocked`) registers it too, in the checked form. That is how a zone already loaded starts signing: a reload that turns signing on, or a later apply to the new ZoneData a `ModifyDynamicZone` leaves. No first load registers either of them (added in review).
- `ResignPeriodic` and its `case` go away. The `ResignKeyStateChanged` branch sets `keepSigned`, which
  keeps today's add-to-watchlist. `ResignQ` then carries only key-state requests. Those are deduplicated
  per zone (`resignQueued`), and when one is dropped `resignPending` covers it, so 10 slots are enough.
- The log line "adding zone to re-sign list" **must stay**. The e2e rig's renewal suite greps for it
  (§4). Emit it when the flag flips from false to true.
- Cost: one atomic load per zone in `Zones` per pass. Microseconds for thousands of zones, and the
  passes come no more often than now.
- tdns-mp breaks at build time (`agent_setup.go:123` names `ResignPeriodic`) until it is repinned.
  That needs a tdns-mp PR in lockstep (Q5).
- Ordering with #995: #995 landed first (f477b414). `StartSigning` now calls `KeepRenewed()`, and its
  wait under `policyApplyMu` goes away with the queue send.

## 3. The worker pool: in a follow-up (johanix/tdns#1034)

The pool belongs in its own PR. (1) is the correctness fix: zones fall off the list and their
signatures expire. It is small and changes no concurrency. With (1) in, a slow zone still delays the
sweep, but it can no longer cost a registration. Key-state requests still fall back to `resignPending`
and the next pass. (2) changes what signs concurrently, and it needs its own soak.

Risks to settle in the pool PR:

- **One zone, one worker.** Today the resigner's replace and its renewal can never overlap on a zone.
  `RenewZoneSignatures` resolves keys before taking `zd.mu` (`sign_renew.go:57-71`). If a replace ran on
  another worker, a renewal holding pre-change keys could sign with a retired key after the replace
  finished. The pool needs an in-flight set by zone name, and the queue's replace must go through the
  same set.
- **`zd.mu` ordering.** N workers hold N zone locks at once. If anything reached under `zd.mu` takes
  another zone's `zd.mu` (the publish in `RenewZoneSignatures`, `sign_renew.go:181`, and its callbacks),
  the resigner can deadlock with itself. Today such a path could deadlock only against another engine.
  Audit the callees of `publishOrQueueLocked` first.
- **Keystore.** There is one SQLite handle, serialized by `kdb.mu` (`structs.go:1489`).
  `EnsureActiveDnssecKeys` can promote or mint keys for zones nobody owns (`sign.go:482`). A slow mint
  stalls the other workers, the KeyStateWorker and the API. Keep the pool small (2–4).
- **Crypto.** Keys are per zone, so workers sign with different keys. Check that the liboqs-backed
  signers (`WITH_LIBOQS` builds) keep no context shared across the process.
- **Publish fan-out.** N publishes at once send N rounds of NOTIFY. Check that the publish path's
  NotifyQ send cannot block under `zd.mu`.
- **Shape of a pass.** Fan out, wait for every worker, then compute `nextResignWake`. Each worker checks
  for shutdown between zones.

## 4. Test plan

**Unit tests for (1)**, as built in `v2/resign_watchlist_test.go`. The pass is factored out of the
engine loop (`resignCandidates`, `resignPass`), so the tests run it without the goroutine and the
timer. A zone counts as renewed when `RenewZoneSignatures` has recorded its schedule (`resignDue()`
known), so no test hook is needed.

1. **A busy resigner.** Hold zone A's `zd.mu` and start a pass, which blocks on A. Register 20 zones:
   they all return at once with their flags set. Release A: the next pass renews all 20. On main every
   one of these registrations went through the queue that nobody was reading.
2. A removed zone leaves the watchlist.
3. A replaced zone: register the old ZoneData, then `Zones.Set` a new one that is not registered. The
   pass renews neither. Register the new one: only the new one is renewed. A rollback brings the old one
   back.
4. A dropped trigger on a zone that never registered: the pass replaces its signatures.
5. Wake: the first registration fills the wake slot, a registration that finds the slot full returns
   at once, and registering a zone already on the watchlist does not wake the resigner again. The
   engine applies `earlierResignWake` to the wake, as it did to a request; that rule keeps its own
   tests (`resign_pending_test.go`).
6. A zone with inline-signing on that never registered, with nothing pending, is not on the watchlist
   (the #995 relayed-copy case).

Breaking the pass, or dropping `resignPending` from the candidates, makes tests 1 and 4 fail. Run them
under `-race` as well as `make check-all`.

**Unit tests for (2):** one zone's `zd.mu` held for the whole test. The other zones are renewed within
one pass, the held zone's worker exits on cancel, and no zone is ever in two workers.

**The tdns-mp e2e rig.** What would show a regression:

- **The renewal suite**, the only one with short signature lifetimes. It checks that the auditor logs
  "ResignerEngine starting" and "adding zone to re-sign list", and that its identity zone's RRSIGs are
  renewed before they first expire. That covers R5 directly, and it goes red if the log line moves.
- **Suites that add a signer at run time** and require it to sign without a restart: R4, once tdns-mp
  calls `StartSigning`.
- **Suites where the signer role is refused or leaves**: a zone that doesn't sign must not be renewed
  (test 6).
- **Suites with the DNSSEC chain on**, where tdns-auth signs the group zones itself, through R1.
- **On-demand rollovers, restarts and reloads.** They exercise the queue's consumer, which this change
  rewrites.

Gaps: no other suite reaches a renewal, because elsewhere signatures last a week and keys never roll.
No suite runs many signed zones, or dynamic or catalog zones. (2) needs a new suite: many signed
zones, short validity, one zone kept busy.

## 5. Size

- **(1), tdns:** `resigner.go` (pass factored out, `ResignPeriodic` gone, walks `Zones`),
  `zone_utils.go` (registration), `structs.go`, three callers plus
  `StartSigning`, and the 2026-09-05 doc. About +80/−90 lines, plus about 200 lines of
  tests. Half a day, then an e2e rig run of the renewal suite and the run-time signer suites.
- **(1), tdns-mp:** repin, and `agent_setup.go` becomes one call with no error path. An hour.
- **(2):** about 150 lines plus tests, the cross-zone lock audit and a new rig suite. One to two days.

## 6. Decisions (Johan, 2026-11-11)

1. **Option B:** a flag on ZoneData, and each sweep walks `Zones`. Not a watchlist with its own lock.
2. **The sweep also takes zones that have `resignPending` set but no flag.** That closes the case
   where both the registration and the trigger were dropped.
3. **The worker pool is a follow-up:** johanix/tdns#1034 (label `priority`). It covers the cross-zone
   lock audit and a new e2e suite with many signed zones.
4. **This PR goes after #995**, and changes `StartSigning`'s registration to `KeepRenewed()`.
5. **tdns-mp lockstep.** One tdns-mp PR repins and switches `agent_setup.go` to `KeepRenewed()`.
   Moving `sendResignRequest` to `tdns.TriggerResign` is johanix/tdns-mp#414 (label `priority`).
6. **"RRSIG counters" are dropped** from the pool's risks. Nobody could name one.
7. **Zones added at run time** (AddDynamicZone, catalog members, ModifyDynamicZone's replacement)
   register only after a restart, and a modify drops the DNSSEC policy name. That is
   johanix/tdns#1035. B doesn't make it worse.
8. **No Linear.** Work is tracked in GitHub issues only.
