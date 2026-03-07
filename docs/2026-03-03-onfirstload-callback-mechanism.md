# OnFirstLoad Callback Mechanism for RefreshEngine

**Date:** 2026-03-03

## Context

The combiner needs to set `PersistContributions` callbacks and hydrate `AgentContributions` on each zone's `ZoneData`. Previously this was attempted in `StartCombiner` by iterating `Zones`, but `Zones` is empty at that point — zones only appear when `RefreshEngine` processes the queued `ZoneRefresher` requests.

**Startup sequence (original problem):**
1. `MainInit` → `ParseZones` → queues `ZoneRefresher` structs to `RefreshZoneCh` channel
2. `MainInit` returns
3. `StartCombiner` → starts `RefreshEngine` (which consumes `RefreshZoneCh` and creates `ZoneData` objects)

The problem: there is no hook point between "zones are known" and "RefreshEngine creates the zd". We need one.

**Solution:** `ParseZones` creates minimal `ZoneData` stubs in the `Zones` map. App-specific `Start*` functions attach `OnFirstLoad` callbacks to the stubs before starting `RefreshEngine`. When `RefreshEngine` encounters a pre-existing `zd` that has never been loaded (`FirstZoneLoad == true`), it merges the `ZoneRefresher` config into the existing `zd`, loads the zone, then executes the callbacks.

## Design

### New field on `ZoneData` (`structs.go`)

```go
// OnFirstLoad holds one-shot callbacks executed after the zone's first successful load.
// Apps register these before RefreshEngine starts, and RefreshEngine clears the slice
// after executing them. Protected by zd.mu.
OnFirstLoad []func(*ZoneData)
```

### RefreshEngine restructuring (`refreshengine.go`)

Extract shared initial-load logic into `initialLoadZone` helper to avoid duplication between the pre-registered path and the dynamic-zone path. The helper handles: `Refresh()`, refresh counter setup, catalog zone parsing, post-init hooks (`tryPostpass`, `SetupZoneSync`), OnFirstLoad callback execution, and downstream notification.

Two main paths in the `zonerefch` case:

1. **Zone exists, `FirstZoneLoad == true`** (pre-registered stub from ParseZones): merge `ZoneRefresher` config into existing `zd`, call `initialLoadZone`
2. **Zone exists, `FirstZoneLoad == false`** (existing zone): normal refresh path (unchanged)

Plus a fallback for dynamic zones:

3. **Zone does not exist** (dynamic zone — catalog member, API-created): create `zd`, register in `Zones`, call `initialLoadZone`, then `SetupZoneSigning` explicitly

### Pre-registration in `ParseZones` and `Start*` functions

`ParseZones` (`parseconfig.go`) creates minimal zd stubs and registers `SetupZoneSigning` as an OnFirstLoad callback for zones with signing options.

`StartCombiner` (`main_initfuncs.go`) attaches combiner-specific OnFirstLoad callbacks to the existing stubs. The combiner callback:
- Checks `OptMultiProvider` (skips non-MP zones)
- Sets `PersistContributions = zd.KeyDB.SaveContributions`
- Hydrates `AgentContributions` from DB via `LoadAllContributions()`
- Calls `rebuildCombinerData()` and `CombineWithLocalChanges()`

### `CombineWithLocalChanges` timing

The OnFirstLoad callback runs *after* `Refresh()` returns. `FetchFromUpstream` (called during `Refresh`) also calls `CombineWithLocalChanges` — but on first load, `CombinerData` is still nil, so that call is a harmless no-op ("No combiner data to apply"). The callback then hydrates and does the real combine. One extra log line on first load, acceptable.

## Files Modified

| File | Change |
|------|--------|
| `structs.go` | Add `OnFirstLoad []func(*ZoneData)` field to `ZoneData` |
| `parseconfig.go` | Create zd stubs in `ParseZones`; register signing callback; size channel |
| `refreshengine.go` | Extract `initialLoadZone` helper; signing via callback not inline |
| `main_initfuncs.go` | `StartCombiner` attaches callbacks to existing stubs (no creation) |
| `zone_utils.go` | Revert FetchFromUpstream PersistContributions/hydration kludge |

## Safety Analysis

1. **All apps**: `ParseZones` creates stubs for all zones. `Start*` attaches app-specific callbacks. RefreshEngine finds stubs, merges config, runs `initialLoadZone`, executes callbacks.
2. **Combiner without multi-provider zones**: Callback checks `OptMultiProvider` and returns early. Zone loads correctly.
3. **Combiner with multi-provider zones**: Callback hydrates contributions + calls `CombineWithLocalChanges`. Correct.
4. **Auth/Signer with explicit signing config**: Signing callback registered in `ParseZones`. Executes after zone loads.
4b. **Signer with MP zone (HSYNC-discovered signing)**: MP callback registered. After `FetchFromUpstream` sets `OptInlineSigning` via HSYNC analysis, callback checks and calls `SetupZoneSigning`. Verified working.
5. **Agent**: No signing callbacks (agent check in `ParseZones`). Zones load normally.
6. **SIGHUP reload**: Zones have `FirstZoneLoad == false` → existing-zone path. No callbacks re-executed. No new stubs.
7. **Dynamic zones** (catalog-created): Not pre-registered → dynamic-zone path in RefreshEngine.
8. **Race conditions**: Stub creation happens in `ParseZones` during `MainInit` (before engines start). No races.

## Evolution: Stub creation moved to ParseZones (2026-03-04)

### Change

Moved zd stub creation from `StartCombiner` into `ParseZones`. Now ALL apps get pre-registered zone stubs, not just the combiner.

**Startup sequence (updated):**
1. `MainInit` → `ParseZones` → creates minimal zd stubs in `Zones` map, queues `ZoneRefresher` to channel
2. `MainInit` returns
3. `Start*` function (combiner/auth/agent) → attaches OnFirstLoad callbacks to existing stubs → starts `RefreshEngine`

### Signing and multi-provider callbacks (2026-03-04)

`ParseZones` registers two separate OnFirstLoad callbacks (skipped for agents):

1. **Signing callback** — for zones with `OptOnlineSigning` or `OptInlineSigning` in config. Calls `SetupZoneSigning` unconditionally.

2. **Multi-provider callback** — for zones with `OptMultiProvider` on auth servers (`AppTypeAuth`). By the time this callback executes, `FetchFromUpstream` has already analyzed the HSYNC RRset and may have dynamically set `OptInlineSigning`. The callback checks `zd.Options[OptInlineSigning]` and only calls `SetupZoneSigning` if it was set. This is an extension point for future MP-specific post-load setup.

This split replaces the earlier single signing callback. The key insight: signer zones discover signing dynamically via HSYNC (not from config), so the signing callback alone misses them. The MP callback handles this case by checking what `FetchFromUpstream` discovered.

Dynamic zones (catalog members, API-created) still get `SetupZoneSigning` called explicitly in RefreshEngine's dynamic-zone path.

### RefreshZoneCh sizing

Channel sized to `max(10, len(conf.Zones))` instead of hardcoded 10. Eliminates goroutine fallback for channel overflow in ParseZones.

### SIGHUP reload safety

`ParseZones` checks `Zones.Get(zname)` before creating stubs. On reload, zones already exist → no new stubs created, no duplicate callbacks.

## RefreshEngine retry fixes (2026-03-04)

Three regressions were found and fixed in the pre-registered stub path:

### Config merge guard

The pre-registered path unconditionally merged all `ZoneRefresher` fields into the existing `zd`. CLI `ReloadZone` sends a sparse `ZoneRefresher` with only `Name`/`Response`/`Force` set (all other fields zero). On retry, this overwrote the correctly-configured `ZoneType` with 0, causing `Refresh()` to fail with "unknown type 0".

**Fix:** Guard config merge with `if zd.ZoneType == 0` — only merge on first pass when the stub hasn't been configured yet. On retries, the zd already has config from the first attempt.

### Fallback refresh counter on failure

`initialLoadZone` returns an error (line 48) before `refreshCounters.Set()` (line 55). Without a refresh counter, the ticker never retries the zone — it's permanently stuck.

**Fix:** On initial load failure, set a fallback refresh counter (`SOARefresh: 300`, `CurRefresh: 30`) so the ticker can retry.

### Error response for CLI

The pre-registered path did `continue` on error without sending a response to `zr.Response`. CLI `ReloadZone` waited for the response and got "timeout waiting for response from RefreshEngine".

**Fix:** Send error response to `zr.Response` before `continue`.

### Ticker improvements

Two ticker changes support retry of failed initial loads:

1. **Allow RefreshError retries** — the ticker previously skipped ALL zones in error state. Now it only skips non-`RefreshError` errors, allowing zones that failed `Refresh()` to be retried.

2. **FirstZoneLoad detection** — when the ticker encounters a zone with `FirstZoneLoad == true`, it routes through `initialLoadZone` instead of the normal refresh path. This ensures callbacks, signing, and sync setup all happen on successful retry.

## Follow-up work (separate issues)

### (a) Convert `SetupZoneSync` to OnFirstLoad callback

Still called unconditionally in `initialLoadZone`. Should be registered selectively in `ParseZones` based on zone options, like `SetupZoneSigning` was.

### (b) Convert `DeferredUpdate` system to OnFirstLoad callbacks

The `DeferredUpdate` mechanism (`DeferredUpdateQ`, `DeferredUpdaterEngine`) is another workaround for the same fundamental problem: zone updates that arrive before a zone is ready. This entire subsystem should be replaced by OnFirstLoad callbacks.
