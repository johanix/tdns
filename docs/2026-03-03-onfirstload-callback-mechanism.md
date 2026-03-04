# OnFirstLoad Callback Mechanism for RefreshEngine

**Date:** 2026-03-03

## Context

The combiner needs to set `PersistContributions` callbacks and hydrate `AgentContributions` on each zone's `ZoneData`. Previously this was attempted in `StartCombiner` by iterating `Zones`, but `Zones` is empty at that point — zones only appear when `RefreshEngine` processes the queued `ZoneRefresher` requests.

**Startup sequence:**
1. `MainInit` → `ParseZones` → queues `ZoneRefresher` structs to `RefreshZoneCh` channel (buffered, size 10)
2. `MainInit` returns
3. `StartCombiner` → starts `RefreshEngine` (which consumes `RefreshZoneCh` and creates `ZoneData` objects)

The problem: there is no hook point between "zones are known" and "RefreshEngine creates the zd". We need one.

**Solution:** Before `RefreshEngine` starts, pre-register minimal `ZoneData` stubs in the `Zones` map with `OnFirstLoad` callbacks attached. When `RefreshEngine` encounters a pre-existing `zd` that has never been loaded (`FirstZoneLoad == true`), it merges the `ZoneRefresher` config into the existing `zd`, loads the zone, then executes the callbacks.

## Design

### New field on `ZoneData` (`structs.go`)

```go
// OnFirstLoad holds one-shot callbacks executed after the zone's first successful load.
// Apps register these before RefreshEngine starts, and RefreshEngine clears the slice
// after executing them. Protected by zd.mu.
OnFirstLoad []func(*ZoneData)
```

### RefreshEngine restructuring (`refreshengine.go`)

Extract shared initial-load logic into `initialLoadZone` helper to avoid duplication between the pre-registered path and the new-zone path. The helper handles: `Refresh()`, refresh counter setup, catalog zone parsing, post-init hooks (`tryPostpass`, `SetupZoneSigning`, `SetupZoneSync`), OnFirstLoad callback execution, and downstream notification.

Three paths in the `zonerefch` case:

1. **Zone exists, `FirstZoneLoad == true`** (pre-registered stub): merge `ZoneRefresher` config into existing `zd`, call `initialLoadZone`
2. **Zone exists, `FirstZoneLoad == false`** (existing zone): normal refresh path (unchanged)
3. **Zone does not exist** (new zone): create `zd`, register in `Zones`, call `initialLoadZone`

### Pre-registration in `StartCombiner` (`main_initfuncs.go`)

Before `RefreshEngine` starts, iterate `conf.Internal.AllZones` and create minimal `ZoneData` stubs with `OnFirstLoad` callbacks. The combiner callback:
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
| `refreshengine.go` | Extract `initialLoadZone` helper; add pre-registered zone path |
| `main_initfuncs.go` | Pre-register zones with OnFirstLoad callbacks in `StartCombiner` |
| `zone_utils.go` | Revert FetchFromUpstream PersistContributions/hydration kludge |

## Safety Analysis

1. **Agent/Auth/Signer apps (today)**: Do not yet pre-register zones → new-zone path → zero behavior change. Will eventually use pre-registration too (see follow-up).
2. **Combiner without multi-provider zones**: Pre-registered, callback checks `OptMultiProvider` and returns early. Zone loads correctly.
3. **Combiner with multi-provider zones**: Callback hydrates contributions + calls `CombineWithLocalChanges`. Correct.
4. **SIGHUP reload**: Zones have `FirstZoneLoad == false` → existing-zone path. No callbacks re-executed.
5. **Dynamic zones** (catalog-created): Not pre-registered → new-zone path.
6. **Race conditions**: Pre-registration happens before `RefreshEngine` starts. No races.

## Follow-up work (separate issues)

### (a) Convert `SetupZoneSigning` / `SetupZoneSync` to OnFirstLoad callbacks

Currently called unconditionally for every zone in `initialLoadZone`. Should instead be registered selectively by app-specific `Start*` functions based on zone options. Makes RefreshEngine fully generic.

### (b) Convert `DeferredUpdate` system to OnFirstLoad callbacks

The `DeferredUpdate` mechanism (`DeferredUpdateQ`, `DeferredUpdaterEngine`) is another workaround for the same fundamental problem: zone updates that arrive before a zone is ready. This entire subsystem should be replaced by OnFirstLoad callbacks.

### (c) Auth/Signer/Agent pre-registration

Once the pattern is established, other apps will also pre-register zones with their own callbacks:
- **Auth/Signer**: `SetupZoneSigning` callback for zones with `OptOnlineSigning`
- **Agent**: whatever currently uses `DeferredUpdate`, registered as OnFirstLoad callbacks

The pre-registered stub path will eventually be used by all apps. The new-zone path will only be used for dynamically added zones (catalog members, API-created zones).
