# Combiner Extraction to tdns-mp

Date: 2026-03-25
Status: DONE (lab-tested 2026-03-26)
Prerequisite: Signer extraction complete, 4g done

## Context

The signer was successfully extracted to tdns-mp. The
combiner follows the same pattern but with more files:
13 MP-specific files vs 4 for the signer.

The combiner does NOT use: AgentRegistry, SDE,
HsyncEngine, gossip, provider groups, leader election,
agent discovery, agent policy. It is a data sink — it
receives zone updates from agents, aggregates them, and
sends confirmations back.

## Files to copy to tdns-mp

### Core business logic (3 files)
1. `combiner_chunk.go` — RegisterCombinerChunkHandler,
   NewCombinerSyncHandler, CombinerProcessUpdate,
   publish instruction handling, signal key resync.
   NOTE: CombinerState stays in tdns (signer uses it too).
   NOTE: RegisterSignerChunkHandler already in tdns-mp.
   Extract combiner-specific functions only.
   (~1700 lines total, subset copied)
2. `combiner_msg_handler.go` — CombinerMsgHandler,
   combinerSendConfirmation (~440 lines)
3. `combiner_utils.go` — AddCombinerData,
   rebuildCombinerData, RRtype policy. Methods converted
   to standalone functions before copying.
   (~1010 lines)

NOT copied:
- `combiner_peer.go` — agent-side only
  (InitializeCombinerAsPeer called by agent, not combiner)

### Database/persistence (3 files)
5. `db_combiner_contributions.go` — agent contribution
   snapshots (~110 lines)
6. `db_combiner_edits.go` — edit queue management
   (~500 lines)
7. `db_combiner_publish_instructions.go` — KEY/CDS
   publication + NS tracking (~490 lines)

### API handlers (2 files)
8. `apihandler_combiner.go` — main combiner API
   (~630 lines)
9. `apihandler_combiner_distrib.go` — distribution
   tracking (~1030 lines)

### CLI commands (4 files)
10. `cli/combiner_cmds.go`
11. `cli/combiner_debug_cmds.go`
12. `cli/combiner_edits_cmds.go`
13. `cli/combiner_peer_cmds.go`

### Startup orchestration (new, in tdns-mp)
14. `start_combiner.go` — StartMPCombiner()

Total: ~14 files, ~6000+ lines

## Files NOT copied (shared infrastructure, stays in tdns)

- MPTransportBridge (hsync_transport.go) — used via
  `conf.Internal.MPTransport`
- config.go, structs.go, enums.go — types
- db_schema.go, db_schema_hsync.go, db_hsync.go — shared
- apirouters.go — API setup (guarded by AppType)
- refreshengine.go, notifier.go, do53.go — DNS engines

## Implementation Steps

### Step 1: Method conversions in tdns — DONE

**(a) Shared callers** — 4 wrappers added to wrappers.go:
- `ZoneDataCombineWithLocalChanges(zd *ZoneData) (bool, error)`
- `ZoneDataRebuildCombinerData(zd *ZoneData)`
- `ZoneDataSnapshotUpstreamData(zd *ZoneData)`
- `ZoneDataInjectSignatureTXT(zd *ZoneData, conf *MultiProviderConf) bool`

**(b) ZoneData combiner-only** — 12 methods converted to
standalone functions in combiner_utils.go:
- AddCombinerData, GetCombinerData, AddCombinerDataNG,
  GetCombinerDataNG, RemoveCombinerDataNG,
  RemoveCombinerDataByRRtype, ReplaceCombinerDataByRRtype,
  replaceCombinerDataByRRtypeLocked, InjectSignatureTXT,
  restoreUpstreamRRset, cleanupRemovedRRtypes,
  cleanupRemovedRRtype

**(c) KeyDB combiner methods** — 20 methods converted to
standalone functions across 3 db files:
- db_combiner_contributions.go: SaveContributions,
  LoadAllContributions, DeleteContributions (3)
- db_combiner_edits.go: NextEditID, SavePendingEdit,
  ListPendingEdits, GetPendingEdit, ApprovePendingEdit,
  RejectPendingEdit, ResolvePendingEdit, ListRejectedEdits,
  ListApprovedEdits, ClearPendingEdits, ClearApprovedEdits,
  ClearRejectedEdits, ClearContributions (13)
- db_combiner_publish_instructions.go: SavePublishInstruction,
  GetPublishInstruction, DeletePublishInstruction,
  LoadAllPublishInstructions (4)

**(d) Callers updated** — 37 call sites across 7 files:
combiner_utils.go, combiner_chunk.go, combiner_msg_handler.go,
apihandler_combiner.go, zone_utils.go, main_initfuncs.go,
wrappers.go

**Methods kept as receivers** (shared, have wrappers):
CombineWithLocalChanges, rebuildCombinerData,
snapshotUpstreamData, mergeWithUpstream

All 6 tdns binaries build clean.

### Step 2: Add AppTypeMPCombiner guards — DONE

AppTypeMPCombiner already defined in enums.go. Guards added:

- **apirouters.go**: Distribution cache init + combiner API
  endpoints now include AppTypeMPCombiner
- **main_initfuncs.go**: MainInit switch: MPCombiner hits
  empty `default:` case (same pattern as MPSigner — all
  MP wiring done by tdns-mp).
  StartCombiner: MP engines (IncomingMessageRouter,
  CombinerMsgHandler, CombinerSyncRouter) skipped for
  AppTypeMPCombiner.
- **zone_utils.go**: 7 AppTypeCombiner checks updated to
  include MPCombiner (HSYNC/DNSKEY change detection,
  snapshotUpstreamData, CombineWithLocalChanges, etc.)
- **parseconfig.go**: expectedRole map includes MPCombiner
- **keys_cmd.go**: JOSE key path + usage message
- **parseoptions.go**: mp-manual-approval validation

All 6 tdns binaries build clean.

### Step 3: Copy combiner files to tdns-mp — DONE

8 files copied with package conversion:
- combiner_utils.go, combiner_chunk.go,
  combiner_msg_handler.go (core logic)
- db_combiner_contributions.go, db_combiner_edits.go,
  db_combiner_publish_instructions.go (persistence)
- apihandler_combiner.go,
  apihandler_combiner_distrib.go (HTTP API)

All combiner functions call each other locally in
tdns-mp. Only infrastructure types (ZoneData, KeyDB,
Zones, Conf) use `tdns.` prefix. Type aliases for
cross-package types (CombinerSyncRequest, etc.).

Original files renamed to `legacy_*.go` in tdns —
remain for legacy tdns-combinerv2 binary.

Functions exported in tdns for tdns-mp access:
IsNoOpOperations, RecordCombinerError,
CombinerReapplyContributions, ListKnownPeers,
RebuildCombinerData, InitCombinerCrypto.
Wrappers added: OurHsyncIdentities,
ZoneDataMatchHsyncProvider, ZoneDataSynthesizeCdsRRs.

### Step 4: Create StartMPCombiner() — DONE

`start_combiner.go`: registers OnFirstLoad callbacks
(PersistContributions, contribution hydration,
signal key re-application), then calls
`conf.Config.StartCombiner()` for DNS engines,
then starts MP engines (IncomingMessageRouter,
CombinerMsgHandler, CombinerSyncRouter).

### Step 5: Create MainInit combiner path — DONE

`MainInit` restructured to branch on `mp.Role`:
- `"signer"` → `initMPSigner` (existing code)
- `"combiner"` → `initMPCombiner` (new): edit tables,
  crypto, RegisterCombinerChunkHandler, TM, peers,
  combiner router.

### Step 6: Create mpcombiner binary — DONE

`cmd/mpcombiner/`: main.go, Makefile, go.mod.
Sets `AppTypeMPCombiner`, calls `MainInit` →
`StartMPCombiner`. Binary builds (26MB).

### Step 7: Wire CLI commands — DONE

4 combiner CLI files copied to tdns-mp/v2/cli/.
mpcli shared_cmds.go updated to use mpcli.CombinerCmd
(from tdns-mp) instead of cli.CombinerCmd (from tdns).
Exported GetApiClient, GetCommandContext, ListDistribPeers
directly in tdns/v2/cli (renamed from unexported).
Original files renamed to legacy_*.go in tdns.

### Step 8: Verify — DONE

- All 6 tdns binaries build
- mpcombiner + mpsigner + mpcli build
- Lab test: combiner receives CHUNK NOTIFYs, processes
  operations, applies changes, sends confirmations.
- Fix applied: combiner role doesn't require mp.Active.

Two categories of receiver functions on tdns types:

**(a) Shared callers** (combiner + other code) — add
wrapper in tdns/v2/wrappers.go. Only 2 methods:
- `CombineWithLocalChanges` — called from
  main_initfuncs.go and zone_utils.go
- `rebuildCombinerData` — called from main_initfuncs.go

**(b) Combiner-only callers** — convert from method to
standalone function directly in tdns. No wrapper needed.
tdns-mp calls `tdns.FuncName(zd, ...)`. ~13 methods:
- AddCombinerData, AddCombinerDataNG
- GetCombinerData, GetCombinerDataNG
- RemoveCombinerDataNG, RemoveCombinerDataByRRtype
- combinerReapplyContributions
- combinerApplyPublishInstruction
- combinerResyncSignalKeys
- combinerProcessOperations
- snapshotUpstreamData
- cleanupRemovedRRtype, restoreUpstreamRRset

For case (b), update the existing combiner callers in
tdns at the same time (they're in the same files being
copied, so both the old and new callers get the new
signature).

**KeyDB combiner methods** (db_combiner_*.go) — all are
combiner-only callers. Convert to standalone functions,
same as ZoneData methods. ~15 methods across 3 files:
- SaveContributions, LoadAllContributions, ClearContributions
- InitCombinerEditTables, AddPendingEdit, ApprovePendingEdit, etc.
- SavePublishInstruction, LoadPublishInstructions, etc.

Note: SaveContributions is used as a callback
(PersistContributions). After conversion, wrap in closure:
```go
zd.MP.PersistContributions = func(z, s string, c ...) error {
    return SaveContributions(kdb, z, s, c)
}
```

The db files are then copied to tdns-mp with the
standalone function signatures.

### Step 8: Verify

- All tdns binaries build
- mpcombiner + mpcli build
- Lab test: combiner receives updates, processes them,
  sends confirmations

## Complexity Assessment

**Higher than signer** due to:
- More files (13 vs 4)
- combiner_chunk.go is complex (1700 lines, policy logic)
- Database persistence files interact closely with KeyDB
- ~13 methods need converting from receiver to standalone

**Simpler than expected** because:
- Only 2 wrappers needed (shared callers)
- ~13 methods are combiner-only → convert directly
- KeyDB methods already exported
- Same proven pattern as signer

## Risk

**Medium-low.** More files but no new patterns. The method
conversion (b) changes tdns code but the callers are in
the same files being migrated, so it's self-contained.

## Estimated Effort

- Method conversions in tdns: ~1 hour (13 methods)
- Copy + prefix: ~2 hours (13 files, mechanical)
- 2 wrappers: ~10 min
- Startup wiring: ~30 min
- AppType guards: ~30 min
- Testing: ~30 min

Total: ~4-5 hours
