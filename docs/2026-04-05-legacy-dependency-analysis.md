# Legacy Dependency Analysis

Date: 2026-04-05
Purpose: Identify what blocks MP code removal from tdns

## Executive Summary

Removing MP code from tdns is blocked by two categories
of dependencies:

1. **Types defined in legacy files, used everywhere**:
   ~34 symbols (types, constants, methods) defined in
   `legacy_*` files are referenced from tdns-mp. These
   are mostly type definitions — they must be relocated
   before the files can be deleted.

2. **API handlers in tdns that call legacy functions**:
   `apihandler_agent.go`, `apihandler_combiner.go`, etc.
   are non-legacy files in tdns that directly call legacy
   functions. They keep most legacy code alive even after
   engine removal.

The path forward: relocate types first, then delete
functions, then delete files.

## Analysis (a): Engine Removal Cascade

Removing MP engines from `Start{Auth,Agent,Combiner}`
makes only ~9 files (or large sections) cleanly removable.
The API handlers keep everything else alive.

### Removable after engine removal

| File | What becomes dead |
|------|-------------------|
| `legacy_hsync_infra_beat.go` | entire file |
| `legacy_hsync_beat.go` | entire file |
| `legacy_agent_policy.go` | entire file |
| `legacy_db_combiner_edits.go` | entire file |
| `legacy_combiner_msg_handler.go` | entire file (relocate `pushKeystateInventoryToAllAgents` first) |
| `legacy_hsync_hello.go` | all except `EvaluateHello()`, `sharedZonesForAgent()` |
| `legacy_hsyncengine.go` | engine functions (keep types) |
| `legacy_syncheddataengine.go` | engine function (keep types) |
| `legacy_hsync_transport.go` | router/queue startup, route*Message functions |

### NOT removable (called from non-legacy code)

All types/structs, `MPTransportBridge`, `AgentRegistry`,
`LeaderElectionManager`, `ProviderGroupManager`,
`GossipStateTable`, most of `legacy_hsync_utils.go`,
all combiner utility functions, all authorization/
discovery/setup functions — all called from API handlers,
`parseconfig.go`, `delegation_sync.go`, `sign.go`,
`resigner.go`, `key_state_worker.go`.

## Analysis (b): tdns-mp → tdns Dependencies

### Legacy types referenced from tdns-mp (34 symbols)

These are the blockers. Each must be relocated before
its containing file can be deleted.

**From `legacy_agent_structs.go` (10 symbols):**
- `Agent` (type) — used in CLI debug, API handler
- `AgentMgmtPost` (type) — ~30 call sites in CLI
- `AgentMgmtResponse` (type) — ~15 call sites in CLI
- `AgentMsgNotify` (const) — also in core, can switch
- `AgentMsgRfi` (const) — also in core, can switch
- `HsyncPeerInfo` (type) — aliased in tdns-mp
- `HsyncSyncOpInfo` (type) — aliased in tdns-mp
- `HsyncConfirmationInfo` (type) — aliased in tdns-mp
- `HsyncTransportEvent` (type) — aliased in tdns-mp
- `HsyncMetricsInfo` (type) — aliased in tdns-mp

**From `legacy_syncheddataengine.go` (3 types):**
- `AgentId` — ~20+ call sites, aliased in tdns-mp
- `ZoneName` — ~30+ call sites, aliased in tdns-mp
- `ZoneUpdate` — ~15+ call sites, aliased in tdns-mp

**From `legacy_hsyncengine.go` (3 types):**
- `SyncRequest` — used via `zd.SyncQ`
- `SyncResponse` — aliased in tdns-mp
- `SyncStatus` — aliased in tdns-mp

**From `legacy_combiner_chunk.go` (5 types):**
- `CombinerState` — used in combiner/signer init
- `CombinerSyncRequest` — used throughout combiner
- `CombinerSyncResponse` — used in combiner
- `CombinerSyncRequestPlus` — aliased
- `RejectedItem` — aliased

**From `legacy_combiner_utils.go` (1 var + 1 method):**
- `AllowedLocalRRtypes` — used in CLI add/del RR
- `CombineWithLocalChanges()` — called via wrapper

**From `legacy_hsync_utils.go` (1 type + 2 methods):**
- `DnskeyStatus` (type) — used in HSYNC analysis
- `matchHsyncProvider()` — called via wrapper
- `weAreASigner()` — called via wrapper

**From `legacy_db_combiner_edits.go` (3 types):**
- `PendingEditRecord` — aliased in tdns-mp
- `ApprovedEditRecord` — aliased in tdns-mp
- `RejectedEditRecord` — aliased in tdns-mp

**From `legacy_apihandler_combiner_distrib.go` (2 types):**
- `CombinerDistribPost` — aliased
- `CombinerDistribResponse` — aliased

**From `legacy_agent_discovery_common.go` (6 methods):**
- `Imr.LookupAgentAPIEndpoint()`
- `Imr.LookupAgentDNSEndpoint()`
- `Imr.LookupAgentTLSA()`
- `Imr.LookupServiceAddresses()`
- `Imr.LookupAgentJWK()`
- `Imr.LookupAgentKEY()`

**From CLI legacy files (2 symbols):**
- `cli.AgentZoneCmd` — from `legacy_agent_zone_cmds.go`
- `cli.RunZoneList` — from `legacy_agent_zone_cmds.go`

### Non-legacy tdns symbols used by tdns-mp

~135 symbols from non-legacy files. These are fine —
they stay in tdns as the library API. Major categories:

- Engine functions: `RefreshEngine`, `DnsEngine`,
  `Notifier`, `AuthQueryEngine`, `NotifyHandler`, etc.
- API: `APIdispatcher`, `APIdispatcherNG`
- Config: `Config`, `Globals`, `Conf`, `MultiProviderConf`
- Zone: `ZoneData` + ~25 methods, `Zones` global
- KeyDB: `KeyDB` + ~15 methods
- IMR: `Imr` + `ImrQuery`, `LookupDSYNCTarget`,
  `DsyncDiscovery`
- Signing: `SignMsg`, `SetupZoneSigning`, `SignZone`
- CLI: `GetApiClient`, `GetCommandContext`, `PrepArgs`,
  `SendZoneCommand`, etc.
- Core types: `RRset`, `HSYNC3`, `HSYNCPARAM`, message
  types, concurrent maps
- Publish ops: `PublishUriRR`, `PublishJWKRR`,
  `PublishSvcbRR`, etc.

## Recommended Removal Strategy

### Phase 1: Relocate types (no behavior change)

Move the 34 legacy-defined types to non-legacy files
in tdns. No code deletion, no functional change — just
move type definitions so they survive file deletion.

Candidates for relocation targets:
- `AgentId`, `ZoneName` → `enums.go` or `structs.go`
- `ZoneUpdate`, `SyncRequest`, `SyncResponse`,
  `SyncStatus` → `structs.go`
- `Agent`, `AgentMgmtPost`, `AgentMgmtResponse`,
  `Hsync*Info` → `api_structs.go`
- `CombinerState`, `CombinerSync*` → `structs.go`
- `DnskeyStatus` → `structs.go`
- `*EditRecord` types → `db_hsync.go`
- IMR Lookup methods → `imrengine.go` or `dnslookup.go`
- `AllowedLocalRRtypes` → `enums.go`
- `CombineWithLocalChanges` → `zone_utils.go`
- `matchHsyncProvider`, `weAreASigner` → `hsync_utils.go`
  (non-legacy, if it exists) or `zone_utils.go`
- CLI: `AgentZoneCmd`, `RunZoneList` → `zone_cmds.go`

### Phase 2: Remove engine startups

Remove MP engines from `Start{Auth,Agent,Combiner}`.
Delete the ~9 files/sections identified in analysis (a).

### Phase 3: Remove API handlers

Delete or migrate `apihandler_agent.go`,
`apihandler_combiner.go`, etc. to tdns-mp. This unblocks
deletion of the remaining legacy functions they call.

### Phase 4: Delete remaining legacy files

With types relocated and callers removed, the legacy
files contain only dead functions. Delete them all.

### Phase 5: Clean up mixed files

Remove MP sections from `config.go`, `parseconfig.go`,
`main_initfuncs.go`, `enums.go`, etc.
