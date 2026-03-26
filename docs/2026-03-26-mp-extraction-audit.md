# MP Extraction Audit: What tdns-mp Still References in tdns

Date: 2026-03-26
Status: Analysis complete, reviewed and corrected

## Revised Conclusions (after review)

### Types: copy to tdns-mp now

**Combiner API types** (no non-legacy consumers in tdns):
- CombinerPost, CombinerResponse
- CombinerEditPost, CombinerEditResponse
- CombinerDebugPost, CombinerDebugResponse
- CombinerDistribPost, CombinerDistribResponse

**Combiner message types** (no non-legacy consumers):
- CombinerSyncRequest, CombinerSyncResponse
- RejectedItem, CombinerSyncRequestPlus
- StoredPublishInstruction

**Edit record types** (definition in structs.go, consumers
are legacy-only):
- PendingEditRecord, ApprovedEditRecord, RejectedEditRecord

**Signer types** (copy to tdns-mp):
- KeyInventoryItem, DnssecKeyWithTimestamps

**CombinerState**: used by agent too (in-process updates
via apihandler_transaction.go). Stays in tdns. Moves
when agent is extracted.

**RRsetString**: shared (apihandler_funcs.go, api_structs.go).
Stays in tdns.

**DistributionCache/Summary**: stays for now, moves when
agent is extracted.

### Functions: copy to tdns-mp now

- InitCombinerCrypto (combiner-specific crypto)
- StripKeyFileComments (trivial utility, used by signer)
- Fix: use local GetProviderZoneRRtypes consistently

### KeyDB signer methods: convert + copy

These are called from tdns-mp signer code. Convert from
receiver methods to standalone functions, copy to tdns-mp:
- GetDnssecKeysByState, UpdateDnssecKeyState
- GenerateAndStageKey, GetKeyInventory
- SetPropagationConfirmed
- TransitionMpdistToPublished, TransitionMpremoveToRemoved

Also for combiner:
- InitCombinerEditTables

### Wrappers: cleanup

**Delete** (not used by tdns-mp at all):
- ZoneDataSnapshotUpstreamData
- ZoneDataInjectSignatureTXT
- ZoneDataRebuildCombinerData

**Keep** (used by tdns-mp):
- ZoneDataCombineWithLocalChanges (zone_utils.go caller)
- ZoneDataWeAreASigner (signer key_state_worker.go)
- ZoneDataMatchHsyncProvider (combiner combiner_chunk.go)
- ZoneDataSynthesizeCdsRRs (combiner combiner_chunk.go)
- OurHsyncIdentities (combiner combiner_chunk.go)
- CombinerStateSetChunkHandler (both signer + combiner)

### ZoneData methods: EnsureMP stays for now

EnsureMP() has non-legacy callers (parseconfig.go,
hsync_utils.go, main_initfuncs.go). Stays as method.
Moves when agent extracted.

CombineWithLocalChanges() has non-legacy caller in
zone_utils.go. Stays as method. Wrapper used by tdns-mp.

## Implementation Progress (2026-03-26)

### Done

- **Unused wrappers deleted**: ZoneDataRebuildCombinerData,
  ZoneDataSnapshotUpstreamData, ZoneDataInjectSignatureTXT
  removed from wrappers.go.
- **Type aliases**: 10 combiner types + 2 signer types
  aliased in tdns-mp/v2/types.go. CLI types aliased in
  tdns-mp/v2/cli/types.go. Callers updated to use local
  names (no `tdns.` prefix).
- **InitCombinerCrypto + StripKeyFileComments**: Copied
  to tdns-mp/v2/combiner_crypto.go. Callers in main_init
  and signer_transport updated to use local versions.
- **GetProviderZoneRRtypes/AllowedLocalRRtypes**: Fixed
  4 call sites in combiner_chunk.go to use local copies.
- **KeyDB signer methods**: 7 methods converted to
  standalone in tdns (keystore.go): GetDnssecKeysByState,
  UpdateDnssecKeyState, GenerateAndStageKey,
  GetKeyInventory, SetPropagationConfirmed,
  TransitionMpdistToPublished, TransitionMpremoveToRemoved.
  Copied as local functions in tdns-mp/v2/signer_keydb.go.
  Callers updated to use local versions.
- **InitCombinerEditTables**: Converted to standalone
  in tdns (db_schema_hsync.go). Copied as local function
  in tdns-mp/v2/combiner_db_schema.go.
- **CombinerOptAddSignature**: Aliased in types.go,
  callers updated.

### All immediate actions complete.

## Context

After extracting the signer and combiner to tdns-mp, this
audit catalogs everything tdns-mp still references in tdns.
The goal is to identify:
1. Types that should be copied to tdns-mp (combiner-only)
2. Things forgotten during migration
3. What can be removed from tdns once the legacy combiner
   is retired (tdns-auth stays, loses MP features)

## Retirement Plan

- **Legacy combiner** (`tdns-combinerv2`): RETIRE. All
  `legacy_combiner_*.go` and `legacy_apihandler_combiner*.go`
  files will be deleted. `legacy_db_combiner_*.go` too.
- **tdns-auth**: STAYS but loses MP signer features.
  The `StartAuth` MP engine block (SignerMsgHandler,
  KeyStateWorker) will be removed. Auth remains as the
  standard authoritative nameserver.

## Category 1: Types Referenced by tdns-mp

### Infrastructure types (STAY in tdns)

These are core tdns types used by all apps. They must
remain in tdns:

- `Config`, `InternalConf`
- `ZoneData`, `OwnerData`
- `KeyDB`
- `MultiProviderConf`
- `MPTransportBridge`, `MPTransportBridgeConfig`
- `MsgQs`
- `ErrorJournal`, `ErrorJournalEntry`
- `DnsNotifyRequest`
- `DistributionCache`, `DistributionSummary`
- `AppDetails`
- `ZoneRefresher`
- `Globals` (global singleton)
- `Zones` (global zone registry)
- `Conf` (global config)
- `CombinerState` (used by signer too)

### Combiner-only API types (COPY to tdns-mp)

These are request/response types used exclusively by the
combiner API handlers and CLI. They exist only to shuttle
data between the CLI and the combiner's HTTP API. They
have no business being in tdns once the legacy combiner
is removed.

- `CombinerPost`
- `CombinerResponse`
- `CombinerEditPost`
- `CombinerEditResponse`
- `CombinerDebugPost`
- `CombinerDebugResponse`
- `CombinerDistribPost`
- `CombinerDistribResponse`

### Combiner-only message types (already aliased)

These are aliased in tdns-mp but still defined in tdns:

- `CombinerSyncRequest`
- `CombinerSyncResponse`
- `RejectedItem`
- `CombinerSyncRequestPlus`
- `PendingEditRecord`
- `ApprovedEditRecord`
- `RejectedEditRecord`
- `StoredPublishInstruction`

Decision: these should be defined in tdns-mp and aliased
back into tdns (reverse the current direction) once the
legacy combiner is retired.

### Signer-only types (COPY to tdns-mp)

Used by the signer code in tdns-mp but defined in tdns:

- `KeyInventoryItem`
- `DnssecKeyWithTimestamps`
- `DnskeyState*` constants (Published, Standby, Retired,
  Removed, Mpremove, Mpdist)

These are part of the DNSSEC key management system. They
will remain in tdns (used by tdns-auth's KeyDB) but the
MP-specific states (Mpremove, Mpdist) could eventually
move. Low priority — they're just constants.

### Shared types (both signer and combiner use)

- `RRsetString` — used by combiner API responses

## Category 2: Functions Referenced by tdns-mp

### Infrastructure (STAY in tdns)

- `StartEngine`, `StartEngineNoError` — engine lifecycle
- `StartAuth`, `StartCombiner` — role startup (DNS parts)
- `SetupAPIRouter`, `SetupCombinerSyncRouter`
- `APIdispatcherNG`
- `MainInit` — DNS infrastructure setup
- `MainLoop` — main event loop
- `ParseZones` — zone config parsing
- `Shutdowner` — graceful shutdown
- `Logger()` — structured logging factory
- `RegisterNotifyHandler` — NOTIFY handler registration
- `NewMPTransportBridge` — TM factory
- `NewDistributionCache`, `StartDistributionGC`
- `NewErrorJournal`
- `FindZone`, `GetProviderZoneRRtypes`
- `NewRRTypeStore`
- `SanitizeForJSON`

### Wrappers (assess whether to keep or export)

Current wrappers in tdns/v2/wrappers.go:

- `ZoneDataCombineWithLocalChanges` — wraps receiver
  method. Used by combiner start_combiner.go.
- `ZoneDataWeAreASigner` — wraps receiver method.
  Used by signer key_state_worker.go.
- `ZoneDataMatchHsyncProvider` — wraps receiver method.
  Used by combiner combiner_chunk.go.
- `ZoneDataSynthesizeCdsRRs` — wraps receiver method.
  Used by combiner combiner_chunk.go.
- `OurHsyncIdentities` — wraps package function.
  Used by combiner combiner_chunk.go.
- `CombinerStateSetChunkHandler` — wraps unexported
  field access. Used by both signer and combiner.
- `ZoneDataSnapshotUpstreamData` — wraps receiver.
  Only called from zone_utils.go (stays in tdns).
- `ZoneDataInjectSignatureTXT` — wraps standalone func.
  Only called from zone_utils.go (stays in tdns).
- `ZoneDataRebuildCombinerData` — wraps standalone func.
  Only called from legacy code (remove with legacy).

Assessment: `ZoneDataSnapshotUpstreamData`,
`ZoneDataInjectSignatureTXT`, `ZoneDataRebuildCombinerData`
are only used by tdns-internal code. They can be removed
when the legacy combiner is retired (callers are all in
legacy_*.go files or zone_utils.go which calls the method
directly).

### Combiner-only functions (already copied)

These are in both tdns (legacy_*.go) and tdns-mp:
- `RegisterCombinerChunkHandler`
- `NewCombinerSyncHandler`
- `CombinerProcessUpdate`
- `CombinerMsgHandler`
- `RebuildCombinerData`
- `AddCombinerData*`, `GetCombinerData*`
- `RemoveCombinerData*`, `ReplaceCombinerDataByRRtype`
- `InjectSignatureTXT`
- `CombinerReapplyContributions`
- All `db_combiner_*.go` functions
- `IsNoOpOperations`, `RecordCombinerError`
- `ListKnownPeers`

These will be deleted from tdns when the legacy combiner
is retired.

### Functions that should have been copied but weren't

- `InitCombinerCrypto` — exported in tdns, called from
  tdns-mp's initMPCombiner. This is crypto init that is
  combiner-specific. Should be copied to tdns-mp so it
  doesn't depend on tdns for combiner crypto.
- `initSignerCrypto` — same pattern (signer_transport.go
  in tdns-mp already has its own version, good).
- `Sig0KeyOwnerName` — utility used by combiner for
  _signal KEY publication. Simple function, could be
  copied. But also used by agent code in tdns.
- `AllowedRRtypePresets`, `AllowedLocalRRtypes`,
  `RegisterProviderZoneRRtypes`, `GetProviderZoneRRtypes`
  — these are in the tdns-mp combiner_utils.go as local
  copies, good. But tdns-mp also calls
  `tdns.GetProviderZoneRRtypes` in some places (e.g.
  combiner_chunk.go, start_combiner.go). Should use the
  local copy consistently.
- `StripKeyFileComments` — utility used by signer crypto
  init. Trivial function. Could be copied.

## Category 3: Constants Referenced by tdns-mp

### Zone options (STAY in tdns)

- `OptMultiProvider`
- `OptMPManualApproval`
- `OptAllowEdits`
- `OptMPDisallowEdits`
- `OptOnlineSigning`
- `OptInlineSigning`

These are zone option flags used throughout tdns. They
stay.

### Combiner options

- `CombinerOptAddSignature` — combiner-only. Copy.

### DNSKEY state constants

- `DnskeyStatePublished`, `DnskeyStateStandby`,
  `DnskeyStateRetired`, `DnskeyStateRemoved`
  — standard DNSSEC states, stay in tdns.
- `DnskeyStateMpremove`, `DnskeyStateMpdist`
  — MP-specific states. Used by signer key_state_worker.
  These interact with KeyDB which stays in tdns. Keep
  in tdns for now.

### Message types

- `AgentMsgRfi` — used by combiner msg handler. Stays
  in tdns (also used by agent).

### AppType constants

- `AppTypeMPSigner`, `AppTypeMPCombiner` — stay in tdns
  (used by AppType guards).

## Category 4: Methods on tdns Types

### ZoneData methods called by tdns-mp

- `GetOwner()`, `Lock()`/`Unlock()`
- `EnsureMP()`
- `CombineWithLocalChanges()` (via wrapper)
- `BumpSerialOnly()`
- `NotifyDownstreams()`
- Field access: `.Data`, `.MP`, `.Options`, `.KeyDB`,
  `.ZoneName`, `.CurrentSerial`, `.Downstreams`,
  `.Logger`, `.OnFirstLoad`, `.Signer`

These all stay in tdns (ZoneData is infrastructure).

### KeyDB methods called by tdns-mp

Signer:
- `GetDnssecKeysByState()`, `UpdateDnssecKeyState()`
- `GenerateAndStageKey()`, `GetKeyInventory()`
- `SetPropagationConfirmed()`
- `TransitionMpdistToPublished()`
- `TransitionMpremoveToRemoved()`

Combiner:
- `InitCombinerEditTables()`
- `Lock()`/`Unlock()`, `.DB` (SQLite access)

These all stay in tdns (KeyDB is infrastructure).

## Recommended Actions

### Immediate (before agent extraction)

1. **Copy combiner API types to tdns-mp** (Category 2
   "Combiner-only API types"): CombinerPost,
   CombinerResponse, CombinerEditPost,
   CombinerEditResponse, CombinerDebugPost,
   CombinerDebugResponse, CombinerDistribPost,
   CombinerDistribResponse. Define locally in tdns-mp,
   alias back to tdns for legacy combiner.

2. **Copy InitCombinerCrypto to tdns-mp**. Currently
   exported in tdns and called cross-package. Should be
   local to tdns-mp like initSignerCrypto already is.

3. **Fix inconsistent GetProviderZoneRRtypes calls**.
   tdns-mp has a local copy but some call sites still
   use `tdns.GetProviderZoneRRtypes`. Use local copy
   everywhere.

4. **Copy StripKeyFileComments** to tdns-mp (trivial
   utility, used by signer crypto).

### When retiring legacy combiner

5. **Delete from tdns**: all `legacy_combiner_*.go`,
   `legacy_apihandler_combiner*.go`,
   `legacy_db_combiner_*.go` files.

6. **Delete combiner API types** from tdns (now defined
   in tdns-mp).

7. **Delete combiner-related wrappers** from wrappers.go:
   `ZoneDataRebuildCombinerData`.

8. **Remove combiner AppType guards** that are no longer
   needed (but keep AppTypeMPCombiner for the new binary).

9. **Delete `combinerv2/` binary** directory from cmdv2/.

### When retiring MP features from tdns-auth

10. **Remove from StartAuth**: the `AppTypeMPSigner` guard
    block (SignerMsgHandler, KeyStateWorker, signer sync
    API). These are only needed when running as MPSigner.

11. **Remove from MainInit**: the Auth-side MP init
    (TransportManager creation, signer CHUNK registration,
    signer router).

12. **Remove MP-specific KeyDB methods** that are only
    called by the signer: TransitionMpdistToPublished,
    TransitionMpremoveToRemoved, etc.

13. **Remove legacy signer wrappers** from wrappers.go:
    ZoneDataWeAreASigner (if only used by MPSigner).
