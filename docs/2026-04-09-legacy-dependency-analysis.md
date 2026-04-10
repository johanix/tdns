# Legacy File Dependency Analysis — tdns/v2/legacy_*.go

**Date**: 2026-04-09, updated 2026-04-10
**Scope**: All `tdns/v2/legacy_*.go` files (19 original + 4 newly
renamed)
**Goal**: Identify which legacy files can be deleted and which still
have non-legacy callers that must be cleaned up first. A file is
"legacy" if its *content* belongs in tdns-mp, not tdns — regardless
of whether non-legacy tdns code currently references it.

## Method

1. Extracted all exported symbols from each `legacy_*.go` file.
2. Grepped the entire `tdns-project/` tree for references.
3. Classified each reference as:
   - **Self-reference**: within another `legacy_*.go` file (does not
     prevent deletion).
   - **Live v2 non-legacy reference**: from a non-legacy file in
     `tdns/v2/`. These are *tendrils* — MP-specific call sites in
     non-legacy code that must be cleaned up before deletion.
   - **Commented-out reference**: inside `/* */` or `//`. Does not
     count.
   - **tdns-mp/v2 reference**: tdns-mp defines its own parallel
     copies; these references don't keep tdns legacy files alive.

Critical lessons from the analysis:
- Grep hits in `main_initfuncs.go` were often inside `/* */` blocks.
- tdns-mp/v2 has local copies of almost every symbol — references
  from there resolve to the local copy.
- A file is legacy based on whether its *content* belongs in tdns-mp,
  not on whether it has zero callers. Non-legacy callers are tendrils
  to clean up, not proof of belonging.

## Parallel copies in tdns-mp/v2

The following symbols exist both in `tdns/v2/legacy_*.go` and as
local definitions in `tdns-mp/v2/`:

| Symbol                         | tdns-mp/v2 definition             |
|--------------------------------|-----------------------------------|
| `GetProviderZoneRRtypes`       | `combiner_utils.go:52`            |
| `RegisterProviderZoneRRtypes`  | `combiner_utils.go:39`            |
| `GetCombinerData`              | `combiner_utils.go:151`           |
| `GetCombinerDataNG`            | `combiner_utils.go:219`           |
| `NewMPTransportBridge`         | `hsync_transport.go:191`          |
| `MPTransportBridge` (type)     | `hsync_transport.go:45`           |
| `MPTransportBridgeConfig`      | `hsync_transport.go:126`          |
| `ProviderGroupManager` (type)  | `gossip_types.go:84`              |
| `NewProviderGroupManager`      | `provider_groups.go:22`           |
| `NewGossipStateTable`          | `gossip.go:40`                    |
| `LoadAllContributions`         | `db_combiner_contributions.go:63` |
| `RequestAndWaitForConfig`      | `hsync_utils.go:414`              |
| `RequestAndWaitForAudit`       | `hsync_utils.go:455`              |
| `MPPreRefresh`                 | `hsync_utils.go:1005` (diff sig)  |
| `MPPostRefresh`                | `hsync_utils.go:1141` (diff sig)  |

## NOT YET DELETABLE (4 files)

These files contain MP-only content that *should* be removed from
tdns, but non-legacy tdns/v2 files still reference their symbols.
Each reference is a tendril that must be cleaned up (removed, guarded
behind an interface, or moved to tdns-mp) before the file can be
deleted.

### legacy_hsync_transport.go — `MPTransportBridge`

| Symbol | File:Line | Category |
|---|---|---|
| `MPTransportBridge` (type) | config.go:529 | struct field |
| `MPTransportBridge` (type) | mptypes.go:150 | struct field |
| `MPTransportBridge` (type) | main_initfuncs.go:505 | func param |
| `IsPeerAuthorized` | apihandler_agent.go:399 | call |
| `SendPing` | apihandler_agent.go:102 | call |
| `SyncPeerFromAgent` | apihandler_agent.go:1083 | call |
| `SendSyncWithFallback` | apihandler_agent.go:1099 | call |
| `GetQueueStats` | apihandler_agent.go:1124 | call |
| `GetQueuePendingMessages` | apihandler_agent.go:1125 | call |
| `EnqueueForCombiner` | parseconfig.go:782 | call |
| `getAllAgentsForZone` | delegation_sync.go:206 | call (private) |
| `PeerRegistry` (embedded) | delegation_sync.go:218 | field access |
| `PeerRegistry` (embedded) | apihandler_agent.go:43 | field access |
| `DNSTransport` (embedded) | delegation_sync.go:201,236 | field access |
| `LocalID` (embedded) | apihandler_agent.go:41 | field access |

### legacy_provider_groups.go — `ProviderGroupManager`

| Symbol | File:Line | Category |
|---|---|---|
| `ProviderGroupManager` (type) | mptypes.go:152 | struct field |
| `ProviderGroupManager` | apihandler_agent.go:537 | nil check |
| `GetGroupForZone` | apihandler_agent.go:538 | call |
| `ProviderGroup` fields | apihandler_agent.go:540 | field access |

### legacy_parentsync_leader.go — `LeaderElectionManager`

| Symbol | File:Line | Category |
|---|---|---|
| `LeaderElectionManager` (type) | config.go:530 | struct field |
| `LeaderElectionManager` (type) | mptypes.go:151 | struct field |
| `LeaderElectionManager` | apihandler_agent.go:518,529,589 | field access |
| `GetParentSyncStatus` | apihandler_agent.go:524 | call |
| `ParentSyncStatus` (type) | apihandler_agent.go:524 | type ref |
| `StartGroupElection` | apihandler_agent.go:540 | call |
| `StartElection` | apihandler_agent.go:556 | call |
| `IsLeader` | apihandler_agent.go:595 | call |
| `IsLeader` | parentsync_bootstrap.go:48,66 | call |
| `IsLeader` | delegation_sync.go:87,128 | call |
| `configuredPeers` | apihandler_agent.go:546 | call (private) |
| `operationalPeersFunc` | apihandler_agent.go:548,549 | field access |

### legacy_apihandler_agent_distrib.go — `DistributionCache`

| Symbol | File:Line | Category |
|---|---|---|
| `DistributionCache` (type) | config.go:533 | struct field |
| `DistributionCache` (type) | apihandler_transaction.go:57 | func param |
| `DistributionCache` | apirouters.go:116,117 | field access |
| `DistributionSummary` (type) | mptypes.go:793 | struct field |

### Tendril summary by non-legacy file

The non-legacy files that need cleanup, sorted by density:

| Non-legacy file | Legacy files touched |
|---|---|
| apihandler_agent.go | all 4 |
| config.go | 3 (transport, leader, distrib) |
| mptypes.go | all 4 |
| delegation_sync.go | 2 (transport, leader) |
| parseconfig.go | 1 (transport) |
| parentsync_bootstrap.go | 1 (leader) |
| apirouters.go | 1 (distrib) |
| apihandler_transaction.go | 1 (distrib) |
| main_initfuncs.go | 1 (transport) |

## DELETABLE (17 files)

All exported symbols are either unreferenced or only referenced from
other `legacy_*.go` files, commented-out code, or tdns-mp/v2 (where
a local copy exists).

 1. `legacy_agent_authorization.go`     — methods on `MPTransportBridge`
 2. `legacy_agent_discovery.go`         — superseded by tdns-mp/v2
 3. `legacy_agent_discovery_common.go`  — only called by above
 4. `legacy_agent_setup.go`             — no live callers
 5. `legacy_agent_structs.go`           — empty (package decl only)
 6. `legacy_agent_utils.go`             — no live callers
 7. `legacy_chunk_query_handler.go`     — no live callers
 8. `legacy_chunk_store.go`             — only config.go field decl
    (never instantiated)
 9. `legacy_combiner_chunk.go`          — callers in `/* */` blocks
10. `legacy_combiner_utils.go`          — callers in `/* */` blocks
11. `legacy_db_combiner_contributions.go` — callers in `/* */` blocks
12. `legacy_db_combiner_edits.go`       — no live callers
13. `legacy_db_combiner_publish_instructions.go` — no live callers
14. `legacy_gossip.go`                  — tdns-mp has local copy
15. `legacy_hsync_beat.go`              — superseded by tdns-mp/v2
16. `legacy_hsync_hello.go`             — superseded by tdns-mp/v2
17. `legacy_hsync_utils.go`             — parseconfig.go no longer
    registers callbacks
18. `legacy_hsyncengine.go`             — superseded
19. `legacy_signer_msg_handler.go`      — superseded by tdns-mp/v2

Note: `legacy_chunk_store.go` defines `ChunkPayloadStore` which
appears as a struct field in `config.go:531`, but the field is never
instantiated or used in any live tdns/v2 code path. It can be deleted
together with the config field.

## Caveats before deletion

1. **Incremental deletion and build between each.** Delete one file
   at a time, then run `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
   before moving on.

2. **Start with the safest.** `legacy_agent_structs.go` is empty.

3. **Files with methods on live types.** Some deletable files define
   methods on `*MPTransportBridge` (e.g. `legacy_agent_authorization.go`).
   Since `MPTransportBridge` is still live in tdns/v2, verify that
   no non-legacy code calls those methods before deleting.

## Change log

- **2026-04-09**: Initial analysis of 19 legacy files. 3 NOT DELETABLE,
  16 DELETABLE.
- **2026-04-09 re-verification**: `legacy_hsync_utils.go` moved to
  DELETABLE (parseconfig.go no longer registers callbacks). Count:
  2 NOT DELETABLE, 17 DELETABLE.
- **2026-04-10**: Four additional files renamed to `legacy_`:
  `chunk_query_handler.go`, `chunk_store.go`, `parentsync_leader.go`,
  `apihandler_agent_distrib.go`. All contain MP-only content. Full
  tendril inventory produced for the 4 NOT YET DELETABLE files.
  Count: 4 NOT YET DELETABLE (with tendrils), 19 DELETABLE.
