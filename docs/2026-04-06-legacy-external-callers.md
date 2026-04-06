# Legacy External Callers Analysis

Date: 2026-04-06
Purpose: Document every call from non-legacy tdns code to
legacy functions, to guide the final removal.

## Functions accessed from tdns-mp via wrappers

These are in `wrappers.go` — thin wrappers that export
unexported legacy methods for tdns-mp to call:

1. `ZoneDataCombineWithLocalChanges(zd)` →
   `zd.CombineWithLocalChanges()` in
   `legacy_combiner_utils.go`
2. `ZoneDataWeAreASigner(zd, mp)` →
   `zd.weAreASigner(mp)` in `legacy_hsync_utils.go`
3. `OurHsyncIdentities(mp)` →
   `ourHsyncIdentities(mp)` in `legacy_hsync_utils.go`
4. `ZoneDataMatchHsyncProvider(zd, ids)` →
   `zd.matchHsyncProvider(ids)` in
   `legacy_hsync_utils.go`
5. `CombinerStateSetChunkHandler(cs, ch)` →
   `cs.chunkHandler = ch` in `legacy_combiner_chunk.go`

Plus functions called directly (not via wrapper):

6. `ListKnownPeers(conf)` in
   `apihandler_agent_distrib.go` — called from tdns-mp
   CLI
7. `NewDistributionCache()` in
   `apihandler_agent_distrib.go` — called from tdns-mp
   init
8. `StartDistributionGC(cache, interval, stopCh)` in
   `apihandler_agent_distrib.go` — called from tdns-mp
   init
9. `SanitizeForJSON(v)` in `sanitize_data.go` — called
   from tdns-mp (non-legacy, stays)
10. `PeerRecordToInfo(r)` / `SyncOpRecordToInfo(r)` /
    `ConfirmRecordToInfo(r)` in `db_hsync.go` — called
    from tdns-mp CLI

Items 6-8 are in `apihandler_agent_distrib.go` which is
itself MP code that should move. Items 9-10 are standard
library functions that stay.

## Non-legacy tdns files calling legacy functions

### apihandler_agent.go (MP code, should move or delete)

| Line | Legacy symbol | Legacy file |
|------|--------------|-------------|
| 102 | `SendPing` (MPTransportBridge) | legacy_hsync_transport.go |
| 425 | `GetZoneAgentData` | legacy_agent_utils.go |
| 435 | `GetAgentInfo` | legacy_agent_utils.go |
| 455 | `IsPeerAuthorized` | legacy_agent_authorization.go |
| 464,478,486 | `DiscoverAgentAsync` | legacy_agent_utils.go |
| 475 | `GetAgentInfo` | legacy_agent_utils.go |
| 607 | `handleRouterList` | legacy_apihandler_agent_router.go |
| 617 | `handleRouterDescribe` | legacy_apihandler_agent_router.go |
| 627 | `handleRouterMetrics` | legacy_apihandler_agent_router.go |
| 637 | `handleRouterWalk` | legacy_apihandler_agent_router.go |
| 647 | `handleRouterReset` | legacy_apihandler_agent_router.go |
| 652 | `RequestAndWaitForKeyInventory` | legacy_hsync_utils.go |
| 665 | `LocalDnskeysFromKeystate` | legacy_hsync_utils.go |
| 996 | `attemptDiscovery` | legacy_agent_utils.go |
| 1019 | `GetGroupByName` | legacy_provider_groups.go |
| 1027 | `GetGroupState` | legacy_gossip.go |
| 1102 | `GetGroups` | legacy_provider_groups.go |
| 1478 | `SyncPeerFromAgent` | legacy_hsync_transport.go |
| 1494 | `SendSyncWithFallback` | legacy_hsync_transport.go |
| 1519 | `GetQueueStats` | legacy_hsync_transport.go |
| 1520 | `GetQueuePendingMessages` | legacy_hsync_transport.go |
| 1627 | `EvaluateHello` | legacy_hsync_hello.go |

**Assessment**: This entire file is MP code. It handles
agent management commands (peer-ping, gossip, resync,
discover, etc.). tdns-mp has its own copy. This file
should be deletable once the `AppTypeAgent` guard in
`apirouters.go` no longer registers its routes.

### apihandler_agent_distrib.go (MP code, should move)

| Line | Legacy symbol | Legacy file |
|------|--------------|-------------|
| 467,540 | `IsPeerAuthorized` | legacy_agent_authorization.go |
| 480,553 | `DiscoverAndRegisterAgent` | legacy_agent_discovery.go |

**Assessment**: Entirely MP code (distribution tracking,
peer listing). tdns-mp has its own copy. Should be
deleted from tdns. Note: also contains `ListKnownPeers`,
`NewDistributionCache`, `StartDistributionGC` which are
called from tdns-mp — those need to stay somewhere
(either in tdns as non-legacy or in tdns-mp).

### main_initfuncs.go

| Line | Legacy symbol | Legacy file |
|------|--------------|-------------|
| 272 | `SetupAgent` | legacy_agent_setup.go |
| 277 | `NewAgentRegistry` | legacy_agent_utils.go |
| 283 | `IsPeerAuthorized` (comment) | legacy_agent_authorization.go |
| 355,439,587 | `NewMPTransportBridge` | legacy_hsync_transport.go |
| 417 | `initSignerCrypto` | legacy_signer_transport.go |
| 469 | `RegisterSignerChunkHandler` | legacy_combiner_chunk.go |
| 476 | `ChunkHandler` | legacy_combiner_chunk.go |
| 492,671 | `SetRouter` | legacy_combiner_chunk.go |
| 562 | `RegisterCombinerChunkHandler` | legacy_combiner_chunk.go |
| 646 | `SetGetPeerAddress` | legacy_combiner_chunk.go |
| 655 | `ChunkHandler` | legacy_combiner_chunk.go |
| 661 | `NewCombinerSyncHandler` | legacy_combiner_chunk.go |
| 696 | `LoadAllContributions` | legacy_db_combiner_contributions.go |
| 721 | `SaveContributions` | legacy_db_combiner_contributions.go |
| 733 | `RebuildCombinerData` | legacy_combiner_utils.go |
| 741 | `CombineWithLocalChanges` | legacy_combiner_utils.go |
| 751 | `GetProviderZoneRRtypes` | legacy_combiner_utils.go |
| 753 | `applyPendingSignalKeys` | legacy_combiner_chunk.go |
| 764 | `StartIncomingMessageRouter` | legacy_hsync_transport.go |
| 775 | `CombinerMsgHandler` | legacy_combiner_msg_handler.go |

**Assessment**: These are all in the MainInit / Start*
functions — MP initialization code that sets up transport
bridges, chunk handlers, agent registries, combiner state.
Most of this code is inside `AppTypeAgent`,
`AppTypeCombiner`, or `AppTypeAuth` guards. As MP engines
have been removed from Start{Auth,Agent}, some of these
are now dead code (e.g. lines 764, 775 which were in the
deleted StartCombiner). The remaining ones in MainInit
set up state that other legacy code depends on. These
will go when MainInit is cleaned up.

### parseconfig.go

| Line | Legacy symbol | Legacy file |
|------|--------------|-------------|
| 727 | `MPPreRefresh` | legacy_hsync_utils.go |
| 728 | `MPPostRefresh` | legacy_hsync_utils.go |
| 771 | `matchHsyncProvider` (via method) | legacy_hsync_utils.go |
| 771 | `ourHsyncIdentities` | legacy_hsync_utils.go |
| 874 | `EnqueueForCombiner` | legacy_hsync_transport.go |
| 1398 | `RegisterProviderZoneRRtypes` | legacy_combiner_utils.go |

**Assessment**: Lines 727-728 register legacy
MPPreRefresh/MPPostRefresh callbacks during zone parsing.
tdns-mp registers its own versions on top via
RegisterMPRefreshCallbacks. The tdns versions should be
removed (they conflict with tdns-mp — the
RefreshAnalysis consumption bug). Line 771 is HSYNC3
provider matching during zone parsing. Lines 874 and
1398 are MP-specific operations during config parsing.

### parentsync_leader.go

| Line | Legacy symbol | Legacy file |
|------|--------------|-------------|
| 219,573,747 | `GetGroup` | legacy_provider_groups.go |
| 626,704,792,872,1140,1330 | `GetGroupForZone` | legacy_provider_groups.go |
| 1218,1461 | `GetZoneAgentData` | legacy_agent_utils.go |
| 1240 | `sendRfiToAgent` | legacy_hsyncengine.go |
| 1497 | `EnqueueForCombiner` | legacy_hsync_transport.go |

**Assessment**: parentsync_leader.go is MP code — it
handles leader-elected delegation sync, which requires
provider groups, agent registries, and combiner enqueue.
Without MP, delegation sync is simpler (single agent,
always the leader). This file needs MP-specific sections
removed or the entire file moved to tdns-mp.

### sign.go, resigner.go, key_state_worker.go

| File | Line | Legacy symbol | Legacy file |
|------|------|--------------|-------------|
| sign.go | 364 | `weAreASigner` | legacy_hsync_utils.go |
| resigner.go | 77 | `weAreASigner` | legacy_hsync_utils.go |
| key_state_worker.go | 214 | `weAreASigner` | legacy_hsync_utils.go |

**Assessment**: These are guards that check "should this
zone be signed?" In a non-MP tdns, the answer is always
yes (if the zone has signing configured). The
`weAreASigner` check is MP-specific — it checks if we're
listed in HSYNCPARAM signers=. Without MP, this check
should be removed (or always return true).

### zone_utils.go

| Line | Legacy symbol | Legacy file |
|------|--------------|-------------|
| 750 | `ourHsyncIdentities` | legacy_hsync_utils.go |
| 750 | `matchHsyncProvider` | legacy_hsync_utils.go |

**Assessment**: Used in `FetchFromUpstream` to check
if we're a provider for this zone (for setting NS
management options). MP-specific check — without MP,
not needed.

### delegation_sync.go

| Line | Legacy symbol | Legacy file |
|------|--------------|-------------|
| 206 | `getAllAgentsForZone` | legacy_hsync_transport.go |

**Assessment**: Used to notify all agents of delegation
changes. MP-specific — without MP, only the local
instance handles delegation sync.

### wrappers.go

| Line | Legacy symbol | Legacy file |
|------|--------------|-------------|
| 18 | `CombineWithLocalChanges` | legacy_combiner_utils.go |
| 23 | `weAreASigner` | legacy_hsync_utils.go |
| 37 | `ourHsyncIdentities` | legacy_hsync_utils.go |
| 42 | `matchHsyncProvider` | legacy_hsync_utils.go |

**Assessment**: Export wrappers for tdns-mp. These stay
as long as tdns-mp needs the underlying functions.

### CLI files

| File | Line | Legacy symbol | Legacy file |
|------|------|--------------|-------------|
| hsync_cmds.go | 216 | `NewAgentRegistry` | legacy_agent_utils.go |
| hsync_cmds.go | 231 | `DiscoverAgentAsync` | legacy_agent_utils.go |
| hsync_cmds.go | 272 | `SendApiHello` | legacy_hsync_hello.go |
| legacy_agent_debug_cmds.go | 256 | `NewAgentRegistry` | legacy_agent_utils.go |
| legacy_agent_debug_cmds.go | 262 | `AddRemoteAgent` | legacy_agent_utils.go |

**Assessment**: `hsync_cmds.go` is non-legacy CLI that
provides HSYNC3 debugging commands. It creates an
AgentRegistry for discovery testing. Could be simplified
to not need the full registry.
`legacy_agent_debug_cmds.go` is legacy CLI — deletable.

## Summary: What blocks deletion

The 21 remaining legacy files (13,088 lines) cannot be
deleted because of ~80 call sites in ~10 non-legacy files.

Of those 10 non-legacy files, at least 3 are themselves
MP code that should be deleted or moved:
- `apihandler_agent.go` (MP agent management API)
- `apihandler_agent_distrib.go` (MP distribution tracking)
- `parentsync_leader.go` (MP leader-elected delegation)

The remaining 7 files have MP-specific *sections* that
reference legacy code:
- `main_initfuncs.go` — MainInit MP setup blocks
- `parseconfig.go` — MP config parsing + callbacks
- `sign.go` / `resigner.go` / `key_state_worker.go` —
  `weAreASigner` guards
- `zone_utils.go` — provider matching in zone refresh
- `delegation_sync.go` — agent notification
- `wrappers.go` — tdns-mp export layer

## Recommended next steps

1. Delete `apihandler_agent.go` (remove `AppTypeAgent`
   route registration first — the tdns agent doesn't
   need MP management APIs)
2. Delete `apihandler_agent_distrib.go` (relocate
   `ListKnownPeers`, `NewDistributionCache`,
   `StartDistributionGC` to a non-legacy file first —
   tdns-mp needs these)
3. Remove `weAreASigner` guards from sign.go /
   resigner.go / key_state_worker.go (non-MP = always
   a signer)
4. Remove MPPreRefresh/MPPostRefresh registration from
   parseconfig.go (tdns-mp registers its own)
5. Clean MP sections from main_initfuncs.go MainInit
6. Tackle parentsync_leader.go MP dependencies
7. After all external callers are resolved, delete the
   remaining legacy files in one pass
