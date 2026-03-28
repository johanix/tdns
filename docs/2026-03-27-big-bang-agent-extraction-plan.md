# Big Bang Agent Extraction: Detailed Execution Plan

Date: 2026-03-27
Status: PLANNING
Depends on: Steps 1, 2b-2d, 3a-3b complete

## Overview

Move all agent code (~10,000 lines, 14 files, ~76 types,
~183 functions) from tdns/v2/ to tdns-mp/v2/ in a single
coordinated operation. No changes to tdns — copy only.

## Constraints

1. **No tdns changes.** This is a copy, not a move.
2. **Methods must live with their type.** Go does not
   allow defining methods on types from another package,
   even via type alias.
3. **Types that stay in tdns** (`*Config`, `*ZoneData`,
   `*Imr`, `*KeyDB`) cannot have new methods added in
   tdns-mp. Existing receiver methods on these types must
   be converted to free functions.
4. **AgentId and ZoneName** stay as type aliases
   (`= tdns.AgentId`, `= tdns.ZoneName`) — they are
   `type X string` in tdns, used pervasively in both
   packages, and have no methods that need to move.
5. **OwnerData** stays as alias (`= tdns.OwnerData`) — it
   is defined in tdns/v2/structs.go (core infrastructure)
   and has no agent-specific methods.

## Files to Copy (14 files)

| File | Lines | Types defined | Methods | Free funcs |
|------|-------|---------------|---------|------------|
| agent_structs.go | 471 | 28 | 2 | 0 |
| agent_policy.go | 503 | 0 | 4 | 0 |
| agent_utils.go | 1134 | 1 | 15 | 2 |
| agent_setup.go | 564 | 0 | 5(STAYS) + 1(MOVING) | 0 |
| agent_discovery_common.go | 289 | 0 | 6(STAYS) | 0 |
| hsync_beat.go | 237 | 0 | 2 | 2(on *Agent) |
| hsync_hello.go | 377 | 0 | 9 | 1(on *Agent) |
| hsync_infra_beat.go | 95 | 0 | 2 | 0 |
| hsyncengine.go | 1131 | 4 | 7 | 2 |
| hsync_utils.go | 909 | 2 | 12(STAYS) | 2 |
| syncheddataengine.go | 1578 | 17 | 18 + 1(STAYS) | 2 |
| gossip.go | 368 | 4 | 9 | 1 |
| provider_groups.go | 275 | 3 | 7 | 2 |
| parentsync_leader.go | 1498 | 4 | 37 | 2 |

## Types to Move (become real structs, replace aliases)

### From agent_structs.go (28 types)
- AgentState (uint8 enum + 8 constants + AgentStateToString)
- Agent, AgentDetails, DeferredAgentTask, AgentApi
- AgentRegistry
- AgentBeatPost, AgentBeatResponse, AgentBeatReport
- AgentHelloPost, AgentHelloResponse
- AgentMsgPost, AgentMsgPostPlus, AgentMsgResponse
- AgentPingPost, AgentPingResponse
- AgentMgmtPost, AgentMgmtPostPlus, AgentMgmtResponse
- AgentDebugPost, AgentMsgReport
- RfiData, KeystateInfo
- HsyncPeerInfo, HsyncSyncOpInfo, HsyncConfirmationInfo
- HsyncTransportEvent, HsyncMetricsInfo

### From syncheddataengine.go (17 types)
- SynchedDataUpdate, SynchedDataResponse
- SynchedDataCmd, SynchedDataCmdResponse
- ZoneUpdate (NOTE: also used in core DNS — see below)
- ZoneDataRepo, PendingRemoteConfirmation
- RemoteConfirmationDetail, AgentRepo
- RRState (uint8 enum + 5 constants)
- RRConfirmation, TrackedRR, TrackedRRset
- ConfirmationDetail, RejectedItemInfo, TrackedRRInfo

### From hsyncengine.go (4 types)
- SyncRequest, SyncResponse, SyncStatus, DeferredTask

### From gossip.go (4 types)
- GossipMessage, MemberState, GroupElectionState
- GossipStateTable

### From provider_groups.go (3 types)
- ProviderGroup, GroupNameProposal, ProviderGroupManager

### From parentsync_leader.go (4 types)
- LeaderElection, LeaderElectionManager
- LeaderStatus, ParentSyncStatus

### From hsync_utils.go (2 types)
- HsyncStatus, DnskeyStatus

### From agent_utils.go (1 type)
- ZoneAgentData

### From config.go (8 types)
- MsgQs, MessageRetentionConf
- KeystateInventoryMsg, KeystateSignalMsg
- EditsResponseMsg, ConfigResponseMsg
- AuditResponseMsg, StatusUpdateMsg

### From apihandler_agent_distrib.go (2 types)
- DistributionInfo, DistributionCache

### From chunk_store.go (1 interface)
- ChunkPayloadStore

### Types that STAY as aliases
- AgentId (= tdns.AgentId) — pervasive, no methods
- ZoneName (= tdns.ZoneName) — pervasive, no methods
- OwnerData (= tdns.OwnerData) — defined in structs.go
- AgentMsg (= core.AgentMsg) — defined in core package

## ZoneUpdate: Special Case

ZoneUpdate is defined in syncheddataengine.go but used in
core DNS code (refreshengine.go, zone_updater.go,
zone_utils.go, updateresponder.go, catalog.go). It CANNOT
move to tdns-mp — it would break core DNS.

**Decision:** Keep ZoneUpdate as alias (= tdns.ZoneUpdate).
It stays in tdns. The syncheddataengine.go copy in tdns-mp
references it as `tdns.ZoneUpdate` or via alias.

## Functions Requiring Receiver Conversion

These are methods on types that STAY in tdns. When copied
to tdns-mp, the receiver must become a normal parameter.

### Methods on *Config (5 functions, in agent_setup.go)
```
(conf *Config) SetupAgent(all_zones)
  → SetupAgent(conf *tdns.Config, all_zones []string)
  Callers: main_init.go (tdns-mp), main_initfuncs.go (tdns)

(conf *Config) SetupAgentAutoZone(zonename)
  → SetupAgentAutoZone(conf *tdns.Config, zonename string)
  Callers: within SetupAgent only

(conf *Config) publishApiTransport(zd)
  → publishApiTransport(conf *tdns.Config, zd *tdns.ZoneData)
  Callers: within SetupAgent only

(conf *Config) publishDnsTransport(zd)
  → publishDnsTransport(conf *tdns.Config, zd *tdns.ZoneData)
  Callers: within SetupAgent only
```

### Methods on *Config (1 function, syncheddataengine.go)
```
(conf *Config) SynchedDataEngine(ctx, msgQs)
  → SynchedDataEngine(conf *tdns.Config, ctx, msgQs *MsgQs)
  Callers: start_agent.go (tdns-mp), main_initfuncs.go (tdns)
```

### Methods on *Config (1 function, agent_utils.go)
```
(conf *Config) NewAgentRegistry()
  → NewAgentRegistry(conf *tdns.Config)
  Callers: main_init.go (tdns-mp), main_initfuncs.go (tdns)
```

### Methods on *ZoneData (12 functions, in hsync_utils.go)
```
(zd *ZoneData) HsyncChanged(newzd)
  → HsyncChanged(zd, newzd *tdns.ZoneData)
  Callers: hsyncengine.go (SyncRequestHandler)

(zd *ZoneData) LocalDnskeysChanged(newzd)
  → LocalDnskeysChanged(zd, newzd *tdns.ZoneData)
  Callers: hsyncengine.go

(zd *ZoneData) LocalDnskeysFromKeystate()
  → LocalDnskeysFromKeystate(zd *tdns.ZoneData)
  Callers: hsyncengine.go

(zd *ZoneData) RequestAndWaitForKeyInventory(ctx)
  → RequestAndWaitForKeyInventory(zd *tdns.ZoneData, ctx)
  Callers: syncheddataengine.go

(zd *ZoneData) RequestAndWaitForEdits(ctx)
  → RequestAndWaitForEdits(zd *tdns.ZoneData, ctx)
  Callers: syncheddataengine.go

(zd *ZoneData) applyEditsToSDE(agentRecords)
  → applyEditsToSDE(zd *tdns.ZoneData, agentRecords)
  Callers: hsync_utils.go (within RequestAndWaitForEdits)

(zd *ZoneData) buildRemoteDNSKEYsFromTags(foreignKeyTags)
  → buildRemoteDNSKEYsFromTags(zd *tdns.ZoneData, ...)
  Callers: hsync_utils.go (internal)

(zd *ZoneData) ValidateHsyncRRset()
  → ValidateHsyncRRset(zd *tdns.ZoneData)
  Callers: hsync_hello.go (EvaluateHello)

(zd *ZoneData) matchHsyncProvider(ourIdentities)
  → matchHsyncProvider(zd *tdns.ZoneData, ourIdentities)
  Callers: hsync_utils.go (populateMPdata)

(zd *ZoneData) analyzeHsyncSigners(ourIdentities, label)
  → analyzeHsyncSigners(zd *tdns.ZoneData, ...)
  Callers: hsync_utils.go (populateMPdata)

(zd *ZoneData) populateMPdata()
  → populateMPdata(zd *tdns.ZoneData)
  Callers: hsync_utils.go, hsyncengine.go

(zd *ZoneData) weAreASigner()
  → weAreASigner(zd *tdns.ZoneData)
  Callers: hsync_utils.go (populateMPdata)
```

### Methods on *ZoneData (2 functions, in agent_setup.go)
```
(zd *ZoneData) AgentSig0KeyPrep(name, kdb)
  → AgentSig0KeyPrep(zd *tdns.ZoneData, name, kdb)
  Callers: agent_setup.go (publishDnsTransport)

(zd *ZoneData) AgentJWKKeyPrep(publishname, kdb)
  → AgentJWKKeyPrep(zd *tdns.ZoneData, publishname, kdb)
  Callers: agent_setup.go (publishDnsTransport)
```

### Methods on *Imr (6 functions, agent_discovery_common.go)

These are ALREADY exported in tdns and called cross-package
from the existing tdns-mp/v2/agent_discovery.go copy. The
agent_discovery_common.go file does NOT need to be copied
at all — the methods stay on *tdns.Imr and are callable.

**Decision: SKIP agent_discovery_common.go.** It stays in
tdns. The 6 Lookup* methods are already exported and work.
This reduces the file count from 14 to 13.

## Global Variable Dependencies

Moving files reference these globals (need `tdns.` prefix):

| Global | Files that use it |
|--------|-------------------|
| Zones | hsync_utils.go, hsyncengine.go, syncheddataengine.go, parentsync_leader.go, provider_groups.go, agent_setup.go |
| Globals | hsyncengine.go, agent_setup.go |
| Conf | agent_setup.go (heaviest: 48 refs via conf param) |

## Cross-Package Callers in tdns (Staying Files)

These tdns files call functions from moving files. After
the move, they still call the tdns copies (which remain).
No changes needed in tdns.

| Staying file | Functions called |
|-------------|-----------------|
| main_initfuncs.go | SetupAgent, NewAgentRegistry, HsyncEngine, SynchedDataEngine, NewLeaderElectionManager, StartInfraBeatLoop, DiscoveryRetrierNG, InitializeCombinerAsPeer, InitializeSignerAsPeer |
| apihandler_agent.go | GetZoneAgentData, GetAgentInfo, DiscoverAgentAsync, GetGroupState, GetGroups, IsLeader, StartGroupElection |
| apihandler_agent_distrib.go | DistributionCache methods |
| delegation_sync.go | IsLeader, MPTransport |
| parentsync_bootstrap.go | IsLeader |
| combiner_peer.go | InitializeCombinerAsPeer |
| signer_peer.go | InitializeSignerAsPeer |
| parseconfig.go | MPTransport access |

Since we're not changing tdns, these all continue to work
with the tdns copies of the functions.

## Cross-Package Callers in tdns-mp (Need Updating)

These already-existing tdns-mp files call into tdns for
agent functions. After the move, they should call the
local copies instead.

| tdns-mp file | Current call | After move |
|-------------|-------------|------------|
| start_agent.go:77 | tdns.HsyncEngine() | HsyncEngine() |
| start_agent.go:80 | ar.StartInfraBeatLoop() | (already correct) |
| start_agent.go:83 | ar.DiscoveryRetrierNG() | (already correct) |
| start_agent.go:87 | conf.Config.SynchedDataEngine() | SynchedDataEngine(conf.Config, ...) |
| main_init.go:343 | conf.Config.NewAgentRegistry() | NewAgentRegistry(conf.Config) |
| main_init.go:336 | conf.Config.SetupAgent() | SetupAgent(conf.Config, ...) |

## Execution Steps

### Step 1: Copy type definitions (agent_structs.go)

Copy agent_structs.go to tdns-mp/v2/. Convert:
- `package tdns` → `package tdnsmp`
- Add `tdns "github.com/johanix/tdns/v2"` import
- `core.AgentMsg` stays as `core.AgentMsg` (external)
- `AgentId`, `ZoneName` references stay unqualified (aliases)
- `core.ConcurrentMap` stays as `core.ConcurrentMap`
- `*MultiProviderConf` → `*tdns.MultiProviderConf`
- `*transport.TransportManager` stays (external)
- `*MPTransportBridge` stays unqualified (local)
- All types in this file are LOCAL after copy

Remove from types.go: all aliases for types now defined
locally (Agent, AgentDetails, AgentState, AgentRegistry,
AgentMsgPost, AgentMsgPostPlus, AgentMsgReport,
AgentMgmtPostPlus, and all AgentState/AgentMsg constants,
AgentStateToString).

**Open dependencies after this step:**
- types.go still has aliases for syncheddataengine types
  (ConfirmationDetail, RejectedItemInfo, etc.)
- types.go still has aliases for config types (MsgQs, etc.)
- types.go still has aliases for gossip/provider/leader types
- AgentApi references ApiClient (check if this type exists)

### Step 2: Copy message queue types (from config.go)

Copy the MsgQs struct definition and related message types
(KeystateInventoryMsg, KeystateSignalMsg, EditsResponseMsg,
ConfigResponseMsg, AuditResponseMsg, StatusUpdateMsg,
MessageRetentionConf) to a new file
tdns-mp/v2/mp_msg_types.go.

Remove from types.go: aliases for these types.

Update NewMsgQs() in types.go to use local types (should
already work since the aliases pointed to the same types).

**Open dependencies after this step:**
- MsgQs channels reference types from Step 1 (ok, done)
- KeystateInventoryMsg references KeyInventoryItem
  (stays as alias — signer type)

### Step 3: Copy SDE types (syncheddataengine.go types only)

Copy the type definitions from syncheddataengine.go to a
new file tdns-mp/v2/sde_types.go:
- SynchedDataUpdate, SynchedDataResponse
- SynchedDataCmd, SynchedDataCmdResponse
- ZoneDataRepo, PendingRemoteConfirmation
- RemoteConfirmationDetail, AgentRepo
- RRState + constants, RRConfirmation, TrackedRR
- TrackedRRset, ConfirmationDetail, RejectedItemInfo
- TrackedRRInfo

Keep ZoneUpdate as alias (= tdns.ZoneUpdate).

Remove from types.go: aliases for these types.

**Open dependencies after this step:**
- ZoneDataRepo.Repo uses core.ConcurrentMap (ok, external)
- AgentRepo.Data uses core.ConcurrentMap (ok, external)
- OwnerData stays as alias (defined in tdns structs.go)

### Step 4: Copy gossip + provider groups + leader election types

Copy type definitions from gossip.go, provider_groups.go,
parentsync_leader.go to tdns-mp/v2/. These can go in
the actual files (since we'll copy the full files).

Actually: since steps 5-8 copy the full files (types +
methods together), steps 1-4 are about getting the types
in place FIRST so the method files can reference them.

Revised approach: steps 1-4 create the type definitions.
Steps 5-8 copy the method implementations.

Remove from types.go: aliases for gossip/provider/leader
types (GossipMessage, GossipStateTable, ProviderGroup,
ProviderGroupManager, LeaderElectionManager, etc.).

Remove from types.go: SyncRequest, SyncStatus (from
hsyncengine.go).

Remove from types.go: DistributionCache, DistributionInfo,
ChunkPayloadStore.

**Open dependencies after this step:**
- All type aliases removed from types.go except:
  AgentId, ZoneName, OwnerData, ZoneUpdate, AgentMsg,
  KeyInventoryItem, DnssecKeyWithTimestamps,
  CombinerState (used by signer/combiner code)
- All combiner-specific aliases stay (CombinerPost, etc.)

### Step 5: Copy method files — hsync protocol

Copy these files, converting package + adapting types:
- hsync_beat.go (methods on *AgentRegistry, *Agent)
- hsync_hello.go (methods on *AgentRegistry, *Agent)
- hsync_infra_beat.go (methods on *AgentRegistry)

These files have zero config coupling — purely methods
on MOVING types. Straightforward copy.

**Open dependencies after this step:**
- hsync_beat.go references GossipStateTable methods,
  ProviderGroupManager methods — resolved if Step 4 done
- hsync_hello.go references ValidateHsyncRRset (on
  *ZoneData — STAYS) — must be converted in Step 7

### Step 6: Copy method files — agent core

Copy these files:
- agent_utils.go (methods on *AgentRegistry, *Agent)
  - Convert: NewAgentRegistry(*Config) → free function
- agent_policy.go (methods on *ZoneDataRepo)
- gossip.go (methods on *GossipStateTable)
- provider_groups.go (methods on *ProviderGroupManager)

**Open dependencies after this step:**
- agent_utils.go references Zones global → `tdns.Zones`
- agent_utils.go references FetchSVCB (check if it uses
  unexported tdns functions)
- provider_groups.go references Zones global → `tdns.Zones`

### Step 7: Copy method files — hsync utilities

Copy hsync_utils.go. This is the hardest file — 12
methods on *ZoneData that must become free functions.

For each method:
```
func (zd *ZoneData) Foo(args) → func Foo(zd *tdns.ZoneData, args)
```

Update all callers within the already-copied files.

Also copy the 2 free functions:
- RequestAndWaitForConfig
- RequestAndWaitForAudit

**Open dependencies after this step:**
- Several functions reference `zd.MP.*` fields — these
  are on ZoneData which stays in tdns. Access works via
  `zd.MP.Foo` since zd is `*tdns.ZoneData`.
- References to `conf.Internal.MPTransport` in the
  original — these were via the *Config receiver which
  is now gone. The free function must receive tm as a
  parameter, OR access it through another path.

### Step 8: Copy method files — engines + leader election

Copy these files:
- hsyncengine.go
  - HsyncEngine: free function, takes *tdns.Config
  - Convert SynchedDataEngine receiver to free function
  - Multiple methods on *AgentRegistry (MOVING, ok)
- syncheddataengine.go
  - Convert SynchedDataEngine(*Config) → free function
  - All ZoneDataRepo methods (MOVING, ok)
  - AgentId.String(), ZoneName.String() — skip (stay as
    aliases, methods defined in tdns)
- parentsync_leader.go
  - All methods on *LeaderElectionManager (MOVING, ok)
  - One method on *AgentRegistry (broadcastElectToZone)
  - GetParentSyncStatus takes *ZoneData, *KeyDB, *Imr
    (STAYS types — passed as params, ok)
- agent_setup.go
  - Convert 5 methods on *Config → free functions
  - Convert 2 methods on *ZoneData → free functions
  - Heavy config references — use conf.* via parameter

**Open dependencies after this step:**
- HsyncEngine takes *tdns.Config — reads conf.Internal.*
  for DNS fields AND conf.Internal.* for MP fields. The
  MP field reads need to change to use InternalMp once
  HsyncEngine lives in tdns-mp. But since HsyncEngine
  receives *tdns.Config (not *tdnsmp.Config), it can't
  access InternalMp. Solution: change HsyncEngine to
  take *Config (tdnsmp) — but then the tdns copy breaks.
  Alternative: pass MsgQs, AgentRegistry etc. as explicit
  parameters instead of extracting from conf.

### Step 9: Update existing tdns-mp files

Update the already-copied files to use local types:
- start_agent.go: remove `tdns.` prefix for functions
  that are now local (HsyncEngine, etc.)
- main_init.go: NewAgentRegistry → local call
- hsync_transport.go: verify all type references resolve

### Step 10: Build, fix, iterate

Build tdns-mp. Fix compile errors. Expected categories:
- Missing type aliases (add back for types we missed)
- Unexported field/method access (convert or skip)
- Import cycle (should not happen — tdns-mp→tdns only)
- Duplicate type definitions (alias + real struct clash)

## Risk Assessment

### HIGH RISK: HsyncEngine config access
HsyncEngine reads MP fields from *tdns.Config. After
moving to tdns-mp, it should read from *tdnsmp.Config.
But it's a free function called from both tdns and
tdns-mp. Needs careful parameter redesign.

### MEDIUM RISK: ZoneUpdate type
ZoneUpdate is defined in syncheddataengine.go but used
in core DNS. Must stay as alias. Verify no methods on
ZoneUpdate exist in the moving files.

### MEDIUM RISK: Duplicate type issue
When we remove a type alias and add a real struct, any
code that was using the alias seamlessly may break if
the real struct has different field visibility or layout.
Must copy struct definitions EXACTLY.

### LOW RISK: agent_discovery_common.go
Decided to SKIP — methods stay on *tdns.Imr. Already
works cross-package.

## Summary

| Step | What | Est. types | Est. functions |
|------|------|-----------|---------------|
| 1 | agent_structs types | 28 | 2 |
| 2 | MsgQs + message types | 8 | 0 |
| 3 | SDE types | 17 | 0 |
| 4 | Gossip/provider/leader types | 11 | 0 |
| 5 | hsync protocol methods | 0 | 13 |
| 6 | Agent core methods | 1 | 28 |
| 7 | hsync_utils (receiver→free) | 0 | 16 |
| 8 | Engines + leader + setup | 0 | ~80 |
| 9 | Update existing tdns-mp | 0 | ~7 call sites |
| 10 | Build and fix | — | — |
