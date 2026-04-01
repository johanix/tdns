# Big Bang Agent Extraction: Detailed Execution Plan

Date: 2026-03-27
Status: PLANNING
Depends on: Steps 1, 2b-2d, 3a-3b complete

## Overview

Move all agent code (~10,000 lines, 13 files, ~76 types,
~183 functions) from tdns/v2/ to tdns-mp/v2/ in a single
coordinated operation. No changes to tdns — copy only.
(One exception: callback injection in zone_utils.go, see
Prerequisite section.)

## Completed Prerequisites

These steps from earlier planning docs are DONE:
- Step 1: MPTransportBridge copied to tdns-mp (3 files)
- Step 2b: tdnsmp.InternalMpConf created with all fields
- Step 2c: All tdns-mp files use conf.InternalMp.*
- Step 2d: Local MPTransportBridge struct active (no alias)
- Step 3a: initMPAgent created in main_init.go
- Step 3b: StartMPAgent + mpagent binary created
- agent_discovery.go already copied (Step 1)
- agent_authorization.go already copied (Step 1)
- hsync_transport.go already copied (Step 1)

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

## Files to Copy (13 files)

NOTE: agent_discovery_common.go is NOT copied. Its 6
methods on *Imr are already exported in tdns and callable
cross-package from the existing tdns-mp agent_discovery.go.

| File | Lines | Types | Config coupling |
|------|-------|-------|-----------------|
| agent_structs.go | 471 | 28 | none |
| agent_policy.go | 503 | 0 | none |
| agent_utils.go | 1134 | 1 | light (6 refs) |
| agent_setup.go | 564 | 0 | heavy (48 refs) |
| hsync_beat.go | 237 | 0 | none |
| hsync_hello.go | 377 | 0 | none |
| hsync_infra_beat.go | 95 | 0 | none |
| hsyncengine.go | 1131 | 4 | light (3 refs) |
| hsync_utils.go | 909 | 2 | moderate (12 refs) |
| syncheddataengine.go | 1578 | 17 | moderate (12 refs) |
| gossip.go | 368 | 4 | none |
| provider_groups.go | 275 | 3 | none |
| parentsync_leader.go | 1498 | 4 | light (3 refs) |

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

**Permanently (no methods, pervasive, or defined elsewhere):**
- AgentId (= tdns.AgentId) — pervasive, no methods
- ZoneName (= tdns.ZoneName) — pervasive, no methods
- ZoneUpdate (= tdns.ZoneUpdate) — used in core DNS
- OwnerData (= tdns.OwnerData) — defined in structs.go
- AgentMsg (= core.AgentMsg) — defined in core package
- KeyInventoryItem — signer type
- DnssecKeyWithTimestamps — signer type
- CombinerState — used by signer/combiner code

**Temporarily (until dual-writes removed):**
- MsgQs — dual-written in main_init.go initMPAgent
- AgentRegistry — dual-written in main_init.go initMPAgent
- DistributionCache — dual-written in main_init.go

These three must remain aliases while main_init.go
dual-writes `conf.Config.Internal.X = conf.InternalMp.X`.
The dual-writes exist so tdns code (HsyncEngine, SDE)
can access the MP state. Once HsyncEngine and SDE become
methods on *tdnsmp.Config (Step 8) and read from
conf.InternalMp directly, the dual-writes are removed
and these aliases can become real types.

**Consequence for Step 1:** Do NOT move MsgQs,
AgentRegistry, or DistributionCache type definitions yet.
Move all other agent_structs.go types. The struct
definitions for these three move in a follow-up step
after Step 8 removes the dual-writes.

## ZoneUpdate: Special Case

ZoneUpdate is defined in syncheddataengine.go but used in
core DNS code (refreshengine.go, zone_updater.go,
zone_utils.go, updateresponder.go, catalog.go). It CANNOT
move to tdns-mp — it would break core DNS.

**Decision:** Keep ZoneUpdate as alias (= tdns.ZoneUpdate).
It stays in tdns. The syncheddataengine.go copy in tdns-mp
references it as `tdns.ZoneUpdate` or via alias.

## Functions Requiring Receiver Conversion

Methods on types that STAY in tdns need conversion when
copied to tdns-mp. Two conversion strategies:

### Strategy A: *tdns.Config → *tdnsmp.Config receiver

Methods on `*tdns.Config` become methods on `*Config`
(tdnsmp). This is the preferred approach because
`*tdnsmp.Config` embeds `*tdns.Config` — so all DNS
fields are accessible via `conf.Config.Internal.*` and
all MP fields via `conf.InternalMp.*`. No parameter
plumbing needed.

### Strategy B: *tdns.ZoneData → free function

Methods on `*tdns.ZoneData` must become free functions
(tdnsmp.Config does not embed ZoneData). The ZoneData
pointer becomes an explicit first parameter.

### Methods on *Config → *tdnsmp.Config (Strategy A)

**From agent_setup.go (5 functions):**
```
(conf *Config) SetupAgent(all_zones)
  → (conf *Config) SetupAgent(all_zones)  [tdnsmp.Config]
  Callers: main_init.go (tdns-mp)

(conf *Config) SetupAgentAutoZone(zonename)
  → (conf *Config) SetupAgentAutoZone(zonename)
  Callers: within SetupAgent only

(conf *Config) publishApiTransport(zd)
  → (conf *Config) publishApiTransport(zd *tdns.ZoneData)
  Callers: within SetupAgent only

(conf *Config) publishDnsTransport(zd)
  → (conf *Config) publishDnsTransport(zd *tdns.ZoneData)
  Callers: within SetupAgent only
```

**From syncheddataengine.go (1 function):**
```
(conf *Config) SynchedDataEngine(ctx, msgQs)
  → (conf *Config) SynchedDataEngine(ctx, msgQs *MsgQs)
  Callers: start_agent.go (tdns-mp)
```

**From agent_utils.go (1 function):**
```
(conf *Config) NewAgentRegistry()
  → (conf *Config) NewAgentRegistry()
  Callers: main_init.go (tdns-mp)
```

**From hsyncengine.go (1 free function → method):**
```
HsyncEngine(ctx, conf *Config, msgQs *MsgQs)
  → (conf *Config) HsyncEngine(ctx, msgQs *MsgQs)
  Callers: start_agent.go (tdns-mp)
```

Inside these functions:
- `conf.MultiProvider` → `conf.Config.MultiProvider`
- `conf.Internal.KeyDB` → `conf.Config.Internal.KeyDB`
- `conf.Internal.MPTransport` → `conf.InternalMp.MPTransport`
- `conf.Internal.AgentRegistry` → `conf.InternalMp.AgentRegistry`
- `conf.Internal.MsgQs` → `conf.InternalMp.MsgQs`
- Other DNS fields via `conf.Config.Internal.*`

### Methods on *ZoneData → free functions (Strategy B)

**From hsync_utils.go (12 functions):**
```
(zd *ZoneData) HsyncChanged(newzd)
  → HsyncChanged(zd, newzd *tdns.ZoneData) (bool, ...)
(zd *ZoneData) LocalDnskeysChanged(newzd)
  → LocalDnskeysChanged(zd, newzd *tdns.ZoneData) (bool, ...)
(zd *ZoneData) LocalDnskeysFromKeystate()
  → LocalDnskeysFromKeystate(zd *tdns.ZoneData) (bool, ...)
(zd *ZoneData) RequestAndWaitForKeyInventory(ctx)
  → RequestAndWaitForKeyInventory(zd *tdns.ZoneData, ctx)
(zd *ZoneData) RequestAndWaitForEdits(ctx)
  → RequestAndWaitForEdits(zd *tdns.ZoneData, ctx)
(zd *ZoneData) applyEditsToSDE(agentRecords)
  → applyEditsToSDE(zd *tdns.ZoneData, agentRecords)
(zd *ZoneData) buildRemoteDNSKEYsFromTags(foreignKeyTags)
  → buildRemoteDNSKEYsFromTags(zd *tdns.ZoneData, ...)
(zd *ZoneData) ValidateHsyncRRset()
  → ValidateHsyncRRset(zd *tdns.ZoneData) (bool, error)
(zd *ZoneData) matchHsyncProvider(ourIdentities)
  → matchHsyncProvider(zd *tdns.ZoneData, ourIdentities)
(zd *ZoneData) analyzeHsyncSigners(ourIdentities, label)
  → analyzeHsyncSigners(zd *tdns.ZoneData, ...)
(zd *ZoneData) populateMPdata()
  → populateMPdata(zd *tdns.ZoneData)
(zd *ZoneData) weAreASigner()
  → weAreASigner(zd *tdns.ZoneData) (bool, error)
```
Callers are all in moving files (hsyncengine.go,
syncheddataengine.go, hsync_hello.go, hsync_utils.go).
Change `zd.Foo()` → `Foo(zd)` at each call site.

**From agent_setup.go (2 functions):**
```
(zd *ZoneData) AgentSig0KeyPrep(name, kdb)
  → AgentSig0KeyPrep(zd *tdns.ZoneData, name, kdb)
(zd *ZoneData) AgentJWKKeyPrep(publishname, kdb)
  → AgentJWKKeyPrep(zd *tdns.ZoneData, publishname, kdb)
```
Callers: within agent_setup.go only (publishDnsTransport).

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
| start_agent.go | tdns.HsyncEngine(ctx, conf.Config, ...) | conf.HsyncEngine(ctx, ...) |
| start_agent.go | ar.StartInfraBeatLoop(ctx) | (already correct — method on MOVING type) |
| start_agent.go | ar.DiscoveryRetrierNG(ctx) | (already correct — method on MOVING type) |
| start_agent.go | conf.Config.SynchedDataEngine(ctx, ...) | conf.SynchedDataEngine(ctx, ...) |
| main_init.go | conf.Config.NewAgentRegistry() | conf.NewAgentRegistry() |
| main_init.go | conf.Config.SetupAgent(zones) | conf.SetupAgent(zones) |

## Prerequisite: Refresh Cycle Callback Injection

The refresh cycle (FetchFromUpstream, FetchFromFile in
zone_utils.go) calls 13+ MP-analysis functions that are
moving to tdns-mp. Since tdns cannot import tdns-mp
(circular dependency), these calls must be replaced with
a registered callback before the big bang.

### The Problem

FetchFromUpstream lines 350-561 contain:
- Analysis: DelegationDataChangedNG, HsyncChanged,
  DnskeysChangedNG, LocalDnskeysChanged,
  LocalDnskeysFromKeystate, RequestAndWaitForKeyInventory
- Actions: snapshotUpstreamData, populateMPdata,
  matchHsyncProvider, CombineWithLocalChanges,
  InjectSignatureTXT, SyncQ/DelegationSyncQ sends

FetchFromFile has the same pattern (lines 169-313).

All of this is MP-specific code that should not remain
in tdns core.

### Design: Two Callbacks (Pre-Flip + Post-Flip)

Two callback slices on ZoneData:

```go
OnZonePreRefresh  []func(zd, new_zd *ZoneData)
OnZonePostRefresh []func(zd *ZoneData)
```

**OnZonePreRefresh** runs BEFORE the hard flip. Receives
both old (`zd`, current, still served) and new (`new_zd`,
incoming, not yet served). This callback:

- **Analyzes**: compares zd (old) vs new_zd (new) for
  delegation, HSYNC, DNSKEY changes. Stores results in
  `zd.MP` (persists across flip; Options map is shared
  between zd and new_zd so changes are visible on both).
- **Modifies new_zd**: adds combiner contributions
  (CombineWithLocalChanges), injects signature TXT,
  snapshots upstream data, populates MP data — all
  applied to new_zd before it goes live.
- **Agent RFIs**: RequestAndWaitForKeyInventory and
  LocalDnskeysFromKeystate run here (have access to
  both zone versions).

When OnZonePreRefresh returns, new_zd is fully prepared.
The hard flip publishes the complete zone atomically.
No race condition — the zone is never served without
combiner contributions.

**OnZonePostRefresh** runs AFTER the hard flip. Receives
`zd` (now serving new data). This callback:

- **Queue sends**: SyncQ, DelegationSyncQ, MusicSyncQ —
  these must happen after the flip because consumers
  read `req.ZoneData` which must point to the live zone.
- **Any action that needs the live zone pointer**: e.g.,
  delegation sync sends `zd` as `ZoneData` in the
  request struct.

The split is clean:
- Pre: analysis + modification of new_zd
- Post: notifications + queue sends

### After Callback Injection

zone_utils.go FetchFromUpstream becomes:
```
// ... zone transfer, serial check ...
for _, cb := range zd.OnZonePreRefresh {
    cb(zd, &new_zd)
}
// ... hard flip (publishes fully-prepared new_zd) ...
// ... RepopulateDynamicRRs (core DNS, stays here) ...
for _, cb := range zd.OnZonePostRefresh {
    cb(zd)
}
// ... persist serial, notify ...
```

FetchFromFile uses the same pattern.

Note: RepopulateDynamicRRs is core DNS (re-adds dynamic
RRs lost in zone transfer). It stays in zone_utils.go
between the flip and the post-refresh callbacks.

### Implementation Note

The callback injection is a change to tdns (zone_utils.go
and structs.go for the two callback fields). This is the
ONE exception to the "no tdns changes" rule — it's a
prerequisite structural change that enables the extraction.

Callbacks are registered by tdns-mp at init time (in
OnFirstLoad, similar to PersistContributions). Each role
registers its own pre and post implementations:
- Agent: pre=analysis+RFIs, post=SyncQ+DelegationSyncQ
- Combiner: pre=analysis+contributions, post=queue sends
- Signer: pre=analysis+signing decisions, post=queue sends

The tdns-agent binary registers the same callbacks from
its own code (the functions stay in tdns too).

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
  - HsyncEngine: becomes method on *tdnsmp.Config
  - Multiple methods on *AgentRegistry (MOVING, ok)
- syncheddataengine.go
  - SynchedDataEngine: becomes method on *tdnsmp.Config
  - All ZoneDataRepo methods (MOVING, ok)
  - AgentId.String(), ZoneName.String() — skip (stay as
    aliases, methods defined in tdns)
- parentsync_leader.go
  - All methods on *LeaderElectionManager (MOVING, ok)
  - One method on *AgentRegistry (broadcastElectToZone)
  - GetParentSyncStatus takes *ZoneData, *KeyDB, *Imr
    (STAYS types — passed as params, ok)
- agent_setup.go
  - 5 methods on *tdns.Config → methods on *tdnsmp.Config
  - 2 methods on *ZoneData → free functions
  - Config references: conf.MultiProvider becomes
    conf.Config.MultiProvider, conf.Internal.KeyDB becomes
    conf.Config.Internal.KeyDB, conf.Internal.MPTransport
    becomes conf.InternalMp.MPTransport

**Open dependencies after this step:**
- HsyncEngine and SynchedDataEngine are now methods on
  *tdnsmp.Config. They access DNS fields via
  conf.Config.Internal.* and MP fields via
  conf.InternalMp.*. No parameter redesign needed.
- start_agent.go callers update:
  `tdns.HsyncEngine(ctx, conf.Config, ...)` becomes
  `conf.HsyncEngine(ctx, ...)`

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

### RESOLVED: HsyncEngine / SynchedDataEngine config access
Previously HIGH risk. Resolved by making these methods on
`*tdnsmp.Config` instead of free functions. The receiver
gives access to both DNS fields (`conf.Config.Internal.*`)
and MP fields (`conf.InternalMp.*`). Same approach applies
to agent_setup.go functions.

### MEDIUM RISK: Type definition completeness
When copying struct definitions from tdns, every field
type must resolve in tdns-mp. Types like `ApiClient`,
`RRTypeStore`, `MultiProviderConf` must be accessible
(via `tdns.` prefix or alias). Missing any field type
causes a compile error. Mitigation: copy struct
definitions exactly, verify every field type.

### MEDIUM RISK: ZoneUpdate type
ZoneUpdate is defined in syncheddataengine.go but used
in core DNS. Must stay as alias. Verify no methods on
ZoneUpdate exist in the moving files.

### MEDIUM RISK: MsgQs channel type coherence
MsgQs channels use types that are moving (AgentMsgReport,
AgentMsgPostPlus, etc.). As long as these types remain
aliases during Step 1-4 of the execution, the channels
work across packages. When types become real structs
(removing aliases), any tdns code reading channels from
a tdns-mp-created MsgQs gets type mismatches. This is
acceptable — the mpagent binary uses tdns-mp types
throughout; the tdns-agent binary uses tdns types.

### MEDIUM RISK: Duplicate type issue
When we remove a type alias and add a real struct, any
code that was using the alias seamlessly may break if
the real struct has different field visibility or layout.
Must copy struct definitions EXACTLY.

### LOW RISK: *ZoneData receiver conversions
14 methods on *ZoneData become free functions. Callers
all in moving files — change `zd.Foo()` → `Foo(zd)`.
Mechanical, low risk. Tedious but straightforward.

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
