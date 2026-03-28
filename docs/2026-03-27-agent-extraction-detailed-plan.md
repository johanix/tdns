# Agent Extraction: Detailed Plan for Steps 2-3

Date: 2026-03-27
Status: PLANNING
Depends on: Step 1 complete (MPTransportBridge copied to
tdns-mp)

## Problem Statement

The agent must move from tdns to tdns-mp. The central
obstacle is `Config.Internal.MPTransport` — it's typed as
`*tdns.MPTransportBridge`, but we now have a local
`MPTransportBridge` definition in tdns-mp. These are
different types. We cannot switch existing tdns-mp code
(signer, combiner) to use the local definition until we
solve the type identity problem.

The solution: give tdns-mp its own `InternalMpConf` that
holds the local `*MPTransportBridge`. Migrate
field-by-field. Both structs coexist during migration.

## Architecture: Config Split

### Current state

```
tdns.Config
  .Internal InternalConf
     InternalDnsConf    (KeyDB, channels, handlers...)
     InternalMpConf     (MPTransport, MsgQs, AgentReg...)

tdnsmp.Config
  *tdns.Config          (pointer, all via conf.Config.*)
```

### Target state (during migration)

```
tdns.Config
  .Internal InternalConf
     InternalDnsConf    (unchanged)
     InternalMpConf     (unchanged — tdns code uses this)

tdnsmp.Config
  *tdns.Config
  InternalMp tdnsmp.InternalMpConf  (local MP state)
```

Both `conf.Config.Internal.MPTransport` (tdns type) and
`conf.InternalMp.MPTransport` (local type) coexist. Code
in tdns uses the former; code in tdns-mp uses the latter.
The rule: when a file moves from tdns to tdns-mp, ALL its
`conf.Internal.X` references switch to `conf.InternalMp.X`
atomically. No split access to the same field.

Fields in tdns.InternalMpConf are NOT removed during
migration — they stay for other tdns consumers (tdns-agent
binary, other apps). They are removed only at the very end
when the agent binary itself moves.

## InternalMpConf Field Analysis

All 14 fields of tdns.InternalMpConf will be mirrored in
tdnsmp.InternalMpConf. During migration, both exist.

### Shared fields (signer + combiner + agent)

| Field | Type | tdns refs | tdns-mp refs |
|-------|------|-----------|--------------|
| MPTransport | *MPTransportBridge | 33 | 11 |
| TransportManager | *transport.TM | 46 | 2 |
| MsgQs | *MsgQs | 28 | 4 |
| DistributionCache | *DistributionCache | 18 | 8 |
| CombinerState | *CombinerState | 7 | 5 |

### Agent-only fields

| Field | Type | tdns refs |
|-------|------|-----------|
| SyncQ | chan SyncRequest | 5 |
| AgentRegistry | *AgentRegistry | 42 |
| ZoneDataRepo | *ZoneDataRepo | 3 |
| LeaderElectionManager | *LeaderElectionMgr | 15 |
| ChunkPayloadStore | ChunkPayloadStore | 1 |
| MPZoneNames | []string | 8 |

### Fields used by external apps only

| Field | Type | Notes |
|-------|------|-------|
| SyncStatusQ | chan SyncStatus | Not used in tdns or tdns-mp |
| KdcDB | interface{} | Used by external apps |
| KdcConf | interface{} | Used by external apps |
| KrsDB | interface{} | Used by external apps |
| KrsConf | interface{} | Used by external apps |

These stay in tdns.InternalMpConf. We do not touch them.

## Type Alias Strategy

During migration, MPTransportBridge in tdns-mp is a type
alias (`= tdns.MPTransportBridge`). This means:

- A single bridge instance can be stored in BOTH
  `conf.InternalMp.MPTransport` and
  `conf.Config.Internal.MPTransport` (same type)
- No two-instance problem
- The local struct definition in hsync_transport.go stays
  dormant until we remove the alias

The alias is removed (activating the local definition)
only when ALL tdns-mp consumers read from InternalMp and
the dual-write to conf.Config.Internal is no longer needed
for the signer/combiner roles.

## Execution Plan

### Step 2b: Create tdnsmp.InternalMpConf

Define in tdns-mp/v2/config.go with ALL fields (mirrors
tdns.InternalMpConf):

```go
type InternalMpConf struct {
   SyncQ                 chan SyncRequest
   MsgQs                 *MsgQs
   SyncStatusQ           chan SyncStatus
   AgentRegistry         *AgentRegistry
   ZoneDataRepo          *ZoneDataRepo
   CombinerState         *CombinerState
   TransportManager      *transport.TransportManager
   MPTransport           *MPTransportBridge
   LeaderElectionManager *LeaderElectionManager
   ChunkPayloadStore     ChunkPayloadStore
   MPZoneNames           []string
   DistributionCache     *DistributionCache
}
```

Update tdnsmp.Config:

```go
type Config struct {
   *tdns.Config
   InternalMp InternalMpConf
}
```

Types that need aliases added to types.go:
- SyncRequest, SyncStatus (channel element types)
- ZoneDataRepo
- CombinerState
- LeaderElectionManager

### Step 2c: Migrate tdns-mp readers to InternalMp

Change all tdns-mp code that accesses
`conf.Config.Internal.{MP field}` to use
`conf.InternalMp.{field}` instead.

In main_init.go, dual-write: set BOTH conf.InternalMp.*
AND conf.Config.Internal.* so tdns code still works.

Files to change (7 files, all in tdns-mp/v2/):
- main_init.go (writes MPTransport, TM, MsgQs, etc.)
- start_combiner.go (reads MPTransport, MsgQs, CombState)
- start_signer.go (reads MPTransport, MsgQs)
- combiner_msg_handler.go (reads MPTransport)
- signer_msg_handler.go (reads MPTransport)
- apihandler_combiner.go (reads MPTransport)
- key_state_worker.go (reads MPTransport)

After this, no tdns-mp code reads MP fields from
conf.Config.Internal. Build + verify.

### Step 2d: Remove MPTransportBridge alias

Remove type aliases for MPTransportBridge and
MPTransportBridgeConfig from types.go. The local struct
definitions in hsync_transport.go become active.

main_init.go creates a local *MPTransportBridge (now a
different type from *tdns.MPTransportBridge). It sets:
- conf.InternalMp.MPTransport = tm (local type, works)
- conf.Config.Internal.MPTransport = tm (TYPE MISMATCH!)

The dual-write to conf.Config.Internal.MPTransport breaks.
This is safe ONLY IF no tdns code reads
Internal.MPTransport for the signer/combiner roles.

CHECK NEEDED: Verify that legacy_combiner_msg_handler.go
and signer_msg_handler.go in tdns/v2/ are dead code for
mpsigner/mpcombiner binaries.

If confirmed dead: remove the dual-write, drop the alias.
If not dead: keep alias, defer Step 2d.

### Step 3a: Create initMPAgent

Add `case "agent":` to MainInit in tdns-mp/v2/main_init.go.
Mirror the AppTypeAgent case from tdns main_initfuncs.go:
- Create local MPTransportBridge (using local constructor)
- Set conf.InternalMp.* fields
- Dual-write to conf.Config.Internal.* for agent code
  that hasn't moved yet

### Step 3b: Create StartMPAgent + mpagent binary

Create tdns-mp/v2/start_agent.go:
- HsyncEngine (agent message consumer)
- SDE startup (SynchedDataEngine)
- Heartbeat loops, discovery retrier

Create tdns-mp/cmd/mpagent/ binary (same pattern as
mpsigner/mpcombiner).

### Step 3c: Move agent files incrementally

Move files one at a time. For each file:
1. Copy to tdns-mp/v2/, change package to tdnsmp
2. Add `tdns.` prefix for CORE-TDNS types
3. Change `conf.Internal.X` → `conf.InternalMp.X`
4. Add type aliases for any new MP-only types
5. Build both repos, verify

The `conf.Internal.X` → `conf.InternalMp.X` change is
mechanical: same field names, just different config path.
No refactoring of logic needed.

For agent_setup.go (48 Conf refs): MultiProviderConf stays
in tdns, so `conf.Config.MultiProvider.*` works unchanged.
Only `conf.Internal.{MP field}` refs change to
`conf.InternalMp.{field}`.

## Agent Files to Move (~13,800 lines)

### Core implementation (17 files, ~9,500 lines)

| File | Lines | Config coupling | Status |
|------|-------|-----------------|--------|
| hsync_transport.go | 2193 | none | Copied (Step 1) |
| agent_authorization.go | 195 | none | Copied (Step 1) |
| agent_discovery.go | 377 | none | Copied (Step 1) |
| agent_discovery_common.go | 290 | none | Easy |
| agent_structs.go | ~500 | none | Easy |
| agent_policy.go | ~300 | none | Easy |
| hsync_beat.go | ~400 | none | Easy |
| hsync_hello.go | ~500 | none | Easy |
| hsync_infra_beat.go | ~200 | none | Easy |
| gossip.go | ~400 | none | Easy |
| provider_groups.go | ~300 | none | Easy |
| agent_utils.go | ~300 | light (6) | Medium |
| parentsync_leader.go | ~300 | light (3) | Medium |
| hsyncengine.go | ~500 | light (3) | Medium |
| hsync_utils.go | ~600 | moderate (12) | Medium |
| syncheddataengine.go | 1578 | moderate (12) | Medium |
| agent_setup.go | ~400 | heavy (48) | Mechanical |

### CLI files (10 files, ~4,200 lines)

All in tdns/v2/cli/: agent_cmds.go, agent_debug_cmds.go,
agent_edits_cmds.go, agent_gossip_cmds.go,
agent_imr_cmds.go, agent_router_cmds.go,
agent_zone_cmds.go, hsync_cmds.go, hsync_debug_cmds.go

## Risks and Mitigations

### Risk 1: Split access to same field
A field exists in both InternalMpConf structs. If some
code writes one and other code reads the other, state is
inconsistent. Mitigation: atomic migration per file. ALL
references in a moved file switch to InternalMp. Dual-write
in main_init.go keeps both copies in sync during transition.

### Risk 2: Circular imports
tdns must never import tdns-mp. Mitigation: all shared
types live in tdns (or core). Agent-specific types that
move to tdns-mp are only referenced by tdns-mp code.

### Risk 3: Two bridge instances
Creating both a tdns and local bridge gives separate state.
Mitigation: type aliases ensure ONE instance during
transition. Alias removed only when all consumers are local.

## Recommended Execution Order

1. Step 2b: Create tdnsmp.InternalMpConf + update Config
2. Step 2c: Migrate 7 tdns-mp files to use InternalMp
3. Verify: Build + lab test mpsigner/mpcombiner
4. Step 2d: Remove alias, activate local struct (if safe)
5. Step 3a: Create initMPAgent in main_init.go
6. Step 3b: Create StartMPAgent + mpagent binary
7. Step 3c: Move agent files (easy ones first, then medium,
   then agent_setup.go last)

Steps 2b-2c are safe and reversible. Step 2d is the point
of no return for the type split. Steps 3a-3c are the bulk.
