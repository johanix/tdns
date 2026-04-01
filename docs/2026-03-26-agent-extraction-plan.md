# Agent Extraction to tdns-mp

Date: 2026-03-26
Status: PLANNING (outline only)

## Context

The agent is the largest and most complex MP role. Unlike
the signer (4 files) and combiner (12 files), the agent
has deep dependencies on engines, registries, and state
management. A single-step migration is not feasible.

## Strategy: Incremental Migration

### Step 1: Copy MPTransportBridge to tdns-mp

Preparatory step. MPTransportBridge is the central hub
for all MP communication — every role uses it. Currently
in tdns, referenced by tdns-mp via `tdns.` prefix.

Copying it to tdns-mp makes the MP apps self-contained
and eliminates the biggest cross-package dependency before
the agent moves. Mpsigner and mpcombiner are refactored
to use the local copy.

### Step 2: Refactor mpsigner/mpcombiner for local bridge

Update mpsigner and mpcombiner to use the tdns-mp copy
of MPTransportBridge (from step 1). Verify both still
work in the lab.

### Step 3: Move agent shell + HsyncEngine

Move the agent startup orchestration and HsyncEngine
(the message handler loop that consumes from MsgQs)
to tdns-mp. Same pattern as signer/combiner: create
StartMPAgent, add initMPAgent to MainInit, create
mpagent binary.

Engines and registries stay in tdns initially — the
agent shell calls back into them.

### Step 4: Move SDE (SynchedDataEngine)

Move the SDE — the agent's core state machine for
tracking per-zone, per-peer sync state (PENDING,
ACCEPTED, REJECTED). This is a large piece but
self-contained.

### Step 5: Move remaining engines incrementally

Move one at a time, testing after each:
- AgentRegistry
- Gossip protocol
- Provider groups
- Leader election
- Agent discovery
- Agent policy (EvaluateUpdate, ProcessUpdate)

## Scope Assessment for Step 1: Copy MPTransportBridge

### Files involved

- `hsync_transport.go` — 2,179 lines. The bridge itself +
  53 methods. NewMPTransportBridge constructor.
- `agent_authorization.go` — ~187 lines. 4 methods on
  MPTransportBridge (IsPeerAuthorized etc.).
- `agent_discovery.go` — ~377 lines. 2 methods
  (RegisterDiscoveredAgent, DiscoverAndRegisterAgent).

Total: ~2,743 lines.

### Dependencies on tdns types

**Used by MPTransportBridge:**
- `AgentRegistry` — agent-only. Signer/combiner pass nil.
- `MsgQs` — shared, all roles use it for async routing.
  Channels are generic; roles use only the channels they
  need, rest are nil.
- `AgentId` — type alias `= string`. Trivial.
- `ZoneName` — type alias `= string`. Trivial.
- `Imr` — IMR resolver for agent discovery. Injected via
  callback, nil for signer/combiner.
- `DistributionCache` — already in tdns, moves later.
- `ChunkPayloadStore` — interface, optional.
- `PendingDnskeyPropagation` — defined in hsync_transport
  itself. Comes along automatically.
- `KeystateInventoryMsg` — MsgQs channel type.

**NOT used:**
- `Conf` (global) — zero references in MPTransportBridge
- `Globals` — zero references
- `ZoneData` — only in agent_authorization.go via `Zones`

### Key architectural insight

MPTransportBridge is already designed for portability:
all role-specific behavior is injected via callbacks
(AuthorizedPeers, MessageRetention, GetImrEngine).
AgentRegistry and Imr are optional (nil for non-agents).
The ONLY hard dependency on tdns globals is in
agent_authorization.go which uses `Zones.Get()` and
`Zones.Keys()`.

### Blocker: agent_authorization.go

`isInHSYNC` and `isInHSYNCAnyZone` access the global
`Zones` variable directly. Fix: refactor to use an
injected callback, e.g.:
```go
GetZone func(name string) (*ZoneData, bool)
IterZoneNames func() []string
```
This is a small, self-contained change (~10 lines).

### What mpsigner/mpcombiner actually use

Both roles create MPTransportBridge with:
- `AgentRegistry: nil` (not an agent)
- `GetImrEngine: nil` (no discovery)
- `SupportedMechanisms: ["dns"]`
- MsgQs from `conf.Config.Internal.MsgQs`

Methods used:
- `PeerRegistry.Add()`, `PeerRegistry.Get()`
- `ChunkHandler` (field set)
- `Router` (field set)
- `StartIncomingMessageRouter(ctx)`
- `SendPing(ctx, peer)` (via TransportManager)
- `DNSTransport.Confirm()`, `DNSTransport.Edits()`,
  `DNSTransport.Keystate()`

### Types that would come along

If we copy MPTransportBridge to tdns-mp, these types
need to exist locally (as aliases or copies):
- `AgentId` — `type AgentId = string` (trivial alias)
- `ZoneName` — `type ZoneName = string` (trivial alias)
- `MsgQs` — alias to `tdns.MsgQs` initially
- `AgentRegistry` — alias to `tdns.AgentRegistry` (only
  needed when agent moves; nil for signer/combiner)

### Viability assessment

**VIABLE.** The copy is feasible with:
1. Refactor agent_authorization.go to inject zone access
   via callback (small change in tdns first)
2. Copy the 3 files to tdns-mp
3. Add type aliases for AgentId, ZoneName, MsgQs
4. Update mpsigner/mpcombiner to use local copy
5. Rename originals to `legacy_*` in tdns

Estimated effort: ~2-3 hours. The bridge is already
designed for portability — callbacks, nil-safe, minimal
global state.
