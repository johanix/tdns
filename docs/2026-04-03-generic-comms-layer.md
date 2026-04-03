# Generic Communications Layer

Date: 2026-04-03
Status: SKETCH
Related: `2026-03-26-architectural-improvements.md` (section 2)

## Problem

Every MP role (agent, combiner, signer, auditor) needs the
same communication infrastructure: peer discovery, hello
exchange, heartbeats, gossip, provider groups. Today this
machinery lives in the agent's `HsyncEngine` — a monolithic
goroutine that mixes generic comms with agent-specific logic
(sync handling, leader election, resync, SDE interaction).

Other roles get partial reimplementations:

- **Combiner/signer**: `InfraBeatLoop` for heartbeats to
  the combiner, but no outbound peer beats, no gossip, no
  hello exchange with other agents.
- **Auditor**: discovered the same gap at implementation
  time. Required patching in: heartbeat ticker, HELLO/BEAT
  delegation to registry, gossip, API routes — each as a
  separate fix.

This creates two problems:

1. **Fragile**: adding a new role means discovering which
   pieces of agent machinery to wire in, one crash at a
   time.
2. **Divergent**: each role's partial implementation drifts
   from the agent's, creating subtle behavioral differences
   (e.g. auditor not sending gossip state despite receiving
   it).

## Relationship to Transport Layer Cleanup

Section 2 of `2026-03-26-architectural-improvements.md`
proposes moving application-level message handlers
(`HandleBeat`, `HandleHello`, `HandleSync`, etc.) out of
`tdns-transport` and into the application layer.

This project is the complement: once handlers move out of
`tdns-transport`, they need a home. The generic comms layer
is that home — it sits between the transport layer (chunk
assembly, crypto, routing) and the role-specific engines
(SDE, combiner persistence, signer key state, auditor event
log).

The two projects should be done together or in sequence:

1. Move handlers out of `tdns-transport` → into tdns-mp
2. Split the handlers into generic (comms layer) vs
   role-specific (role engines)

## Proposed Architecture

```
┌─────────────────────────────────────────────────┐
│  Role-specific engines                          │
│  (agent: SDE, sync, resync, leader election)    │
│  (combiner: persistence, chunk processing)      │
│  (signer: key state, signing)                   │
│  (auditor: event log, observations)             │
├─────────────────────────────────────────────────┤
│  Generic comms layer  (new)                     │
│  - Peer discovery (DNS: HSYNC3, JWK, URI, SVCB) │
│  - Hello exchange (introduce, INTRODUCED state) │
│  - Heartbeat ticker (periodic BEATs)            │
│  - Gossip state exchange (NxN matrix in BEATs)  │
│  - Provider group computation                   │
│  - Peer registry management                     │
│  - Management API routes (peer list/ping/gossip)│
│  - Message consumption (Beat/Hello/Ping from    │
│    MsgQs, delegating to registry handlers)      │
├─────────────────────────────────────────────────┤
│  tdns-transport                                 │
│  - DNSMessageRouter (generic routing)           │
│  - Middleware (auth, crypto, stats, logging)     │
│  - Chunk assembly/disassembly                   │
│  - Peer registry and transport selection        │
│  - SendBeat/SendHello/SendSync (wire protocol)  │
└─────────────────────────────────────────────────┘
```

## What Lives in the Comms Layer

### Functions (extracted from HsyncEngine + agent setup)

**From `hsyncengine.go`:**
- Heartbeat ticker (`HBticker` + `SendHeartbeats()`)
- Beat consumption (`HeartbeatHandler`)
- Hello consumption (`HelloHandler`)
- Gossip state refresh (`RefreshLocalStates`)

**From `agent_discovery.go` / `agent_utils.go`:**
- `DiscoverAndRegisterAgent`
- `DiscoveryRetrierNG`
- `HelloRetrierNG`

**From `hsync_hello.go`:**
- `SingleHello`
- `HelloRetrier` / `HelloRetrierNG`

**From `hsync_beat.go`:**
- `SendHeartbeats`
- `SendSingleBeat`

**From `hsync_infra_beat.go`:**
- `StartInfraBeatLoop` (beats to combiner/signer)

**From `provider_groups.go`:**
- `ProviderGroupManager`
- Group computation from HSYNC3 data

**From `gossip.go` / `gossip_types.go`:**
- `GossipStateTable`
- State merge, group operational detection

**From `apihandler_agent.go` (subset):**
- `peer-ping`, `peer-apiping`
- `hsync-peer-status`
- `gossip-group-list`, `gossip-group-state`
- `discover`, `peer-reset`
- `router-list`, `router-describe`, `router-metrics`
- `imr-query`, `imr-flush`, `imr-reset`, `imr-show`

**From `apihandler_agent_routes.go` (subset):**
- `/agent/distrib` (peer list)

### Functions That Stay Role-Specific

**Agent only:**
- `SyncRequestHandler`
- `MsgHandler` (sync/update processing)
- `CommandHandler` (resync, send-rfi, etc.)
- Leader election wiring (`OnGroupOperational` callback)
- `SynchedDataEngine`
- `HsyncEngine` residual (sync ticker, SDE interaction)

**Combiner only:**
- `CombinerMsgHandler`
- Chunk processing, contribution persistence

**Signer only:**
- `SignerMsgHandler`
- Key state worker

**Auditor only:**
- `AuditorMsgHandler` (event logging, observation)
- Audit state tracking

## API: How Roles Use the Comms Layer

```go
// CommsEngine encapsulates generic MP communication.
type CommsEngine struct {
    Registry          *AgentRegistry
    Transport         *MPTransportBridge
    GossipStateTable  *GossipStateTable
    ProviderGroups    *ProviderGroupManager
    MsgQs             *MsgQs
}

// StartComms launches all generic comms goroutines.
// The onMessage callback receives messages that the comms
// layer does not handle (sync, update, rfi, confirm, etc.)
// and routes them to the role-specific engine.
func (ce *CommsEngine) Start(ctx context.Context) {
    // Discovery retrier
    // Hello retrier (for newly discovered peers)
    // Heartbeat ticker (periodic SendHeartbeats)
    // Infra beat loop (combiner/signer heartbeats)
    // Beat/Hello/Ping consumer (from MsgQs, delegates
    //   to registry HeartbeatHandler/HelloHandler)
    // Gossip state refresh
}

// RegisterCommsAPIRoutes adds peer/gossip/debug routes.
func (ce *CommsEngine) RegisterAPIRoutes(sr *mux.Router)
```

Each role's startup becomes:

```go
// Agent
comms := NewCommsEngine(registry, transport, msgQs)
comms.Start(ctx)
comms.RegisterAPIRoutes(apiRouter)
// Then start agent-specific engines:
go SynchedDataEngine(ctx, msgQs)
go HsyncEngineLite(ctx, msgQs)  // sync ticker only

// Auditor
comms := NewCommsEngine(registry, transport, msgQs)
comms.Start(ctx)
comms.RegisterAPIRoutes(apiRouter)
// Then start auditor-specific engines:
go AuditorMsgHandler(ctx, msgQs, stateManager)
```

## Where Does the Comms Layer Live?

In `tdns-mp/v2/`. It uses types from `tdns-transport`
(PeerRegistry, TransportManager) but contains application-
level logic (gossip semantics, provider groups, management
API handlers) that doesn't belong in the transport library.

After the transport handler migration (section 2 of the
architectural improvements doc), the dependency chain is:

```
tdns-transport: wire protocol, crypto, routing
    ↑
tdns-mp comms layer: discovery, gossip, groups, mgmt API
    ↑
tdns-mp role engines: agent/combiner/signer/auditor
```

## Implementation Phases

### Phase 1: Extract CommsEngine struct

Create `comms_engine.go` with the `CommsEngine` struct.
Move the heartbeat ticker, beat/hello consumption, and
discovery retrier into `CommsEngine.Start()`. All roles
call `CommsEngine.Start()` instead of wiring individually.

No behavioral change — purely structural extraction.

### Phase 2: Move management API routes

Extract peer/gossip/debug/IMR API cases from `APIagent`
into `CommsEngine.RegisterAPIRoutes()`. The agent's
`APIagent` handler retains only agent-specific commands
(resync, send-rfi, parentsync, etc.).

### Phase 3: Migrate transport handlers

Per section 2 of architectural improvements: move
`HandleBeat`, `HandleHello`, `HandleConfirm`, etc. from
`tdns-transport` into `tdns-mp`. The comms layer registers
them on the router during `Start()`.

### Phase 4: Slim down HsyncEngine

`HsyncEngine` becomes a thin role-specific engine that
handles only agent concerns: sync ticker, SDE interaction,
leader election callbacks. All comms are delegated to
`CommsEngine`.

## Complexity

Medium-high. Lots of code movement, many call sites. But
the pieces are already self-contained functions — the
extraction is largely mechanical, not algorithmic.

The risk is in the wiring: getting the goroutine lifecycle,
channel ownership, and initialization order right across
four roles. Phase 1 (extract without behavioral change)
mitigates this by validating the structure before changing
behavior.

## Priority

After mpauditor-1 and combiner-persistence-sep-1 merge.
The auditor works with its current ad-hoc wiring, and the
combiner/signer have their existing partial implementations.
This is a quality-of-life improvement, not a blocker.
