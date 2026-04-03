# Generic Communications Layer

Date: 2026-04-03
Status: SKETCH
Related: `2026-03-26-architectural-improvements.md` (section 2)

## Problem

Every application using the DNS transport needs the same
communication infrastructure: peer discovery, hello
exchange, heartbeats, gossip. Today this machinery lives
in the MP agent's `HsyncEngine` — a monolithic goroutine
that mixes generic comms with agent-specific logic (sync
handling, leader election, resync, SDE interaction).

Other MP roles get partial reimplementations:

- **Combiner/signer**: `InfraBeatLoop` for heartbeats to
  the combiner, but no outbound peer beats, no gossip, no
  hello exchange with other agents.
- **Auditor**: discovered the same gap at implementation
  time. Required patching in: heartbeat ticker, HELLO/BEAT
  delegation to registry, gossip, API routes — each as a
  separate fix.

Future non-MP applications (KDC, KRS, and others) will
need the same infrastructure. If the comms layer only
exists as agent internals in tdns-mp, every new application
reimplements discovery, hello, heartbeat, and gossip from
scratch.

This creates three problems:

1. **Fragile**: adding a new role or application means
   discovering which pieces of agent machinery to wire in,
   one failure at a time.
2. **Divergent**: each partial implementation drifts from
   the original, creating subtle behavioral differences.
3. **Not reusable**: applications outside tdns-mp cannot
   use the comms infrastructure at all.

## Relationship to Transport Layer Cleanup

Section 2 of `2026-03-26-architectural-improvements.md`
proposes moving application-level message handlers
(`HandleBeat`, `HandleHello`, `HandleSync`, etc.) out of
`tdns-transport` and into the application layer.

This project refines that proposal: the handlers should
not simply move to the application — they should be split
into two categories:

- **Generic comms handlers** (PING, HELLO, BEAT, gossip):
  stay in `tdns-transport` as part of the comms layer.
  Every application needs these.
- **Application-specific handlers** (SYNC, UPDATE, RFI,
  CONFIRM, KEYSTATE): move to the application layer
  (tdns-mp for MP apps, other repos for other apps).

The two projects are one project done right.

## Two Levels of Interface in tdns-transport

`tdns-transport` should provide two levels of abstraction:

### Level 1: Raw Transport

What exists today. CHUNK assembly/disassembly, sent via
NOTIFY+EDNS(0) options or in response to queries. Crypto
(encrypt/decrypt/sign/verify). DNS message router with
middleware chain. Peer registry with transport selection.

An application using only Level 1 must implement its own
discovery, its own hello/heartbeat protocol, its own peer
lifecycle management. This is appropriate for applications
with fundamentally different communication patterns.

### Level 2: Comms Layer

Built on top of Level 1. Provides managed peer
communication: discovery, hello exchange, heartbeats,
gossip, peer groups. An application using Level 2 gets
working peer-to-peer communication by providing
configuration and optional callbacks.

Most applications should use Level 2. Level 1 is the
escape hatch for applications that need raw control.

```
┌─────────────────────────────────────────────────┐
│  Application (tdns-mp, kdc, krs, ...)           │
│  - Role-specific message handlers               │
│  - Application logic                            │
│  - OnMessage callback for app-specific messages │
├─────────────────────────────────────────────────┤
│  tdns-transport: Level 2 — Comms Layer          │
│  - Peer discovery (DNS: identity zone lookup)   │
│  - Hello exchange (peer introduction)           │
│  - Heartbeat ticker (periodic BEATs)            │
│  - Gossip state exchange (NxN matrix in BEATs)  │
│  - Peer group computation                       │
│  - Peer lifecycle management                    │
│  - PING handler (built-in)                      │
│  - HELLO handler (built-in)                     │
│  - BEAT handler (built-in, with gossip)         │
├─────────────────────────────────────────────────┤
│  tdns-transport: Level 1 — Raw Transport        │
│  - DNSMessageRouter + middleware                │
│  - Chunk assembly/disassembly                   │
│  - Crypto (JOSE encrypt/decrypt/sign/verify)    │
│  - Peer registry + transport selection          │
│  - Wire protocol (SendBeat/SendHello/SendSync)  │
└─────────────────────────────────────────────────┘
```

## Interface Design Challenges

The comms layer must be generic enough for different
applications while allowing application-specific behavior.
Key design questions:

### 1. What does the comms layer own vs delegate?

**Comms layer owns autonomously:**
- Discovery: DNS lookup of identity zones (URI, JWK,
  SVCB records), peer registration
- Hello exchange: send HELLO on discovery, process
  incoming HELLO, transition peer to INTRODUCED
- Heartbeats: periodic BEAT to all introduced peers,
  process incoming BEATs, detect peer liveness
- Gossip: state matrix exchange in BEAT payloads,
  merge received state, detect group operational status
- Peer groups: compute groups from shared membership,
  track group health
- Ping: respond to PING with PONG (already in transport)

**Application provides via callbacks:**
- `OnMessage(msg)`: receive application-specific messages
  (sync, update, rfi, confirm, keystate) that the comms
  layer does not handle
- `OnGroupOperational(group)`: notification when a peer
  group reaches mutual OPERATIONAL state
- `OnGroupDegraded(group)`: notification when a group
  loses a member
- `OnPeerDiscovered(peer)`: optional hook for application-
  specific setup after discovery (e.g. register SIG(0)
  keys)
- `AuthorizePeer(identity) bool`: policy check before
  accepting a peer (application decides who is allowed)

### 2. Gossip: required or optional?

Not every application needs NxN gossip state exchange.
A simple two-party protocol (e.g. KDC talking to KRS)
does not need gossip. The comms layer should support
gossip as an opt-in feature:

```go
type CommsConfig struct {
    Identity        string
    DiscoveryZones  []string       // zones to discover peers from
    BeatInterval    time.Duration
    EnableGossip    bool           // opt-in
    Callbacks       CommsCallbacks
}
```

When gossip is disabled, BEATs are still sent (for
liveness detection) but carry no gossip payload.

### 3. Discovery: how does the application specify peers?

Today, MP agents discover peers by reading HSYNC3 records
from zone data. This is MP-specific. Other applications
may discover peers differently (configuration file, SRV
records, hardcoded list, etc.).

The comms layer should accept a peer source interface:

```go
type PeerSource interface {
    // ListPeers returns identities to discover.
    // Called periodically by the discovery retrier.
    ListPeers() []string
}
```

For MP applications, `ListPeers` reads HSYNC3 from zone
data. For KDC/KRS, it reads from config. The comms layer
doesn't care where the list comes from.

### 4. Message routing: who registers handlers?

The comms layer registers handlers for PING, HELLO, and
BEAT on the router. The application registers handlers
for its own message types (SYNC, UPDATE, etc.).

The router is shared — both the comms layer and the
application register on the same `DNSMessageRouter`.
Registration order doesn't matter (message types are
distinct).

```go
// Comms layer registers:
router.Register("ping", comms.handlePing)
router.Register("hello", comms.handleHello)
router.Register("beat", comms.handleBeat)

// Application registers:
router.Register("sync", app.handleSync)
router.Register("update", app.handleUpdate)
router.Register("keystate", app.handleKeystate)
```

### 5. Management API: who provides it?

Peer list, peer ping, gossip group status — these are
comms-layer concerns. The comms layer should provide
HTTP handler functions that the application mounts on
its API router:

```go
comms.RegisterManagementAPI(apiRouter)
// Registers:
//   POST /comms/peers     — list peers
//   POST /comms/ping      — ping a peer
//   POST /comms/gossip    — gossip state
//   POST /comms/groups    — peer groups
//   POST /comms/discover  — trigger discovery
```

The URL prefix (`/comms/` vs `/agent/`) is configurable
or chosen by the application.

## What Moves Where

### Into tdns-transport comms layer (Level 2)

**From tdns-mp:**
- `AgentRegistry` (peer tracking, state management)
- `DiscoverAndRegisterAgent` / `DiscoveryRetrierNG`
- `HelloRetrierNG` / `SingleHello`
- `SendHeartbeats` / `SendSingleBeat`
- `HeartbeatHandler` / `HelloHandler`
- `InfraBeatLoop`
- `GossipStateTable` (state merge, refresh)
- `ProviderGroupManager` (group computation)
- Management API handlers (peer list, ping, gossip)

**Already in tdns-transport (stays):**
- `HandlePing`
- `PeerRegistry`
- `TransportManager`
- `DNSMessageRouter`
- `ChunkNotifyHandler`
- Middleware chain
- Crypto

### Stays in application layer (tdns-mp)

- `HandleSync` / `HandleUpdate`
- `HandleConfirm`
- `HandleRfi`
- `HandleKeystate`
- `HandleEdits`
- Router initialization functions (`InitializeAgentRouter`,
  `InitializeCombinerRouter`, etc.) — these register
  application-specific handlers
- `SynchedDataEngine`, `HsyncEngine` (agent)
- `CombinerMsgHandler` (combiner)
- `SignerMsgHandler` (signer)
- `AuditorMsgHandler` (auditor)
- Leader election
- All role-specific API handlers

## Implementation Phases

### Phase 1: Define the interface

Design `CommsConfig`, `CommsCallbacks`, `PeerSource`,
and the `CommsEngine` type in `tdns-transport`. Write
the interface with documentation but no implementation.
Review with all known use cases (MP agent, combiner,
signer, auditor, KDC, KRS).

This is the critical phase. Getting the interface right
determines whether the comms layer is genuinely reusable
or just a relocation of MP-specific code.

### Phase 2: Extract into tdns-transport

Move discovery, hello, heartbeat, gossip, and peer
management code from tdns-mp into tdns-transport behind
the defined interface. Refactor tdns-mp roles to use
`CommsEngine` instead of direct wiring.

No behavioral change — purely structural extraction.

### Phase 3: Move application handlers out of transport

Per section 2 of architectural improvements: move
`HandleBeat`, `HandleHello`, `HandleSync`, etc. out of
their current locations in tdns-transport. The comms
handlers (`HandleBeat`, `HandleHello`) move into the
Level 2 comms layer (still in tdns-transport). The
application handlers (`HandleSync`, `HandleUpdate`,
etc.) move to tdns-mp.

### Phase 4: Slim down HsyncEngine

`HsyncEngine` becomes a thin agent-specific engine
handling only sync ticker, SDE interaction, and leader
election callbacks. All comms are delegated to
`CommsEngine`.

### Phase 5: Adopt in non-MP applications

KDC, KRS, and future applications use Level 2 directly
with their own `PeerSource` and `CommsCallbacks`.
Validates that the interface is genuinely generic.

## Complexity

High. This is a cross-repo refactoring touching
tdns-transport, tdns-mp, and eventually other application
repos. The interface design (Phase 1) is the hardest part
— code movement is mechanical once the interface is right.

The risk is designing an interface that looks generic but
is secretly shaped by MP assumptions. Phase 5 (non-MP
adoption) is the real test.

## Priority

After mpauditor-1 and combiner-persistence-sep-1 merge.
The auditor works with its current ad-hoc wiring, and
other roles have their existing partial implementations.

Phase 1 (interface design) can start as a document
exercise at any time — it doesn't require code changes.
