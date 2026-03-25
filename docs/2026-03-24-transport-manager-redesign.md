# TransportManager Redesign: Generic TM for tdns-transport

## Context

During Phase 2 (tdns-mp extraction) we discovered that
TransportManager (TM) and ReliableMessageQueue (RMQ) should
live in tdns-transport, not tdns or tdns-mp. The current TM
is in tdns/v2/hsync_transport.go (2229 lines, ~45 methods)
with only ~8 generic methods — the rest know about MP
concepts (combiner, signer, MsgQs, gossip, DNSKEY tracking).

The goal: extract a **generic TransportManager** into
tdns-transport that any application can use, with MP-specific
logic remaining in tdns as application-level wiring.

## Design Principles

1. **TM is orchestration, not per-packet.** At startup TM
   creates and wires components. At runtime, messages flow
   directly between components without passing through TM.

2. **Router is the sole incoming fan-out.** No IncomingChan
   bottleneck. Each message type dispatches directly to the
   application's typed channel via Router handler registration.

3. **All outgoing messages go through RMQ.** Two policies:
   - `PolicyRequestResponse` — synchronous send, response is
     the confirmation (beat, hello, ping)
   - `PolicyAsyncConfirm` — send + ACK, wait for separate
     CONFIRM message (sync, update)

4. **TM and RMQ don't know about "combiner" or "agent".**
   All recipients are peer IDs (strings). The application
   decides who is who and enqueues by peer ID.

5. **Peer configuration and discovery is application logic.**
   Once discovered, peers are registered in PeerRegistry.
   TM provides the registry, application populates it.

## Revised Incoming Message Path

```
1. DNS NOTIFY arrives (QTYPE=CHUNK)
       |
2. ChunkNotifyHandler.RouteViaRouter()
   - Reassemble CHUNKs, decrypt payload
   - Create MessageContext
       |
3. Router.Route(ctx, messageType)
   - Middleware chain (auth, signature, stats)
   - Dispatch to handler for this type
       |
4. Application's registered handlers:
   handler for "beat"  --> beatChan
   handler for "sync"  --> syncChan
   handler for "hello" --> helloChan
   (trivial: parse + push to typed channel + return)
       |
5. Application goroutines consume typed channels
   - HsyncEngine reads beatChan
   - CombinerMsgHandler reads syncChan
   - etc.
```

No IncomingChan. One dispatch. No bottleneck. A slow
beat never blocks a sync.

## Outgoing Message Path

### Request/response messages (beat, hello, ping)

```
App --> RMQ.Enqueue(peerID, payload, PolicyRequestResponse)
        |
        RMQ calls sendFunc(peerID, payload)
        |
        sendFunc: PeerRegistry.Get(peerID)
                  --> SelectTransport(peer)
                  --> transport.Beat/Hello/Ping(ctx, peer, req)
        |
        Response = confirmation. Done.
        Retry on failure.
```

### Async-confirmed messages (sync, update)

```
App --> RMQ.Enqueue(peerID, payload, PolicyAsyncConfirm)
        |
        RMQ calls sendFunc(peerID, payload)
        |
        sendFunc: same as above --> transport.Sync()
        |
        ACK received immediately.
        RMQ waits for separate CONFIRM.
        |
        CONFIRM arrives via incoming path:
        Router handler for "confirm"
          --> RMQ.MarkDeliveryConfirmed(distID)
        |
        RMQ marks message complete. Done.
        Retry if CONFIRM times out.
```

### Caller specifies recipient by peer ID

```go
// MP code knows combiner ID from config
combinerID := conf.MultiProvider.CombinerIdentity
rmq.Enqueue(combinerID, zone, payload, PriorityHigh)

// Or for all agents in a zone
for _, agentID := range getZoneAgents(zone) {
    rmq.Enqueue(agentID, zone, payload, PriorityNormal)
}
```

RMQ never interprets peer IDs. Application decides
who to send to.

## Generic TransportManager API

```go
type TransportManagerConfig struct {
    LocalID             string
    ControlZone         string
    APITimeout          time.Duration
    DNSTimeout          time.Duration
    ChunkMode           string
    ChunkMaxSize        int
    PayloadCrypto       *PayloadCrypto
    SupportedMechanisms []string
    ClientCertFile      string
    ClientKeyFile       string

    // Callbacks (injected by application)
    IsPeerAuthorized      func(senderID, zone string) (bool, string)
    IsRecipientReady      func(recipientID string) bool
    GetPeerAddress        func(senderID string) (string, bool)
    OnPeerDiscoveryNeeded func(peerID string)

    // RMQ send function (application provides)
    SendFunc func(ctx context.Context,
                  recipientID string,
                  payload []byte) error
}

type TransportManager struct {
    // Components (all in tdns-transport)
    APITransport   *APITransport
    DNSTransport   *DNSTransport
    ChunkHandler   *ChunkNotifyHandler
    Router         *DNSMessageRouter
    PeerRegistry   *PeerRegistry
    ReliableQueue  *ReliableMessageQueue

    LocalID        string
    ControlZone    string
}
```

### TM methods

```go
// Construction
NewTransportManager(cfg *TransportManagerConfig) *TM

// Transport selection (used by app's sendFunc)
SelectTransport(peer *Peer) Transport

// Lifecycle
RegisterChunkNotifyHandler(
    registerFn func(uint16, func(...) error) error) error
StartReliableQueue(ctx context.Context)

// Reliable delivery
Enqueue(recipientID, zone, operation string,
    payload []byte, priority MessagePriority) (string, error)
MarkDeliveryConfirmed(distributionID, senderID string) bool
GetQueueStats() QueueStats

// Convenience send (used by app's sendFunc)
SendPing(ctx context.Context, peer *Peer) (*PingResponse, error)
```

### What TM does NOT do

- No message type dispatch (Router does it)
- No MsgQs channels (application registers Router handlers)
- No combiner/signer/agent knowledge
- No gossip, DNSKEY tracking, discovery
- No IncomingChan
- No per-packet involvement at runtime (after setup)

## ReliableMessageQueue in tdns-transport

```go
type DeliveryPolicy int
const (
    PolicyRequestResponse DeliveryPolicy = iota
    PolicyAsyncConfirm
)

type ReliableMessageQueueConfig struct {
    IsRecipientReady  func(recipientID string) bool
    SendFunc          func(ctx context.Context,
                          recipientID string,
                          payload []byte) error
    BaseBackoff       time.Duration
    MaxBackoff        time.Duration
    ConfirmTimeout    time.Duration
    ExpirationTimeout time.Duration
}

type OutgoingMessage struct {
    RecipientID    string
    Zone           string
    Operation      string
    Payload        []byte
    DistributionID string
    Priority       MessagePriority
    Policy         DeliveryPolicy
}
```

No AgentRegistry dependency. No "combiner"/"agent"
RecipientType. Recipients are peer ID strings.

## MP Wiring (stays in tdns)

### MsgQs struct disappears

The current `MsgQs` struct is statically typed with a
fixed set of named channels (`Beat chan *AgentBeatReport`,
`Msg chan *AgentMsgPostPlus`, etc.). This is the opposite
of generic — it hardcodes one application's message types.

In the new design there is no MsgQs struct in tdns-transport.
The application creates whatever channels it needs, of
whatever types, and registers Router handlers that wire
incoming messages to those channels. tdns-transport never
sees the channels or knows their types.

The Router handler signature is `func(ctx *MessageContext)
error`. The handler closure captures the channel:

```go
func makeBeatHandler(ch chan *AgentBeatReport) transport.MessageHandlerFunc {
    return func(ctx *transport.MessageContext) error {
        report := parseBeatReport(ctx)
        ch <- report
        return nil
    }
}
```

A hypothetical future app with 12 new message types creates
12 channels and registers 12 handlers. tdns-transport is
not involved.

The MP application may keep a convenience struct holding
its channels (e.g. `MPChannels`), but that lives in tdns
(or later tdns-mp), not in tdns-transport.

### Channel creation and wiring

```go
// In MainInit or StartAgent (MP code in tdns)
beatChan := make(chan *AgentBeatReport, 100)
syncChan := make(chan *AgentMsgPostPlus, 100)
helloChan := make(chan *AgentMsgReport, 100)
// ... one per message type the MP app cares about

// Register handlers that wire Router to channels
tm.Router.Register("mp-beat", "beat",
    makeBeatHandler(beatChan))
tm.Router.Register("mp-sync", "sync",
    makeSyncHandler(syncChan))
tm.Router.Register("mp-hello", "hello",
    makeHelloHandler(helloChan))

// Start consumer goroutines
go HsyncEngine(beatChan, ...)
go CombinerMsgHandler(syncChan, ...)
```

### Outgoing messages

```go
// Caller knows recipient from config or HSYNC lookup
combinerID := conf.MultiProvider.CombinerIdentity
tm.Enqueue(combinerID, zone, payload, PriorityHigh)

for _, agentID := range getZoneAgents(zone) {
    tm.Enqueue(agentID, zone, payload, PriorityNormal)
}
```

### MP-specific concerns stay in tdns:
- Message channel creation and Router handler registration
- AgentRegistry (agent state, gossip, provider groups)
- Authorization logic (config peers + HSYNC checks)
- Agent discovery (DNS lookups to find peers)
- DNSKEY propagation tracking
- Combiner/signer/agent role knowledge

## Implementation Steps

### Step 1: Move RMQ to tdns-transport — DONE

Genericized RMQ with `interface{}` payload,
`IsRecipientReady` callback. In tdns-transport.

### Step 2: Create generic TransportManager — DONE

`transport/manager.go` in tdns-transport. Orchestration
only, not per-packet.

### Step 3: RouteToCallback middleware — DONE

Added alongside existing RouteToMsgHandler. Lab-tested:
incoming messages fan out directly, no IncomingChan
bottleneck.

### Step 4a-f: Refactor tdns to use generic TM — DONE

- 4a: Local TM embeds `*transport.TransportManager`
- 4b: Construction creates generic TM inside wrapper
- 4c: RouteToCallback replaces IncomingChan goroutine
  (lab-tested: all message types work)
- 4d+4e+4f: Enqueue/StartReliableQueue use generic RMQ,
  local reliable_message_queue.go deleted

### Step 4g: Delete wrapper — IN PROGRESS

The local `TransportManager` in hsync_transport.go is a
temporary wrapper embedding `*transport.TransportManager`.
It must be replaced with an `MPTransportBridge` struct
that aggregates MP-specific state and methods.

**Caller analysis** (28 files reference TransportManager):
- 19 files access only generic fields (Router, PeerRegistry,
  DNSTransport) — change to `*transport.TransportManager`,
  zero method changes needed
- 9 files call MP methods — change to MPTransportBridge

**The 9 files calling MP methods:**
- agent_utils.go
- apihandler_agent.go
- apihandler_agent_distrib.go
- hsync_beat.go
- hsync_hello.go
- hsync_infra_beat.go
- hsync_transport.go
- hsyncengine.go
- main_initfuncs.go

**Sub-steps:**

4g.1: Create `MPTransportBridge` struct in
hsync_transport.go. Holds MP state (agentRegistry,
msgQs, combinerID, signerID, pendingDnskeyPropagations,
authorizedPeers, messageRetention, getImrEngine,
keystateRfiState) and a `*transport.TransportManager`
reference.

4g.2: Move all MP methods from the local TransportManager
wrapper to MPTransportBridge. The methods keep the same
names and signatures — only the receiver type changes.

4g.3: Add `MPTransport *MPTransportBridge` field to
`InternalMpConf` in config.go.

4g.4: Change `Config.Internal.TransportManager` type
from `*TransportManager` (local wrapper) to
`*transport.TransportManager` (generic).

4g.5: Update the 9 MP caller files:
`conf.Internal.TransportManager.SomeMP()` →
`conf.Internal.MPTransport.SomeMP()`

The 19 files accessing only generic fields (Router,
PeerRegistry, DNSTransport) need no changes — these
fields exist on `*transport.TransportManager`.

4g.6: Delete the local `TransportManager` type and
`NewTransportManager` constructor. Update
main_initfuncs.go to create `*transport.TransportManager`
directly and populate `MPTransportBridge` separately.

4g.7: Build all 6 tdns binaries + tdns-mp binaries.
Lab test.

### Step 5: Verify end-to-end

- tdns-transport/v2: builds, tests pass, exercise binary
  updated and passes
- tdns/cmdv2: all 6 binaries build
- tdns-mp: mpsigner + mpcli build
- Deploy to lab: full multi-provider scenario works
  (agent<->combiner<->signer communication, gossip,
  DNSKEY propagation, reliable delivery with confirmation)

### Step 5: Verify end-to-end

- tdns-transport/v2: builds, tests pass, exercise binary
  updated and passes
- tdns/cmdv2: all 6 binaries build
- Deploy to lab: full multi-provider scenario works
  (agent<->combiner<->signer communication, gossip,
  DNSKEY propagation, reliable delivery with confirmation)

## Critical Files

**tdns-transport** (done):
- `v2/transport/manager.go` — generic TransportManager
- `v2/transport/reliable_message_queue.go` — generic RMQ
- `v2/transport/handlers.go` — RouteToCallback middleware

**tdns** (steps 4a-f done, 4g in progress):
- `v2/hsync_transport.go` — local TM wrapper (to be
  replaced by MPTransportBridge in 4g)
- `v2/main_initfuncs.go` — creates TM, registers handlers
- `v2/config.go` — TransportManager type changes in 4g

**PeerRegistry**: stays generic in tdns-transport.
Agent→Peer conversion, HSYNC authorization, agent
discovery are application logic in tdns.

## Complexity Assessment (for remaining step 4g)

### Scope

| Metric | Count |
|---|---|
| Files accessing generic TM fields only | 19 (no changes) |
| Files calling MP methods | 9 (update callers) |
| MP state fields to move | ~10 |
| MP methods to move | ~37 |
| New struct | MPTransportBridge |
| New config field | InternalMpConf.MPTransport |

### Risk: LOW

The wrapper already works. 4g is a mechanical rename:
- Move MP state/methods from local TM to MPTransportBridge
- Change config type
- Update 9 files' MP method calls

No logic changes. No threading changes. No new behavior.
Build after each sub-step. Lab test at the end.

## Verification

1. `cd tdns-transport/v2 && go build ./... && go test ./...`
2. `go run ./cmd/transport-exercise` — updated for new API
3. `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make` — all 6
4. Deploy to lab, run multi-provider test
5. Verify: beats flow, syncs delivered+confirmed, gossip
   converges, DNSKEY propagation works
