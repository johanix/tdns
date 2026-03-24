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

### Step 1: Move RMQ to tdns-transport

- Copy reliable_message_queue.go to
  tdns-transport/v2/transport/
- Change package to `transport`
- Replace AgentRegistry with IsRecipientReady callback
- Genericize OutgoingMessage (remove MP-specific fields)
- Add DeliveryPolicy enum
- Update tdns to import RMQ from tdns-transport
- Verify tdns builds

### Step 2: Create generic TransportManager

- New file: tdns-transport/v2/transport/manager.go
- TransportManagerConfig with all callbacks
- Constructor creates transports, PeerRegistry, Router,
  ChunkHandler, RMQ — wires them together
- SelectTransport, SendPing
- RegisterChunkNotifyHandler with registration callback
- Enqueue wraps RMQ
- Verify tdns-transport builds

### Step 3: Replace IncomingChan with callback middleware

The current flow: handlers store IncomingMessage in
ctx.Data, then RouteToMsgHandler middleware pushes to
a single IncomingChan. The application reads IncomingChan
in one goroutine and re-dispatches by type.

The fix: add RouteToCallback middleware that takes a
func(*IncomingMessage) instead of a channel. The
application provides the callback, which does per-type
fan-out directly (push to typed channels).

Concrete changes:
- Add RouteToCallback(fn func(*IncomingMessage))
  MiddlewareFunc alongside existing RouteToMsgHandler
- Keep RouteToMsgHandler for backwards compatibility
- Remove IncomingChan from RouterConfig (application
  uses RouteToCallback instead)
- ChunkNotifyHandler.IncomingChan becomes optional
  (nil if application uses callback pattern)
- Handlers (HandleBeat, HandleSync etc.) stay unchanged —
  they parse and store in ctx.Data, middleware routes
- Verify tdns-transport builds + exercise binary

### Step 4: Refactor tdns to use generic TM

Migration strategy: **temporary wrapper** (option b).
The local TransportManager becomes a wrapper that embeds
the generic `*transport.TransportManager`. Callers are
migrated one by one. Wrapper is deleted when done.

Caller analysis (28 files reference TransportManager):
- 12 access `.Router` (field)
- 8 access `.PeerRegistry` (field)
- 4 access `.DNSTransport` (field)
- 3 call `.SendBeatWithFallback` (MP method)
- 3 call `.SendPing` (generic method)
- 3 call `.SendSyncWithFallback` (generic method)
- 3 call `.SyncPeerFromAgent` (MP method)
- 3 call `.IsPeerAuthorized` (MP method)
- 3 call `.StartIncomingMessageRouter` (MP method)
- 2 call `.DiscoverAndRegisterAgent` (MP method)
- Other methods: 1-2 callers each

#### Sub-step 4a: Create wrapper

In `hsync_transport.go`, restructure TransportManager
to embed the generic TM:

```go
type TransportManager struct {
    *transport.TransportManager // generic (fields promoted)
    // MP-specific state
    agentRegistry *AgentRegistry
    msgQs         *MsgQs
    combinerID    AgentId
    signerID      string
    signerAddress string
    // ... other MP fields
}
```

Because embedding promotes fields, existing callers
that access `tm.Router`, `tm.PeerRegistry`, `tm.DNSTransport`
continue to work without changes — they resolve to
the embedded generic TM's fields.

`Config.Internal.TransportManager` type unchanged
(still `*TransportManager`, the local type).

**Checkpoint**: all 6 binaries build.

#### Sub-step 4b: Migrate construction

In `main_initfuncs.go`, change NewTransportManager calls
to create the generic TM inside the wrapper:

```go
genericTM := transport.NewTransportManager(
    &transport.TransportManagerConfig{
        LocalID:     identity,
        ControlZone: controlZone,
        // ... transport config
        IsPeerAuthorized: func(s, z string) (bool, string) {
            return mpTM.IsPeerAuthorized(s, z)
        },
        IsRecipientReady: func(id string) bool {
            return mpTM.isRecipientReady(id)
        },
        // ... other callbacks
    })

mpTM := &TransportManager{
    TransportManager: genericTM,
    agentRegistry:    agentRegistry,
    msgQs:            msgQs,
    combinerID:       combinerID,
    // ...
}
conf.Internal.TransportManager = mpTM
```

Three construction sites: agent (line ~352), signer
(line ~432), combiner (line ~578).

**Checkpoint**: all 6 binaries build.

#### Sub-step 4c: Switch to RouteToCallback

Replace `StartIncomingMessageRouter` (which reads
IncomingChan and re-dispatches by type in one goroutine)
with Router handler registration + RouteToCallback.

The ~548 lines of route* methods become registration
functions that register Router handlers. Each handler
pushes to the appropriate MsgQs channel:

```go
func (tm *TransportManager) registerMPHandlers() {
    tm.Router.Use(transport.RouteToCallback(
        func(msg *transport.IncomingMessage) {
            tm.routeToTypedChannel(msg)
        }))
}

func (tm *TransportManager) routeToTypedChannel(
    msg *transport.IncomingMessage) {
    switch msg.Type {
    case "beat":
        // parse + push to msgQs.Beat
    case "sync", "update":
        // parse + push to msgQs.Msg
    case "hello":
        // parse + push to msgQs.Hello
    // etc.
    }
}
```

Note: routeToTypedChannel does the SAME dispatch as
the current routeIncomingMessage — the logic doesn't
change, only the entry point (callback vs goroutine
reading IncomingChan).

**Checkpoint**: all 6 binaries build + lab test.
This is the highest-risk sub-step (threading change).

#### Sub-step 4d: Switch Enqueue methods

Replace EnqueueForCombiner/Agent/SpecificAgent with
calls to the generic TM's Enqueue:

```go
func (tm *TransportManager) EnqueueForCombiner(
    zone ZoneName, update *ZoneUpdate, distID string,
) (string, error) {
    msg := &transport.OutgoingMessage{
        RecipientID:    string(tm.combinerID),
        Zone:           string(zone),
        Payload:        update, // interface{}
        Priority:       transport.PriorityHigh,
        DistributionID: distID,
    }
    return "", tm.TransportManager.Enqueue(msg)
}
```

These remain as convenience methods on the local TM
for now. Callers (5 files) don't change.

**Checkpoint**: all 6 binaries build.

#### Sub-step 4e: Switch reliable queue startup

Replace StartReliableQueue to use generic TM's method:

```go
func (tm *TransportManager) StartReliableQueue(
    ctx context.Context) {
    tm.TransportManager.StartReliableQueue(ctx,
        func(ctx context.Context,
            msg *transport.OutgoingMessage) error {
            return tm.deliverMessage(ctx, msg)
        })
}
```

The deliverMessage sendFunc stays as MP code — it does
the combiner/agent dispatch and transport selection.

**Checkpoint**: all 6 binaries build.

#### Sub-step 4f: Delete local RMQ

Remove reliable_message_queue.go from tdns (now
imported from tdns-transport). Remove local type
definitions (MessageState, OutgoingMessage, etc.)
that are now in transport package.

**Checkpoint**: all 6 binaries build.

#### Sub-step 4g: Delete wrapper (deferred)

Once all MP methods are converted to standalone
functions or are clearly MP-only (not called via
the generic TM interface):
- Change Config.Internal.TransportManager type to
  *transport.TransportManager
- Move MP state to a separate MPTransportBridge struct
- Update all 28 caller files
- Delete local TransportManager type

This can be deferred to a later session — the wrapper
is functional and doesn't block anything.

### Step 5: Verify end-to-end

- tdns-transport/v2: builds, tests pass, exercise binary
  updated and passes
- tdns/cmdv2: all 6 binaries build
- Deploy to lab: full multi-provider scenario works
  (agent<->combiner<->signer communication, gossip,
  DNSKEY propagation, reliable delivery with confirmation)

## Critical Files

**tdns-transport** (new/modified):
- `v2/transport/manager.go` — NEW: generic TransportManager
- `v2/transport/reliable_message_queue.go` — MOVED+refactored
- `v2/transport/chunk_notify_handler.go` — remove IncomingChan
- `v2/transport/handler.go` — handlers become optional/removed
- `v2/cmd/transport-exercise/main.go` — update for new API

**tdns** (modified):
- `v2/hsync_transport.go` — MP wiring uses generic TM
- `v2/main_initfuncs.go` — creates generic TM, registers
  MP handlers on Router, provides callbacks
- `v2/config.go` — TransportManager type changes to
  *transport.TransportManager

## Open Question: PeerRegistry

PeerRegistry is currently in tdns-transport and is generic.
MP code adds layers on top:
- Agent -> Peer conversion (SyncPeerFromAgent)
- HSYNC-based authorization (isInHSYNC)
- Agent discovery (DiscoverAndRegisterAgent)

**Decision**: all of this is application logic, stays in
tdns. PeerRegistry provides generic CRUD. Application
populates it with discovered/configured peers.

## Complexity Assessment

### Scope by numbers

| Metric | Count |
|---|---|
| hsync_transport.go (TM + MP wiring) | 2229 lines |
| reliable_message_queue.go | 559 lines |
| Files referencing TransportManager | 28 |
| Files referencing MsgQs | 10 |
| Files referencing Enqueue* methods | 5 |
| Files referencing Send*WithFallback | 11 |
| Files referencing IncomingChan | 3 |
| TM initialization code in main_initfuncs | ~109 lines |
| route* methods (MP dispatch) | ~548 lines |
| Existing tdns-transport infrastructure | 2513 lines |

### What changes where

**tdns-transport** (new code):
- `transport/manager.go` — NEW, ~200-300 lines. Generic TM
  struct, constructor, SelectTransport, Enqueue,
  RegisterChunkNotifyHandler, StartReliableQueue. This is
  new code but straightforward — it wires existing
  components that are already in the package.
- `transport/reliable_message_queue.go` — MOVED from tdns,
  ~559 lines. Needs genericizing: replace AgentRegistry
  with callback, genericize OutgoingMessage. ~50-100 lines
  of actual changes within the file.
- `transport/chunk_notify_handler.go` — MODIFY, remove
  IncomingChan (~20 lines). Handlers push directly to
  Router instead of channel.
- `transport/handler.go` + `transport/handlers.go` — MODIFY.
  Default handlers may be removed or made optional. The
  application registers its own. ~100 lines affected.

Estimated new/changed in tdns-transport: **~500-700 lines**

**tdns** (refactored code):
- `hsync_transport.go` — HEAVY REFACTOR. Currently 2229
  lines. The ~8 generic methods move to tdns-transport.
  The ~548 lines of route* methods stay but are rewritten
  as Router handler registrations. The ~37 MP-specific
  methods stay. Net effect: file shrinks significantly
  (~800-1000 lines removed, ~200 lines rewritten).
- `main_initfuncs.go` — MODERATE. ~109 lines of TM setup
  rewritten to create generic TM + register MP handlers.
  Same amount of code, different structure.
- `config.go` — SMALL. TransportManager type changes,
  MsgQs struct eventually replaced. ~20 lines.
- 25 other files — SMALL each. Import path changes,
  possibly method call adjustments. ~1-5 lines per file.

Estimated changed in tdns: **~1200-1500 lines**

**Total estimated change**: ~1700-2200 lines across both
repos.

### Overall complexity: MEDIUM-HIGH

The refactoring is significant but well-bounded:
- The generic TM is small (just orchestration)
- RMQ genericization is mechanical (replace types)
- The route* methods → Router handlers is a rewrite but
  the logic doesn't change, only where it lives
- The 28 files referencing TM mostly need minor updates

### Risk Analysis

**High risk:**
- **IncomingChan removal (Step 3)** — this changes the
  threading model. Today all incoming messages serialize
  through one goroutine. After: each handler runs in the
  DNS server goroutine and pushes to its own channel.
  Risk: handlers must be non-blocking (channel push only).
  If a channel is full, the handler blocks the DNS server.
  Mitigation: buffered channels + log warnings on near-full.

- **RMQ genericization (Step 1)** — the current RMQ has
  tight coupling to AgentRegistry for isRecipientReady.
  The callback replacement must preserve the exact same
  readiness semantics or messages may be sent to peers
  that aren't ready.
  Mitigation: the callback returns bool, same as today.
  Test with lab deployment.

**Medium risk:**
- **MsgQs removal** — 10 files reference MsgQs. Each
  consumer (HsyncEngine, CombinerMsgHandler, etc.) needs
  to accept channels as parameters instead of reading
  from a global struct.
  Mitigation: straightforward refactor, one consumer at a
  time.

- **Confirmation flow** — today, confirmations arrive via
  IncomingChan and are routed through routeSyncMessage to
  RMQ.MarkConfirmed. After the change, the Router handler
  for "confirm" must call RMQ.MarkConfirmed directly. The
  path changes but the logic is the same.
  Mitigation: trace the confirmation flow carefully.

**Low risk:**
- **Generic TM creation (Step 2)** — new code, no existing
  behavior to break. Just wires existing components.

- **Import path changes** — mechanical, compiler-driven.

- **main_initfuncs.go rewrite** — same logic, different
  structure. The TM config fields map 1:1 to the new
  callbacks.

### Risk mitigation strategy

1. **Step-by-step with builds after each step.** Never
   change more than one concept at a time.
2. **Step 1 (RMQ) is the safest start** — move + genericize
   one file, verify build.
3. **Step 3 (IncomingChan removal) is the riskiest** — do
   this last, after TM and RMQ are working. Can be deferred
   if it causes problems (keep IncomingChan as temporary
   bridge).
4. **Lab test after Step 4** — full multi-provider scenario
   before declaring success.
5. **Fallback**: the tdns monolith on the `repo-split-phase0-1`
   branch still builds and runs. If the refactoring goes
   sideways, revert to that.

## Verification

1. `cd tdns-transport/v2 && go build ./... && go test ./...`
2. `go run ./cmd/transport-exercise` — updated for new API
3. `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make` — all 6
4. Deploy to lab, run multi-provider test
5. Verify: beats flow, syncs delivered+confirmed, gossip
   converges, DNSKEY propagation works
