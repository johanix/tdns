# Plan: API Transport Support for PING, HELLO, and BEAT

## Context

PING, HELLO, and BEAT are the three "lifecycle" messages — they establish identity, maintain liveness, and probe connectivity. Getting these right over API is the foundation for all other message types (SYNC, UPDATE, KEYSTATE, EDITS, RFI, CONFIG).

### Current State

| Message | Client (sending) | Server (receiving) | Dispatch | Status |
|---------|------------------|--------------------|----------|--------|
| HELLO | `APITransport.Hello()` works | `APIhello()` at `/hello` works | `SendHello()` tries both transports | Agent↔agent works. No combiner/signer endpoint. |
| BEAT | `APITransport.Beat()` works | `APIbeat()` at `/beat` works | `SendBeatWithFallback()` tries both | Agent↔agent works. No combiner/signer endpoint. |
| PING | `APITransport.Ping()` works | **Wrong handler** — `/ping` on sync router is the management health-check (`APIping` in `api_utils.go`), not HSYNC peer ping | `SendPing()` prefers DNS, API fallback hits wrong handler | Broken over API. No combiner/signer endpoint. |

### Design Decisions

**All peer relationships follow the same lifecycle**: Hello → Beat → OPERATIONAL. This applies to agent↔agent, agent↔combiner, and agent↔signer. The symmetry means one state machine to reason about, one place to look when a connection is degraded.

**Beat frequency to signer/combiner is lower**: Agent↔agent beats run every 30–60 seconds (existing `agent.remote.beat_interval`). Agent↔combiner and agent↔signer beats run every 10 minutes by default. This is configurable. The lower frequency reflects that signer and combiner are local-infrastructure peers (discovered via config, not DNS) where liveness failures are also detected on the next UPDATE or KEYSTATE attempt. The main value of the beat to these peers is the `SupportedMsgTypes` capability exchange and the state machine progression to OPERATIONAL — not sub-minute liveness detection.

**Connection to signer/combiner does not reach OPERATIONAL until a successful beat**. This makes the semantics uniform and ensures capability information has been exchanged before the connection is considered fully established.

### Root Causes

1. **No HSYNC peer ping handler**: The sync API router (`SetupAgentSyncRouter` in `apirouters.go:270`) registers the management `APIping()` on `/ping`. This handler returns boot time, version, pong counter — it doesn't echo nonces or route to `MsgQs.Ping`. The management ping must stay (it serves a different purpose), but the sync router needs a separate HSYNC peer ping at a different path.

2. **No combiner/signer sync API server**: Only agents call `SetupAgentSyncRouter()`. Combiners and signers only run the management API (`SetupAPIRouter()` with API key auth). Agents cannot send HELLO, BEAT, or PING to combiner/signer over API.

3. **No periodic beats to signer/combiner**: `HsyncEngine` and `hsync_beat.go` currently only send beats to agent peers. Combiner and signer are not in the beat loop. After this change, a separate low-frequency beat loop covers them.

4. **Missing HELLO in combiner/signer DNS routers**: `InitializeCombinerRouter()` and `InitializeSignerRouter()` in `router_init.go` don't register a Hello handler. Even over DNS, combiner/signer cannot receive Hello.

5. **No peer stats for API messages**: API handlers don't update `PeerRegistry` statistics, making API peers invisible in diagnostics.

## Implementation Plan

### Step 0: Beat Carries Supported Message Types

**Motivation**: As API transport support is built incrementally, it becomes hard to track which message types each peer supports on each transport. A beat arriving over DNS implicitly tells us what the peer's DNS transport supports; a beat arriving over API tells us what the peer's API transport supports. By including the list of registered message types in each beat, peers can advertise their capabilities per-transport automatically.

**Design**: Each beat includes a `SupportedMsgTypes []string` field listing the message types the sender handles on the transport carrying the beat. The data source differs by transport:

- **DNS transport**: Extract from `DNSMessageRouter.List()` which returns `map[MessageType][]*HandlerRegistration` — the keys are the registered message types. Already available.
- **API transport**: Maintain a `[]string` list of registered sync API endpoints. Built at `SetupAgentSyncRouter` / `SetupCombinerSyncRouter` / `SetupSignerSyncRouter` time.

The receiver stores the list per-transport on the `Agent` struct (in `ApiDetails.SupportedMsgTypes` and `DnsDetails.SupportedMsgTypes`). The CLI `agent debug show agents` displays it.

**0a. Add field to transport-layer types** (`agent/transport/transport.go`):

```go
type BeatRequest struct {
    SenderID          string
    Timestamp         time.Time
    Sequence          uint64
    State             string
    SupportedMsgTypes []string  // NEW: message types supported on this transport
}

type BeatResponse struct {
    ResponderID       string
    Timestamp         time.Time
    Sequence          uint64
    State             string
    Ack               bool
    SupportedMsgTypes []string  // NEW: responder's supported types on this transport
}
```

**0b. Add field to serialization types**:

DNS payload (`agent/transport/dns.go`):
```go
type DnsBeatPayload struct {
    // ... existing fields ...
    SupportedMsgTypes []string `json:"SupportedMsgTypes,omitempty"` // NEW
}
```

API request/response (`agent/transport/api.go`):
```go
type apiBeatRequest struct {
    // ... existing fields ...
    SupportedMsgTypes []string `json:"supported_msg_types,omitempty"` // NEW
}

type apiBeatResponse struct {
    // ... existing fields ...
    SupportedMsgTypes []string `json:"supported_msg_types,omitempty"` // NEW
}
```

Agent-level post/response (`agent_structs.go`):
```go
type AgentBeatPost struct {
    // ... existing fields ...
    SupportedMsgTypes []string // NEW
}

type AgentBeatResponse struct {
    // ... existing fields ...
    SupportedMsgTypes []string // NEW
}
```

**0c. Populate at send time**:

In `SendBeatWithFallback()` (`hsync_transport.go`), before calling each transport's `Beat()`:
- For DNS: `req.SupportedMsgTypes = tm.GetDNSSupportedMsgTypes()` — extracts keys from `tm.Router.List()`
- For API: `req.SupportedMsgTypes = tm.GetAPISupportedMsgTypes()` — returns the maintained API endpoint list

Add two helper methods on `TransportManager`:
```go
func (tm *TransportManager) GetDNSSupportedMsgTypes() []string {
    if tm.Router == nil { return nil }
    var types []string
    for msgType := range tm.Router.List() {
        types = append(types, string(msgType))
    }
    sort.Strings(types)
    return types
}

func (tm *TransportManager) GetAPISupportedMsgTypes() []string {
    return tm.apiSupportedMsgTypes  // set during sync router setup
}
```

**0d. Store at receive time**:

In `APIbeat()` handler (`apihandler_agent.go`): pass `SupportedMsgTypes` through `AgentMsgReport` to the beat processor.

In the beat processor (`hsyncengine.go` or `hsync_transport.go`): store on the `Agent` struct:
```go
// When beat arrives over API:
agent.ApiDetails.SupportedMsgTypes = report.SupportedMsgTypes
// When beat arrives over DNS:
agent.DnsDetails.SupportedMsgTypes = report.SupportedMsgTypes
```

**0e. Add field to `AgentDetails`** (`agent_structs.go` or wherever `AgentDetails` is defined):

```go
type AgentDetails struct {
    // ... existing fields ...
    SupportedMsgTypes []string  // NEW: message types peer supports on this transport
}
```

**0f. Display in CLI**:

In the `agent debug show agents` output, add a line per transport showing supported message types:
```
  API: OPERATIONAL [hello, beat, ping]
  DNS: OPERATIONAL [hello, beat, ping, sync, confirm, keystate, edits, rfi, update]
```

**0g. Beat response also carries capabilities**:

The `APIbeat()` handler populates `SupportedMsgTypes` in the response with the local node's supported types for the transport the beat arrived on. Same for the DNS beat handler's confirmation payload. This way both sides learn each other's capabilities in a single beat exchange.

**Files**:
- `agent/transport/transport.go` — add `SupportedMsgTypes` to `BeatRequest`, `BeatResponse`
- `agent/transport/dns.go` — add to `DnsBeatPayload`
- `agent/transport/api.go` — add to `apiBeatRequest`, `apiBeatResponse`; populate in `Beat()` method
- `agent_structs.go` — add to `AgentBeatPost`, `AgentBeatResponse`, `AgentDetails`
- `hsync_transport.go` — add `GetDNSSupportedMsgTypes()`, `GetAPISupportedMsgTypes()`; populate `req.SupportedMsgTypes` in `SendBeatWithFallback()`; store on `Agent` when beat received
- `apihandler_agent.go` — pass `SupportedMsgTypes` through in `APIbeat()` handler and response
- `agent/transport/handlers.go` — include `SupportedMsgTypes` in DNS beat confirmation payload
- CLI display code (likely in `cli/` or `agent_debug_cmds.go`)

### Step 1: HSYNC Peer Ping Handler

**Problem**: The sync API router's `/ping` endpoint points to the management health-check handler (`APIping` in `api_utils.go:35-77`). This handler is needed and must stay — but the sync router also needs a proper HSYNC peer ping that echoes nonces and routes to `MsgQs.Ping`.

**Fix**: Add a new `APIsyncPing()` handler and register it on a separate path (`/sync/ping`) on the sync router. The management `/ping` stays untouched.

**1a. New handler in `apihandler_agent.go`**:

```go
func (conf *Config) APIsyncPing() func(w http.ResponseWriter, r *http.Request) {
    return func(w http.ResponseWriter, r *http.Request) {
        // Decode AgentPingPost (MessageType, MyIdentity, YourIdentity, Nonce, Timestamp)
        // Echo nonce back in AgentPingResponse
        // Route to MsgQs.Ping with Transport: "API"
    }
}
```

The handler mirrors DNS `HandlePing` (`handlers.go:65-120`): validate nonce is non-empty, echo it back, set `Transport: "API"` in the report.

**1b. New request/response types in `agent_structs.go`**:

```go
type AgentPingPost struct {
    MessageType  AgentMsg
    MyIdentity   AgentId
    YourIdentity AgentId
    Nonce        string
    Timestamp    time.Time
}

type AgentPingResponse struct {
    Status       string
    MyIdentity   AgentId
    YourIdentity AgentId
    Nonce        string    // echoed
    Time         time.Time
    Msg          string
    Error        bool
    ErrorMsg     string
}
```

**1c. Register in `SetupAgentSyncRouter()` (`apirouters.go`)**:

```go
// Existing management ping stays:
secureRouter.HandleFunc("/ping", APIping(conf)).Methods("POST")
// Add HSYNC peer ping on separate path:
secureRouter.HandleFunc("/sync/ping", conf.APIsyncPing()).Methods("POST")
```

**1d. Update `APITransport.Ping()` endpoint** (`api.go`):

Change the ping URL from `/ping` to `/sync/ping` so the client hits the HSYNC handler, not the management health-check.

**1e. Update `SendPing()` dispatch** (`hsync_transport.go:1214-1229`):

Remove the DNS-preference bias. Current code has comment "Prefer DNS for ping (API transport returns 'not implemented')". After this fix, the API transport does implement peer ping, so use the same transport selection logic as Hello/Beat.

**Files**:
- `apihandler_agent.go` — add `APIsyncPing()` function
- `agent_structs.go` — add `AgentPingPost` and `AgentPingResponse` structs
- `apirouters.go:270` — add `/sync/ping` endpoint (keep `/ping` as management)
- `agent/transport/api.go` — change `Ping()` URL from `/ping` to `/sync/ping`
- `hsync_transport.go` — update `SendPing()` comment and dispatch logic

### Step 2: Combiner Sync API Router

**Problem**: Only agents call `SetupAgentSyncRouter()`. Combiners use `SetupAPIRouter()` which only has management endpoints (with API key auth via `X-API-Key` header). Agents cannot send BEAT, HELLO, or PING to the combiner over API.

**Current config state**:
- `LocalCombinerConf` (`config.go:101-128`) has: `Identity`, `LongTermJosePrivKey`, `ChunkMode`, `ChunkQueryEndpoint`, `ChunkMaxSize`, `Agents`, `Signature`, `ProtectedNamespaces`, `ProviderZones`
- **No API listen addresses or TLS cert fields** — only DNS chunk config exists
- The management API (`ApiServerConf`) has `Combiner ApiServerAppConf` with `Addresses` and `ApiKey`, but these serve the management API (key-authenticated, not cert-authenticated)

**2a. Add API sync config to `LocalCombinerConf`** (`config.go`):

```go
Api struct {
    Addresses struct {
        Listen []string
    }
    CertFile string `yaml:"cert_file" mapstructure:"cert_file"`
    KeyFile  string `yaml:"key_file" mapstructure:"key_file"`
} `yaml:"api"`
```

**2b. Add `conf.LocalIdentity()` method** (`config.go`):

`APIhello()` and `APIbeat()` reference `conf.Agent.Identity` directly. For the combiner, identity is `conf.Combiner.Identity`. For the signer, it's `conf.MultiProvider.Identity`.

```go
func (conf *Config) LocalIdentity() string {
    switch Globals.App.Type {
    case AppTypeAgent:
        if conf.Agent != nil {
            return conf.Agent.Identity
        }
    case AppTypeCombiner:
        if conf.Combiner != nil {
            return conf.Combiner.Identity
        }
    default:
        if conf.MultiProvider.Identity != "" {
            return conf.MultiProvider.Identity
        }
    }
    return ""
}
```

Then update `APIhello()` and `APIbeat()` to use `conf.LocalIdentity()` instead of `conf.Agent.Identity`.

**2c. Add `SetupCombinerSyncRouter()` in `apirouters.go`**:

Runs on a dedicated HTTPS port (separate from management API), same pattern as `SetupAgentSyncRouter()`:

- `/hello` — reuse `APIhello()` (handler uses `conf.LocalIdentity()`)
- `/beat` — reuse `APIbeat()` (handler uses `conf.LocalIdentity()`)
- `/ping` — management ping (for health checks)
- `/sync/ping` — HSYNC peer ping (from Step 1)
- `/msg` — reuse `APImsg()` (handles SYNC, UPDATE, RFI, STATUS)

Same TLS client-cert middleware as `SetupAgentSyncRouter()` — requires valid client cert verified against agent's TLSA record in `AgentRegistry`.

**2d. Startup integration in `main_initfuncs.go`**:

In the combiner startup section, after TransportManager is initialized:

```go
combinerSyncRtr, err := conf.SetupCombinerSyncRouter(ctx)
// ...
APIdispatcherNG(conf, combinerSyncRtr,
    conf.Combiner.Api.Addresses.Listen,
    conf.Combiner.Api.CertFile,
    conf.Combiner.Api.KeyFile,
    conf.Internal.APIStopCh)
```

**Files**:
- `config.go` — add `Api` block to `LocalCombinerConf`, add `LocalIdentity()` method
- `apirouters.go` — add `SetupCombinerSyncRouter()`
- `apihandler_agent.go` — update `APIhello()` and `APIbeat()` to use `conf.LocalIdentity()`
- `main_initfuncs.go` — start combiner sync API dispatcher

### Step 3: Signer Sync API Router

**Problem**: Same as combiner — signer has no sync API endpoints.

**Current config state**:
- `MultiProviderConf` (`config.go:152-171`) has: `Active`, `Identity`, `HsyncIdentity`, `LongTermJosePrivKey`, `ChunkMode`, `ChunkMaxSize`, `Agents`
- **No API listen addresses or TLS cert fields**

**3a. Add API sync config to `MultiProviderConf`** (`config.go`):

```go
Api struct {
    Addresses struct {
        Listen []string
    }
    CertFile string `yaml:"cert_file" mapstructure:"cert_file"`
    KeyFile  string `yaml:"key_file" mapstructure:"key_file"`
} `yaml:"api"`
```

**3b. Add `SetupSignerSyncRouter()` in `apirouters.go`**:

Same pattern as combiner, registers:
- `/hello` — reuse `APIhello()` (uses `conf.LocalIdentity()` → `conf.MultiProvider.Identity`)
- `/beat` — reuse `APIbeat()`
- `/ping` — management ping
- `/sync/ping` — HSYNC peer ping
- `/msg` — reuse `APImsg()` (for RFI KEYSTATE)

**3c. Startup integration**:

In the signer startup path in `main_initfuncs.go` (search for `AppTypeAuth` or `MultiProvider`), add sync API router setup.

**Files**:
- `config.go` — add `Api` block to `MultiProviderConf`
- `apirouters.go` — add `SetupSignerSyncRouter()`
- `main_initfuncs.go` — start signer sync API dispatcher

### Step 4: Register HELLO in Combiner/Signer DNS Routers

**Problem**: `InitializeCombinerRouter()` (`router_init.go:271`) registers: Ping, Beat, RFI, Update — **no Hello**. `InitializeSignerRouter()` (`router_init.go:396`) registers: Ping, Beat, Keystate, RFI — **no Hello**.

This means even over DNS, a combiner/signer cannot receive a Hello from an agent. The Hello handshake only works agent↔agent.

**Fix**: Add Hello handler registration to both routers:

```go
// In InitializeCombinerRouter, after Beat handler:
if err := router.Register(
    "HelloHandler",
    MessageType("hello"),
    HandleHello,
    WithPriority(100),
    WithDescription("Processes Hello messages from agents"),
); err != nil {
    return err
}
```

Same for `InitializeSignerRouter`.

**Files**:
- `agent/transport/router_init.go` — add Hello to both `InitializeCombinerRouter()` and `InitializeSignerRouter()`

### Step 5: Peer Stats for API-Received Messages

**Problem**: DNS messages go through `StatsMiddleware` which updates `PeerRegistry` counters (sent/received by type, LastUsed). API handlers (`APIhello`, `APIbeat`, `APIsyncPing`) don't update any stats. API peers are invisible in diagnostics.

**Fix**: After routing to MsgQs in each API handler, update peer stats via the `PeerRegistry`:

```go
// After successful MsgQs routing in APIhello/APIbeat/APIsyncPing:
if tm := conf.Internal.TransportManager; tm != nil && tm.PeerRegistry != nil {
    if peer, ok := tm.PeerRegistry.Get(senderID); ok {
        peer.Stats.RecordReceived("hello")  // or "beat", "ping"
    }
}
```

Check `stats_middleware.go` for the exact stats update pattern — `MessageStats` may use different field names or methods.

**Files**:
- `apihandler_agent.go` — add stats updates to `APIhello()`, `APIbeat()`, and new `APIsyncPing()`
- `agent/transport/stats_middleware.go` — reference for stats update pattern

### Step 6: Periodic Beat Loop to Signer and Combiner

**Problem**: `HsyncEngine` and `hsync_beat.go` only beat agent peers. Signer and combiner never receive beats, never reach OPERATIONAL state from the agent's perspective, and never exchange `SupportedMsgTypes`.

**Design**: A separate low-frequency beat loop for infrastructure peers (signer and combiner). Runs independently of the agent↔agent beat loop so the frequencies can differ. The same `SendBeatWithFallback()` function is used — no new send logic needed.

**Beat interval**: Configurable, defaulting to 10 minutes. Add to config:

```yaml
# In agent config:
combiner:
  beat_interval: 600   # seconds, default 600 (10 min)

signer:
  beat_interval: 600   # seconds, default 600 (10 min)
```

Config fields added to `PeerConf` (already used for `agent.combiner` and `agent.signer` peer config in `LocalAgentConf`):

```go
type PeerConf struct {
    // ... existing fields ...
    BeatInterval int `yaml:"beat_interval" mapstructure:"beat_interval"` // seconds; 0 = default (600)
}
```

**6a. Add beat loop for combiner** in `hsync_beat.go` (or a new `hsync_infra_beat.go`):

```go
func (tm *TransportManager) StartInfraBeatLoop(ctx context.Context) {
    // One ticker per infrastructure peer (combiner, signer)
    // Uses PeerConf.BeatInterval, defaulting to 600s
    // Calls SendHello if not yet INTRODUCED, SendBeatWithFallback if INTRODUCED or OPERATIONAL
    // Updates Agent state to OPERATIONAL after first successful beat
}
```

The loop follows the same Hello-first pattern as the agent beat loop: if the peer is in state KNOWN, send Hello first; if INTRODUCED or OPERATIONAL, send Beat.

**6b. State machine for signer/combiner**:

These peers are pre-registered at startup (from config, not discovered via DNS). Initial state: KNOWN. After successful Hello: INTRODUCED. After first successful Beat: OPERATIONAL.

The existing `Agent` struct and `AgentDetails`/`AgentState` machinery is reused. The signer and combiner are already stored in `AgentRegistry` — this just adds them to the beat loop.

**6c. Startup wiring in `main_initfuncs.go`**:

```go
// After TransportManager is initialized, alongside existing HsyncEngine startup:
startEngineNoError(&Globals.App, "InfraBeatLoop", func() {
    conf.Internal.TransportManager.StartInfraBeatLoop(ctx)
})
```

**Files**:
- `config.go` — add `BeatInterval int` to `PeerConf`
- `hsync_beat.go` (or new `hsync_infra_beat.go`) — add `StartInfraBeatLoop()`
- `main_initfuncs.go` — start the infra beat loop alongside agent-specific engines

## Implementation Order

1. **Step 4** (HELLO in DNS routers) — smallest change, no dependencies
2. **Step 0** (beat carries supported message types) — foundation for visibility; Step 6 depends on it
3. **Step 1** (HSYNC peer ping handler) — new handler, needed by Steps 2-3
4. **Step 5** (peer stats) — can be done alongside Step 1
5. **Step 2** (combiner sync router) — depends on Steps 1, 2b (LocalIdentity)
6. **Step 3** (signer sync router) — depends on Steps 1, 2b (LocalIdentity)
7. **Step 6** (infra beat loop) — depends on Steps 0, 2, 3 (combiner/signer must be able to receive beats first)

## Files Modified (Summary)

| File | Steps | Changes |
|------|-------|---------|
| `agent/transport/transport.go` | 0 | Add `SupportedMsgTypes` to `BeatRequest`, `BeatResponse` |
| `agent/transport/dns.go` | 0 | Add `SupportedMsgTypes` to `DnsBeatPayload` |
| `agent/transport/api.go` | 0, 1 | Add `SupportedMsgTypes` to `apiBeatRequest`/`apiBeatResponse`; change `Ping()` URL to `/sync/ping` |
| `agent/transport/handlers.go` | 0 | Include `SupportedMsgTypes` in DNS beat confirmation payload |
| `agent/transport/router_init.go` | 4 | Add Hello to combiner + signer DNS routers |
| `agent_structs.go` | 0, 1 | Add `SupportedMsgTypes` to `AgentBeatPost`/`AgentBeatResponse`/`AgentDetails`; add `AgentPingPost`/`AgentPingResponse` |
| `apihandler_agent.go` | 0, 1, 2, 5 | Beat capabilities in `APIbeat()`; add `APIsyncPing()`; update `APIhello()`/`APIbeat()` to use `LocalIdentity()`; add stats |
| `apirouters.go` | 1, 2, 3 | Add `/sync/ping` endpoint; add `SetupCombinerSyncRouter()`; add `SetupSignerSyncRouter()` |
| `hsync_transport.go` | 0, 1 | Add `GetDNS/APISupportedMsgTypes()`; populate in `SendBeatWithFallback()`; store on `Agent`; update `SendPing()` dispatch |
| `config.go` | 2, 3 | Add `Api` block to `LocalCombinerConf` and `MultiProviderConf`; add `LocalIdentity()` |
| `main_initfuncs.go` | 2, 3, 6 | Start combiner and signer sync API dispatchers; start infra beat loop |
| `config.go` | 2, 3, 6 | Add `Api` blocks to combiner/signer conf; add `BeatInterval` to `PeerConf`; add `LocalIdentity()` |
| `hsync_beat.go` (or new file) | 6 | Add `StartInfraBeatLoop()` for signer/combiner beats |
| CLI display code | 0 | Show per-transport supported message types in `agent debug show agents` |

## Verification

1. **Build**: `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
2. **Beat capabilities (Step 0)**: Start two agents. After beats exchange, run `agent debug show agents`. Verify each peer shows per-transport supported message types (e.g. `DNS: [beat, confirm, edits, hello, keystate, ping, rfi, sync]`). Verify API shows fewer types initially.
3. **HELLO over API**: Configure two agents with `supported_mechanisms: ["api"]`. Start both. Verify Hello handshake succeeds and agent transitions to INTRODUCED. Check `agent debug show agents` shows API transport state.
4. **BEAT over API**: After HELLO, verify heartbeats arrive and update LastContactTime. Check `agent debug show agents` shows increasing beat counts and API-side supported message types.
5. **PING over API**: Run `agent debug ping <peer>`. Verify nonce echoes back correctly and response shows API transport.
6. **Management ping unchanged**: Verify `tdns-cliv2 ping` still works against all roles (uses management `/ping`, not `/sync/ping`).
7. **Combiner HELLO/BEAT over API**: Configure agent with combiner using API transport. Verify the agent can Hello and Beat the combiner.
8. **Signer HELLO/BEAT over API**: Configure agent with signer using API transport. Verify the agent can Hello and Beat the signer.
9. **Stats**: After API messages, check `agent debug show agents` shows stats for API-received messages.
10. **Infra beat loop (Step 6)**: Start agent with combiner and signer configured. After ~10 minutes, verify combiner and signer peers reach OPERATIONAL state. Verify `agent debug show agents` shows `SupportedMsgTypes` populated for combiner and signer from their beat responses. Reduce `beat_interval` to 30s in test config to avoid waiting 10 minutes.

## Complexity Assessment

### Step 0: Beat Carries Supported Message Types

**Complexity: Low–Medium**

The data structures are additive — `SupportedMsgTypes []string` added to five structs with no field removals. The logic chain has several touch points but each is simple:

- `AgentDetails` (agent_structs.go:83) — add one field. Trivial.
- `AgentMsgReport` (agent_structs.go:453) — add one field. Trivial.
- `BeatRequest`/`BeatResponse` (transport.go) — add one field each. Trivial.
- `DnsBeatPayload` (dns.go) — add one JSON field. Trivial.
- `apiBeatRequest`/`apiBeatResponse` (api.go) — add one JSON field each. Trivial.
- `AgentBeatPost`/`AgentBeatResponse` (agent_structs.go) — add one field each. Trivial.
- `DNSTransport.Beat()` (dns.go) — populate `SupportedMsgTypes` in payload. Requires access to the router's registered types, but `tm.Router.List()` already exists and returns `map[MessageType][]*HandlerRegistration`.
- `APITransport.Beat()` (api.go) — populate from the maintained API list. Requires `APITransport` to hold a `[]string` set during router setup.
- `SendBeatWithFallback()` (hsync_transport.go:1379, 2075 lines) — pass the right capability list to each transport's beat call. 2 callers (`hsync_beat.go`, `hsync_hello.go`), no signature change needed if populated inside `SendBeatWithFallback` before dispatch.
- `APIbeat()` handler (apihandler_agent.go:1614) — extract `SupportedMsgTypes` from decoded `AgentBeatPost`, pass through `AgentMsgReport`.
- Beat processors (`hsyncengine.go:93`, `combiner_msg_handler.go:58`) — store `report.SupportedMsgTypes` on `agent.ApiDetails` or `agent.DnsDetails`. Requires knowing which transport the beat arrived on — already present as `report.Transport`.
- `HandleBeat` in `handlers.go` (line 151) — the DNS confirmation response payload is an anonymous struct with fixed fields. Adding `SupportedMsgTypes` to it requires also adding it to the response parsing in `DNSTransport.Beat()`.
- CLI display — locate and extend the `agent debug show agents` output. Low complexity but requires finding the right CLI file.

**Estimated lines changed: ~80–100** across 12 files, mostly struct field additions and small populate/store blocks.

### Step 1: HSYNC Peer Ping Handler

**Complexity: Low**

New `APIsyncPing()` handler mirrors `APIbeat()` exactly but without the beat-specific processing. Add `AgentPingPost`/`AgentPingResponse` structs (similar to existing `AgentBeatPost`/`AgentBeatResponse`). One new route registration. One URL change in `APITransport.Ping()`. One comment + minor logic change in `SendPing()`.

**Estimated lines changed: ~60–80** across 4 files.

### Step 2 & 3: Combiner and Signer Sync API Routers

**Complexity: Medium**

`SetupCombinerSyncRouter()` and `SetupSignerSyncRouter()` are structurally identical to `SetupAgentSyncRouter()` (apirouters.go:211–277, ~66 lines). The main non-trivial part is the config changes: adding `Api` blocks to `LocalCombinerConf` and `MultiProviderConf`, and wiring the startup dispatch in `main_initfuncs.go`. `conf.LocalIdentity()` is a simple switch. The handlers themselves (`APIhello`, `APIbeat`) only need a one-line change each (replacing `conf.Agent.Identity` with `conf.LocalIdentity()`).

**Estimated lines changed: ~150–180** across 5 files (two new router functions ~66 lines each, config structs, startup wiring, identity method).

### Step 4: HELLO in Combiner/Signer DNS Routers

**Complexity: Trivial**

Copy-paste of an existing `router.Register()` block into two functions. 10 lines of code total.

**Estimated lines changed: ~10** in 1 file.

### Step 5: Peer Stats for API Messages

**Complexity: Low**

Three handlers need a short stats-update block each. The `PeerRegistry` is already accessible via `conf.Internal.TransportManager.PeerRegistry`. Need to confirm the exact `MessageStats` update pattern from `stats_middleware.go`, but it's a few lines per handler.

**Estimated lines changed: ~20–30** across 1 file.

### Step 6: Infra Beat Loop

**Complexity: Low–Medium**

`StartInfraBeatLoop()` is structurally similar to the existing agent beat loop in `hsync_beat.go`. The logic is: for each configured infra peer (combiner, signer), check state and send Hello or Beat accordingly using existing functions. One ticker per peer at configurable interval (default 10 min). The Hello-first and state-transition logic is already implemented for agents — this reuses it for different peer types.

Adding `BeatInterval` to `PeerConf` is a trivial struct addition. Wiring the loop in `main_initfuncs.go` is straightforward.

**Estimated lines changed: ~80–100** across 3 files.

### Total Estimate

| Step | Lines changed | Files touched |
|------|--------------|---------------|
| 0 — Beat capabilities | 80–100 | 12 |
| 1 — Sync ping handler | 60–80 | 4 |
| 2 — Combiner sync router | 90–110 | 3 |
| 3 — Signer sync router | 60–70 | 2 |
| 4 — HELLO in DNS routers | 10 | 1 |
| 5 — Peer stats | 20–30 | 1 |
| 6 — Infra beat loop | 80–100 | 3 |
| **Total** | **~400–500** | **~15 distinct files** |

## Risk Analysis

### Low Risk (safe to implement without extra caution)

**Step 4 — HELLO in DNS routers**: Pure addition. `HandleHello` is already implemented and registered in the agent router. Adding it to combiner/signer routers cannot break existing behavior — previously unhandled Hello messages would have hit `DefaultUnsupportedHandler` and been ignored anyway.

**Step 5 — Peer stats**: Additive. Stats update is a post-hoc side effect after the MsgQs routing that already succeeds. A nil check on `TransportManager` guards against any startup ordering issues.

**Step 0, struct additions**: Adding `omitempty` JSON fields to serialization structs is fully backward-compatible. Old peers that don't send `SupportedMsgTypes` will produce an empty slice — the receiver handles that as "unknown capabilities", not an error.

### Medium Risk (needs care, but bounded)

**Step 0 — Beat confirmation response (DNS path)**: The DNS `HandleBeat` confirmation payload is an anonymous struct (handlers.go:173–185). Adding `SupportedMsgTypes` to it requires `HandleBeat` to have access to the router's registered types. `HandleBeat` currently only has the `MessageContext` — the router itself is not in scope there. **Fix**: pass `SupportedMsgTypes` into `HandleBeat` via `MessageContext.Data` (set by the caller before dispatch), the same pattern already used for `response` and `distribution_id`. This is the one non-trivial data-flow addition in Step 0.

**Step 0 — Transport field in beat processor**: The beat processors (`hsyncengine.go:93`, `combiner_msg_handler.go:58`) need to route `SupportedMsgTypes` to the correct `AgentDetails` (API vs DNS) based on `report.Transport`. The `Transport` field is already set (`"API"` or `"DNS"`) by the handlers, so the logic is straightforward, but it requires the correct `Agent` lookup in the registry. The combiner's beat processor currently only uses `report.Identity` and `report.BeatInterval` — adding `SupportedMsgTypes` storage extends it but doesn't change its control flow.

**Step 1 — `/sync/ping` URL change in APITransport**: Changing the URL in `APITransport.Ping()` is safe for new peers, but any peer running old code that registers `/ping` (not `/sync/ping`) on the sync router will fail the API ping. Since this is a development codebase with no installed base this is not a problem, but all instances must be updated together.

**Step 2/3 — `conf.LocalIdentity()` and handler reuse**: `APIhello()` and `APIbeat()` access `conf.Agent.Identity`. Changing to `conf.LocalIdentity()` is a one-line change per handler, but if `conf.Agent` is nil (which it is on a combiner), the existing code would panic at runtime. The `LocalIdentity()` method guards against this. **Risk**: any code path that reaches these handlers before `LocalIdentity()` is in place would panic on a combiner. Mitigation: implement `LocalIdentity()` first, update handlers before wiring the combiner router.

**Step 2/3 — New startup code in main_initfuncs.go**: Starting a new `APIdispatcherNG` goroutine for combiner/signer requires correct config (listen addresses, cert/key files). If config is missing or malformed, the dispatcher logs a warning and exits without crashing the process (consistent with existing behavior in `APIdispatcherNG` which returns early if addresses are empty). No risk of breaking existing combiner/signer behavior if the new `Api` config block is absent — the dispatcher simply doesn't start.

### Higher Risk (requires careful implementation)

**Step 0 — `APITransport.Beat()` needs capability list**: `APITransport` currently has no reference to the registered API endpoints. To populate `SupportedMsgTypes` in the beat request, `APITransport` needs to know what the sync API router handles. Options:
- Store a `[]string` on `APITransport` set at router-setup time (cleanest)
- Pass it through `BeatRequest.SupportedMsgTypes` from `SendBeatWithFallback` (already has access to `tm`)

The second option is simpler — `SendBeatWithFallback` already holds `tm`, which can compute or store the API capability list. **Risk level becomes low** if this option is chosen.

**Step 2 — Combiner AgentRegistry for TLSA verification**: `SetupAgentSyncRouter()` uses `conf.Internal.AgentRegistry.S.Get(AgentId(clientId))` to look up the client's TLSA record. The combiner also has an `AgentRegistry` (used in `combiner_msg_handler.go`). Verify that `conf.Internal.AgentRegistry` is populated for the combiner role before the sync router middleware runs — if it's nil, the middleware returns 401 for all connections. This is a startup ordering question, not a code correctness issue.

### Step 6 — Infra Beat Loop

**Risk: Low**

`StartInfraBeatLoop()` reuses `SendBeatWithFallback()` and the existing Hello/Beat send path — no new transport logic. The main risk is startup ordering: the loop must not start before the combiner/signer's sync API server is ready to receive beats (Steps 2 and 3). This is handled by starting the infra beat loop after the API dispatchers are running, with a short initial delay (the same pattern already used for the agent discovery retry loop). If the combiner or signer is not configured (nil `PeerConf`), the loop simply skips that peer — no panic.

One subtle point: the combiner and signer are already in `AgentRegistry` (registered at startup from config). Their initial state must be set to `KNOWN` explicitly when registered, so the Hello-first logic in the beat loop fires correctly. If they start in a different state (e.g. `NEEDED`), the loop may skip the Hello and go straight to Beat, which would fail since no handshake has occurred. Verify initial state assignment at combiner/signer registration time.

### Non-Risks (things that look risky but aren't)

- **Breaking existing DNS PING**: `APITransport.Ping()` URL change only affects the API client. DNS ping is untouched.
- **Breaking management `/ping`**: The management `APIping()` stays registered on `/ping` in both management and sync routers. Only the sync router gets the additional `/sync/ping`. The management CLI continues to use `/ping`.
- **Breaking existing HELLO/BEAT agent↔agent over API**: `APIhello()` and `APIbeat()` are not removed or replaced — only `conf.Agent.Identity` references change to `conf.LocalIdentity()`, which returns the same value for the agent role.
