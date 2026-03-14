# Plan: API Transport Support for PING, HELLO, and BEAT

## Context

PING, HELLO, and BEAT are the three "lifecycle" messages — they establish identity, maintain liveness, and probe connectivity. Getting these right over API is the foundation for all other message types (SYNC, UPDATE, KEYSTATE, EDITS, RFI, CONFIG).

### Current State

| Message | Client (sending) | Server (receiving) | Dispatch | Status |
|---------|------------------|--------------------|----------|--------|
| HELLO | `APITransport.Hello()` works | `APIhello()` at `/hello` works | `SendHello()` tries both transports | Agent↔agent works. No combiner/signer endpoint. |
| BEAT | `APITransport.Beat()` works | `APIbeat()` at `/beat` works | `SendBeatWithFallback()` tries both | Agent↔agent works. No combiner/signer endpoint. |
| PING | `APITransport.Ping()` works | **Wrong handler** — `/ping` on sync router is the management health-check (`APIping` in `api_utils.go`), not HSYNC peer ping | `SendPing()` prefers DNS, API fallback hits wrong handler | Broken over API. No combiner/signer endpoint. |

### Root Causes

1. **No HSYNC peer ping handler**: The sync API router (`SetupAgentSyncRouter` in `apirouters.go:270`) registers the management `APIping()` on `/ping`. This handler returns boot time, version, pong counter — it doesn't echo nonces or route to `MsgQs.Ping`. The management ping must stay (it serves a different purpose), but the sync router needs a separate HSYNC peer ping at a different path.

2. **No combiner/signer sync API server**: Only agents call `SetupAgentSyncRouter()`. Combiners and signers only run the management API (`SetupAPIRouter()` with API key auth). Agents cannot send HELLO, BEAT, or PING to combiner/signer over API.

3. **Missing HELLO in combiner/signer DNS routers**: `InitializeCombinerRouter()` and `InitializeSignerRouter()` in `router_init.go` don't register a Hello handler. Even over DNS, combiner/signer cannot receive Hello.

4. **No peer stats for API messages**: API handlers don't update `PeerRegistry` statistics, making API peers invisible in diagnostics.

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

## Implementation Order

1. **Step 0** (beat carries supported message types) — foundation for visibility into transport gaps
2. **Step 4** (HELLO in DNS routers) — smallest change, no dependencies
3. **Step 1** (HSYNC peer ping handler) — new handler, needed by Steps 2-3
4. **Step 5** (peer stats) — can be done alongside Step 1
5. **Step 2** (combiner sync router) — depends on Steps 1, 2b (LocalIdentity)
6. **Step 3** (signer sync router) — depends on Steps 1, 2b (LocalIdentity)

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
| `main_initfuncs.go` | 2, 3 | Start combiner and signer sync API dispatchers |
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
