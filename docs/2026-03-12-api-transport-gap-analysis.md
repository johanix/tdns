# API Transport Gap Analysis and Implementation Plan

## Context

The TDNS inter-agent communication infrastructure is designed to be transport-agnostic. A `Transport` interface (`agent/transport/transport.go`) defines the common operations, and two implementations exist:

- **DNSTransport** (`agent/transport/dns.go`): Uses DNS NOTIFY with CHUNK records and EDNS(0) options. Fully functional end-to-end.
- **APITransport** (`agent/transport/api.go`): Uses HTTPS REST with JSON payloads. Client-side partially implemented; server-side and dispatch logic incomplete.

This document catalogs every gap that must be closed for the API transport to support the full message set: HELLO, BEAT, SYNC, UPDATE, KEYSTATE, EDITS, RFI, CONFIG, AUDIT, CONFIRM, PING, and RELOCATE.

## Architecture Overview

### Message Flow Layers

```
Business Logic (SynchedDataEngine, HsyncEngine, CombinerMsgHandler, SignerMsgHandler)
        │
        ▼
TransportManager (hsync_transport.go)
   ├── SelectTransport() / SendSyncWithFallback() / SendHello() / SendBeat()
   ├── sendSyncConfirmation() / sendImmediateConfirmation() / sendRemoteConfirmation()
   ├── sendRfiToSigner() / sendRfiToCombiner()
   │
   ├── APITransport (api.go)          ──── HTTPS POST ───→  Sync API Server (apirouters.go)
   │   Hello, Beat, Sync, Relocate,                          └── apihandler_agent.go handlers
   │   Confirm, Ping                                              APIhello, APIbeat, APImsg
   │
   └── DNSTransport (dns.go)          ──── DNS NOTIFY ──→  ChunkNotifyHandler
       Hello, Beat, Sync, Relocate,                          └── DNSMessageRouter
       Confirm, Ping, Keystate, Edits                             └── Middleware chain
                                                                       └── handlers.go
```

### Key Files

| File | Role |
|------|------|
| `agent/transport/transport.go` | Transport interface + request/response types |
| `agent/transport/api.go` | APITransport client implementation |
| `agent/transport/dns.go` | DNSTransport client implementation |
| `agent/transport/handlers.go` | Message handlers (HandleHello, HandleSync, etc.) |
| `agent/transport/router_init.go` | Router initialization per role (agent, combiner, signer) |
| `agent/transport/dns_message_router.go` | DNSMessageRouter with middleware |
| `agent/transport/chunk_notify_handler.go` | DNS incoming message pipeline |
| `hsync_transport.go` | TransportManager — orchestrates both transports |
| `apirouters.go` | SetupAgentSyncRouter — API server endpoints |
| `apihandler_agent.go` | API server handler implementations |
| `combiner_msg_handler.go` | Combiner message processing + confirmation dispatch |
| `signer_msg_handler.go` | Signer message processing + keystate dispatch |
| `hsyncengine.go` | HsyncEngine — agent-side message consumer |

## Current State: What Works Over API

| Capability | Client (sending) | Server (receiving) | Dispatch (transport selection) |
|-----------|-------------------|-------------------|-------------------------------|
| HELLO | `APITransport.Hello()` | `APIhello()` at `/hello` | `SendHello()` tries both |
| BEAT | `APITransport.Beat()` | `APIbeat()` at `/beat` | `SendBeatWithFallback()` tries both |
| SYNC (agent→agent) | `APITransport.Sync()` | `APImsg()` at `/msg` handles `AgentMsgNotify` | `SendSyncWithFallback()` with fallback |
| PING | `APITransport.Ping()` | `APIping()` at `/ping` | `SendPing()` prefers DNS, falls back to API |
| RELOCATE | `APITransport.Relocate()` | No endpoint | Not dispatched |
| CONFIRM | `APITransport.Confirm()` | No endpoint | All 4 sites hardcode DNSTransport |
| UPDATE (agent→combiner) | `APITransport.Sync()` with `MessageType: "update"` | `/msg` does NOT handle `AgentMsgUpdate` | Via reliable queue → `SendSyncWithFallback()` |
| RFI (agent→agent) | Via `APITransport.Sync()` with `MessageType: "rfi"` | `APImsg()` handles `AgentMsgRfi` | `sendRfiToAgent()` uses `SendSyncWithFallback` |
| RFI (agent→combiner) | Via `SyncRequest` | Combiner has no sync API server | `sendRfiToCombiner()` hardcodes DNS |
| RFI (agent→signer) | Via `SyncRequest` | Signer has no sync API server | `sendRfiToSigner()` hardcodes DNS |
| KEYSTATE | **No method on APITransport** | No endpoint | All sites hardcode `DNSTransport.Keystate()` |
| EDITS | **No method on APITransport** | No endpoint | `sendEditsToAgent()` hardcodes `DNSTransport.Edits()` |
| CONFIG | **No method on APITransport** | No endpoint | Not implemented at all yet |
| AUDIT | **No method on APITransport** | No endpoint | Not implemented at all yet |

## Detailed Gap Analysis

### Gap 1: Transport Interface Missing Methods

The `Transport` interface (lines 77-101 of `transport.go`) only declares: Hello, Beat, Sync, Relocate, Confirm, Ping, Name.

`Keystate()` and `Edits()` exist only as methods on `DNSTransport` (not on the interface). `Config()` and `Audit()` don't exist on either transport.

**Impact**: Any code that uses the `Transport` interface cannot access Keystate, Edits, Config, or Audit. Dispatch code must use concrete `*DNSTransport` references, preventing transport-agnostic dispatch.

**Required types already defined in `transport.go`** (after recent additions):
- `KeystateRequest` / `KeystateResponse` (lines 224-243)
- `EditsRequest` / `EditsResponse` (lines 248-262)
- `ConfigRequest` / `ConfigResponse` (lines 267-282)
- `AuditRequest` / `AuditResponse` (lines 285-301)

### Gap 2: APITransport Missing Client Methods

`api.go` implements 6 methods: Hello, Beat, Sync, Relocate, Confirm, Ping.

Missing methods:
1. **`Keystate()`** — POST to `/keystate` with KeystateRequest JSON
2. **`Edits()`** — POST to `/edits` with EditsRequest JSON
3. **`Config()`** — POST to `/config-sync` with ConfigRequest JSON (NOT `/config` which is the CLI management endpoint)
4. **`Audit()`** — POST to `/audit` with AuditRequest JSON

Each needs corresponding `api*Request` / `api*Response` JSON structs.

### Gap 3: API Sync Server Missing Endpoints

`SetupAgentSyncRouter()` in `apirouters.go` (lines 211-277) registers only 4 endpoints:
- `/hello` (no client cert required)
- `/ping`, `/beat`, `/msg` (client cert required)

Missing endpoints:
1. `/confirm` — receive confirmation from peer
2. `/keystate` — receive keystate signal from signer (or from agent for signer role)
3. `/edits` — receive edits response from combiner
4. `/config-sync` — receive config data from peer
5. `/audit` — receive audit data from peer

Additionally, `/msg` needs to accept `AgentMsgUpdate` (currently only handles `AgentMsgNotify`, `AgentMsgStatus`, `AgentMsgRfi`).

### Gap 4: Combiner and Signer Have No Sync API Server

Only the agent role calls `SetupAgentSyncRouter()`. The combiner and signer roles use `SetupAPIRouter()` which serves management/CLI endpoints only (e.g., `/combiner`, `/combiner/edits`, `/combiner/debug`).

This means:
- A combiner cannot receive UPDATE, RFI, BEAT, HELLO, or PING from agents over API
- A signer cannot receive KEYSTATE, RFI, BEAT, or PING from agents over API

**Fix**: Either extend `SetupAgentSyncRouter` to be role-aware and register it for combiners/signers too, or add sync endpoints to the existing management API router behind the client-cert middleware.

### Gap 5: Confirmation Dispatch Hardcodes DNSTransport

All 4 confirmation senders use `tm.DNSTransport.Confirm()` directly:

| Function | File:Line | Called When |
|----------|-----------|------------|
| `sendSyncConfirmation` | `hsync_transport.go:903` | Agent confirms received sync to peer |
| `sendImmediateConfirmation` | `hsync_transport.go:942` | Agent sends PENDING ack before forwarding to combiner |
| `sendRemoteConfirmation` | `hsync_transport.go:992` | Agent relays combiner's confirmation back to originator |
| `combinerSendConfirmation` | `combiner_msg_handler.go:304` | Combiner confirms UPDATE back to agent |

Each function:
- Checks `if tm.DNSTransport == nil` and returns silently if true
- Never considers APITransport
- Has no way to know which transport the original message arrived on

**Fix**: Add a transport-aware `sendConfirmation` helper on TransportManager that:
1. Looks up the peer's preferred/available transport
2. Tries the preferred transport first, falls back to the other
3. Replaces all 4 hardcoded call sites

### Gap 6: Keystate and Edits Dispatch Hardcodes DNSTransport

| Function | File:Line | Direction |
|----------|-----------|-----------|
| `SendKeystateToSigner` | `hsync_transport.go:1830` | Agent → Signer |
| `sendKeystateInventoryToAgent` | `signer_msg_handler.go:217` | Signer → Agent |
| `sendEditsToAgent` | `combiner_msg_handler.go:376` | Combiner → Agent |

All use `tm.DNSTransport.Keystate()` or `tm.DNSTransport.Edits()` directly.

**Fix**: Add transport-aware dispatch methods (e.g., `tm.SendKeystate()`, `tm.SendEdits()`) that select transport based on peer capabilities, similar to `SendSyncWithFallback`.

### Gap 7: RFI to Combiner/Signer Hardcodes DNSTransport

| Function | File:Line |
|----------|-----------|
| `sendRfiToCombiner` | `hsync_transport.go:1891` |
| `sendRfiToSigner` | `hsync_transport.go:1855` |

Both create a `SyncRequest` with `MessageType: "rfi"` and call `tm.DNSTransport.Sync()` directly.

**Fix**: Use `SendSyncWithFallback()` which already handles transport selection. The Sync method on APITransport already supports `MessageType: "rfi"`.

### Gap 8: API Sync Response Lacks Confirmation Detail

`apiSyncResponse` (api.go:413-419) only has:
```go
type apiSyncResponse struct {
    Identity       string `json:"identity,omitempty"`
    DistributionID string `json:"distribution_id,omitempty"`
    Msg            string `json:"msg,omitempty"`
    Error          bool   `json:"error"`
    ErrorMsg       string `json:"error_msg,omitempty"`
}
```

Missing fields that DNS inline confirmations carry:
- `AppliedRecords []string`
- `RemovedRecords []string`
- `RejectedItems []RejectedItemDTO`
- `Truncated bool`
- `Status string`

Without these, the `SyncResponse` returned by `APITransport.Sync()` always returns `ConfirmSuccess` or `ConfirmFailed` with no per-RR detail. The SynchedDataEngine needs this detail for per-RR tracking.

### Gap 9: SecurePayloadWrapper Tied to DNSTransport

Three discovery/peer-setup functions access `tm.DNSTransport.SecureWrapper` for JWK/HPKE crypto:

| File:Line | Usage |
|-----------|-------|
| `agent_discovery.go:243-244` | Get crypto for encrypting payloads to discovered agent |
| `agent_discovery.go:267-268` | Register peer's public key |
| `combiner_peer.go:85-90` | Get crypto for combiner peer setup |
| `signer_peer.go:87-91` | Get crypto for signer peer setup |

If DNSTransport is nil (API-only mode), peer key exchange fails. The SecurePayloadWrapper should be on TransportManager, not DNSTransport.

### Gap 10: API Handlers Bypass Router Middleware

DNS messages go through a middleware chain: Authorization → Signature → Stats → Logging → RouteToMsgHandler → Handler.

API messages in `apihandler_agent.go` go directly to `MsgQs` channels with only the TLS client-cert check in the mux middleware. No statistics tracking, no structured logging middleware, no authorization check against the HSYNC peer list.

This is not a correctness issue (TLS certs provide auth), but it means API peers don't appear in per-peer stats and diagnostics.

## Implementation Plan

### Phase 1: Transport-Aware Confirmation (Critical Path)

This is the highest-priority gap. Without it, confirmations silently fail in API-only mode, and the reliable message queue never transitions messages from "pending" to "confirmed".

**Step 1.1**: Add `sendConfirmation` helper to TransportManager

```
File: hsync_transport.go
Add: func (tm *TransportManager) sendConfirmation(peer *transport.Peer, req *transport.ConfirmRequest) error
Logic: Try API if peer.APIEndpoint != "" and tm.APITransport != nil, else DNS.
```

**Step 1.2**: Replace 4 hardcoded `tm.DNSTransport.Confirm()` calls

```
hsync_transport.go:903  (sendSyncConfirmation)
hsync_transport.go:942  (sendImmediateConfirmation)
hsync_transport.go:992  (sendRemoteConfirmation)
combiner_msg_handler.go:304  (combinerSendConfirmation)
```

**Step 1.3**: Register `/confirm` endpoint in SetupAgentSyncRouter

```
File: apirouters.go
Add: secureRouter.HandleFunc("/confirm", conf.APIconfirmSync()).Methods("POST")
File: apihandler_agent.go
Add: func (conf *Config) APIconfirmSync() handler that routes to ChunkHandler.OnConfirmationReceived
```

**Step 1.4**: Enrich `apiSyncResponse` with confirmation detail

```
File: api.go
Add: AppliedRecords, RemovedRecords, RejectedItems, Truncated, Status to apiSyncResponse
Update: APITransport.Sync() to parse these fields from response
```

### Phase 2: Add Keystate and Edits to API Transport

**Step 2.1**: Add `Keystate()` method to APITransport

```
File: api.go
Add: func (t *APITransport) Keystate(ctx, peer, *KeystateRequest) (*KeystateResponse, error)
Add: apiKeystateRequest, apiKeystateResponse structs
Endpoint: POST /keystate
```

**Step 2.2**: Add `Edits()` method to APITransport

```
File: api.go
Add: func (t *APITransport) Edits(ctx, peer, *EditsRequest) (*EditsResponse, error)
Add: apiEditsRequest, apiEditsResponse structs
Endpoint: POST /edits
```

**Step 2.3**: Add `Config()` method to APITransport

```
File: api.go
Add: func (t *APITransport) Config(ctx, peer, *ConfigRequest) (*ConfigResponse, error)
Add: apiConfigRequest, apiConfigResponse structs
Endpoint: POST /config-sync  (NOT /config, which is the CLI management endpoint)
```

**Step 2.4**: Register server-side endpoints and handlers

```
File: apirouters.go — register /keystate, /edits, /config-sync in SetupAgentSyncRouter
File: apihandler_agent.go — add APIkeystate(), APIedits(), APIconfigSync() handlers
```

**Step 2.5**: Transport-aware dispatch for Keystate, Edits, Config

```
File: hsync_transport.go
Add: func (tm *TransportManager) SendKeystate(ctx, peer, *KeystateRequest) (*KeystateResponse, error)
Add: func (tm *TransportManager) SendEdits(ctx, peer, *EditsRequest) (*EditsResponse, error)
Add: func (tm *TransportManager) SendConfig(ctx, peer, *ConfigRequest) (*ConfigResponse, error)

Replace:
  hsync_transport.go:1830  tm.DNSTransport.Keystate() → tm.SendKeystate()
  signer_msg_handler.go:217  tm.DNSTransport.Keystate() → tm.SendKeystate()
  combiner_msg_handler.go:376  tm.DNSTransport.Edits() → tm.SendEdits()
```

### Phase 3: Fix RFI Dispatch and UPDATE Handling

**Step 3.1**: Make `sendRfiToCombiner()` and `sendRfiToSigner()` transport-aware

```
File: hsync_transport.go
Change: sendRfiToCombiner() and sendRfiToSigner() to use SendSyncWithFallback()
        instead of tm.DNSTransport.Sync()
```

**Step 3.2**: Add `AgentMsgUpdate` to APImsg handler

```
File: apihandler_agent.go, APImsg() function
Change: switch statement to include AgentMsgUpdate alongside AgentMsgNotify, AgentMsgStatus, AgentMsgRfi
```

**Step 3.3**: Set up sync API endpoints for combiner and signer roles

```
File: apirouters.go or main_initfuncs.go
Add: Call SetupAgentSyncRouter (or a variant) for combiner and signer app types
Register at minimum: /beat, /ping, /msg (for UPDATE and RFI), /keystate (for signer)
```

### Phase 4: Move SecurePayloadWrapper to TransportManager

**Step 4.1**: Add `SecureWrapper` field to TransportManager

```
File: hsync_transport.go
Add: SecureWrapper field on TransportManager struct
Init: In NewTransportManager(), set tm.SecureWrapper (currently lives on DNSTransport)
```

**Step 4.2**: Update references

```
agent_discovery.go:243-244, 267-268 → tm.SecureWrapper
combiner_peer.go:85-90 → tm.SecureWrapper
signer_peer.go:87-91 → tm.SecureWrapper
```

### Phase 5 (Future): Unified Incoming Message Router

This is a larger refactoring that unifies the DNS and API incoming message pipelines. Defer this until the above phases are complete and tested.

**Concept**: Rename `DNSMessageRouter` to `MessageRouter`. Factor out DNS-specific NOTIFY/CHUNK handling from the generic routing. Route API handler payloads through the same router so they get authorization, stats, and logging middleware.

## Decision: Transport Interface Extension

There are two approaches to adding Keystate/Edits/Config/Audit to the transport abstraction:

**Option A: Extend the Transport interface**
```go
type Transport interface {
    Hello(...)
    Beat(...)
    Sync(...)
    Relocate(...)
    Confirm(...)
    Ping(...)
    Keystate(...)
    Edits(...)
    Config(...)
    Name()
}
```
Pro: Clean, type-safe dispatch. Con: Interface grows; not every transport needs every method.

**Option B: Keep Transport interface minimal, add per-method dispatch on TransportManager**
```go
// TransportManager methods that internally check both transports
func (tm *TransportManager) SendKeystate(ctx, peer, req) (*KeystateResponse, error)
func (tm *TransportManager) SendEdits(ctx, peer, req) (*EditsResponse, error)
```
Pro: Interface stays small. Con: TransportManager must know about both transports' capabilities.

**Recommendation**: Option B. The Transport interface stays focused on the universal message types (Hello, Beat, Sync, Confirm, Ping, Relocate). Keystate, Edits, Config, and Audit are role-specific operations that only some roles send/receive. TransportManager dispatch methods handle the transport selection internally, checking which concrete transport supports the operation.

## Files to Modify (Summary)

| Phase | File | Changes |
|-------|------|---------|
| 1 | `hsync_transport.go` | `sendConfirmation()` helper; replace 3 hardcoded `DNSTransport.Confirm()` |
| 1 | `combiner_msg_handler.go` | Replace `combinerSendConfirmation` DNSTransport usage |
| 1 | `apirouters.go` | Register `/confirm` endpoint |
| 1 | `apihandler_agent.go` | Add `APIconfirmSync()` handler |
| 1 | `api.go` | Enrich `apiSyncResponse` with per-RR detail fields |
| 2 | `api.go` | Add `Keystate()`, `Edits()`, `Config()` methods + JSON types |
| 2 | `apirouters.go` | Register `/keystate`, `/edits`, `/config-sync` endpoints |
| 2 | `apihandler_agent.go` | Add server-side handlers |
| 2 | `hsync_transport.go` | Add `SendKeystate()`, `SendEdits()`, `SendConfig()` dispatch methods |
| 2 | `signer_msg_handler.go` | Use `tm.SendKeystate()` instead of `tm.DNSTransport.Keystate()` |
| 2 | `combiner_msg_handler.go` | Use `tm.SendEdits()` instead of `tm.DNSTransport.Edits()` |
| 3 | `hsync_transport.go` | `sendRfiToCombiner/Signer` use `SendSyncWithFallback()` |
| 3 | `apihandler_agent.go` | Add `AgentMsgUpdate` to `APImsg()` switch |
| 3 | `apirouters.go` or init | Set up sync API for combiner/signer roles |
| 4 | `hsync_transport.go` | Move `SecureWrapper` to TransportManager |
| 4 | `agent_discovery.go` | Update `SecureWrapper` references |
| 4 | `combiner_peer.go`, `signer_peer.go` | Update `SecureWrapper` references |

## Verification

Each phase should be verifiable independently:

**Phase 1**: Configure an agent pair with `supported_mechanisms: ["api"]`. Send a SYNC. Confirm that:
- The receiving agent sends a confirmation back via API (not DNS)
- The reliable message queue transitions the message to "confirmed"
- `agent debug show queue` shows the confirmation

**Phase 2**: With API-only agents, test:
- Agent→signer KEYSTATE signal (propagated/rejected) arrives and is acknowledged
- Signer→agent KEYSTATE inventory arrives and populates the SDE
- Combiner→agent EDITS response arrives and populates the SDE

**Phase 3**: With API-only agents, test:
- Agent sends RFI SYNC to combiner via API, gets response
- Agent sends UPDATE to combiner via API, combiner processes it
- Agent sends RFI KEYSTATE to signer via API, gets inventory back

**Phase 4**: With API-only agents (no DNS transport configured), verify:
- Agent discovery completes (peer key exchange succeeds via tm.SecureWrapper)
- Combiner peer setup works without DNSTransport
