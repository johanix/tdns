# RFI EDITS: Bootstrap Agent SDE from Combiner

**Date**: 2026-03-03
**Linear**: DNS-132
**Depends on**: DNS-131 (CombinerContributions snapshot table)

## Context

After agent restart, the SynchedDataEngine (SDE) starts empty. Remote agent data is recovered via RFI SYNC (agent→agents), and DNSKEYs via RFI KEYSTATE (agent→signer). But the agent's own *local edits* (typically NS records added/removed via the agent) are lost — there is no mechanism to recover them from the combiner.

With DNS-131, the combiner now persists `AgentContributions` in the `CombinerContributions` snapshot table. The combiner knows exactly what each agent has contributed. We need a way for the agent to ask the combiner "what are my current edits?" and get them back.

**Goal**: Implement `RFI EDITS` + `EDITS` message, modeled exactly on the existing `RFI KEYSTATE` + `KEYSTATE` pattern. Same two-phase approach: agent sends RFI, combiner responds with a separate message carrying the data, agent waits on a dedicated channel.

## Pattern Comparison

| Aspect | KEYSTATE (existing) | EDITS (new) |
|--------|-------------------|-------------|
| Initiator | Agent | Agent |
| Target | Signer | Combiner |
| RFI send | `sendRfiToSigner(zone, "KEYSTATE")` | `sendRfiToCombiner(zone, "EDITS")` |
| Response msg type | `"keystate"` | `"edits"` |
| Transport method | `DNSTransport.Keystate()` | `DNSTransport.Edits()` |
| Core payload struct | `AgentKeystatePost` | `AgentEditsPost` |
| DNS payload struct | `DnsKeystatePayload` | `DnsEditsPayload` |
| Handler (receiver) | `HandleKeystate` (agent router) | `HandleEdits` (agent router) |
| Router case | `routeKeystateMessage` | `routeEditsMessage` |
| MsgQs channel | `KeystateInventory` | `EditsResponse` |
| Wait function | `RequestAndWaitForKeyInventory` | `RequestAndWaitForEdits` |
| Combiner handler | — | `CombinerMsgHandler` RFI EDITS case |
| Combiner send fn | — | `sendEditsToAgent()` |
| Agent msg constant | `AgentMsgKeystate` | `AgentMsgEdits` |

## Message Flow

```
Agent                                    Combiner
  |                                         |
  |--- RFI (rfiType="EDITS") ------------->|  (via sendRfiToCombiner + SendSyncWithFallback)
  |                                         |
  |                                         |  CombinerMsgHandler: RFI case
  |                                         |  -> looks up AgentContributions[agentID]
  |                                         |  -> converts to records
  |                                         |
  |<-- EDITS message (records) ------------|  (via DNSTransport.Edits())
  |                                         |
  |  routeEditsMessage -> EditsResponse ch  |
  |  RequestAndWaitForEdits picks it up     |
  |  -> applies to SDE as confirmed         |
```

This mirrors the KEYSTATE flow exactly:

```
Agent                                    Signer
  |                                         |
  |--- RFI (rfiType="KEYSTATE") ---------->|  (via sendRfiToSigner + SendSyncWithFallback)
  |                                         |
  |<-- KEYSTATE message (inventory) -------|  (via DNSTransport.Keystate())
  |                                         |
  |  routeKeystateMessage -> KeystateInv ch |
  |  RequestAndWaitForKeyInventory picks up |
```

## Implementation Steps

### Step 1: Add `AgentMsgEdits` constant and `AgentEditsPost` struct

**File**: `core/messages.go`

Add constant:
```go
AgentMsgEdits    AgentMsg = "edits"
```

Add to `AgentMsgToString` map: `AgentMsgEdits: "EDITS"`.

Add payload struct (modeled on `AgentKeystatePost`):
```go
type AgentEditsPost struct {
    MessageType  AgentMsg           // AgentMsgEdits
    MyIdentity   string             // Combiner identity
    YourIdentity string             // Requesting agent identity
    Zone         string             // Zone (FQDN)
    Records      map[string][]string // Agent's current contributions (owner → []RR strings)
    Message      string             // Optional status message
    Time         time.Time          // Timestamp
}
```

Records use `map[string][]string` (owner → RR strings), consistent with the existing sync/update payload format used throughout the codebase.

### Step 2: Transport layer — `EditsRequest`, `EditsResponse`, `DNSTransport.Edits()`

**File**: `agent/transport/transport.go`

Add request/response types (modeled on `KeystateRequest`/`KeystateResponse`):
```go
type EditsRequest struct {
    SenderID  string               // Combiner identity
    Zone      string               // Zone (FQDN)
    Records   map[string][]string  // Agent's contributions (owner → []RR strings)
    Message   string               // Optional status
    Timestamp time.Time
}

type EditsResponse struct {
    ResponderID string
    Zone        string
    Accepted    bool
    Message     string
    Timestamp   time.Time
}
```

**File**: `agent/transport/dns.go`

Add `DnsEditsPayload` (modeled on `DnsKeystatePayload`):
```go
type DnsEditsPayload struct {
    MessageType  string              `json:"MessageType"`  // "edits"
    MyIdentity   string              `json:"MyIdentity"`
    YourIdentity string              `json:"YourIdentity"`
    Zone         string              `json:"Zone"`
    Records      map[string][]string `json:"Records,omitempty"`
    Message      string              `json:"Message,omitempty"`
    Timestamp    int64               `json:"timestamp"`
    // Legacy
    Type     string `json:"type"`
    SenderID string `json:"sender_id"`
}
```

Add `DNSTransport.Edits()` method (modeled on `DNSTransport.Keystate()`):
- Builds `core.AgentEditsPost` payload
- Marshals to JSON
- Calls `sendNotifyWithPayload(ctx, peer, qname, "edits", distributionID, payloadJSON, false)`
- Parses ACK via `extractEditsConfirmFromResponse()`
- Returns `EditsResponse`

### Step 3: Handler — `HandleEdits`

**File**: `agent/transport/handlers.go`

Add `HandleEdits` (modeled on `HandleKeystate`):
- Parse `DnsEditsPayload` from `ctx.ChunkPayload`
- Validate `MessageType == "edits"`
- Store as `ctx.Data["incoming_message"] = &IncomingMessage{Type: "edits", ...}`
- Return confirm ACK (same pattern as `HandleKeystate`)

**File**: `agent/transport/router_init.go`

- Register `HandleEdits` in `InitializeRouter` (agent router, alongside `HandleKeystate`)
- Add `"edits"` case to `DetermineMessageType()`

### Step 4: Agent-side routing — `routeEditsMessage`

**File**: `hsync_transport.go`

Add `"edits"` case to `routeIncomingMessage`:
```go
case "edits":
    tm.routeEditsMessage(msg)
```

Add `routeEditsMessage` (modeled on `routeKeystateMessage`):
- Parse `DnsEditsPayload` from `msg.Payload`
- Build `EditsResponseMsg` struct
- Send to `msgQs.EditsResponse` channel

**File**: `config.go` — Add `EditsResponse chan *EditsResponseMsg` to `MsgQs`

**File**: `agent_structs.go` — Add `EditsResponseMsg` struct and `AgentMsgEdits` alias

### Step 5: Combiner-side — handle RFI EDITS, send EDITS response

**File**: `agent/transport/router_init.go`

Register `HandleRfi` in `InitializeCombinerRouter` (currently only handles ping, beat, update — NOT rfi).

**File**: `combiner_msg_handler.go`

In `CombinerMsgHandler`, add RFI dispatch before the existing update processing:
```go
if msg.MessageType == AgentMsgRfi {
    switch msg.RfiType {
    case "EDITS":
        go sendEditsToAgent(conf, tm, senderID, zone)
    default:
        lgCombiner.Warn("Unknown RFI type", ...)
    }
    continue
}
```

Add `sendEditsToAgent` (modeled on `sendKeystateInventoryToAgent` in `signer_msg_handler.go`):
1. Look up `zd.AgentContributions[agentID]` for the zone
2. Convert `map[string]map[uint16]core.RRset` → `map[string][]string`
3. Look up agent peer in PeerRegistry
4. Send via `tm.DNSTransport.Edits(ctx, peer, req)`

Add `contributionsToRecords` helper for the conversion.

### Step 6: Agent-side — `sendRfiToCombiner` and `RequestAndWaitForEdits`

**File**: `hsync_transport.go`

Add `sendRfiToCombiner` (modeled on `sendRfiToSigner`):
- Uses `getCombinerID()` + `agentRegistry` + `SyncPeerFromAgent()` for peer lookup (unlike `sendRfiToSigner` which uses `signerAddress`)
- Sends `SyncRequest` with `MessageType: "rfi"`, `RfiType: rfiType`

**File**: `hsync_utils.go`

Add `RequestAndWaitForEdits` (modeled on `RequestAndWaitForKeyInventory`):
- Send RFI via `tm.sendRfiToCombiner(zone, "EDITS")`
- Wait on `msgQs.EditsResponse` with 15s timeout
- On receive: apply records to SDE

### Step 7: Apply received edits to SDE

The received records are the agent's own contributions as already accepted by the combiner. They should be imported into `ZoneDataRepo` as confirmed data (not queued for re-sending).

- Convert `map[string][]string` to per-owner per-rrtype entries
- Add to `ZoneDataRepo.Repo[zone].AgentRepo[localAgentID]`
- Set tracking state to `RRStateConfirmed`

### Step 8: Integrate into agent startup + CLI

Call `RequestAndWaitForEdits()` during agent startup, after transport is ready and combiner is reachable. Should happen alongside or after `RequestAndWaitForKeyInventory`.

Add `"EDITS"` to valid RFI types in `cli/agent_debug_cmds.go`.

## Files to Modify

| File | Change |
|------|--------|
| `core/messages.go` | Add `AgentMsgEdits` constant, `AgentEditsPost` struct |
| `agent/transport/transport.go` | Add `EditsRequest`, `EditsResponse` |
| `agent/transport/dns.go` | Add `DnsEditsPayload`, `DNSTransport.Edits()`, `extractEditsConfirmFromResponse` |
| `agent/transport/handlers.go` | Add `HandleEdits` |
| `agent/transport/router_init.go` | Register `HandleEdits` in agent router, `HandleRfi` in combiner router, `"edits"` in `DetermineMessageType` |
| `config.go` | Add `EditsResponse` channel to `MsgQs` |
| `agent_structs.go` | Add `EditsResponseMsg` struct, `AgentMsgEdits` alias |
| `hsync_transport.go` | Add `sendRfiToCombiner()`, `routeEditsMessage()`, `"edits"` case in `routeIncomingMessage` |
| `hsync_utils.go` | Add `RequestAndWaitForEdits()` |
| `combiner_msg_handler.go` | Add RFI EDITS handling, `sendEditsToAgent()`, `contributionsToRecords()` |
| `syncheddataengine.go` | Call `RequestAndWaitForEdits()` at startup |
| `cli/agent_debug_cmds.go` | Add `"EDITS"` to valid RFI types |

## Verification

1. **Build**: `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
2. **RFI send**: Agent sends `RFI EDITS` to combiner on startup — verify in combiner logs
3. **Combiner response**: Combiner looks up `AgentContributions[agentID]` and sends `EDITS` message — verify in logs
4. **Agent receive**: Agent receives on `EditsResponse` channel, applies to SDE — verify in agent logs
5. **End-to-end**: After agent restart, `agent debug zone <zone>` should show same local edits as before
6. **Empty case**: Agent with no prior contributions gets empty EDITS response (no error)
7. **CLI**: `agent debug rfi --rfi EDITS --zone <zone>` should work
