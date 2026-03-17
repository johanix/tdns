# RFI CONFIG Consolidation + Two-Phase Transport Fix

Date: 2026-03-12

## Problem

### 1. Data-returning RFIs broken over DNS transport

Agent-to-agent RFI messages that return data are broken over DNS transport.
The four affected RFI types are: UPSTREAM, DOWNSTREAM, CONFIG (sig0key), and AUDIT.

The root cause is a fundamental asymmetry in the DNS transport path:

1. When an RFI arrives via DNS, `HandleRfi()` sends the ACK **before** `MsgHandler`
   processes the request.
2. `RouteToMsgHandler` forwards the message to `incomingChan` with no Response channel
   (`AgentMsgPostPlus.Response` is nil).
3. `MsgHandler` processes the RFI and populates `resp.RfiResponse` with data, but the
   defer block checks `ampp.Response != nil` — it's nil, so the response is discarded.
4. Back on the sender side, `sendRfiToAgent()` constructs a bare `AgentMsgResponse` from
   the DNS ACK containing only `Status` and `Msg` — no `RfiResponse` map.

The DNS ACK succeeds without error, so the API transport fallback is never triggered.
The sender gets an empty `RfiResponse` and either reports confusing errors
("unexpected response format", "peer does not have SIG(0) key") or silently fails.

**Which RFI types work over DNS and which don't:**

| RFI Type    | Returns data? | Has side effects?           | Works over DNS? |
|-------------|---------------|-----------------------------|-----------------|
| SYNC        | No            | Yes (triggers resync)       | YES             |
| ELECT-*     | No            | Yes (broadcasts votes)      | YES             |
| UPSTREAM    | Yes           | No                          | NO — data lost  |
| DOWNSTREAM  | Yes           | No                          | NO — data lost  |
| CONFIG      | Yes           | No                          | NO — data lost  |
| AUDIT       | Yes           | No                          | NO — data lost  |

SYNC and ELECT-* work because their value is in the side effects, not in returned data.

### 2. UPSTREAM and DOWNSTREAM are misclassified

UPSTREAM and DOWNSTREAM are config data queries (XFR sources/destinations). They
should be subtypes of CONFIG, not separate RFI types. Having separate message types
for each config query doesn't scale — future config types (TSIG keys, etc.) would each
require new RFI types, handlers, CLI commands, and display logic.

The existing CONFIG subtype mechanism uses a hack: `Records["_subtype"]` carries the
subtype as a side-channel in the records map.

## Solution

### Part 1: Consolidate UPSTREAM + DOWNSTREAM into CONFIG subtypes

Add a proper `RfiSubtype` field to `AgentMsgPost` (and the transport structs that carry
it). Remove UPSTREAM and DOWNSTREAM as separate RFI types. They become CONFIG subtypes
`"upstream"` and `"downstream"`, alongside the existing `"sig0key"`.

This makes CONFIG extensible: adding a new config query (e.g., TSIG keys) means adding
a subtype string and a handler case, not a new message type.

### Part 2: Two-phase transport for CONFIG

Convert CONFIG from synchronous inline response to the two-phase pattern already used
by KEYSTATE (agent↔signer) and EDITS (agent↔combiner):

**Phase 1 (existing, unchanged):** Agent A sends RFI CONFIG → Agent B returns ACK.

**Phase 2 (new):** Agent B processes the request asynchronously, gathers the config
data, and sends it back as a separate `"config"` message (new DNS NOTIFY transaction).

**Waiting:** Agent A's `RequestAndWaitForConfig()` blocks on `MsgQs.ConfigResponse`
with a 15-second timeout.

This follows the EDITS pattern (shared MsgQs channel, no atomic pointer). CONFIG
responses are always solicited — the receiving agent never proactively pushes config
data — so a dedicated channel (like KEYSTATE's `keystateRfiChan`) is unnecessary.

### Part 3: Two-phase transport for AUDIT

Same two-phase pattern as CONFIG, but with its own message type (`"audit"`) and data
structure (`interface{}` instead of `map[string]string`). AUDIT content remains a
placeholder (zone data repo dump) — the transport mechanism is the fix.

## Message Flow: Before and After

### Before (broken over DNS)

```
Agent A                          Agent B
   |                                |
   |-- RFI CONFIG (DNS NOTIFY) ---->|
   |                                |-- HandleRfi: ACK "rfi received"
   |<---- DNS response (ACK) -------|
   |                                |-- RouteToMsgHandler → incomingChan
   |  sendRfiToAgent returns        |      (Response channel = nil)
   |  AgentMsgResponse{             |
   |    Status: "ok",               |-- MsgHandler processes CONFIG
   |    Msg: "rfi received",        |   populates resp.RfiResponse
   |    RfiResponse: nil ← LOST     |   ampp.Response == nil → DISCARDED
   |  }                             |
```

### After (two-phase, works over DNS)

```
Agent A                          Agent B
   |                                |
   |-- RFI CONFIG (DNS NOTIFY) ---->|
   |                                |-- HandleRfi: ACK "rfi received"
   |<---- DNS response (ACK) -------|
   |                                |-- RouteToMsgHandler → incomingChan
   |  RequestAndWaitForConfig()     |
   |  waiting on ConfigResponse     |-- MsgHandler dispatches:
   |  channel...                    |   go sendConfigToAgent(...)
   |                                |
   |                                |-- sendConfigToAgent gathers data
   |                                |-- DNSTransport.Config() sends
   |<- "config" msg (DNS NOTIFY) ---|   new transaction
   |                                |
   |  routeConfigMessage() →        |
   |  MsgQs.ConfigResponse          |
   |                                |
   |  RequestAndWaitForConfig()     |
   |  receives ConfigResponseMsg    |
```

## Implementation Steps

### Step 1: Add RfiSubtype + consolidate UPSTREAM/DOWNSTREAM

**Struct changes (additive, no existing fields modified):**
- `core/messages.go`: Add `RfiSubtype string` to `AgentMsgPost`
- `agent/transport/transport.go`: Add `RfiSubtype string` to `SyncRequest`
- `agent/transport/dns.go`: Add `RfiSubtype string` to `DnsSyncPayload`
- `agent_structs.go`: Add `RfiSubtype string` to `AgentMgmtPost`

**Propagation:**
- `agent/transport/dns.go` `Sync()`: carry `RfiSubtype` in payload
- `hsync_transport.go` `routeSyncMessage()`: propagate `payload.RfiSubtype`
- `hsyncengine.go` `sendRfiToAgent()`: carry `RfiSubtype` into `SyncRequest`

**Handler consolidation (only touches broken code):**
- `hsyncengine.go` `MsgHandler`: Remove `case "UPSTREAM"` and `case "DOWNSTREAM"`.
  In `case "CONFIG"`: switch on `ampp.RfiSubtype` (not `Records["_subtype"]`).
  Add `"upstream"` and `"downstream"` sub-cases with moved logic.
- `hsyncengine.go` `CommandHandler`: Remove UPSTREAM/DOWNSTREAM cases. Add CONFIG
  case that routes to target(s) based on `RfiSubtype`.

**CLI:**
- `cli/agent_debug_cmds.go`: Valid types = CONFIG, SYNC, AUDIT, EDITS.
  Add `--subtype` flag (required for CONFIG).

**Internal callers:**
- `main_initfuncs.go` `onLeaderElected`: Use `RfiSubtype: "sig0key"` instead of
  `Records["_subtype"]` hack.

### Step 2: Two-phase CONFIG transport

**New message type and structs:**
- `core/messages.go`: `AgentMsgConfig = "config"`, `AgentConfigPost` struct
- `config.go`: `ConfigResponse chan *ConfigResponseMsg` in MsgQs, `ConfigResponseMsg`
- `agent/transport/transport.go`: `ConfigRequest`, `ConfigResponse`

**DNS transport:**
- `agent/transport/dns.go`: `DnsConfigPayload`, `DNSTransport.Config()` method

**Handler + router:**
- `agent/transport/handlers.go`: `HandleConfig` (modeled on HandleEdits)
- `agent/transport/router_init.go`: Register in `DetermineMessageType` + agent router

**Routing:**
- `hsync_transport.go`: `routeConfigMessage()` → `MsgQs.ConfigResponse`
- `hsync_transport.go`: `sendConfigToAgent()` — gathers data, sends via Config()

**Two-phase wiring:**
- `hsyncengine.go` MsgHandler CONFIG: dispatch `go sendConfigToAgent(...)` async
- `hsync_utils.go`: `RequestAndWaitForConfig()` — send RFI + wait on channel
- `hsyncengine.go` CommandHandler CONFIG: use RequestAndWaitForConfig
- `main_initfuncs.go` onLeaderElected: use RequestAndWaitForConfig
- `main_initfuncs.go`: Init `ConfigResponse: make(chan *ConfigResponseMsg, 10)`

### Step 3: Two-phase AUDIT transport

Same pattern as Step 2 but for AUDIT:
- `core/messages.go`: `AgentMsgAudit = "audit"`, `AgentAuditPost`
- `config.go`: `AuditResponse chan *AuditResponseMsg`, `AuditResponseMsg`
- `agent/transport/`: `DnsAuditPayload`, `DNSTransport.Audit()`, `HandleAudit`
- `hsync_transport.go`: `routeAuditMessage()`, `sendAuditToAgent()`
- `hsync_utils.go`: `RequestAndWaitForAudit()`
- `hsyncengine.go`: Wire up MsgHandler + CommandHandler
- `main_initfuncs.go`: Init `AuditResponse: make(chan *AuditResponseMsg, 10)`

## Risk Assessment

**No working message paths are modified.** SYNC, ELECT-*, KEYSTATE, EDITS are untouched.
All changes remove/modify broken code or add new code.

**Channel contention (Step 2):** Multiple concurrent CONFIG requests share one
`MsgQs.ConfigResponse` channel. Mitigated: `onLeaderElected` already iterates peers
sequentially. CLI sends to one peer at a time. No concurrent waiters in practice.

**Reverse peer resolution (Step 2):** `sendConfigToAgent()` must resolve the RFI
originator's identity to a Peer and send a CONFIG message back. Agents have symmetric
peer relationships, so this should work. Needs verification on test VMs.

## Implementation Status

All three steps implemented and building (2026-03-12):
- **Step 1** (DONE): RfiSubtype field + UPSTREAM/DOWNSTREAM consolidated into CONFIG subtypes
- **Step 2** (DONE): Two-phase CONFIG transport (config message type, channel, handler, routing)
- **Step 3** (DONE): Two-phase AUDIT transport (audit message type, channel, handler, routing)

Functional testing on test VMs still needed.

## Existing Patterns Referenced

- **EDITS two-phase pattern**: `sendRfiToCombiner()` → `sendEditsToAgent()` →
  `routeEditsMessage()` → `MsgQs.EditsResponse` → `RequestAndWaitForEdits()`
- **KEYSTATE two-phase pattern**: `sendRfiToSigner()` → `sendKeystateInventoryToAgent()`
  → `routeKeystateMessage()` → `keystateRfiChan` → `RequestAndWaitForKeyInventory()`
- CONFIG follows the EDITS pattern (shared channel, no atomic pointer)
