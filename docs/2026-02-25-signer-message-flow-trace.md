# Signer Message Flow Trace

## Overview
This document traces the detailed path for incoming PING, BEAT, and SYNC messages in the **signer** role (tdns-auth), from when they arrive in the DnsEngine to when responses are sent out.

## Architectural Context

The signer role uses the same **DNSMessageRouter** and **ChunkNotifyHandler** infrastructure as the agent and combiner, but with key differences:
- **No AgentQs**: The signer doesn't have agent queues or hsyncengine routing
- **Synchronous processing**: Messages are handled immediately by router handlers
- **Limited message types**: Only handles PING and KEYSTATE (as of Phase 6)
- **No BEAT/SYNC routing**: These handlers exist in the router but have no downstream processing

---

## Message Flow Trace

### Common Entry Path (All Message Types)

#### 1. DNS Server (DnsEngine) Receives UDP Packet
**File**: `v2/do53.go:212-269`
```
DNS packet arrives → ServeDNS handler
├─ Opcode check: dns.OpcodeNotify
├─ Extract qtype from Question[0]
└─ Look up registered NOTIFY handlers: getNotifyHandlers(conf, qtype)
```

#### 2. NOTIFY Handler Dispatch
**File**: `v2/do53.go:221-240`
```
handlers := getNotifyHandlers(conf, qtype)  // qtype = TypeCHUNK (65400)
├─ Registered via: RegisterNotifyHandler(core.TypeCHUNK, handler)
└─ Call handler(ctx, &DnsNotifyRequest{...})
```

**Registration**: `v2/signer_transport.go:36`
```go
RegisterNotifyHandler(core.TypeCHUNK, handler.CreateNotifyHandlerFunc())
```

#### 3. CombinerChunkHandler Entry Point
**File**: `v2/combiner_chunk.go:121`
```
CreateNotifyHandlerFunc() returns: func(ctx, req) → RouteViaRouter()
├─ Adapts tdns.NotifyHandlerFunc signature
└─ Routes to ChunkNotifyHandler.RouteViaRouter()
```

#### 4. ChunkNotifyHandler.RouteViaRouter()
**File**: `v2/agent/transport/chunk_notify_handler.go:331-471`

This is the **critical routing junction** where all CHUNK messages are processed:

```
RouteViaRouter(ctx, qname, msg, responseWriter)
├─ 1. Extract distribution ID from QNAME
│     ├─ Format: {receiver}.{distid}.{sender}.{control-zone}
│     └─ Example: "signer.abc123.agent.example.com."
│
├─ 2. Extract sender hint from QNAME (for key selection)
│     └─ Used for decryption: identifies which peer's key to use
│
├─ 3. Extract CHUNK payload
│     ├─ Try EDNS0 option (edns0 mode)
│     └─ Or fetch via CHUNK query (query mode)
│
├─ 4. Decrypt payload (if SecureWrapper configured)
│     ├─ Use sender's verification key (strict)
│     ├─ On missing key → trigger discovery (OnPeerDiscoveryNeeded)
│     └─ On failure → REFUSED (prevents forgery)
│
├─ 5. Parse payload to normalize format
│     └─ parsePayload() → IncomingMessage{Type, SenderID, Zone, Payload}
│
├─ 6. Create MessageContext
│     ├─ DistributionID: from QNAME
│     ├─ PeerID: sender hint
│     ├─ ChunkPayload: decrypted payload (plaintext)
│     ├─ SignatureValid: true (verified during decrypt)
│     └─ Data map:
│         ├─ "local_id": h.LocalID
│         ├─ "transport": h.Transport
│         ├─ "incoming_message": parsed IncomingMessage
│         └─ "zone": extracted from payload
│
└─ 7. Route through Router + Middleware
      └─ SendResponseMiddleware wraps: h.Router.Route(ctx, msgType)
```

---

### Signer Router Initialization

**File**: `v2/main_initfuncs.go:420-469`
```
MainInit (multi-provider mode active)
├─ Initialize signer crypto (PayloadCrypto)
│     ├─ Load signer's JOSE private key
│     ├─ Derive public key
│     └─ Load agent's public key (for verification)
│
├─ Create DNSMessageRouter
│     └─ signerRouter := transport.NewDNSMessageRouter()
│
├─ Initialize router with middleware & handlers
│     └─ transport.InitializeSignerRouter(signerRouter, config)
│
└─ Register CHUNK handler
      └─ RegisterSignerChunkHandler(mp.Identity, signerRouter)
```

**File**: `v2/agent/transport/router_init.go:314-360`
```
InitializeSignerRouter(router, cfg)
├─ Middleware registration (in order):
│     ├─ 1. SignatureMiddleware (crypto verification)
│     └─ 2. LoggingMiddleware (visibility)
│
└─ Handler registration:
      ├─ PingHandler (MessageType "ping")
      └─ KeystateHandler (MessageType "keystate")

Note: NO RouteToHsyncEngine middleware (signer has no AgentQs)
Note: NO authorization middleware (added separately if needed)
```

---

## Individual Message Type Traces

### PING Message Flow

#### Router Dispatch
```
h.Router.Route(ctx, MessageType("ping"))
├─ Middleware chain execution:
│     ├─ SignatureMiddleware (already done in RouteViaRouter)
│     └─ LoggingMiddleware
│
└─ Handler execution: HandlePing(ctx)
```

#### HandlePing Handler
**File**: `v2/agent/transport/handlers.go:63-114`

```
HandlePing(ctx *MessageContext)
├─ 1. Get pre-parsed message from ctx.Data["incoming_message"]
│
├─ 2. Parse ping payload
│     └─ Unmarshal DnsPingPayload{Type, SenderID, Nonce, ...}
│
├─ 3. Validate
│     ├─ Check message type == "ping"
│     └─ Check nonce != ""
│
├─ 4. Create confirmation response
│     └─ DnsPingConfirmPayload{
│           Type: "ping_confirm",
│           SenderID: localID,
│           Nonce: echoed,
│           DistributionID: ctx.DistributionID,
│           Status: "ok",
│           Timestamp: now
│        }
│
└─ 5. Store response in context
      ├─ ctx.Data["ping_response"] = confirmPayload
      └─ ctx.Data["ping_nonce"] = ping.Nonce
```

#### Response Sending
**File**: `v2/agent/transport/chunk_notify_handler.go:460-463`
```
SendResponseMiddleware wraps router execution
├─ After handler returns: middleware sends DNS response
│     ├─ Encrypt ping_response payload (if crypto enabled)
│     └─ Package in EDNS0 option or prepare for CHUNK query fetch
│
└─ Send DNS NOTIFY response (NOERROR)
      └─ ResponseWriter.WriteMsg(response)
```

**Flow Summary (PING)**:
```
UDP packet → DnsEngine → RegisteredNotifyHandler → ChunkNotifyHandler.RouteViaRouter()
  → Decrypt → Router.Route("ping") → HandlePing → Create confirm payload
  → SendResponseMiddleware → Encrypt confirm → DNS response sent
```

---

### BEAT Message Flow

#### Entry & Routing
```
Same as PING up to Router.Route(ctx, MessageType("beat"))
```

#### HandleBeat Handler
**File**: `v2/agent/transport/handlers.go:146-191`

```
HandleBeat(ctx *MessageContext)
├─ 1. Get pre-parsed message from ctx.Data["incoming_message"]
│
├─ 2. Validate message type == "beat"
│
├─ 3. Store for routing (but signer has NO AgentQs!)
│     ├─ ctx.Data["message_type"] = "beat"
│     └─ ctx.Data["incoming_message"] = beatMsg
│
├─ 4. Create confirmation response
│     └─ confirm{Type: "confirm", DistributionID, Status: "ok", Message: "beat acknowledged"}
│
└─ 5. Store response in context
      └─ ctx.Data["sync_response"] = confirmPayload
```

**⚠️ ARCHITECTURAL ISSUE**:
- The handler stores data for hsyncengine routing
- But the **signer has no RouteToHsyncEngine middleware**
- Beat messages are acknowledged but **NOT processed further**
- No state updates, no peer tracking, no beat interval tracking

**Flow Summary (BEAT)**:
```
UDP packet → DnsEngine → RegisteredNotifyHandler → ChunkNotifyHandler.RouteViaRouter()
  → Decrypt → Router.Route("beat") → HandleBeat → Create confirm payload
  → SendResponseMiddleware → Encrypt confirm → DNS response sent

⚠️ Message is acknowledged but NOT routed to any processing engine!
```

---

### SYNC Message Flow

#### Entry & Routing
```
Same as PING up to Router.Route(ctx, MessageType("sync"))
```

#### Handler Registration Status
**⚠️ CRITICAL ARCHITECTURAL ISSUE**:

```
InitializeSignerRouter() registers:
├─ PingHandler ✓
└─ KeystateHandler ✓

But does NOT register:
├─ BeatHandler ✗
└─ SyncHandler ✗
```

**What Happens**:
```
h.Router.Route(ctx, MessageType("sync"))
└─ Router looks up handlers for MessageType("sync")
   └─ handlers map has NO entry for "sync"
      └─ Returns error: "no handlers registered for message type sync"
         └─ RouteViaRouter logs: "Routing failed"
            └─ Sends DNS response: RcodeServerFailure
```

**Flow Summary (SYNC)**:
```
UDP packet → DnsEngine → RegisteredNotifyHandler → ChunkNotifyHandler.RouteViaRouter()
  → Decrypt → Router.Route("sync") → NO HANDLER FOUND
  → Error: "no handlers registered for message type sync"
  → DNS response: SERVFAIL
```

---

## Response Path (All Message Types)

### SendResponseMiddleware
**File**: Location not specified in the trace, but called at `chunk_notify_handler.go:460`

```
After handler execution:
├─ Check for response payload in ctx.Data
│     ├─ "ping_response" (for ping)
│     └─ "sync_response" (for beat/sync/confirm)
│
├─ Encrypt payload (if crypto enabled)
│     └─ SecureWrapper.WrapOutgoing(payload)
│
├─ Package response
│     ├─ EDNS0 mode: Add EDNS0 option with encrypted payload
│     └─ Query mode: Store for later CHUNK query fetch
│
└─ Send DNS response
      ├─ Create DNS message: msg.SetReply(request)
      ├─ Set rcode: NOERROR (success)
      └─ ResponseWriter.WriteMsg(msg)
```

---

## Summary of Architectural Issues

### 1. **Inconsistent Handler Registration**
```
Agent Router:      Ping ✓  Beat ✓  Sync ✓  Hello ✓  Relocate ✓  RFI ✓  Keystate ✓
Combiner Router:   Ping ✓  Beat ✓  Sync ✓  (others N/A)
Signer Router:     Ping ✓  Beat ✗  Sync ✗  Keystate ✓

⚠️ Signer router is MISSING Beat and Sync handlers!
```

### 2. **Message Path Asymmetry**

**Incoming Messages** (via CHUNK NOTIFY):
```
Agent:    CHUNK → Router → Handler → RouteToHsyncEngine → AgentQs → Processing
Combiner: CHUNK → Router → Handler → Inline processing (no queues)
Signer:   CHUNK → Router → Handler → ❌ NOTHING (no downstream processing)
```

**Outgoing Messages** (via TransportManager):
```
Agent:    Processing → TransportManager → DNSTransport.Send() → CHUNK NOTIFY
Combiner: Processing → (no outbound transport in combiner role)
Signer:   Processing → TransportManager → DNSTransport.Send() → CHUNK NOTIFY
```

### 3. **Router Handler Behavior Mismatch**
```
HandleBeat in Agent:
  ├─ Store in ctx.Data for routing
  ├─ Create confirm response
  └─ RouteToHsyncEngine middleware → AgentQs.Beat channel → hsyncengine

HandleBeat in Signer:
  ├─ Store in ctx.Data for routing (but NO RouteToHsyncEngine middleware!)
  ├─ Create confirm response
  └─ ❌ Data stored in context is NEVER consumed

Same handler function, different middleware chains = different behavior!
```

### 4. **Missing Processing for BEAT Messages**
When agent sends BEAT to signer:
```
✓ Message received
✓ Decrypted
✓ Routed to handler
✓ Confirmation sent
✗ No peer state tracking
✗ No liveness monitoring
✗ No beat interval enforcement
```

### 5. **SYNC Messages Completely Rejected**
When agent sends SYNC to signer:
```
✓ Message received
✓ Decrypted
✗ No handler registered
✗ Router returns error
✗ SERVFAIL sent to sender
```

This is likely intentional (signer shouldn't receive sync from agent in multi-signer architecture), but the error handling is poor.

---

## Recommendations

### 1. **Clarify Message Type Support Per Role**
Document which message types each role supports:
```
Agent Role (receives):    HELLO, BEAT, SYNC, RFI, RELOCATE, CONFIRM, PING
Combiner Role (receives): PING, BEAT, SYNC
Signer Role (receives):   PING, KEYSTATE (only)
```

### 2. **Consistent Error Handling for Unsupported Messages**
Instead of "no handlers registered" error, handle gracefully:
```go
// In signer router init, register a "not supported" handler:
router.Register("UnsupportedMessageHandler", MessageType("sync"),
    func(ctx *MessageContext) error {
        log.Printf("Signer: Sync messages not supported, ignoring")
        return nil // Send success but don't process
    })
```

### 3. **Unified Handler/Middleware Architecture**
Create role-aware middleware:
```go
router.Use(RoleAwareRoutingMiddleware(role))
// Conditionally routes to AgentQs, inline processing, or drops based on role
```

### 4. **Explicit Message Routing Strategy**
Define a routing strategy matrix:
```
Message | Agent Incoming  | Combiner Incoming | Signer Incoming
--------|-----------------|-------------------|------------------
PING    | Respond inline  | Respond inline    | Respond inline
BEAT    | Route to engine | Respond inline    | ❌ Reject
SYNC    | Route to engine | Process inline    | ❌ Reject
KEYSTATE| Route to engine | ❌ Reject         | Process inline
```

### 5. **Separate Handler Implementations**
Instead of reusing agent handlers with different middleware:
```
HandlePing        → Shared (all roles)
HandleBeatAgent   → Agent-specific (routes to engine)
HandleBeatCombiner→ Combiner-specific (inline processing)
HandleSyncAgent   → Agent-specific (routes to engine)
HandleSyncCombiner→ Combiner-specific (inline processing)
```

---

## Current Status (Phase 6)

### Working:
- ✅ Signer receives PING, responds correctly
- ✅ Signer receives KEYSTATE (agent→signer), processes correctly
- ✅ Signer sends KEYSTATE to agent (when DNSKEY propagation confirmed)
- ✅ Encryption/decryption works for all message types
- ✅ Authorization (if configured) works

### Broken/Inconsistent:
- ❌ Signer rejects BEAT messages (no handler)
- ❌ Signer rejects SYNC messages (no handler)
- ⚠️ HandleBeat stores data that's never consumed (in agent/combiner contexts)
- ⚠️ No documentation of supported message types per role

### Design Questions:
1. **Should signer accept BEAT from agent?** (Probably not needed for key lifecycle)
2. **Should signer accept SYNC from agent?** (Definitely not in RFC 8901 architecture)
3. **Should missing handlers be silent (ignore) or loud (SERVFAIL)?**
4. **Should we unify handler logic or split into role-specific implementations?**

---

## File Reference Index

| Component | File | Line Range |
|-----------|------|------------|
| DNS Server Entry | v2/do53.go | 212-269 |
| NOTIFY Handler Registration | v2/registration.go | 145-168 |
| Signer Handler Setup | v2/signer_transport.go | 24-36 |
| ChunkNotifyHandler Routing | v2/agent/transport/chunk_notify_handler.go | 331-471 |
| Router Initialization (Signer) | v2/agent/transport/router_init.go | 314-360 |
| Ping Handler | v2/agent/transport/handlers.go | 63-114 |
| Beat Handler | v2/agent/transport/handlers.go | 146-191 |
| Sync Handler | v2/agent/transport/handlers.go | 194-243 |
| Keystate Handler | v2/agent/transport/handlers.go | 290-360 |
| Signer Main Init | v2/main_initfuncs.go | 420-469 |
| Message Router | v2/agent/transport/dns_message_router.go | 97-383 |

