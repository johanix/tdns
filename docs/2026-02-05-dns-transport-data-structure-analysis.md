# DNS Transport Data Structure Analysis

**Date**: 2026-02-05
**Purpose**: Evaluate API transport data structures for DNS transport suitability
**Context**: Implementing agent state machine transitions over DNS-based CHUNK transport

---

## Executive Summary

The existing API transport uses **HTTP POST with JSON payloads** to send structured agent messages (Hello, Beat, Msg, etc.). DNS transport already has **parallel payload structures defined** in `agent/transport/dns.go` that are **mostly appropriate** but need enhancement to match API transport capabilities.

**Key Finding**: DNS payloads are **leaner** (exclude redundant discovery data) but **missing critical fields** needed for proper state machine operation.

---

## 1. API vs DNS Payload Comparison

### HELLO Message

**API Transport** (`AgentHelloPost` - agent_structs.go:169-178):
```go
type AgentHelloPost struct {
    MessageType  AgentMsg      // AgentMsgHello
    Name         string        // optional agent name
    MyIdentity   AgentId       // sender's identity (FQDN)
    YourIdentity AgentId       // recipient's identity (FQDN)
    Addresses    []string      // IPv4/IPv6 addresses for API
    Port         uint16        // API port
    TLSA         dns.TLSA      // TLS certificate record
    Zone         ZoneName      // zone triggering the HELLO
}
```

**DNS Transport** (`DnsHelloPayload` - agent/transport/dns.go:715-722):
```go
type DnsHelloPayload struct {
    Type         string   `json:"type"`           // "hello"
    SenderID     string   `json:"sender_id"`      // sender's identity
    Capabilities []string `json:"capabilities,omitempty"`
    SharedZones  []string `json:"shared_zones,omitempty"`
    Timestamp    int64    `json:"timestamp"`
    Nonce        string   `json:"nonce,omitempty"`
}
```

**Analysis**:
- ✅ **Appropriate**: `SenderID` (identity), `SharedZones` (multi-zone support), `Timestamp`
- ✅ **Better**: `Capabilities` (extensibility), `Nonce` (replay protection)
- ❌ **Missing**: `YourIdentity` (recipient verification), `Zone` (single-zone trigger)
- ❌ **Unnecessary in DNS**: `Addresses`, `Port`, `TLSA` (redundant with DNS discovery)

**Recommendation**:
- **Keep**: Lean structure without discovery data (DNS provides this)
- **Add**: `RecipientID` field for mutual identity verification
- **Keep**: `SharedZones` as array (more flexible than single `Zone`)
- **Consider**: Do we need `Capabilities` for version negotiation?

---

### BEAT (Heartbeat) Message

**API Transport** (`AgentBeatPost` - agent_structs.go:145-152):
```go
type AgentBeatPost struct {
    MessageType    AgentMsg      // AgentMsgBeat
    MyIdentity     AgentId       // sender's identity
    YourIdentity   AgentId       // recipient's identity
    MyBeatInterval uint32        // intended heartbeat interval in seconds
    Zones          []string      // zones shared with remote agent
    Time           time.Time     // beat timestamp
}
```

**DNS Transport** (`DnsBeatPayload` - agent/transport/dns.go:725-731):
```go
type DnsBeatPayload struct {
    Type      string `json:"type"`        // "beat"
    SenderID  string `json:"sender_id"`   // sender's identity
    Timestamp int64  `json:"timestamp"`   // Unix timestamp
    Sequence  uint64 `json:"sequence"`    // beat sequence number
    State     string `json:"state,omitempty"` // optional state info
}
```

**Analysis**:
- ✅ **Appropriate**: `SenderID`, `Timestamp`, `Sequence` (ordering/dedup)
- ✅ **Better**: `Sequence` number (not in API version - useful for detecting packet loss)
- ❌ **Missing**: `RecipientID` (mutual verification)
- ❌ **Missing**: `MyBeatInterval` (tells recipient how often to expect beats)
- ❌ **Missing**: `Zones` (context for which zones this beat covers)
- ❓ **Unclear**: What is `State` field for? Agent state? Transport state?

**Recommendation**:
- **Add**: `RecipientID` for consistency
- **Add**: `BeatInterval` (critical for health monitoring)
- **Add**: `SharedZones` array (zone context)
- **Keep**: `Sequence` (better than API version)
- **Clarify**: `State` field purpose or remove if unused

---

### SYNC/MSG Message

**API Transport** (`AgentMsgPost` - agent_structs.go:192-205):
```go
type AgentMsgPost struct {
    MessageType  AgentMsg      // NOTIFY | RFI | STATUS
    MyIdentity   AgentId
    YourIdentity AgentId
    Addresses    []string      // ❌ Redundant
    Port         uint16        // ❌ Redundant
    TLSA         dns.TLSA      // ❌ Redundant
    Zone         ZoneName      // Single zone per message
    RRs          []string      // RR strings (dns.RR cannot be JSON marshalled)
    Time         time.Time
    RfiType      string        // "UPSTREAM" | "DOWNSTREAM"
}
```

**DNS Transport** (`DnsSyncPayload` - agent/transport/dns.go:734-743):
```go
type DnsSyncPayload struct {
    Type          string   `json:"type"`         // "sync"
    SenderID      string   `json:"sender_id"`
    Zone          string   `json:"zone"`
    SyncType      string   `json:"sync_type"`    // similar to RfiType?
    Records       []string `json:"records"`      // RR strings
    Serial        uint32   `json:"serial"`       // SOA serial
    CorrelationID string   `json:"correlation_id"` // request/response matching
    Timestamp     int64    `json:"timestamp"`
}
```

**Analysis**:
- ✅ **Appropriate**: `SenderID`, `Zone`, `Records`, `Timestamp`
- ✅ **Better**: `Serial` (SOA tracking), `CorrelationID` (request/response matching)
- ✅ **Cleaner**: No redundant `Addresses`, `Port`, `TLSA`
- ❌ **Missing**: `RecipientID` (consistency)
- ❓ **Unclear**: Is `SyncType` equivalent to API's `RfiType`? Need alignment.

**Recommendation**:
- **Keep**: Current structure is good
- **Add**: `RecipientID` for consistency
- **Align**: `SyncType` values with API's message types (NOTIFY, RFI, STATUS)
- **Keep**: `CorrelationID` (critical for async operations)

---

### PING Message

**API Transport**: No dedicated PING operation (uses BEAT for liveness)

**DNS Transport** (`DnsPingPayload` - agent/transport/dns.go:774-779):
```go
type DnsPingPayload struct {
    Type      string `json:"type"`
    SenderID  string `json:"sender_id"`
    Nonce     string `json:"nonce"`
    Timestamp int64  `json:"timestamp"`
}
```

**Analysis**:
- ✅ **New capability**: DNS transport adds explicit PING/PONG
- ✅ **Good design**: `Nonce` for round-trip verification
- ❌ **Missing**: `RecipientID` (consistency)

**Recommendation**:
- **Keep**: Useful for one-shot connectivity tests (distinct from periodic BEAT)
- **Add**: `RecipientID`
- **Use case**: User-initiated `agent distrib op ping` vs automatic heartbeat (beat)

---

## 2. Response/Acknowledgment Structures

### API Transport Responses

**HelloResponse** (agent_structs.go:180-189):
```go
type AgentHelloResponse struct {
    Status       string      // "ok" | "error"
    MyIdentity   AgentId     // responder's identity
    YourIdentity AgentId     // original sender
    Time         time.Time
    Msg          string
    Error        bool
    ErrorMsg     string
}
```

**BeatResponse** (agent_structs.go:154-163):
```go
type AgentBeatResponse struct {
    Status       string
    MyIdentity   AgentId
    YourIdentity AgentId
    Time         time.Time
    Client       string      // optional client name
    Msg          string
    Error        bool
    ErrorMsg     string
}
```

### DNS Transport Responses

**DnsConfirmPayload** (agent/transport/dns.go:763-771):
```go
type DnsConfirmPayload struct {
    Type          string `json:"type"`       // "confirm"
    SenderID      string `json:"sender_id"`   // responder
    Zone          string `json:"zone"`
    CorrelationID string `json:"correlation_id"`
    Status        string `json:"status"`      // "ok" | "error"
    Message       string `json:"message,omitempty"`
    Timestamp     int64  `json:"timestamp"`
}
```

**Analysis**:
- ✅ **Appropriate**: `CorrelationID` (matches async request/response)
- ✅ **Good**: `Status` + `Message` (similar to API's `Error` + `ErrorMsg`)
- ❌ **Missing**: `RecipientID` (original sender)
- ❓ **Unclear**: Is one `DnsConfirmPayload` used for all response types (Hello, Beat, Sync)?

**Recommendation**:
- **Option A**: Use generic `DnsConfirmPayload` for all operations (current approach)
  - Pro: Simple, one structure
  - Con: May need operation-specific response data later
- **Option B**: Create specific response types (`DnsHelloConfirm`, `DnsBeatConfirm`, etc.)
  - Pro: Type safety, operation-specific fields
  - Con: More structs to maintain
- **Suggest**: Start with generic, split if needed

---

## 3. Critical Missing Fields Across All Messages

### Recipient Identity Verification

**Problem**: API transport includes `YourIdentity` in requests and responses for **mutual verification**:
```go
MyIdentity:   AgentId("agent.alpha.dnslab.")
YourIdentity: AgentId("agent.beta.dnslab.")
```

**Current DNS**: Only `SenderID` included, no recipient verification

**Security Risk**:
- Sender can craft message to wrong recipient
- Recipient cannot verify message was intended for them
- MITM could redirect messages

**Recommendation**: **Add `RecipientID` to all DNS payload types**

### Beat Interval Communication

**Problem**: API transport includes `MyBeatInterval` so recipient knows **expected heartbeat frequency**:
```go
MyBeatInterval: 30  // expect beat every 30 seconds
```

**Current DNS**: Missing - recipient doesn't know when to expect next beat

**Impact**:
- Cannot accurately detect DEGRADED state (2x interval exceeded)
- Cannot accurately detect INTERRUPTED state (10x interval exceeded)
- Health monitoring broken

**Recommendation**: **Add `BeatInterval` to `DnsBeatPayload`**

### Shared Zones Context

**Problem**: API transport includes `Zones` array in BEAT to communicate **zone collaboration context**

**Current DNS**: Missing from `DnsBeatPayload`

**Impact**:
- Recipient doesn't know which zones the beat covers
- Cannot associate beat with specific zone operations
- Harder to debug multi-zone scenarios

**Recommendation**: **Add `SharedZones` to `DnsBeatPayload`**

---

## 4. Redundant Fields in API Transport

### Discovery Data in Messages

**API Transport includes**:
- `Addresses []string` - IP addresses
- `Port uint16` - service port
- `TLSA dns.TLSA` - TLS certificate

**Problem**: These fields are **redundant** because:
1. This data comes from DNS discovery (SVCB, URI, TLSA records)
2. Including it in every message wastes bandwidth
3. Could create inconsistency (message data ≠ DNS data)

**DNS Transport correctly omits these** - receiver uses discovery data

**Recommendation**: **Do NOT add these to DNS payloads**

---

## 5. New Capabilities in DNS Transport

### Sequence Numbers

**DnsBeatPayload** includes:
```go
Sequence uint64 `json:"sequence"`
```

**Benefit**:
- Detect lost/duplicate packets
- Detect out-of-order delivery
- Better than API version which only has timestamp

**Recommendation**: **Keep and use for reliability**

### Correlation IDs

**DNS payloads** include:
```go
CorrelationID string `json:"correlation_id"`
```

**Benefit**:
- Match async requests with responses
- Handle concurrent operations
- Essential for DNS (no HTTP session context)

**Recommendation**: **Keep - critical for DNS transport**

### Nonce for Replay Protection

**DnsPingPayload** and **DnsHelloPayload** include:
```go
Nonce string `json:"nonce"`
```

**Benefit**:
- Prevent replay attacks
- Verify round-trip (nonce echoed in response)
- More secure than timestamp-only

**Recommendation**: **Keep and consider adding to other message types**

---

## 6. State Machine Integration

### Current State Tracking

**API Transport**:
- State stored in `agent.ApiDetails.State`
- Updated in response handlers (HelloHandler, HeartbeatHandler)
- Transitions: KNOWN→INTRODUCED (hello) → OPERATIONAL (beat)

**DNS Transport**:
- Partial implementation exists (routeHelloMessage updates state)
- **Missing**: Beat handler state transition
- **Missing**: Health monitoring (DEGRADED/INTERRUPTED)

### Required Message Flow

```
1. Discovery (DNS queries) → NEEDED → KNOWN
   ↓
2. Send Hello (DnsHelloPayload) → Wait for DnsConfirmPayload
   ↓ (if accepted)
3. State: KNOWN → INTRODUCED
   ↓
4. Send Beat (DnsBeatPayload) → Wait for DnsConfirmPayload
   ↓ (first success)
5. State: INTRODUCED → OPERATIONAL
   ↓
6. Periodic Beats + CheckState()
   - Healthy: OPERATIONAL
   - 2x late: DEGRADED
   - 10x late: INTERRUPTED
```

### What DNS Payloads Need

To support this flow, DNS payloads must include:

**In DnsHelloPayload**:
- `RecipientID` - verify we're talking to the right agent
- `SharedZones` - ✅ already present

**In DnsBeatPayload**:
- `RecipientID` - mutual verification
- `BeatInterval` - expected heartbeat frequency (for health checks)
- `SharedZones` - zone context
- `Sequence` - ✅ already present (better than API)

**In DnsConfirmPayload** (response):
- `RecipientID` - echo original sender
- `CorrelationID` - ✅ already present
- `Status` - ✅ already present

---

## 7. Recommended Payload Updates

### DnsHelloPayload (Updated)

```go
type DnsHelloPayload struct {
    Type         string   `json:"type"`            // "hello"
    SenderID     string   `json:"sender_id"`       // sender's identity (FQDN)
    RecipientID  string   `json:"recipient_id"`    // ← ADD: recipient verification
    Capabilities []string `json:"capabilities,omitempty"`
    SharedZones  []string `json:"shared_zones"`    // zones we share
    Timestamp    int64    `json:"timestamp"`
    Nonce        string   `json:"nonce,omitempty"`
}
```

**Changes**:
- **ADD**: `RecipientID` for mutual identity verification

---

### DnsBeatPayload (Updated)

```go
type DnsBeatPayload struct {
    Type         string   `json:"type"`         // "beat"
    SenderID     string   `json:"sender_id"`    // sender's identity
    RecipientID  string   `json:"recipient_id"` // ← ADD: recipient verification
    BeatInterval uint32   `json:"beat_interval"` // ← ADD: expected beat frequency (seconds)
    SharedZones  []string `json:"shared_zones"` // ← ADD: zone context
    Timestamp    int64    `json:"timestamp"`
    Sequence     uint64   `json:"sequence"`
    State        string   `json:"state,omitempty"` // Remove or clarify purpose
}
```

**Changes**:
- **ADD**: `RecipientID` for consistency
- **ADD**: `BeatInterval` (critical for health monitoring)
- **ADD**: `SharedZones` for zone context
- **KEEP**: `Sequence` (better than API version)
- **REVIEW**: `State` field - clarify or remove

---

### DnsSyncPayload (Updated)

```go
type DnsSyncPayload struct {
    Type          string   `json:"type"`          // "sync"
    SenderID      string   `json:"sender_id"`
    RecipientID   string   `json:"recipient_id"`  // ← ADD: consistency
    Zone          string   `json:"zone"`
    SyncType      string   `json:"sync_type"`     // "NOTIFY" | "RFI" | "STATUS"
    Records       []string `json:"records"`
    Serial        uint32   `json:"serial"`
    CorrelationID string   `json:"correlation_id"`
    Timestamp     int64    `json:"timestamp"`
}
```

**Changes**:
- **ADD**: `RecipientID`
- **ALIGN**: `SyncType` values with API message types

---

### DnsConfirmPayload (Updated)

```go
type DnsConfirmPayload struct {
    Type          string `json:"type"`          // "confirm"
    SenderID      string `json:"sender_id"`      // responder's identity
    RecipientID   string `json:"recipient_id"`   // ← ADD: original sender (echo)
    OperationType string `json:"operation_type"` // ← ADD: "hello"|"beat"|"sync"
    CorrelationID string `json:"correlation_id"` // matches request
    Status        string `json:"status"`         // "ok" | "error" | "rejected"
    Message       string `json:"message,omitempty"`
    Timestamp     int64  `json:"timestamp"`
}
```

**Changes**:
- **ADD**: `RecipientID` (echo original sender)
- **ADD**: `OperationType` (which operation is being confirmed)
- **CLARIFY**: `Status` values ("ok", "error", "rejected")

---

## 8. Data Structure Suitability Summary

| Message Type | Current DNS Payload | Suitability | Required Changes |
|--------------|---------------------|-------------|------------------|
| **Hello** | DnsHelloPayload | ⚠️ Mostly OK | Add `RecipientID` |
| **Beat** | DnsBeatPayload | ❌ Incomplete | Add `RecipientID`, `BeatInterval`, `SharedZones` |
| **Sync** | DnsSyncPayload | ⚠️ Mostly OK | Add `RecipientID`, align `SyncType` |
| **Ping** | DnsPingPayload | ⚠️ Mostly OK | Add `RecipientID` |
| **Confirm** | DnsConfirmPayload | ⚠️ Generic OK | Add `RecipientID`, `OperationType` |

**Overall Assessment**:
- ✅ **Good foundation** - DNS payloads are lean and appropriate
- ⚠️ **Missing critical fields** - need recipient verification and beat metadata
- ✅ **Better in some areas** - sequence numbers, correlation IDs, nonces
- ❌ **Incomplete for state machine** - beat payload needs enhancement

---

## 9. Implementation Strategy

### Phase 1: Update Data Structures (Low Risk)
1. Add `RecipientID` to all payload types
2. Add `BeatInterval` and `SharedZones` to `DnsBeatPayload`
3. Add `OperationType` to `DnsConfirmPayload`

### Phase 2: Implement Handlers
1. Create DNS Beat handler (similar to API `HeartbeatHandler`)
2. Create DNS Sync handler (similar to API `MsgHandler`)
3. Wire handlers to routeMessage() dispatcher

### Phase 3: State Transitions
1. Update routeHelloMessage() to properly transition KNOWN→INTRODUCED
2. Add routeBeatMessage() to transition INTRODUCED→OPERATIONAL
3. Implement CheckState() for DEGRADED/INTERRUPTED detection

### Phase 4: Authorized Peers Integration
1. Trigger discovery for agents in `authorized_peers` list
2. Start Hello/Beat sequence when discovery completes
3. Maintain OPERATIONAL state via periodic beats

---

## 10. Open Questions

### Q1: Should we have operation-specific response types?
**Current**: Generic `DnsConfirmPayload` for all responses
**Alternative**: `DnsHelloConfirm`, `DnsBeatConfirm`, `DnsSyncConfirm`
**Recommendation**: Start generic, split if operation-specific data needed

### Q2: What is the `State` field in DnsBeatPayload for?
**Options**:
- A: Agent's current state (OPERATIONAL, DEGRADED, etc.)
- B: Transport state
- C: Unused/legacy field
**Action**: Clarify or remove

### Q3: How to handle concurrent operations?
**Challenge**: Multiple Hellos/Beats in flight simultaneously
**Solution**: `CorrelationID` + response matching logic
**Status**: Already supported in DNS payloads ✅

### Q4: Should all messages include replay protection (nonce)?
**Current**: Only Hello and Ping have nonces
**Consideration**: Beat uses sequence numbers instead
**Recommendation**: Nonce for one-shot ops, sequence for periodic ops

---

## Conclusion

The existing DNS transport payload structures provide a **good foundation** but need **targeted enhancements** to support the full agent state machine:

**Critical Additions**:
1. **RecipientID** in all messages (security/verification)
2. **BeatInterval** in beat messages (health monitoring)
3. **SharedZones** in beat messages (context)

**Strengths to Keep**:
1. Lean payloads (no redundant discovery data)
2. Sequence numbers (better than API)
3. Correlation IDs (async operation matching)
4. Nonces (replay protection)

**Next Steps**:
1. Update payload structs (Phase 1)
2. Implement missing handlers (Phase 2)
3. Wire state transitions (Phase 3)
4. Test authorized_peers flow end-to-end (Phase 4)
