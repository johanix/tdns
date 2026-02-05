# Unified Transport Data Structures - Refactoring Plan

**Date**: 2026-02-05
**Purpose**: Eliminate duplicate struct hierarchies by using the same data structures for both API and DNS transports
**Goal**: Transport-neutral code that's simpler to maintain

---

## Executive Summary

**Key Insight**: Both API and DNS transports already use `json.Marshal()` to serialize messages, so we can use **identical struct definitions** for both transports.

**Current Problem**: Parallel struct hierarchies
- **API**: `AgentHelloPost`, `AgentBeatPost`, `AgentMsgPost` (in `agent_structs.go`)
- **DNS**: `DnsHelloPayload`, `DnsBeatPayload`, `DnsSyncPayload` (in `agent/transport/dns.go`)

**Solution**: Use the API structs for both transports, eliminate DNS-specific structs entirely.

**Benefit**:
- ✅ Single source of truth
- ✅ Transport-neutral handlers
- ✅ Simpler maintenance
- ✅ Better type safety

---

## Phase 1: Clean Up Existing API Structs

### Remove Redundant Discovery Fields

**Problem**: API structs contain fields that duplicate DNS discovery data:
```go
type AgentHelloPost struct {
    // ... identity fields ...
    Addresses    []string  // ❌ Redundant - comes from SVCB
    Port         uint16    // ❌ Redundant - comes from URI
    TLSA         dns.TLSA  // ❌ Redundant - comes from TLSA query
}
```

**Solution**: Remove these fields from ALL message structs:
- `AgentHelloPost` - remove `Addresses`, `Port`, `TLSA`
- `AgentMsgPost` - remove `Addresses`, `Port`, `TLSA`
- Leave only identity and message-specific data

**Rationale**:
1. DNS discovery provides authoritative contact info
2. Including in messages creates stale data risk
3. Wastes bandwidth
4. API handlers already ignore these fields

**Files to Modify**:
- `tdns/v2/agent_structs.go` - update struct definitions

---

### Updated Struct Definitions (Phase 1)

#### AgentHelloPost (Cleaned)
```go
type AgentHelloPost struct {
    MessageType  AgentMsg      // AgentMsgHello
    MyIdentity   AgentId       // sender's identity (FQDN)
    YourIdentity AgentId       // recipient's identity (FQDN)
    Zone         ZoneName      // zone triggering the hello
    Time         time.Time     // message timestamp
}
```

**Changes**:
- ❌ Removed: `Name` (unused)
- ❌ Removed: `Addresses`, `Port`, `TLSA` (redundant)
- ✅ Added: `Time` (for consistency with other messages)

---

#### AgentBeatPost (Cleaned)
```go
type AgentBeatPost struct {
    MessageType    AgentMsg      // AgentMsgBeat
    MyIdentity     AgentId       // sender's identity
    YourIdentity   AgentId       // recipient's identity
    MyBeatInterval uint32        // expected heartbeat interval (seconds)
    Zones          []string      // zones shared with remote agent
    Time           time.Time     // message timestamp
}
```

**Changes**:
- ✅ Already clean - no redundant fields

---

#### AgentMsgPost (Cleaned)
```go
type AgentMsgPost struct {
    MessageType  AgentMsg      // NOTIFY | RFI | STATUS
    MyIdentity   AgentId       // sender's identity
    YourIdentity AgentId       // recipient's identity
    Zone         ZoneName      // single zone per message
    RRs          []string      // RR strings (dns.RR cannot be JSON marshalled)
    Time         time.Time     // message timestamp
    RfiType      string        // "UPSTREAM" | "DOWNSTREAM" (for RFI only)
}
```

**Changes**:
- ❌ Removed: `Addresses`, `Port`, `TLSA` (redundant)

---

## Phase 2: Update API Transport to Use Cleaned Structs

### Files to Check/Update

1. **Senders** (create messages):
   - `tdns/v2/hsync_hello.go:134` - `SendApiHello()` creates `AgentHelloPost`
   - `tdns/v2/hsync_beat.go` - `SendApiBeat()` creates `AgentBeatPost`
   - Search for all places creating these structs

2. **Receivers** (parse messages):
   - `tdns/v2/apihandler_agent.go:692` - `APIhello()` receives `AgentHelloPost`
   - `tdns/v2/apihandler_agent.go:638` - `APIbeat()` receives `AgentBeatPost`
   - `tdns/v2/apihandler_agent.go:764` - `APImsg()` receives `AgentMsgPost`

**Action**: Remove references to `Addresses`, `Port`, `TLSA` fields

**Verification**:
```bash
# Find all field accesses
grep -r "\.Addresses" tdns/v2/*.go
grep -r "\.Port" tdns/v2/*.go | grep -v "agent.ApiDetails.Port"
grep -r "\.TLSA" tdns/v2/*.go
```

**Expected Impact**: Minimal - these fields are already unused in handlers

---

## Phase 3: Replace DNS Structs with API Structs

### Mapping DNS → API Structs

| DNS Struct | API Struct | Notes |
|------------|------------|-------|
| `DnsHelloPayload` | `AgentHelloPost` | Direct replacement |
| `DnsBeatPayload` | `AgentBeatPost` | Direct replacement |
| `DnsSyncPayload` | `AgentMsgPost` | Use for sync/notify/RFI |
| `DnsPingPayload` | New: `AgentPingPost` | Create new struct |
| `DnsConfirmPayload` | `AgentHelloResponse` etc | Use existing response structs |

---

### Create Missing Structs

#### AgentPingPost (New)
```go
type AgentPingPost struct {
    MessageType  AgentMsg      // AgentMsgPing
    MyIdentity   AgentId       // sender's identity
    YourIdentity AgentId       // recipient's identity
    Nonce        string        // for round-trip verification
    Time         time.Time     // message timestamp
}
```

#### AgentPingResponse (New)
```go
type AgentPingResponse struct {
    Status       string        // "ok" | "error"
    MyIdentity   AgentId       // responder's identity
    YourIdentity AgentId       // original sender
    Nonce        string        // echo from request
    Time         time.Time
    Msg          string
    Error        bool
    ErrorMsg     string
}
```

---

### Update DNS Transport to Use API Structs

**File**: `tdns/v2/agent/transport/dns.go`

#### Before (Current):
```go
func (t *DNSTransport) Hello(ctx context.Context, peer *Peer, req *HelloRequest) (*HelloResponse, error) {
    // Create DNS-specific payload
    payload := &DnsHelloPayload{
        Type:         "hello",
        SenderID:     req.SenderID,
        Capabilities: req.Capabilities,
        SharedZones:  req.SharedZones,
        Timestamp:    req.Timestamp.Unix(),
        Nonce:        req.Nonce,
    }

    payloadJSON, err := json.Marshal(payload)
    // ...
}
```

#### After (Unified):
```go
func (t *DNSTransport) Hello(ctx context.Context, peer *Peer, req *HelloRequest) (*HelloResponse, error) {
    // Use same struct as API transport
    payload := &AgentHelloPost{
        MessageType:  AgentMsgHello,
        MyIdentity:   AgentId(req.SenderID),
        YourIdentity: AgentId(peer.ID),
        Zone:         ZoneName(req.SharedZones[0]), // Use first zone
        Time:         req.Timestamp,
    }

    payloadJSON, err := json.Marshal(payload)
    // ...
}
```

**Changes Required**:
1. Import `tdns` package to access `AgentHelloPost` etc
2. Replace `DnsHelloPayload` with `AgentHelloPost`
3. Map field names (SenderID → MyIdentity, etc.)
4. Update parser functions

---

### Update Parser Functions

**File**: `tdns/v2/agent/transport/dns.go`

#### Before (Current):
```go
func ParseHelloPayload(data []byte) (*DnsHelloPayload, error) {
    var payload DnsHelloPayload
    if err := json.Unmarshal(data, &payload); err != nil {
        return nil, err
    }
    return &payload, nil
}
```

#### After (Unified):
```go
func ParseHelloPayload(data []byte) (*AgentHelloPost, error) {
    var payload AgentHelloPost
    if err := json.Unmarshal(data, &payload); err != nil {
        return nil, err
    }
    return &payload, nil
}
```

**Update All Parsers**:
- `ParseHelloPayload()` → returns `*AgentHelloPost`
- `ParseBeatPayload()` → returns `*AgentBeatPost`
- `ParseSyncPayload()` → returns `*AgentMsgPost`
- `ParsePingPayload()` → returns `*AgentPingPost`
- Generic `ParseConfirmPayload()` → returns response structs

---

## Phase 4: Update Message Routing in TransportManager

**File**: `tdns/v2/hsync_transport.go`

### Current Implementation

```go
func (tm *TransportManager) routeHelloMessage(msg *transport.IncomingMessage) {
    payload, err := transport.ParseHelloPayload(msg.Payload)  // Returns DnsHelloPayload
    // ...
    var zone string
    if len(payload.SharedZones) > 0 {
        zone = payload.SharedZones[0]
    }
    authorized, reason := tm.IsAgentAuthorized(payload.SenderID, zone)
    // ...
}
```

### Updated Implementation

```go
func (tm *TransportManager) routeHelloMessage(msg *transport.IncomingMessage) {
    payload, err := transport.ParseHelloPayload(msg.Payload)  // Returns AgentHelloPost
    // ...
    zone := string(payload.Zone)  // Direct access
    authorized, reason := tm.IsAgentAuthorized(string(payload.MyIdentity), zone)
    // ...
}
```

**Field Mapping**:
- `payload.SenderID` → `payload.MyIdentity` (cast to string)
- `payload.SharedZones[0]` → `payload.Zone` (cast to string)

**Similar Updates Needed**:
- `routeBeatMessage()` - use `AgentBeatPost`
- `routeSyncMessage()` - use `AgentMsgPost`
- `routePingMessage()` - use `AgentPingPost`

---

## Phase 5: Remove DNS-Specific Struct Definitions

**File**: `tdns/v2/agent/transport/dns.go`

### Structs to Delete (lines 715-789):
- `DnsHelloPayload`
- `DnsBeatPayload`
- `DnsSyncPayload`
- `DnsRelocatePayload` (keep if needed, or create `AgentRelocatePost`)
- `DnsConfirmPayload` (use response structs instead)
- `DnsPingPayload`
- `DnsPingConfirmPayload`

### Helper Structs to Keep:
- `DnsAddress` - internal transport representation
- Internal request/response wrappers (HelloRequest, HelloResponse, etc.)

---

## Phase 6: Update Response Handling

### Current Approach
DNS transport uses generic `DnsConfirmPayload` for all responses:
```go
type DnsConfirmPayload struct {
    Type          string
    SenderID      string
    Status        string
    Message       string
    CorrelationID string
    Timestamp     int64
}
```

### Unified Approach
Use operation-specific response structs (same as API):
- `AgentHelloResponse` - for hello operations
- `AgentBeatResponse` - for beat operations
- `AgentMsgResponse` - for sync/notify/RFI operations
- `AgentPingResponse` - for ping operations

**Benefit**: Type-safe responses, operation-specific fields

**Implementation**:
```go
// Instead of generic confirm
func (t *DNSTransport) Hello(...) (*HelloResponse, error) {
    // ...
    var response AgentHelloResponse
    if err := json.Unmarshal(responseData, &response); err != nil {
        return nil, err
    }

    return &HelloResponse{
        ResponderID:  AgentId(response.MyIdentity),
        Accepted:     !response.Error,
        RejectReason: response.ErrorMsg,
        Timestamp:    response.Time,
    }, nil
}
```

---

## Phase 7: Update Message Handlers

### Create Transport-Agnostic Handlers

**Current**: Separate handlers for API vs DNS
- `APIhello()` in `apihandler_agent.go` - handles HTTP POST
- `routeHelloMessage()` in `hsync_transport.go` - handles DNS NOTIFY

**Goal**: Shared validation and processing logic

#### Extract Common Logic

**New file**: `tdns/v2/agent_message_handlers.go`

```go
// ProcessHelloMessage handles hello messages from any transport
func (ar *AgentRegistry) ProcessHelloMessage(hello *AgentHelloPost) (*AgentHelloResponse, error) {
    log.Printf("ProcessHelloMessage: Received from %s for zone %s", hello.MyIdentity, hello.Zone)

    // Validate identities
    if hello.MyIdentity == "" || hello.YourIdentity == "" {
        return &AgentHelloResponse{
            Status:       "error",
            MyIdentity:   ar.LocalAgent.Identity,
            YourIdentity: hello.MyIdentity,
            Time:         time.Now(),
            Error:        true,
            ErrorMsg:     "Missing identity fields",
        }, nil
    }

    // Check authorization (HSYNC membership)
    accepted, reason, err := ar.EvaluateHello(&AgentHelloPost{
        MessageType:  hello.MessageType,
        MyIdentity:   hello.MyIdentity,
        YourIdentity: hello.YourIdentity,
        Zone:         hello.Zone,
    })

    if err != nil || !accepted {
        return &AgentHelloResponse{
            Status:       "error",
            MyIdentity:   ar.LocalAgent.Identity,
            YourIdentity: hello.MyIdentity,
            Time:         time.Now(),
            Error:        true,
            ErrorMsg:     reason,
        }, nil
    }

    // Accept and update state
    return &AgentHelloResponse{
        Status:       "ok",
        MyIdentity:   ar.LocalAgent.Identity,
        YourIdentity: hello.MyIdentity,
        Time:         time.Now(),
        Msg:          "Hello accepted",
        Error:        false,
    }, nil
}
```

#### Update API Handler
```go
func (conf *Config) APIhello(w http.ResponseWriter, r *http.Request) {
    var hello AgentHelloPost
    if err := json.NewDecoder(r.Body).Decode(&hello); err != nil {
        http.Error(w, "Invalid request", http.StatusBadRequest)
        return
    }

    // Use shared handler
    response, err := conf.Internal.AgentRegistry.ProcessHelloMessage(&hello)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}
```

#### Update DNS Handler
```go
func (tm *TransportManager) routeHelloMessage(msg *transport.IncomingMessage) {
    payload, err := transport.ParseHelloPayload(msg.Payload)
    if err != nil {
        log.Printf("TransportManager: Failed to parse hello: %v", err)
        return
    }

    // Use shared handler
    response, err := tm.agentRegistry.ProcessHelloMessage(payload)
    if err != nil {
        log.Printf("TransportManager: Hello processing failed: %v", err)
        return
    }

    // Send response back via DNS
    tm.sendHelloResponse(msg.CorrelationID, response)
}
```

**Benefit**: Single source of truth for business logic

---

## Phase 8: Update EvaluateHello Signature

**Current**:
```go
func (ar *AgentRegistry) EvaluateHello(ahp *AgentHelloPost) (bool, string, error)
```

**Issue**: Takes `*AgentHelloPost` but only uses subset of fields

**Solution**: Keep signature, but document that it works with unified struct

**Alternative**: Create minimal struct for validation:
```go
type HelloValidationRequest struct {
    SenderIdentity    AgentId
    RecipientIdentity AgentId
    Zone              ZoneName
}
```

**Recommendation**: Keep current signature for simplicity

---

## Implementation Order

### Step 1: Cleanup (Low Risk)
1. Remove redundant fields from `AgentHelloPost`, `AgentMsgPost`
2. Update API transport code to not set these fields
3. Verify API transport still works
4. **Test**: Run API hello/beat operations

### Step 2: Add Missing Structs (Low Risk)
1. Add `AgentPingPost` and `AgentPingResponse` to `agent_structs.go`
2. Add `AgentMsg` constants for new message types if needed
3. **Test**: Compilation only

### Step 3: Update DNS Transport Senders (Medium Risk)
1. Update `dns.go` `Hello()` to create `AgentHelloPost`
2. Update `dns.go` `Beat()` to create `AgentBeatPost`
3. Update parser functions to return API structs
4. **Test**: DNS transport send operations

### Step 4: Update DNS Transport Receivers (Medium Risk)
1. Update `routeHelloMessage()` to work with `AgentHelloPost`
2. Update `routeBeatMessage()` to work with `AgentBeatPost`
3. Update field access patterns
4. **Test**: DNS transport receive operations

### Step 5: Delete DNS Structs (Low Risk)
1. Remove `DnsHelloPayload`, `DnsBeatPayload`, etc from `dns.go`
2. Remove parser functions that are no longer needed
3. **Test**: Full compilation, all tests

### Step 6: Extract Common Handlers (Optional, High Value)
1. Create `agent_message_handlers.go`
2. Extract `ProcessHelloMessage()`, `ProcessBeatMessage()`
3. Update API and DNS handlers to use shared logic
4. **Test**: End-to-end hello/beat flows for both transports

---

## Testing Strategy

### Unit Tests
```go
// Test struct marshaling is identical
func TestUnifiedStructMarshaling(t *testing.T) {
    hello := &AgentHelloPost{
        MessageType:  AgentMsgHello,
        MyIdentity:   "agent.alpha.example.",
        YourIdentity: "agent.beta.example.",
        Zone:         "example.com.",
        Time:         time.Now(),
    }

    // Marshal to JSON
    data, err := json.Marshal(hello)
    require.NoError(t, err)

    // Unmarshal back
    var parsed AgentHelloPost
    err = json.Unmarshal(data, &parsed)
    require.NoError(t, err)

    // Verify equality
    assert.Equal(t, hello.MyIdentity, parsed.MyIdentity)
    assert.Equal(t, hello.YourIdentity, parsed.YourIdentity)
}
```

### Integration Tests
1. **API Transport**: Send hello via HTTP POST, verify response
2. **DNS Transport**: Send hello via NOTIFY(CHUNK), verify response
3. **Cross-Transport**: API hello, DNS beat, verify state transitions
4. **Backward Compat**: Verify old API clients still work (if needed)

### Manual Testing
```bash
# Test API hello
tdns-cliv2 agent hello --agent-id agent.alpha.example --zone example.com

# Test DNS hello (after implementation)
tdns-cliv2 agent distrib op ping --to agent.alpha.example --transport dns
```

---

## Migration Path for Existing Deployments

### Backward Compatibility

**Question**: Do we need to support old DNS clients that send `DnsHelloPayload`?

**Option A: No Backward Compat** (Recommended)
- All agents update simultaneously
- Simpler implementation
- Clean break

**Option B: Temporary Dual Support**
- Accept both `DnsHelloPayload` AND `AgentHelloPost`
- Detect based on JSON fields
- Remove after transition period

**Implementation** (if Option B):
```go
func ParseHelloPayload(data []byte) (*AgentHelloPost, error) {
    // Try new format first
    var newPayload AgentHelloPost
    if err := json.Unmarshal(data, &newPayload); err == nil {
        if newPayload.MessageType == AgentMsgHello {
            return &newPayload, nil
        }
    }

    // Fall back to old format
    var oldPayload DnsHelloPayload
    if err := json.Unmarshal(data, &oldPayload); err != nil {
        return nil, err
    }

    // Convert old → new
    return &AgentHelloPost{
        MessageType:  AgentMsgHello,
        MyIdentity:   AgentId(oldPayload.SenderID),
        // ... map other fields
    }, nil
}
```

**Recommendation**: Skip backward compat unless needed

---

## Risks and Mitigations

### Risk 1: Field Name Mismatches
**Problem**: `SenderID` vs `MyIdentity` - JSON field names differ

**Mitigation**: Use JSON tags to maintain wire compatibility if needed
```go
type AgentHelloPost struct {
    MyIdentity   AgentId `json:"my_identity,omitempty"`  // New name
    // OR
    MyIdentity   AgentId `json:"sender_id"`  // Match old name for compat
}
```

**Recommendation**: Use semantic names (`my_identity`), not backward compat names

---

### Risk 2: Missing Fields in Transit
**Problem**: Removing `Addresses`, `Port`, `TLSA` might break something

**Mitigation**:
1. Search codebase for all field accesses
2. Verify handlers don't use these fields
3. Test API transport thoroughly before DNS changes

**Expected**: No impact - fields already unused

---

### Risk 3: Type Conversion Complexity
**Problem**: `AgentId` vs `string`, `ZoneName` vs `string`

**Mitigation**:
- Cast explicitly: `string(payload.MyIdentity)`
- Document type expectations
- Use helper functions if needed

---

## Success Criteria

✅ **Single struct per message type** - no duplicate definitions
✅ **Both transports use same structs** - no Dns* variants
✅ **All tests pass** - API and DNS transport both work
✅ **Code is simpler** - fewer lines, easier to understand
✅ **Type-safe** - compile-time verification of message structure

---

## Estimated Effort

| Phase | Effort | Risk |
|-------|--------|------|
| 1. Cleanup API structs | 2 hours | Low |
| 2. Add missing structs | 1 hour | Low |
| 3. Update DNS senders | 3 hours | Medium |
| 4. Update DNS receivers | 3 hours | Medium |
| 5. Delete DNS structs | 1 hour | Low |
| 6. Extract common handlers | 4 hours | Low |
| **Total** | **14 hours** | **Medium** |

---

## Next Steps

1. **Review this plan** - confirm approach
2. **Phase 1**: Clean up API structs (remove redundant fields)
3. **Phase 2**: Update API transport (verify no breakage)
4. **Phase 3**: Update DNS transport senders
5. **Phase 4**: Update DNS transport receivers
6. **Phase 5**: Delete DNS structs
7. **Phase 6** (optional): Extract common handlers

---

## Open Questions

1. **Field naming**: Use `MyIdentity/YourIdentity` or `SenderID/RecipientID`?
   - Recommendation: Keep `MyIdentity/YourIdentity` (already in API structs)

2. **Zone field**: Single `Zone` or array `Zones`?
   - Current API: `Zone ZoneName` (single)
   - Current DNS: `SharedZones []string` (array)
   - Recommendation: Use `Zone` for hello (single trigger), `Zones` for beat (multi-zone context)

3. **Response structs**: Generic or operation-specific?
   - Recommendation: Operation-specific (current API approach)

4. **Backward compatibility**: Support old DNS payloads?
   - Recommendation: No - clean break

5. **JSON field names**: Preserve old names for wire compat?
   - Recommendation: No - use semantic names

---

## Conclusion

This refactoring will significantly simplify the codebase by eliminating duplicate struct hierarchies. Both transports already use JSON marshaling, so using identical structs is straightforward.

The main work is:
1. Remove redundant fields from API structs
2. Update DNS transport to use API structs
3. Delete DNS-specific struct definitions

The result is transport-neutral code that's easier to maintain and extend.
