# Existing Agent State Machine Analysis

**Date**: 2026-02-05
**Purpose**: Document existing state machine implementation to guide DNS transport augmentation

---

## Executive Summary

The agent state machine and introduction protocol **already exist** and work for API transport. The task is to **augment** (not create) this implementation to support DNS transport with the same security model.

---

## Current State Machine Implementation

### Location
- **Primary**: [tdns/v2/agent/transport/peer.go](../../../tdns/v2/agent/transport/peer.go)
- **Integration**: [tdns/v2/hsync_transport.go](../../../tdns/v2/hsync_transport.go)
- **Hello Handler**: [tdns/v2/hsync_hello.go](../../../tdns/v2/hsync_hello.go)

### PeerState Enum (peer.go:17-29)
```go
type PeerState uint8
const (
    PeerStateNeeded      PeerState = iota // Peer is needed but not yet discovered
    PeerStateDiscovering                  // Discovery in progress
    PeerStateKnown                        // Discovered but not yet contacted
    PeerStateIntroducing                  // Hello handshake in progress
    PeerStateOperational                  // Fully operational
    PeerStateDegraded                     // Operational but with issues
    PeerStateInterrupted                  // Temporarily unreachable
    PeerStateError                        // Persistent error state
)
```

### Parallel AgentState (agent_structs.go:19-26)
```go
const (
    AgentStateNeeded      AgentState = iota + 1
    AgentStateKnown       // Complete information, no communication established
    AgentStateIntroduced  // Got nice reply to HELLO
    AgentStateOperational // Got nice reply to (secure) BEAT
    AgentStateDegraded    // Last heartbeat > 2x normal interval
    AgentStateInterrupted // Last heartbeat > 10x normal interval
    AgentStateError
)
```

**Mapping** (hsync_transport.go:435-453):
- `AgentStateKnown` → `PeerStateKnown`
- `AgentStateIntroduced` → `PeerStateIntroducing`
- `AgentStateOperational` → `PeerStateOperational`

---

## Current Introduction Flow (API Transport)

### 1. Discovery Phase
**Function**: `DiscoverAgent()` in [agent_discovery.go:52-143](../../../tdns/v2/agent_discovery.go#L52-L143)

**DNS Queries**:
1. `_https._tcp.<identity> URI` → API endpoint
2. `api.<identity> SVCB` → IP addresses (ipv4hint/ipv6hint)
3. `_<port>._tcp.api.<identity> TLSA` → TLS certificate
4. `_dns._tcp.<identity> URI` → DNS endpoint (optional)
5. `dns.<identity> SVCB` → IP addresses for DNS
6. `dns.<identity> JWK` → Public key (preferred)
7. `dns.<identity> KEY` → Legacy public key (fallback)

**Result**: `AgentDiscoveryResult` with:
- `APIUri`, `DNSUri`
- `APIAddresses[]`, `DNSAddresses[]`
- `JWKData`, `PublicKey`, `KeyAlgorithm`
- `TLSA` for TLS verification

**State Transition**: Agent moves to `AgentStateKnown` / `PeerStateKnown`

### 2. Hello Phase (Introduction)
**Initiator**: `SingleHello()` in [hsync_hello.go:105-158](../../../tdns/v2/hsync_hello.go#L105-L158)

**Flow**:
```go
// Line 109: Use TransportManager with fallback
helloResp, err := ar.TransportManager.SendHelloWithFallback(ctx, agent, sharedZones)

// Line 125: On success, transition to INTRODUCED
if err == nil && helloResp.Accepted {
    agent.ApiDetails.State = AgentStateIntroduced
}
```

**Responder**: `EvaluateHello()` in [hsync_hello.go:160-211](../../../tdns/v2/hsync_hello.go#L160-L211)

**Authorization Logic**:
```go
// Line 164: Require zone in hello
if ahp.Zone == "" {
    return false, "Error: No zone specified", nil
}

// Line 170: Verify we know this zone
zd, exists := Zones.Get(string(ahp.Zone))
if !exists {
    return false, "Error: We don't know about zone", nil
}

// Line 177: Get HSYNC RRset
hsyncRR, err := zd.GetRRset(zd.ZoneName, core.TypeHSYNC)

// Line 188-201: Check both identities in HSYNC RRset
foundMe := false
foundYou := false
for _, rr := range hsyncRR.RRs {
    if hsync.Identity == ar.LocalAgent.Identity {
        foundMe = true
    }
    if AgentId(hsync.Identity) == ahp.MyIdentity {
        foundYou = true
    }
}
if !foundMe || !foundYou {
    return false, "Error: HSYNC RRset does not include both identities", nil
}
```

**State Transition**: Peer moves to `PeerStateIntroducing`

### 3. Beat Phase (Operational)
**Initiator**: `BeatRetrier()` in hsync_beat.go

**Trigger**: Sends beats to agents in `AgentStateIntroduced` or `AgentStateOperational` (line 46)

**State Transition**: After successful beat, peer moves to `PeerStateOperational` / `AgentStateOperational`

---

## Transport Abstraction

### TransportManager (hsync_transport.go:29-54)
```go
type TransportManager struct {
    APITransport *transport.APITransport
    DNSTransport *transport.DNSTransport
    ChunkHandler *transport.ChunkNotifyHandler
    PeerRegistry *transport.PeerRegistry
    LocalID      string
    ControlZone  string
    agentRegistry *AgentRegistry
    agentQs       *AgentQs
}
```

### Transport Interface (agent/transport/transport.go:35-75)
```go
type Transport interface {
    Name() string
    Hello(ctx, peer, req) (*HelloResponse, error)
    Beat(ctx, peer, req) (*BeatResponse, error)
    Sync(ctx, peer, req) (*SyncResponse, error)
    Ping(ctx, peer, req) (*PingResponse, error)
    // ...
}
```

### SendHelloWithFallback (hsync_transport.go:456-503)
```go
func (tm *TransportManager) SendHelloWithFallback(ctx, agent, sharedZones) (*HelloResponse, error) {
    peer := tm.SyncPeerFromAgent(agent)

    // Try primary transport (API first if available)
    primary := tm.SelectTransport(peer)
    if primary != nil {
        resp, err := primary.Hello(ctx, peer, req)
        if err == nil {
            return resp, nil
        }
    }

    // Try fallback transport
    if fallback != nil {
        return fallback.Hello(ctx, peer, req)
    }
}
```

### DNS Transport Hello Implementation (agent/transport/dns.go:198+)
```go
func (t *DNSTransport) Hello(ctx, peer, req) (*HelloResponse, error) {
    // Build NOTIFY with hello payload
    payload := &DnsHelloPayload{
        Type:         "hello",
        SenderID:     req.SenderID,
        Capabilities: req.Capabilities,
        SharedZones:  req.SharedZones,
        Timestamp:    req.Timestamp.Unix(),
    }

    // Encrypt payload (JWE)
    // Send NOTIFY(CHUNK)
    // Wait for response
}
```

---

## What's Missing for DNS Transport

### ❌ Authorization Check on Receive
**Location**: DNS Hello handler (chunk_notify_handler.go or similar)

**Current State**: DNS transport receives Hello NOTIFY, decrypts payload, but **doesn't validate** sender authorization before accepting.

**Needed**:
```go
// Before accepting Hello via DNS transport:
authorized, reason := IsAgentAuthorized(senderID, zone)
if !authorized {
    return error(reason)
}
```

### ❌ State Transition After DNS Hello Success
**Current State**: API Hello success triggers `agent.ApiDetails.State = AgentStateIntroduced` (line 125)

**Missing**: DNS Hello success doesn't update `PeerRegistry` state or `agent.DnsDetails.State`

**Needed**:
```go
// After successful DNS Hello response:
peer.SetState(transport.PeerStateIntroducing, "DNS hello accepted")
agent.DnsDetails.State = AgentStateIntroduced
```

### ❌ IsAgentAuthorized() Function
**Purpose**: Check if sender is authorized via config OR HSYNC

**Needed Implementation**:
```go
func IsAgentAuthorized(senderID string, zone string) (bool, string) {
    // Check 1: Is sender in agent.peers config list?
    if isInConfigList(senderID) {
        return true, ""
    }

    // Check 2: Is sender in HSYNC RRset for this zone?
    if zone != "" {
        zd, exists := Zones.Get(zone)
        if !exists {
            return false, "zone not known"
        }
        hsyncRR := zd.GetRRset(zone, core.TypeHSYNC)
        if hsyncRR != nil {
            for _, rr := range hsyncRR.RRs {
                if hsync.Identity == senderID {
                    return true, ""
                }
            }
        }
    }

    return false, "not authorized (not in config or HSYNC)"
}
```

### ❌ Config Refactor to Identity-Only List
**Current State**: Config may contain keys, addresses, endpoints (stale data risk)

**Needed**:
```yaml
agent:
  peers:
    - agent1.example.com
    - agent2.example.com
    # No keys, no addresses - DNS discovery provides these
```

---

## Security Model

### Attack Prevention
**DoS Attack**: Malicious bot sends Hello → forces agent to discover attacker

**Defense**: Authorization BEFORE discovery
1. Receive encrypted Hello (can decrypt because we published our public key)
2. Check: Is sender in config OR HSYNC?
3. If NO → reject immediately (no discovery)
4. If YES → accept and transition to INTRODUCING

### Mutual Authentication
**Requirement**: Both sides must be authorized

**API Transport** (already implemented):
- Responder checks HSYNC in `EvaluateHello()` (lines 160-211)
- Rejects if sender not in HSYNC

**DNS Transport** (needs implementation):
- Same check required before accepting DNS Hello
- Use `IsAgentAuthorized()` to check config OR HSYNC

---

## Implementation Tasks (DNS-37, DNS-38)

### DNS-37: Extend State Machine to DNS Transport
**Scope**: Implementation (not design - state machine exists)

**Tasks**:
1. Add state transition after DNS Hello succeeds
2. Update PeerRegistry when DNS Hello completes
3. Ensure `peer.SetState(PeerStateIntroducing)` called
4. Update `agent.DnsDetails.State = AgentStateIntroduced`

**Files to Modify**:
- `agent/transport/dns.go` - Hello() response handling
- `hsync_transport.go` - routeHelloMessage() to update state
- `chunk_notify_handler.go` - handle Hello response

### DNS-38: Add Authorization Checks to DNS Transport
**Scope**: Implementation (not design - protocol exists)

**Tasks**:
1. Implement `IsAgentAuthorized(senderID, zone)` function
2. Add authorization check in DNS Hello handler (before accepting)
3. Use same HSYNC validation logic as API transport
4. Add config list check as additional authorization path

**Files to Modify**:
- New file: `agent_authorization.go` - IsAgentAuthorized()
- `chunk_notify_handler.go` - add auth check in HandleChunkNotify()
- `hsync_transport.go` - add auth check in routeHelloMessage()

---

## References

### Key Files
- [tdns/v2/agent/transport/peer.go](../../../tdns/v2/agent/transport/peer.go) - State machine
- [tdns/v2/hsync_hello.go](../../../tdns/v2/hsync_hello.go) - API Hello flow + authorization
- [tdns/v2/hsync_transport.go](../../../tdns/v2/hsync_transport.go) - TransportManager
- [tdns/v2/agent_discovery.go](../../../tdns/v2/agent_discovery.go) - DNS discovery
- [tdns/v2/agent/transport/dns.go](../../../tdns/v2/agent/transport/dns.go) - DNS transport

### Documentation
- [docs/agent-discovery-queries.md](../../../tdns/docs/agent-discovery-queries.md) - DNS query reference

### Linear Issues
- **DNS-36**: Define secure agent introduction semantics (problem statement)
- **DNS-37**: Extend state machine transitions to DNS transport
- **DNS-38**: Add authorization checks to DNS transport introduction
- **DNS-39**: Refactor config to identity-only list
- **DNS-40**: Implement IsAgentAuthorized()
- **DNS-41**: Implement state machine in PeerRegistry (already done - needs DNS extension)
- **DNS-42**: Update CLI (remove cold-calling)
- **DNS-43**: Implement introduction handlers (DNS transport)
- **DNS-44**: Update documentation

---

## Next Steps

1. **Understand DNS Hello receive path**: Where does DNS Hello NOTIFY get processed?
2. **Add authorization check**: Implement IsAgentAuthorized() and call before accepting Hello
3. **Add state transitions**: Update PeerRegistry and AgentRegistry after DNS Hello succeeds
4. **Test with both transports**: Verify API and DNS Hello both enforce authorization
5. **Refactor config**: Remove keys/addresses, keep only identity list
