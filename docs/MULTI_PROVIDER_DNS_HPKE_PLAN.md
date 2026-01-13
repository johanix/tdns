# DNS-Native HPKE Multi-Provider Synchronization Plan

## Executive Summary

This document outlines the plan to **add** a DNS-native HPKE-based alternative to the current REST API + TLS-based multi-provider DNS synchronization infrastructure. The new design reuses the existing JSONMANIFEST/JSONCHUNK infrastructure from KDC/KRS and provides an option that eliminates the need for TLS certificates, PKI, and separate API endpoints. **The TLS/API-based approach will remain available as an alternative**, allowing operators to choose the best transport method for their environment.

**Status**: Planning phase (2025)  
**Target Implementation**: 2026  
**Approach**: Hybrid - Add DNS-native option alongside existing API-based approach  
**Related Systems**: KDC/KRS, HSYNC records, Agent Registry

## Current State: API-Based Multi-Provider DNS

### Architecture

The current implementation (`tdns/hsyncengine.go`, `tdns/agent_utils.go`, etc.) uses:

1. **Agent Discovery via DNS**:
   - URI records (`_https._tcp.<agent-id>`) for API endpoint discovery
   - SVCB records for address hints and port information
   - TLSA records for certificate pinning
   - KEY records (`_dns._tcp.<agent-id>`) for DNS transport (SIG(0))

2. **Communication via HTTPS**:
   - REST API endpoints (`/hello`, `/beat`, `/msg`)
   - TLS 1.3 with client certificates
   - Certificate verification via TLSA records
   - JSON payloads for messages

3. **Agent States**:
   - NEEDED → KNOWN → INTRODUCED → OPERATIONAL → (DEGRADED/INTERRUPTED)
   - State transitions based on heartbeat timing and communication success

4. **Synchronization Protocol**:
   - HELLO: Initial introduction, verifies both agents in HSYNC RRset
   - BEAT: Periodic heartbeats to maintain connection
   - MSG: Zone updates (NOTIFY-like with RRsets)
   - RFI: Request For Information (UPSTREAM/DOWNSTREAM)

### Limitations

1. **Operational Complexity**:
   - TLS certificate management and renewal
   - PKI infrastructure requirements
   - API endpoint configuration and firewall rules
   - Separate service management (HTTP server)

2. **Deployment Challenges**:
   - HTTPS may be blocked in some environments
   - Requires separate port management
   - Certificate distribution and trust

3. **Code Duplication**:
   - Separate transport layer from KDC/KRS
   - Different encryption mechanisms (TLS vs HPKE)

**Note**: These limitations are acceptable for many deployments. The DNS-native approach provides an alternative for environments where these are problematic, but the API-based approach will remain fully supported.

## Proposed State: DNS-Native HPKE Approach (Additional Option)

### Core Concept

**Add** DNS-native HPKE-based synchronization as an alternative transport method, reusing the exact same infrastructure as KDC/KRS. This will coexist with the existing API-based approach, allowing operators to choose the best method for their environment.

- **HPKE encryption** (same as KDC/KRS)
- **JSONMANIFEST/JSONCHUNK** transport (same as KDC/KRS)
- **NOTIFY** for triggering synchronization (same as KDC/KRS)
- **DNS queries** for data retrieval (same as KDC/KRS)

### Architecture Overview

```
Provider A (agent-a.example.com.)          Provider B (agent-b.example.com.)
     |                                              |
     | 1. NOTIFY(JSONMANIFEST) for zone            |
     |-------------------------------------------->|
     |                                              |
     | 2. Query JSONMANIFEST                        |
     |<--------------------------------------------|
     |    <zone>.<control-domain>?                 |
     |                                              |
     | 3. Query JSONCHUNK (N times)                |
     |<--------------------------------------------|
     |    <chunkid>.<zone>.<control-domain>?        |
     |                                              |
     | 4. Decrypt and process                       |
     |                                              |
     | 5. Confirmation NOTIFY (optional)            |
     |-------------------------------------------->|
```

### Key Components

#### 1. HPKE Key Publication

**Problem**: How do providers discover each other's HPKE public keys?

**Proposed Solutions**:

**Option A: New RRtype `HPKEKEY`**
```
example.com.  IN HPKEKEY <algorithm> <public-key-data>
agent-a.example.com.  IN HPKEKEY 0x0020 <32-byte-X25519-public-key>
```

**Option B: Well-Known Subdomain**
```
_hpke.agent-a.example.com.  IN TXT "hpke-key=<base64-encoded-key>"
```

**Option C: HSYNC Record Extension**
- Extend HSYNC record to include HPKE public key
- Requires HSYNC record format change

**Recommendation**: Option A (new RRtype) for clean separation and DNSSEC signing.

**Implementation**:
- Define new RRtype (e.g., 0x0FA0) in `tdns/core/rr_defs.go`
- Implement parsing/encoding in `tdns/core/rr_hpkekey.go`
- Publish in zone apex or agent identity zone
- Must be DNSSEC signed for security

#### 2. Agent Discovery

**Current**: DNS lookup for URI, SVCB, TLSA, KEY records  
**Proposed**: DNS lookup for HPKEKEY records

**Discovery Flow**:
1. Parse HSYNC RRset to identify agent identities
2. For each agent identity:
   - Query `HPKEKEY` record for `<agent-id>`
   - Verify DNSSEC signature
   - Store public key in agent registry
3. Agent state: NEEDED → KNOWN (when HPKE key discovered)

**Code Changes**:
- Modify `LocateAgent()` in `tdns/agent_utils.go`
- **Add** HPKEKEY lookup alongside URI/SVCB/TLSA lookup
- Support both discovery methods (API and DNS)
- Add transport capability detection

#### 3. Communication Protocol

**Message Types** (same as current, but DNS-native):

**HELLO**:
- Sender: NOTIFY(JSONMANIFEST) with HELLO payload
- Receiver: Queries JSONMANIFEST, then JSONCHUNK
- Decrypts HELLO message
- Verifies both agents in HSYNC RRset
- Responds with confirmation NOTIFY

**BEAT** (Heartbeat):
- Sender: NOTIFY(JSONMANIFEST) with BEAT payload
- Receiver: Queries and processes
- Updates agent state based on heartbeat timing

**MSG** (Zone Update):
- Sender: NOTIFY(JSONMANIFEST) with zone update payload
- Receiver: Queries, decrypts, validates, applies update
- Responds with confirmation

**RFI** (Request For Information):
- Sender: NOTIFY(JSONMANIFEST) with RFI request
- Receiver: Queries, processes, responds with data
- Used for UPSTREAM/DOWNSTREAM zone transfer configuration

#### 4. Message Flow Details

**Sending a Message** (Provider A → Provider B):

1. **Prepare Payload**:
   ```go
   payload := AgentMsgPost{
       MessageType: AgentMsgHello,
       MyIdentity: "agent-a.example.com.",
       YourIdentity: "agent-b.example.com.",
       Zone: "example.com.",
       // ... other fields
   }
   ```

2. **Encrypt with HPKE**:
   ```go
   // Get B's HPKE public key from registry
   agentB := registry.GetAgent("agent-b.example.com.")
   encryptedData := hpke.Encrypt(agentB.HpkePublicKey, payloadJSON)
   ```

3. **Create JSONMANIFEST**:
   ```go
   manifest := JSONMANIFEST{
       ChunkCount: calculateChunks(encryptedData),
       ChunkSize: 60000,
       Checksum: sha256(encryptedData),
       Metadata: {
           Content: "agent_message",
           MessageType: "HELLO",
           Zone: "example.com.",
       }
   }
   ```

4. **Chunk Data**:
   ```go
   chunks := chunkData(encryptedData, manifest.ChunkSize)
   ```

5. **Send NOTIFY**:
   ```go
   // NOTIFY for <zone>.<control-domain>
   notifyQname := fmt.Sprintf("%s.%s", zone, controlDomain)
   sendNOTIFY(notifyQname, dns.TypeJSONMANIFEST)
   ```

6. **Wait for Queries**:
   - Receiver will query JSONMANIFEST
   - Receiver will query JSONCHUNK(s)
   - Receiver will decrypt and process

**Receiving a Message** (Provider B receives from Provider A):

1. **Receive NOTIFY**:
   - NOTIFY handler detects JSONMANIFEST query type
   - Extracts zone from QNAME
   - Triggers JSONMANIFEST query

2. **Query JSONMANIFEST**:
   ```go
   qname := fmt.Sprintf("%s.%s", zone, controlDomain)
   manifest := queryJSONMANIFEST(qname)
   ```

3. **Query JSONCHUNK(s)**:
   ```go
   for i := 0; i < manifest.ChunkCount; i++ {
       chunkQname := fmt.Sprintf("%d.%s", i, qname)
       chunk := queryJSONCHUNK(chunkQname)
       chunks = append(chunks, chunk)
   }
   ```

4. **Reassemble and Decrypt**:
   ```go
   encryptedData := reassembleChunks(chunks)
   payload := hpke.Decrypt(agentA.HpkePublicKey, encryptedData, localPrivateKey)
   ```

5. **Process Message**:
   ```go
   switch payload.MessageType {
   case AgentMsgHello:
       processHello(payload)
   case AgentMsgBeat:
       processBeat(payload)
   case AgentMsgNotify:
       processZoneUpdate(payload)
   }
   ```

6. **Send Confirmation** (optional):
   ```go
   sendNOTIFY(confirmationQname, dns.TypeJSONMANIFEST)
   ```

#### 5. Control Domain

**Concept**: Similar to KDC's `controlzone`, a well-known domain for multi-provider synchronization.

**Options**:
- Use agent identity zone (e.g., `agent-a.example.com.`)
- Use a dedicated control domain (e.g., `sync.example.com.`)
- Use zone being synchronized (e.g., `example.com.`)

**Recommendation**: Use zone being synchronized with a well-known prefix:
- `_sync.example.com.` for synchronization metadata
- Or: `<zone>._sync.<control-domain>.` for per-zone sync

**Implementation**:
- Add `control_domain` configuration option
- Default to zone name with `_sync.` prefix
- Allow override in configuration

### Code Reuse Strategy

#### Existing Components to Reuse

1. **HPKE Infrastructure** (`tdns/hpke/`):
   - ✅ Encryption/decryption functions
   - ✅ Key derivation
   - ✅ All HPKE modes (Base, PSK, Auth, AuthPSK)

2. **JSONMANIFEST/JSONCHUNK** (`tdns/code/`):
   - ✅ RRtype definitions
   - ✅ Parsing/encoding
   - ✅ Chunking logic

3. **NOTIFY Infrastructure** (`tdns/notifyresponder.go`):
   - ✅ NOTIFY sending
   - ✅ NOTIFY receiving
   - ✅ Handler registration

4. **DNS Query Infrastructure**:
   - ✅ Query handlers
   - ✅ TCP/UDP fallback
   - ✅ EDNS(0) support

#### Components to Modify

1. **Agent Discovery** (`tdns/agent_utils.go`):
   - **Add** HPKEKEY lookup alongside URI/SVCB/TLSA lookup
   - Keep API client creation for API-based transport
   - Add HPKE key storage in agent registry
   - Support both discovery methods

2. **Message Sending** (`tdns/hsyncengine.go`):
   - **Add** DNS-based sending alongside `SendApiMsg()`
   - Implement transport selection logic
   - Use NOTIFY + JSONMANIFEST/JSONCHUNK pattern for DNS
   - Implement HPKE encryption for DNS transport
   - Keep existing API sending for API transport

3. **Message Receiving**:
   - **Add** NOTIFY handler for agent messages (DNS transport)
   - **Add** JSONMANIFEST/JSONCHUNK query handlers for agent sync
   - Implement HPKE decryption for DNS transport
   - Keep existing API handlers for API transport

4. **Agent Registry**:
   - **Add** HPKE public key storage alongside API details
   - Keep API client references for API transport
   - Add HPKE key management
   - Support both transport types per agent

### Implementation Phases

#### Phase 1: HPKE Key Publication (Foundation)

**Goal**: Define and implement HPKE key publication mechanism

**Tasks**:
1. Design HPKEKEY RRtype format
2. Implement RRtype in `tdns/core/rr_hpkekey.go`
3. Add DNSSEC signing support
4. Update zone publishing to include HPKEKEY records
5. Add HPKE key generation/storage for agents

**Deliverables**:
- HPKEKEY RRtype implementation
- Key generation utilities
- Publishing mechanism

#### Phase 2: Agent Discovery with HPKE

**Goal**: Add HPKE key discovery alongside API-based discovery

**Tasks**:
1. Modify `LocateAgent()` to **also** query HPKEKEY records
2. Keep URI/SVCB/TLSA lookup code for API transport
3. Update agent registry to store HPKE keys (in addition to API details)
4. Implement HPKE key validation (DNSSEC verification)
5. Update agent state machine (KNOWN when either HPKE key or API details found)
6. Add transport capability detection (which transports does agent support?)

**Deliverables**:
- Enhanced agent discovery (both methods)
- HPKE key storage in registry
- DNSSEC verification
- Transport capability tracking

#### Phase 3: DNS-Based Message Transport

**Goal**: Add DNS-based transport alongside API-based transport

**Tasks**:
1. Implement NOTIFY handler for agent messages (DNS transport)
2. Implement JSONMANIFEST query handler for agent sync
3. Implement JSONCHUNK query handler for agent sync
4. Add HPKE encryption to message sending (DNS transport)
5. Add HPKE decryption to message receiving (DNS transport)
6. Implement chunking for agent messages
7. Add transport selection logic (when to use DNS vs API)
8. Keep existing API transport fully functional

**Deliverables**:
- DNS-based message sending (alongside API)
- DNS-based message receiving (alongside API)
- HPKE encryption/decryption integration
- Transport selection mechanism

#### Phase 4: Protocol Implementation

**Goal**: Implement all message types (HELLO, BEAT, MSG, RFI) for DNS transport

**Tasks**:
1. Implement HELLO protocol over DNS (alongside API)
2. Implement BEAT (heartbeat) over DNS (alongside API)
3. Implement MSG (zone updates) over DNS (alongside API)
4. Implement RFI (request for information) over DNS (alongside API)
5. Add confirmation mechanism for DNS transport
6. Update state management to work with both transports
7. Ensure feature parity between DNS and API transports

**Deliverables**:
- Complete protocol implementation for DNS transport
- State management updates (both transports)
- Error handling for both transports
- Feature parity verification

#### Phase 5: Testing and Integration

**Goal**: Test DNS-based approach and integrate with existing API-based system

**Tasks**:
1. Comprehensive testing of DNS-based transport
2. Performance benchmarking (compare with API-based)
3. Integration testing (both transports working simultaneously)
4. Configuration system for transport selection
5. Documentation updates
6. Operator guide for choosing transport method

**Deliverables**:
- Test suite for DNS-based transport
- Performance comparison metrics
- Configuration guide
- Updated documentation
- Both transports fully supported

### Comparison: API vs DNS-Native

| Aspect | API-Based (Current) | DNS-Native (Proposed) |
|--------|---------------------|------------------------|
| **Transport** | HTTPS/TLS 1.3 | DNS (UDP/TCP) |
| **Encryption** | TLS | HPKE |
| **Authentication** | TLS certificates + TLSA | DNSSEC + HPKE |
| **Key Management** | PKI, certificate renewal | HPKE keys in DNS |
| **Discovery** | URI, SVCB, TLSA, KEY | HPKEKEY |
| **Endpoints** | HTTP API servers | DNS query handlers |
| **Firewall** | Requires HTTPS ports | Uses DNS (port 53) |
| **Operational** | Certificate management | DNS record management |
| **Code Reuse** | Separate from KDC/KRS | Reuses KDC/KRS infra |
| **Latency** | Lower (direct connection) | Higher (multiple queries) |
| **Debugging** | HTTP tools (curl, etc.) | DNS tools (dig, etc.) |
| **Message Size** | HTTP body (unlimited) | DNS with chunking |

### Security Considerations

#### HPKE Key Security

1. **Key Publication**:
   - HPKE public keys must be DNSSEC signed
   - Keys published in agent identity zone or zone apex
   - Consider key rotation mechanism

2. **Key Storage**:
   - Private keys stored securely (similar to KRS)
   - No key distribution needed (each agent has its own)

3. **Key Validation**:
   - Verify DNSSEC signature on HPKEKEY record
   - Check key expiration (if implemented)
   - Validate key format and algorithm

#### Message Security

1. **Encryption**:
   - All messages encrypted with HPKE
   - Use Base mode (same as KDC/KRS)
   - KEM: X25519, KDF: HKDF-SHA256, AEAD: AES-256-GCM

2. **Authentication**:
   - DNSSEC validates HPKE key source
   - HPKE provides message authentication
   - No additional signature needed

3. **Replay Protection**:
   - Include timestamps in messages
   - Implement nonce/sequence numbers
   - Validate message freshness

#### Zone Update Security

1. **Validation**:
   - Verify sender is in HSYNC RRset
   - Validate RRtypes (only DNSKEY, CDS, CSYNC, NS)
   - Check RR names (only zone apex)

2. **Policy Enforcement**:
   - Apply same policy as current implementation
   - Validate upstream/downstream relationships
   - Check zone ownership

### Performance Considerations

#### Query Overhead

**Current API**: 1 HTTPS request per message  
**Proposed DNS**: 1 NOTIFY + 1 JSONMANIFEST + N JSONCHUNK queries

**Example** (100KB message, 60KB chunks):
- NOTIFY: 1 query
- JSONMANIFEST: 1 query
- JSONCHUNK: 2 queries (100KB / 60KB = 2 chunks)
- **Total**: 4 queries vs 1 HTTPS request

**Mitigation**:
- Chunk size optimization (larger chunks = fewer queries)
- TCP for large messages (already implemented)
- Batch operations where possible

#### Latency

**Current API**: Direct TCP connection, ~10-50ms  
**Proposed DNS**: Multiple DNS queries, ~50-200ms (depending on network)

**Acceptability**:
- Synchronization is not real-time
- Acceptable latency for batch operations
- Heartbeats can use longer intervals

#### Throughput

**Current API**: Limited by HTTP server capacity  
**Proposed DNS**: Limited by DNS server capacity

**Considerations**:
- DNS servers typically handle high query rates
- Chunking spreads load across multiple queries
- Can implement rate limiting if needed

### Transport Selection Strategy

**Approach**: Hybrid - Support both transports simultaneously

#### Configuration Options

**Per-Agent Selection**:
```yaml
agent:
  remote:
    transport: "dns"  # or "api" or "auto"
```

**Per-Zone Selection**:
- Could be specified in HSYNC record
- Or in zone configuration
- Default: use agent-level setting

**Auto Selection**:
- Try DNS first, fallback to API if DNS fails
- Or: try API first, fallback to DNS if API unavailable
- Configurable preference

#### Implementation Strategy

1. **Phase 1**: Implement DNS-based alongside API-based
2. **Phase 2**: Add transport selection configuration
3. **Phase 3**: Support both simultaneously
4. **Phase 4**: Maintain both as long-term options

**Benefits**:
- Maximum flexibility for operators
- Can use different transports for different agents/zones
- Fallback capability
- Gradual adoption path

**Considerations**:
- More code to maintain (both transports)
- Need to ensure feature parity
- Testing complexity (test both paths)

### Open Questions

1. **HPKE Key Rotation**:
   - How to handle key rotation?
   - Grace period for old keys?
   - Notification mechanism?

2. **Control Domain**:
   - Best naming scheme?
   - Per-zone or global?
   - Configuration approach?

3. **Transport Selection**:
   - Per-agent or per-zone configuration?
   - Auto-fallback strategy?
   - How to negotiate transport capability?

4. **Error Handling**:
   - How to handle query failures?
   - Retry strategy?
   - Fallback to API if DNS fails?

5. **Monitoring**:
   - What metrics to track for both transports?
   - How to debug DNS-based communication?
   - Logging strategy for both transports?

6. **Performance Tuning**:
   - Optimal chunk size?
   - Query timeout values?
   - Connection pooling?
   - When to prefer DNS vs API?

7. **Feature Parity**:
   - Ensure all message types work in both transports
   - Same state management for both
   - Consistent error handling

### Success Criteria

1. ✅ All message types work over DNS (HELLO, BEAT, MSG, RFI)
2. ✅ All message types **still** work over API (backward compatibility)
3. ✅ HPKE key discovery and validation working
4. ✅ Transport selection mechanism working (per-agent, per-zone, auto)
5. ✅ Code reuse from KDC/KRS > 80%
6. ✅ Performance acceptable (< 500ms per synchronization for DNS)
7. ✅ Security equivalent or better than current approach
8. ✅ Both transports can coexist and be used simultaneously
9. ✅ Operators can choose transport method based on their needs

### Related Documentation

- `tdns/MIGRATION_PLAN.md` - KDC/KRS migration plan
- `tdns/kdc/SERVICE_COMPONENT_MODEL.md` - Service-component model
- `tdns/agent/AGENT-to-AGENT.md` - Current agent communication docs
- `tdns/NEW-RRTYPES.md` - HSYNC record documentation

### Next Steps (2026)

1. **Q1**: Design HPKEKEY RRtype and key publication mechanism
2. **Q2**: Implement Phase 1 (HPKE key publication)
3. **Q3**: Implement Phase 2-3 (Discovery and transport)
4. **Q4**: Implement Phase 4 (Protocol) and testing

---

**Document Version**: 1.0  
**Last Updated**: 2025-12-20  
**Status**: Planning Phase  
**Author**: Architectural Planning Session

