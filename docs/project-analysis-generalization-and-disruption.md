# Project Analysis: Generalization Opportunities and JWE/JWS Disruption Assessment

## Document Version
- **Date**: 2025-01-25
- **Status**: Analysis Complete - Ready for Decision
- **Analysis**: Code Examination Results (KDC/KRS in tdns-nm, Agents/HSYNC in tdns/v2)

## Executive Summary

This document presents findings from detailed code analysis of both systems:

1. **~400-500 lines** of pure protocol utilities in tdns-nm/tnm can be extracted to tdns/v2 as shared infrastructure
2. **Agent infrastructure in tdns/v2** is partially ready for multi-transport but needs:
   - Transport abstraction layer (currently REST API only)
   - Persistent confirmation database
   - DNS RR-based message serialization
3. **JWE/JWS Redesign disruption assessment**: Moderate impact, manageable with planning
4. **Recommendation**: **Project 2 first**, then Project 1 (JWE/JWS) as an upgrade

---

## Part 1: Generalization Opportunities (tdns-nm → tdns/v2)

### 1.1 CHUNK Protocol Utilities

**Status**: Ready to move immediately, zero KDC/KRS coupling

**Files to Extract:**
- `tnm/chunk_format.go` (118 lines)
- `tnm/chunks.go` (94 lines)

**Functions:**
```
CreateCHUNKManifest()           # Create manifest with metadata
ExtractManifestData()            # Parse manifest RRdata
SplitIntoCHUNKs()               # Split data into sequence 1, 2, 3, ..., N
ReassembleCHUNKChunks()         # Reassemble chunks into complete data
```

**Destination**: `tdns/v2/core/chunk_protocol.go`

**Why**: These are pure DNS protocol utilities with no business logic coupling

**Impact**: None - these are new utilities, not replacing anything

---

### 1.2 HMAC Manifest Integrity

**Status**: Ready to move, needs minor generalization

**Location**: `tnm/chunk_format.go` lines 85-115

**Functions:**
```go
CalculateCHUNKHMAC(chunk *ChunkRecord, pubKey []byte) []byte
VerifyCHUNKHMAC(chunk *ChunkRecord, pubKey []byte) (bool, error)
```

**Current Issue**: Uses 32-byte assumption (HPKE key size), hardcoded HMAC-SHA256

**Generalization Needed**:
- Accept any `[]byte` as key (works for any length)
- Document that algorithm is HMAC-SHA256 (hard requirement for TDNS)

**Destination**: `tdns/v2/core/chunk_integrity.go`

**Why**: Generic integrity mechanism for any manifested data (keys, sync data, etc.)

**Impact**: None - functions are already algorithm-agnostic for key size

---

### 1.3 Crypto Transport Layer

**Status**: Ready to move, pure abstraction

**Location**: `tnm/hpke_transport_v2.go` (62 lines)

**Functions:**
```go
EncryptAndEncodeV2(plaintext []byte, pubKey crypto.PublicKey, backend crypto.Backend) (string, error)
DecodeAndDecryptV2(encoded string, privKey crypto.PrivateKey, backend crypto.Backend) ([]byte, error)
```

**Format**:
- Input: plaintext, public key (as crypto.PublicKey interface)
- Output: base64-encoded ciphertext (backend-specific format inside)
- Supported backends: HPKE, JOSE (auto-registered)

**Current Usage Pattern**:
```go
// KDC encrypts key:
ciphertext, _ := EncryptAndEncodeV2(privateKeyBytes, nodePublicKey, joseBackend)

// KRS decrypts key:
plaintext, _ := DecodeAndDecryptV2(ciphertext, nodePrivateKey, joseBackend)
```

**Destination**: `tdns/v2/crypto/transport.go`

**Why**: Generic encrypt/encode and decode/decrypt - used by KDC, KRS, and soon agents/combiners

**Impact**: None - zero coupling to business logic, already backend-agnostic

---

### 1.4 NOTIFY Pattern Utilities

**Status**: Ready to move, needs extraction from KDC-specific code

**Location**: `tnm/kdc/notify.go` (96 lines)

**Functions to Extract**:
```go
SendNotifyWithCHUNK(qname string, qtype uint16, remoteAddr string) error
ExtractDistributionIDFromQNAME(qname string, controlZone string) (string, error)
ParseNotifyManifestOption(edns0Option dns.Option) (*ManifestMetadata, error)
```

**Current Usage**:
- KDC sends NOTIFY with distribution ID in QNAME
- KRS receives NOTIFY, extracts distribution ID
- KDC confirms via NOTIFY with manifest option containing status

**Generalization**:
- Make zone/domain-agnostic
- Support custom correlation ID extraction
- Generic confirmation option parsing

**Destination**: `tdns/v2/core/notify_patterns.go`

**Why**: Both KDC→KRS and Agent→Agent communication uses identical NOTIFY pattern

**Impact**: None - new utilities, enables both systems to use same pattern

---

### 1.5 Confirmation Accumulation Pattern

**Status**: Partially generalizable, needs abstraction

**Location**: `tnm/krs/confirm.go` (159 lines)

**Current Structure**:
- KRS accumulates per-operation success/failure
- KeyStatusEntry: zone_name, key_id, error_status
- ComponentStatusEntry: component_id, error_status
- Asynchronously sent back to KDC via NOTIFY(CHUNK)

**What Can Move**:
```go
type ConfirmationEntry interface {
    GetId() string
    GetStatus() string
    GetDetails() string
}

type ConfirmationAccumulator struct {
    entries map[string]ConfirmationEntry
    startTime time.Time
    completedTime *time.Time
}

func (ca *ConfirmationAccumulator) AddSuccess(id string, details string)
func (ca *ConfirmationAccumulator) AddFailure(id string, error string)
func (ca *ConfirmationAccumulator) Marshal() ([]byte, error)
```

**Destination**: `tdns/v2/core/confirmation.go`

**Why**: Same pattern needed for agent sync confirmations

**Implementation Note**: KRS and agents implement the ConfirmationEntry interface with their own types

**Impact**: None - new abstraction, reduces duplication

---

### 1.6 Manifest Metadata and Enrichment

**Status**: Partially generalizable

**Location**: `tnm/kdc/chunks_v2.go` (420 lines)

**What Can Move**:
- Metadata JSON schema definition
- Metadata marshaling/unmarshaling
- Backend selection logic (generalizable)

**What Stays KDC-Specific**:
- Distribution event preparation (zone-specific logic)
- Content type determination (roll_key, delete_key, etc.)
- Caching strategy (distribution-specific)

**Generalizable Functions**:
```go
SelectBackendForRecipient(supportedBackends []string, preferredBackend string) (string, error)
EnrichMetadata(base map[string]interface{}, backend string, ttl time.Duration) map[string]interface{}
```

**Destination**: `tdns/v2/crypto/backend_selection.go`

**Why**: Agents need same backend selection logic for recipients

**Impact**: Minor - clarifies backend selection patterns

---

## Part 2: Current Agent/HSYNC Infrastructure Assessment

### 2.1 Architecture Overview

**Current Implementation Status**:
```
✅ Complete:
  - HSYNC RRset definition and parsing
  - HSYNC change detection
  - Agent discovery from HSYNC
  - Agent state machine (NEEDED→KNOWN→INTRODUCED→OPERATIONAL)
  - API-mode transport (REST/HTTPS with TLSA validation)
  - Agent heartbeat/BEAT messages
  - Agent HELLO handshake
  - Agent data structures and registry
  - Sync data repository (in-memory)
  - Update policy evaluation

⚠️  Partial:
  - DNS-mode discovery (endpoint discovery works, no usage)
  - Confirmation tracking (in-memory only, heartbeat-based)
  - Multi-transport abstraction (framework exists but API-only)

❌ Missing:
  - DNS-mode message transport
  - Persistent confirmation database
  - Transport selection/fallback logic
  - DNS RR-based message encoding
```

### 2.2 Ready for Multi-Transport Integration

**Positive Findings**:

1. **Agent struct already has DNS transport fields**:
   ```go
   ApiDetails *AgentDetails  // API transport (implemented)
   DnsDetails *AgentDetails  // DNS transport (discoverable but unused)
   ApiMethod bool            // Supports API
   DnsMethod bool            // Supports DNS (discovered but not used)
   ```

2. **Message types are mostly transport-agnostic**:
   ```go
   AgentHelloPost       # Contains identity, addresses, port, TLSA
   AgentBeatPost       # Lightweight keepalive
   AgentMsgPost        # Generic message with RRs
   ```
   - These could be encoded as JSON (REST) or DNS wire format (DNS mode)

3. **Confirmation response type exists**:
   ```go
   type AgentMsgResponse struct {
       Status string
       Msg string
       RfiResponse map[AgentId]*RfiData
       Error bool
   }
   ```

4. **Configuration already has DNS transport section**:
   ```yaml
   agent:
     dns:
       addresses: [...]
       port: 53
   ```

### 2.3 Gaps Requiring Implementation

**Gap 1: Transport Abstraction**

**Current**: Tightly coupled to REST API
```go
func (agent *Agent) SendApiBeat(...) error {
    return agent.Api.RequestNG("POST", "/agent/beat", msg, false)
}
```

**Needed**: Abstract transport interface
```go
type AgentTransport interface {
    SendHello(ctx context.Context, msg *AgentHelloMsg) (*AgentHelloResponse, error)
    SendBeat(ctx context.Context, msg *AgentBeatMsg) (*AgentBeatResponse, error)
    SendMsg(ctx context.Context, msg *AgentSyncMsg) (*AgentMsgResponse, error)
}

// Two implementations:
type RestTransport struct { client *http.Client; ... }
type DnsTransport struct { queryClient *dns.Client; ... }
```

**Impact**: Moderate refactoring (~200-300 lines in hsync_beat.go, agent_utils.go)

---

**Gap 2: Message Serialization**

**Current**: JSON-only
```go
type AgentBeatPost struct {
    MessageType AgentMsg      // enum encoded as int
    MyIdentity AgentId        // string
    // ... more fields
}
// Serialized as JSON for REST
```

**Needed**: Abstract serialization
```go
type AgentBeatMsg struct { ... }

// Transport A: JSON serialization
json.Marshal(msg)

// Transport B: DNS wire format
// Could use custom DNS RR type or CHUNK RR
```

**Impact**: Minimal (~100 lines for serialization helpers)

---

**Gap 3: Persistent Confirmation Database**

**Current**: In-memory counter in AgentDetails
```go
SentBeats uint32
ReceivedBeats uint32
LatestSBeat time.Time
LatestRBeat time.Time
```

**Needed**: Database tables for:
1. Agent confirmation state per zone
2. Sync data acknowledgments
3. Key/component installation status
4. Historical confirmation log

**Impact**: Database schema addition (~5-10 tables, ~200 lines SQL)

---

**Gap 4: DNS Query Handler for Agent Messages**

**Current**: REST endpoints handle messages
```go
router.Post("/agent/hello", handleAgentHello)
router.Post("/agent/beat", handleAgentBeat)
router.Post("/agent/msg", handleAgentMsg)
```

**Needed**: DNS RR handlers for agent messages
```go
// Option A: Define custom DNS RR types for agent messages
// Option B: Use CHUNK RR for encoded agent messages
// Option C: Use TXT RR with base64-encoded JSON (minimal)

func (engine *DnsEngine) QueryAgentMsg(qname string, qtype uint16) dns.RR
```

**Impact**: Medium (~150-200 lines for DNS handler)

---

**Gap 5: Transport Selection and Failover**

**Current**: Hardcoded to API if available
```go
if agent.ApiMethod {
    agent.SendApiBeat()  // REST
} else {
    return errors.New("no transport available")
}
```

**Needed**: Intelligent selection
```go
func (agent *Agent) SendBeat(ctx context.Context) error {
    // Try API first (if configured, healthy)
    if agent.ShouldUseApi() {
        if err := agent.SendBeatViaRest(...); err == nil {
            return nil
        }
    }

    // Fallback to DNS
    if agent.ShouldUseDns() {
        if err := agent.SendBeatViaDns(...); err == nil {
            return nil
        }
    }

    return errors.New("all transports failed")
}
```

**Impact**: Light (~150 lines for transport selection logic)

---

## Part 3: JWE/JWS Redesign Disruption Assessment

### 3.1 Current Crypto Usage in KDC/KRS

**Current Implementation Pattern**:

```go
// KDC (encrypt_v2.go):
encrypted, _ := EncryptAndEncodeV2(key, nodePublicKey, backend)
// Stored as: base64(backend-specific ciphertext)

// KRS (crypto_router.go):
decrypted, _ := DecodeAndDecryptV2(encrypted, nodePrivateKey, backend)
// backend name stored in manifest metadata
```

**Current Serialization**: `base64(ciphertext)`
- HPKE: `base64(encapsulated_key || encrypted_data)`
- JOSE: `base64(JWE_compact_serialization)`

---

### 3.2 JWE/JWS Redesign Changes

**From Design Document**:

**New Serialization**: `JWS(JWE(plaintext))`
- Outer: JWS Compact Serialization (3 parts)
- Inner: JWE JSON Serialization with multi-recipient support

**New Format**:
```
<JWS_HEADER>.<JWE_JSON_PAYLOAD>.<SIGNATURE>
```

Where `JWE_JSON_PAYLOAD` is:
```json
{
  "protected": "...",
  "ciphertext": "...",
  "iv": "...",
  "tag": "...",
  "recipients": [
    { "header": {...}, "encrypted_key": "..." },
    { "header": {...}, "encrypted_key": "..." }
  ]
}
```

---

### 3.3 Disruption Analysis: KDC Side

**Current Calls to Encryption**:

**File: `tnm/kdc/encrypt_v2.go`**
```go
func EncryptKeyForNodeV2(key *DNSSECKey, node *Node, backend crypto.Backend) {
    ciphertext, _ := backend.Encrypt(nodePublicKey, key.PrivateKey)
    // Store ciphertext
}
```

**With JWE/JWS, would become**:
```go
func EncryptKeyForNodeV2(key *DNSSECKey, nodeList []*Node, backend crypto.Backend) {
    // Build recipients array from node list
    recipients := make([]JWERecipient, len(nodeList))
    for i, node := range nodeList {
        recipients[i] = JWERecipient{
            header: {...},
            publicKey: node.PublicKey,
        }
    }

    jwe, _ := backend.EncryptMultiRecipient(key.PrivateKey, recipients)
    jws, _ := kdcPrivateKey.Sign(jwe)
    // Store JWS
}
```

**Disruption Level**: **MEDIUM**
- Function signature changes (single node → recipients list)
- Adds recipient loop logic
- KDC callers must change to pass recipient list
- **~30-50 lines of change**

**Affected Callers**:
- `prepareChunksForNodeV2()` in `chunks_v2.go` (line 63-90)
- Any test code that calls `EncryptKeyForNodeV2()`

---

### 3.4 Disruption Analysis: KRS Side

**Current Decryption**:

**File: `tnm/krs/decrypt_v2.go`**
```go
func DecryptAndStoreKeyV2(encrypted []byte, nodePrivKey crypto.PrivateKey, backend crypto.Backend) {
    plaintext, _ := backend.Decrypt(nodePrivKey, encrypted)
    // Store plaintext as key
}
```

**With JWE/JWS, would become**:
```go
func DecryptAndStoreKeyV2(jws []byte, nodePrivKey crypto.PrivateKey, kdcPubKey crypto.PublicKey, backend crypto.Backend) {
    // 1. Verify JWS signature (cheap operation)
    if !jws.Verify(kdcPubKey) {
        return error("signature verification failed")
    }

    // 2. Extract JWE from JWS payload
    jwe := jws.GetPayload()

    // 3. Decrypt JWE with node's private key
    plaintext, _ := backend.DecryptMultiRecipient(nodePrivKey, jwe)
    // Store plaintext as key
}
```

**Disruption Level**: **MEDIUM**
- Function signature changes (need KDC public key for verification)
- Adds JWS verification logic
- Adds multi-recipient decryption logic
- **~40-60 lines of change**

**Affected Callers**:
- `ProcessDistribution()` in `krs/chunk.go` (line 145-200)
- Test code that calls `DecryptAndStoreKeyV2()`

---

### 3.5 Disruption Analysis: Manifest Metadata

**Current**:
```json
{
  "content_type": "key_operations",
  "crypto_backend": "jose",
  "distribution_id": "uuid",
  "timestamp": "2025-01-25T..."
}
```

**With JWE/JWS, protected headers contain metadata**:
```json
{
  "alg": "ECDH-ES+A256KW",
  "enc": "A256GCM",
  "typ": "tdns-distribution",
  "distribution_id": "uuid",
  "content_type": "key_operations",
  "timestamp": "2025-01-25T...",
  "crypto_backend": "jose",
  "recipients_count": 3
}
```

**Disruption Level**: **LOW**
- Metadata fields mostly the same
- New fields (alg, enc, typ) are JWE/JWS specifics
- Parsing code needs minor updates
- **~20-30 lines of change**

---

### 3.6 Disruption Analysis: Multi-Transport (Agents)

**Current**: Agents not yet using encryption

**When Agents Add DNS Mode Communication**:

**Current API-mode agents send unencrypted messages** (or use REST HTTPS):
```go
type AgentBeatPost struct {
    MessageType AgentMsg
    MyIdentity AgentId
    // ... unencrypted fields
}
```

**With JWE/JWS, agents would send encrypted/signed messages**:
```go
plaintext := json.Marshal(AgentBeatMsg{...})
jwe, _ := backend.EncryptMultiRecipient(plaintext, recipientsList)  // Could encrypt for multiple agents
jws, _ := agentPrivKey.Sign(jwe)
// Send JWS over DNS CHUNK RR
```

**Disruption Level**: **MEDIUM**
- New requirement: agents need signing/verification logic
- Adds encryption step to agent communication
- Must handle both single-recipient (agent-to-combiner) and multi-recipient (agent broadcast)
- **~100-150 lines of new code**
- **No change to existing API-mode** (can remain unencrypted for now)

---

### 3.7 Overall Disruption Assessment

**Total Changes Required for JWE/JWS**:

| Component | Files | Lines Changed | Disruption |
|-----------|-------|----------------|-----------|
| KDC Encryption | 1-2 | 30-50 | MEDIUM |
| KRS Decryption | 1-2 | 40-60 | MEDIUM |
| Manifest Parsing | 1-2 | 20-30 | LOW |
| Agent DNS Mode | 2-3 | 100-150 | MEDIUM |
| Backend Interface | 1 | 50-100 | MEDIUM |
| Tests | 3-5 | 150-200 | MEDIUM |
| **TOTAL** | **9-15** | **~400-600** | **MEDIUM** |

**Key Insight**: Changes are **localized, not pervasive**
- Affect 9-15 files in tdns-nm and tdns/v2
- Core data structures stay mostly same
- Function signatures change but call sites are small in number
- Can be implemented incrementally
- Backward compatibility strategy (Option B in design doc) allows V1 to stay unchanged

---

## Part 4: Project Ordering Decision Framework

### 4.1 Project 1 (JWE/JWS) Benefits

✅ **Advantages of Starting Project 1**:
1. **KDC/KRS benefits immediately** from multi-recipient (3+ nodes)
2. **Stabilizes crypto layer** before agents use it
3. **Cleaner agent implementation** (agents start with JWE/JWS built-in)
4. **Single migration path** (no need to upgrade agents later)
5. **Future-proof** (JWE/JWS is standard, more widely supported)

❌ **Disadvantages of Starting Project 1**:
1. **Longer before DNS mode** works (need JWE/JWS + then agents)
2. **Requires generalization first** (move ~500 lines to tdns/v2)
3. **HPKE Option B creates interim complexity** (two formats simultaneously)
4. **Agents still can't coordinate** during Project 1 implementation
5. **Testing more complex** (need test with multi-recipient)

---

### 4.2 Project 2 (DNS Mode) Benefits

✅ **Advantages of Starting Project 2**:
1. **Agents can coordinate immediately** (even if just 2 providers)
2. **Faster to deliver** agent communication
3. **Multi-recipient not needed yet** (2-3 providers typical)
4. **Can use existing crypto** (single-recipient per agent-agent pair)
5. **Establishes agent patterns** that Project 1 extends
6. **Simpler testing** (no multi-recipient complexity)
7. **Solves immediate need** (multi-provider DNS coordination)

❌ **Disadvantages of Starting Project 2**:
1. **Agents built on old crypto pattern** (will be refactored in Project 1)
2. **Can't leverage multi-recipient** (missed optimization)
3. **Need to refactor agents later** when JWE/JWS lands
4. **KDC/KRS still single-recipient** during Project 2
5. **Less elegant** (different paths for agents vs KDC/KRS)

---

### 4.3 Implementation Complexity Analysis

**Project 1 Implementation Order** (if done first):
1. Generalize CHUNK protocol utilities to tdns/v2
2. Implement JWE/JWS in backends
3. Update KDC encryption for multi-recipient
4. Update KRS decryption for JWE/JWS verification
5. HPKE Option B: dual support (old and new formats)
6. Update agents with JWE/JWS
7. Then proceed with Project 2 (agents already use right crypto)

**Estimated**: 3-4 months (crypto is subtle, needs thorough testing)

**Project 2 Implementation Order** (if done first):
1. Generalize CHUNK + NOTIFY patterns to tdns/v2
2. Create transport abstraction in agents
3. Implement DNS message handler for agents
4. Implement DNS-mode agent communication
5. Agent heartbeats over DNS
6. Agent sync operations over DNS
7. Test agent-to-agent and agent-to-combiner
8. Then Project 1 upgrades agents to JWE/JWS (refactor crypto calls)

**Estimated**: 2-3 months (less crypto complexity)

---

### 4.4 Risk Analysis

**Project 1 First Risk**:
- ✅ No crypto rework needed later
- ❌ Agents can't work during Project 1 (longer wait)
- ❌ HPKE Option B creates temporary complexity
- ⚠️  Multi-recipient testing adds complexity

**Project 2 First Risk**:
- ✅ Agents can coordinate sooner
- ✅ Simpler immediate implementation
- ❌ Agent refactoring in Project 1 (rework cost)
- ❌ Pattern inconsistency between KDC and agents during overlap
- ⚠️  Two implementations of similar patterns

---

## Part 5: Recommendation

### 5.1 Recommended Path: **Project 2 First**

**Reasoning**:

1. **Unblocks multi-provider coordination immediately**
   - DNS zone owners can start using multi-provider DNS with TDNS
   - Agents can communicate and synchronize zones
   - Immediate business value

2. **Simpler Project 2 implementation** (~2-3 months)
   - Uses existing single-recipient crypto
   - No multi-recipient complexity
   - Agents are 2-3 providers (multi-recipient not critical)
   - Cleaner, less risky delivery

3. **Project 1 can be cleaner as Project 2 stabilizes**
   - After agents are working, Project 1 becomes a pure upgrade
   - Refactoring agents to JWE/JWS is straightforward
   - KDC/KRS already have patterns from agents

4. **Parallelization opportunity**
   - Project 2 develops in tdns/v2 (agents)
   - Project 1 development can occur simultaneously in backends (crypto layer)
   - Two teams can work independently

5. **Lower disruption risk**
   - Project 2 adds new functionality (DNS mode)
   - Doesn't change existing API mode
   - Existing systems continue working
   - Project 1 (later) upgrades everything to JWE/JWS

### 5.2 Implementation Sequence

**Phase A: Infrastructure Generalization** (Weeks 1-2)
- Extract CHUNK utilities to tdns/v2
- Extract NOTIFY patterns
- Extract confirmation framework
- Extract crypto transport layer

**Phase B: Project 2 - DNS Mode for Agents** (Weeks 3-12)
- Transport abstraction in agents
- DNS message handler
- DNS-mode agent communication
- Agent heartbeats
- Agent sync operations
- Agent-to-combiner communication
- Confirmation database
- Testing

**Phase C: Project 1 - JWE/JWS Redesign** (Weeks 13-24)
- Implement multi-recipient JWE/JWS in backends
- Update KDC for multi-recipient encryption
- Update KRS for JWE/JWS verification
- Refactor agents to use JWE/JWS
- HPKE Option B handling
- Full testing

**Result**: By week 24, both projects complete with agents and KDC/KRS on unified JWE/JWS stack

---

## Appendix A: Generalization Checklist

### To Move from tdns-nm/tnm to tdns/v2

- [ ] `chunk_format.go` → `tdns/v2/core/chunk_protocol.go`
  - CreateCHUNKManifest
  - ExtractManifestData
  - SplitIntoCHUNKs
  - ReassembleCHUNKChunks

- [ ] `chunk_format.go` (HMAC functions) → `tdns/v2/core/chunk_integrity.go`
  - CalculateCHUNKHMAC
  - VerifyCHUNKHMAC

- [ ] `hpke_transport_v2.go` → `tdns/v2/crypto/transport.go`
  - EncryptAndEncodeV2
  - DecodeAndDecryptV2

- [ ] `kdc/notify.go` (utilities) → `tdns/v2/core/notify_patterns.go`
  - SendNotifyWithCHUNK
  - ExtractCorrelationID
  - ParseNotifyManifestOption

- [ ] `krs/confirm.go` (abstraction) → `tdns/v2/core/confirmation.go`
  - ConfirmationEntry interface
  - ConfirmationAccumulator
  - Accumulation logic

- [ ] `kdc/chunks_v2.go` (backend selection) → `tdns/v2/crypto/backend_selection.go`
  - SelectBackendForRecipient
  - EnrichMetadata

---

## Appendix B: Agent DNS Mode Gaps (Detailed)

### Gap 1: Transport Interface Definition

```go
// New file: tdns/v2/agent/transport.go

type AgentTransport interface {
    // HELLO handshake
    SendHello(ctx context.Context, msg *AgentHelloMsg) (*AgentHelloResponse, error)

    // Heartbeat keepalive
    SendBeat(ctx context.Context, msg *AgentBeatMsg) (*AgentBeatResponse, error)

    // Sync data exchange
    SendMsg(ctx context.Context, msg *AgentSyncMsg) (*AgentMsgResponse, error)
}

type RestTransport struct {
    client *http.Client
    baseURL string
}

type DnsTransport struct {
    queryClient *dns.Client
    signer *dns.TSIG  // or SIG(0)
}
```

**Implementation**: ~200-250 lines

---

### Gap 2: Agent Configuration

```yaml
# In tdns/v2/config.go

agent:
  # Local agent identity
  identity: "agent.example.com"

  # Transport preferences
  transports:
    preferred: "dns"  # or "rest"
    available: ["rest", "dns"]
    dns:
      port: 53
      addresses:
        publish: ["192.0.2.1"]
        listen: ["192.0.2.1"]
    rest:
      port: 443
      baseUrl: "https://api.example.com"
      certFile: "/etc/tdns/certs/agent.crt"
      keyFile: "/etc/tdns/certs/agent.key"
```

**Implementation**: ~50-100 lines config parsing

---

### Gap 3: DNS Message Handler

```go
// New file: tdns/v2/agent/dns_handler.go

func (engine *DnsEngine) HandleAgentMessage(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
    // Parse agent message from CHUNK RR or custom RR type
    // Verify signature (SIG(0) or agent's long-term key)
    // Route to appropriate handler (HELLO, BEAT, SYNC)
    // Build response
    // Sign response
    // Return response
}
```

**Implementation**: ~150-200 lines

---

### Gap 4: Persistent Confirmation State

```go
// New tables in tdns/v2/db_schema.go

CREATE TABLE agent_confirmations (
  id TEXT PRIMARY KEY,
  zone TEXT,
  agent_id TEXT,
  operation_id TEXT,
  status TEXT,  // "pending", "partial", "confirmed", "failed"
  created_at TIMESTAMP,
  confirmed_at TIMESTAMP,
  details JSON,
  FOREIGN KEY (zone) REFERENCES zones(name),
  UNIQUE(zone, agent_id, operation_id)
);

CREATE TABLE agent_confirmations_log (
  id TEXT PRIMARY KEY,
  confirmation_id TEXT,
  item_id TEXT,
  item_type TEXT,  // "zone", "key", "component"
  status TEXT,     // "success", "failed"
  message TEXT,
  created_at TIMESTAMP,
  FOREIGN KEY (confirmation_id) REFERENCES agent_confirmations(id)
);
```

**Implementation**: ~100-150 lines SQL + ORM code

---

**Document Status**: Analysis Complete - Ready for Management Decision

**Next Step**: Decision on Project 1 vs Project 2 ordering, then begin implementation
