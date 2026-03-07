# Project 2: DNS Mode for Multi-Provider DNSSEC Coordination

## Document Version
- **Date**: 2026-01-25 (Updated: 2026-01-29)
- **Status**: Phase 1, 2, 3 & 4 Complete - Ready for Phase 5 (Testing and Debug Infrastructure)
- **Author**: Architecture Review
- **Project**: TDNS Multi-Provider DNS Synchronization

## UPDATE: DNS Mode Implementation Complete

**Phase 1, Phase 2, Phase 3, and Phase 4 are now complete**:

✅ **Infrastructure Already Complete**:
- Backend abstraction interface with plugin registry (tdns/v2/crypto/)
- HPKE and JOSE backend implementations
- CHUNK RR type unified in tdns/v2/core
- Feature flag architecture for gradual V1→V2 migration
- Cross-backend testing framework
- Confirmation framework with EDNS(0) CHUNK option support
- NOTIFY RR type unified in tdns/v2/core

✅ **Transport Abstraction Complete** (tdns/v2/agent/transport/):
- Transport interface unifying API and DNS modes
- Peer management with state machine (NEEDED → KNOWN → OPERATIONAL)
- API transport implementation (wraps existing HTTPS code)
- DNS transport implementation with NOTIFY(CHUNK) pattern
- Support for Relocate operation (DDoS mitigation)

✅ **Integration and Operations Complete** (Phase 4):
- Transport fallback (API → DNS → retry) in TransportManager
- Comprehensive database schema for HSYNC persistence (6 tables)
- Peer state persistence with full CRUD operations
- Sync operation tracking with confirmation audit trail
- Operational metrics and transport event logging

**Ready for Phase 5**: Testing and Debug Infrastructure
- All core functionality is implemented
- Transport abstraction provides unified interface
- Database persistence layer is complete

## Executive Summary

Project 2 specifies and implements **DNS Mode** for secure agent-to-agent and agent-to-combiner communication in multi-provider DNSSEC scenarios. This complements the existing API Mode and reuses TDNS CHUNK infrastructure for:

1. **Zone owner intent declaration** via HSYNC RRsets
2. **Secure provider discovery** via DNSSEC-authenticated DNS records
3. **Encrypted data synchronization** using CHUNK operations
4. **Detailed confirmation** of received and processed data
5. **Graceful multi-transport** (API mode and DNS mode coexist)

## Problem Statement

### Multi-Provider DNS Reality
- Zone owners often use multiple DNS providers for reliability and geographic distribution
- No standardized mechanism for providers to coordinate DNSSEC key material, NS records, glue records, CDS/CSYNC records
- Current practice: manual coordination or vendor-specific APIs (not interoperable)

### TDNS Multi-Provider Architecture
```
Zone Owner
    ↓
    ├─→ Combiner (Provider A)  ←─→  Agent (Provider A)  ←→  Agent (Provider B)
    │        ↓                                   ↓
    │     Signer A                            KDC/KRS comms
    │        ↓
    │     Nameserver A
    │
    └─→ Combiner (Provider B)  ←─→  Agent (Provider B)
             ↓
          Signer B
             ↓
          Nameserver B
```

- **Zone Owner**: Publishes unsigned zone via AXFR
- **Combiner**: DNS zone transfer proxy between zone owner and signer
  - Receives zone from owner
  - Receives modification instructions from local agent
  - Merges modifications (NS records, glue, DNSKEYs, CDS/CSYNC)
  - Sends merged zone to signer
  - Narrowly scoped: only modifies specific record types
- **Agent**: Provider-side orchestrator
  - Receives signed zone from signer via AXFR
  - Detects changes that need multi-provider coordination
  - Communicates with agents at other providers
  - Instructs local combiner about modifications needed
- **Signer**: Standard DNSSEC signer (takes unsigned zone, produces signed zone)
- **Nameserver**: Standard authoritative nameserver

## HSYNC: Zone Owner Intent Declaration

### HSYNC RRset Structure

**Location**: Zone apex (owner name = zone name)

**RDATA Fields** (per HSYNC record):
```
provider_name           Domain name identifying this provider
signing_model           "owner" | "agent" (who signs the zone)
delegation_model        "owner" | "agent" (who syncs delegation/DNSSEC)
zone_source            "owner" | "provider:{name}" | "manual"
```

### Example: Multi-Provider Zone

```
example.com.  IN  HSYNC  ns1.providerA.com. agent agent owner
example.com.  IN  HSYNC  ns1.providerB.com. agent agent provider:ns1.providerA.com.
```

- Zone owner publishes both HSYNC records
- All nameservers see the complete HSYNC RRset (DNSSEC-protected)
- Each provider finds its own identity
- Each provider discovers other providers from the RRset

### HSYNC Semantics

| Field | Meaning |
|-------|---------|
| `provider_name` | FQDN of the provider's nameserver (used for agent discovery) |
| `signing_model` | "owner" = owner handles DNSSEC signing; "agent" = provider agents coordinate signing |
| `delegation_model` | "owner" = owner handles NS/glue/CDS; "agent" = providers coordinate via agents |
| `zone_source` | Where this provider gets the zone: "owner" (zone transfer from owner), "provider:X" (zone transfer from provider X), "manual" (no auto-transfer) |

## Discovery and Authentication

### Provider Discovery via HSYNC

1. Provider sees HSYNC RRset (DNSSEC-authenticated)
2. Finds its own `provider_name` in one HSYNC record
3. Discovers other providers from remaining HSYNC records
4. Knows other providers' identities as domain names

### Secure Endpoint Discovery

Each provider (identified as domain name like `agent.providerB.com`) can be contacted using two modes:

#### API Mode (Existing, Largely Implemented)
1. Query `_https._tcp.agent.providerB.com` URI record (DNSSEC-authenticated)
2. Query SVCB for hostname in URI (DNSSEC-authenticated)
3. Query TLSA for TLS certificate pinning (DNSSEC-authenticated)
4. Connect via HTTPS to discovered endpoint
5. Complete `/hello` REST handshake
6. Use REST API for ongoing communication

#### DNS Mode (Project 2)
1. Query long-term public key of `agent.providerB.com` via DNS (DNSSEC-authenticated)
2. Query address:port information (DNSSEC-authenticated)
3. No HTTPS involved
4. Use DNS NOTIFY(CHUNK) + query pattern
5. Complete CHUNK-based "hello" operation
6. Use DNS mode for ongoing communication

## DNS Mode Communication

### Core Pattern: NOTIFY(CHUNK) + Query + Confirmation

```
Agent A wants to send sync data to Agent B:

1. Agent A creates CHUNK with sync data
   - Encrypted with Agent B's public key
   - Signed by Agent A with its private key
   - Protected headers contain operation type, sequence, correlation IDs

2. Agent A sends NOTIFY(CHUNK) query to Agent B
   - Tells Agent B "there's a CHUNK ready for you"
   - NOTIFY includes correlation ID for tracking

3. Agent B receives NOTIFY(CHUNK)
   - Queries Agent A for the actual CHUNK data

4. Agent B decrypts and parses CHUNK
   - Verifies Agent A's signature
   - Validates operation structure
   - Processes sync data

5. Agent B sends detailed CONFIRMATION CHUNK back to Agent A
   - Confirms exactly what was received and processed
   - Lists any errors, rejections, partial processing
   - Includes DNSSEC signatures for proof
   - Signed by Agent B with its private key
```

### CHUNK Operations for DNS Mode

**Hello Operation**:
- Initiator introduces itself to discovered provider
- Exchanges long-term public key identifiers
- Establishes bidirectional trust
- Confirms provider identities match HSYNC intent

**Sync Operation**:
- Carries coordination data (new NS records, DNSKEY changes, etc.)
- Type-specific (NS sync, DNSSEC sync, glue sync, etc.)
- **Always zone-specific**: Each operation targets exactly one zone
- Agent only announces facts about its own provider
- Includes operation-specific fields

**Relocate Operation** (DDoS Mitigation):
- After secure communication is established, agents can relocate to private addresses
- Public HSYNC addresses are potential DDoS targets (discoverable by adversaries)
- Relocate payload contains new address:port inside encrypted envelope
- New address is invisible to adversaries (only decryptable by authenticated peer)
- Operational communication continues on private addresses
- Allows separation of "discovery address" from "operational address"

**Confirmation Operation**:
- Response to any operation
- Details exactly what was received
- Lists processing status per item
- Includes correlation IDs to link to original operation

## Agent-to-Agent Communication

### Key Principle: Agents Only Speak for Themselves

**Critical constraint**: An agent can ONLY make statements about its own provider. Agent A cannot make statements about what provider B or provider C should do. This ensures:
- Clear authority boundaries (each agent speaks for exactly one provider)
- No ambiguity about source of information
- No delegation of authority between providers

Each agent announces facts about itself: "For zone X, provider P (that I represent) serves on nameservers [list]"

### Scenario: NS Record Coordination

```
Zone: example.com
Providers: A (ns1.providerA.com), B (ns1.providerB.com)

1. Zone owner adds new provider C
   - Updates HSYNC RRset to include ns1.providerC.com
   - All existing providers see updated HSYNC RRset

2. Agent A detects HSYNC change
   - Sees new provider C in HSYNC RRset
   - Initiates DNS mode discovery for Agent C
   - Performs Hello handshake with Agent C

3. Agent A announces its NS records to Agent B and Agent C
   - Agent A sends Sync(NS) to Agent B (encrypted for B's public key)
   - Agent A sends Sync(NS) to Agent C (encrypted for C's public key)
   - Payload: "For zone example.com, provider A serves on nameservers: [ns1.providerA.com, ns2.providerA.com]"
   - Note: Agent A only announces its own records, never speaks for B or C

4. Agent B and Agent C announce their own NS records
   - Agent B sends Sync(NS) to A and C: "For zone example.com, provider B serves on: [ns1.providerB.com]"
   - Agent C sends Sync(NS) to A and B: "For zone example.com, provider C serves on: [ns1.providerC.com]"

5. Each agent locally computes the combined NS RRset
   - Agent B receives announcements from A and C
   - Combines with its own knowledge: {ns1.A, ns2.A, ns1.B, ns1.C}
   - Instructs local Combiner: "ensure NS RRset contains all four records"

6. Combiner modifies zone as it passes to signer
   - When zone transfer from owner arrives, combiner injects NS records
   - Signer signs the merged zone
   - Resulting NS RRset now includes all providers' nameservers

7. Agent B detects signer's zone changed
   - Sends Confirmation(NS) to Agent A
   - "For zone example.com: successfully applied NS records"

8. Agent A receives confirmation
   - Marks synchronization complete for zone example.com with provider B
   - Logs completion for operator visibility
```

## Agent-to-Combiner Communication

### Scenario: Combiner Receives Sync Instructions

```
Agent at Provider B wants Combiner to modify zone example.com:

1. Agent receives Sync(NS) announcements from Agent A and Agent C
   - A announces: "For zone example.com, provider A serves on: [ns1.A, ns2.A]"
   - C announces: "For zone example.com, provider C serves on: [ns1.C]"

2. Agent B locally computes combined NS RRset for zone example.com
   - Own records: [ns1.B]
   - From A: [ns1.A, ns2.A]
   - From C: [ns1.C]
   - Combined: [ns1.A, ns2.A, ns1.B, ns1.C]

3. Agent B sends Modification CHUNK to local Combiner
   - Type: Sync(NS)
   - Zone: example.com
   - Payload: "For zone example.com, ensure NS RRset contains: [ns1.A, ns2.A, ns1.B, ns1.C]"
   - Signed by Agent with its private key
   - Encrypted with Combiner's public key (or symmetric shared secret)

4. Combiner receives NOTIFY(CHUNK) from Agent
   - Queries Agent for modification CHUNK

5. Combiner decrypts and verifies
   - Validates Agent signature (Agent public key known from enrollment)
   - Checks modification is within allowed scope (NS, glue, DNSKEY, CDS, CSYNC only)
   - Checks modification is for a zone the combiner manages

6. Combiner applies modification to next zone transfer
   - Modifications are zone-specific and temporary per-transfer (held in memory)
   - When zone owner sends new AXFR for example.com, combiner merges in modifications
   - Sends merged zone to signer

7. Combiner sends Confirmation CHUNK back to Agent
   - Zone: example.com
   - Details what was applied
   - References to DNSSEC signatures for proof
   - Signed by Combiner with its private key

8. Agent receives Confirmation
   - Validates Combiner signature
   - Logs successful application for zone example.com
```

## Confirmation Pattern: Critical Importance

### Why Detailed Confirmations?

1. **Operator Visibility**: Must see exactly what synchronized and what failed
2. **Debugging**: Trace which zones, which records, which providers participated
3. **Auditing**: Compliance requirement: show proof of coordination
4. **Reliability**: Know when to retry, what to escalate

### Confirmation Structure

```
Confirmation Operation:
  - correlation_id: links to original operation
  - timestamp: when processed
  - status: "success" | "partial" | "failed"
  - items_processed: [
      { record_type: "NS", zone: "example.com", status: "applied", details: "..." },
      { record_type: "DNSKEY", zone: "example.com", status: "applied", details: "..." },
      { record_type: "CDS", zone: "example.com", status: "rejected", reason: "zone unsigned" }
    ]
  - signed_proof: DNSSEC signatures from signer proving zone state
  - agent_signature: Signature by confirming agent/combiner
```

## Parallels with KDC/KRS Communication

### Architectural Similarities

| Aspect | KDC/KRS | Agent/Agent | Agent/Combiner |
|--------|---------|------------|-----------------|
| **Frequency** | Infrequent | Infrequent | Infrequent |
| **Criticality** | High (DNSSEC keys) | High (zone structure) | High (zone mods) |
| **Transport** | CHUNK/NOTIFY | CHUNK/NOTIFY | CHUNK/NOTIFY |
| **Encryption** | JWE (single-recipient) | JWE (single-recipient) | JWE |
| **Confirmation** | Detailed per-zone per-key | Detailed per-zone per-record | Detailed per-modification |
| **Authentication** | KDC signs with long-term key | Agent signs with long-term key | Agent/Combiner sign |
| **Endpoint Discovery** | KRS registers via enrollment | DNS (DNSSEC-authenticated) | Local (combiner is local) |

### Communication Pattern Generalization

Both KDC/KRS and Agent systems use:
1. **CHUNK envelope** for data transport
2. **NOTIFY(CHUNK)** for pull-based update notification
3. **Long-term keypair** for authentication
4. **JWE/JWS** for encryption and signing
5. **Detailed confirmation** for operational visibility

This suggests a **generalized communication framework** in tdns/v2:
- Abstract "CHUNK operation sender/receiver"
- Abstract "NOTIFY responder"
- Abstract "confirmation accumulator"
- Reusable by KDC/KRS, agents, and future components

## Multi-Transport: API Mode and DNS Mode

### Coexistence Strategy

Providers must support both transports during transition:

```
Agent A → Agent B:
  1. Try API mode first (if configured)
     - Fast, lower latency
     - Uses REST API
  2. Fall back to DNS mode (always available)
     - More portable (works through firewalls)
     - Uses DNSSEC authentication
  3. If both fail, escalate (retry with backoff)
```

**Data Model Requirement**:
- Both API mode and DNS mode must produce identical results
- Same database tables, schemas, confirmations
- Transport layer abstraction: transparent to business logic

## Security Considerations

### DDoS Mitigation: The Relocate Operation

**Problem**: The agent's public address is discoverable via DNS:
- HSYNC record contains the provider name (e.g., `agent.providerA.com`)
- Address lookups are public and DNSSEC-authenticated
- Adversaries can easily discover the agent's "official" address:port
- This makes the public endpoint a potential DDoS target

**Solution**: Relocate to private operational addresses after initial discovery:

```
1. Discovery Phase (Public Address)
   - Agent B discovers Agent A via HSYNC RRset
   - Looks up agent.providerA.com address via DNS
   - Initiates Hello handshake on public address
   - Establishes secure communication (mutual authentication)

2. Relocate Operation (Move to Private Address)
   - Agent A sends Relocate operation to Agent B
   - Payload (encrypted, inside JWE): { "new_address": "10.x.y.z", "new_port": 5354 }
   - Address is invisible to adversaries (only Agent B can decrypt)
   - Agent B acknowledges and switches to new address

3. Operational Phase (Private Address)
   - All subsequent Sync, Confirmation operations use private address
   - Public address remains for new peer discovery only
   - Private address can be changed periodically for additional security
```

**Benefits**:
- Separation of "discovery address" from "operational address"
- Private addresses are not publicly discoverable
- Reduces attack surface for established peer relationships
- Allows address rotation without disrupting discovery

### Encryption and Authentication

All agent-to-agent communication is:
- **Encrypted**: JWE with recipient's public key (asymmetric)
- **Signed**: JWS with sender's private key
- **Replay-protected**: Timestamps and correlation IDs
- **Zone-scoped**: Each operation targets a specific zone

## Implementation Scope

### Phase 1: Review and Evaluation of Existing API-Mode Communications ✅ COMPLETE
**Goal**: Understand and evaluate the existing API-mode communications layer

Note: The existing API-mode code is incomplete and not in production use. There are no backwards compatibility constraints - we can redesign as needed to create a clean, transport-neutral communications layer that works for both API mode and DNS mode.

- ✅ Define HSYNC RRset format
- ✅ Specify API mode endpoint discovery
- ✅ Define DNS mode protocol
- ✅ Design CHUNK operations (including Relocate for DDoS mitigation)
- ✅ Specify confirmation format
- ✅ Examine existing agent code in tdns/v2
- ✅ Evaluate existing API-mode communications (what works, what doesn't)
- ✅ Identify what can be reused vs. redesigned
- ✅ Plan transport-neutral comms framework (API mode + DNS mode unified)

**Findings**:
- Existing API-mode more complete than expected: working heartbeat, discovery, hello handshake, message routing
- Key gaps: DNS transport not implemented, no confirmation protocol, no encryption
- Reusable: Agent state machine, AgentRegistry, LocateAgent() discovery, event loop orchestration
- Redesigned: Transport abstraction interface to unify API/DNS modes

### Phase 2: Infrastructure Generalization ✅ COMPLETE
**Status**: Complete - transport abstraction framework implemented

**Already Complete:**
- ✅ Backend abstraction (crypto layer)
- ✅ Feature flag architecture
- ✅ CHUNK RR type unified in tdns/v2/core
- ✅ CHUNK utilities moved to tdns/v2/core/chunk_utilities.go and tdns/v2/distrib/
- ✅ NOTIFY helpers moved to tdns/v2/core/notify_helpers.go
- ✅ Confirmation types in tdns/v2/distrib/confirmation.go
- ✅ JWT manifest format in tdns/v2/distrib/manifest_jwt.go
- ✅ **Transport abstraction framework** in tdns/v2/agent/transport/

**Transport Abstraction Files Created:**
- `tdns/v2/agent/transport/transport.go` - Transport interface with Hello, Beat, Sync, Relocate, Confirm operations
- `tdns/v2/agent/transport/peer.go` - Peer management with state machine and address handling
- `tdns/v2/agent/transport/api.go` - API transport implementation wrapping existing HTTPS code
- `tdns/v2/agent/transport/dns.go` - DNS transport implementation (full implementation)
- `tdns/v2/agent/transport/handler.go` - DNS message handler for incoming NOTIFY(CHUNK)
- `tdns/v2/agent/transport/doc.go` - Package documentation

**Key Design Elements:**
- Transport interface unifies API and DNS modes with same business logic
- Peer struct tracks DiscoveryAddr vs OperationalAddr (for Relocate/DDoS mitigation)
- SyncType enum: NS, DNSKEY, GLUE, CDS, CSYNC
- ConfirmStatus enum: SUCCESS, PARTIAL, FAILED, REJECTED
- PeerRegistry provides thread-safe peer management
- All sync operations are zone-specific (agents speak only for themselves)

### Phase 3: DNS Mode Implementation ✅ COMPLETE
Build DNS transport on top of the transport abstraction:
- ✅ DNS transport implementation (NOTIFY + CHUNK query pattern)
- ✅ DNS message handler for agent communication
- ✅ Agent HELLO operation via DNS
- ✅ Agent BEAT (heartbeat) operation via DNS
- ✅ Agent Sync operations via DNS (NS, DNSKEY, glue, CDS/CSYNC)
- ✅ Agent Relocate operation via DNS
- ✅ Confirmation sending via DNS
- ✅ CHUNK NOTIFY handler using tdns registration pattern (RegisterNotifyHandler)
- ✅ Integration with hsyncengine (TransportManager for routing and transport selection)
- ✅ JWS/JWE encryption module for payloads (crypto.go with PayloadCrypto)
- [ ] Testing DNS mode operations

**Phase 3 Files Created:**
- `tdns/v2/agent/transport/dns.go` - Full DNS transport implementation (~560 lines)
- `tdns/v2/agent/transport/handler.go` - DNS message handler with payload parsing
- `tdns/v2/agent/transport/chunk_notify_handler.go` - CHUNK NOTIFY handler using registration pattern
- `tdns/v2/agent/transport/crypto.go` - JWS/JWE encryption for payloads (~350 lines)
- `tdns/v2/agent/transport/init.go` - Integration guide documentation
- `tdns/v2/hsync_transport.go` - TransportManager bridging transport package with hsyncengine

**Key Integration Points:**
- CHUNK NOTIFY handler registers via `tdns.RegisterNotifyHandler(core.TypeCHUNK, handler)`
- TransportManager routes incoming DNS messages to hsyncengine channels (Hello, Beat, Msg)
- PayloadCrypto wraps existing crypto.Backend for JWS(JWE) authenticated encryption
- SecurePayloadWrapper provides optional encrypt-on-send, verify-on-receive

### Phase 4: Integration and Operations ✅ COMPLETE
- ✅ Update agent discovery to support DNS endpoints (already in LocateAgent)
- ✅ Implement transport fallback (API → DNS → retry)
- ✅ Update combiner to use transport abstraction (low priority - local communication)
- ✅ Persistent confirmation database schema
- ✅ Confirmation accumulation and operator reporting
- ✅ Peer state persistence (addresses, keys, zone mappings)

**Phase 4 Files Created:**
- `tdns/v2/db_schema_hsync.go` - Database schema with 6 tables (~300 lines):
  - PeerRegistry: Peer information with API/DNS transport details
  - PeerZones: Zone-peer relationships with sync state
  - SyncOperations: Per-operation tracking with correlation IDs
  - SyncConfirmations: Confirmation records with proof storage
  - OperationalMetrics: Time-series metrics for monitoring
  - TransportEvents: Transport event logging for debugging
- `tdns/v2/db_hsync.go` - Data access layer (~500 lines):
  - Full CRUD operations for all tables
  - PeerRecord/SyncOperationRecord/SyncConfirmationRecord structs
  - Conversion functions from Agent/Peer to database records
  - Bulk operations and state updates
- `tdns/v2/hsync_transport.go` - Extended with fallback methods:
  - SendHelloWithFallback() - Hello with transport fallback
  - SendBeatWithFallback() - Beat with transport fallback
  - OnAgentDiscoveryComplete() - Discovery completion callback
  - Transport availability helpers

**Key Design Elements:**
- Peer state machine: NEEDED → KNOWN → INTRODUCING → OPERATIONAL → DEGRADED → INTERRUPTED → ERROR
- Comprehensive indexing for efficient queries
- Automatic cleanup of expired data (7 days events, 30 days operations, 90 days metrics)
- Conversion functions between Agent/transport.Peer and database PeerRecord

### Phase 5: Testing and Debug Infrastructure (In Progress)
- ✅ Debug CLI commands implemented:
  - `agent hsync query` - Query HSYNC RRset via DNS
  - `agent hsync peers` - Show peer status from database
  - `agent hsync sync-ops` - Show sync operations
  - `agent hsync confirmations` - Show confirmation records
  - `agent hsync events` - Show transport events
  - `agent hsync metrics` - Show operational metrics
  - `debug agent hsync chunk-send` - Send test CHUNK (stub)
  - `debug agent hsync chunk-recv` - Show received CHUNKs (stub)
  - `debug agent hsync init-db` - Initialize database tables
- [ ] Simulate provider discovery (mocked DNS responses)
- [ ] Test CHUNK operations in isolation
- [ ] Test DNS mode operations end-to-end
- [ ] Test confirmation flows
- [ ] Multi-provider integration test (2-3 providers coordinating)

**Phase 5 Files Created:**
- `tdns/v2/cli/hsync_debug_cmds.go` - Debug CLI commands (~450 lines)
- `tdns/v2/apihandler_agent.go` - Extended with HSYNC debug handlers
- `tdns/v2/agent_structs.go` - Extended with HsyncPeerInfo, HsyncSyncOpInfo, etc.
- `tdns/v2/db_hsync.go` - Extended with query functions and conversions

## Design Decisions

### Single-Recipient Encryption (Simplified)

With only 2-3 providers per zone, multi-recipient JWE encryption is not needed:
- The go-jose library does not support multi-recipient mode
- The overhead of separate encryption for 2-3 recipients is minimal
- Single-recipient JWE simplifies implementation and debugging
- Each agent encrypts separately for each peer

### Agents Only Speak for Themselves

A fundamental constraint of the protocol:
- Agent A can ONLY announce facts about provider A
- Agent A cannot make statements about what provider B or C should do
- Each agent announces its own records; recipients locally combine them
- This ensures clear authority boundaries and no ambiguity about information sources

### Zone-Specific Communication

All synchronization operations are scoped to specific zones:
- Agents may coordinate thousands of zones between them
- Different zones can have different nameserver configurations
- Each Sync operation targets exactly one zone
- Confirmations reference the specific zone they apply to

## Data Model Integration: API Mode + DNS Mode

### Requirement
Both API mode and DNS mode must feed identical data into:
- Database tables
- Agent state machines
- Confirmation accumulation
- Operator reporting

### Current API Mode (Existing)
- Agent receives sync data via REST API
- Stores in database
- Triggers confirmation flow

### DNS Mode (To Be Implemented)
- Agent receives sync data via CHUNK
- Must parse into identical database format
- Triggers same confirmation flow
- Operator reports identically

**This requires mapping and understanding**:
1. Current agent data models in tdns/v2
2. Current database schema
3. How API mode populates data
4. What abstraction layer makes both transports transparent

## Testing Strategy

### Isolated Component Tests
- CHUNK operations: encode/decode/sign/verify
- Confirmation accumulation: structure and reporting
- Discovery: DNS lookups with DNSSEC validation
- Encryption/decryption: single-recipient JWE
- Relocate operation: address transition

### Integration Tests
- Agent discovery via HSYNC
- Agent-to-agent hello handshake (DNS mode)
- Agent-to-agent sync operation (NS records)
- Agent-to-combiner modification instruction
- Confirmation round-trip
- Multi-transport fallback

### End-to-End Tests (Once System Mature)
- Two-provider zone with multi-provider DNSSEC coordination
- Three-provider scenario
- Provider addition/removal
- Failure and recovery scenarios

### Debug CLI Commands Needed
- `agent hsync query` - Query and decode HSYNC RRset for a zone
- `agent discovery` - Test provider discovery for a zone
- `agent chunk send` - Manually send CHUNK to test endpoint
- `agent chunk recv` - Manually receive and decode CHUNK
- `combiner chunk recv` - Manually receive combiner instructions
- `agent confirm query` - Query confirmations for a sync operation
- `agent crypto keys` - List agent long-term keys with key IDs

## Generalization Opportunities (To Be Analyzed)

### In tdns-nm/tnm (KDC/KRS Specific)

Current structure likely includes:
- KDC-specific CHUNK operation definitions
- KRS-specific CHUNK handling
- KDC enrollment logic
- KRS bootstrap logic
- Confirmation structures hard-coded for keys

### Candidates for Moving to tdns/v2 (Generalized)

```
tdns/v2/comms/
  ├── chunk_operation.go        # Generic CHUNK operation base
  ├── chunk_sender.go            # Generic sender (reusable by KDC, agents, etc.)
  ├── chunk_receiver.go          # Generic receiver
  ├── notify_handler.go          # Generic NOTIFY(CHUNK) handler
  ├── confirmation.go            # Generic confirmation accumulation
  └── long_term_keys.go          # Long-term key lookup/validation
```

This would eliminate duplication and make DNS mode implementation cleaner.

## Open Questions for Investigation

1. **Current API Mode Implementation**: Where in tdns/v2 is agent discovery and API communication implemented? What works and what needs redesign?
2. **Data Models**: What database tables store agent sync data? How is it keyed per-zone?
3. **Confirmation System**: How are confirmations currently handled in API mode? Can they be unified?
4. **KDC/KRS Generalization**: What parts of tdns-nm/tnm/kdc and tdns-nm/tnm/krs can be extracted and generalized?
5. **Transport Abstraction**: What abstraction layer allows API mode and DNS mode to share the same business logic?
6. **Relocate Operation**: Where should private operational addresses be stored and managed?

## References

- HSYNC: IETF Draft (to be specified)
- DNSSEC: RFC 4033, 4034, 4035
- TLSA: RFC 6698
- SVCB: RFC 9460
- URI RRset: RFC 7553
- NOTIFY: RFC 1996
- TSIG: RFC 2845

---

**Document Status**: Implementation complete through Phase 4, ready for testing

**Next Steps (Phase 5)**:
1. Implement debug CLI commands for testing HSYNC operations
2. Create isolated component tests for CHUNK operations
3. Set up integration tests for agent-to-agent communication
4. Test DNS mode operations end-to-end
5. Validate multi-provider coordination scenarios
