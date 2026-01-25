# Project 2: DNS Mode for Multi-Provider DNSSEC Coordination

## Document Version
- **Date**: 2025-01-25
- **Status**: Requirements and Design Phase (Pre-Implementation)
- **Author**: Architecture Review
- **Project**: TDNS Multi-Provider DNS Synchronization

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
   - Encrypted with Agent B's public key (+ optional multi-recipient)
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
- Includes operation-specific fields

**Confirmation Operation**:
- Response to any operation
- Details exactly what was received
- Lists processing status per item
- Includes correlation IDs to link to original operation

## Agent-to-Agent Communication

### Scenario: NS Record Coordination

```
Zone: example.com
Providers: A (ns1.providerA.com), B (ns1.providerB.com)

1. Zone owner adds new provider C
   - Updates HSYNC RRset to include ns1.providerC.com
   - All existing providers see updated RRset

2. Agent A detects HSYNC change
   - Sees new provider C in RRset
   - Initiates DNS mode discovery for Agent C

3. Agent A sends Sync(NS) CHUNK to Agent B and Agent C
   - Multi-recipient encryption: each agent gets their encrypted_key
   - Payload: "NS RRset should be: ns1.A, ns1.B, ns1.C"

4. Agent B receives and decrypts
   - Queries signer for current NS RRset
   - If different, sends Confirmation(NS) with difference details

5. Agent B sends modification instruction to its Combiner
   - Combiner receives CHUNK via Sync(NS) from Agent B
   - Agent B tells Combiner: "ensure NS RRset includes ns1.C"

6. Combiner modifies zone as it passes to signer
   - When zone transfer from owner arrives, combiner injects NS record for C
   - Signer signs the merged zone
   - Resulting NS RRset now includes all three providers

7. Agent B detects signer's zone changed
   - Sends Confirmation(NS) to Agent A
   - "Successfully updated NS RRset: {ns1.A, ns1.B, ns1.C}"

8. Agent A receives confirmation
   - Marks synchronization complete
   - Logs completion for operator visibility
```

## Agent-to-Combiner Communication

### Scenario: Combiner Receives Sync Instructions

```
Agent at Provider B wants Combiner to modify zone:

1. Agent receives Sync(NS) CHUNK from Agent A
   - Contains new NS record for provider C

2. Agent sends Modification CHUNK to local Combiner
   - Type: Sync(NS)
   - Payload: "Add NS record ns1.C"
   - Signed by Agent with its private key
   - Encrypted with Combiner's public key (or symmetric shared secret)

3. Combiner receives NOTIFY(CHUNK) from Agent
   - Queries Agent for modification CHUNK

4. Combiner decrypts and verifies
   - Validates Agent signature (Agent public key known from enrollment)
   - Checks modification is within allowed scope (NS, glue, DNSKEY, CDS, CSYNC only)

5. Combiner applies modification to next zone transfer
   - Modifications are temporary per-transfer (held in memory)
   - When zone owner sends new AXFR, combiner merges in modifications
   - Sends merged zone to signer

6. Combiner sends Confirmation CHUNK back to Agent
   - Details what was applied
   - References to DNSSEC signatures for proof
   - Signed by Combiner with its private key

7. Agent receives Confirmation
   - Validates Combiner signature
   - Logs successful application
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
| **Encryption** | JWE (single/multi-recipient) | JWE (single/multi-recipient) | JWE |
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

## Implementation Scope

### Phase 1: Design and Infrastructure (Current)
- ✅ Define HSYNC RRset format
- ✅ Specify API mode endpoint discovery
- ✅ Define DNS mode protocol
- ✅ Design CHUNK operations
- ✅ Specify confirmation format
- [ ] Examine existing agent code (tdns/v2)
- [ ] Identify generalization opportunities
- [ ] Plan generalized comms framework

### Phase 2: Generalization (tdns/v2)
- [ ] Extract KDC/KRS-specific code
- [ ] Create generalized CHUNK sender/receiver
- [ ] Create generalized NOTIFY handler
- [ ] Create generalized confirmation accumulator
- [ ] Move to tdns/v2 as shared infrastructure

### Phase 3: DNS Mode Implementation
- [ ] Implement CHUNK operations for hello, sync, confirmation
- [ ] Implement NOTIFY(CHUNK) handling
- [ ] Implement long-term key discovery via DNS
- [ ] Add DNS mode to agent discovery logic
- [ ] Add DNS mode communication alongside API mode

### Phase 4: Agent Integration
- [ ] Update agent to use generalized comms framework
- [ ] Implement multi-transport (API + DNS mode)
- [ ] Update combiner to use generalized comms
- [ ] Implement confirmation handling and logging

### Phase 5: Testing and Debug Infrastructure
- [ ] Add debug CLI commands for isolated testing
- [ ] Simulate provider discovery
- [ ] Simulate CHUNK operations
- [ ] Test confirmation flows
- [ ] Full end-to-end multi-provider test

## Critical Decision: Project 1 vs Project 2 Ordering

### Context
- **Project 1 (JWE/JWS Redesign)**: Multi-recipient support, better JOSE integration
- **Project 2 (DNS Mode)**: Agent-to-agent communication, immediate need

### Trade-offs

**Project 2 First Rationale**:
- Agent-to-agent typically 2-3 providers (multi-recipient not critical now)
- Can use existing single-recipient crypto
- Faster to deliver agent communication
- Can upgrade to multi-recipient later
- Establishes generalized comms framework

**Project 1 First Rationale**:
- Multi-recipient reduces encryption overhead (important for future KDC/KRS scale)
- Stabilizes crypto layer before building DNS mode on top
- Cleaner integration if transport layer doesn't change mid-implementation
- If JWE/JWS requires API changes, better done before DNS mode heavily uses CHUNK

### To Determine: Disruption Analysis Needed

**Key Question**: How disruptive is JWE/JWS to CHUNK comms APIs?
- If mostly internal (serialization, key handling) → Project 2 first is safe
- If requires API changes (CHUNK operation structure, encryption calls) → Project 1 first is safer

**Analysis Step**: Examine current KDC/KRS CHUNK usage patterns in tdns-nm to determine disruption scope.

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
- Encryption/decryption: single and multi-recipient

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

1. **Current API Mode Implementation**: Where in tdns/v2 is agent discovery and API communication implemented?
2. **Data Models**: What database tables store agent sync data? How is it keyed?
3. **Confirmation System**: How are confirmations currently handled in API mode?
4. **KDC/KRS Generalization**: What parts of tdns-nm/tnm/kdc and tdns-nm/tnm/krs can be extracted and generalized?
5. **Multi-Transport**: How should API mode and DNS mode coexist in the agent code?
6. **Encryption Calls**: How deeply are KDC/KRS specific the encryption operation calls?

## References

- HSYNC: IETF Draft (to be specified)
- DNSSEC: RFC 4033, 4034, 4035
- TLSA: RFC 6698
- SVCB: RFC 9460
- URI RRset: RFC 7553
- NOTIFY: RFC 1996
- TSIG: RFC 2845

---

**Document Status**: Ready for code investigation

**Next Steps**:
1. Examine tdns/v2 agent/HSYNC implementation
2. Examine tdns-nm/tnm KDC/KRS communication patterns
3. Map generalization opportunities
4. Assess JWE/JWS disruption
5. Make Project 1 vs Project 2 ordering decision
