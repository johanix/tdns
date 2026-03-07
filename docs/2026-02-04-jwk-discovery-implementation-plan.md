# JWK-Based Agent Discovery Implementation Plan

**Status**: In Progress (Phase 2)
**Date**: 2026-02-04
**Author**: Implementation plan for DNS-based agent discovery using JWK RRtype

## Overview

This document outlines the complete implementation plan for adding JWK-based public key publication to the TDNS agent discovery system. The goal is to enable agents to automatically discover each other via DNS and establish secure communication channels.

## Background

### Current State
- `LocateAgent()` in [agent_utils.go](../v2/agent_utils.go) performs HSYNC-triggered discovery
- Works for API transport, DNS transport less tested
- Missing: standardized public key publication mechanism
- Preliminary implementation in [agent_discovery.go](../v2/agent_discovery.go) needs integration

### Design Decision
After discussion, the design uses:
- **RRtype mnemonic**: `JWK` (not AGENTKEY)
- **RDATA format**: base64url-encoded JSON per RFC 7517
- **Rationale**: JWK is a generic facility, not agent-specific. Parsers exist, format is well-defined.
- **Key types supported**: JOSE P-256 (ECDSA), HPKE x25519 (Curve25519)

### Key Requirements
1. **Integration**: Discovery must use the same mechanism whether triggered by HSYNC or CLI
2. **Auto-publication**: Agents must automatically publish their discovery records
3. **Transport fallback**: API → DNS fallback already implemented in TransportManager
4. **Review**: `LocateAgent()` suspected to have problems requiring fixes

## Implementation Phases

### Phase 1: JWK RRtype Specification and Implementation

#### 1.1 Define JWK RRtype Specification

**Wire Format**:
```
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     NAME                      /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     TYPE (JWK)                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                   RDATA                       /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

RDATA format:
    - Variable-length base64url-encoded JWK JSON string
    - No internal structure in wire format (opaque blob)
```

**Type Code**:
- Testing: 65300 (private use range 65280-65534)
- Production: Request IANA allocation

**Zone File Format**:
```
agent.alpha.dnslab. 3600 IN JWK "eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Ii4uLiIsInkiOiIuLi4ifQ"
```

**JWK JSON Structure** (before base64url encoding):

P-256 (ECDSA):
```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "base64url-x-coordinate",
  "y": "base64url-y-coordinate"
}
```

X25519:
```json
{
  "kty": "OKP",
  "crv": "X25519",
  "x": "base64url-public-key"
}
```

**Size Estimates**:
- P-256: ~160-180 bytes JSON → ~210-240 bytes base64url
- X25519: ~90-110 bytes JSON → ~120-150 bytes base64url
- Both well within DNS size limits (512 bytes UDP, 64KB TCP/EDNS)

#### 1.2 Implement JWK RRtype in miekg/dns

**File**: Create `tdns/v2/dns_jwk.go`

Tasks:
- Define `dns.JWK` struct implementing `dns.RR` interface
- Implement zone file parsing: `"base64url-string"` → decoded data
- Implement wire format encoding/decoding
- Add type registration (TypeJWK constant)
- Follow miekg/dns patterns from existing RRtypes

Required methods:
```go
type JWK struct {
    Hdr dns.RR_Header
    JWKData string // base64url-encoded JWK JSON
}

func (rr *JWK) Header() *dns.RR_Header
func (rr *JWK) String() string
func (rr *JWK) copy() dns.RR
func (rr *JWK) len() int
func (rr *JWK) pack(msg []byte, off int, compression map[string]int, compress bool) (int, error)
func (rr *JWK) unpack(msg []byte, off int) (int, error)
```

#### 1.3 Create JWK Helper Functions

**File**: Create `tdns/v2/jwk_helpers.go`

Functions needed:
```go
// EncodePublicKeyToJWK converts a Go crypto.PublicKey to base64url JWK
func EncodePublicKeyToJWK(key crypto.PublicKey) (string, string, error)
    Returns: (base64url-jwk, key-algorithm, error)
    Supports: *ecdsa.PublicKey (P-256), ed25519.PublicKey, x25519 public key

// DecodeJWKToPublicKey parses base64url JWK to Go crypto.PublicKey
func DecodeJWKToPublicKey(jwkData string) (crypto.PublicKey, string, error)
    Returns: (public-key, key-algorithm, error)

// ValidateJWK checks if JWK is well-formed
func ValidateJWK(jwkData string) error
```

Implementation details:
- Use `encoding/json` for JWK JSON handling
- Use `encoding/base64.RawURLEncoding` for base64url
- Support P-256 (`kty: EC, crv: P-256`)
- Support X25519 (`kty: OKP, crv: X25519`)
- Clear error messages for validation failures

---

### Phase 2: Review and Fix LocateAgent()

**Status**: In Progress

#### 2.1 Analyze Current LocateAgent() Implementation

**Location**: [agent_utils.go:99-234](../v2/agent_utils.go#L99-L234)

**Current Flow**:
1. Skip if agent is self
2. Check if agent already exists in registry
3. Initialize agent with `AgentStateNeeded`
4. Launch goroutine for discovery
5. Look up URI records for _https._tcp and _dns._tcp
6. Look up SVCB records (code incomplete in provided excerpt)

**Scope of Review**:
- **Concurrency safety**: Verify mutex usage, race conditions
- **Error handling**: Check for unhandled errors, proper propagation
- **State transitions**: Verify state machine correctness (NEEDED → KNOWN → INTRODUCED → OPERATIONAL)
- **Resource leaks**: Check for goroutine leaks, unclosed channels
- **DNS lookup logic**: Verify query construction, response parsing
- **Transport detection**: Ensure both API and DNS transports are discovered
- **Integration points**: Check how it interacts with AgentRegistry, TransportManager, PeerRegistry
- **Retry logic**: Verify retry behavior on failures
- **Timeout handling**: Check for hanging operations

**Specific Issues to Investigate**:
- Lines 175-198: API URI lookup in separate goroutine with no synchronization on completion
- Lines 205-228: DNS URI lookup similar pattern
- No visible completion check before considering discovery "done"
- No KEY or TLSA record lookup visible in provided excerpt
- State change to `AgentStateKnown` not visible in excerpt
- Unclear when `SingleHello()` is triggered to move to `AgentStateIntroduced`

#### 2.2 Document Problems Found

**File**: Create `tdns/docs/locateagent-review-findings.md`

Structure:
```markdown
# LocateAgent() Review Findings

## Critical Issues
- Issue 1: Description, impact, proposed fix

## Major Issues
- Issue 2: Description, impact, proposed fix

## Minor Issues
- Issue 3: Description, impact, proposed fix

## Recommendations
- Overall improvements needed
```

#### 2.3 Fix Identified Problems

For each issue:
1. Document the problem clearly
2. Propose a fix
3. Implement the fix
4. Test the fix
5. Update documentation

**Files to modify**:
- [agent_utils.go](../v2/agent_utils.go) - LocateAgent() fixes
- Related functions that LocateAgent() depends on

---

### Phase 3: Integrate Discovery Code with LocateAgent()

#### 3.1 Merge Discovery Logic

**Current Situation**:
- [agent_discovery.go](../v2/agent_discovery.go): Standalone `DiscoverAgent()` function
- [agent_utils.go](../v2/agent_utils.go): HSYNC-triggered `LocateAgent()` function
- Both do similar DNS lookups but in different styles

**Integration Strategy**:

1. **Extract Common DNS Lookup Helpers** (new file: `agent_discovery_common.go`):
   ```go
   // lookupAgentAPIURI looks up _https._tcp.<identity> URI record
   func lookupAgentAPIURI(ctx context.Context, identity string, resolvers []string) (*dns.URI, error)

   // lookupAgentDNSURI looks up _dns._udp.<identity> URI record
   func lookupAgentDNSURI(ctx context.Context, identity string, resolvers []string) (*dns.URI, error)

   // lookupAgentJWK looks up <identity> JWK record for public key
   func lookupAgentJWK(ctx context.Context, identity string, resolvers []string) (*dns.JWK, error)

   // lookupAgentTLSA looks up _443._tcp.<identity> TLSA record
   func lookupAgentTLSA(ctx context.Context, identity string, port uint16, resolvers []string) (*dns.TLSA, error)

   // lookupAgentAddresses looks up <identity> A/AAAA records
   func lookupAgentAddresses(ctx context.Context, identity string, resolvers []string) ([]string, error)
   ```

2. **Refactor DiscoverAgent()** to use common helpers:
   - Keep current synchronous structure
   - Replace direct DNS queries with helper calls
   - Add JWK lookup (replace KEY lookup)
   - Return `AgentDiscoveryResult` as before

3. **Refactor LocateAgent()** to use common helpers:
   - Keep current asynchronous/goroutine structure (for backward compat)
   - Replace inline DNS queries with helper calls
   - Add JWK lookup
   - Fix identified issues from Phase 2
   - Ensure proper state transitions

4. **Result**: Both paths use identical DNS lookup logic, just orchestrated differently

#### 3.2 Unify Registration Path

**Goal**: Both discovery paths register agents consistently

**Files**:
- [agent_discovery.go](../v2/agent_discovery.go): `RegisterDiscoveredAgent()`, `DiscoverAndRegisterAgent()`
- [agent_utils.go](../v2/agent_utils.go): LocateAgent's implicit registration

**Tasks**:
1. Ensure `RegisterDiscoveredAgent()` handles both AgentRegistry and PeerRegistry
2. Update `LocateAgent()` to call `RegisterDiscoveredAgent()` or use same logic
3. Verify state transitions are consistent:
   - Discovery → `PeerStateKnown` / `AgentStateKnown`
   - After Hello → `PeerStateIntroducing` / `AgentStateIntroduced`
   - After Beat → `PeerStateOperational` / `AgentStateOperational`

4. Handle dual registry correctly:
   - PeerRegistry: Used by TransportManager (new path)
   - AgentRegistry: Used by HSYNC legacy (backward compat)
   - Keep both updated for now

#### 3.3 Add Discovery Trigger Modes

**Three trigger paths**:

1. **HSYNC-triggered** (existing):
   - Zone HSYNC RRset changes
   - `LocateAgent()` called for new agents in RRset
   - Asynchronous discovery

2. **CLI-triggered** (implemented):
   - User runs: `tdns-cliv2 agent distrib discover agent.delta.dnslab.`
   - Calls: `DiscoverAndRegisterAgent()`
   - Synchronous with timeout

3. **API auto-discovery** (implemented):
   - Ping to unknown agent identity
   - [apihandler_agent_distrib.go:278-298](../v2/apihandler_agent_distrib.go#L278-L298)
   - Automatic fallback discovery

**Verification**: All three paths must:
- Use same DNS lookup helpers
- Register agents consistently
- Set same initial states
- Trigger Hello/Beat correctly

---

### Phase 4: Update Agent Setup for Auto-Publication

#### 4.1 Locate Agent Setup Functions

**File**: [agent_setup.go](../v2/agent_setup.go)

**Key Functions**:
- `SetupAgent()` (line 274): Main entry point
- `SetupAgentAutoZone()` (line 38): Creates auto zone for agent identity
- `SetupApiTransport()` (line 83): Publishes API discovery records
- `SetupDnsTransport()` (line 178): Publishes DNS discovery records

**Current Publications** (API transport):
- `_https._tcp.<identity> URI` - API endpoint
- `<host> A/AAAA` - IP addresses
- `_<port>._tcp.<host> TLSA` - TLS certificate
- `<host> SVCB` - Service binding with addresses

**Current Publications** (DNS transport):
- `_dns._tcp.<identity> URI` - DNS endpoint
- `<host> A/AAAA` - IP addresses
- `<identity> KEY` - SIG(0) public key (line 223: `AgentSig0KeyPrep()`)
- `<host> SVCB` - Service binding

**Missing**: JWK record publication

#### 4.2 Implement JWK Auto-Publication

**Task**: Add JWK record publication to agent setup

**Location**: Both `SetupApiTransport()` and `SetupDnsTransport()` need JWK

**New Function** (add to `agent_setup.go`):
```go
func (conf *Config) SetupJWKPublication() error {
    identity := dns.Fqdn(conf.Agent.Identity)

    du := createDeferredUpdate(
        identity,
        fmt.Sprintf("Publish JWK record for agent %q", identity),
        func() error {
            zd, ok := Zones.Get(identity)
            if !ok {
                return fmt.Errorf("SetupJWKPublication: zone data for agent identity %q not found", identity)
            }

            // Get agent's long-term public key
            // TODO: Determine source of public key (from config? from keystore?)
            var publicKey crypto.PublicKey

            // For DNS transport: extract from SIG(0) key
            // For API transport: extract from TLS certificate

            // Encode to JWK
            jwkData, keyAlg, err := EncodePublicKeyToJWK(publicKey)
            if err != nil {
                return fmt.Errorf("SetupJWKPublication: failed to encode public key to JWK: %v", err)
            }

            log.Printf("SetupJWKPublication: publishing JWK record for agent %q (algorithm: %s)", identity, keyAlg)

            // Publish JWK record
            err = zd.PublishJWKRR(identity, jwkData)
            if err != nil {
                return fmt.Errorf("SetupJWKPublication: failed to publish JWK record: %v", err)
            }

            log.Printf("SetupJWKPublication: successfully published JWK record for agent %q", identity)
            return nil
        },
    )

    select {
    case conf.Internal.DeferredUpdateQ <- du:
        return nil
    default:
        return fmt.Errorf("SetupJWKPublication: deferred update queue is full")
    }
}
```

**New Method** (add to `zone_updates.go` or similar):
```go
func (zd *ZoneData) PublishJWKRR(owner, jwkData string) error {
    // Create JWK record
    jwkRR := &dns.JWK{
        Hdr: dns.RR_Header{
            Name:   dns.Fqdn(owner),
            Rrtype: dns.TypeJWK,
            Class:  dns.ClassINET,
            Ttl:    3600,
        },
        JWKData: jwkData,
    }

    // Add to zone
    return zd.AddRR(jwkRR)
}
```

**Integration**:
1. Call `SetupJWKPublication()` from `SetupAgent()` (after transport setup)
2. Ensure it runs after key generation (for DNS transport)
3. Ensure it runs after certificate loading (for API transport)

**Open Questions**:
- Which public key to publish? DNS SIG(0) key? API TLS cert key? Both?
- If both: publish multiple JWK records or combine in one?
- Recommendation: Publish separate keys for DNS and API transports if they differ

#### 4.3 Publication Records Summary

After Phase 4, agents will publish:

**For API Transport**:
- `_https._tcp.<identity> IN URI` - API endpoint URL
- `_443._tcp.<identity> IN TLSA` - TLS certificate anchor
- `<host> IN A/AAAA` - IP addresses
- `<host> IN SVCB` - Service binding
- `<identity> IN JWK` - Public key (from TLS cert)

**For DNS Transport**:
- `_dns._udp.<identity> IN URI` - DNS endpoint URL
- `<host> IN A/AAAA` - IP addresses
- `<host> IN SVCB` - Service binding
- `<identity> IN KEY` - SIG(0) public key (existing)
- `<identity> IN JWK` - Public key (from SIG(0) key)

**Question**: Should we keep KEY record for backward compatibility? Likely yes.

---

### Phase 5: Testing and Validation

#### 5.1 Unit Tests

**File**: Create `tdns/v2/jwk_test.go`

Tests:
- JWK encoding/decoding for P-256
- JWK encoding/decoding for X25519
- Base64url round-trip
- Invalid JWK handling
- DNS RR parsing/unpacking

**File**: Create `tdns/v2/agent_discovery_test.go`

Tests:
- Discovery result parsing
- Registration with both registries
- State transitions
- Error handling

#### 5.2 Integration Tests

**Scenarios**:

1. **HSYNC-Triggered Discovery**:
   - Setup: Two agents with HSYNC configuration
   - Action: Add zone with HSYNC RRset
   - Verify: LocateAgent() discovers remote agent
   - Verify: JWK record is looked up
   - Verify: Agent moves to Known → Introduced → Operational

2. **CLI-Triggered Discovery**:
   - Setup: Agent with published JWK records
   - Action: `tdns-cliv2 agent distrib discover <identity>`
   - Verify: Discovery completes successfully
   - Verify: Agent registered in PeerRegistry
   - Verify: Can ping discovered agent

3. **API Auto-Discovery**:
   - Setup: Two agents, one unknown to the other
   - Action: Ping unknown agent
   - Verify: Auto-discovery triggers
   - Verify: Agent registered and ping succeeds

4. **Transport Fallback**:
   - Setup: Agent with both API and DNS transport
   - Action: Simulate API transport failure
   - Verify: Fallback to DNS transport works
   - Verify: Communication succeeds via DNS

#### 5.3 Manual Testing Scenarios

**Test Lab Setup**:
- agent.alpha.dnslab. (local)
- agent.delta.dnslab. (remote)
- Both with JWK records published

**Test Cases**:

1. **Mutual Discovery**:
   ```bash
   # On alpha
   tdns-cliv2 agent distrib discover agent.delta.dnslab.
   tdns-cliv2 agent distrib op ping --to agent.delta.dnslab.

   # On delta
   tdns-cliv2 agent distrib discover agent.alpha.dnslab.
   tdns-cliv2 agent distrib op ping --to agent.alpha.dnslab.
   ```

2. **API-Only Agent**:
   - Configure agent with only API transport
   - Verify URI, TLSA, JWK records published
   - Verify discovery works from remote

3. **DNS-Only Agent**:
   - Configure agent with only DNS transport
   - Verify URI, KEY, JWK records published
   - Verify discovery works from remote

4. **Both Transports**:
   - Configure agent with both transports
   - Verify preferred transport is used
   - Verify fallback works on failure

5. **TLSA Verification**:
   - Verify TLS certificate is validated against TLSA
   - Test with mismatched TLSA (should fail)
   - Test with expired certificate (should fail)

---

## Implementation Order

### Recommended Sequence

1. ✅ **Phase 2 Start**: Review LocateAgent() (IN PROGRESS)
   - Identify and document issues
   - Critical for understanding what needs fixing

2. **Phase 1**: Implement JWK RRtype
   - Foundation for everything else
   - Can be developed and tested independently

3. **Phase 2 Complete**: Fix LocateAgent()
   - Apply fixes from review
   - Prepare for integration

4. **Phase 3**: Integrate Discovery Mechanisms
   - Merge DiscoverAgent() and LocateAgent()
   - Use common helpers
   - Add JWK lookups

5. **Phase 4**: Auto-Publication
   - Enable discovery by others
   - Complete the cycle

6. **Phase 5**: Testing
   - Validate everything works together
   - Test all trigger paths
   - Verify transport fallback

### Dependencies

```
Phase 2 (Review) → Phase 1 (JWK RRtype) → Phase 3 (Integration)
                                              ↓
                    Phase 4 (Publication) ← ←
                           ↓
                    Phase 5 (Testing)
```

---

## Key Integration Points

### Files Requiring Modification

**Core Discovery**:
- [agent_discovery.go](../v2/agent_discovery.go) - Add JWK lookup, use common helpers
- [agent_utils.go](../v2/agent_utils.go) - Fix and refactor LocateAgent()
- `agent_discovery_common.go` (NEW) - Common DNS lookup helpers

**Setup and Publication**:
- [agent_setup.go](../v2/agent_setup.go) - Add JWK publication
- `zone_updates.go` or similar - Add PublishJWKRR() method

**JWK Implementation**:
- `dns_jwk.go` (NEW) - JWK RRtype for miekg/dns
- `jwk_helpers.go` (NEW) - Encoding/decoding helpers

**API/CLI** (already implemented):
- [apihandler_agent_distrib.go](../v2/apihandler_agent_distrib.go) - Discover command
- [cli/distrib_cmds.go](../v2/cli/distrib_cmds.go) - CLI discover command

**Testing**:
- `jwk_test.go` (NEW)
- `agent_discovery_test.go` (NEW)

### Data Structures

**AgentDiscoveryResult** (existing):
```go
type AgentDiscoveryResult struct {
    Identity  string
    APIUri    string
    DNSUri    string
    PublicKey *dns.KEY  // Change to *dns.JWK
    TLSA      *dns.TLSA
    Addresses []string
    Port      uint16
    Error     error
    Partial   bool
}
```

**Changes Needed**:
- Replace `PublicKey *dns.KEY` with `PublicKey *dns.JWK`
- Consider adding `KeyAlgorithm string` field

---

## Design Principles

1. **Single Discovery Mechanism**
   - Both HSYNC and CLI use same underlying DNS lookups
   - Only orchestration differs (sync vs async)

2. **JWK as Universal Format**
   - Generic facility, not agent-specific
   - Can be used for other purposes beyond agent discovery
   - Well-defined standard (RFC 7517)

3. **Graceful Fallback**
   - API → DNS transport fallback already implemented
   - Discovery should attempt both transports
   - Prefer configured transport, fallback on failure

4. **Automatic Publication**
   - Agents auto-publish all discovery records
   - No manual configuration needed
   - Deferred updates ensure zone is ready

5. **State Management**
   - Consistent state transitions across all paths
   - Clear state machine: NEEDED → KNOWN → INTRODUCED → OPERATIONAL
   - Proper error states and recovery

6. **Backward Compatibility**
   - Keep KEY records for SIG(0) (existing functionality)
   - Add JWK records alongside (new functionality)
   - AgentRegistry and PeerRegistry coexist during migration

---

## Open Questions / Decisions Needed

1. **Public Key Selection**:
   - Q: Which public key to publish in JWK?
   - Options:
     a) DNS SIG(0) key only
     b) API TLS certificate key only
     c) Both (separate JWK records)
     d) New dedicated long-term key (neither SIG(0) nor TLS)
   - Recommendation: (c) Both - publish what's used for each transport

2. **KEY vs JWK**:
   - Q: Keep KEY record or replace entirely with JWK?
   - Recommendation: Keep both - KEY for SIG(0), JWK for general discovery

3. **Type Code Allocation**:
   - Q: Use private range (65300) or request IANA allocation?
   - Recommendation: Start with private range, request allocation if successful

4. **Multiple JWK Records**:
   - Q: Can one owner have multiple JWK records (DNS key + API key)?
   - A: Yes, DNS allows RRsets with multiple records
   - Discovery should handle multiple JWK records

5. **JWK Record TTL**:
   - Q: What TTL for JWK records?
   - Recommendation: 3600 seconds (1 hour) - same as other agent records
   - Long-term keys change infrequently

---

## Success Criteria

### Phase Completion Criteria

**Phase 1 Complete**:
- [ ] JWK RRtype implemented in miekg/dns fork
- [ ] Zone file parsing works
- [ ] Wire format encoding/decoding works
- [ ] Helper functions encode/decode P-256 and X25519
- [ ] Unit tests pass

**Phase 2 Complete**:
- [ ] LocateAgent() review document written
- [ ] All identified issues documented with severity
- [ ] Critical issues fixed
- [ ] Tests verify fixes work

**Phase 3 Complete**:
- [ ] Common DNS lookup helpers extracted
- [ ] DiscoverAgent() uses common helpers
- [ ] LocateAgent() uses common helpers
- [ ] JWK lookup added to both paths
- [ ] Both paths register agents consistently
- [ ] All three trigger modes work (HSYNC, CLI, API auto-discovery)

**Phase 4 Complete**:
- [ ] JWK records auto-published on agent startup
- [ ] Publication works for both API and DNS transports
- [ ] Deferred updates handle zone readiness correctly
- [ ] Can verify records with dig/kdig

**Phase 5 Complete**:
- [ ] All unit tests pass
- [ ] Integration tests pass for all scenarios
- [ ] Manual testing confirms end-to-end functionality
- [ ] Transport fallback verified
- [ ] Two agents can discover and communicate

### Overall Success

Project is successful when:
1. Two agents can discover each other via DNS (no manual config)
2. Discovery works via HSYNC, CLI, and auto-discovery triggers
3. JWK records are published and consumed correctly
4. Transport fallback (API → DNS) works seamlessly
5. All tests pass
6. Code is integrated (not parallel implementations)

---

## Timeline Estimate

*Note: No specific time estimates per user request. This is a complexity-based ordering only.*

- **Phase 2 (Review)**: Focus on thoroughness, not speed
- **Phase 1 (JWK RRtype)**: Standard implementation work
- **Phase 3 (Integration)**: Most complex, requires careful refactoring
- **Phase 4 (Publication)**: Straightforward once Phase 3 complete
- **Phase 5 (Testing)**: Depends on issues found

---

## References

- RFC 7517: JSON Web Key (JWK)
- [agent_discovery.go](../v2/agent_discovery.go)
- [agent_utils.go](../v2/agent_utils.go)
- [agent_setup.go](../v2/agent_setup.go)
- [agent/transport/peer.go](../v2/agent/transport/peer.go)
- miekg/dns library documentation

---

## Revision History

- 2026-02-04: Initial plan created
- 2026-02-04: Phase 2 (LocateAgent review) started
