# Agent Synchronization Data Flow Review

## Executive Summary

This review examines the complete data flow for synchronizing DNS RRsets across multiple providers in the TDNS agent system. The review confirms that **most core components are implemented**, but **several critical gaps prevent the complete synchronization cycle from working**.

## Architectural Context

### The Multi-Provider Problem
- Customer zone has nameservers from multiple providers (customer, providerA, providerB)
- Each provider contributes partial NS RRset
- Goal: All providers publish the union of all contributions
- **Critical requirement**: Source-attributed storage (track which peer contributed which data)

### Key Mechanisms
- **HSYNC RRset**: Discovery/membership mechanism (WHO to sync with)
- **SYNC messages**: Actual data synchronization (WHAT data to exchange)
- **Combiner**: Authorized modification point between customer and signer
- **Agent**: Complex component that detects discrepancies and requests combiner updates

---

## Data Flow Analysis

### ✅ WORKING: Agent Receives SYNC from Peers

**Files**: [hsyncengine.go:171-336](tdns/v2/hsyncengine.go#L171-L336), [syncheddataengine.go:275-342](tdns/v2/syncheddataengine.go#L275-L342)

**Flow**:
1. SYNC message arrives via DNS transport (CHUNK NOTIFY)
2. Router routes to HandleSync handler ([handlers.go](tdns/v2/agent/transport/handlers.go))
3. Handler creates IncomingMessage, stores in context
4. Middleware routes to hsyncengine via IncomingChan
5. HsyncEngine.MsgHandler receives AgentMsgPost (line 171)
6. Creates ZoneUpdate with RRsets from message (lines 216-237)
7. Sends SynchedDataUpdate to SynchedDataEngine queue (line 241)

**Result**: ✅ Agent successfully receives and queues remote SYNC messages

---

### ✅ WORKING: Agent Stores Peer Contributions

**Files**: [syncheddataengine.go:275-342](tdns/v2/syncheddataengine.go#L275-L342), [agent_policy.go:65-166](tdns/v2/agent_policy.go#L65-L166)

**Storage Structure**:
```go
type ZoneDataRepo struct {
    Repo ConcurrentMap[ZoneName, *AgentRepo]  // map[zone]AgentRepo
}

type AgentRepo struct {
    Data ConcurrentMap[AgentId, *OwnerData]   // map[agentID]OwnerData
}

type OwnerData struct {
    RRtypes ConcurrentMap[uint16, RRset]      // map[RRtype]RRset
}
```

**Storage Detail Level**:
- ✅ **Zone**: Tracked (ZoneName key in ZoneDataRepo)
- ✅ **Source Agent**: Tracked (AgentId key in AgentRepo.Data)
- ✅ **RRtype**: Tracked (uint16 key in OwnerData.RRtypes)
- ✅ **RRs**: Tracked (full RRset with individual RRs)

**Processing** ([agent_policy.go:65-166](tdns/v2/agent_policy.go#L65-L166)):
1. EvaluateUpdate: Validates RRtype (NS, DNSKEY, CDS, CSYNC) and owner (apex only)
2. ProcessUpdate: Stores/updates in source-attributed structure
3. Handles DNS UPDATE semantics:
   - Class ANY: Delete entire RRset
   - Class NONE: Delete individual RR
   - Class IN: Add RR to RRset
4. **REPLACE semantics**: Each agent's contribution completely replaces their previous contribution

**Result**: ✅ Agent stores contributions with **full source attribution** (zone, agent, RRtype, RRs)

---

### ✅ WORKING: Agent Sends Updates to Combiner (CHUNK Transport)

**Files**: [syncheddataengine.go:311-333](tdns/v2/syncheddataengine.go#L311-L333), [combiner_chunk.go:360-454](tdns/v2/combiner_chunk.go#L360-L454)

**Flow for Remote Updates**:
1. SynchedDataEngine receives remote update (line 275)
2. ProcessUpdate stores in ZoneDataRepo (line 304)
3. If data changed, sends to combiner (lines 315-332):
   - Creates CombinerSyncRequest via ConvertZoneUpdateToSyncRequest
   - Calls SendToCombiner with CombinerHandler
   - Handler.ProcessUpdate applies to zone via AddCombinerDataNG
4. Logs success/failure (lines 323-331)

**Flow for Local Updates** ([syncheddataengine.go:202-219](tdns/v2/syncheddataengine.go#L202-L219)):
- Same mechanism, sends to combiner after storing locally
- Also sends to remote agents (lines 221-264)

**Combiner Processing** ([combiner_chunk.go:360-454](tdns/v2/combiner_chunk.go#L360-L454)):
1. Validates zone exists (line 374)
2. Parses and validates RRs (lines 386-422)
3. Enforces policy:
   - Only allowed RRtypes (NS, DNSKEY, CDS, CSYNC)
   - Only apex updates (line 409)
4. Applies via zd.AddCombinerDataNG (line 426)
5. Returns detailed response with applied/rejected RRs

**Result**: ✅ Agent-to-combiner communication works via CHUNK transport

---

### ✅ WORKING: Agent Sends SYNC to Peers

**Files**: [syncheddataengine.go:220-264](tdns/v2/syncheddataengine.go#L220-L264), [hsyncengine.go:428-488](tdns/v2/hsyncengine.go#L428-L488)

**Flow**:
1. Local update applied and stored in ZoneDataRepo
2. SynchedDataEngine sends NOTIFY to remote agents (line 229)
3. Gets operational agents via RemoteOperationalAgents (line 223)
4. For each agent, sends AgentMsgNotify via SendApiMsg or TransportManager
5. Uses TransportManager.SendSyncWithFallback for DNS/API fallback (lines 434-455)

**Transport Options**:
- **Primary**: DNS transport via TransportManager (CHUNK NOTIFY)
- **Fallback**: API transport via agent.SendApiMsg

**Result**: ✅ Agent sends SYNC to peers (both via CHUNK and API)

---

## ❌ MISSING: Zone Transfer Triggers Re-evaluation

**Problem**: When agent receives zone transfer from signer, it should:
1. Extract RRsets that are synchronized (NS, DNSKEY, etc.)
2. Compare received RRsets with expected union from ZoneDataRepo
3. Detect discrepancies (missing contributions, extra data, etc.)
4. Send update requests to combiner to fix discrepancies

**Current State**:
- Zone transfer handling exists ([notifyresponder.go:189-200](tdns/v2/notifyresponder.go#L189-L200))
- NOTIFY(SOA) triggers zone refresh via zonech channel
- **No code found that compares zone data with ZoneDataRepo**
- **No code found that detects discrepancies**
- **No code found that generates combiner update requests based on discrepancies**

**Evidence of Gap**:
```bash
# Search for comparison/discrepancy detection code
grep -r "CompareWithExpected\|DetectDiscrepanc\|VerifyUnion" tdns/v2/
# Result: No files found
```

**Impact**: 🔴 **Critical gap** - The verification loop doesn't work. Agent stores peer contributions but never uses them to verify the signer's zone matches expectations.

---

## ❌ MISSING: Complete Union Calculation

**Problem**: To detect discrepancies, agent must:
1. Iterate through ZoneDataRepo for the zone
2. For each synchronized RRtype (NS, DNSKEY), compute union across all peers
3. Compare union with what signer published
4. Generate update request for combiner if mismatch

**Current State**:
- ZoneDataRepo structure supports this (map[zone]map[agent]map[rrtype]rrset)
- No code found that computes union across all agents
- No code found that compares union with zone transfer data

**Required Function** (doesn't exist):
```go
// Pseudocode - THIS DOES NOT EXIST
func (zdr *ZoneDataRepo) ComputeExpectedUnion(zone ZoneName, rrtype uint16) (*RRset, error) {
    agentRepo := zdr.Get(zone)
    var union RRset
    for _, agentData := range agentRepo.Data.Items() {
        if rrset, ok := agentData.RRtypes.Get(rrtype); ok {
            union.Merge(rrset)  // Add all RRs from this agent
        }
    }
    return &union, nil
}
```

**Impact**: 🔴 **Critical gap** - Can't verify signer matches expectations without union computation

---

## Summary Table

| Component | Status | Location | Notes |
|-----------|--------|----------|-------|
| Receive SYNC from peers | ✅ Working | hsyncengine.go:171-336 | Via CHUNK NOTIFY, routes to queue |
| Store peer contributions | ✅ Working | agent_policy.go:65-166 | Full source attribution: zone/agent/RRtype/RRs |
| Storage detail sufficient | ✅ Yes | syncheddataengine.go:73-110 | Tracks zone, agent, RRtype, individual RRs |
| Send to combiner (CHUNK) | ✅ Working | syncheddataengine.go:311-333 | Both remote and local updates |
| Combiner CHUNK handler | ✅ Working | combiner_chunk.go:360-454 | Validates and applies updates |
| Send SYNC to peers | ✅ Working | syncheddataengine.go:220-264 | CHUNK + API fallback |
| Zone transfer handling | ⚠️ Partial | notifyresponder.go:189-200 | Receives NOTIFY(SOA), triggers refresh |
| Compare zone with union | ❌ Missing | - | No discrepancy detection code found |
| Union calculation | ❌ Missing | - | No code to compute expected union |
| Generate combiner updates | ❌ Missing | - | No automatic discrepancy fixing |

---

## Critical Gaps

### 1. Zone Transfer Post-Processing (Critical)
**Missing**: After zone transfer from signer completes, no code re-evaluates synchronized RRsets.

**Needed**:
- Hook into zone refresh completion
- Extract synchronized RRsets (NS, DNSKEY, CDS, CSYNC)
- Trigger comparison with ZoneDataRepo

### 2. Union Computation (Critical)
**Missing**: No function to compute expected union of peer contributions.

**Needed**:
```go
func (zdr *ZoneDataRepo) ComputeExpectedUnion(zone ZoneName) map[uint16]*RRset
```

### 3. Discrepancy Detection (Critical)
**Missing**: No code compares zone transfer data with expected union.

**Needed**:
```go
func DetectDiscrepancies(receivedZone *ZoneData, expectedUnions map[uint16]*RRset) []Discrepancy
```

### 4. Automatic Combiner Updates (Critical)
**Missing**: No code generates combiner update requests when discrepancies found.

**Needed**:
```go
func (agent *Agent) FixDiscrepancies(discrepancies []Discrepancy) error {
    // Generate CombinerSyncRequest
    // Send to combiner
}
```

---

## Recommended Implementation Path

### Phase 1: Union Computation
1. Add `ComputeExpectedUnion(zone, rrtype)` to ZoneDataRepo
2. Test with mock data in ZoneDataRepo

### Phase 2: Zone Transfer Hook
1. Add callback to RefreshEngine when zone transfer completes
2. Extract NS, DNSKEY, CDS, CSYNC from transferred zone
3. Trigger comparison

### Phase 3: Discrepancy Detection
1. Implement comparison logic (union vs. received)
2. Generate Discrepancy list (missing RRs, extra RRs)
3. Log discrepancies for visibility

### Phase 4: Automatic Fixing
1. Convert discrepancies to CombinerSyncRequest
2. Send to combiner via existing CHUNK mechanism
3. Log results

### Phase 5: Testing
1. Multi-agent test scenario
2. Inject discrepancies (combiner removes peer contribution)
3. Verify agent detects and fixes

---

## Conclusion

**What Works**:
- ✅ Agent receives SYNC from peers (CHUNK NOTIFY transport)
- ✅ Agent stores contributions with full source attribution (zone/agent/RRtype/RRs)
- ✅ Agent sends updates to combiner (CHUNK transport works)
- ✅ Combiner processes CHUNK updates correctly
- ✅ Agent sends SYNC to peers (CHUNK + API fallback)

**What's Missing**:
- ❌ Zone transfer doesn't trigger re-evaluation
- ❌ No union computation across peer contributions
- ❌ No discrepancy detection comparing zone vs. union
- ❌ No automatic combiner update requests when discrepancies found

**Bottom Line**:
The **storage and communication infrastructure is complete and working**. The **verification and self-healing loop is completely missing**. Agent can exchange data with peers and combiner, but doesn't use that data to verify the signer's zone matches expectations.

**Priority**: Implement the verification loop (Phases 1-4 above) to complete the multi-provider synchronization system.
