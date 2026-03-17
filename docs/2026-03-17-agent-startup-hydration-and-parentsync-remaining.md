# Agent Startup Hydration + Parent Sync Remaining Items

**Date:** 2026-03-17
**Status:** Plan
**Depends on:** Parent Sync Implementation (2026-03-18 plan, Steps 1-8 complete),
  SIG(0) KEY Publication (DNS-147/148/149), Delegation Sync Refresh (DNS-136-143)

## Overview

Two sets of work that improve agent operational robustness:

**Part A** — Agent startup hydration: bring the agent automatically in sync
with all available data when it starts, without manual intervention.

**Part B** — Parent sync remaining items: persist outgoing serial, add
EDNS(0)/EDE to UPDATE messages, combiner NS target validation.

---

## Part A: Agent Startup Hydration

### Problem

When an agent restarts, its SDE (SynchedDataEngine) is empty. Currently the
startup loop only sends RFI EDITS to the combiner, which returns only the
agent's own contributions. Remote agent data and DNSKEY state are not fetched
— they only arrive reactively when peers happen to send updates, or via
manual `peer resync` CLI commands.

### Solution

For each multi-provider zone, the agent sends three sequential RFI requests
at startup:

1. **RFI EDITS → combiner** (synchronous, wait for response)
   - Returns ALL agents' contributions (local + remote), not just the
     requesting agent's own data
   - Wire format changes from `map[owner][]RR` to
     `map[agentID]map[owner][]RR` to preserve attribution
   - Remote agent data from the combiner serves as a baseline — it will
     be overwritten by more authoritative data from the actual agents
     in step 3

2. **RFI KEYSTATE → signer** (synchronous, wait for response)
   - Gets DNSKEY inventory: all keys the signer knows about
   - Agent derives local vs foreign keys, populates RemoteDNSKEYs
   - Uses existing `RequestAndWaitForKeyInventory()`

3. **RFI SYNC → remote agents** (fire-and-forget)
   - Asks each remote agent to re-send their data
   - Response arrives asynchronously via normal SYNC flow
   - Overwrites the combiner-sourced baseline with authoritative data

### Targeted RFI SYNC Response

**Problem with current behavior**: When an agent receives RFI SYNC, it
triggers a full `"resync"` SDE command that pushes data to the combiner
AND all remote agents. One agent restarting causes O(N²) fan-out — each
of N-1 remote agents sends to N-2 other agents + combiner.

**Fix**: New `"resync-targeted"` SDE command that only sends data back to
the specific requesting agent. No combiner push (combiner already has the
data), no fan-out to other agents.

The existing `"resync"` command (used by `peer resync --push` CLI) stays
unchanged for recovery scenarios.

### Files Modified (Part A)

| File | Change |
|------|--------|
| `core/messages.go` | `AgentEditsPost`: `Records` → `AgentRecords` |
| `agent/transport/transport.go` | `EditsRequest`: same |
| `agent/transport/dns.go` | `DnsEditsPayload`: same; `Edits()` method |
| `agent/transport/handlers.go` | `HandleEdits`: parse `AgentRecords` |
| `config.go` | `EditsResponseMsg`: same |
| `hsync_transport.go` | `routeEditsMessage()`; new `EnqueueForSpecificAgent()` |
| `hsync_utils.go` | `applyEditsToSDE()`: per-agent attribution |
| `combiner_msg_handler.go` | `sendEditsToAgent`: all-agent response |
| `syncheddataengine.go` | Startup loops; `"resync-targeted"` handler |
| `hsyncengine.go` | RFI SYNC receive: targeted response |

---

## Part B: Parent Sync Remaining Items

The parent sync implementation (2026-03-18 plan) is complete for Steps 1-8.
Four items remain.

### B1. Persist Outgoing Serial

**Purpose**: Track the SOA serial sent in UPDATE messages to the parent so
that on restart the agent doesn't re-send with a lower serial (which
parents may reject).

The enum constant `CombinerOptPersistOutgoingSerial` is defined but not
yet used. Implementation needs a persistence mechanism (KeyDB table or
similar) to store the last serial per zone.

### B2. EDNS(0) on Outgoing UPDATEs + EDE on Receiver

**Rationale**: If the parent supports UPDATE and we get a positive
confirmation back, there is no need to also send NOTIFYs. But we need the
parent to be able to report errors via Extended DNS Error (EDE, RFC 8914).

**Outgoing UPDATEs**: `CreateChildUpdate()` (delta mode) already includes
`m.SetEdns0(1232, true)`. Add the same to `CreateChildReplaceUpdate()`
for when replace mode is re-enabled.

**Note**: There is an unresolved bug in `CreateChildReplaceUpdate()`
(replace mode). Until fixed, `SyncZoneDelegationViaUpdate()` sets
`ConfigError` on the zone and returns an error if replace mode is
configured, making the problem immediately visible.

**UPDATE Receiver**: The update responder (`updateresponder.go`) already
attaches EDE for some errors (zone not found, frozen). Extend to cover
all failure paths: SIG(0) verification failure, policy rejection, etc.

`SendUpdate()` already extracts EDE from responses — no change needed
on the response parsing side.

### B3. Combiner NS Target Sanity Check

When the combiner accepts an NS record in a provider zone, verify that the
NS target has at least one address record. This prevents accepting NS
records that point to nonexistent names.

The combiner already has `checkNSNamespacePolicy` (protected namespace
check). This adds a resolvability check. The combiner may not have IMR
access, so the check may use the combiner's own zone data or log a warning
without hard-rejecting.

### B4. End-to-End VM Testing

Not code — deferred to testing phase on NetBSD VMs. Covers:
- Combiner → agent STATUS-UPDATE flow
- CDS/CSYNC publication via InternalUpdate
- Full delegation sync cycle with real parent

### Files Modified (Part B)

| File | Change |
|------|--------|
| `childsync_utils.go` | EDNS(0) on `CreateChildReplaceUpdate` |
| `delegation_sync.go` | Error on replace mode (broken); delta only |
| `updateresponder.go` | EDE on all failure paths |
| `combiner_chunk.go` | NS target resolvability check |
| `enums.go` / KeyDB | Outgoing serial persistence |

---

## Implementation Order

1. **B1**: Persist outgoing serial
2. **B2**: EDNS(0) on outgoing UPDATEs + EDE on UPDATE receiver
3. **B3**: Combiner NS target sanity check
4. **A1**: RFI EDITS wire format + combiner all-agent response
5. **A2**: Targeted RFI SYNC response
6. **A3**: SDE startup: RFI KEYSTATE + RFI SYNC loops
7. **A4**: Comment cleanup

Part B items are smaller and more self-contained. Part A is the larger
structural change and is done last.
