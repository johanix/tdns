# Parent Sync: Who Sends the UPDATE?

**Date:** 2026-03-17
**Status:** Decision: Option B (combiner detects, agent sends)
**Context:** Parent Sync End-to-End project

## Background

The TDNS multi-provider system has extensive infrastructure
for UPDATE-based parent delegation sync:

- **DelegationSyncher** goroutine that consumes requests and
  dispatches to SyncZoneDelegationViaUpdate or
  SyncZoneDelegationViaNotify
- **SyncZoneDelegationViaUpdate** creates signed DNS UPDATE
  messages and sends them to the parent's DSYNC target
- **CreateChildReplaceUpdate** atomically replaces all
  delegation data (NS) in one UPDATE
- **AnalyseZoneDelegation** queries the parent for its
  current delegation view and computes the delta
- **Leader election** determines which agent may send
- **SIG(0) key lifecycle** — generation, bootstrap with
  parent, KeyState polling, trust establishment
- **DSYNC discovery** — child discovers parent's UPDATE
  target and supported schemes

All of this infrastructure lives in the `tdns/v2` library
and is available to any role (agent, combiner, signer, auth).

## The Problem

In multi-provider mode, the combiner is the source of truth
for NS and DNSKEY records. When an agent sends changes to
the combiner and the combiner applies them, nobody triggers
a sync with the parent. The existing trigger points are:

1. **Zone file reload** (`FetchFromFile`) — detects changes
   via `DelegationDataChangedNG()`
2. **Zone transfer** (`FetchFromUpstream`) — same pattern
3. **DNS UPDATE** (`zone_updater.go`) — detects via
   `ZoneUpdateChangesDelegationDataNG()`

None of these fire when the combiner processes an UPDATE
from an agent. The combiner applies changes but never
signals that parent-relevant data has changed.

## What the Combiner Must Watch For

There are **two** types of changes that require parent
synchronization:

### 1. NS RRset changes

When the NS records for the child zone change (nameservers
added or removed), the parent's delegation must be updated.

### 2. KSK changes (DNSKEY flags=257)

When the set of Key Signing Keys changes (new KSK published
or old KSK removed), the parent's DS RRset must be updated
(DS records are derived from DNSKEY/CDS).

## Parent Sync Mechanisms

The parent may support one or both of:

- **UPDATE** — child sends a signed DNS UPDATE directly to
  the parent's UPDATE Receiver (DSYNC target)
- **NOTIFY** — child publishes indicator records (CSYNC for
  NS, CDS for keys) in its own zone, then sends a NOTIFY
  to the parent's NOTIFY Receiver, prompting the parent to
  fetch and process the records

When the parent supports both, **both are used** (belt and
suspenders).

## The Action Matrix

| Change | UPDATE path | NOTIFY path |
|--------|------------|-------------|
| **NS** | Agent sends DNS UPDATE with NS data | Combiner publishes CSYNC, agent sends NOTIFY(CSYNC) |
| **KSK** | Agent sends DNS UPDATE with DS data | Combiner publishes CDS, agent sends NOTIFY(CDS) |

For the NOTIFY path, the combiner must publish the
indicator records (CDS or CSYNC) in the customer zone
**before** notifying the agent. The agent then sends the
NOTIFY to the parent.

For the UPDATE path, the combiner notifies the agent with
the relevant data, and the agent constructs and sends the
signed UPDATE.

## Architectural Constraints

### Combiner scope

The combiner only talks to its own provider's agent(s).
It has no knowledge of or communication with remote
agents/providers. Only the local agent communicates with
remote agents.

### Glue records

Currently only out-of-bailiwick NS names are supported.
The combiner is restricted to apex-only records (NS,
DNSKEY, CDS, CSYNC, KEY). No A/AAAA glue is needed.
(Glue support will be needed in the future but is out
of scope for now.)

### Replace mode

`CreateChildReplaceUpdate` is preferred over delta mode.
It atomically replaces all records of the relevant type
in one UPDATE, regardless of what the parent currently
has. This avoids dependency on child and parent being
in sync.

## The Three Options Considered

### Option A: Combiner Sends Directly

The combiner detects changes, signs the UPDATE with a
SIG(0) key (shared by the agent), and sends to parent.

**Pros:**
- Combiner is source of truth — knows exactly when data
  changes and can distinguish real changes from no-ops
- Direct path — detector also sends, no intermediary
- All library code is available to any role

**Cons:**
- Adds significant complexity to the combiner: DSYNC
  discovery, SIG(0) signing, UPDATE construction, retry
  logic, error handling, result tracking, leadership
  gating
- Combiner must track leadership state
- Result propagation back to agents is unnatural
- Requires SIG(0) private key sharing
- **Violates "minimize combiner complexity" principle**

### Option B: Combiner Detects, Agent Sends (CHOSEN)

The combiner detects changes, performs any necessary
zone publication (CDS, CSYNC), and sends a lightweight
notification to its local agent. The agent handles the
full parent sync flow.

**Pros:**
- Minimal combiner addition: detect change, optionally
  publish CDS/CSYNC, send notification. No signing, no
  DSYNC, no retries, no state tracking.
- Agent already has the full stack: SIG(0) signing,
  DSYNC discovery, UPDATE construction, leader election,
  retry logic
- Result handling natural for agent
- **Keeps combiner simple**

**Cons:**
- Requires a new combiner→agent message type
- Notification must carry data (current NS or DS set)
- Agent must handle multiple actions per notification
  (UPDATE and/or NOTIFY depending on parent capabilities)

### Option C: Agent Detects and Sends

The agent detects changes in its own zone data and sends.

**Pros:**
- Simplest code change, no combiner changes

**Cons:**
- Agent doesn't have the combiner's integrated view
- Agent is stateless — can't distinguish real changes
  from no-ops
- Wrong trigger point — SDE data comes from peer agents,
  not the combiner (source of truth)
- May trigger prematurely or not at all

## Design Principle: Minimize Combiner Complexity

The combiner is the most sensitive component in the
system. It is the only component allowed to edit customer
zones. If the combiner has a bug, customer zone data is
at risk.

The agent, by contrast, is already complex but less
sensitive. If the agent breaks, no customer data is
modified — it only synchronizes data between parties
(signer, combiner, remote agents).

**Given a choice, minimize complexity in the combiner**
so that it can be more easily reviewed, certified, and
hardened for production use.

This principle drives the choice of Option B.

## Decision: Option B

### Combiner responsibilities (minimal)

1. Detect NS RRset changes after `CombinerProcessUpdate`
2. Detect KSK changes (DNSKEY flags=257) after
   `CombinerProcessUpdate`
3. For NOTIFY path: publish CDS or CSYNC in the customer
   zone before notifying the agent
4. Send a new message type (`AgentMsgDelegationChanged`
   or similar) to the local agent carrying:
   - Zone name
   - Change type (NS, KSK, or both)
   - Current NS records (for NS changes)
   - Current CDS/DS records (for KSK changes)

### Agent responsibilities (complex, but already equipped)

1. Receive the notification
2. Check leader election — only the leader acts
3. Determine parent's supported schemes via DSYNC
   discovery (existing code)
4. For each applicable scheme:
   - **UPDATE + NS change**: construct and send signed
     DNS UPDATE with NS data to parent UPDATE Receiver
   - **UPDATE + KSK change**: construct and send signed
     DNS UPDATE with DS data to parent UPDATE Receiver
   - **NOTIFY + NS change**: send NOTIFY(CSYNC) to
     parent NOTIFY Receiver (CSYNC already published
     by combiner)
   - **NOTIFY + KSK change**: send NOTIFY(CDS) to
     parent NOTIFY Receiver (CDS already published
     by combiner)
5. Handle results, retries, and state updates

### Communication model

The combiner only communicates with its own provider's
agent(s). It does not know about or contact remote
agents/providers. The agent handles all cross-provider
communication.

## Data Flow Clarifications

### Combiner does NOT push data to agents (normally)

The combiner is reactive. Agents send data TO the
combiner. The only existing combiner→agent messages are:
- CONFIRM (after processing an UPDATE)
- Responses to RFI requests (EDITS, CONFIG, AUDIT)

The new delegation-changed notification will be a third
type of combiner→agent message.

### Combiner only handles apex RRtypes

The combiner processes: DNSKEY, CDS, CSYNC, NS, KEY.
It does NOT handle A or AAAA records.

## Existing Infrastructure to Reuse

### NS change detection

`combinerResyncSignalKeys()` in `combiner_chunk.go`
already diffs old vs new NS targets after every update
(for _signal KEY publication). The same detection logic
can trigger delegation notifications.

### CDS publication

`PublishCdsRRs()` in `delegation_sync.go` already
publishes CDS records. The combiner can call this
(or equivalent) before notifying the agent.

### CSYNC publication

CSYNC record creation exists in the delegation sync
infrastructure.

### Agent-side sync

`SyncZoneDelegationViaUpdate` and
`SyncZoneDelegationViaNotify` both exist and work.
`BestSyncScheme` determines which to use based on
DSYNC discovery. The action matrix requires both when
both are supported.

### Transport

`DNSTransport.Confirm()` is a fire-and-forget NOTIFY
pattern. A new message type following the same pattern
provides the notification mechanism.

## Open Questions

1. **Message type design**: Should the notification use
   a single message type with a "change type" field, or
   separate message types for NS vs KSK changes?

2. **Result reporting**: Where should parent sync results
   be persisted? Agent keystore (already has parent_state)?
   Should the agent report results back to the combiner?

3. **Post-bootstrap trigger**: After initial KEY bootstrap
   succeeds and parent trusts the agent, should the agent
   trigger an initial full delegation sync? (Likely yes.)

4. **Timing**: Should the combiner debounce rapid changes
   (e.g., multiple NS operations in quick succession)
   before sending the notification? Or let the agent
   handle idempotency?

5. **CSYNC content**: What flags and type bitmap should
   the CSYNC record contain? (Likely: SOA minimum TTL,
   immediate flag, NS type in bitmap.)
