# Reliable Message Delivery Architecture

**Date:** 2026-02-11
**Status:** Design Document
**Related Issues:** Agent-to-combiner sync, agent-to-agent sync reliability

## Executive Summary

This document describes the architecture for reliable message delivery in the TDNS multi-agent DNSSEC coordination system. The design ensures that critical synchronization messages are never lost, even when recipients are temporarily unavailable, by implementing retry-until-confirmed semantics with a state-aware message queue.

## Problem Statement

Current synchronization messages in TDNS are sent with fire-and-forget semantics:
- Messages are only sent to OPERATIONAL agents, skipping non-operational ones entirely
- No retry mechanism for transient failures
- Messages are lost if an agent is temporarily unavailable
- No confirmation tracking or correlation
- Synchronous blocking calls that couple sender to recipient availability

This is unacceptable for DNSSEC coordination where every agent in the HSYNC RRset MUST receive updates to maintain zone consistency.

## Design Principles

1. **No Lost Messages**: Every message queued must eventually be delivered or explicitly expire
2. **Separation of Concerns**: Each component has a single, clear responsibility
3. **Zone-Scoped Operations**: Upper layers work with zones, not individual agent identities
4. **State-Aware Delivery**: Queue handles operational state checking, not the caller
5. **Transport Neutrality**: Same data structures regardless of DNS CHUNK or API transport
6. **Retry Until Confirmed**: Messages retry with exponential backoff until acknowledged

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SynchedDataEngine                            │
│  Responsibility: Decide WHAT data goes WHERE (scope)                │
│  - Local update  → combiner + all agents for zone                   │
│  - Remote update → combiner only                                    │
└────────────────────┬────────────────────────────────────────────────┘
                     │ Zone-scoped calls:
                     │ - EnqueueForCombiner(zone, update)
                     │ - EnqueueForZoneAgents(zone, update)
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       TransportManager                              │
│  Responsibility: Resolve zone → recipients, build messages          │
│  - Query AgentRegistry for zone→agent mapping                       │
│  - Look up combiner identity for zone                               │
│  - Build messages (CombinerSyncRequest, AgentMsgNotify)             │
│  - Encrypt per recipient's public key                               │
│  - Delegate to ReliableMessageQueue                                 │
└────────────────────┬────────────────────────────────────────────────┘
                     │ Per-recipient messages:
                     │ Enqueue(recipientID, message, options)
                     ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    ReliableMessageQueue                             │
│  Responsibility: Ensure delivery with retry-until-confirmed         │
│  - Accept messages immediately (don't check state)                  │
│  - Background workers check agent state before sending              │
│  - Retry with exponential backoff on failure                        │
│  - Track confirmations via distribution ID                          │
│  - Expire messages after timeout (default: 24 hours)                │
└─────────────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

### SynchedDataEngine: Data Synchronization Coordinator

**Location:** `tdns/v2/syncheddataengine.go`

**Knows:**
- What data changed (ZoneUpdate)
- Who originated the change (local vs remote via UpdateType field)
- Which zone the data belongs to

**Does NOT know:**
- Specific agent identities or combiner identity
- Transport mechanisms (DNS CHUNK vs API)
- Delivery state or retry logic

**Interface:**
```go
// For local updates (we originated)
tm.EnqueueForCombiner(zone, update)
tm.EnqueueForZoneAgents(zone, update)

// For remote updates (another agent originated)
tm.EnqueueForCombiner(zone, update)
// (does NOT send to other agents - originator handles broadcast)
```

**Distribution Logic:**
```go
switch synchedDataUpdate.UpdateType {
case "local":
    // We originated → broadcast to everyone
    recipients = [combiner] + all_agents_for_zone
case "remote":
    // They originated → only forward to combiner
    recipients = [combiner]
}
```

---

### AgentRegistry: Entity and Zone Mapping Manager

**Location:** `tdns/v2/hsyncengine.go`

**Knows:**
- Zone → agents mapping (parsed from HSYNC RRsets)
- Agent states (OPERATIONAL, INTRODUCED, KNOWN, etc.)
- Agent metadata (identity, shared zones, transport capabilities)

**Does NOT know:**
- Message delivery or retry logic
- Transport selection
- Queue management

**Provides:**
```go
// Returns ALL agents from HSYNC (no state filtering)
GetZoneAgentData(zone) -> ZoneAgentData {
    MyUpstreams []AgentId
    MyDownstreams []AgentId
    MyPeers []AgentId
    Agents []*Agent  // All combined
}
```

**Updates:**
- When zones are reloaded (SIGHUP)
- When HSYNC RRsets change
- When agent discovery completes

---

### TransportManager: Reliable Delivery Orchestrator

**Location:** `tdns/v2/hsync_transport.go`

**Knows:**
- How to map zone → combiner identity (from config)
- How to map zone → list of agent identities (via AgentRegistry)
- Which transport to use per recipient (DNS CHUNK vs API)
- How to build messages for each recipient type

**Does NOT know:**
- Business logic about what data to send where
- HSYNC RRset details (trusts AgentRegistry)

**New Field:**
```go
type TransportManager struct {
    // ... existing fields ...

    // New: Reliable message queue
    reliableQueue *ReliableMessageQueue
}
```

**New Methods:**
```go
// EnqueueForCombiner queues data for the combiner with retry-until-confirmed
func (tm *TransportManager) EnqueueForCombiner(zone ZoneName, update *ZoneUpdate) error

// EnqueueForZoneAgents queues data for all agents in zone's HSYNC
func (tm *TransportManager) EnqueueForZoneAgents(zone ZoneName, update *ZoneUpdate) error

// Helper methods
func (tm *TransportManager) getCombinerForZone(zone ZoneName) AgentId
func (tm *TransportManager) getAllAgentsForZone(zone ZoneName) ([]AgentId, error)
```

**Implementation Flow:**
```go
func (tm *TransportManager) EnqueueForCombiner(zone ZoneName, update *ZoneUpdate) error {
    // 1. Look up combiner identity for this zone
    combinerID := tm.getCombinerForZone(zone)

    // 2. Build CombinerSyncRequest
    distID := generateDistributionID()
    syncReq := ConvertZoneUpdateToSyncRequest(update, tm.LocalID, distID)

    // 3. Build message payload (JSON + encryption)
    payload, err := tm.buildCombinerPayload(syncReq, combinerID)

    // 4. Create OutgoingMessage
    msg := &OutgoingMessage{
        DistributionID: distID,
        RecipientID:    combinerID,
        Zone:           zone,
        MessageType:    "sync",
        Payload:        payload,
        Priority:       PriorityHigh,
        CreatedAt:      time.Now(),
        ExpiresAt:      time.Now().Add(24 * time.Hour),
    }

    // 5. Enqueue (returns immediately)
    return tm.reliableQueue.Enqueue(msg)
}

func (tm *TransportManager) EnqueueForZoneAgents(zone ZoneName, update *ZoneUpdate) error {
    // 1. Get ALL agents for zone (not just operational)
    agents, err := tm.getAllAgentsForZone(zone)
    if err != nil {
        return err
    }

    if len(agents) == 0 {
        log.Printf("TransportManager: No agents in HSYNC for zone %s", zone)
        return nil
    }

    // 2. Build message once (same data for all agents)
    distID := generateDistributionID()

    // 3. For each agent, create encrypted message and enqueue
    var errs []error
    for _, agentID := range agents {
        payload, err := tm.buildAgentPayload(update, agentID, distID)
        if err != nil {
            errs = append(errs, fmt.Errorf("failed to build payload for %s: %w", agentID, err))
            continue
        }

        msg := &OutgoingMessage{
            DistributionID: distID + "-" + string(agentID),  // Unique per agent
            RecipientID:    agentID,
            Zone:           zone,
            MessageType:    "notify",
            Payload:        payload,
            Priority:       PriorityNormal,
            CreatedAt:      time.Now(),
            ExpiresAt:      time.Now().Add(24 * time.Hour),
        }

        if err := tm.reliableQueue.Enqueue(msg); err != nil {
            errs = append(errs, fmt.Errorf("failed to enqueue for %s: %w", agentID, err))
        }
    }

    if len(errs) > 0 {
        return fmt.Errorf("some enqueues failed: %v", errs)
    }
    return nil
}

func (tm *TransportManager) getAllAgentsForZone(zone ZoneName) ([]AgentId, error) {
    // Query the zone's HSYNC RRset
    zad, err := tm.agentRegistry.GetZoneAgentData(zone)
    if err != nil {
        return nil, fmt.Errorf("zone %s has no HSYNC RRset: %w", zone, err)
    }

    // Collect all agent identities from HSYNC
    var agents []AgentId
    agents = append(agents, zad.MyUpstreams...)
    agents = append(agents, zad.MyDownstreams...)
    agents = append(agents, zad.MyPeers...)

    // Remove ourselves from the list
    localID := AgentId(tm.agentRegistry.LocalAgent.Identity)
    var filtered []AgentId
    for _, aid := range agents {
        if aid != localID {
            filtered = append(filtered, aid)
        }
    }

    // Deduplicate (in case an agent appears in multiple lists)
    seen := make(map[AgentId]bool)
    var unique []AgentId
    for _, aid := range filtered {
        if !seen[aid] {
            seen[aid] = true
            unique = append(unique, aid)
        }
    }

    return unique, nil
}
```

---

### ReliableMessageQueue: State-Aware Durable Message Queue

**Location:** `tdns/v2/reliable_message_queue.go` (new file)

**Knows:**
- Pending messages per recipient
- Retry state (attempt count, last attempt time, backoff)
- Confirmation tracking (distribution ID correlation)
- Agent operational state (via AgentRegistry reference)

**Does NOT know:**
- Business logic about zones or data
- How to build messages (receives pre-built messages)

**Data Structures:**
```go
// OutgoingMessage represents a message to be delivered
type OutgoingMessage struct {
    DistributionID string        // Unique ID for this message instance
    RecipientID    AgentId        // Who should receive this
    Zone           ZoneName       // Zone context
    MessageType    string         // "sync", "notify", "rfi", etc.
    Payload        []byte         // Pre-encrypted JSON payload
    Priority       MessagePriority // High (combiner), Normal (agents)
    CreatedAt      time.Time      // When enqueued
    ExpiresAt      time.Time      // When to give up (default: 24h)
}

// PendingMessage tracks delivery state
type PendingMessage struct {
    Message      *OutgoingMessage
    State        MessageState    // Queued, Sending, AwaitingConfirm, Confirmed, Failed
    AttemptCount int
    LastAttempt  time.Time
    NextAttempt  time.Time       // Exponential backoff
    LastError    string
}

type MessageState int
const (
    MessageQueued MessageState = iota
    MessageSending
    MessageAwaitingConfirm
    MessageConfirmed
    MessageFailed
)

type MessagePriority int
const (
    PriorityHigh   MessagePriority = iota  // Combiner updates
    PriorityNormal                          // Agent updates
)

type ReliableMessageQueue struct {
    pending       map[string]*PendingMessage  // distributionID -> message
    mu            sync.RWMutex
    agentRegistry *AgentRegistry              // For state checking
    transport     *TransportManager            // For sending

    // Channels for queue operations
    enqueueC      chan *OutgoingMessage
    confirmC      chan string  // distributionID
    stopC         chan struct{}

    // Configuration
    maxRetries    int           // Default: unlimited until expiration
    baseBackoff   time.Duration // Default: 1 second
    maxBackoff    time.Duration // Default: 60 seconds
}
```

**Core Methods:**
```go
// NewReliableMessageQueue creates a new queue instance
func NewReliableMessageQueue(ar *AgentRegistry, tm *TransportManager) *ReliableMessageQueue

// Start begins processing the queue (call in goroutine)
func (q *ReliableMessageQueue) Start(ctx context.Context)

// Enqueue adds a message to the queue (returns immediately)
func (q *ReliableMessageQueue) Enqueue(msg *OutgoingMessage) error

// MarkConfirmed marks a message as successfully delivered
func (q *ReliableMessageQueue) MarkConfirmed(distributionID string) error

// GetQueueStatus returns current queue statistics
func (q *ReliableMessageQueue) GetQueueStatus() QueueStats
```

**Delivery Worker Logic:**
```go
func (q *ReliableMessageQueue) deliveryWorker(ctx context.Context) {
    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            q.processQueue()
        }
    }
}

func (q *ReliableMessageQueue) processQueue() {
    q.mu.Lock()
    defer q.mu.Unlock()

    now := time.Now()

    for distID, pending := range q.pending {
        // Skip if not ready for next attempt
        if now.Before(pending.NextAttempt) {
            continue
        }

        // Check expiration
        if now.After(pending.Message.ExpiresAt) {
            log.Printf("Queue: Message %s expired after %d attempts",
                distID, pending.AttemptCount)
            pending.State = MessageFailed
            continue
        }

        // Check if recipient is operational
        agent, exists := q.agentRegistry.S.Get(pending.Message.RecipientID)
        if !exists {
            log.Printf("Queue: Recipient %s not in registry, will retry",
                pending.Message.RecipientID)
            q.scheduleRetry(pending)
            continue
        }

        if agent.State != AgentStateOperational {
            log.Printf("Queue: Recipient %s not operational (state: %s), will retry",
                pending.Message.RecipientID, agent.State)
            q.scheduleRetry(pending)
            continue
        }

        // Recipient is operational, attempt delivery
        pending.State = MessageSending
        pending.AttemptCount++
        pending.LastAttempt = now

        go q.sendMessage(pending)
    }
}

func (q *ReliableMessageQueue) sendMessage(pending *PendingMessage) {
    msg := pending.Message

    // Select transport based on recipient's capabilities
    agent, _ := q.agentRegistry.S.Get(msg.RecipientID)

    var err error
    if agent.DnsMethod {
        // Send via DNS CHUNK transport
        err = q.transport.DNSTransport.SendRaw(msg.RecipientID, msg.Payload)
    } else if agent.ApiMethod {
        // Send via API transport
        err = q.transport.APITransport.SendRaw(msg.RecipientID, msg.Payload)
    } else {
        err = fmt.Errorf("no available transport for %s", msg.RecipientID)
    }

    q.mu.Lock()
    defer q.mu.Unlock()

    if err != nil {
        log.Printf("Queue: Failed to send message %s to %s: %v",
            msg.DistributionID, msg.RecipientID, err)
        pending.LastError = err.Error()
        q.scheduleRetry(pending)
    } else {
        // Successfully sent, now waiting for confirmation
        pending.State = MessageAwaitingConfirm
        // Confirmation timeout: if no confirm in 30s, retry
        pending.NextAttempt = time.Now().Add(30 * time.Second)
    }
}

func (q *ReliableMessageQueue) scheduleRetry(pending *PendingMessage) {
    // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s, 60s, 60s...
    backoff := q.baseBackoff * time.Duration(1<<uint(pending.AttemptCount))
    if backoff > q.maxBackoff {
        backoff = q.maxBackoff
    }

    pending.NextAttempt = time.Now().Add(backoff)
    pending.State = MessageQueued
}
```

---

## Message Flow Examples

### Example 1: Local Update (User adds NS record via CLI)

```
1. User runs: tdns-cli agent debug add-ns --zone whisky.dnslab. \
                --rr "whisky.dnslab. IN NS ns.alpha.dnslab."

2. CommandHandler → SynchedDataEngine
   - SynchedDataUpdate{
       Zone: "whisky.dnslab.",
       AgentId: "agent.alpha.dnslab.",  // us
       UpdateType: "local",             // we originated
       Update: ZoneUpdate{NS record}
     }

3. SynchedDataEngine.ProcessUpdate()
   - Apply to local ZoneDataRepo ✓
   - tm.EnqueueForCombiner("whisky.dnslab.", update)
   - tm.EnqueueForZoneAgents("whisky.dnslab.", update)
   - Return success immediately

4. TransportManager.EnqueueForCombiner()
   - Look up: combiner.alpha.dnslab.
   - Build CombinerSyncRequest
   - Encrypt for combiner's key
   - Queue message (priority: HIGH)

5. TransportManager.EnqueueForZoneAgents()
   - Query AgentRegistry: agents for "whisky.dnslab."
   - Result: [agent.beta.dnslab., agent.gamma.dnslab.]
   - For each agent:
     * Build AgentMsgNotify
     * Encrypt for agent's key
     * Queue message (priority: NORMAL)

6. ReliableMessageQueue (background workers)
   - 3 pending messages:
     * combiner.alpha.dnslab. (HIGH priority)
     * agent.beta.dnslab. (NORMAL, state=OPERATIONAL) → send immediately
     * agent.gamma.dnslab. (NORMAL, state=INTRODUCED) → queue, retry when operational

7. Delivery:
   - Combiner: Send via DNS CHUNK → wait for confirmation
   - Agent Beta: Send via DNS CHUNK → wait for confirmation
   - Agent Gamma: Retry every 1s, 2s, 4s... until operational

8. Confirmations arrive:
   - Combiner confirms → mark confirmed, remove from queue
   - Agent Beta confirms → mark confirmed, remove from queue
   - Agent Gamma: eventually becomes operational → send → confirm → remove
```

### Example 2: Remote Update (Another agent sends us SYNC)

```
1. DNS CHUNK NOTIFY arrives from agent.beta.dnslab.

2. Transport middleware → TransportManager.routeSyncMessage()

3. HsyncEngine.MsgHandler()
   - Build SynchedDataUpdate{
       Zone: "whisky.dnslab.",
       AgentId: "agent.beta.dnslab.",  // they originated
       UpdateType: "remote",
       Update: ZoneUpdate{NS record}
     }

4. SynchedDataEngine.ProcessUpdate()
   - Apply to local ZoneDataRepo ✓
   - tm.EnqueueForCombiner("whisky.dnslab.", update)
   - (does NOT send to other agents - originator broadcasts)
   - Return success

5. TransportManager.EnqueueForCombiner()
   - Look up combiner
   - Build message, encrypt, queue

6. ReliableMessageQueue
   - 1 pending message: combiner.alpha.dnslab.
   - Send via DNS CHUNK
   - Track confirmation
   - Retry if needed
```

---

## Current Code Problems

### Problem 1: SynchedDataEngine Has Too Many Responsibilities

**File:** `tdns/v2/syncheddataengine.go`
**Lines:** 210-292 (local update), 338-384 (remote update)

**Current code:**
- ❌ Looks up combiner identity directly
- ❌ Checks operational state before sending (should queue if not operational)
- ❌ Uses synchronous `SendApiMsg()` call (fire-and-forget)
- ❌ No retry on failure
- ❌ Iterates through agents synchronously
- ❌ Skips non-operational agents entirely

**XXX Comment (lines 262-265):**
```go
// If any remote agent is not operational, we can't send the message
if len(notOperationalAgents) > 0 {
    // XXX: Mark this zone as "dirty", i.e. not yet sent to the remote agents
    log.Printf("SynchedDataEngine: Agents %v are not operational, skipping agent NOTIFY", notOperationalAgents)
```

This comment explicitly acknowledges the problem we're solving!

### Problem 2: RemoteOperationalAgents() Filters Too Early

**File:** `tdns/v2/hsyncengine.go`
**Lines:** 709-739

**XXX Comment (lines 719-729):**
```go
// XXX: This is not quite clear: if one remote agent is unavailable for some reason,
// should we skip the command or not? Or should we send the command to the other agents?
// ...
// The question is what to do if one or more agents are not operational. One alternative is
// to queue the update and resend when all remote agents are back. Another alternative is
// put a "dirty" flag on the local data for the tuple <zone, agent> and send the update
// when the agent comes back online.
//
// The second alternative seems more attractive.
```

**Issue:** Filters by OPERATIONAL state at query time, should return ALL agents.

### Problem 3: No Queue Infrastructure

**Completely missing:**
- ❌ No ReliableMessageQueue implementation
- ❌ No OutgoingMessage/PendingMessage data structures
- ❌ No retry workers
- ❌ No confirmation tracking
- ❌ No exponential backoff

---

## Implementation Plan

### Phase 1: Foundation - ReliableMessageQueue

**New file:** `tdns/v2/reliable_message_queue.go`

**Tasks:**
1. Define data structures (OutgoingMessage, PendingMessage, ReliableMessageQueue)
2. Implement core queue logic:
   - `Enqueue()` - accept messages immediately
   - `deliveryWorker()` - background goroutine
   - `processQueue()` - check state, send, retry
   - `MarkConfirmed()` - handle confirmations
3. Implement exponential backoff with configurable limits
4. Add queue statistics/monitoring
5. Unit tests for queue behavior

**Files to create:**
- `tdns/v2/reliable_message_queue.go`
- `tdns/v2/reliable_message_queue_test.go`

### Phase 2: TransportManager Integration

**Modify:** `tdns/v2/hsync_transport.go`

**Tasks:**
1. Add `reliableQueue *ReliableMessageQueue` field to TransportManager
2. Implement `EnqueueForCombiner(zone, update)`
3. Implement `EnqueueForZoneAgents(zone, update)`
4. Implement `getCombinerForZone(zone)` helper
5. Implement `getAllAgentsForZone(zone)` helper
6. Add message building helpers (`buildCombinerPayload`, `buildAgentPayload`)
7. Initialize queue in `NewTransportManager()`

**Lines to add:** ~200-300

### Phase 3: SynchedDataEngine Simplification

**Modify:** `tdns/v2/syncheddataengine.go`

**Tasks:**
1. Replace lines 210-292 (local update combiner + agent sync)
2. Replace lines 338-384 (remote update combiner sync)
3. Remove agent iteration loops
4. Remove state checking (trust queue)
5. Simplify error handling

**Lines to remove:** ~150
**Lines to add:** ~30

**Before:**
```go
// 80 lines of combiner lookup, state checking, sending, error handling
// 40 lines of agent iteration, state checking, sending, error handling
```

**After:**
```go
if change {
    tm.EnqueueForCombiner(zone, update)
    tm.EnqueueForZoneAgents(zone, update)
}
```

### Phase 4: AgentRegistry Cleanup

**Modify:** `tdns/v2/hsyncengine.go`

**Tasks:**
1. Replace `RemoteOperationalAgents()` with `GetAllAgentsForZone()`
2. Remove operational state filtering
3. Update method documentation

**Lines to change:** ~30

### Phase 5: Confirmation Wiring

**Modify:**
- `tdns/v2/hsync_transport.go` (agent confirmations)
- `tdns/v2/combiner_chunk.go` (combiner confirmations)

**Tasks:**
1. In `routeSyncMessage()`, after sending confirmation, call `reliableQueue.MarkConfirmed(distributionID)`
2. In combiner CHUNK handler, after processing, call confirmation tracking
3. Add distribution ID to response messages

**Lines to add:** ~20-30

### Phase 6: Testing & Validation

**Integration tests:**
1. Local update → combiner + operational agents (immediate delivery)
2. Local update → combiner + non-operational agent (queued, retry when operational)
3. Remote update → combiner only
4. Retry with exponential backoff
5. Confirmation correlation
6. Message expiration after timeout
7. Queue statistics/monitoring

**Test files to create:**
- `tdns/v2/integration_reliable_delivery_test.go`

---

## Configuration

Add to agent configuration:

```yaml
agent:
  message_queue:
    # Maximum time to keep retrying a message (default: 24h)
    expiration_timeout: 24h

    # Base retry backoff (default: 1s)
    base_backoff: 1s

    # Maximum retry backoff (default: 60s)
    max_backoff: 60s

    # Maximum queue size (default: 10000)
    max_queue_size: 10000

    # Confirmation timeout (default: 30s)
    confirmation_timeout: 30s
```

---

## Monitoring & Observability

Add queue statistics endpoint: `GET /agent/queue/status`

```json
{
  "queue_size": 42,
  "pending_by_state": {
    "queued": 10,
    "sending": 2,
    "awaiting_confirm": 30
  },
  "pending_by_priority": {
    "high": 5,
    "normal": 37
  },
  "oldest_message_age_seconds": 120,
  "messages_delivered_total": 1523,
  "messages_failed_total": 3,
  "messages_expired_total": 0
}
```

Add logging:
- Enqueue: "Queue: Enqueued message %s for %s (priority: %s)"
- Retry: "Queue: Retrying message %s to %s (attempt %d, next in %s)"
- Confirm: "Queue: Message %s confirmed by %s"
- Expire: "Queue: Message %s expired after %d attempts"
- Recipient not ready: "Queue: Recipient %s not operational (state: %s), will retry"

---

## Migration Strategy

1. **Phase 1**: Implement ReliableMessageQueue in isolation with unit tests
2. **Phase 2**: Add to TransportManager but don't use yet (feature flag: `agent.use_reliable_queue: false`)
3. **Phase 3**: Enable for combiner only (`use_reliable_queue: combiner_only`)
4. **Phase 4**: Enable for agents (`use_reliable_queue: true`)
5. **Phase 5**: Remove old synchronous code paths
6. **Phase 6**: Mark feature as stable, remove feature flag

---

## Success Criteria

1. ✅ No messages lost when recipients are temporarily unavailable
2. ✅ Messages retry until confirmed or expired
3. ✅ SynchedDataEngine simplified (zone-scoped interface)
4. ✅ AgentRegistry no longer filters by operational state
5. ✅ All integration tests passing
6. ✅ Queue monitoring shows delivery success rate >99.9%
7. ✅ No blocking calls in SynchedDataEngine
8. ✅ Exponential backoff prevents overwhelming non-operational agents

---

## Future Enhancements

1. **Persistent Queue**: Survive process restarts (write to disk/database)
2. **Priority Queue**: Send HIGH priority messages first
3. **Batching**: Combine multiple updates to same recipient
4. **Dead Letter Queue**: Separate failed messages for investigation
5. **Metrics**: Prometheus metrics for queue depth, delivery latency, retry counts
6. **Circuit Breaker**: Temporarily stop retrying to consistently failing recipients

---

## References

- **HSYNC Protocol**: Multi-agent DNSSEC coordination via DNS HSYNC RRsets
- **Transport Layer**: `tdns/v2/agent/transport/` - DNS CHUNK and API abstractions
- **Agent State Machine**: NEEDED → KNOWN → INTRODUCED → OPERATIONAL → LEGACY
- **Distribution ID**: Unique identifier for tracking message instances and confirmations

---

## Appendix: Key Code Locations

| Component | File | Lines | Purpose |
|-----------|------|-------|---------|
| SynchedDataEngine | [syncheddataengine.go](../v2/syncheddataengine.go) | 159-400 | Processes updates, needs simplification |
| AgentRegistry | [hsyncengine.go](../v2/hsyncengine.go) | 709-739 | RemoteOperationalAgents() needs replacement |
| TransportManager | [hsync_transport.go](../v2/hsync_transport.go) | 30-100 | Needs queue integration |
| CombinerSyncRequest | [combiner_chunk.go](../v2/combiner_chunk.go) | 39-49 | Already transport-neutral |
| ConvertZoneUpdateToSyncRequest | [combiner_chunk.go](../v2/combiner_chunk.go) | 662-692 | Groups records by owner |

---

**Document Status:** Design Complete - Ready for Implementation
**Next Step:** Phase 1 - Implement ReliableMessageQueue
