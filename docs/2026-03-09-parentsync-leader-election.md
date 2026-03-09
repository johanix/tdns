# Parent Sync Leader Election Protocol

**Date**: 2026-03-09
**Status**: Planning
**Prerequisite**: Phases 1-2 of agent-driven parent delegation sync (HSYNC3, HSYNCPARAM, CDS/CSYNC publication, DSYNC discovery)

## Problem

When multiple agents manage the same zone, all detect NS/DNSKEY changes simultaneously and all attempt to DDNS the parent. Only one agent should send the UPDATE to avoid duplicate or conflicting writes.

## Solution: Per-Zone Leader Election

A lightweight leader election protocol among agents for each zone where `parentsync != none`. The elected leader is the only agent that sends DNS UPDATE to the parent. All other agents defer.

## Design: Reuse RFI Message Type (Zero Transport Changes)

Instead of registering a new message type in the transport layer — which would require changes to `router_init.go`, `handlers.go`, `hsync_transport.go`, `config.go` — we reuse `MessageType: "rfi"` with new `RfiType` values:

- `"ELECT-CALL"` — initiates election
- `"ELECT-VOTE"` — carries random uint32 vote
- `"ELECT-CONFIRM"` — carries winner determination

These flow through the existing pipeline: `routeSyncMessage → MsgQs.Msg → MsgHandler → AgentMsgRfi switch`. Only 3 new cases in the existing RfiType switch.

### Data Carried in `Records` Map

The existing `AgentMsgPost.Records` field (type `map[string][]string`) carries election data:

| RfiType | Records | Notes |
|---------|---------|-------|
| `ELECT-CALL` | `_term: ["42"]` | Term number prevents stale elections |
| `ELECT-VOTE` | `_vote: ["2847391"], _term: ["42"]` | Sender identified by OriginatorID |
| `ELECT-CONFIRM` | `_winner: ["netnod."], _term: ["42"]` | Sender identified by OriginatorID |

## Election Protocol

### Triggers

Election is cheap — don't optimize for avoiding it:
- Agent startup with no known leader
- HSYNC3 RRset changes (provider added or removed)
- Cached leader TTL expires (default: 5 minutes)
- Any situation where leader is unknown = call election

### Flow (per zone, among agents with `OptDelSyncChild`)

1. **Call**: Any agent broadcasts `ELECT-CALL` with incremented term number to all peers.
2. **Vote**: Every agent (including the caller) generates a random uint32 and broadcasts `ELECT-VOTE` with `{vote, term}` to all peers.
3. **Collect**: After 3-second timeout (or all votes received), each agent determines winner: highest vote number wins. Ties broken by lexicographic comparison of agent label.
4. **Confirm**: Each agent broadcasts `ELECT-CONFIRM` with `{winner, term}` to all peers.
5. **Consensus**: After 3-second timeout (or all confirms received):
   - All confirmations agree → leader established, cached with TTL
   - Confirmations disagree → re-elect (a vote was lost in transit)
   - Peer unresponsive → proceed without it

### Message Cost

| Agents | Call | Votes | Confirms | Total Messages |
|--------|------|-------|----------|----------------|
| 2 | 1 | 2 | 2 | 5 |
| 3 | 1 | 6 | 6 | 13 |

### Single Agent Optimization

If `expectedPeers == 0`, the agent immediately becomes leader. No messages sent.

### Leader TTL and Re-election

Leader is cached with a configurable TTL (default 5 minutes). A `time.AfterFunc` at 90% of TTL proactively triggers re-election before expiry.

## Types

```go
type LeaderElection struct {
    mu               sync.Mutex
    Zone             ZoneName
    Leader           AgentId
    LeaderExpiry     time.Time
    ElectionActive   bool
    Term             uint64
    MyVote           uint32
    Votes            map[AgentId]uint32
    Confirms         map[AgentId]AgentId
    ExpectedPeers    int
    VoteTimer        *time.Timer
    ConfirmTimer     *time.Timer
}

type LeaderElectionManager struct {
    mu            sync.RWMutex
    elections     map[ZoneName]*LeaderElection
    localID       AgentId
    leaderTTL     time.Duration  // default 5 minutes
    broadcastFunc func(zone ZoneName, rfiType string, records map[string][]string) error
}
```

## Key Methods

- `NewLeaderElectionManager(localID, leaderTTL, broadcastFunc)` — constructor
- `GetLeader(zone) (AgentId, bool)` — returns cached leader if not expired
- `IsLeader(zone) bool` — convenience: are we the leader?
- `StartElection(zone, expectedPeers)` — broadcast ELECT-CALL, cast own vote
- `HandleMessage(zone, senderID, rfiType, records)` — dispatch to handleCall/handleVote/handleConfirm

## Implementation Steps

### Step 1: New file `parentsync_leader.go` (~280 lines)

All election logic in a self-contained module. Types, constructor, election state machine, message handling, vote collection, winner determination, leader caching.

The `broadcastFunc` callback is injected at construction time, decoupling election logic from transport details.

### Step 2: Wire into MsgHandler (`hsyncengine.go` ~line 419)

Add 3 cases to the existing `AgentMsgRfi` switch:

```go
case "ELECT-CALL", "ELECT-VOTE", "ELECT-CONFIRM":
    if lem := conf.Internal.LeaderElectionManager; lem != nil {
        lem.HandleMessage(ampp.Zone, ampp.OriginatorID, ampp.RfiType, ampp.Records)
    }
```

### Step 3: Add field to `InternalConf` (`config.go`)

```go
LeaderElectionManager *LeaderElectionManager
```

### Step 4: Initialize in `main_initfuncs.go`

In `StartAgent`, after TransportManager creation:

```go
conf.Internal.LeaderElectionManager = NewLeaderElectionManager(
    AgentId(conf.Agent.Identity), 5*time.Minute,
    func(zone ZoneName, rfiType string, records map[string][]string) error {
        return conf.Internal.AgentRegistry.broadcastElectToZone(zone, rfiType, records)
    },
)
```

### Step 5: Trigger elections

**On HSYNC3 changes** — end of `UpdateAgents` in `agent_utils.go`:
```go
if zd.Options[OptDelSyncChild] {
    lem.StartElection(zonename, len(zad.Agents))
}
```

**On zone startup** — in `parseconfig.go` OnFirstLoad callback after `SetupZoneSync`:
```go
if zd.Options[OptDelSyncChild] && conf.Internal.LeaderElectionManager != nil {
    zad, _ := conf.Internal.AgentRegistry.GetZoneAgentData(ZoneName(zd.ZoneName))
    conf.Internal.LeaderElectionManager.StartElection(ZoneName(zd.ZoneName), len(zad.Agents))
}
```

### Step 6: Gate DDNS on leader (`delegation_sync.go`)

In `"SYNC-DELEGATION"` case, before `SyncZoneDelegation`:
```go
if lem := conf.Internal.LeaderElectionManager; lem != nil {
    if !lem.IsLeader(ZoneName(ds.ZoneName)) {
        lgDns.Info("not the delegation sync leader, skipping DDNS", "zone", ds.ZoneName)
        continue
    }
}
```

For `"EXPLICIT-SYNC-DELEGATION"` (CLI-triggered): proceed regardless — user explicitly asked.

### Broadcast Helper

`broadcastElectToZone` on `AgentRegistry`:
```go
func (ar *AgentRegistry) broadcastElectToZone(zone ZoneName, rfiType string, records map[string][]string) error {
    zad, err := ar.GetZoneAgentData(zone)
    for _, agent := range zad.Agents {
        if !agent.IsAnyTransportOperational() { continue }
        go ar.sendRfiToAgent(agent, &AgentMsgPost{...})  // parallel sends
    }
}
```

## Files Modified

| File | Action | Est. Lines |
|------|--------|-----------|
| `parentsync_leader.go` | **NEW** — election state machine | ~280 |
| `hsyncengine.go` | Add ELECT cases to RFI dispatch | ~6 |
| `config.go` | Add LeaderElectionManager to InternalConf | ~1 |
| `main_initfuncs.go` | Initialize LeaderElectionManager | ~15 |
| `delegation_sync.go` | Gate SYNC-DELEGATION on IsLeader | ~8 |
| `agent_utils.go` | Trigger election after UpdateAgents | ~10 |
| `parseconfig.go` | Trigger election in OnFirstLoad | ~8 |

## Verification

1. Build: `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
2. Single agent with `HSYNCPARAM parentsync=update` → `GetLeader` returns self (no messages needed)
3. Election state machine: StartElection → castVote → onVoteTimeout → determineWinner → broadcastConfirm → onConfirmTimeout → leader cached
4. DDNS gating: only leader proceeds with `SyncZoneDelegation`
5. Leader TTL expiry triggers proactive re-election
