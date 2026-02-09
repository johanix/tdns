# Agent Debug Commands for Testing Synchronization

This document describes the four debug commands for testing agent synchronization functionality.

## Overview

These commands allow you to:
1. **Inspect** what data the agent has stored from peers
2. **Inspect** what modifications the combiner has stored
3. **Inject** fake SYNC messages as if they came from remote agents
4. **Send** real SYNC messages to remote agents

All commands go through normal authorization and validation paths.

---

## 1. show-synced-data

**Purpose**: Display the agent's ZoneDataRepo showing contributions from all peer agents.

**Usage**:
```bash
# Show all synchronized data
tdns-cliv2 debug agent show-synced-data

# Filter by specific zone
tdns-cliv2 debug agent show-synced-data --zone example.com.
```

**Output Format**:
```
Synchronized Data from Peer Agents
===================================

Zone: example.com.
────────────────────────────────────────
  Source: agent.provider-a.example.com.
    NS (2 records):
      example.com. 3600 IN NS ns1.provider-a.example.com.
      example.com. 3600 IN NS ns2.provider-a.example.com.

  Source: agent.provider-b.example.com.
    NS (2 records):
      example.com. 3600 IN NS ns1.provider-b.example.com.
      example.com. 3600 IN NS ns2.provider-b.example.com.
```

**Data Organization**:
- Sorted by: zone → source agent → RRtype → RRs
- Shows exactly what the agent has stored from each peer

---

## 2. show-combiner-data

**Purpose**: Display the combiner's stored local modifications that are applied to zones.

**Usage**:
```bash
# Show all combiner modifications
tdns-cliv2 debug agent show-combiner-data

# Filter by specific zone
tdns-cliv2 debug agent show-combiner-data --zone example.com.
```

**Output Format**:
```
Combiner Local Modifications
=============================

Zone: example.com.
────────────────────────────────────────
  Owner: example.com.
    NS (4 records):
      example.com. 3600 IN NS ns1.provider-a.example.com.
      example.com. 3600 IN NS ns2.provider-a.example.com.
      example.com. 3600 IN NS ns1.provider-b.example.com.
      example.com. 3600 IN NS ns2.provider-b.example.com.
```

**Data Organization**:
- Sorted by: zone → owner → RRtype → RRs
- Shows what the combiner will apply to the zone

**Note**: This displays `zd.CombinerData` which contains modifications that are merged into the zone during `CombineWithLocalChanges()`.

---

## 3. fake-sync-from

**Purpose**: Inject a fake SYNC message from a remote agent for testing.

**Behavior**:
- Simulates receiving a SYNC message from a specified remote agent
- Goes through normal authorization (HSYNC membership check)
- Stores data in ZoneDataRepo with source attribution
- Triggers combiner update if data changes
- **Does NOT send to remote agents** (injection only affects local state)

**Usage**:
```bash
tdns-cliv2 debug agent fake-sync-from \
  --from agent.provider-b.example.com. \
  --zone example.com. \
  "example.com. 3600 IN NS ns1.provider-b.example.com." \
  "example.com. 3600 IN NS ns2.provider-b.example.com."
```

**Parameters**:
- `--from`: Source agent ID (who the SYNC is "from")
- `--zone`: Zone name
- `<RR>...`: One or more DNS records (full RR strings)

**Output**:
```
Fake SYNC injected successfully:
  From: agent.provider-b.example.com.
  Zone: example.com.
  Records: 2

Sync injected successfully: 2 RRs processed from "agent.provider-b.example.com."
```

**Use Cases**:
- Test agent storage without needing remote agents running
- Verify HSYNC authorization works correctly
- Test combiner updates triggered by peer contributions
- Simulate multi-provider scenarios locally

---

## 4. send-sync-to

**Purpose**: Send a real SYNC message to a remote agent using actual transport.

**Behavior**:
- Creates and sends a real SYNC message via CHUNK NOTIFY transport
- Uses fallback to API if DNS transport fails
- Goes through normal authorization
- Remote agent stores the contribution and updates its combiner

**Usage**:
```bash
tdns-cliv2 debug agent send-sync-to \
  --to agent.provider-b.example.com. \
  --zone example.com. \
  "example.com. 3600 IN NS ns1.provider-a.example.com." \
  "example.com. 3600 IN NS ns2.provider-a.example.com."
```

**Parameters**:
- `--to`: Target agent ID (who to send the SYNC to)
- `--zone`: Zone name
- `<RR>...`: One or more DNS records (full RR strings)

**Output**:
```
SYNC sent successfully:
  To: agent.provider-b.example.com.
  Zone: example.com.
  Records: 2

SYNC sent successfully to "agent.provider-b.example.com." (distribution: debug-send-sync-1738954123)
  Distribution ID: debug-send-sync-1738954123
  Status: success
  Message: sync received and processed
```

**Use Cases**:
- Test end-to-end SYNC communication
- Verify DNS transport works (CHUNK NOTIFY)
- Test API fallback mechanism
- Trigger real combiner updates on remote agents

---

## Authorization Requirements

All commands respect HSYNC authorization:

1. **fake-sync-from**: Requires the source agent (`--from`) to be in the zone's HSYNC RRset or agent.authorized_peers
2. **send-sync-to**: Requires the target agent (`--to`) to exist in the agent registry
3. **Zone membership**: Both commands require the zone to exist and have an HSYNC RRset with the local agent

**Note**: The temporary bypass via `agent.authorized_peers` was for initial testing. For production use, agents should be properly listed in the zone's HSYNC RRset.

---

## Testing Scenarios

### Scenario 1: Test Local Storage
```bash
# Inject fake SYNC from provider B
tdns-cliv2 debug agent fake-sync-from \
  --from agent.provider-b.example.com. \
  --zone example.com. \
  "example.com. 3600 IN NS ns1.provider-b.example.com." \
  "example.com. 3600 IN NS ns2.provider-b.example.com."

# Verify it was stored
tdns-cliv2 debug agent show-synced-data --zone example.com.

# Check if combiner received the update
tdns-cliv2 debug agent show-combiner-data --zone example.com.
```

### Scenario 2: Test End-to-End SYNC
```bash
# Send SYNC to remote agent
tdns-cliv2 debug agent send-sync-to \
  --to agent.provider-b.example.com. \
  --zone example.com. \
  "example.com. 3600 IN NS ns1.provider-a.example.com." \
  "example.com. 3600 IN NS ns2.provider-a.example.com."

# On provider B, verify it was received
ssh provider-b
tdns-cliv2 debug agent show-synced-data --zone example.com.
```

### Scenario 3: Multi-Provider Union
```bash
# Provider A: Inject contributions from B and C
tdns-cliv2 debug agent fake-sync-from \
  --from agent.provider-b.example.com. \
  --zone example.com. \
  "example.com. 3600 IN NS ns1.provider-b.example.com."

tdns-cliv2 debug agent fake-sync-from \
  --from agent.provider-c.example.com. \
  --zone example.com. \
  "example.com. 3600 IN NS ns1.provider-c.example.com."

# Verify all contributions are stored separately
tdns-cliv2 debug agent show-synced-data --zone example.com.

# Verify combiner has the union
tdns-cliv2 debug agent show-combiner-data --zone example.com.
```

---

## Implementation Details

### CLI Layer
- Location: `tdns/v2/cli/agent_debug_cmds.go`
- Commands: DebugAgentShowSyncedDataCmd, DebugAgentShowCombinerDataCmd, DebugAgentFakeSyncFromCmd, DebugAgentSendSyncToCmd
- RR validation: Uses `dns.NewRR()` to parse and validate before sending

### Backend Layer
- Location: `tdns/v2/apihandler_agent.go`
- Handlers: `show-combiner-data`, `fake-sync-from`, `send-sync-to`
- Processing: `fake-sync-from` sends to SynchedDataEngine, `send-sync-to` uses TransportManager

### Data Flow

**fake-sync-from**:
```
CLI → API Handler → SynchedDataEngine → ZoneDataRepo → Combiner (if changed)
```

**send-sync-to**:
```
CLI → API Handler → TransportManager → CHUNK NOTIFY → Remote Agent → Remote ZoneDataRepo → Remote Combiner
```

---

## Notes

1. **RR Format**: Must provide complete RR strings (owner, TTL, class, type, rdata)
2. **FQDNs**: Domain names should be fully qualified (ending with `.`)
3. **Multiple RRs**: Can provide multiple RRs in a single command (space-separated arguments)
4. **Transport**: `send-sync-to` uses CHUNK NOTIFY (UDP/TCP) with API fallback
5. **Timeout**: Commands have 5-second timeout for SynchedDataEngine response

---

## Troubleshooting

### "source agent ID not found"
- Agent must be in the zone's HSYNC RRset or `agent.authorized_peers` config
- Check: `tdns-cliv2 agent peers` to see known agents

### "TransportManager not available"
- DNS transport not configured
- Check agent config has `agent.remote.address` and `agent.remote.port`

### "zone not found"
- Zone must exist in the agent
- Check: `tdns-cliv2 zones` to list known zones

### "timeout waiting for SynchedDataEngine"
- SynchedDataEngine not running or blocked
- Check agent logs for processing errors
