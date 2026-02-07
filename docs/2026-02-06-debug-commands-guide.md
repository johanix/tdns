# Debug Commands Guide

**Date:** 2026-02-06
**Status:** Implemented
**Related Issues:** DNS-57, DNS-64

## Overview

The debug command suite provides comprehensive introspection and testing capabilities for the DNS CHUNK NOTIFY transport system. These commands enable developers to test message routing, inspect agent state, and validate synchronization without requiring a full multi-agent deployment.

## Command Structure

All debug commands follow this pattern:

```bash
tdns-cli debug agent <subcommand> [flags]
```

**Location:** [tdns/v2/cli/agent_debug_cmds.go](../../v2/cli/agent_debug_cmds.go)

## Available Commands

### 1. Send NOTIFY

**Command:** `tdns-cli debug agent send-notify`

Send a DNS NOTIFY message to trigger agent processing.

**Flags:**
- `--id, -I`: Agent identity to claim
- `--rrtype, -R`: RR type to send notify for
- `--RR`: DNS record to send
- `--zone, -z`: Target zone name

**Example:**
```bash
tdns-cli debug agent send-notify \
  --zone example.com \
  --id agent.alpha \
  --rrtype A \
  --RR "test.example.com. A 192.0.2.1"
```

**Expected Output:**
```
NOTIFY sent successfully:
Triggered zone update notification for example.com
```

**Use Cases:**
- Test NOTIFY reception and processing
- Validate zone update triggers
- Debug notification routing

---

### 2. Send RFI (Request For Information)

**Command:** `tdns-cli debug agent send-rfi`

Send an RFI message to request information from peers.

**Flags:**
- `--rfi`: RFI type (`UPSTREAM` or `DOWNSTREAM`)
- `--zone, -z`: Target zone name

**Example:**
```bash
tdns-cli debug agent send-rfi \
  --zone example.com \
  --rfi UPSTREAM
```

**Expected Output:**
```
RFI sent successfully:
Request for upstream information sent for zone example.com
```

**Use Cases:**
- Test RFI message routing
- Validate upstream/downstream discovery
- Debug peer communication

---

### 3. Dump Agent Registry

**Command:** `tdns-cli debug agent dump-agent-registry`

Display all registered agents and their metadata.

**Flags:**
- `--zone, -z`: Target zone name (optional, shows all if omitted)

**Example:**
```bash
tdns-cli debug agent dump-agent-registry --zone example.com
```

**Expected Output:**
```
Agent Registry for zone: example.com
====================================

Agent ID: agent.alpha
  Status: active
  Last Seen: 2026-02-06T10:30:00Z
  Working Keys: 2
  Endpoints: [dns://ns1.example.com:53]

Agent ID: agent.bravo
  Status: active
  Last Seen: 2026-02-06T10:29:45Z
  Working Keys: 2
  Endpoints: [dns://ns2.example.com:53]

Total agents: 2
```

**Use Cases:**
- Verify agent discovery
- Check agent connectivity status
- Debug key exchange issues

---

### 4. Dump Zone Data Repo

**Command:** `tdns-cli debug agent dump-zone-data-repo`

Display the zone data repository state including all tracked changes.

**Flags:**
- `--zone, -z`: Target zone name

**Example:**
```bash
tdns-cli debug agent dump-zone-data-repo --zone example.com
```

**Expected Output:**
```
Zone Data Repository: example.com
=================================

Current Version: 42
Last Modified: 2026-02-06T10:25:00Z

Recent Changes:
  1. [v42] ADD test.example.com A 192.0.2.1 (from agent.alpha)
  2. [v41] UPDATE www.example.com A 192.0.2.10 (from agent.bravo)
  3. [v40] DELETE old.example.com A 192.0.2.99 (from agent.alpha)

Pending Syncs:
  - agent.charlie (v38 -> v42)
  - agent.delta (v40 -> v42)
```

**Use Cases:**
- Verify zone state consistency
- Debug synchronization lag
- Track change history

---

### 5. Registry Inspection

**Command:** `tdns-cli debug agent registry`

Display raw agent registry data structure.

**Example:**
```bash
tdns-cli debug agent registry
```

**Expected Output:**
```
Agent registry:
agent.alpha
Agent registry:
&{ID:agent.alpha Status:active LastSeen:2026-02-06T10:30:00Z ...}
```

**Use Cases:**
- Low-level registry debugging
- Inspect internal data structures

---

### 6. Trigger Sync

**Command:** `tdns-cli debug agent trigger-sync`

Simulate a zone change and trigger synchronization to peers.

**Flags:**
- `--from`: Source agent ID (required)
- `--rr`: DNS record to sync (required)
- `--zone, -z`: Target zone name

**Example:**
```bash
tdns-cli debug agent trigger-sync \
  --zone example.com \
  --from agent.alpha \
  --rr "test.example.com. A 192.0.2.1"
```

**Expected Output:**
```
Sync triggered successfully:
Initiated sync from agent.alpha for example.com
RR: test.example.com. A 192.0.2.1
Syncing to 3 peers: agent.bravo, agent.charlie, agent.delta
```

**Use Cases:**
- Test zone synchronization logic
- Validate multi-peer sync
- Debug sync failures

**API Endpoint:** `/agent` with command `hsync-inject-sync`

---

### 7. Force Sync

**Command:** `tdns-cli debug agent force-sync`

Force synchronization with a specific peer agent.

**Flags:**
- `--peer`: Target peer agent ID (required)
- `--rr`: DNS record to sync (optional)
- `--zone, -z`: Target zone name

**Example:**
```bash
tdns-cli debug agent force-sync \
  --zone example.com \
  --peer agent.bravo \
  --rr "test.example.com. A 192.0.2.1"
```

**Expected Output:**
```
Force sync completed:
Successfully synced with agent.bravo
Correlation ID: corr-12345-abc
```

**Use Cases:**
- Fix out-of-sync peers
- Test single-peer synchronization
- Debug peer communication

**API Endpoint:** `/agent` with command `hsync-force-sync`

---

### 8. Sync State

**Command:** `tdns-cli debug agent sync-state`

Display the current synchronization state for a zone.

**Flags:**
- `--zone, -z`: Target zone name

**Example:**
```bash
tdns-cli debug agent sync-state --zone example.com
```

**Expected Output:**
```
Sync State for zone example.com:
Current state: synchronized

Zone Data Repository:
  Version: 42
  Last Modified: 2026-02-06T10:25:00Z
  Total Changes: 156

Peer Sync Status:
  agent.bravo: v42 (synced)
  agent.charlie: v38 (4 versions behind)
  agent.delta: v42 (synced)

Pending Operations: 1
  - Sync to agent.charlie (started: 2026-02-06T10:29:30Z)
```

**Use Cases:**
- Monitor synchronization progress
- Identify sync lag
- Debug stuck synchronizations

**API Endpoint:** `/agent` with command `hsync-sync-state`

---

### 9. Send to Combiner

**Command:** `tdns-cli debug agent send-to-combiner`

Send test zone data to the combiner for processing.

**Flags:**
- `--rr`: DNS record to send (required)
- `--zone, -z`: Target zone name

**Example:**
```bash
tdns-cli debug agent send-to-combiner \
  --zone example.com \
  --rr "test.example.com. A 192.0.2.1"
```

**Expected Output:**
```
Data sent to combiner:
Successfully transmitted zone data to combiner
RR: test.example.com. A 192.0.2.1
Combiner will process and publish to catalog zone
```

**Use Cases:**
- Test agent-to-combiner communication
- Validate combiner data processing
- Debug catalog zone publishing

**API Endpoint:** `/agent` with command `hsync-send-to-combiner`

**Note:** Only works when combiner is configured.

---

### 10. Test Chain

**Command:** `tdns-cli debug agent test-chain`

Execute a full end-to-end test chain including local update, peer sync, and combiner processing.

**Flags:**
- `--scenario`: Test scenario (`add`, `update`, or `delete`, default: `add`)
- `--rr`: DNS record for test (required)
- `--zone, -z`: Target zone name

**Example:**
```bash
tdns-cli debug agent test-chain \
  --zone example.com \
  --scenario add \
  --rr "test.example.com. A 192.0.2.1"
```

**Expected Output:**
```
Test Chain Results:
===================

Scenario: add
Zone: example.com
RRs Count: 1

Step 1 (Local Update):
  ✓ Success: Zone data updated locally (version 43)

Step 2 (Peer Sync):
  Peers synced: 3
    ✓ agent.bravo: Sync completed (correlation: corr-123-abc)
    ✓ agent.charlie: Sync completed (correlation: corr-123-def)
    ✓ agent.delta: Sync completed (correlation: corr-123-ghi)

Step 3 (Combiner Processing):
  ⊘ Skipped: Combiner not configured
```

**Scenarios:**
- `add`: Test adding new records
- `update`: Test updating existing records
- `delete`: Test removing records

**Use Cases:**
- End-to-end testing
- Validate full sync pipeline
- Regression testing after changes

**API Endpoint:** `/agent` with command `hsync-test-chain`

---

## Common Workflows

### Testing New Agent Setup

1. **Verify Agent Registration:**
   ```bash
   tdns-cli debug agent dump-agent-registry --zone example.com
   ```

2. **Test Communication:**
   ```bash
   tdns-cli debug agent trigger-sync \
     --zone example.com \
     --from agent.alpha \
     --rr "test A 1.2.3.4"
   ```

3. **Check Sync State:**
   ```bash
   tdns-cli debug agent sync-state --zone example.com
   ```

### Debugging Sync Issues

1. **Check Zone Data:**
   ```bash
   tdns-cli debug agent dump-zone-data-repo --zone example.com
   ```

2. **Force Sync with Problem Peer:**
   ```bash
   tdns-cli debug agent force-sync \
     --zone example.com \
     --peer agent.problematic
   ```

3. **Verify Sync State:**
   ```bash
   tdns-cli debug agent sync-state --zone example.com
   ```

### End-to-End Validation

1. **Run Full Test Chain:**
   ```bash
   tdns-cli debug agent test-chain \
     --zone example.com \
     --scenario add \
     --rr "test A 1.2.3.4"
   ```

2. **Verify All Steps Succeeded:**
   - Check each step shows ✓
   - Note any failures or skipped steps
   - Review correlation IDs for tracking

---

## Troubleshooting

### Command Fails with "API error: Router not available"

**Cause:** DNS transport not configured or router not initialized.

**Solution:**
- Ensure `agent.dns.enabled: true` in config
- Verify DNS transport is running
- Check agent started without errors

### "Authorization failed" errors

**Cause:** Peer authentication failed or working keys not established.

**Solution:**
- Verify peer has valid JWK published
- Check working keys with `dump-agent-registry`
- Test key exchange with hello messages

### Sync appears stuck

**Cause:** Network issues or peer offline.

**Solution:**
1. Check peer status: `dump-agent-registry`
2. Review sync state: `sync-state`
3. Force sync: `force-sync --peer <problem-peer>`
4. Check distribution status: `tdns-cli agent distrib list`

### Test chain shows "Skipped: Combiner not configured"

**Cause:** Combiner configuration missing.

**Solution:**
- This is expected if not using combiner mode
- To enable: Add combiner config to agent YAML
- For testing without combiner: Use individual commands instead

---

## API Implementation

All debug commands use the `/agent` API endpoint with various commands.

**Location:** [tdns/v2/apihandler_agent.go](../../v2/apihandler_agent.go)

### Request Format

```go
type AgentMgmtPost struct {
    Command  string
    Zone     ZoneName
    AgentId  AgentId
    RRs      []string
    Data     map[string]interface{}
}
```

### Response Format

```go
type AgentMgmtResponse struct {
    Time     time.Time
    Msg      string
    Error    bool
    ErrorMsg string
    Data     interface{}
}
```

### Available Commands

- `hsync-inject-sync`: Trigger sync
- `hsync-force-sync`: Force peer sync
- `hsync-sync-state`: Get sync state
- `hsync-send-to-combiner`: Send to combiner
- `hsync-test-chain`: Run test chain
- (Additional commands for registry/zone dumps)

---

## See Also

- [DNS Router Architecture](2026-02-06-dns-router-architecture.md) - Router design and implementation
- [End-to-End Testing Guide](2026-02-06-e2e-testing.md) - Comprehensive testing procedures
- [Agent Debug Handlers Design](DEBUG_HANDLERS_DESIGN.md) - Original debug handler design
