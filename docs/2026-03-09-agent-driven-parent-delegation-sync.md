# Agent-Driven Parent Delegation Synchronization

**Date**: 2026-03-09
**Status**: Planning

## Context

The TDNS multi-provider architecture needs agents to synchronize delegation data (NS, glue, DNSKEY/CDS) with the parent zone. Currently:

- Delegation sync (`OptDelSyncChild`) is configured per-zone in the config file, not driven by HSYNC
- Sync scheme (UPDATE vs NOTIFY) is global viper config, not per-zone
- No CDS synthesis from DNSKEYs
- CSYNC only published reactively on the NOTIFY path, not proactively on NS changes
- HSYNC2 has a `ParentSync` field but it's dead code — never read at runtime
- No coordination between agents for who sends DDNS updates to the parent

### Design Decisions

- **Agents send to parent** (not combiner — keep combiner simple)
- **Dynamic leader election** among agents for who sends the actual DDNS update (random number, highest wins — sufficient for 2-3 agents)
- **Shared SIG(0) key** across all agents, distributed via existing encrypted CHUNK channel
- **HSYNC v1 extended now** with ParentSync field; SVCB-style redesign later
- **No installed base** — wire format changes are fine

## Phase 1: Extend HSYNC v1 with ParentSync

### 1a. Add ParentSync field to HSYNC struct

**File**: `core/rr_hsync.go`

Add `ParentSync uint8` after `Sign`. Values reuse HSYNC2 semantics:

```
HsyncParentSyncNone   uint8 = 0  // zone owner handles parent sync (default/backwards compat)
HsyncParentSyncNotify uint8 = 1  // agents publish CSYNC/CDS + send NOTIFY to parent
HsyncParentSyncUpdate uint8 = 2  // agents send DDNS UPDATE to parent
HsyncParentSyncAuto   uint8 = 3  // agents discover parent DSYNC and choose best method
```

Update:
- `Pack()` / `Unpack()` — add 1 byte after Sign, before Identity
- `Parse()` — accept 6 fields (was 5): State, NSmgmt, Sign, ParentSync, Identity, Upstream
- `String()` — include ParentSync in presentation format
- `Len()` — add 1
- `Copy()` — copy ParentSync
- String/parse maps: `HsyncParentSyncToString`, `StringToHsyncParentSync`

Zone file example:
```
example.com. IN HSYNC ON AGENT SIGN UPDATE agent1.example.com. upstream.example.com.
example.com. IN HSYNC ON AGENT NOSIGN AUTO agent2.example.com. .
```

### 1b. Agent reads ParentSync from HSYNC and sets zone option

**File**: `hsync_utils.go` (or `agent_utils.go`)

When agent processes HSYNC RRset (in `UpdateAgents` or `analyzeHsyncSigners`), also extract ParentSync from *our* HSYNC record:
- If ParentSync != NONE → set `OptDelSyncChild` on the zone (currently set from config only)
- Store the desired scheme (NOTIFY/UPDATE/AUTO) in ZoneData or a new per-zone field
- This replaces the static config-file-based `delegation-sync-child` option

### 1c. Update all HSYNC consumers for new field

**Files**: `cli/hsync_debug_cmds.go`, `hsync_utils.go`, `agent_policy.go`, zone file examples

Update parsing, display, validation code that handles HSYNC records.

## Phase 2: Proactive CDS and CSYNC Publication

### 2a. CDS synthesis from DNSKEYs

**File**: new function in `ops_cds.go` (or extend `delegation_sync.go`)

When DNSKEYs change (detected via KEYSTATE or zone update):
- Synthesize CDS RRset from current KSK DNSKEY(s)
- Publish CDS into the zone via `UpdateQ`
- CDS format: hash of DNSKEY per RFC 7344 (DS-like record at zone apex)

Trigger: hook into the existing DNSKEY change detection path (KEYSTATE message handler in `signer_msg_handler.go` or agent's SDE).

### 2b. Proactive CSYNC on NS changes

**File**: `zone_updater.go` or `delegation_sync.go`

When `ZoneUpdateChangesDelegationDataNG` detects NS/glue changes:
- Always publish/update CSYNC RR (currently only done on NOTIFY path)
- CSYNC should be published regardless of which sync scheme is configured
- CSYNC serves as a signal to scanning parents even if we also do active DDNS

### 2c. DSYNC discovery on zone setup

**File**: `zone_utils.go` (`SetupZoneSync` or new OnFirstLoad callback)

When a zone's HSYNC says ParentSync != NONE:
1. Discover parent zone (via IMR)
2. Look up `_dsync.<parent>` for DSYNC RRset
3. If parent supports UPDATE scheme → prefer DDNS (if our HSYNC says UPDATE or AUTO)
4. If parent supports NOTIFY → use NOTIFY (if our HSYNC says NOTIFY or AUTO)
5. If no DSYNC found → fall back to CSYNC publication only (passive, wait for parent to scan)
6. Cache discovery result in ZoneData for use by delegation sync engine

## Phase 3: Leader Election for DDNS Updates

### 3a. Simple leader election protocol

**File**: new `parentsync_leader.go` (or extend `hsyncengine.go`)

Protocol (runs per zone, among agents that have ParentSync != NONE):
1. When an agent detects it needs to send a DDNS update to the parent
2. Agent generates a random uint32 and broadcasts `PARENTSYNC-ELECT` message to all peer agents (via existing CHUNK messaging)
3. Each agent responds with its own random number
4. Highest number wins (ties broken by agent identity string comparison)
5. Winner sends the DDNS update; losers stand down
6. Election result cached with a TTL (e.g., 5 minutes) — don't re-elect on every change

Failure handling:
- If elected leader doesn't respond to beats within timeout → re-elect
- If only one agent is alive → it sends directly (no election needed)
- Election only needed when >1 agent has ParentSync set

### 3b. SIG(0) key distribution

**File**: extend existing key management in `ops_key.go` + CHUNK messaging

When an agent generates or receives a SIG(0) key for delegation sync:
1. Agent generates the SIG(0) keypair (as today in `BootstrapSig0KeyWithParent`)
2. Agent distributes the private key to peer agents via encrypted CHUNK message (new message type `PARENTSYNC-KEY`)
3. Receiving agents store the private key in their local keystore, associated with the zone
4. On key rollover, same distribution mechanism

For first cut: the first agent to set up delegation sync for a zone generates the key and distributes it. Other agents wait for the key before attempting DDNS.

### 3c. Coordinated DDNS sending

**File**: extend `delegation_sync.go`

When delegation data changes and agent determines DDNS update is needed:
1. Check if we are the current elected leader for this zone's parent sync
2. If yes → send the DDNS update (existing `SyncZoneDelegationViaUpdate` machinery)
3. If no → do nothing (leader will handle it)
4. If no leader elected → trigger election (Phase 3a)

## Phase 4 (Future): SVCB-style HSYNC Redesign

Not in scope for this implementation, but the direction:
- Replace fixed RDATA fields with SVCB-like key=value pairs
- Each pair: `<key-code>` (uint16) + `<value-length>` (uint16) + `<value>` (variable)
- Existing fields become standard keys (state, nsmgmt, sign, parentsync, identity, upstream)
- New keys can be added without wire format changes
- Presentation format: `example.com. IN HSYNC 1 agent1.example.com. upstream.example.com. nsmgmt=agent sign=yes parentsync=auto`

## Implementation Order

1. **Phase 1** (HSYNC extension + agent reads ParentSync) — prerequisite for everything
2. **Phase 2a-2b** (CDS/CSYNC publication) — can be done independently, useful even without DDNS
3. **Phase 2c** (DSYNC discovery) — needed before Phase 3
4. **Phase 3a** (leader election) — needed before coordinated DDNS
5. **Phase 3b** (key distribution) — needed before coordinated DDNS
6. **Phase 3c** (coordinated DDNS sending) — the final piece

Phases 1 and 2 are the immediate work. Phase 3 can follow as a second iteration.

## Files Modified

| Phase | Files |
|-------|-------|
| 1a | `core/rr_hsync.go` |
| 1b | `hsync_utils.go`, `agent_utils.go` |
| 1c | `cli/hsync_debug_cmds.go`, `agent_policy.go`, zone files |
| 2a | new `ops_cds.go` or `delegation_sync.go` |
| 2b | `zone_updater.go` or `delegation_sync.go` |
| 2c | `zone_utils.go` |
| 3a | new `parentsync_leader.go` |
| 3b | `ops_key.go`, CHUNK message handlers |
| 3c | `delegation_sync.go` |

## Verification

1. Build: `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
2. Parse HSYNC with ParentSync in zone file → verify correct field values
3. Wire format round-trip test for HSYNC with ParentSync
4. Agent startup with HSYNC ParentSync=UPDATE → verify `OptDelSyncChild` set automatically
5. NS change in zone → verify CSYNC published proactively
6. DNSKEY change → verify CDS synthesized and published
7. (Phase 3) Two agents restart → verify leader election and single DDNS update sent
