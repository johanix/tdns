# Migrate Remaining Legacy Records/RRsets to Operations

**Date:** 2026-03-15
**Status:** Plan (not started)

## Problem

The codebase has two formats for zone update data:

- **Legacy**: `RRsets map[uint16]core.RRset` on `ZoneUpdate`, or `Records map[string][]string`
  on wire structs (`AgentMsgPost`, `CombinerSyncRequest`, `DnsSyncPayload`, `SyncRequest`)
- **Modern**: `Operations []core.RROperation` — explicit add/replace/delete operations

The legacy format overloads DNS class to signal intent (ClassINET=add, ClassNONE=delete,
ClassANY=bulk-delete). The modern format uses explicit operation strings. We have migrated
agent→combiner paths to Operations. Several paths remain.

## Remaining Legacy Uses

### 1. Agent→Agent SYNC

**Files**: `syncheddataengine.go`, `hsyncengine.go`, `hsync_transport.go`

The resync command builds `agentZU.RRsets` for `EnqueueForZoneAgents`. The `deliverToAgent`
function converts via `zoneUpdateToGroupedRecords()`. The HsyncEngine builds and reads
`zu.RRsets` in multiple places when processing incoming agent SYNCs.

**Migration**: Convert agent→agent to Operations. Agent-to-agent is always full-replace
semantics (the receiving agent replaces its view of the remote agent's data), so every
RRtype becomes `Operation: "replace"`.

### 2. Local Update Enqueue from API/CLI

**File**: `apihandler_agent.go` (5 places)

Commands that build `zu.RRsets` directly:
- `update-local-zonedata`
- `get-zone-agent-data` (fake sync)
- `mark-authoritative-pending`
- `inject-fake-sync`
- `mark-no-longer-authoritative`

**Migration**: Convert each to build `zu.Operations` instead.

### 3. Legacy Combiner Path in CombinerProcessUpdate

**File**: `combiner_chunk.go` lines 269–459

Fallback when `len(req.Operations) == 0`. Processes `req.Records` with
ClassINET/ClassNONE/ClassANY routing, calls `AddCombinerDataNG` / `RemoveCombinerDataNG`.
Also used by the approved-edit replay path in `apihandler_combiner.go`.

**Migration**: Once all senders use Operations, this path becomes dead code. The approved-edit
replay needs to either store Operations in the pending edit table or convert Records→Operations
on replay.

### 4. Combiner Edit Persistence

**File**: `combiner_msg_handler.go`

`SavePendingEdit` stores incoming `msg.Records` in the pending edits table. The approval
path replays them through the legacy `CombinerProcessUpdate` path.

**Migration**: Store Operations alongside (or instead of) Records. The pending edit table
schema would need an `operations_json` column.

### 5. Transport Bridge: zoneUpdateToGroupedRecords()

**File**: `hsync_transport.go`

Converts `ZoneUpdate.RRs`/`RRsets` → `Records map[string][]string` for both combiner
and agent delivery. The Operations field is carried alongside when present.

**Migration**: Once all senders populate Operations, this function and the Records field
on wire structs become dead code.

## Not Zone Data (keep as-is)

### Election Messages

**File**: `hsyncengine.go`

CALL/VOTE/CONFIRM use `ampp.Records["_term"]` / `ampp.Records["_vote"]` as a key-value
carrier. This is metadata, not zone data — Operations semantics don't apply.

### RFI EDITS

**File**: `hsync_utils.go`

`AgentEditsPost.Records` carries contributions from combiner back to agent on bootstrap.
Different protocol with different semantics.

## Suggested Migration Order

1. **Agent→agent SYNC** — most impactful, unifies the last major data path
2. **API/CLI local updates** — 5 mechanical conversions in `apihandler_agent.go`
3. **Pending edit persistence** — schema change + approved-edit replay conversion
4. **Remove legacy combiner path** — once no sender uses Records-only format
5. **Remove `zoneUpdateToGroupedRecords`** and Records fields from wire structs

## Complexity Assessment

**Overall: Low-Medium** — mostly mechanical conversions. The main risk is the pending edit
table migration (schema change with existing data).
