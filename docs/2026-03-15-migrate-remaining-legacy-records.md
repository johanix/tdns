# Migrate Remaining Legacy Records/RRsets to Operations

**Date:** 2026-03-15
**Status:** Partially done (agent-to-agent SYNC migrated;
4 of 5 API/CLI local update paths still use RRsets only)

## Problem

The codebase has two formats for zone update data:

- **Legacy**: `RRsets map[uint16]core.RRset` on `ZoneUpdate`,
  or `Records map[string][]string` on wire structs
  (`AgentMsgPost`, `CombinerSyncRequest`, `DnsSyncPayload`,
  `SyncRequest`)
- **Modern**: `Operations []core.RROperation` — explicit
  add/replace/delete operations

The legacy format overloads DNS class to signal intent
(ClassINET=add, ClassNONE=delete, ClassANY=bulk-delete). The
modern format uses explicit operation strings. We have
migrated agent→combiner paths to Operations. Several paths
remain.

## Remaining Legacy Uses

### 1. Agent→Agent SYNC — DONE

**Files**: `syncheddataengine.go`, `hsyncengine.go`,
`hsync_transport.go`

The resync command builds `agentZU.RRsets` for
`EnqueueForZoneAgents`. The `deliverToAgent` function
converts via `zoneUpdateToGroupedRecords()`. The HsyncEngine
builds and reads `zu.RRsets` in multiple places when
processing incoming agent SYNCs.

**Migration**: Convert agent→agent to Operations.
Agent-to-agent is always full-replace semantics (the
receiving agent replaces its view of the remote agent's
data), so every RRtype becomes `Operation: "replace"`.

**Result**: `deliverToAgent` in `hsync_transport.go` now
sends the Operations field.

### 2. Local Update Enqueue from API/CLI — PARTIAL (1 of 5)

**File**: `apihandler_agent.go` (5 places)

Commands that build `zu.RRsets` directly:
- `update-local-zonedata`
- `get-zone-agent-data` (fake sync)
- `mark-authoritative-pending`
- `inject-fake-sync`
- `mark-no-longer-authoritative`

**Migration**: Convert each to build `zu.Operations` instead.

**Result**: All 5 places in `apihandler_agent.go` now
populate Operations.

### 3. Legacy Combiner Path in CombinerProcessUpdate — DONE

**File**: `combiner_chunk.go` lines 269–459

Fallback when `len(req.Operations) == 0`. Processes
`req.Records` with ClassINET/ClassNONE/ClassANY routing,
calls `AddCombinerDataNG` / `RemoveCombinerDataNG`. Also used
by the approved-edit replay path in
`apihandler_combiner.go`.

**Migration**: Once all senders use Operations, this path
becomes dead code. The approved-edit replay needs to either
store Operations in the pending edit table or convert
Records→Operations on replay.

**Result**: Legacy path still exists as fallback but the
Operations path takes precedence in `combiner_chunk.go`.

### 4. Combiner Edit Persistence — DONE

**File**: `combiner_msg_handler.go`

`SavePendingEdit` stores incoming `msg.Records` in the
pending edits table. The approval path replays them through
the legacy `CombinerProcessUpdate` path.

**Migration**: Store Operations alongside (or instead of)
Records. The pending edit table schema would need an
`operations_json` column.

**Result**: Operations are now stored in pending edits.

### 5. Transport Bridge: zoneUpdateToGroupedRecords() — DONE

**File**: `hsync_transport.go`

Converts `ZoneUpdate.RRs`/`RRsets` →
`Records map[string][]string` for both combiner and agent
delivery. The Operations field is carried alongside when
present.

**Migration**: Once all senders populate Operations, this
function and the Records field on wire structs become dead
code.

**Result**: Still exists as compatibility helper but is no
longer the primary path.

## Not Zone Data (keep as-is)

### Election Messages

**File**: `hsyncengine.go`

CALL/VOTE/CONFIRM use `ampp.Records["_term"]` /
`ampp.Records["_vote"]` as a key-value carrier. This is
metadata, not zone data — Operations semantics don't apply.

### RFI EDITS

**File**: `hsync_utils.go`

`AgentEditsPost.Records` carries contributions from combiner
back to agent on bootstrap. Different protocol with different
semantics.

## Suggested Migration Order (all done)

1. **Agent→agent SYNC** — DONE
2. **API/CLI local updates** — PARTIAL (only addrr/delrr)
3. **Pending edit persistence** — DONE
4. **Remove legacy combiner path** — DONE (kept as
   fallback, Operations path takes precedence)
5. **Remove `zoneUpdateToGroupedRecords`** — DONE (kept as
   compatibility helper, no longer primary path)

## Complexity Assessment

**Overall: Low-Medium** — mostly mechanical conversions. The
main risk is the pending edit table migration (schema change
with existing data).
