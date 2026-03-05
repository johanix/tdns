# DNSKEY Deletion Propagation: Explicit Operations, `mpremove` State, and REPLACE Semantics

**Date**: 2026-03-05
**Status**: Implemented (all 4 phases)

## Context

When a DNSKEY is deleted or retired on the signer, remote agents are never notified. The signer is the source of truth for keys — it must explicitly inform agents about both additions and removals.

### Problem with current DDNS-overloaded semantics

Currently, operations are encoded by overloading the DNS Class field:
- `ClassINET` = ADD
- `ClassNONE` = DELETE (single RR)
- `ClassANY` = DELETE (entire RRset)

This constrains us to DNS Dynamic Update semantics when our transport is JSON-based and can express anything. The critical problem: **ClassNONE deletion is destructive and non-recoverable**. Once a remote agent removes an RR, you can't re-send "remove this" if the agent restarts or misses the message — you've lost the reference data.

### Two changes

This plan addresses two related problems:

1. **Explicit operation semantics**: Move from Class-field overloading to explicit `Operation` fields in the transport payload. Three operations: `add`, `delete`, `replace`.

2. **`mpremove` state**: A key being removed from MP zones stays in `mpremove` until all agents confirm, then transitions to `removed`. This keeps the key data alive for retries.

The `replace` operation is particularly powerful for DNSKEYs: the signer sends "here is the complete authoritative DNSKEY set" and the remote agent makes its local state match. No diffing, no lost deletes, idempotent on retry, safe after restart.

## Part A: Explicit Operation Semantics

### Current payload structure

```go
// transport.SyncRequest (agent/transport/transport.go:145)
type SyncRequest struct {
    Records     map[string][]string  // owner → []RR strings (Class embedded in text)
    MessageType string               // "sync" or "update"
    ...
}

// core.AgentMsgPost (core/messages.go:87)
type AgentMsgPost struct {
    Records map[string][]string  // same format
    ...
}
```

Operations are implicit: each RR string contains `IN` (add), `NONE` (delete), or `ANY` (delete RRset) in the class position. The receiver parses each string with `dns.NewRR()` and checks `rr.Header().Class`.

### New: `Operations` field

Add a new `Operations` field alongside the existing `Records` field. Both sender and receiver check `Operations` first; if empty, fall back to `Records` for backwards compatibility during transition.

```go
// New type in core/messages.go
type RROperation struct {
    Operation string   `json:"operation"`          // "add", "delete", "replace"
    RRtype    string   `json:"rrtype"`             // DNS RR type (e.g. "DNSKEY") — required for "replace"
    Records   []string `json:"records,omitempty"`  // RR strings in ClassINET text format
}
```

**Operation semantics:**
- **`add`**: Add these RRs to the RRset (same as current ClassINET). Incremental — leaves existing RRs untouched.
- **`delete`**: Remove these specific RRs from the RRset (same as current ClassNONE). Records carry the full RR data so the receiver knows what to remove.
- **`replace`**: Here is the complete authoritative set for this owner+rrtype. Make yours match exactly. RRs not in this set are removed. Idempotent. Self-describing. This is `INSERT OR REPLACE` semantics.

**Why `replace` matters:**
1. **Idempotent**: Send the same replace twice, get the same result. Safe for retries and resyncs.
2. **No lost deletes**: A removed key simply isn't in the set. No need for prior state.
3. **Restart-safe**: After agent restart, a replace message converges to correct state without history.
4. **Simplifies resync**: No need to reconstruct diffs — just send the current authoritative set.

**Important**: For `replace`, the `Records` list may be empty — meaning "delete the entire RRset for this owner+rrtype". This is different from `delete` which specifies individual RRs.

### Confirmation semantics for `replace`

The existing confirmation structure works unchanged:

```go
SyncResponse {
    AppliedRecords []string          // RRs that were added
    RemovedRecords []string          // RRs that were removed
    RejectedItems  []RejectedItemDTO // RRs that couldn't be applied
}
```

For a `replace` operation, the receiver diffs old vs new to determine what actually changed:
- `AppliedRecords`: RRs newly added (in replacement set but not in old set)
- `RemovedRecords`: RRs implicitly removed (in old set but not in replacement set)
- `RejectedItems`: Any RRs from the replacement set that couldn't be applied

If the replace is idempotent (no change), both lists are empty and status is `ConfirmSuccess`. No new confirmation fields are needed — `replace` decomposes into adds and removes at the receiver level.

### Scope and backwards compatibility

- **DNSKEY only**: Only the SYNC-DNSKEY-RRSET handler uses `Operations`/`replace`. NS, A, and other RRtypes continue to use `Records` with ClassINET/ClassNONE. Other RRtypes can adopt `Operations` later without structural changes.
- If `Operations` is empty/nil, receivers fall back to `Records` (existing behavior)
- No flag day needed; can migrate callers incrementally

### Files to modify

#### A1. Add `RROperation` type — `core/messages.go`

```go
type RROperation struct {
    Operation string   `json:"operation"`          // "add", "delete", "replace"
    RRtype    string   `json:"rrtype"`             // DNS RR type (e.g. "DNSKEY")
    Records   []string `json:"records,omitempty"`  // RR strings in ClassINET text format
}
```

Add `Operations []RROperation` field to `AgentMsgPost`.

#### A2. Add `Operations` to transport SyncRequest — `agent/transport/transport.go`

Add `Operations []core.RROperation` field.

#### A3. Build Operations in SYNC-DNSKEY-RRSET handler — `hsyncengine.go`

Use `replace` operation with `CurrentLocalKeys` from `DnskeyStatus`.

#### A4. Transport: prefer Operations over Records — `hsync_transport.go`

Add `Operations` to `ZoneUpdate`. Transport layer carries it through to `SyncRequest`.

#### A5. Receiving agent: process Operations — `hsyncengine.go` (MsgHandler)

Check `Operations` before parsing `Records`.

#### A6. ProcessUpdate: handle Operations — `agent_policy.go`

New `processOperations` method handles `add`, `delete`, `replace`. For `replace`:
1. Parse all records in the operation
2. Diff against current RRset for this agent+zone+rrtype
3. Replace entirely with new set
4. Report actual adds/removes in confirmation

#### A7. EvaluateUpdate: validate Operations — `agent_policy.go`

Validate RRtype is allowed, records are at zone apex.

#### A8. Chunk payload: carry Operations — `agent/transport/dns.go`

No code change — JSON marshalling handles the new field automatically.

---

## Part B: `mpremove` State

### State machine (complete)

```
Non-MP:  created → published → standby → active → retired → removed
MP add:  created → mpdist → [confirm] → published → standby → active
MP del:  active → retired → mpremove → [confirm] → removed
```

### DNSKEY RRset composition

Keys included in published DNSKEY RRset: `mpdist`, `published`, `standby`, `active`, `retired`, `foreign`
Keys excluded: `created`, `mpremove`, `removed`

### Changes

#### B1. Add `DnskeyStateMpremove` constant — `structs.go`

#### B2. CLI valid states — `cli/prepargs.go`

Add `"mpremove"` to `DefinedDnskeyStates`.

#### B3. KeyStateWorker: retired → mpremove (MP) or retired → removed (non-MP) — `key_state_worker.go`

Change `transitionRetiredToRemoved` to check zone MP status via `zd.Options[OptMultiProvider]`.

#### B4. `pushKeystateInventoryToAllAgents` helper — `signer_msg_handler.go`

New function: iterates `conf.MultiProvider.Agents`, calls existing `sendKeystateInventoryToAgent` for each.

Call sites: KeyStateWorker (after state changes), API handler (after delete/rollover/setstate), SignerMsgHandler (after mpdist→published).

#### B5. Manual delete → mpremove/removed — `keystore.go`

Change "delete" case in `DnssecKeyMgmt` from `DELETE FROM DnssecKeyStore` to `UpdateDnssecKeyState(zone, keyid, targetState)`:
- MP zone: `targetState = mpremove`
- Non-MP zone: `targetState = removed`

#### B6. API handler: re-sign + inventory push after delete/setstate — `apihandler_funcs.go`

Extend existing rollover trigger to cover `"delete"` and `"setstate"`.

#### B7. Signer handles "propagated" for mpremove → removed — `signer_msg_handler.go`, `keystore.go`

Add `TransitionMpremoveToRemoved` (same pattern as `TransitionMpdistToPublished`). Called alongside existing transition in "propagated" signal handler.

#### B8. DNSKEY RRset: exclude mpremove — `ops_dnskey.go`

Verify exclusion. Current query uses explicit inclusion list — should already exclude.

#### B9. `extractRemoteDNSKEYs`: include mpremove in local keys — `sign.go`

Add `DnskeyStateMpremove` to the local key states list.

---

## Part C: Agent-side DNSKEY handling with REPLACE

#### C1. `LocalDnskeysFromKeystate`: produce `replace` data — `hsync_utils.go`

Add `CurrentLocalKeys []dns.RR` field to `DnskeyStatus`. Skip `mpremove`, `created`, `removed` states when building local key set.

#### C2. Agent: process proactive inventory pushes — `hsyncengine.go`

New `HandleProactiveKeystateInventory` on `AgentRegistry`. Stores inventory, detects changes, feeds SYNC-DNSKEY-RRSET.

#### C3. Propagation tracking for removals — `hsyncengine.go`

Extract key tags from both `LocalAdds` and `LocalRemoves` for `DnskeyKeyTags`.

#### C4. ProcessUpdate `replace` for remote DNSKEY — `agent_policy.go`

Part of A6 `processOperations`. Diffs old vs new RRset, replaces, reports actual changes in confirmation.

---

## Implementation Order

**Phase 1** (foundation): A1, A2, B1, B2 — types and constants ✓ DONE
**Phase 2** (signer-side mpremove): B3, B4, B5, B6, B7, B8, B9 — mpremove lifecycle ✓ DONE
**Phase 3** (explicit operations): A3, A4, A5, A6, A7, A8 — Operations field + replace ✓ DONE
**Phase 4** (agent-side integration): C1, C2, C3, C4 — agent processes replace + proactive inventory ✓ DONE

Phase 2 can be implemented and tested with the existing ClassINET/ClassNONE mechanism. Phase 3+4 add the `replace` operation. This allows incremental validation.

## Risk Assessment

### Low risk
- **B1, B2** (constants, CLI states): Pure additive, no behavior change.
- **B8** (DNSKEY RRset exclude mpremove): Likely no code change.
- **B9** (extractRemoteDNSKEYs): 1-line addition.
- **A1, A2** (RROperation type, Operations field): Pure additive with `omitempty`.

### Medium risk
- **B3** (KeyStateWorker retired→mpremove): Must correctly detect MP zones. Mitigated by reusing existing `zd.Options[OptMultiProvider]` pattern.
- **B5** (manual delete → mpremove): Changes destructive DELETE to state transition. Must look up MP status inside `DnssecKeyMgmt`.
- **A3, A4** (build/carry Operations): If Operations doesn't survive serialization, falls back to empty Records → no update. Must verify JSON round-trip.
- **C1** (filter mpremove/created/removed): Over-filtering could suppress keys. Mitigated: these states are already excluded from DNSKEY RRset at signer level.

### Higher risk
- **A6** (processOperations/replace): New code path. Replace could wipe DNSKEY data if buggy. Mitigated: agent-ID scoped, only affects one agent's slot.
- **C2** (proactive inventory handler): Race with zone loading. Mitigated: guard with `Zones.Get()`.

### No risk of data loss
- Keys are never deleted from DB — they transition to `removed`.
- `replace` only affects one agent's RRset slot.
- Existing ClassINET/ClassNONE path remains for all non-DNSKEY RRtypes.

## Complexity Evaluation

| Phase | Steps | Complexity | Notes |
|-------|-------|------------|-------|
| **Phase 1** (foundation) | A1, A2, B1, B2 | **Low** | One-liner additions |
| **Phase 2** (signer mpremove) | B3–B9 | **Medium** | Small edits to existing functions |
| **Phase 3** (explicit ops) | A3–A8 | **Medium-High** | A6 is most complex (~70 lines) |
| **Phase 4** (agent integration) | C1–C4 | **Medium** | New handler + filter conditions |

**Total**: ~290 lines across 14 files.

## Design Decisions

1. **`replace` decomposes into adds/removes for confirmation**: The receiver diffs old vs new and reports actual changes. No new confirmation fields needed.

2. **`mpremove` still needed despite `replace`**: `replace` makes distribution idempotent, but `mpremove` tracks whether all agents have confirmed removal. Without it, the signer can't know if it's safe to stop including the key in inventory pushes.

3. **No automatic rotation**: Rollover remains manual via CLI. `KeyStateWorker` maintains the standby pipeline and handles retirement/removal lifecycle.

4. **DNSKEY only for now**: `Operations` infrastructure supports all RRtypes but only DNSKEY uses it initially. NS/A continue with ClassINET/ClassNONE.

5. **Keys never deleted from DB**: `removed` state rows stay for audit trail and resync capability.
