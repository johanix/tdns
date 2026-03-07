# Combiner Operations Support: Handle `replace` for DNSKEY Forwarding

## Context

Phases 1–4 of the DNSKEY deletion propagation plan are implemented. The agent side correctly:
- Builds `replace` operations for DNSKEY syncs (SYNC-DNSKEY-RRSET handler)
- Processes `replace` operations from remote agents (processReplaceOp in agent_policy.go)
- Forwards the Operations field to the combiner (deliverToCombiner in hsync_transport.go)

**The hole**: The combiner has **zero code to handle Operations**. When a remote DNSKEY `replace` is forwarded to the combiner, only the legacy `Records` (ClassINET additions) are processed. The `Operations` field is carried through the transport but ignored at the combiner.

**Result**: Removed DNSKEYs linger in the combiner's `AgentContributions` because the combiner only sees ClassINET adds — it never knows to remove the old keys.

### What the combiner needs to do for `replace`

For a `replace` operation targeting DNSKEY from agent X:
1. Remove agent X's existing DNSKEY contributions for that owner
2. Set agent X's DNSKEY contributions to the new set
3. Rebuild CombinerData (merge all agents)
4. Report what was added and what was removed (for confirmation tracking)

This is exactly what the agent-side `processReplaceOp` does for the SDE, adapted for `AgentContributions`.

## Changes Required

### 1. Add `Operations` field to `CombinerSyncRequest` — combiner_chunk.go:33

```go
type CombinerSyncRequest struct {
    ...
    Records    map[string][]string   // Legacy: Class-overloaded RR strings
    Operations []core.RROperation    // Explicit operations (takes precedence)
    ...
}
```

### 2. Pass `msg.Operations` through `CombinerMsgHandler` — combiner_msg_handler.go:178

In the auto-approve path where `CombinerSyncRequest` is built (line 178):
```go
syncReq := &CombinerSyncRequest{
    ...
    Records:        msg.Records,
    Operations:     msg.Operations,    // NEW
    ...
}
```

Also: the `isNoOpUpdate` check (line 141) must handle Operations. Currently it only checks `msg.Records` via Class-overloaded semantics. Add a new `isNoOpOperations` function that checks Operations against the agent's current `AgentContributions`:

- **`replace`**: Compare the replacement set against `AgentContributions[senderID][zonename][rrtype].RRs`. If they contain exactly the same RRs (using `dns.IsDuplicate`), it's a no-op. Empty replacement set + no existing contributions = also no-op.
- **`add`**: Each RR in the operation already exists in `AgentContributions` or the live zone → no-op.
- **`delete`**: Each RR in the operation is already absent → no-op.

The call site in `CombinerMsgHandler` becomes:
```go
if len(msg.Operations) > 0 {
    noOp = isNoOpOperations(zd, senderID, msg.Operations)
} else {
    noOp = isNoOpUpdate(zd, senderID, msg.Records)
}
```

When Operations are present and it IS a no-op, the auto-confirm response should still collect the appropriate `AppliedRecords` from the Operations (all RRs in replace/add ops, since these are the records the agent expects confirmation for).

Also: the pending edit persistence (line 122) currently stores `msg.Records`. Operations should also be stored, but this is audit trail — can be deferred. The Records field still contains the ClassINET RR strings (from `zoneUpdateToGroupedRecords`), so the audit trail is not empty.

### 3. Add `ReplaceCombinerDataByRRtype` — combiner_utils.go

New function, modeled on existing `RemoveCombinerDataByRRtype` + `AddCombinerDataNG`:

```go
func (zd *ZoneData) ReplaceCombinerDataByRRtype(senderID, owner string, rrtype uint16, newRRs []dns.RR) (applied []string, removed []string, changed bool, err error)
```

Logic:
1. Get the agent's existing contributions for this owner/rrtype
2. Diff old vs new to determine what's added and removed
3. If no diff → return `changed=false` (idempotent)
4. Replace the agent's contribution entry entirely
5. Call `rebuildCombinerData()` + `PersistContributions` + `CombineWithLocalChanges`
6. Return lists of added/removed RR strings for confirmation

### 4. Handle Operations in `CombinerProcessUpdate` — combiner_chunk.go:159

At the top of `CombinerProcessUpdate`, check if `req.Operations` is non-empty. If so, process each operation:

```go
if len(req.Operations) > 0 {
    return combinerProcessOperations(req, protectedNamespaces)
}
// ... existing Records path unchanged
```

New `combinerProcessOperations` function:
- **`replace`**: Call `ReplaceCombinerDataByRRtype` for the specified owner (zone apex) + rrtype
- **`add`**: Convert to `AddCombinerDataNG` call (same as current ClassINET path)
- **`delete`**: Convert to `RemoveCombinerDataNG` call (same as current ClassNONE path)

The owner for replace operations is always the zone apex (DNSKEYs live at apex). Extract from `req.Zone`.

### 5. Extract Operations in `ParseAgentMsgNotify` — combiner_chunk.go:113

Add Operations to the anonymous struct for JSON parsing:
```go
var msg struct {
    OriginatorID string              `json:"OriginatorID"`
    Zone         string              `json:"Zone"`
    Records      map[string][]string `json:"Records"`
    Operations   []core.RROperation  `json:"Operations"`  // NEW
    Time         time.Time           `json:"Time"`
}
```

Pass through to `CombinerSyncRequest`:
```go
return &CombinerSyncRequest{
    ...
    Operations: msg.Operations,
}
```

### 6. `ConvertZoneUpdateToSyncRequest` — combiner_chunk.go:675

Also pass Operations through here (used by in-process `SendToCombiner` path):
```go
func ConvertZoneUpdateToSyncRequest(update *ZoneUpdate, ...) *CombinerSyncRequest {
    ...
    req := &CombinerSyncRequest{
        ...
        Records: records,
    }
    if len(update.Operations) > 0 {
        req.Operations = update.Operations
    }
    return req
}
```

### 7. `isNoOpOperations` — combiner_chunk.go

New function alongside existing `isNoOpUpdate`:

```go
func isNoOpOperations(zd *ZoneData, senderID string, ops []core.RROperation) bool
```

For each operation:
- **`replace`**: Get `AgentContributions[senderID][zonename][rrtype]`. Parse all RRs in op.Records. Compare sets using `dns.IsDuplicate`. Same length + all match = no-op. Empty replacement + no existing = no-op.
- **`add`**: Each RR already exists in contributions or live zone (reuse `rrExistsInZone`).
- **`delete`**: Each RR is already absent from contributions and live zone.

If any operation would cause a change, return false.

## Files Modified

| File | Change |
|------|--------|
| `combiner_chunk.go` | Add `Operations` to `CombinerSyncRequest`, `ParseAgentMsgNotify`, `CombinerProcessUpdate`, `ConvertZoneUpdateToSyncRequest`, new `isNoOpOperations` + `combinerProcessOperations` |
| `combiner_msg_handler.go` | Pass `msg.Operations` to `CombinerSyncRequest`, branch `isNoOpUpdate`/`isNoOpOperations` |
| `combiner_utils.go` | New `ReplaceCombinerDataByRRtype` function |

~120 lines of new/changed code across 3 files. Low-medium risk — follows existing patterns.

## Verification

1. `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
2. End-to-end: Agent A sends DNSKEY replace → Agent B receives and processes locally → Agent B forwards to combiner → combiner replaces Agent A's DNSKEY contributions → old keys removed, new keys set → combiner rebuilds zone data.
