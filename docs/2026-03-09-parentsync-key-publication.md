# Parent Sync: SIG(0) KEY Publication + CLI

**Date**: 2026-03-09
**Status**: Planning
**Prerequisite**: Phase 3a (leader election) complete

## Context

Phase 3a (leader election) is complete. The elected leader is the only agent that sends DNS UPDATE to the parent. Before the leader can send SIG(0)-signed UPDATEs, the KEY record must be published.

All of this is gated on HSYNCPARAM `parentsync != none` (MP zones) or the `delegation-sync-child` config option (non-MP zones). If parentsync is not set, no leader election, no KEY publication, and no DNS UPDATEs happen.

The gating chain:
1. `SetupZoneSync` (`zone_utils.go:1016`) reads HSYNCPARAM. Only if `GetParentSync() != HsyncParentSyncNone` does it set `OptDelSyncChild = true`.
2. Leader election (`parseconfig.go`) is gated on `OptDelSyncChild`.
3. DDNS sending (`delegation_sync.go`) is gated on `OptDelSyncChild` + `IsLeader`.
4. KEY publication (`DelegationSyncSetup`) is gated on `OptDelSyncChild`.

## Two Publication Models

### 1. RFC 8078 (zone apex KEY)

Works when the parent zone is signed (most are). The KEY RR is published at the child zone apex.

- **Non-MP zones** (`OptDelSyncChild`): Agent publishes KEY directly via `Sig0KeyPreparation` + `PublishKeyRRs` (already exists).
- **MP zones** (`HSYNCPARAM parentsync != none`): Agent sends REPLACE UPDATE with KEY to the combiner. The combiner publishes it at the apex.

### 2. RFC 9615 (_signal. KEY)

Additional discovery path. KEY published at `_sig0key.<childzone>._signal.<child-ns>`. The agent **cannot** publish this (doesn't control the NS operator's zone). Agent can only report what needs to be published and check if it has been.

## What This Phase Does

1. **Non-MP zones**: Existing `Sig0KeyPreparation` already handles apex KEY — no new code needed.
2. **MP zones**: Agent sends KEY as REPLACE operation to combiner via `EnqueueForCombiner`.
3. **RFC 9615 status check**: For each child NS, query `_sig0key.<zone>._signal.<ns>` via IMR to check publication.
4. **CLI `agent parentsync status --zone <zone>`**: Shows leader, KEY, apex publication, _signal publication per NS.
5. **CLI `agent parentsync election --force --zone <zone>`**: Triggers forced re-election.

## Design

### Owner Name Convention (RFC 9615-style)

Per RFC 9615 pattern `<purpose>.<zone>._signal.<nameserver>`:

```
_sig0key.example.com._signal.ns1.netnod.se.
_sig0key.example.com._signal.ns1.cloudflare.com.
```

The child zone's own NS records determine the nameserver names. For each NS in the child zone's NS RRset, the agent constructs the expected owner name and queries the IMR to check whether the KEY is published.

### KEY Publication Check (not publication itself)

The agent **cannot** publish the KEY at `_signal.<ns>` — the subtree is in the nameserver operator's zone, not the agent's. The agent only:

1. Ensures a SIG(0) keypair exists locally (reuse `Sig0KeyPreparation`)
2. Reads the child zone's NS RRset to get nameserver names
3. For each NS, computes `_sig0key.<childzone>._signal.<ns>`
4. Queries IMR for KEY at each owner name
5. Reports: published / not published / query error

### Data Structure

```go
type ParentSyncStatus struct {
    Zone           ZoneName
    Leader         AgentId
    LeaderExpiry   time.Time
    ElectionTerm   uint64
    IsLeader       bool
    KeyAlgorithm   string
    KeyID          uint16
    KeyRR          string              // KEY RR RDATA for out-of-band publication
    ApexPublished  bool                // KEY published at zone apex?
    ChildNS        []string            // child zone NS names
    KeyPublication map[string]bool     // _sig0key owner → published?
    LastChecked    time.Time
}
```

Computed on demand by `GetParentSyncStatus()` — no caching needed.

### CLI Commands

#### `agent parentsync status --zone <zone>`

CLI sends `AgentMgmtPost{Command: "parentsync-status", Zone: zone}` → agent API handler.

Example output:
```
Parent Sync Status for example.com.
  Leader:          netnod  (self, expires in 4m12s)
  Election term:   3
  SIG(0) KEY:      ED25519 (key-id 12345)
  KEY RDATA:       0 3 15 l02Hu...==
  Apex KEY:        PUBLISHED
  _signal KEY Publication (child NS):
    _sig0key.example.com._signal.ns1.netnod.se.       NOT PUBLISHED
    _sig0key.example.com._signal.ns2.netnod.se.       NOT PUBLISHED
    _sig0key.example.com._signal.ns1.cloudflare.com.  PUBLISHED
```

The KEY RDATA line gives the operator what they need to publish the record out-of-band.

#### `agent parentsync election --force --zone <zone>`

CLI sends `AgentMgmtPost{Command: "parentsync-election", Zone: zone}` → agent API handler.

Handler calls `lem.StartElection(zone, peers)` and returns confirmation.

### Existing Code to Reuse

| Code | File | Purpose |
|------|------|---------|
| `Sig0KeyPreparation` | `delegation_sync.go:270` | Generate/check SIG(0) key |
| `ParentSig0KeyPrep` | `delegation_sync.go:236` | Wrapper with config algorithm |
| `PublishKeyRRs` | `ops_key.go:17` | Publish KEY to local zone |
| `EnqueueForCombiner` | `hsync_transport.go:1478` | Reliable delivery to combiner |
| `RROperation` | `core/messages.go:88` | Operation struct with "replace" |
| `zd.GetOwner(zd.ZoneName)` | `zonedata.go` | Child zone NS names |
| `SendAgentMgmtCmd` | `cli/agent_cmds.go:350` | CLI→agent API pattern |
| `APIagent` handler | `apihandler_agent.go:165` | Command dispatch switch |
| `GetLeader/IsLeader` | `parentsync_leader.go` | Leader election state |
| `GetSig0Keys` | `sig0_utils.go` | Retrieve active SIG(0) keys |

## Implementation Steps

### Step 1: Add `ParentSyncStatus` type + `GetParentSyncStatus` + helpers (~100 lines)

In `parentsync_leader.go`:

`Sig0KeyOwnerName(zone, nameserver string) string` — computes `_sig0key.<zone>._signal.<ns>`.

`GetParentSyncStatus(zone, zd, kdb, imr)` — on-demand status computation:
1. Get leader + term from `LeaderElection`
2. Get SIG(0) key from `kdb.GetSig0Keys` (using DSYNC update target name)
3. Check if KEY is published at zone apex (`zd.GetOwner(zd.ZoneName)` → KEY RRtype)
4. Get child NS names from apex NS RRset
5. For each NS, compute `_sig0key.<zone>._signal.<ns>`, query IMR for KEY
6. Return populated `ParentSyncStatus`

### Step 2: Add `PublishKeyToCombiner` (~30 lines)

In `parentsync_leader.go`. For MP zones: send KEY as REPLACE operation to combiner via `EnqueueForCombiner`.

```go
func PublishKeyToCombiner(zone ZoneName, keyRR dns.RR, tm *TransportManager) (string, error) {
    update := &ZoneUpdate{
        Zone: string(zone),
        Operations: []core.RROperation{{
            Operation: "replace",
            RRtype:    "KEY",
            Records:   []string{keyRR.String()},
        }},
    }
    return tm.EnqueueForCombiner(zone, update, "")
}
```

The combiner already handles `"replace"` operations (`combiner_msg_handler.go:166`).

### Step 3: Wire KEY publication into OnFirstLoad (`parseconfig.go`)

In the existing OnFirstLoad callback for `OptDelSyncChild || OptMultiProvider`:
- Non-MP zones: existing `Sig0KeyPreparation` + `PublishKeyRRs` already handles apex KEY — no change needed.
- MP zones: after `Sig0KeyPreparation`, call `PublishKeyToCombiner` to send KEY to combiner.

### Step 4: Add API handler cases in `apihandler_agent.go` (~30 lines)

In the `APIagent` switch:
- `"parentsync-status"`: call `GetParentSyncStatus`, return via `resp.Data`
- `"parentsync-election"`: call `lem.StartElection`, return confirmation via `resp.Msg`

### Step 5: New file `cli/parentsync_cmds.go` (~120 lines)

Two subcommands under `agent parentsync`:
- `status --zone <zone>`: POST `{Command: "parentsync-status", Zone: zone}`, format and print `ParentSyncStatus` from `amr.Data`
- `election --force --zone <zone>`: POST `{Command: "parentsync-election", Zone: zone}`, print confirmation

Uses `SendAgentMgmtCmd` pattern from `cli/agent_cmds.go:350`.

## Files Modified

| File | Action | Est. Lines |
|------|--------|-----------|
| `parentsync_leader.go` | Add ParentSyncStatus, GetParentSyncStatus, Sig0KeyOwnerName, PublishKeyToCombiner | ~130 |
| `cli/parentsync_cmds.go` | **NEW** — CLI commands (status + election) | ~120 |
| `apihandler_agent.go` | Add parentsync-status and parentsync-election cases | ~30 |
| `parseconfig.go` | Wire PublishKeyToCombiner for MP zones in OnFirstLoad | ~10 |

## Verification

1. Build: `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
2. `tdns-cliv2 agent parentsync status --zone example.com.` → shows leader, KEY, apex publication, _signal status per NS
3. `tdns-cliv2 agent parentsync election --force --zone example.com.` → triggers election, returns confirmation
4. Single agent: status shows self as leader, KEY info, apex published/not, "NOT PUBLISHED" for _signal per NS
5. MP zone: KEY sent to combiner via REPLACE operation (check combiner log for received KEY)
