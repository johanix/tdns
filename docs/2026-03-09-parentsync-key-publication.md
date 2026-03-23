# Parent Sync: SIG(0) KEY Publication + CLI

**Date**: 2026-03-09 (updated 2026-03-11)
**Status**: Phase 3b complete, Phase 3c complete
**Prerequisite**: Phase 1 (HSYNC3+HSYNCPARAM) DONE.
Phase 3a (leader election) complete.

## Context

Phase 3a (leader election) is complete. The elected leader
is the only agent that sends DNS UPDATE to the parent.
Before the leader can send SIG(0)-signed UPDATEs, the KEY
record must be published.

All of this is gated on HSYNCPARAM `parentsync=agent` (MP
zones) or the `delegation-sync-child` config option (non-MP
zones). If parentsync is not set (defaults to "owner"), no
leader election, no KEY publication, and no DNS UPDATEs
happen.

The gating chain:
1. `SetupZoneSync` (`zone_utils.go`) reads HSYNCPARAM. Only
   if `GetParentSync() == HsyncParentSyncAgent` does it set
   `OptDelSyncChild = true`.
2. Leader election (`parseconfig.go`) is gated on
   `OptDelSyncChild`.
3. DDNS sending (`delegation_sync.go`) is gated on
   `OptDelSyncChild` + `IsLeader`.
4. KEY publication (`DelegationSyncSetup`) is gated on
   `OptDelSyncChild`.

## Two Publication Models

### 1. RFC 8078 (zone apex KEY)

Works when the parent zone is signed (most are). The KEY RR
is published at the child zone apex.

- **Non-MP zones** (`OptDelSyncChild`): Agent publishes KEY
  directly via `Sig0KeyPreparation` + `PublishKeyRRs`
  (already exists).
- **MP zones** (`HSYNCPARAM parentsync=agent`): Agent sends
  REPLACE UPDATE with KEY to the combiner. The combiner
  publishes it at the apex.

### 2. RFC 9615 (_signal. KEY)

Additional discovery path. KEY published at
`_sig0key.<childzone>._signal.<child-ns>`. The agent
**cannot** publish this (doesn't control the NS operator's
zone). Agent can only report what needs to be published and
check if it has been.

## What This Phase Does

1. **Non-MP zones**: Existing `Sig0KeyPreparation` already
   handles apex KEY — no new code needed.
2. **MP zones**: Agent sends KEY as REPLACE operation to
   combiner via `EnqueueForCombiner`.
3. **RFC 9615 status check**: For each child NS, query
   `_sig0key.<zone>._signal.<ns>` via IMR to check
   publication.
4. **CLI `agent parentsync status --zone <zone>`**: Shows
   leader, KEY, apex publication, _signal publication per NS.
5. **CLI `agent parentsync election --force --zone <zone>`**:
   Triggers forced re-election.

## Design

### Owner Name Convention (RFC 9615-style)

Per RFC 9615 pattern
`<purpose>.<zone>._signal.<nameserver>`:

```
_sig0key.example.com._signal.ns1.netnod.se.
_sig0key.example.com._signal.ns1.cloudflare.com.
```

The child zone's own NS records determine the nameserver
names. For each NS in the child zone's NS RRset, the agent
constructs the expected owner name and queries the IMR to
check whether the KEY is published.

### KEY Publication Check (not publication itself)

The agent **cannot** publish the KEY at `_signal.<ns>` — the
subtree is in the nameserver operator's zone, not the
agent's. The agent only:

1. Ensures a SIG(0) keypair exists locally (reuse
   `Sig0KeyPreparation`)
2. Reads the child zone's NS RRset to get nameserver names
3. For each NS, computes
   `_sig0key.<childzone>._signal.<ns>`
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

Computed on demand by `GetParentSyncStatus()` — no caching
needed.

### CLI Commands

#### `agent parentsync status --zone <zone>`

CLI sends
`AgentMgmtPost{Command: "parentsync-status", Zone: zone}` →
agent API handler.

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

The KEY RDATA line gives the operator what they need to
publish the record out-of-band.

#### `agent parentsync election --force --zone <zone>`

CLI sends
`AgentMgmtPost{Command: "parentsync-election", Zone: zone}`
→ agent API handler.

Handler calls `lem.StartElection(zone, peers)` and returns
confirmation.

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

`Sig0KeyOwnerName(zone, nameserver string) string` — computes
`_sig0key.<zone>._signal.<ns>`.

`GetParentSyncStatus(zone, zd, kdb, imr)` — on-demand status
computation:
1. Get leader + term from `LeaderElection`
2. Get SIG(0) key from `kdb.GetSig0Keys` (using DSYNC update
   target name)
3. Check if KEY is published at zone apex
   (`zd.GetOwner(zd.ZoneName)` → KEY RRtype)
4. Get child NS names from apex NS RRset
5. For each NS, compute `_sig0key.<zone>._signal.<ns>`,
   query IMR for KEY
6. Return populated `ParentSyncStatus`

### Step 2: Add `PublishKeyToCombiner` (~30 lines)

In `parentsync_leader.go`. For MP zones: send KEY as REPLACE
operation to combiner via `EnqueueForCombiner`.

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

The combiner already handles `"replace"` operations
(`combiner_msg_handler.go:166`).

### Step 3: Wire KEY publication into OnFirstLoad (`parseconfig.go`)

In the existing OnFirstLoad callback for
`OptDelSyncChild || OptMultiProvider`:
- Non-MP zones: existing `Sig0KeyPreparation` +
  `PublishKeyRRs` already handles apex KEY — no change
  needed.
- MP zones: after `Sig0KeyPreparation`, call
  `PublishKeyToCombiner` to send KEY to combiner.

### Step 4: Add API handler cases in `apihandler_agent.go` (~30 lines)

In the `APIagent` switch:
- `"parentsync-status"`: call `GetParentSyncStatus`, return
  via `resp.Data`
- `"parentsync-election"`: call `lem.StartElection`, return
  confirmation via `resp.Msg`

### Step 5: New file `cli/parentsync_cmds.go` (~120 lines)

Two subcommands under `agent parentsync`:
- `status --zone <zone>`: POST
  `{Command: "parentsync-status", Zone: zone}`, format and
  print `ParentSyncStatus` from `amr.Data`
- `election --force --zone <zone>`: POST
  `{Command: "parentsync-election", Zone: zone}`, print
  confirmation

Uses `SendAgentMgmtCmd` pattern from
`cli/agent_cmds.go:350`.

## Files Modified

| File | Action | Est. Lines |
|------|--------|-----------|
| `parentsync_leader.go` | Add ParentSyncStatus, GetParentSyncStatus, Sig0KeyOwnerName, PublishKeyToCombiner | ~130 |
| `cli/parentsync_cmds.go` | **NEW** — CLI commands (status + election) | ~120 |
| `apihandler_agent.go` | Add parentsync-status and parentsync-election cases | ~30 |
| `parseconfig.go` | Wire PublishKeyToCombiner for MP zones in OnFirstLoad | ~10 |

## Verification

1. Build: `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
2. `tdns-cliv2 agent parentsync status --zone example.com.`
   → shows leader, KEY, apex publication, _signal status
   per NS
3. `tdns-cliv2 agent parentsync election --force --zone example.com.`
   → triggers election, returns confirmation
4. Single agent: status shows self as leader, KEY info, apex
   published/not, "NOT PUBLISHED" for _signal per NS
5. MP zone: KEY sent to combiner via REPLACE operation
   (check combiner log for received KEY)

---

# Phase 3c: CONFIG Message Type + SIG(0) Private Key Distribution

**Status**: Implemented (2026-03-20)
**Prerequisite**: Phase 3b complete

**Implemented**: onLeaderElected callback with 4-step key
acquisition flow (check local, ask peers via RFI CONFIG
sig0key, generate if none, publish). RFI CONFIG message
type with sig0key subtype. importSig0KeyFromPeer in
parentsync_leader.go. GetSig0KeyRaw in keystore.go.
Authorization check (upstream/downstream peer validation).
CLI support via "agent debug rfi --rfi CONFIG --subtype
sig0key".

## Context

After a leader election, the new leader may not have the
SIG(0) private key. All agents share the same SIG(0) identity
(same KEY RR at the apex), but only the agent that generated
the keypair has the private key. The leader must obtain it
from peers.

## Design Decisions

1. **New message type constant `CONFIG`** — for "sensitive
   configuration data NOT intended for publication" (vs SYNC
   for DNS records). First subtype: `sig0-privkey`. Future
   subtypes: `tsig-key`, `endpoint-info`, `acl`, etc.
2. **Leader initiates** — after election, leader checks local
   keystore. If no key, sends RFI CONFIG to all peers.
3. **All peers must respond** — "have-key" with encrypted
   private key, or "no-key". No silent waiting.
4. **No peer has key** → leader generates new keypair +
   bootstraps with parent via `BootstrapSig0KeyWithParent`.
5. **Key verification** — leader verifies received key is
   "working" via KeyState EDNS(0) inquiry
   (`UpdateKeyState`).
6. **Organic spreading** — as leadership changes, each new
   leader requests the key, so eventually all agents have it.
7. **CHUNK encryption** — private key material encrypted via
   existing `SecureWrapper` (FormatJWT) during transport.

## Transport

RFI CONFIG uses the **synchronous agent-to-agent RFI
pattern** (like UPSTREAM/DOWNSTREAM/AUDIT in
`hsyncengine.go`). The peer responds directly in
`AgentMsgResponse.RfiResponse`. This is simpler than the
async pattern (KEYSTATE/EDITS) and appropriate because:
- `sendRfiToAgent` is already synchronous (returns
  `*AgentMsgResponse`)
- Election broadcasts already use this pattern
  (`broadcastElectToZone`)
- CHUNK/JWT encryption is applied automatically by the
  transport layer
- No new channel, handler registration, or router changes
  needed

## RFI CONFIG Convention

Request (in `AgentMsgPost.Records`):
```
Records: {"config-type": ["sig0-privkey"], "zone": ["example.com."]}
```

Response (in `RfiResponse[agentId].ConfigData`):
```go
// Peer has key:
ConfigData: {"config-type": "sig0-privkey", "status": "have-key",
             "private-key": "<PEM>", "algorithm": "15", "key-id": "12345",
             "key-rr": "<KEY RR string>"}

// Peer has no key:
ConfigData: {"config-type": "sig0-privkey", "status": "no-key"}
```

## Flow: Leader Key Acquisition

```
1. Election completes → onLeaderElected callback fires (if this agent won)
   ↓
2. Check local keystore: kdb.GetSig0Keys(keyName, Sig0StateActive)
   ↓
3a. Key found locally → done (proceed to DDNS when needed)
3b. No local key → send RFI CONFIG to all peers concurrently
   ↓
4. Collect all responses (with 15s timeout per peer)
   ↓
5a. Peer has key → import into local keystore via Sig0KeyMgmt("add")
    → verify via kdb.UpdateKeyState (KeyState EDNS(0) inquiry)
    → if parent says "unknown": try next peer or generate new
5b. No peer has key → BootstrapSig0KeyWithParent (generate + send UPDATE)
   ↓
6. Key ready → publish KEY (apex/combiner) if not already published
```

## Existing Code to Reuse

| Code | File | Purpose |
|------|------|---------|
| `sendRfiToAgent` | `hsyncengine.go:907` | Send RFI to a peer agent (synchronous) |
| `broadcastElectToZone` | `parentsync_leader.go:392` | Iterate all zone agents, skip self |
| `GetZoneAgentData` | `hsyncengine.go` | Get all agents for a zone |
| `GetSig0Keys` | `keystore.go:520` | Retrieve SIG(0) keys from keystore |
| `Sig0KeyMgmt("add")` | `keystore.go:71` | Import key into keystore |
| `PrepareKeyCache` | `readkey.go:230` | Parse private+public key into PrivateKeyCache |
| `BootstrapSig0KeyWithParent` | `ops_key.go:155` | Generate key + send UPDATE to parent |
| `UpdateKeyState` | `keybootstrapper.go:276` | KeyState EDNS(0) inquiry to verify key |
| `DsyncUpdateTargetName` | `ops_dsync.go:240` | Compute DSYNC target name from config |

## Implementation Steps

### Step 1: Add `AgentMsgConfig` constant + `ConfigData` to `RfiData` (~10 lines)

**`core/messages.go`**: Add
`AgentMsgConfig AgentMsg = "config"` and `AgentMsgToString`
entry. Add `ConfigData map[string]string` field to
`core.RfiData`.

**`agent_structs.go`**: Add `ConfigData map[string]string`
field to local `RfiData`.

### Step 2: Add `case "CONFIG":` RFI handler in `hsyncengine.go` (~35 lines)

In the `AgentMsgRfi` switch (after ELECT-* cases):
1. Extract `config-type` from
   `ampp.Records["config-type"]`
2. For `"sig0-privkey"`: compute key name via
   `DsyncUpdateTargetName`, check local keystore
3. If key found: respond with `ConfigData` containing PEM
   key, algorithm, key-id, key-rr
4. If no key: respond with
   `ConfigData{"status": "no-key"}`

### Step 3: Add `onLeaderElected` callback to `LeaderElectionManager` (~10 lines)

**`parentsync_leader.go`**: Add
`onLeaderElected func(zone ZoneName)` field. Call it (in
goroutine) from `StartElection` (single-agent path) and
`finalizeElection` (multi-agent, when `isUs`).

**`main_initfuncs.go`**: Pass callback to
`NewLeaderElectionManager` that calls `AcquireSig0Key`.

### Step 4: Implement `AcquireSig0Key` in `parentsync_leader.go` (~70 lines)

1. Check local keystore → if found, return
2. Get peers via `GetZoneAgentData`
3. Send RFI CONFIG to each peer concurrently
4. Collect responses; find first "have-key"
5. Import key via `Sig0KeyMgmt("add")`
6. Verify via `UpdateKeyState`
7. If no peer has it: `BootstrapSig0KeyWithParent`

## Files Modified

| File | Action | Est. Lines |
|------|--------|-----------|
| `core/messages.go` | Add `AgentMsgConfig`, `ConfigData` to `RfiData` | ~5 |
| `agent_structs.go` | Add `ConfigData` to local `RfiData` | ~2 |
| `hsyncengine.go` | Add `case "CONFIG":` in RFI switch | ~35 |
| `parentsync_leader.go` | Add `onLeaderElected` field, `AcquireSig0Key` | ~80 |
| `main_initfuncs.go` | Wire onLeaderElected callback | ~10 |

## Verification

1. Build: `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
2. Single agent: after election, leader checks local key →
   finds it → no RFI sent
3. `agent parentsync status --zone example.com.` → shows
   leader + key info
4. Log inspection: on election, look for "acquiring SIG(0)
   key" log messages
5. Future multi-agent test: new leader without key → RFI
   CONFIG → peer responds → leader imports + verifies
