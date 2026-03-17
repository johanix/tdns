# Parent Sync Implementation Plan

**Date:** 2026-03-18
**Status:** Plan (revised)
**Depends on:** SIG(0) KEY Publication (DNS-147/148/149),
  Delegation Sync Refresh (DNS-136 through DNS-143)
**Architecture:** See `2026-03-17-parent-sync-who-sends-the-update.md`

## Context

The combiner is the source of truth for NS and DNSKEY
records in multi-provider zones. When these change, the
parent zone's delegation data (NS, DS) must be updated.
Currently nobody triggers this — the combiner applies
changes but never signals that parent-relevant data has
changed.

Decision: **combiner detects changes, agent sends the
UPDATE** (Option B from the architecture discussion).
This keeps the combiner simple while leveraging the
agent's existing parent sync infrastructure.

## What the Combiner Watches For

Two types of changes require parent synchronization:

1. **NS RRset changes** — nameservers added or removed
2. **KSK changes** — DNSKEY records with flags=257
   (SEP bit) added or removed

## Parent Sync Mechanisms

The parent may support UPDATE, NOTIFY, or both. When
both are supported, both are used (belt and suspenders).

| Change | UPDATE path (agent) | NOTIFY path |
|--------|---------------------|-------------|
| NS     | Agent sends UPDATE with NS data to parent | Combiner publishes CSYNC, agent sends NOTIFY(CSYNC) |
| KSK    | Agent sends UPDATE with DS data to parent | Combiner publishes CDS, agent sends NOTIFY(CDS) |

For the NOTIFY path, the combiner publishes CDS/CSYNC
in the customer zone **before** notifying the agent.
The combiner does this "blindly" — it doesn't know if
the local provider is the current leader. This is
correct: all combiners should publish CDS/CSYNC. Only
the leader agent will act on the notification.

## Constraints

- Combiner only talks to its own provider's agent(s).
  It has no knowledge of remote agents/providers.
- Only out-of-bailiwick NS names are supported (no
  glue records needed).
- Replace mode (`CreateChildReplaceUpdate`) is used
  for UPDATEs — atomic replacement, no delta tracking.
- CSYNC is only useful if the zone is signed. The
  combiner knows this via the HSYNCPARAM `signers=`
  field (helper: `HSYNCPARAM.GetSigners()`).

## Steps

### Step 1: Extend delegation sync pipeline for DS

The existing delegation sync pipeline handles NS, A,
and AAAA records. It must be extended to also handle
DS records. This benefits all callers — zone file
reload, zone transfer, DNS UPDATE, and the new
combiner notification path.

#### 1a: DelegationSyncStatus — add DS fields

**File:** `v2/structs.go`

Add to `DelegationSyncStatus`:

```go
DSAdds    []dns.RR
DSRemoves []dns.RR
NewDS     []dns.RR // Complete DS RRset for replace mode
```

#### 1b: AnalyseZoneDelegation — add DS comparison

**File:** `v2/delegation_utils.go`

Extend `AnalyseZoneDelegation` to also query the parent
for DS records at the child delegation point, compare
against local DS data (derived from CDS or DNSKEY via
`ToDS(dns.SHA256)`), and populate the new DS fields in
`DelegationSyncStatus`.

#### 1c: CreateChildReplaceUpdate — add DS parameter

**File:** `v2/childsync_utils.go`

Add `newDS []dns.RR` parameter. In replace mode, delete
all existing DS records for the child zone and add the
new DS records, alongside the existing NS/A/AAAA logic.

#### 1d: SyncZoneDelegationViaUpdate — include DS

**File:** `v2/delegation_sync.go`

Pass `syncstate.NewDS` to `CreateChildReplaceUpdate`.
In delta mode, include `DSAdds`/`DSRemoves` in the
UPDATE message.

#### 1e: SyncZoneDelegationViaNotify — add NOTIFY(CDS)

**File:** `v2/delegation_sync.go`

Currently sends only NOTIFY(CSYNC) for NS changes.
Extend to also send NOTIFY(CDS) when DS records have
changed. CDS is already published by the zone owner
(combiner in MP mode, or directly in single-provider);
the NOTIFY tells the parent to fetch and process it.

#### 1f: Update existing callers

**Files:** `v2/delegation_utils.go`, `v2/zone_updater.go`

- `DelegationDataChangedNG` (zone reload) — populate
  DS fields when DNSKEY changes detected
- `DnskeysChanged` — already detects DNSKEY changes,
  extend to compute DS diff and populate DS fields
- `ZoneUpdateChangesDelegationDataNG` (UPDATE handler)
  — same extension

All existing callers that don't touch DNSKEYs will
simply have empty DS diffs, which flow through as
no-ops.

### Step 2: Generic STATUS-UPDATE message type

**File:** `v2/core/messages.go`

Instead of a purpose-specific `delegation-notify`
message type, add a generic STATUS-UPDATE that can
carry different subtypes. This follows the precedent
of consolidating UPSTREAM/DOWNSTREAM/SIG0KEY into
CONFIG — less wiring overhead, reusable for future
status notifications.

Add message type constant:

```go
AgentMsgStatusUpdate AgentMsg = "status-update"
```

Add payload struct:

```go
type StatusUpdatePost struct {
    Zone    string   `json:"zone"`
    SubType string   `json:"subtype"`
    // Subtype-specific data
    NSRecords []string `json:"ns_records,omitempty"`
    DSRecords []string `json:"ds_records,omitempty"`
    Result    string   `json:"result,omitempty"`
    Msg       string   `json:"msg,omitempty"`
}
```

Add to `AgentMsgToString` map.

Subtypes used in this plan:

- `"ns-changed"` — combiner → agent: NS RRset has
  changed, agent should verify and sync with parent
- `"ksk-changed"` — combiner → agent: KSK (DNSKEY
  with SEP bit) has changed, agent should verify and
  sync with parent
- `"parentsync-done"` — agent → agent: leader informs
  peers that parent sync completed

The combiner always knows which specific change
triggered the notification (NS or KSK), so we
propagate that specificity. Our agent implementation
may handle `"ns-changed"` and `"ksk-changed"`
identically (both enqueue EXPLICIT-SYNC-DELEGATION),
but another implementation may choose to handle them
differently.

This replaces both the `AgentMsgDelegationNotify`
message type from the original plan AND the semantic
overloading of SYNC for parentsync-done notifications.

### Step 3: Combiner — detect NS and KSK changes

**File:** `v2/combiner_chunk.go`

Add a helper that inspects `CombinerSyncResponse` for
parent-relevant changes:

```go
func detectDelegationChanges(
    resp *CombinerSyncResponse,
) (nsChanged, kskChanged bool) {
    for _, rr := range append(
        resp.AppliedRecords,
        resp.RemovedRecords...,
    ) {
        parsed, err := dns.NewRR(rr)
        if err != nil {
            continue
        }
        switch parsed.Header().Rrtype {
        case dns.TypeNS:
            nsChanged = true
        case dns.TypeDNSKEY:
            if dk, ok := parsed.(*dns.DNSKEY); ok {
                if dk.Flags&dns.SEP != 0 {
                    kskChanged = true
                }
            }
        }
    }
    return
}
```

### Step 4: Combiner — publish CDS/CSYNC, notify agent

**File:** `v2/combiner_chunk.go`

At the two hook points after existing post-processing
(operations path around line 309 and legacy path around
line 503), add:

```go
nsChanged, kskChanged := detectDelegationChanges(resp)
if nsChanged || kskChanged {
    go combinerNotifyDelegationChange(
        tm, req.SenderID, zonename, zd,
        nsChanged, kskChanged)
}
```

**New function** `combinerNotifyDelegationChange`:

1. Check if zone is signed (via HSYNCPARAM
   `GetSigners()` — non-empty means signed).

2. If zone is signed and NS changed:
   publish CSYNC via `zd.PublishCsyncRR()` (existing
   function in `ops_csync.go`).

3. If KSK changed:
   publish CDS via `zd.PublishCdsRRs()` (existing
   function in `ops_cds.go`).

4. Build `StatusUpdatePost` with:
   - Zone name
   - SubType `"ns-changed"` or `"ksk-changed"`
     (one notification per change type; if both
     changed, send two separate notifications)
   - Current NS records (from `getAgentNSTargets()`
     or `zd.AgentContributions`)
   - Current DS records if KSK changed (synthesize
     from DNSKEY via `dnskey.ToDS(dns.SHA256)`)

5. Send notification to the local agent via the new
   transport method (Step 5). The combiner sends to
   the agent that delivered the update (the
   `deliveredBy` peer from PeerRegistry).

Note: the combiner publishes CDS/CSYNC "blindly" — it
doesn't know if the local provider is the current
leader. This is correct: all combiners should publish
these records. Only the leader agent will act on the
notification.

### Step 5: Transport — status-update method

**File:** `v2/agent/transport/dns.go`

Add `SendStatusUpdate()` method on `DNSTransport`,
modeled on the existing `Confirm()` (fire-and-forget
NOTIFY(CHUNK)):

- Takes: peer, zone, statusUpdatePost
- Marshals payload as `StatusUpdatePost`
- Sends as NOTIFY(CHUNK) with message type
  `"status-update"`
- Does not wait for response (fire-and-forget)

This method is used by both the combiner (Step 4) and
the leader agent (Step 8) — same message type, different
subtypes.

### Step 6: Agent — handler for status-update

**File:** `v2/agent/transport/handlers.go`
**File:** `v2/agent/transport/router_init.go`

Add `HandleStatusUpdate` handler, register it in
**all three routers** — agent, combiner, and signer.
This makes STATUS-UPDATE bi-directional from the
start and prevents "unhandled message type" errors
if a STATUS-UPDATE reaches the wrong role.

#### Agent router — full handler

Handler dispatches on SubType:

**SubType "ns-changed" / "ksk-changed"** (from
combiner):

1. Parse `StatusUpdatePost` from payload.

2. Check leader election via `LeaderElectionManager`.

3. If NOT leader:
   - Log "delegation change noted, leader will handle"
   - Return (no action needed — the leader will inform
     peers via "parentsync-done" after syncing)

4. If IS leader:
   - Enqueue `EXPLICIT-SYNC-DELEGATION` to
     `DelegationSyncQ` — this runs the existing
     verify-then-sync path: `AnalyseZoneDelegation`
     queries the parent, compares all delegation data
     (NS, A, AAAA, DS), and only syncs if there is an
     actual delta

   No new DelegationSyncher command needed — the
   existing `EXPLICIT-SYNC-DELEGATION` does exactly
   what we want.

**SubType "parentsync-done"** (from leader agent):

1. Log the completion with zone and result
2. Do NOT apply any records — this is informational
3. Send confirmation back to the sender

#### Combiner and signer routers — stub handler

Log "received STATUS-UPDATE, no action" with zone
and subtype. Send acknowledgement response. These
roles do not act on status updates but having the
handler registered avoids unhandled message errors
and makes the message type usable in both directions
from the start.

### Step 7: Leader informs remote agents

**File:** `v2/delegation_sync.go`

After successful parent sync in the
`EXPLICIT-SYNC-DELEGATION` path (and also in
`SYNC-DELEGATION`), the leader agent sends a
STATUS-UPDATE to all remote agents:

```go
StatusUpdatePost{
    Zone:    zoneName,
    SubType: "parentsync-done",
    Result:  "success",
    Msg:     "NS+DS synced with parent",
}
```

Uses `DNSTransport.SendStatusUpdate()` (Step 5) to
each remote agent peer. Remote agents receive it via
`HandleStatusUpdate` (Step 6).

This replaces the original plan's semantic overloading
of SYNC with "parentsync-done" operations.

### Step 8: Post-bootstrap delegation verification

**File:** `v2/parentsync_bootstrap.go`

In `parentSyncAfterKeyPublication`, when
`KeyStateTrusted` is reached (both the immediate case
and the polling-success case):

- Enqueue `EXPLICIT-SYNC-DELEGATION` to
  `DelegationSyncQ`
- This runs `AnalyseZoneDelegation` which queries
  the parent for current delegation data (NS, A,
  AAAA, DS) and compares against local state
- Only syncs if there is an actual delta
- No proactive UPDATE if already in sync — this is
  important at scale (a TLD parent may have millions
  of delegations; unnecessary UPDATEs waste parent
  resources)

## Existing Code Reused

| Function | File | Purpose |
|----------|------|---------|
| `PublishCsyncRR()` | `v2/ops_csync.go` | Publish CSYNC in zone |
| `PublishCdsRRs()` | `v2/ops_cds.go` | Publish CDS from KSKs |
| `CreateChildReplaceUpdate()` | `v2/childsync_utils.go` | Build atomic replace UPDATE (extended for DS) |
| `AnalyseZoneDelegation()` | `v2/delegation_utils.go` | Query parent, compute diff (extended for DS) |
| `SyncZoneDelegation()` | `v2/delegation_sync.go` | Router: UPDATE or NOTIFY |
| `SyncZoneDelegationViaUpdate()` | `v2/delegation_sync.go` | Send UPDATE (extended for DS) |
| `SyncZoneDelegationViaNotify()` | `v2/delegation_sync.go` | Send NOTIFY (extended for CDS) |
| `BestSyncScheme()` | `v2/delegation_sync.go` | Determine UPDATE vs NOTIFY |
| `LookupDSYNCTarget()` | IMR | Discover parent DSYNC target |
| `DNSTransport.Confirm()` | `v2/agent/transport/dns.go` | Fire-and-forget pattern (model for SendStatusUpdate) |
| `getAgentNSTargets()` | `v2/combiner_chunk.go` | Get NS targets from contributions |
| `combinerResyncSignalKeys()` | `v2/combiner_chunk.go` | Existing NS change detection |
| `HSYNCPARAM.GetSigners()` | `v2/core/rr_hsyncparam.go` | Check if zone is signed |
| `LeaderElectionManager` | `v2/parentsync_leader.go` | Leader check |

## Files Modified

| File | Change |
|------|--------|
| `v2/structs.go` | `DSAdds`, `DSRemoves`, `NewDS` fields in `DelegationSyncStatus` |
| `v2/core/messages.go` | `AgentMsgStatusUpdate` + `StatusUpdatePost` struct |
| `v2/delegation_utils.go` | `AnalyseZoneDelegation` DS query + comparison; `DelegationDataChangedNG` and `DnskeysChanged` DS diff |
| `v2/childsync_utils.go` | `CreateChildReplaceUpdate` gains `newDS` parameter |
| `v2/delegation_sync.go` | `SyncZoneDelegationViaUpdate` passes DS; `SyncZoneDelegationViaNotify` sends NOTIFY(CDS); post-sync STATUS-UPDATE to peers |
| `v2/zone_updater.go` | `ZoneUpdateChangesDelegationDataNG` populates DS fields |
| `v2/combiner_chunk.go` | `detectDelegationChanges` + `combinerNotifyDelegationChange` + hooks |
| `v2/agent/transport/dns.go` | `SendStatusUpdate` method |
| `v2/agent/transport/handlers.go` | `HandleStatusUpdate` (dispatches on subtype) |
| `v2/agent/transport/router_init.go` | Register handler |
| `v2/parentsync_bootstrap.go` | Post-bootstrap verification trigger |

## Implementation Order

1. **Step 1:** Extend delegation sync pipeline for DS
   (foundation — benefits all callers)
2. **Step 2:** Generic STATUS-UPDATE message type
3. **Steps 3-4:** Combiner detection, CDS/CSYNC
   publish, notification send
4. **Steps 5-6:** Transport method and handlers
5. **Step 7:** Post-sync STATUS-UPDATE to peers
6. **Step 8:** Post-bootstrap verification
7. gofmt + build

Step 1 is independent and can be implemented and
tested on its own (existing callers gain DS support).
Steps 2-6 are the multi-provider notification chain.
Step 7 is cross-agent notification. Step 8 is
independent.

## Verification

Test on NetBSD VMs with two agents + combiner + parent
auth server:

1. Agent A wins election, bootstraps KEY with parent
2. Agent A sends NS change to combiner
3. Verify: combiner publishes CSYNC (if signed zone),
   sends STATUS-UPDATE(ns-changed) to Agent A
4. Verify: Agent A (leader) runs AnalyseZoneDelegation,
   finds delta, sends DNS UPDATE with NS+DS data AND
   NOTIFY(CSYNC) to parent
5. Verify: Agent A sends STATUS-UPDATE(parentsync-done)
   to Agent B
6. Agent B receives and logs completion
7. Test KSK change: publish new DNSKEY(257) via combiner
8. Verify: combiner publishes CDS, sends notification
9. Verify: Agent A queries parent, finds DS delta, sends
   UPDATE(DS) + NOTIFY(CDS) to parent
10. Test non-leader: Agent B receives ns-changed,
    does nothing, waits for leader's parentsync-done
11. Test post-bootstrap: after KEY trusted, agent runs
    AnalyseZoneDelegation — verify no UPDATE sent if
    already in sync
