# Agent-Driven Parent Delegation Synchronization

**Date**: 2026-03-09
**Status**: Planning

## Context

The TDNS multi-provider architecture needs agents to synchronize delegation data (NS, glue, DNSKEY/CDS) with the parent zone. The current HSYNC record conflates two distinct signal types in one RRset:

1. **Zone-wide policy** (NSmgmt, ParentSync, signing config) — must be consistent across all agents
2. **Per-agent details** (identity, endpoint, upstream, state) — naturally varies per agent

This creates consistency problems: if NSmgmt=OWNER in one RR and NSmgmt=AGENT in another, agents get mixed signals. `ValidateHsyncRRset` (`hsync_utils.go:466-484`) already checks for NSmgmt consistency at runtime, but this is a design flaw — the structure should prevent inconsistency.

### Design: Split into HSYNCPARAM + HSYNC

**HSYNCPARAM** — single RR, zone-wide policy from zone owner to all providers. SVCB-style extensible (key=value pairs). New keys can be added without wire format changes.

**HSYNC** — RRset with one RR per provider. Minimal static record with per-agent operational details.

### Key Design Decisions

- **Agents send to parent** (not combiner — keep combiner simple)
- **Dynamic leader election** for DDNS (random number, highest wins — sufficient for 2-3 agents)
- **Shared SIG(0) key** across all agents, distributed via existing encrypted CHUNK channel
- **No installed base** — wire format changes are fine
- **Identity is a label, not an FQDN** — customer-chosen tag ("netnod", "cloudflare") used as reference token. Discovery endpoint is a separate FQDN field. This decouples naming from discovery.
- **Sign moves to HSYNCPARAM** as `signers="provA,provB"` list — zone-wide, not per-agent
- **Coexistence**: HSYNC v1 and v2 are kept as-is. New HSYNC3+HSYNCPARAM coexist in the same zone files. Old code looks for HSYNC, new code looks for HSYNC3+HSYNCPARAM. No runtime switch.

### Field Classification

**HSYNCPARAM** (zone-wide, must be consistent):
- `nsmgmt` — owner/agent (was per-RR in HSYNC, required runtime consistency check)
- `parentsync` — owner/agent (who handles parent sync; mechanism comes from parent's DSYNC)
- `audit` — yes/no (was in HSYNC2 flags)
- `signers` — comma-separated list of agent labels that sign (replaces per-RR `Sign` field)

**HSYNC** (per-agent):
- `Label` — unqualified string tag, customer-chosen ("netnod", "cloudflare"). Reference token for Upstream and HSYNCPARAM signers.
- `Endpoint` — FQDN for agent discovery (URI, SVCB, JWK lookups). Only entered once per agent.
- `Upstream` — label of upstream provider, or "." for top of chain.
- `State` — on/off for per-agent onboarding/offboarding control.

## Phase 1: HSYNCPARAM + HSYNC Record Redesign

### 1a. HSYNC3 — per-agent record (static, minimal)

**New file**: `core/rr_hsync3.go`

Zone file format:
```
customer.zone. HSYNC3 cloudflare agent.cloudflare.com. netnod
customer.zone. HSYNC3 netnod    agent.netnod.se.      .
customer.zone. HSYNC3 akamai    agent.akamai.com.     cloudflare
```

Wire format: `State(1) + Label(character-string) + Endpoint(domain-name) + Upstream(character-string)`

```go
type HSYNC3 struct {
    State    uint8  // 0=OFF, 1=ON
    Label    string // unqualified tag, e.g. "netnod"
    Endpoint string // FQDN for discovery, e.g. "agent.netnod.se."
    Upstream string // label of upstream provider, or "."
}
```

~150 lines. Simpler than current HSYNC (no SVCB machinery needed).

### 1b. HSYNCPARAM — zone-wide policy record (SVCB-style extensible)

**New file**: `core/rr_hsyncparam.go` (adapted from `core/rr_deleg.go`, uses `core/zscan.go` zlexer)

Zone file format:
```
customer.zone. HSYNCPARAM nsmgmt=agent parentsync=agent signers="netnod" audit=no
customer.zone. HSYNCPARAM nsmgmt=agent parentsync=agent signers="netnod,cloudflare"
```

```go
type HSYNCPARAM struct {
    Value []HSYNCPARAMKeyValue  // key=value pairs
}
```

Keys:
```go
const (
    HSYNCPARAM_NSMGMT     HSYNCPARAMKey = 0  // uint8: 1=OWNER, 2=AGENT
    HSYNCPARAM_PARENTSYNC HSYNCPARAMKey = 1  // uint8: 0=OWNER, 1=AGENT
    HSYNCPARAM_AUDIT      HSYNCPARAMKey = 2  // uint8: 0=NO, 1=YES
    HSYNCPARAM_SIGNERS    HSYNCPARAMKey = 3  // comma-separated list of agent labels
    hsyncparam_RESERVED   HSYNCPARAMKey = 65535
)
```

Reuses from `rr_deleg.go`: key string/code conversion, zlexer-based key=value parsing, packData/unpackData, DELEGLocal pattern, paramToStr/parseParam helpers.

~350 lines. Most is mechanical adaptation from DELEG.

### 1c. Type registration

**File**: `core/rr_defs.go`
- `TypeHSYNC3 = 0x0F9F`
- `TypeHSYNCPARAM = 0x0FA0`

### 1d. Accessor helpers

```go
func (h *HSYNCPARAM) GetNSmgmt() uint8
func (h *HSYNCPARAM) GetParentSync() uint8
func (h *HSYNCPARAM) GetAudit() uint8
func (h *HSYNCPARAM) GetSigners() []string
func (h *HSYNCPARAM) IsSignerLabel(label string) bool
```

### 1e. Update consumers

**AgentId becomes a label, not an FQDN.** Discovery uses the Endpoint field.

| File | Change |
|------|--------|
| `agent_utils.go` (~35 sites) | `hsync.Identity` → `hsync.Label` as AgentId, `hsync.Endpoint` for discovery |
| `hsync_utils.go` (~8 sites) | `hsync.NSmgmt`, `hsync.Sign` → read from HSYNCPARAM |
| `agent_authorization.go` (~6 sites) | `hsync.Identity` → `hsync.Label` |
| `agent_policy.go` (~2 sites) | `hsync.NSmgmt` → HSYNCPARAM `GetNSmgmt()` |
| `hsync_hello.go` (~2 sites) | `hsync.Identity` → `hsync.Label` |
| `agent_discovery.go` | `result.Identity` → `hsync.Endpoint` as discovery target |
| `cli/hsync_debug_cmds.go` | Update display for new format |

Key consumer changes:
- `UpdateAgents`: `DiscoverAgentAsync(AgentId(hsync.Label), hsync.Endpoint, nil)` — pass endpoint separately
- `analyzeHsyncSigners`: read `signers` list from HSYNCPARAM, check if our label is in the list
- `EvaluateUpdate`: read `GetNSmgmt()` from HSYNCPARAM

### 1f. Coexistence with HSYNC v1

Keep `rr_hsync.go` and `rr_hsync2.go` as-is. Test zones contain both HSYNC and HSYNC3+HSYNCPARAM. Old code ignores HSYNC3/HSYNCPARAM, new code ignores HSYNC. No runtime switch — which record type is used depends on which codebase is running.

**Phase 1 complexity**: ~8 hours. ~500 lines new code, ~50 consumer site changes.

## Phase 2: Proactive CDS and CSYNC Publication

**Prerequisite**: Zone must be signed AND have a signed delegation (DS in parent).

### 2a. CDS synthesis from DNSKEYs

**File**: `delegation_sync.go` or new `ops_cds.go`

On DNSKEY change (via KEYSTATE): synthesize CDS RRset from current KSK DNSKEY(s), publish via UpdateQ. CDS format: hash of DNSKEY per RFC 7344. ~2 hours.

### 2b. Proactive CSYNC on NS changes

**File**: `zone_updater.go` or `delegation_sync.go`

On NS/glue change (via `ZoneUpdateChangesDelegationDataNG`): publish/update CSYNC RR. Currently only done on NOTIFY path — extend to always publish. `PublishCsyncRR` in `ops_csync.go` already exists. ~1 hour.

### 2c. DSYNC discovery on zone setup

**File**: `zone_utils.go`

When HSYNCPARAM `parentsync=agent`: discover parent via IMR, look up `_dsync.<parent>`, select sync scheme, cache in ZoneData. ~2 hours.

## Phase 3: Leader Election and Coordinated DDNS

### 3a. Leader election protocol

**File**: new `parentsync_leader.go`

**Triggers** — election is cheap, don't optimize for avoiding it:
- Agent startup with no known leader
- HSYNC RRset changes (provider added or removed)
- Cached leader TTL expires (e.g., 5 minutes)
- "I don't know who the leader is" = "call election"

**Protocol** (per zone, among agents with parentsync=agent):

1. **Call**: Any agent broadcasts `PARENTSYNC-ELECT {zone}` to all peers.
2. **Vote**: Every agent generates a random uint32 and broadcasts `PARENTSYNC-VOTE {zone, random_number, my_label}` to **all** peers.
3. **Confirm**: After timeout (3s), each agent determines winner (highest number, ties by label) and broadcasts `PARENTSYNC-CONFIRM {zone, winner_label}` to **all** peers.

Outcomes:
- All confirmations agree → leader established, cached with TTL
- Confirmations disagree → re-elect (vote was lost)
- Peer unresponsive → proceed without it

Message cost (via existing CHUNK messaging):

| Providers | Call | Votes | Confirmations | Total |
|-----------|------|-------|---------------|-------|
| 2 | 1 | 2 | 2 | 5 |
| 3 | 1 | 6 | 6 | 13 |

Single agent: no election needed, sends directly. ~4 hours.

### 3b. SIG(0) key generation and publication

**File**: extend `ops_key.go`

**(b1) RFC 8078 model** (first): KEY RR at zone apex. Existing `BootstrapSig0KeyWithParent` already does this.

**(b2) RFC 9615 model** (second): KEY RR at `_signal.<nameserver-name>`. Publish at both locations.

### 3c. SIG(0) private key distribution

**File**: extend CHUNK messaging

New message type `PARENTSYNC-KEY`. First agent generates keypair, distributes private key to peers via encrypted CHUNK. Receiving agents store in local keystore. ~3 hours.

### 3d. Coordinated DDNS sending

**File**: extend `delegation_sync.go`

Gate DDNS sends on leader election result. Existing `SyncZoneDelegationViaUpdate` machinery handles the actual send. ~2 hours.

## Implementation Order

1. **Phase 1** (HSYNCPARAM + HSYNC redesign) — prerequisite for everything (~8h)
2. **Phase 2a-2b** (CDS/CSYNC publication) — independent once Phase 1 done (~3h)
3. **Phase 2c** (DSYNC discovery) — needed before Phase 3 (~2h)
4. **Phase 3a** (leader election) (~4h)
5. **Phase 3b-3c** (SIG(0) key publication + distribution) (~3h)
6. **Phase 3d** (coordinated DDNS sending) (~2h)

## Files Modified

| Phase | Files |
|-------|-------|
| 1a | new `core/rr_hsync3.go` |
| 1b | new `core/rr_hsyncparam.go` |
| 1c | `core/rr_defs.go` |
| 1e | `agent_utils.go`, `hsync_utils.go`, `agent_authorization.go`, `agent_policy.go`, `hsync_hello.go`, `agent_discovery.go`, `cli/hsync_debug_cmds.go` |
| 1f | no changes — keep `core/rr_hsync.go`, `core/rr_hsync2.go` as-is |
| 2a | `delegation_sync.go` or new `ops_cds.go` |
| 2b | `zone_updater.go` or `delegation_sync.go` |
| 2c | `zone_utils.go` |
| 3a | new `parentsync_leader.go` |
| 3b | `ops_key.go` |
| 3c | CHUNK message handlers |
| 3d | `delegation_sync.go` |

## Verification

1. Build: `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
2. Parse HSYNC3 with label/endpoint/upstream in zone file → verify correct field values
3. Parse HSYNCPARAM with key=value pairs → verify accessor helpers work
4. Wire format round-trip for both record types
5. `signers="netnod"` in HSYNCPARAM → `analyzeHsyncSigners` returns correct result
6. Agent startup with HSYNCPARAM parentsync=agent → `OptDelSyncChild` set automatically
7. NS change in signed zone with signed delegation → CSYNC published proactively
8. DNSKEY change in signed zone → CDS synthesized and published
9. SIG(0) KEY published at zone apex (RFC 8078)
10. Two agents restart → leader election, single DDNS update sent
