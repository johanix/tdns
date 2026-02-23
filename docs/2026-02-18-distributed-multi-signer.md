# Distributed Multi-Signer DNSSEC Support for TDNS

**Date**: 2026-02-18
**Status**: Future project (effort estimate, not yet scheduled)

## Motivation

The "Distributed Multi-Signer Architecture, Evolved" enables multiple independent signer providers to each maintain their own signed copy of a zone. Each provider runs its own agent + combiner + signer (tdns-auth) stack. The published DNSKEY RRset must always reflect the **union** of all providers' keys, and key rollovers at one provider must coordinate with all others before activating new signing keys.

Reference: RFC 8901 (Multi-Signer DNSSEC Models).

---

## Architecture

```
                    Zone Owner
                   (unsigned zone)
                   /            \
          UPDATE|API          UPDATE|API
                /                \
   ┌─────────────────┐    ┌─────────────────┐
   │  signer-providerA│    │  signer-providerB│
   │                  │    │                  │
   │  ┌────────────┐  │    │  ┌────────────┐  │
   │  │   agent    │◄─┼─API|DNS──►│   agent    │  │
   │  └──────┬─────┘  │    │  └──────┬─────┘  │
   │         │SYNC    │    │         │SYNC    │
   │  ┌──────▼─────┐  │    │  ┌──────▼─────┐  │
   │  │  combiner  │  │    │  │  combiner  │  │
   │  └──────┬─────┘  │    │  └──────┬─────┘  │
   │      XFR│        │    │      XFR│        │
   │  ┌──────▼─────┐  │    │  ┌──────▼─────┐  │
   │  │   signer   │──┼─XFR to agent (for   │  │
   │  │ (tdns-auth)│  │  analysis only)      │  │
   │  └──────┬─────┘  │    │  └──────┬─────┘  │
   │      XFR│        │    │      XFR│        │
   │  ┌──────▼─────┐  │    │  ┌──────▼─────┐  │
   │  │nameservers │  │    │  │nameservers │  │
   │  └────────────┘  │    │  └────────────┘  │
   └──────────────────┘    └──────────────────┘
```

### Zone transfer chain

- **combiner → signer (XFR)**: Signer receives the combined unsigned zone (including remote DNSKEYs from other providers, delivered via agent SYNC → combiner)
- **signer → nameservers (XFR)**: Signed zone served to public nameservers
- **signer → agent (XFR)**: Agent receives the signed zone for DNSKEY analysis and SYNC with remote agents. The agent is **not** part of the public serving chain.

### Data flow for DNSKEY coordination

1. Signer publishes a new DNSKEY (key rollover step 1: "publish")
2. Agent detects the new local DNSKEY in the signed zone (via XFR from signer)
3. Agent SYNCs the new DNSKEY to remote agents (not to our own combiner — our combiner only needs foreign DNSKEYs, not our own)
4. Remote agents receive the DNSKEY via SYNC → propagate to their combiner → signer
5. Remote signers include the new DNSKEY in their signed zones
6. Remote agents confirm SYNC back to originating agent (two-phase confirmation)
7. Agent signals signer: "key X confirmed propagated to all providers" — this is one of two prerequisites for activation
8. Signer waits for **both** prerequisites before activating:
   a. All remote providers have confirmed the new DNSKEY is in their zones (propagation confirmation from step 7)
   b. Enough time has passed for all old cached DNSKEY RRsets to have expired from caches worldwide (TTL-based timer — typically the DNSKEY RRset's TTL)
9. Once both conditions are met, signer activates the key (key rollover step 2: "activate")

---

## What exists today

- Agent↔agent SYNC with two-phase confirmation (double NOTIFY)
- Agent↔combiner SYNC with confirmation tracking
- tdns-auth DNSSEC signing: `SignZone()`, `SignRRset()`, `ensureActiveDnssecKeys()` (`sign.go`)
- Key lifecycle management: created → published → active → retired (`keystore.go`)
- TransportManager in agent and combiner (not yet in tdns-auth)
- `HsyncChanged()` (`hsync_utils.go`) — RRset change detection pattern, directly reusable for DNSKEY
- `core.RRsetDiffer()` (`core/rrset_utils.go`) — generic RRset comparison, works for any RR type
- HSYNC record `Sign` field (`HsyncSignYES`/`HsyncSignNO` in `core/rr_hsync.go`, `FlagSign` in `core/rr_hsync2.go`) — already defines whether a zone should be signed
- NSmgmt policy check pattern in `agent_policy.go:63` — existing example of gating behavior on an HSYNC field
- SYNC rejection wire format already implemented end-to-end:
  - Combiner produces `RejectedItems []RejectedItem` in `ProcessUpdate()` (`combiner_chunk.go`) for parse errors, disallowed RRtypes, non-apex owners, unsupported classes
  - `RejectedItem{Record, Reason}` flows through `CombinerSyncResponse` → `ConfirmationDetail` → `RemoteConfirmationDetail` → `DnsConfirmPayload` → `RejectedItemDTO`
  - RR state machine includes `RRStateRejected` with proper transitions (`syncheddataengine.go`)
- Agent policy evaluation in `EvaluateUpdate()` (`agent_policy.go`) — checks RRtype, apex, NSmgmt, ownership. Currently all-or-nothing (rejects entire update, no per-record `RejectedItems`)
- Two-level multi-signer config gate already partially wired (needs rename to `multi-provider`):
  - Server-level: `Config.MultiSigner map[string]MultiSignerConf` (`config.go:26`, YAML key `multisigner:`) → rename to `Config.MultiProvider *MultiProviderConf` with YAML key `multi-provider:`
  - Zone-level: `OptMultiSigner` zone option (`enums.go:21`) + `ZoneConf.MultiSigner string` (`structs.go:126`) → rename to `OptMultiProvider` + `ZoneConf.MultiProvider bool`
  - Validation: `parseoptions.go:199-223` — zone referencing missing config → error, zone option without config name → error. Pattern reusable.
  - Guard: `if zd.Options[OptMultiSigner]` already used in `zone_utils.go:227` for DNSKEY change detection → rename to `OptMultiProvider`
  - Note: `MultiSignerConf` struct (`musicstructs.go:34-37`) is from an older external-controller design; replace with `MultiProviderConf`

---

## Operational Mode: Explicit Opt-In, Not Zone Data Detection

### Design decision: single application, two-level gate

tdns-auth remains a general-purpose DNSSEC-aware authoritative nameserver. Multi-provider support is an optional enhancement, **not** a separate application. However, it must be impossible for multi-provider behavior to activate accidentally — a stray HSYNC record in a zone must not change the signer's operational mode.

### Existing infrastructure (partially implemented, needs rename)

The two-level gate pattern **already exists** in the codebase, originally built for an earlier multi-signer design (external controller-based). The wiring is in place but needs renaming from `multisigner` → `multi-provider` and content updates:

| Layer | What exists today | Where | What changes |
|-------|-------------------|-------|--------------|
| **Server-level config** | `Config.MultiSigner map[string]MultiSignerConf` | `config.go:26` (`yaml:"multisigner"`) | Rename to `Config.MultiProvider *MultiProviderConf` (`yaml:"multi-provider"`). Replace old `map[string]` of named configs with a single struct containing `Active bool`, agent peer config (follows `PeerConf` pattern from `agent:`/`combiner:` blocks), transport config |
| **Zone-level option** | `OptMultiSigner` zone option enum | `enums.go:21` (currently marked "OBE?" — remove that) | Rename to `OptMultiProvider`. Zone config: `options: [multi-provider]` |
| **Zone config field** | `ZoneConf.MultiSigner string` | `structs.go:126` | Change to `ZoneConf.MultiProvider bool` — no longer needs to name a config (there's only one server-level `multi-provider:` block) |
| **ZoneData field** | `ZoneData.MultiSigner *MultiSignerConf` | `structs.go:95` | Change to `ZoneData.MultiProvider bool` (or keep pointer to config if zone needs per-zone overrides) |
| **Two-level validation** | Zone references non-existing config → error; zone has option but no config name → error | `parseoptions.go:199-223` | Simplify: zone has `multi-provider` option but `conf.MultiProvider.Active == false` → error. Also checks `MusicSyncQ` channel — update to check TransportManager instead |
| **Guard in code** | `if zd.Options[OptMultiSigner]` | `zone_utils.go:227` | Rename to `if zd.Options[OptMultiProvider]`. Pattern reusable for all multi-provider guards |

### Two-level gate

Multi-provider behavior requires **both** levels to be explicitly enabled:

1. **Server-level**: `multi-provider:` section with `active: true` in server config — controls whether TransportManager, JOSE crypto, peer registry, and KEYSTATE messaging are initialized at all. This is also where the signer's local agent peer is configured (address, JOSE key, transport) — symmetric to how `agent:` configures its combiner peer and `combiner:` configures its agent peers.
2. **Zone-level**: `options: [multi-provider]` in per-zone config — controls whether HSYNC analysis, DNSKEY merge, KEYSTATE gating, and Sign field checking apply to that specific zone

```yaml
# Server-level (tdns-auth config):
multi-provider:
  active: true
  identity: signer.alpha.dnslab.           # signer's own identity for CHUNK
  long_term_jose_priv_key: /path/to/signer-privkey.pem
  chunk_mode: edns0                         # or "query"
  agent:                                    # local agent peer (follows PeerConf pattern)
    identity: agent.alpha.dnslab.
    address: 127.0.0.1:5399
    long_term_jose_pub_key: /path/to/agent-pubkey.pem
    api_base_url: https://localhost:8085/api/v1  # optional: for API transport

# Zone-level:
zones:
  - name: whisky.dnslab.
    options: [multi-provider, online-signing]
    # ...
```

The `multi-provider:` block follows the same pattern as `agent:` and `combiner:`:
- `agent:` block has `combiner: *PeerConf` — the agent's combiner peer
- `combiner:` block has `agents: []*PeerConf` — the combiner's agent peers
- `multi-provider:` block has `agent: *PeerConf` — the signer's local agent peer

### Validation rules

| `multi-provider.active` | Zone `options: [multi-provider]` | Zone has HSYNC records | Behavior |
|--------------------------|----------------------------------|----------------------|----------|
| absent/false (default) | absent | doesn't matter | **Normal nameserver**. HSYNC records are just data. No HSYNC analysis, no DNSKEY merge, no KEYSTATE, no TransportManager. Key rollover is time-based as today. |
| absent/false | present | doesn't matter | **Error at config load**. Zone enters error state: "zone has multi-provider option but server multi-provider.active is false". Prevents silent misconfiguration. |
| `true` | absent | doesn't matter | **Normal nameserver for this zone**. Server has TransportManager initialized (for other zones), but this zone is signed normally. HSYNC records in the zone are just data — no semantic interpretation, no DNSKEY merge, no confirmation gating. |
| `true` | present | yes | **Full multi-provider mode** for this zone. Exact behavior depends on HSYNC Sign fields: if our HSYNC says `SIGN=NO` and only one signer exists → pure pass-through (mode 3); if we are the sole signer → strip and replace (mode 2); if multiple signers → DNSKEY merge, KEYSTATE coordination, confirmation-gated key activation (mode 4). |
| `true` | present | no | **Warning at zone load**. Multi-provider enabled but no HSYNC records found — zone will be signed normally until HSYNC records appear. |

### What this prevents

**Confused customer scenario**: An upstream customer adds HSYNC records to a zone served by a normal tdns-auth instance (`multi-provider.active` absent or false). Result: **nothing changes**. The HSYNC records are served as authoritative data. `SignZone()` signs them like any other record. Key rollover proceeds on its normal time-based schedule. No TransportManager is running, no KEYSTATE messages are sent or expected, no DNSKEY merge logic runs.

**Single-flag misconfiguration**: Operator adds `options: [multi-provider]` on a zone but has `multi-provider.active: false` (or no `multi-provider:` section at all). Validation at config load catches this and puts the zone in error state.

### Implementation guards

Every multi-provider code path in tdns-auth must be gated:

```go
// Zone-level guard:
if !zd.Options[OptMultiProvider] {
    return  // skip — this zone is in normal mode
}

// Server-level guard:
if !conf.MultiProvider.Active {
    return  // skip — server has no multi-provider support
}
```

Specific guard points:

| Code path | Guard |
|-----------|-------|
| TransportManager initialization in `MainInit()` | `if !conf.MultiProvider.Active { skip }` |
| HSYNC analysis in `FetchFromUpstream()` / `FetchFromFile()` | `if !zd.Options[OptMultiProvider] { skip }` |
| DNSKEY handling in `SignZone()` | `if !zd.Options[OptMultiProvider] { strip and replace (mode 1) }` else if `!zd.weAreASigner() { pass-through (mode 3) }` else if `!zd.isMultiSigner() { strip and replace (mode 2) }` else `{ merge (mode 4) }` |
| HSYNC Sign field check in `SignZone()` | `if !zd.Options[OptMultiProvider] { skip }` |
| Key activation gating (wait for KEYSTATE) | `if !zd.Options[OptMultiProvider] { time-based promotion as today }` else `{ require propagation_confirmed AND DNSKEY TTL expired since confirmation }` |
| DNSKEY change detection in agent | `if !zd.Options[OptMultiProvider] { skip }` |

### Cost in normal mode

| Resource | Cost when `multi-provider.active: false` (or absent) |
|----------|-------------------------------------------------------|
| Memory | Zero (no TransportManager, no peer registry, no JOSE crypto, no remote DNSKEY tracking) |
| Goroutines | Zero (no message router, no KEYSTATE listener) |
| CPU per `SignZone()` | Zero (multi-provider code paths not entered — `zd.Options[OptMultiProvider]` is false) |
| Attack surface | Zero (no new listeners, no CHUNK handler, no JOSE) |
| New failure modes | Zero (key rollover unchanged, no confirmation gating) |
| Binary size | Slightly larger (compiled code exists but is never executed) |

---

## What's needed

Five components, each described in detail below:

| Component | Description |
|-----------|-------------|
| **A: Agent↔Signer signaling** | TransportManager for tdns-auth + KEYSTATE message type |
| **B: Signer DNSKEY handling** | Four modes: strip+replace, pass-through, or merge depending on multi-provider/signer state |
| **C: Agent DNSKEY analysis** | Detect local key changes, SYNC to remote agents, signal signer |
| **D: HSYNC Sign field check in signer** | Signer checks HSYNC `Sign` field to decide whether to sign or pass through |
| **E: General SYNC rejection** | Per-record policy evaluation on incoming remote SYNCs with rejection feedback |

---

## Component A: Agent↔Signer Signaling

### Problem

The signer generates a new DNSKEY (published state). The key must NOT be activated for signing until all remote providers have confirmed they've added it to their zones. Today the agent knows when remote confirmation arrives (via two-phase SYNC confirms), but has no way to tell the signer.

### Design

**TransportManager for tdns-auth** — same infrastructure as agent/combiner. The signer gets a TransportManager initialized in `MainInit()`, with DNS and/or API transports to communicate with its local agent. The transport is agnostic — may use CHUNK NOTIFYs, API, or both. **Only initialized when `multi-provider.active: true`** in the server config — otherwise zero cost.

**New message type: KEYSTATE** — carries key lifecycle signals:

| Direction | Signal | Meaning |
|-----------|--------|---------|
| Agent → Signer | `propagated` | Key with tag X confirmed present in all N providers' zones |
| Agent → Signer | `rejected` | Key with tag X rejected by remote provider (e.g. key tag collision) — signer should scrap key, regenerate, and retry |
| Agent → Signer | `removed` | Key with tag X confirmed removed from all providers |
| Signer → Agent | `published` | New key with tag X published, awaiting propagation confirmation |
| Signer → Agent | `retired` | Key with tag X retired, awaiting removal confirmation |

### Components

1. **TransportManager init for tdns-auth** — Follow the same pattern as agent (`main_initfuncs.go:365-383`). tdns-auth needs:
   - Identity, control zone, CHUNK mode config
   - PayloadCrypto (JOSE) for secure messaging
   - DNSMessageRouter with handlers for KEYSTATE (and PING for diagnostics)
   - Peer registry with its local agent as the only peer

2. **KEYSTATE message type** — New message type in the CHUNK vocabulary:
   - Message definition (payload struct with zone, key tag, algorithm, action)
   - Handler in `handlers.go`
   - Sender function in dns.go/api.go transports
   - Router registration in `InitializeSignerRouter()`

3. **Key activation gating** — Modify `ensureActiveDnssecKeys()` and `PromoteDnssecKey()` in `keystore.go`:
   - **Only for zones with `options: [multi-provider]`** — normal zones use time-based promotion as today
   - A key in "published" state gains a sub-state: "awaiting_propagation"
   - Promotion to "active" requires **two conditions** (AND):
     a. Agent has confirmed propagation to all remote providers
     b. Enough time has passed for old cached DNSKEY RRsets to expire (typically the DNSKEY RRset's TTL)
   - New fields in key store: `propagation_confirmed bool`, `propagation_confirmed_at time.Time`
   - The time-based wait starts when propagation is confirmed (not when the key was published) — we need the full TTL after the last provider has the key, to ensure all caches worldwide have expired
   - `DnssecKeyMgmt("setstate")` checks both propagation status and TTL expiry before allowing published→active

4. **Config** — Replace the old `MultiSignerConf` struct (`musicstructs.go:34-37`) with a new `MultiProviderConf` struct under YAML key `multi-provider:`. Contains `Active bool`, signer identity, JOSE key path, CHUNK mode, and an `Agent *PeerConf` for the local agent peer (address, JOSE pub key, optional API URL). Follows the same `PeerConf` pattern used by the `agent:` and `combiner:` blocks. The existing config-parsing wiring in `parseoptions.go` provides the validation pattern.

5. **CLI** — `auth key status` showing propagation state, `auth peer ping`

### Key integration points

| File | Integration |
|------|-------------|
| `main_initfuncs.go` | TransportManager initialization for tdns-auth |
| `keystore.go` | Key activation gating, propagation_confirmed field |
| `sign.go` | Check propagation state before key promotion |
| `agent/transport/handlers.go` | KEYSTATE handler |
| `agent/transport/router_init.go` | `InitializeSignerRouter()` |
| Config files | Signer transport config |

### Effort estimate

| Component | Lines |
|-----------|-------|
| TransportManager init for tdns-auth | ~150-200 |
| KEYSTATE message type (definition + handler + sender) | ~200-300 |
| Key activation gating (keystore.go, sign.go) | ~150-200 |
| Config + CLI | ~100-150 |
| Tests | ~200-300 |
| **Total** | **~800-1150** |

**Comparable to**: Transport Unification Phase 1c (Combiner Router) — wiring an existing component (TransportManager) into a new app, plus a new message type.

---

## Component B: Signer DNSKEY Handling (Strip, Pass-Through, or Merge)

### Problem

When tdns-auth receives a zone from upstream (combiner or primary) and that zone contains DNSKEY records, the signer must decide what to do with them. There are four distinct operational modes:

1. **Normal signing mode** (no `multi-provider` option, but we are signing): The incoming DNSKEYs are **stripped** and replaced with the signer's own keys from its local keystore. This is the correct default — a downstream signer owns the DNSKEY RRset entirely.

2. **Multi-provider, single-signer, we ARE the signer** (`multi-provider` option set, only one agent has `SIGN=YES` in the HSYNC RRset, and that agent is ours): Same as mode 1 — this signer is the only signer, so it owns the DNSKEY RRset. Strip and replace.

3. **Multi-provider, single-signer, we are NOT the signer** (`multi-provider` option set, only one agent has `SIGN=YES`, but it is NOT ours): **Pure pass-through**. We fetch the zone via inbound zone transfer and provide it via outbound zone transfer. Absolutely no modifications to the signed zone — we do not sign, we do not strip DNSKEYs, we do not merge. The zone is already signed by the actual signer and we just serve it as-is.

4. **Multi-provider, multi-signer** (`multi-provider` option set AND multiple agents have `SIGN=YES`, including ours): The incoming zone contains remote DNSKEYs from other providers (delivered via agent SYNC → combiner). These must be **preserved and merged** with local keys. Per RFC 8901, each signer signs the **entire** DNSKEY RRset (local + remote) with its own KSK.

The key distinction between modes 2 and 3 is whether **we** are the signer. This is determined by checking the HSYNC RRset: our own agent's HSYNC record tells us whether we have `SIGN=YES` (we sign) or `SIGN=NO` (we don't).

### Design

**Four-mode DNSKEY handling in `SignZone()`**:

```
if !zd.Options[OptMultiProvider] {
    // Mode 1: Normal — strip incoming DNSKEYs, replace with local keys, sign
} else if !zd.weAreASigner() {
    // Mode 3: Multi-provider, we are NOT a signer — pure pass-through, no signing at all
    return  // skip SignZone() entirely
} else if !zd.isMultiSigner() {
    // Mode 2: Multi-provider, single-signer, we ARE the signer — strip and replace
} else {
    // Mode 4: Multi-provider, multi-signer — merge remote DNSKEYs with local keys
}
```

Note: Mode 3 (pass-through) is closely related to Component D's `SIGN=NO` check but has a different trigger. Component D checks the zone's own HSYNC record's `Sign` field. Mode 3 here is the logical consequence: if our HSYNC says `SIGN=NO` and there's only one signer in the HSYNC RRset (and it's not us), we're in pure pass-through mode. In practice, Component D's early check in `SignZone()` will catch mode 3 before reaching the DNSKEY handling logic — but it's important to model it as a distinct mode.

**`weAreASigner()` check**: Look up our own agent's HSYNC record (identified by the agent identity from the `multi-provider:` config). If our HSYNC record has `Sign == SIGN` (or `IsSign()` for HSYNC2), we are a signer. If `Sign == NOSIGN`, we are not.

**`isMultiSigner()` check**: Examine the HSYNC RRset at the zone apex. Count how many agents have the `Sign` field set to `SIGN` (or `IsSign()` for HSYNC2). If more than one → multi-signer mode. This check is structurally similar to the `ValidateHsyncRRset()` consistency check already in `hsync_utils.go`.

**Key classification** (modes 1, 2, 4 only): The signer knows its own keys (they're in its keystore). Any DNSKEY in the incoming zone that doesn't match a key in the local keystore is a "remote" DNSKEY.

**Merge point** (mode 4 only): In `ensureActiveDnssecKeys()` / `PublishDnskeyRRs()` — when building the DNSKEY RRset for the zone apex:
1. Start with local keys (from keystore, as today)
2. Add remote DNSKEYs (from the incoming zone data, not in keystore)
3. Sign the merged RRset with local KSK

**Per RFC 8901**: Each signer signs the **entire** DNSKEY RRset (local + remote) with its own KSK. This is already what `SignRRset()` does — it signs whatever RRs are in the RRset. The key change is: don't strip remote DNSKEYs from the RRset before signing.

### Components

1. **`weAreASigner()` check** — Look up our own HSYNC record by agent identity, check `Sign` field. Returns true if we have `SIGN=YES`. This is the gate that distinguishes "we sign" (modes 1/2/4) from "pure pass-through" (mode 3).

2. **`isMultiSigner()` check** — Examine HSYNC RRset, count agents with `SIGN=YES`. Returns true if more than one signer. This is the gate that distinguishes "strip and replace" (mode 2) from "merge" (mode 4).

3. **Remote DNSKEY detection** — **Only in mode 4** (multi-provider AND multiple signers); otherwise strip (modes 1/2) or pass through (mode 3). Compare incoming zone's DNSKEY RRset against local keystore. Keys not in keystore = remote. Store in a `remoteDNSKEYs` set on ZoneData.

4. **DNSKEY merge in `PublishDnskeyRRs()`** — When building DNSKEY RRset in mode 4: local keys (from keystore) + remote keys (from `remoteDNSKEYs`). In modes 1/2 this function only publishes local keys (as today). In mode 3 this function is never called (no signing).

5. **Preserve across resignings** — `SignZone()` must not discard remote DNSKEYs when it rebuilds the DNSKEY RRset in mode 4. They persist until explicitly removed (via agent SYNC removing them).

6. **Zone transfer handling** — When signer receives updated zone from combiner (AXFR/IXFR), extract and track remote DNSKEYs before signing (only in mode 4).

### The four modes at a glance

| Mode | Config | HSYNC state | DNSKEY handling | Signing |
|------|--------|-------------|-----------------|---------|
| 1. Normal | No `multi-provider` | N/A | Strip and replace | Yes |
| 2. MP single-signer (we sign) | `multi-provider` | 1 signer (us) | Strip and replace | Yes |
| 3. MP single-signer (we don't sign) | `multi-provider` | 1 signer (not us) | Pass-through (no touch) | No |
| 4. MP multi-signer | `multi-provider` | N signers (incl. us) | Merge remote + local | Yes |

### Key integration points

| File | Integration |
|------|-------------|
| `sign.go` | Four-mode DNSKEY handling in `SignZone()`, `PublishDnskeyRRs()` merge, preservation |
| `hsync_utils.go` | `weAreASigner()` — check our own HSYNC `Sign` field; `isMultiSigner()` — count agents with `SIGN=YES` |
| `keystore.go` | Remote DNSKEY detection (compare against keystore) |
| `structs.go` | `ZoneData.RemoteDNSKEYs` field |
| Zone transfer code | Extract remote DNSKEYs on zone receipt (mode 4 only) |

### Effort estimate

| Component | Lines |
|-----------|-------|
| `weAreASigner()` check | ~20-30 |
| `isMultiSigner()` check | ~30-50 |
| Remote DNSKEY detection + storage | ~100-150 |
| Four-mode DNSKEY handling in SignZone | ~60-100 |
| DNSKEY merge in PublishDnskeyRRs | ~50-100 |
| Preserve across resigning | ~50-100 |
| Zone transfer DNSKEY extraction | ~50-100 |
| Tests | ~150-200 |
| **Total** | **~510-830** |

**Comparable to**: Error Journal (Phase 6) in scope — a focused addition wired into existing signing code. The four-mode handling adds a small amount of logic over the original three-mode design (primarily the `weAreASigner()` check), but the pass-through mode (mode 3) is actually the simplest — it's "do nothing".

---

## Component C: Agent DNSKEY Analysis + SYNC Distribution

### Problem

The agent receives the signed zone from the signer via XFR (the agent is downstream of the signer for analysis purposes, not part of the public serving chain). It must:

1. Analyze the DNSKEY RRset to identify local vs remote keys
2. Track local DNSKEYs and detect changes (new key added, old key removed)
3. When a local key changes: SYNC the change to all remote agents
4. When confirmation comes back from all remote agents: signal the signer (via KEYSTATE)

### Design

**Reuse `HsyncChanged()` pattern**: The existing `HsyncChanged()` function in `hsync_utils.go` already does exactly this pattern for the HSYNC RRset — compare old vs new, compute adds/removes via `core.RRsetDiffer()`. A `DnskeyChanged()` function follows the same structure, operating on `dns.TypeDNSKEY` instead of `core.TypeHSYNC`.

**Key classification in agent**: The agent knows which keys are "remote" because they arrive via SYNC transactions from remote peers. The remaining DNSKEYs in the signed zone from the signer are "local" (from our signer). The agent tracks a set of known remote DNSKEY key tags, and anything not in that set is local.

**Change detection**: When the agent receives a new zone version via XFR from the signer:
1. Extract DNSKEY RRset
2. Filter out known remote DNSKEYs
3. Compare remaining (local) DNSKEYs against previously known local set
4. New local keys → SYNC ADD to all remote agents (not to our own combiner — it doesn't need our local DNSKEYs)
5. Removed local keys → SYNC DELETE to all remote agents

**Confirmation → KEYSTATE**: Hook into existing `PendingRemoteConfirms` in `syncheddataengine.go`. When all remote agents confirm a DNSKEY SYNC: send KEYSTATE "propagated" message to local signer.

### Components

1. **`DnskeyChanged()` function** — Modeled on `HsyncChanged()` (~80 lines). Compare old vs new DNSKEY RRset, return adds/removes. Uses existing `core.RRsetDiffer()`.

2. **Local vs remote DNSKEY classification** — Track set of remote DNSKEY key tags (populated when receiving DNSKEY SYNC from remote agents). Filter these out when analyzing the signed zone from the signer.

3. **DNSKEY change → SYNC** — When local DNSKEY changes detected, create SYNC operations (ClassINET for add, ClassNONE for remove). Send via existing SYNC machinery to remote agents only (our own combiner doesn't need our local DNSKEYs — it already gets them from the signer via XFR).

4. **Confirmation → KEYSTATE** — When all remote agents confirm a DNSKEY SYNC, send KEYSTATE `propagated` message to signer. Hook into `PendingRemoteConfirms` confirmation path. When any remote agent rejects (e.g. key tag collision via Component E), send KEYSTATE `rejected` to signer.

### Key integration points

| File | Integration |
|------|-------------|
| `hsync_utils.go` (or new `dnskey_utils.go`) | `DnskeyChanged()` function |
| `syncheddataengine.go` | Confirmation → KEYSTATE hook, DNSKEY SYNC dispatch |
| Zone transfer reception code | Trigger DNSKEY analysis on zone update |

### Effort estimate

| Component | Lines |
|-----------|-------|
| `DnskeyChanged()` function | ~80-120 |
| Local/remote DNSKEY classification | ~50-80 |
| DNSKEY change → SYNC distribution | ~80-120 |
| Confirmation → KEYSTATE signaling (accept + reject) | ~50-80 |
| Tests | ~100-150 |
| **Total** | **~360-550** |

The DNSKEY analysis is structurally identical to `HsyncChanged()` + the HSYNC-based agent discovery that already exists. The only new logic is the local-vs-remote classification and the KEYSTATE signaling on full confirmation. DNSKEY-specific policy checks (key tag collision detection) are in Component E.

**Comparable to**: `HsyncChanged()` + agent discovery wiring — existing patterns applied to a new RR type with a thin coordination layer on top. Significantly less complex than the Reliable Message Queue.

---

## Component D: HSYNC Sign Field Check in Signer

### Problem

The HSYNC record for each agent has a `Sign` field (`SIGN` or `NOSIGN`). This tells the signer whether it should sign the zone or pass it through unchanged. Not all providers in a multi-provider setup necessarily run their own signer — some may receive an already-signed zone from another provider and simply serve it (Component B's mode 3: pure pass-through). The signer (tdns-auth) must check this field before signing.

This is the implementation mechanism for Component B's mode 3. The `Sign` field check runs early in `SignZone()` and short-circuits the entire signing path when `SIGN=NO`. This is analogous to the existing NSmgmt check in the agent: `agent_policy.go:63` checks `hsync.NSmgmt != core.HsyncNSmgmtAGENT` before allowing NS RRset modifications. The signer needs the same pattern for `hsync.Sign`.

### Existing infrastructure

- **HSYNC record `Sign` field**: Already defined in both record formats:
  - `core/rr_hsync.go:26`: `Sign uint8` with constants `HsyncSignYES = 1`, `HsyncSignNO = 0`
  - `core/rr_hsync2.go:35`: `FlagSign uint16 = 1 << 1` with methods `SetSign()`, `IsSign()`
- **NSmgmt check pattern**: `agent_policy.go:63` — get HSYNC RRset from zone apex, extract field, gate behavior. Directly reusable as a template.

### Design

**Only for zones with `options: [multi-provider]`** — normal zones are always signed (no HSYNC inspection).

In `SignZone()` (`sign.go`), before signing:

1. Check `zd.Options[OptMultiProvider]` — if false, skip this check entirely and sign normally
2. Get the HSYNC RRset from the zone apex
3. Extract the `Sign` field (handle both HSYNC and HSYNC2 record types)
4. If `Sign == NOSIGN` (or `!IsSign()`): skip signing entirely, pass zone through unchanged
5. If `Sign == SIGN` (or `IsSign()`): proceed with signing as today

This check should be early in `SignZone()`, before `ensureActiveDnssecKeys()` is called — no point generating or managing keys for a zone that won't be signed.

The same check may also be needed in the `ResignerEngine` periodic loop, to avoid repeatedly attempting to resign zones marked NOSIGN.

### Key integration points

| File | Integration |
|------|-------------|
| `sign.go` | Early check in `SignZone()` before key management and signing |
| `sign.go` | ResignerEngine loop: skip NOSIGN zones |
| `agent_policy.go` | Existing NSmgmt pattern to follow (line 63) |

### Effort estimate

| Component | Lines |
|-----------|-------|
| Sign field check in `SignZone()` | ~20-30 |
| ResignerEngine skip for NOSIGN zones | ~10-20 |
| Tests | ~30-50 |
| **Total** | **~60-100** |

This is a small, mechanical change — essentially a conditional check copied from the NSmgmt pattern.

**Comparable to**: A single policy check addition. Trivially small compared to the other components.

---

## Component E: General SYNC Rejection Protocol

### Problem

The SYNC protocol currently has no agent-side per-record policy evaluation for incoming remote SYNCs. The combiner does per-record rejection (parse errors, disallowed RRtypes, non-apex owners), but the agent's `EvaluateUpdate()` is all-or-nothing — it either accepts or rejects the entire update. There is no content-based policy checking on the receiving agent.

This is a general protocol gap, not just a DNSKEY concern. Examples of policy violations that should trigger per-record rejection:

- **NS namespace policy**: agent.alpha adds `whisky.dnslab. IN NS ns7.ECHO.dnslab.` — echo should reject this because alpha is claiming nameservers inside echo's namespace. An agent should only be allowed to add NS records pointing to nameservers in its own namespace.
- **DNSKEY key tag collision**: agent.alpha SYNCs a DNSKEY with key tag X, but echo already has its own local key with tag X — collision must be detected and resolved.
- **Future policies**: RRSIG validation, TTL sanity checks, content-based filtering.

### Existing infrastructure

The rejection wire format is **already fully implemented** end-to-end:

| Layer | Structure | Location |
|-------|-----------|----------|
| Combiner response | `RejectedItem{Record, Reason}` | `combiner_chunk.go:59-66` |
| Engine confirmation | `RejectedItemInfo{Record, Reason}` | `syncheddataengine.go:99-215` |
| Transport DTO | `RejectedItemDTO{Record, Reason}` | `agent/transport/dns.go:922-944` |
| RR state machine | `RRStateRejected` with transitions | `syncheddataengine.go:775-911` |
| Confirmation callback | Rejection forwarding via `OnConfirmationReceived` | `hsync_transport.go:203-232` |
| Remote forwarding | `RemoteConfirmationDetail.RejectedItems` | `hsync_transport.go:234-241` |

The combiner already produces `RejectedItems` in 4 checkpoints in `ProcessUpdate()`. The agent just needs to produce the same structure.

### Design

**New function: `EvaluateRemoteSyncRecords()`** — called in the agent's remote SYNC processing path (in `syncheddataengine.go` or `agent_policy.go`). Unlike the current `EvaluateUpdate()` which is all-or-nothing, this function evaluates each record individually and returns:
- `accepted []dns.RR` — records that pass all policy checks
- `rejected []RejectedItemInfo` — records that fail, with per-record reasons

**Policy checks** (extensible, each is a function that takes a record + context and returns accept/reject):

1. **NS namespace policy** — For NS records: the RDATA (nameserver target) must be within the sending agent's own namespace. The agent knows the sender's identity from the SYNC message (`AgentID` field). The agent's namespace is derivable from its HSYNC identity (e.g., `agent.alpha.dnslab.` → namespace `alpha.dnslab.`). If the NS target is not a subdomain of the sender's namespace, reject with reason `"NS target <target> is outside sender's namespace <namespace>"`.

2. **DNSKEY key tag collision** — For DNSKEY records: check if the incoming key has the same key tag as any local (non-remote) DNSKEY. If collision:
   - If local key is in `created` or `published` state: prefer remote (it has propagated further), scrap local key, accept remote
   - If local key is `active`: reject with reason `"key tag collision with active local key <tag>"`
   - Compare full DNSKEY RDATA, not just key tags — identical keys from different sources should be accepted

3. **Additional policies** (future, not for initial implementation):
   - RRSIG validity checks
   - TTL sanity bounds
   - Record count limits per RRtype

**Integration point**: The agent's remote SYNC processing path currently calls `EvaluateUpdate()` and then forwards accepted records to the combiner. The new flow:

1. `EvaluateUpdate()` — existing coarse checks (RRtype, apex) — rejects entire update if fundamentally invalid
2. `EvaluateRemoteSyncRecords()` — **new** per-record policy evaluation — splits accepted from rejected
3. Forward only accepted records to combiner
4. Include rejected records in the confirmation response back to originating agent (using existing `RejectedItems` wire format)

### Key integration points

| File | Integration |
|------|-------------|
| `agent_policy.go` | New `EvaluateRemoteSyncRecords()` function with per-record policy checks |
| `syncheddataengine.go` | Call `EvaluateRemoteSyncRecords()` after `EvaluateUpdate()`, split records, populate `RejectedItems` in confirmation |
| `hsync_transport.go` | Agent-generated `RejectedItems` flow through existing confirmation path (no changes needed — already works for combiner-generated rejections) |

### Effort estimate

| Component | Lines |
|-----------|-------|
| `EvaluateRemoteSyncRecords()` framework | ~60-80 |
| NS namespace policy check | ~40-60 |
| DNSKEY key tag collision check | ~60-80 |
| Wire into remote SYNC processing path | ~40-60 |
| Tests | ~100-150 |
| **Total** | **~300-430** |

The rejection wire format is already fully implemented. This is primarily new policy logic + wiring into the existing processing path.

**Comparable to**: Extending the existing combiner-side `ProcessUpdate()` rejection pattern to the agent side. The individual policy checks are small; the framework to evaluate per-record and produce `RejectedItems` is the main new code.

---

## Combined Effort Summary

| Component | New Code | Files | Complexity | Comparable Phase |
|-----------|----------|-------|------------|-----------------|
| **A: Agent↔Signer signaling** | ~800-1150 | 2 new + 5 modified | Medium-High | Transport Unification 1c |
| **B: Signer DNSKEY handling** | ~510-830 | 0 new + 4-5 modified | Medium | Error Journal (Phase 6) |
| **C: Agent DNSKEY analysis** | ~360-550 | 1 new + 2-3 modified | Medium | HsyncChanged + KEYSTATE wiring |
| **D: HSYNC Sign check** | ~60-100 | 0 new + 1 modified | Low | Single policy gate |
| **E: General SYNC rejection** | ~300-430 | 0 new + 2-3 modified | Medium | Combiner ProcessUpdate pattern |
| **All combined** | **~2030-3060** | **3 new + 11-14 modified** | **Medium-High** | **~Transport Unification Phases 1-2** |

### Comparison to completed work

| Project | Lines | Files | Notes |
|---------|-------|-------|-------|
| JOSE/HPKE crypto (Phases 2+3) | ~1600 | 4 | New subsystem with tests |
| Reliable Message Queue + Confirmations (Phases 5-9) | ~2000 | 11 | New state machine + integration |
| Transport Unification Phase 1 (all sub-steps) | ~1500 | 8 | Architecture refactor |
| RPZ + DNSTAP (estimated, separate doc) | ~1600-2400 | 9-12 | New subsystem + cross-app wiring |
| **Distributed Multi-Signer (estimated)** | **~2030-3060** | **14-17** | **TransportManager wiring + DNSKEY coordination + SYNC rejection** |

---

## Risk Factors

1. **Key lifecycle state machine** — The interaction between signer key states, agent confirmation tracking, and remote propagation is a distributed coordination problem. Error cases need care: what if one provider never confirms? Timeout/fallback policy needed.

2. **Circular dependency in publish/activate** — Signer publishes DNSKEY → agent detects → SYNCs to remote → remote confirms → agent tells signer to activate. The "publish" and "activate" steps must be clearly separated. Publishing triggers the SYNC; activation waits for confirmation. The SYNC of a published key must not be confused with activation.

3. **SYNC rejection as a general protocol requirement** — The ability to reject individual records in a SYNC is not just a DNSKEY concern — it is a fundamental protocol requirement. Component E addresses this comprehensively. Key examples:
   - **DNSKEY key tag collision**: Different DNSKEY records can share the same key tag (rare but possible per RFC 4034 appendix B). When provider A SYNCs a new DNSKEY to provider B and B has its own key with the same tag, B must reject or resolve the collision.
   - **NS namespace policy**: An agent should not be able to claim nameservers inside another agent's namespace. E.g., agent.alpha adding `whisky.dnslab. IN NS ns7.ECHO.dnslab.` should be rejected by echo — alpha should not be asserting nameservers within echo's domain.
   - The rejection wire format (`RejectedItems`) already flows end-to-end through the confirmation protocol. What's missing is agent-side per-record policy evaluation on incoming remote SYNCs (see Component E).

4. **IXFR vs AXFR** — If the agent receives incremental transfers from the signer, DNSKEY changes appear as IXFR diffs. If AXFR, the agent compares the full RRset. Both paths need to work.

5. **Initialization ordering** — TransportManager for tdns-auth must start after key material is loaded but before zone signing begins.

6. **Accidental multi-provider activation** — Mitigated by the two-level config gate (see "Operational Mode" section above). Zone content (including HSYNC records) never triggers multi-provider behavior. Both `multi-provider.active: true` at server level AND `options: [multi-provider]` at zone level must be explicitly set. Validation at config load catches mismatches (zone with option but server inactive → error state).

---

## No New External Dependencies

All components use existing TDNS infrastructure: TransportManager, SYNC protocol, zone transfers, keystore, `core.RRsetDiffer()`. No new libraries needed.

---

## Suggested Implementation Order

1. **Component D first** (HSYNC Sign check) — trivially small, no dependencies, immediately useful. Ensures the signer respects the SIGN/NOSIGN policy before any multi-signer logic is added.

2. **Component E second** (general SYNC rejection) — independently useful for the existing agent↔agent SYNC protocol, even before multi-signer. Provides the NS namespace policy check and the per-record rejection framework that DNSKEY collision handling will use.

3. **Component B third** (signer DNSKEY merge) — small, self-contained, immediately useful. A signer that correctly includes remote DNSKEYs is the foundation for the coordination logic.

4. **Component A fourth** (agent↔signer signaling) — TransportManager for tdns-auth + KEYSTATE message type. Enables the coordination channel.

5. **Component C last** (agent DNSKEY analysis) — the coordination glue that ties B, A, and E together. Depends on A (KEYSTATE transport), B (signer understanding remote keys), and E (DNSKEY collision rejection).

## Phasing Sketch

**Phase 0**: HSYNC Sign field check (D)
- Check `Sign` field in `SignZone()` before signing
- Skip NOSIGN zones in ResignerEngine
- Pattern: copy from `agent_policy.go:63` NSmgmt check

**Phase 1**: General SYNC rejection (E)
- `EvaluateRemoteSyncRecords()` per-record policy framework
- NS namespace policy check (agent can only claim nameservers in its own namespace)
- DNSKEY key tag collision policy check
- Wire into remote SYNC processing path in `syncheddataengine.go`
- Agent-generated `RejectedItems` flow through existing confirmation path

**Phase 2**: Signer DNSKEY handling (B)
- Four-mode decision tree: `weAreASigner()` + `isMultiSigner()` checks
- Mode 3 (pass-through) is largely handled by Phase 0's Sign field check
- Remote DNSKEY detection in incoming zone (compare against local keystore, mode 4 only)
- Merge into DNSKEY RRset during signing (`PublishDnskeyRRs()`, mode 4 only)
- Preserve remote DNSKEYs across resignings

**Phase 3**: TransportManager for tdns-auth (A, part 1)
- Init TransportManager in tdns-auth `MainInit()`
- PING support for diagnostics
- Config + basic CLI (`auth peer ping`)

**Phase 4**: KEYSTATE message type (A, part 2)
- Message definition, handler, sender
- Key activation gating in keystore: dual-condition check (`propagation_confirmed` AND DNSKEY TTL expired since confirmation)

**Phase 5**: Agent DNSKEY tracker (C, part 1)
- `DnskeyChanged()` function (modeled on `HsyncChanged()`)
- Local/remote DNSKEY classification
- DNSKEY change → SYNC distribution to remote agents (not our own combiner — it only needs foreign DNSKEYs)

**Phase 6**: Propagation confirmation → KEYSTATE (C, part 2)
- Hook into `PendingRemoteConfirms` in `syncheddataengine.go`
- Send KEYSTATE `propagated` to signer on full confirmation
- Handle KEYSTATE `rejected` in signer: scrap key, regenerate, retry (rejection itself handled by Phase 1's DNSKEY collision policy)
- End-to-end key rollover flow verified (both happy path and collision path)

## Key Rollover Lifecycle (End-to-End)

### Happy path — ZSK rollover at provider A:

1. **Signer generates new ZSK** → state: `created`
2. **Signer publishes new ZSK** → state: `published`, DNSKEY added to zone
3. **Signer sends KEYSTATE `published`** to agent (key tag X, awaiting propagation)
4. **Agent detects new DNSKEY** in signed zone via XFR, classifies as local
5. **Agent SYNCs DNSKEY ADD** to remote agents (not to our own combiner — it only needs foreign DNSKEYs)
6. **Remote agents receive DNSKEY** → propagate to their combiner → signer → their signed zone
7. **Remote agents confirm SYNC** back to originating agent (two-phase confirmation)
8. **Agent sends KEYSTATE `propagated`** to signer (all N providers confirmed)
9. **Signer notes propagation confirmed** — records `propagation_confirmed_at` timestamp. But does NOT activate yet.
10. **Signer waits for DNSKEY TTL expiry** — old cached DNSKEY RRsets (without the new key) must expire from all caches worldwide. The wait is the DNSKEY RRset's TTL, counted from when the last provider confirmed (step 9).
11. **Signer activates key** → state: `active`, begins signing with new ZSK. Both prerequisites met: all providers confirmed AND TTL expired.
12. *(After old key's signatures expire)*
13. **Signer retires old ZSK** → state: `retired`, sends KEYSTATE `retired` to agent
14. **Agent SYNCs DNSKEY REMOVE** for old key to remote agents
15. **Remote agents confirm removal**
16. **Agent sends KEYSTATE `removed`** to signer
17. **Signer deletes old key** from keystore

### Key tag collision path:

1. Steps 1-5 as above: provider A publishes key with tag X, agent SYNCs to remote agents
2. **Remote agent B detects collision** (via Component E's DNSKEY key tag collision policy): incoming DNSKEY has key tag X, but provider B has its own unpublished/published key with the same tag X
3. **Resolution options** (in priority order):
   a. **Remote agent B scraps its own key**: If its local key with tag X is still in `created` or `published` state (not yet active), it can scrap the local key, accept provider A's key, regenerate its own key with a different tag. This is the preferred resolution — provider A's key has propagated further.
   b. **Remote agent B rejects**: If its local key with tag X is already `active` (can't be scrapped), it rejects the SYNC with reason `"key tag collision with active local key <tag>"` via `EvaluateRemoteSyncRecords()`. The `RejectedItems` field carries this through the existing confirmation flow.
4. **On rejection**: Originating agent receives the rejection in the SYNC confirmation
5. **Agent sends KEYSTATE `rejected`** to signer with the rejection reason
6. **Signer scraps key with tag X**, generates a new key with a different tag, and restarts from step 1
