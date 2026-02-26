# RFI KEYSTATE: Agent Tickles Signer for Key Inventory

## Context

The agent cannot reliably distinguish local DNSKEYs (from its own signer) from remote DNSKEYs (from other providers' signers) when processing zone transfers. The zone received from the signer contains **all** merged DNSKEYs (local + remote via combiner). The current approach (`PopulateRemoteDNSKEYsFromRepo` in `hsync_utils.go:174`) has a chicken-and-egg problem: it relies on the ZoneDataRepo already containing correct per-agent data, which fails on first load and after restarts.

**Solution — the "tickle" pattern**: The signer is the single source of truth for key ownership (its KeyDB stores `state=created/published/standby/active/retired` for local keys, `state=foreign` for remote keys). The agent sends an **RFI KEYSTATE** (`MessageType: "rfi"`, `RfiType: "KEYSTATE"`) to "tickle" the signer into pushing a full **KEYSTATE inventory** message back. This is the same model as RFI SYNC → triggers resync.

**Flow**: Agent detects DNSKEY change → sends RFI KEYSTATE to signer → gets ACK → signer composes KEYSTATE inventory and pushes it to agent → agent receives it, populates `zd.RemoteDNSKEYs` from foreign keys → agent confirms back → `LocalDnskeysChanged` works correctly.

## Design principle: always send the complete inventory

KEYSTATE inventory messages always carry the **complete** set of keys for the zone — every key in the KeyDB regardless of state. The data is tiny (a handful of entries), the overhead is dominated by CHUNK framing and crypto, and by always sending the full set we eliminate an entire class of partial-state/missed-deletion bugs. The agent replaces its entire `RemoteDNSKEYs` from the inventory each time (no incremental updates).

## Architecture

### Key infrastructure facts (verified by exploration)

1. **Signer CAN send to agents**: Signer initializes a TransportManager with DNSTransport (`main_initfuncs.go:456-476`). Agent addresses are statically registered in PeerRegistry from `multi-provider.agents[]` config (`main_initfuncs.go:514-543`).

2. **`tm.DNSTransport.Keystate()` is symmetric**: Exists on all TransportManagers (`transport/dns.go:556-599`). Currently only called agent→signer via `sendKeystateToSigner()` (`hsync_transport.go:1574`), but signer→agent is mechanically identical.

3. **Current KEYSTATE is per-key**: `KeystateRequest` has single `KeyTag`+`Signal` (`transport/transport.go:208-216`). Signals: "propagated", "rejected", "removed" (agent→signer), "published", "retired" (signer→agent). This needs extending.

4. **Signer router doesn't handle RFI**: `InitializeSignerRouter` (`router_init.go:350-421`) only registers `ping` + `keystate`. The generic `HandleRfi` handler exists (`handlers.go:248-288`) but isn't registered.

5. **SignerMsgHandler is receive-only**: Consumes beat, hello, ping from MsgQs but does NOT read the `Msg` channel and never sends outbound messages.

6. **KeyDB key states**: `created`, `published`, `standby`, `active`, `retired` (local keys) + `foreign` (remote keys stored via `extractRemoteDNSKEYs`). Lifecycle: created → published → standby (propagated everywhere, safe for immediate rollover) → active → retired → removed. Queried via `GetDnssecKeys(zonename, state)` (`keystore.go:519`).

7. **Agent wait pattern**: The synchronous channel+timeout pattern from RFI SYNC (`hsyncengine.go:494-511`) works well — `SynchedDataCmd` with `Response` channel + 10s timeout.

8. **RFI is a first-class message type**: `MessageType: "rfi"` with `RfiType` subfield (UPSTREAM, DOWNSTREAM, SYNC, AUDIT). Sent via `SyncRequest` + `SendSyncWithFallback()`. Handler: `HandleRfi` ACKs and routes to MsgHandler.

### Part A: Extend KEYSTATE for full inventory (new signal: "inventory")

Add a new KEYSTATE signal `"inventory"` that carries the complete key set for a zone.

**New struct** (in `transport/transport.go`):
```go
type KeyInventoryEntry struct {
    KeyTag    uint16 `json:"key_tag"`
    Algorithm uint8  `json:"algorithm"`
    Flags     uint16 `json:"flags"`
    State     string `json:"state"` // "created","published","standby","active","retired","foreign"
}
```

**Extend `KeystateRequest`**: Add `KeyInventory []KeyInventoryEntry` field. When `Signal == "inventory"`, the inventory carries ALL keys for the zone. The existing `KeyTag`/`Algorithm` fields are unused for inventory messages.

**Extend `HandleKeystate`** (`handlers.go:290-363`): Accept "inventory" as valid signal. When signal is "inventory", validate that `KeyInventory` is present rather than requiring `KeyTag != 0`.

**Extend `AgentKeystatePost`** (`core/messages.go`): Add `KeyInventory` field for JSON wire format.

### Part B: Signer-side — receive RFI KEYSTATE, push inventory

**Step 1: Register RFI handler on signer router**

In `InitializeSignerRouter` (`router_init.go:350`): Add `HandleRfi` registration (same handler as agent). This routes RFI messages through existing middleware and delivers to SignerMsgHandler via `IncomingChan → MsgQs.Msg`.

**Step 2: SignerMsgHandler processes RFI KEYSTATE**

Add `case msg := <-msgQs.Msg:` to `SignerMsgHandler` (`signer_msg_handler.go:35`). When receiving an RFI with `RfiType == "KEYSTATE"`:
1. Query KeyDB for ALL keys for the requested zone across ALL states (created, published, standby, active, retired, foreign)
2. Build complete `[]KeyInventoryEntry` list
3. Send KEYSTATE "inventory" message back to the requesting agent

**Step 3: `sendKeystateInventoryToAgent()`**

New function in `signer_msg_handler.go`:
- Looks up agent peer in PeerRegistry
- Builds `KeystateRequest` with `Signal: "inventory"`, populated `KeyInventory`, zone
- Calls `tm.DNSTransport.Keystate(ctx, peer, req)` — symmetric with `sendKeystateToSigner()`

### Part C: Agent-side — receive inventory + synchronous wait

**Step 1: Route incoming KEYSTATE on agent**

KEYSTATE is missing from `routeIncomingMessage()` switch (`hsync_transport.go:403-416`). Add `case "keystate":` → `routeKeystateMessage()` that delivers inventory messages to a `KeystateInventoryChan` on MsgQs.

**Step 2: `RequestAndWaitForKeyInventory()`** — replaces `PopulateRemoteDNSKEYsFromRepo()`

In `hsync_utils.go`:
1. Send RFI KEYSTATE to signer (via new `sendRfiToSigner()`, same pattern as `sendRfiToAgent()`)
2. Wait on `KeystateInventoryChan` with timeout (15s)
3. On receive: build `zd.RemoteDNSKEYs` from entries where `State == "foreign"` (complete replacement, not incremental)
4. On timeout: log warning, fall back to empty RemoteDNSKEYs (conservative — treats all keys as local)

**Step 3: `sendRfiToSigner()`**

In `hsync_transport.go`:
- Get signer peer from config (`conf.Agent.Signer.Identity` / `conf.Agent.Signer.Address`)
- Build RFI message with `RfiType: "KEYSTATE"` and zone name
- Send via `tm.SendSyncWithFallback()` (same as `sendRfiToAgent()`)
- Return ACK (RFI just triggers the push; data comes separately)

## Files Modified

| File | Change |
|------|--------|
| `v2/agent/transport/transport.go` | Add `KeyInventoryEntry` struct. Add `KeyInventory` field to `KeystateRequest` |
| `v2/agent/transport/handlers.go` | Extend `HandleKeystate`: accept "inventory" signal, relax `KeyTag != 0` for inventory |
| `v2/agent/transport/router_init.go` | Register `HandleRfi` in `InitializeSignerRouter`. Update handler count |
| `v2/signer_msg_handler.go` | Add `case msg := <-msgQs.Msg:` for RFI KEYSTATE. Add `sendKeystateInventoryToAgent()` |
| `v2/hsync_transport.go` | Add `case "keystate":` to `routeIncomingMessage()`. Add `routeKeystateMessage()`. Add `sendRfiToSigner()` |
| `v2/hsync_utils.go` | Replace `PopulateRemoteDNSKEYsFromRepo` with `RequestAndWaitForKeyInventory()` |
| `v2/zone_utils.go` | Change call site: `PopulateRemoteDNSKEYsFromRepo()` → `RequestAndWaitForKeyInventory()` (line 373) |
| `v2/structs.go` | Add `KeystateInventoryChan` to MsgQs. Add `DnskeyStateStandby = "standby"` constant |
| `v2/core/messages.go` | Extend `AgentKeystatePost` with `KeyInventory` field for JSON wire format |

## What does NOT change

- `LocalDnskeysChanged` / `filterLocalDNSKEYs` — works the same, just gets correct input
- `SYNC-DNSKEY-RRSET` handler in hsyncengine — unchanged
- SynchedDataEngine — unchanged
- Combiner — unchanged
- Remote agent SYNC — unchanged
- `extractRemoteDNSKEYs` in sign.go — signer still uses it as before
- Existing per-key KEYSTATE signals (propagated/rejected/removed) — unchanged for now

## Implementation Order

1. Extend transport types (`transport.go`, `handlers.go`, `messages.go`) — foundation
2. Register RFI on signer router (`router_init.go`) — enable receiving
3. Signer RFI→KEYSTATE push (`signer_msg_handler.go`) — signer sends inventory
4. Agent routing of KEYSTATE (`hsync_transport.go`) — agent receives inventory
5. Agent RFI send + synchronous wait (`hsync_utils.go`, `zone_utils.go`, `hsync_transport.go`) — tie it together
6. Build and test

## Verification

1. `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make` — all 6 binaries build
2. Start signer, agent, combiner in multi-provider mode
3. Agent AXFRs zone from signer → detects DNSKEY change → sends RFI KEYSTATE to signer
4. Signer receives RFI, queries KeyDB, sends complete KEYSTATE inventory back to agent
5. Agent receives inventory, replaces `zd.RemoteDNSKEYs` from foreign entries
6. `show-synced-data` shows correct per-agent attribution (no DNSKEY duplication)
7. On agent restart: first zone load triggers DNSKEY change (empty→non-empty) → RFI KEYSTATE → correct classification
