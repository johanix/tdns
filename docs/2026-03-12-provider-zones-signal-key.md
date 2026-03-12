# Provider Zones in the Combiner — `_signal` KEY Publication

**Date**: 2026-03-12
**Status**: Implemented

## Context

The combiner managed only MP (multi-provider) zones with a hardcoded RRtype
whitelist (`DNSKEY, CDS, CSYNC, NS, KEY` at the apex). We needed it to also
manage **provider zones** — zones like `alpha.dnslab.` where agents insert
`_signal` KEY records for SIG(0) key discovery (RFC 9615).

Provider zones differ from MP zones:
- **MP zones**: Multiple agents contribute apex RRsets. Hardcoded RRtype
  restrictions. Combiner merges contributions.
- **Provider zones**: Agents make targeted edits (non-apex, specific RRtypes).
  Config-driven RRtype restrictions. Combiner applies edits and passes zone
  downstream.

## Design

### Zone class taxonomy

A `ZoneClass` string field travels with every UPDATE transaction:

| ZoneClass    | Meaning                          | RRtype policy                | Apex-only? |
|-------------|----------------------------------|------------------------------|------------|
| `"mp"` (default) | Multi-provider zone        | Hardcoded `AllowedRRtypePresets["apex-combiner"]` | Yes |
| `"provider"` | Provider infrastructure zone    | Config-driven per-zone       | No         |

Default: `"mp"` — existing transactions without a zone class are treated as MP.

### Wire format

`ZoneClass` added to all structs in the transaction pipeline:

```
ZoneUpdate → OutgoingMessage → deliverToCombiner → SyncRequest → DnsSyncPayload → AgentMsgPost → CombinerSyncRequest
```

Structs modified:
- `core.AgentMsgPost.ZoneClass`
- `transport.SyncRequest.ZoneClass`
- `DnsSyncPayload.ZoneClass`
- `ZoneUpdate.ZoneClass`
- `CombinerSyncRequest.ZoneClass`
- Local `AgentMsgPost.ZoneClass` (in `agent_structs.go`)

### YAML config

```yaml
combiner:
  provider-zones:
    - zone: alpha.dnslab.
      allowed-rrtypes: [KEY]
```

Struct: `ProviderZoneConf` in `config.go`, field `ProviderZones` on
`LocalCombinerConf`.

### Combiner policy enforcement

Both `CombinerProcessUpdate` (legacy path) and `combinerProcessOperations`
(operations path) in `combiner_chunk.go` branch on `req.ZoneClass`:

- **`"provider"`**: Look up per-zone allowed RRtypes from config via
  `GetProviderZoneRRtypes()`. Owner may be any name within the zone (not
  restricted to apex).
- **`"mp"` or empty**: Current behavior — hardcoded `AllowedLocalRRtypes`,
  apex-only.

Provider zone RRtype maps are registered during config parsing via
`RegisterProviderZoneRRtypes()` in `combiner_utils.go`.

### `_signal` KEY publication

`PublishSignalKeyToCombiner()` in `parentsync_leader.go`:
1. Constructs the `_signal` owner name: `_sig0key.{childZone}._signal.{ns}`
2. Finds the provider zone containing that name via `findProviderZone()`
3. Clones the KEY RR with the `_signal` owner name
4. Sends a REPLACE operation with `ZoneClass: "provider"` to the combiner

Called from two places:
- `onLeaderElected` in `main_initfuncs.go` — after SIG(0) key generation
- `OnFirstLoad` callback in `parseconfig.go` — idempotent republication on restart

## Files modified

| File | Change |
|------|--------|
| `core/messages.go` | Added `ZoneClass` to `AgentMsgPost` |
| `agent/transport/dns.go` | Added `ZoneClass` to `DnsSyncPayload`, propagated in `Sync()` |
| `agent/transport/transport.go` | Added `ZoneClass` to `SyncRequest` |
| `agent_structs.go` | Added `ZoneClass` to local `AgentMsgPost` |
| `syncheddataengine.go` | Added `ZoneClass` to `ZoneUpdate` |
| `hsync_transport.go` | Propagated `ZoneClass` in `deliverToCombiner` and `routeSyncMessage` |
| `combiner_chunk.go` | Added `ZoneClass` to `CombinerSyncRequest`; branched policy in both update paths |
| `combiner_utils.go` | Added `providerZoneRRtypes` registry, `RegisterProviderZoneRRtypes()`, `GetProviderZoneRRtypes()` |
| `config.go` | Added `ProviderZones []ProviderZoneConf` to `LocalCombinerConf`, `ProviderZoneConf` struct |
| `parseconfig.go` | Normalize + register provider zones in `normalizeConfigIdentities`; `_signal` KEY in `OnFirstLoad` |
| `parentsync_leader.go` | Added `PublishSignalKeyToCombiner()`, `findProviderZone()` |
| `main_initfuncs.go` | Added `_signal` KEY publication in `onLeaderElected` |

## Verification

1. Configure `alpha.dnslab.` as a provider zone in combiner config with `allowed-rrtypes: [KEY]`
2. Agent publishes `_signal` KEY via `PublishSignalKeyToCombiner` with `ZoneClass: "provider"`
3. Combiner accepts (KEY is in allowed list, non-apex owner is permitted)
4. `combiner zone edits list --zone alpha.dnslab.` shows the edit
5. Zone transfer downstream includes the `_signal` KEY record
6. Sending a non-KEY RRtype to the provider zone is rejected
7. MP zone behavior unchanged
