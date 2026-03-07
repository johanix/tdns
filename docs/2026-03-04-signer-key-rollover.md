# Signer DNSSEC Key Rollover: State Machine and Lifecycle Management

**Date**: 2026-03-04
**Status**: Implemented

## Context

The TDNS signer previously had a completely static DNSKEY state machine. Keys were generated directly as "active" by `ensureActiveDnssecKeys()`, there were no automated state transitions, no key lifecycle goroutine, and no rollover mechanism. The tdns-kdc (Key Distribution Center in the tdns-nm repo) has a mature key state worker that served as the reference model.

This work adds:
- A full key lifecycle with automated time-based state transitions
- An `mpdist` state for multi-provider zones (keys pause until remote providers confirm)
- Signer-side handling of KEYSTATE "propagated" signals from agents
- A `KeyStateWorker` goroutine for background transitions and standby key maintenance
- A CLI `rollover` command for manual ZSK/KSK rollover
- Re-sign triggers at all state transition points

## Key State Machine

```
                     +-----------+
                     |  created  |
                     +-----+-----+
                           |
              +------------+------------+
              |                         |
         (non-MP zone)             (MP zone)
              |                         |
              v                         v
        +-----------+           +------------+
        | published |           |   mpdist   |  (awaiting agent "propagated" signal)
        +-----+-----+           +------+-----+
              |                        |
              |              (agent sends "propagated")
              |                        |
              |                        v
              |                  +-----------+
              +----------------->| published |
              |                  +-----+-----+
              |                        |
              |        (propagation_delay elapsed)
              |                        |
              v                        v
        +-----------+           +-----------+
        |  standby  |<----------+  standby  |
        +-----+-----+           +-----------+
              |
         (CLI rollover)
              |
              v
        +-----------+
        |  active   |  (used for signing)
        +-----+-----+
              |
         (CLI rollover: old active)
              |
              v
        +-----------+
        |  retired  |  (still in DNSKEY RRset, RRSIGs expiring)
        +-----+-----+
              |
              |  (propagation_delay elapsed)
              v
        +-----------+
        |  removed  |  (kept in DB for audit trail, excluded from DNSKEY RRset)
        +-----------+

        +-----------+
        |  foreign  |  (remote provider keys, never rolled by us)
        +-----------+
```

## DNSKEY RRset Composition

Keys included in the published DNSKEY RRset (visible to resolvers):
- `mpdist` (MP zones: key being distributed to peers)
- `published` (propagating through caches)
- `standby` (ready for rollover)
- `active` (currently signing)
- `retired` (old signatures still valid)
- `foreign` (remote provider keys)

Keys excluded:
- `created` (not yet staged)
- `removed` (lifecycle complete)

## Automated Transitions (KeyStateWorker)

The `KeyStateWorker` goroutine runs on a configurable ticker and performs three checks:

1. **published -> standby**: Keys where `time.Since(published_at) >= propagation_delay`
2. **retired -> removed**: Keys where `time.Since(retired_at) >= propagation_delay`
3. **Standby key maintenance**: For each signing zone, ensures the configured number of standby keys exist for both ZSKs and KSKs. Pipeline-aware: won't generate new keys if `published` or `mpdist` keys of that type are already in flight.

### KASP Configuration

```yaml
kasp:
    propagation_delay: 1h       # time for DNSKEY RRset to propagate through caches
    standby_key_count: 1        # standby keys per type (ZSK + KSK) per zone
    check_interval: 1m          # KeyStateWorker tick rate
```

All values have sensible defaults if omitted.

## Multi-Provider Flow (mpdist state)

For zones with `OptMultiProvider`, new keys are staged as `mpdist` instead of `published`. The flow:

1. `KeyStateWorker` calls `GenerateAndStageKey()` which creates the key as `created`, then transitions to `mpdist`
2. The key appears in the DNSKEY RRset and KEYSTATE inventory
3. Agent receives the inventory and distributes the DNSKEY to other providers
4. Agent sends a KEYSTATE "propagated" signal back to the signer
5. `SignerMsgHandler` receives the signal via the dedicated `KeystateSignal` channel
6. Signer calls `SetPropagationConfirmed()` + `TransitionMpdistToPublished()`
7. From `published`, the normal time-based pipeline continues

For non-MP zones, `GenerateAndStageKey()` skips `mpdist` and goes directly to `published`.

## Manual Rollover (CLI)

```
tdns-cliv2 keystore dnssec rollover --zone example.com. [--keytype ZSK|KSK]
```

Default keytype is ZSK. The rollover:
1. Finds the active key of the specified type (error if none)
2. Finds a standby key of the specified type (error if none)
3. In a transaction: standby -> active, active -> retired (sets `retired_at`)
4. Triggers zone re-sign via `ResignQ`

The retired key remains in the DNSKEY RRset until `KeyStateWorker` transitions it to `removed` after `propagation_delay`.

## Re-sign Triggers

All state transitions trigger a zone re-sign to refresh the DNSKEY RRset:

| Location | Trigger | File |
|----------|---------|------|
| KeyStateWorker | published->standby, retired->removed | `key_state_worker.go` |
| SignerMsgHandler | mpdist->published (on "propagated" signal) | `signer_msg_handler.go` |
| API keystore handler | After successful rollover | `apihandler_funcs.go` |

All use `triggerResign()` which sends the zone to `conf.Internal.ResignQ` (non-blocking with warning on full queue).

## DB Schema Changes

Added columns to `DnssecKeyStore`:
- `published_at TEXT DEFAULT ''` — set when transitioning to `published` state
- `retired_at TEXT DEFAULT ''` — set when transitioning to `retired` state

Existing databases are migrated automatically via `ALTER TABLE ADD COLUMN`.

## Files Modified

| File | Changes |
|------|---------|
| `structs.go` | Added `DnskeyStateMpdist`, `DnskeyStateRemoved` constants |
| `db_schema.go` | Added `published_at`, `retired_at` columns |
| `db.go` | Added migration entries |
| `keystore.go` | `DnssecKeyWithTimestamps`, `GetDnssecKeysByState`, `UpdateDnssecKeyState`, `GenerateAndStageKey`, `TransitionMpdistToPublished`, `RolloverKey`, "rollover" case in `DnssecKeyMgmt` |
| `ops_dnskey.go` | Updated DNSKEY RRset query to include mpdist/standby |
| `config.go` | `KaspConf` struct, `KeystateSignalMsg` struct, `KeystateSignal` channel in `MsgQs` |
| `hsync_transport.go` | Route non-inventory KEYSTATE signals to `KeystateSignal` channel |
| `signer_msg_handler.go` | Handle "propagated"/"rejected" signals, re-sign trigger |
| `key_state_worker.go` | New file: `KeyStateWorker` goroutine |
| `main_initfuncs.go` | Initialize `KeystateSignal` channel, register `KeyStateWorker` engine |
| `apihandler_funcs.go` | `APIkeystore` accepts `conf`, re-sign trigger after rollover |
| `apirouters.go` | Pass `conf` to `APIkeystore` |
| `cli/keystore_cmds.go` | `keystoreDnssecRolloverCmd` command |
| `cli/prepargs.go` | Added mpdist/standby/removed to valid states |

## Design Decisions

1. **`ensureActiveDnssecKeys` unchanged**: Remains as bootstrap safety net. Generates directly as `active` when no active keys exist. Normal key pipeline flows through `KeyStateWorker`.

2. **No automatic rotation**: `KeyStateWorker` maintains the standby pipeline but rollover is always manual via CLI. This avoids surprises in production.

3. **Dedicated `KeystateSignal` channel**: Same pattern as `KeystateInventory` and `EditsResponse`. Cleaner than demuxing inside the `Msg` channel.

4. **Removed keys kept in DB**: State `removed` rows stay for audit trail, matching the KDC pattern.

5. **Single `propagation_delay`**: Used for both published->standby and retired->removed. Simplifies config while being correct (both transitions wait for cache expiry).

6. **Pipeline awareness**: `KeyStateWorker` won't generate new keys if `published` or `mpdist` keys of the same type are already in the pipeline, preventing key accumulation.

7. **Both KSK and ZSK**: Standby maintenance covers both key types, and the rollover command supports either via `--keytype`.
