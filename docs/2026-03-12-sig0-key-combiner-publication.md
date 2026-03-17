# SIG(0) Key Generation + Combiner-Mediated Publication for MP Zones

Date: 2026-03-12

## Problem

After winning a leader election, `onLeaderElected` (main_initfuncs.go) should generate a SIG(0) keypair and publish the KEY RR. Currently it bails out because it checks `delegationsync.child.schemes` for `"update"` — but that config controls *direct parent UPDATE*, not combiner-mediated publication.

For multi-provider zones with `parentsync=agent`, the agent should:

1. Generate a SIG(0) keypair (store in KeyStore)
2. Send the KEY RR to the combiner via UPDATE with REPLACE operation
3. Send a SYNC to remote agents so they add the KEY via their combiners
4. NOT attempt direct parent bootstrapping (that's a separate concern)

## Design

### Guard logic

The correct guard for SIG(0) key generation is:
- `OptDelSyncChild` — means `parentsync=agent` (HSYNCPARAM)
- **AND** parent supports UPDATE scheme — checked via live `LookupDSYNCTarget` against the parent's DSYNC RRset

The old guard (`delegationsync.child.schemes` config) controlled direct parent UPDATE and is not relevant for combiner-mediated publication.

### Key publication flow (onLeaderElected)

After key generation/import:
1. Get the active SIG(0) key from keystore
2. Call `PublishKeyToCombiner()` — sends REPLACE operation to combiner
3. Call `EnqueueForZoneAgents()` — sends KEY to remote agents for them to publish via their combiners

### Combiner acceptance

Add `dns.TypeKEY` to `AllowedRRtypePresets["apex-combiner"]` so the combiner's policy gate accepts KEY records.

### OnFirstLoad republication

The existing OnFirstLoad callback in `parseconfig.go` re-publishes persisted SIG(0) KEY to the combiner on restart. This is kept as-is — the REPLACE operation is idempotent, so it's a harmless no-op if the combiner already has the key, and essential if the combiner restarted.

## Files modified

| File | Change |
|------|--------|
| `main_initfuncs.go` | Replace config-based guard with DSYNC lookup; capture TransportManager; replace `delsyncq` send with `PublishKeyToCombiner` + `EnqueueForZoneAgents` |
| `combiner_utils.go` | Add `dns.TypeKEY` to apex-combiner preset |

## Status

- [ ] Implementation
- [ ] Testing
