# MP Removal from tdns: Detailed Plan

**Date**: 2026-03-30
**Scope**: Remove all multi-provider (MP) functionality from the `tdns`
repository, leaving `tdns-authv2` and `tdns-agentv2` as simplified,
standalone authoritative DNS servers.

## 1. Goal

Strip the tdns repo of all MP code: the combiner app entirely, and
all MP machinery from both tdns-authv2 (signer role) and
tdns-agentv2 (agent role). After removal, both apps become standard
authoritative DNS servers with DNSSEC signing, zone refresh, UPDATE
handling, and delegation sync — but without inter-agent
communication, combiner coordination, gossip, leader election, or
the SynchedDataEngine.

MP functionality continues to exist in the `tdns-mp` repo, which
imports `tdns/v2` as a library and layers MP on top.

## 2. What Stays vs What Goes

### 2.1 Engines in tdns-authv2

| Engine | Verdict | Reason |
|--------|---------|--------|
| APIdispatcher | KEEP | Admin HTTP API |
| ValidatorEngine | KEEP | DNSSEC validation |
| ImrEngine | KEEP | Internal mini-recursor |
| RefreshEngine | KEEP | Zone refresh from primary |
| Notifier | KEEP | NOTIFY to secondaries |
| AuthQueryEngine | KEEP | Authoritative query serving |
| ScannerEngine | KEEP | CSYNC/DSYNC scanning |
| ZoneUpdaterEngine | KEEP | DNS UPDATE processing |
| DeferredUpdaterEngine | KEEP | Deferred update queue |
| UpdateHandler | KEEP | UPDATE protocol handler |
| KeyBootstrapper | KEEP | DNSSEC key trust bootstrap |
| DelegationSyncher | KEEP | RFC delegation sync (CDS/CSYNC) |
| NotifyHandler | KEEP | Incoming NOTIFY handler |
| DnsEngine | KEEP | UDP/TCP DNS server |
| ResignerEngine | KEEP | DNSSEC re-signing |
| KeyStateWorker | KEEP | DNSSEC key lifecycle (RFC 7583) |
| SignerMsgHandler | **REMOVE** | MP transport message consumer |
| SignerAPIdispatcherNG | **REMOVE** | MP HTTPS sync API |
| IncomingMessageRouter | **REMOVE** | MP message routing |

### 2.2 Engines in tdns-agentv2

| Engine | Verdict | Reason |
|--------|---------|--------|
| APIdispatcher | KEEP | Admin HTTP API |
| ImrEngine | KEEP | Internal mini-recursor |
| RefreshEngine | KEEP | Zone refresh from primary |
| Notifier | KEEP | NOTIFY to secondaries |
| AuthQueryEngine | KEEP | Authoritative query serving |
| ScannerEngine | KEEP | CSYNC/DSYNC scanning |
| ZoneUpdaterEngine | KEEP | DNS UPDATE processing |
| DeferredUpdaterEngine | KEEP | Deferred update queue |
| UpdateHandler | KEEP | UPDATE protocol handler |
| NotifyHandler | KEEP | Incoming NOTIFY handler |
| DnsEngine | KEEP | UDP/TCP DNS server |
| DelegationSyncher | KEEP | RFC delegation sync |
| HsyncEngine | **REMOVE** | MP agent coordination loop |
| InfraBeatLoop | **REMOVE** | Heartbeats to combiner/signer |
| DiscoveryRetrierNG | **REMOVE** | Agent discovery retries |
| SynchedDataEngine | **REMOVE** | Zone sync to combiner/agents |
| APIdispatcherNG | **REMOVE** | Agent-to-agent HTTPS sync API |
| CHUNK handler | **REMOVE** | MP transport mechanism |
| IncomingMessageRouter | **REMOVE** | MP message routing |
| ReliableMessageQueue | **REMOVE** | MP reliable delivery |
| LeaderElectionManager | **REMOVE** | MP leader election |
| ProviderGroupManager | **REMOVE** | MP provider groups |
| OnLeaderElected callbacks | **REMOVE** | MP leadership actions |

### 2.3 Apps

| App | Verdict |
|-----|---------|
| tdns-authv2 | KEEP (simplified) |
| tdns-agentv2 | KEEP (simplified) |
| tdns-combinerv2 | **DELETE entirely** |

## 3. File Inventory

### 3.1 Files to DELETE entirely (PURE-MP)

All pure-MP files have been renamed with the `legacy_` prefix to
make them visually distinct from active code. They will be deleted
when MP extraction testing is complete.

**v2/ root** (28 files, all `legacy_`-prefixed):
- `legacy_agent_authorization.go`
- `legacy_agent_discovery.go`
- `legacy_agent_discovery_common.go`
- `legacy_agent_policy.go`
- `legacy_agent_setup.go`
- `legacy_agent_structs.go`
- `legacy_agent_utils.go`
- `legacy_apihandler_combiner.go`
- `legacy_apihandler_combiner_distrib.go`
- `legacy_combiner_chunk.go`
- `legacy_combiner_msg_handler.go`
- `legacy_combiner_peer.go`
- `legacy_combiner_utils.go`
- `legacy_db_combiner_contributions.go`
- `legacy_db_combiner_edits.go`
- `legacy_db_combiner_publish_instructions.go`
- `legacy_gossip.go`
- `legacy_hsync_beat.go`
- `legacy_hsync_hello.go`
- `legacy_hsync_infra_beat.go`
- `legacy_hsync_transport.go`
- `legacy_hsync_utils.go`
- `legacy_hsyncengine.go`
- `legacy_provider_groups.go`
- `legacy_signer_msg_handler.go`
- `legacy_signer_peer.go`
- `legacy_signer_transport.go`
- `legacy_syncheddataengine.go`

**v2/cli/** (12 files, all `legacy_`-prefixed):
- `legacy_agent_cmds.go`
- `legacy_agent_debug_cmds.go`
- `legacy_agent_edits_cmds.go`
- `legacy_agent_gossip_cmds.go`
- `legacy_agent_imr_cmds.go`
- `legacy_agent_router_cmds.go`
- `legacy_agent_router_cmds_test.go`
- `legacy_agent_zone_cmds.go`
- `legacy_combiner_cmds.go`
- `legacy_combiner_debug_cmds.go`
- `legacy_combiner_edits_cmds.go`
- `legacy_combiner_peer_cmds.go`

**cmdv2/combinerv2/** (entire directory):
- `main.go`, `defaults.go`, `version.go`, `Makefile`, `go.mod`,
  `go.sum`, config files

### 3.2 Files to EDIT (MIXED — contains both MP and non-MP code)

These files have MP-specific sections that must be removed while
preserving the non-MP functionality:

**Configuration & init:**
- `config.go` — Remove `MultiProviderConf`, `MsgQs`,
  `InternalMpConf`, `PeerConf`, `ProviderZoneConf`,
  `CombinerOption`, `SignerOption`, `AgentOption` structs.
  Remove `LocalIdentity()` method. Keep generic DNS config.
- `config_validate.go` — Remove MP validation sections
  (combiner/signer/agent role checks).
- `main_initfuncs.go` — Gut MP sections from `MainInit()` (agent
  case, auth/combiner case for transport init). Remove
  `StartCombiner()` entirely. Clean up `StartAuth()` (remove
  SignerMsgHandler, SignerAPIdispatcherNG, IncomingMessageRouter).
  Clean up `StartAgent()` (remove all MP engines listed in §2.2).
- `parseconfig.go` — Remove MP config parsing (MultiProvider
  section, agent/combiner/signer peers, MP zone options).
- `parseoptions.go` — Remove `OptMultiProvider` option handling.

**Enums & structs:**
- `enums.go` — Remove `AppTypeCombiner`, `AppTypeMPSigner`,
  `AppTypeMPAgent`, `AppTypeMPCombiner`. Remove `OptMultiProvider`,
  `OptMPManualApproval`, `OptMultiSigner`, `OptMPNotListedErr`,
  `OptMPDisallowEdits`. Remove corresponding string mappings.
- `structs.go` — Remove `MPdata`, `ZoneMPExtension` (or reduce
  to only non-MP fields like `RefreshAnalysis`). Remove
  `KeyInventorySnapshot`.

**API handlers:**
- `apihandler_agent.go` — Remove MP-specific endpoints
  (hello/beat/ping/sync/update/rfi handlers). Keep generic zone
  query/update API if any.
- `apihandler_agent_distrib.go` — Remove distribution tracking
  API. This is entirely MP.
- `apihandler_agent_router.go` — Remove MP sync router setup.
- `apihandler_transaction.go` — Remove `CombinerState` reference.
- `apihandler_zone.go` — Remove `OptMultiProvider` check.
- `apirouters.go` — Remove combiner/agent MP API route
  registration.

**Signing/DNSSEC (light edits — remove MP gates only):**
- `sign.go` — Remove `OptMultiProvider` gate in signing path.
  All zones sign normally without MP checks.
- `resigner.go` — Remove signer-role check (`weAreASigner()`).
  All zones re-sign normally.
- `key_state_worker.go` — Remove `mpremove`/`mpdist` states.
  Remove `OptMultiProvider`/signer checks. Simplify to pure
  RFC 7583 key lifecycle.
- `keystore.go` — Remove MP role check in key acquisition.
- `keys_cmd.go` — Remove combiner/signer role conditionals.

**Zone/data:**
- `zone_utils.go` — Remove MP-aware zone type checks.
- `delegation_sync.go` — Remove leader election guard (without
  MP, there is only one instance — it is always "the leader").
  Remove `OptMultiProvider` check.
- `hsync_utils.go` — This is mostly MP. May become deletable
  after removing MP references. If any non-MP HSYNC3/HSYNCPARAM
  parsing remains needed, keep only that.

**Database:**
- `db_hsync.go` — Remove MP-specific tables (peer sync ops,
  confirmations, events) if not needed for HSYNC3 RR storage.
- `db_schema_hsync.go` — Remove MP-specific schema definitions.

**CLI:**
- `cli/jose_keys_cmds.go` — Remove combiner role check.
- `cli/hsync_cmds.go` — Keep HSYNC3/HSYNCPARAM RR management
  commands (still used for zone data). Remove MP-specific
  sub-commands if any.
- `cli/distrib_cmds.go` — Likely entirely MP; evaluate if
  anything remains.

### 3.3 Files that need NO changes (NON-MP)

All remaining ~80 files in v2/ and ~30 files in v2/cli/ are pure
DNS/DNSSEC functionality and require no modification.

## 4. External Dependencies

### 4.1 tdns-transport package

The `github.com/johanix/tdns-transport/v2` dependency is **entirely
MP-specific** in tdns. All imports are in MP files or in MP-guarded
sections of mixed files. After removing all MP code, this dependency
can be removed from `go.mod` entirely.

Check: after all deletions, run `go mod tidy` and verify
tdns-transport is no longer required.

### 4.2 JOSE/crypto imports

`crypto/jose` from tdns-transport is used for CHUNK encryption
(MP-only). After MP removal, these imports disappear with the
deleted files.

`keys_cmd.go` uses `jose.NewBackend()` for key generation — this
may need to move to a different import or be removed if SIG(0) key
generation doesn't need JOSE. Evaluate during implementation.

## 5. Implementation Order

The removal must be done in a careful sequence to keep the code
compiling at each step. Each phase ends with a successful build.

### Phase 1: Delete the combiner app

**What**: Delete `cmdv2/combinerv2/` entirely.

**Verification**: The combiner is a standalone binary. Deleting it
does not affect tdns-authv2 or tdns-agentv2 compilation.

**Build check**: `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
(combiner target will fail — remove it from Makefile first, or
just verify auth+agent targets build).

### Phase 2: Delete pure-MP files that are only referenced by other pure-MP files

Delete files in dependency order — leaves before branches.

**Step 2.1**: Delete combiner-specific files (no non-combiner
references):
- `legacy_db_combiner_contributions.go`
- `legacy_db_combiner_edits.go`
- `legacy_db_combiner_publish_instructions.go`
- `legacy_apihandler_combiner.go`
- `legacy_apihandler_combiner_distrib.go`
- `legacy_combiner_utils.go`
- `legacy_combiner_msg_handler.go`
- `legacy_combiner_chunk.go`
- `legacy_combiner_peer.go`
- `legacy_signer_peer.go`
- `legacy_signer_transport.go`
- `legacy_signer_msg_handler.go`
- `cli/legacy_combiner_cmds.go`
- `cli/legacy_combiner_debug_cmds.go`
- `cli/legacy_combiner_edits_cmds.go`
- `cli/legacy_combiner_peer_cmds.go`

**Verification**: These files are only called from MP code paths.
After deletion, fix any remaining references in mixed files
(mainly `main_initfuncs.go` calling `StartCombiner`,
`CombinerMsgHandler`, `SignerMsgHandler`).

**Step 2.2**: Delete agent MP leaf files (called only from
hsyncengine/hsync_transport):
- `legacy_agent_authorization.go`
- `legacy_agent_discovery.go`
- `legacy_agent_discovery_common.go`
- `legacy_agent_policy.go`
- `legacy_agent_setup.go`
- `legacy_gossip.go`
- `legacy_provider_groups.go`
- `legacy_hsync_beat.go`
- `legacy_hsync_hello.go`
- `legacy_hsync_infra_beat.go`

**Step 2.3**: Delete agent MP core files:
- `legacy_hsync_utils.go`
- `legacy_hsyncengine.go`
- `legacy_hsync_transport.go` (MPTransportBridge — the big one)
- `legacy_syncheddataengine.go`
- `legacy_agent_structs.go`
- `legacy_agent_utils.go`

**Step 2.4**: Delete agent MP CLI files:
- `cli/legacy_agent_cmds.go`
- `cli/legacy_agent_debug_cmds.go`
- `cli/legacy_agent_edits_cmds.go`
- `cli/legacy_agent_gossip_cmds.go`
- `cli/legacy_agent_imr_cmds.go`
- `cli/legacy_agent_router_cmds.go`
- `cli/legacy_agent_router_cmds_test.go`
- `cli/legacy_agent_zone_cmds.go`

**Build check**: Will NOT compile yet — mixed files still
reference deleted types/functions. This is expected.

### Phase 3: Clean up mixed files (make it compile)

This is the most labor-intensive phase. Work through each mixed
file, removing MP references. Order matters — start with types
(enums, structs, config) then functions.

**Step 3.1**: Clean enums and types
- `enums.go`: Remove MP AppType and ZoneOption constants +
  string mappings.
- `structs.go`: Remove `MPdata`, `ZoneMPExtension` (keep
  `RefreshAnalysis` if used by non-MP code — move it to
  `ZoneData` directly). Remove `KeyInventorySnapshot`.
- `config.go`: Remove `MultiProviderConf`, `MsgQs`,
  `InternalMpConf` fields, `PeerConf`, `ProviderZoneConf`,
  combiner/signer/agent option types. Remove `LocalIdentity()`.
  Clean `InternalConf` to remove MP fields (TransportManager,
  MPTransport, AgentRegistry, ZoneDataRepo, CombinerState,
  LeaderElectionManager, MsgQs, MPZoneNames,
  DistributionCache, ChunkPayloadStore).

**Step 3.2**: Clean config parsing
- `parseconfig.go`: Remove parsing of `multi_provider:` YAML
  section, agent/combiner/signer peer configs, MP zone options.
  Remove `PostParseZonesHook` if it is MP-only.
- `parseoptions.go`: Remove `OptMultiProvider` handling.
- `config_validate.go`: Remove MP validation (role checks,
  identity validation, peer verification).

**Step 3.3**: Clean init and startup functions
- `main_initfuncs.go`:
  - `MainInit()`: Remove the entire `case AppTypeAgent:` MP
    setup block (AgentRegistry init, CombinerState, HSYNC
    tables, DistributionCache, TransportManager creation,
    peer registration). Remove the `case AppTypeAuth,
    AppTypeCombiner:` MP setup block (transport init, CHUNK
    handler, signer router). Remove MP AppType checks
    (`AppTypeMPSigner`, `AppTypeMPAgent`, `AppTypeMPCombiner`).
    Remove zone option handler for `OptMultiProvider`.
  - Delete `StartCombiner()` entirely.
  - `StartAuth()`: Remove SignerMsgHandler, KeyStateWorker MP
    guard (keep KeyStateWorker but remove `AppTypeMPSigner`
    check), SignerAPIdispatcherNG, IncomingMessageRouter.
  - `StartAgent()`: Remove all MP engine starts (CHUNK handler,
    IncomingMessageRouter, combiner/signer peer init, RMQ,
    LeaderElectionManager, ProviderGroupManager, all
    OnFirstLoad MP callbacks, OnLeaderElected, HsyncEngine,
    InfraBeatLoop, DiscoveryRetrierNG, SynchedDataEngine,
    APIdispatcherNG). Keep only: APIdispatcher, ImrEngine,
    RefreshEngine, Notifier, AuthQueryEngine, ScannerEngine,
    ZoneUpdaterEngine, DeferredUpdaterEngine, UpdateHandler,
    DelegationSyncher, NotifyHandler, DnsEngine.

**Step 3.4**: Clean API handlers
- `apirouters.go`: Remove combiner/agent MP route registration.
- `apihandler_agent.go`: Remove MP endpoints. Keep any generic
  agent status/zone endpoints if they exist independently.
  Likely most of this file is deletable.
- `apihandler_agent_distrib.go`: Evaluate — may be entirely
  deletable.
- `apihandler_agent_router.go`: Likely entirely deletable.
- `apihandler_transaction.go`: Remove CombinerState reference.
- `apihandler_zone.go`: Remove OptMultiProvider check.

**Step 3.5**: Clean DNSSEC files (light edits)
- `sign.go`: Remove OptMultiProvider gate. All zones sign.
- `resigner.go`: Remove `weAreASigner()` gate.
- `key_state_worker.go`: Remove mpremove/mpdist states and
  OptMultiProvider/signer guards. Pure RFC 7583 lifecycle.
- `keystore.go`: Remove MP role check.
- `keys_cmd.go`: Remove combiner/signer conditionals.
- `keybootstrapper.go`: Verify no MP references (should be
  clean already).
- `delegation_sync.go`: Remove leader election guard (single
  instance = always leader). Remove OptMultiProvider check.

**Step 3.6**: Clean zone/data files
- `zone_utils.go`: Remove MP zone type checks.
- `db_hsync.go`: Remove MP-specific tables. Keep HSYNC3/
  HSYNCPARAM storage if still needed for zone data.
- `db_schema_hsync.go`: Match db_hsync.go changes.

**Step 3.7**: Clean CLI files
- `cli/jose_keys_cmds.go`: Remove combiner role check.
- `cli/hsync_cmds.go`: Keep HSYNC3/HSYNCPARAM RR management.
- `cli/distrib_cmds.go`: Evaluate — may be entirely deletable.

**Build check**: `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
— both tdns-authv2 and tdns-agentv2 must compile.

### Phase 4: Remove external dependency

**Step 4.1**: Run `go mod tidy` in `tdns/v2/` to drop
tdns-transport.

**Step 4.2**: If `keys_cmd.go` still needs JOSE key generation,
either:
- (a) Move that functionality to a local package, or
- (b) Keep a minimal jose import from a different source, or
- (c) Remove JOSE key generation from tdns CLI entirely (it
  can live in tdns-mp CLI).

**Build check**: Full build + `go mod tidy` clean.

### Phase 5: Clean up Makefile and build

- Remove combiner target from `cmdv2/Makefile`.
- Verify all remaining targets build cleanly.
- Remove combiner sample configs from cmdv2/.

### Phase 6: Verification

**6.1 Compilation**: Both binaries build without errors.

**6.2 Startup smoke test** (on build server):
- tdns-authv2 starts with a config containing only standard
  zones (no `multi_provider:` section).
- tdns-agentv2 starts with a config containing only standard
  zones.
- Both serve DNS queries for their configured zones.
- Both accept zone transfers.
- Both handle DNS UPDATE.
- DNSSEC signing works (tdns-authv2).
- Delegation sync works (CDS/CSYNC to parent).

**6.3 Negative tests**:
- Config with `multi_provider:` section is rejected (or
  ignored) gracefully — no crash.
- Zone option `multi-provider` is rejected (or ignored) —
  no crash.

**6.4 Code hygiene**:
- `go vet ./...` passes.
- `staticcheck ./...` passes (no U1000 for intentionally
  kept code — ask before removing anything flagged).
- No stale imports remain.
- No dead code referencing deleted types.

## 6. Risk Assessment

### Low risk
- Deleting the combiner app (standalone, no dependents).
- Deleting pure-MP files (leaf files with no non-MP callers).
- Removing MP engines from StartAuth/StartAgent.

### Medium risk
- Cleaning `config.go` / `structs.go` — these are central to
  all apps. Must be careful not to break non-MP fields.
- Cleaning `main_initfuncs.go` — contains interleaved MP and
  non-MP init. Easy to accidentally remove something needed.
- Cleaning `parseconfig.go` — YAML parsing is fragile; removing
  struct fields must match YAML tag removal.

### Mitigation
- Build after every step (not just every phase).
- Review each mixed file diff carefully before proceeding.
- Keep a branch; don't squash until verified on build server.
- If a step introduces too many compilation errors to fix at
  once, split it further.

## 7. Estimated Scope

| Category | Files | Rough Lines |
|----------|-------|-------------|
| Delete entirely | ~40 files | ~15,000 lines |
| Edit (remove MP sections) | ~25 files | ~3,000 lines removed |
| **Total removal** | **~65 files** | **~18,000 lines** |

## 8. Post-Removal State

After completion, tdns/v2 provides:
- Authoritative DNS server (UDP/TCP/DOH/DOQ/DOT)
- DNSSEC signing with automatic key lifecycle (RFC 7583)
- Zone refresh (primary/secondary)
- DNS UPDATE (RFC 2136) with SIG(0)
- NOTIFY (RFC 1996)
- Delegation sync (CDS/CSYNC/DSYNC to parent)
- HSYNC3/HSYNCPARAM RR types (zone data, no protocol)
- Catalog zones
- IMR (internal mini-recursor)
- Admin HTTP API
- CLI management tools

It does NOT provide:
- Inter-agent communication
- Combiner zone merging
- Agent discovery
- Gossip / provider groups
- Leader election
- SynchedDataEngine
- Reliable message queue
- CHUNK transport
- KEYSTATE signaling between agents/signer
- Distribution tracking

These capabilities live in `tdns-mp`, which imports `tdns/v2` and
layers MP functionality on top via the `AppTypeMPAgent`,
`AppTypeMPSigner`, `AppTypeMPCombiner` app types.
