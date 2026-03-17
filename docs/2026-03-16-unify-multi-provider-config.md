# Plan: Unify Multi-Provider Config Across Roles

## Context

Three separate config blocks (`agent:`, `combiner:`, `multi-provider:`) exist for the three MP roles. This prevents the combiner from reusing helpers like `analyzeHsyncSigners()` that rely on `Conf.MultiProvider.Agents`. Unifying into a single `multi-provider:` block with a `role:` field enables shared helpers and prepares for combiner safety guards (verifying zones are actually MP zones before accepting contributions).

**This is config restructuring only. No functional changes to combiner behavior.**

## Target State

All three roles use `multi-provider:` with `role: agent|combiner|signer`. `Conf.Agent` and `Conf.Combiner` are removed. `Conf.MultiProvider` is the single entry point.

## MPdata: Per-Zone MP State Cache

Add a single `MPdata *MPdata` field to `ZoneData`. For non-MP zones this is nil. For MP zones, populated during zone setup (where `analyzeHsyncSigners()` is already called). This avoids polluting `ZoneData` with many MP-specific fields.

```go
type MPdata struct {
    WeAreSigner  bool   // Are we listed as a signer in HSYNCPARAM?
    OurLabel     string // Our provider label from the matching HSYNC3 record
    OtherSigners int    // Count of other signers
}
```

**Where populated:** `zone_utils.go` lines 248 and 426, where `analyzeHsyncSigners()` is already called. Cache the results into `zd.MPdata` instead of discarding them.

**Where consumed:** Any code that currently calls `analyzeHsyncSigners()` or `weAreASigner()` can check `zd.MPdata` instead. Also serves as the natural gate for combiner safety checks — `if zd.MPdata == nil { zone is not MP, don't touch }`.

**Files:** `structs.go` (add field + type), `zone_utils.go` (populate), `hsync_utils.go` (callers can use cache)

## Migration Order: signer → combiner → agent

### Phase 1: Signer (smallest change — already uses `multi-provider:`)

**Changes to `MultiProviderConf` in `config.go`:**
- Add `Role string` field (`yaml:"role"`)
- Remove `HsyncIdentity` field (HSYNC identity derived by matching all agents' identities against HSYNC3 RRset — see `analyzeHsyncSigners` changes below)
- Rename `Api` to `SyncApi` (`yaml:"sync_api"`)
- Add `FindAgent()` method (copy from `LocalCombinerConf`)

**Changes to `hsync_utils.go`:**
- `analyzeHsyncSigners()`: Remove `HsyncIdentity` branch. For non-agent roles (`Conf.MultiProvider.Role != "agent"`), iterate ALL `Conf.MultiProvider.Agents` identities to find a matching HSYNC3 record. Any agent's identity may appear in the HSYNC3 RRset — it depends on the customer's configuration. The current `Agents[0]` shortcut is wrong because a provider may have multiple agents and only one may match the customer's HSYNC3.

**Changes to `config.go` `LocalIdentity()`:**
- Signer case (`default:`) already returns `conf.MultiProvider.Identity` — no change needed yet.

**Changes to `main_initfuncs.go`:**
- Signer init block: `conf.MultiProvider.Api` → `conf.MultiProvider.SyncApi` (a few refs)

**Changes to `parseconfig.go`:**
- Remove `HsyncIdentity` normalization
- Add `Role` validation: if `Globals.App.Type == AppTypeAuth` and `conf.MultiProvider != nil`, hard fail if `Role != "signer"`

**Config file:** `tdns-auth.sample.yaml`
- Add `role: signer`
- Remove `hsync-identity:` line
- Rename `api:` → `sync_api:` (under multi-provider block, if present)

**Files:** `config.go`, `hsync_utils.go`, `main_initfuncs.go`, `parseconfig.go`, `tdns-auth.sample.yaml`

### Phase 2: Combiner

**Absorb `LocalCombinerConf` fields into `MultiProviderConf` in `config.go`:**
- `ChunkQueryEndpoint`, `Signature`, `AddSignature`, `ProtectedNamespaces`, `ProviderZones` — add to `MultiProviderConf`
- These fields are only relevant when `role: combiner`
- `Agents []*PeerConf` already exists in `MultiProviderConf`
- `Identity`, `LongTermJosePrivKey`, `ChunkMode`, `ChunkMaxSize` already exist
- Remove `LocalCombinerConf` struct and `FindAgent()` method from it (now on `MultiProviderConf`)

**Changes to `Config` struct:**
- Remove `Combiner *LocalCombinerConf` field
- No migration bridge — config must use `multi-provider:` with `role: combiner`. Hard fail if old `combiner:` block is present.

**Migrate ~45 `conf.Combiner` references across 7 files:**
- `main_initfuncs.go` (~25 refs): `conf.Combiner.X` → `conf.MultiProvider.X`, nil checks become role checks
- `combiner_msg_handler.go` (~4 refs)
- `apihandler_combiner.go` (~5 refs)
- `apihandler_agent_distrib.go` (~3 refs)
- `keys_cmd.go` (2 refs)
- `parseconfig.go` (~5 refs)
- `config.go`: `LocalIdentity()` combiner case simplified

**`Globals.CombinerConf`:** Eliminate entirely. All callers migrate to `Conf.MultiProvider`. Check `global.go` and all read sites.

**`InjectSignatureTXT`:** Parameter type changes from `*LocalCombinerConf` to `*MultiProviderConf`. ~5 call sites.

**Config file:** `tdns-combiner.sample.yaml`
- `combiner:` block becomes `multi-provider:` with `role: combiner`
- All sub-keys stay the same except `api:` → `sync_api:`

**Files:** `config.go`, `global.go`, `main_initfuncs.go`, `combiner_msg_handler.go`, `apihandler_combiner.go`, `apihandler_agent_distrib.go`, `keys_cmd.go`, `parseconfig.go`, `combiner_utils.go`, `zone_utils.go`, `tdns-combiner.sample.yaml`

### Phase 3: Agent (largest — ~35 identity refs + sub-struct refs)

**Absorb `LocalAgentConf` fields into `MultiProviderConf` in `config.go`:**
- `SupportedMechanisms`, `Combiner *PeerConf`, `Signer *PeerConf`, `AuthorizedPeers`, `Peers` (deprecated), `Local`, `Remote`, `Syncengine`, `Api` (LocalAgentApiConf), `Dns` (LocalAgentDnsConf), `Xfr`
- Agent's `Api` (transport publication) keeps YAML key `api:` — no conflict because only one role is active per binary
- Remove `LocalAgentConf` struct

**Changes to `Config` struct:**
- Remove `Agent *LocalAgentConf` field

**Migrate ~35 `conf.Agent.Identity` references across 10 files:**
- All become `conf.MultiProvider.Identity`
- `apihandler_agent.go` (~12), `agent_setup.go` (~10), `main_initfuncs.go` (~5), `apihandler_agent_distrib.go` (~3), `syncheddataengine.go` (1), `hsyncengine.go` (1), `hsync_utils.go` (1), `apihandler_transaction.go` (1), `parseconfig.go` (2), `agent_utils.go` (1)

**Migrate other `conf.Agent.X` references:**
- `conf.Agent.Combiner` → `conf.MultiProvider.Combiner`
- `conf.Agent.Signer` → `conf.MultiProvider.Signer`
- `conf.Agent.Api` → `conf.MultiProvider.Api`
- `conf.Agent.Dns` → `conf.MultiProvider.Dns`
- `conf.Agent.Local`, `.Remote`, `.Syncengine`, `.Xfr` — same pattern
- Estimate ~50 additional references across `agent_setup.go`, `main_initfuncs.go`, `parseconfig.go`

**`Globals.AgentId`:** Keep the global. It's set once from `conf.MultiProvider.Identity` during init (currently set from `conf.Agent.Identity`). The ~15 consumption sites stay unchanged.

**`LocalIdentity()`:** Simplifies to just `conf.MultiProvider.Identity` for all roles.

**Config file:** `tdns-agent.sample.yaml`
- `agent:` block becomes `multi-provider:` with `role: agent`
- All sub-keys stay the same

**Files:** `config.go`, `agent_setup.go`, `apihandler_agent.go`, `main_initfuncs.go`, `apihandler_agent_distrib.go`, `syncheddataengine.go`, `hsyncengine.go`, `hsync_utils.go`, `apihandler_transaction.go`, `parseconfig.go`, `agent_utils.go`, `tdns-agent.sample.yaml`

### Phase 4: Cleanup

- Final `LocalIdentity()` simplification
- Verify no references to old types remain
- `gofmt` all modified files

## Risk Areas

1. **Agent `api:` vs combiner/signer `sync_api:`**: Different Go types, different YAML keys. No conflict since only one role active per binary.
2. **`Globals.App.Type` vs `conf.MultiProvider.Role`**: Both exist. Add validation that they agree during init.
3. **External apps (KDC, KRS)**: Use `TransportManager` but not `conf.Agent`/`conf.Combiner`. Should be unaffected. Verify they don't reference the removed fields.
4. **Config reload**: `Conf.MultiProvider` pointer is set once during init. Config reload via `ReloadZones` doesn't replace it. Safe for concurrent reads.

## Verification

After each phase:
1. `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make` — all binaries must build
2. Grep for removed field names to ensure no stale references
3. After Phase 3: grep for `conf.Agent` and `conf.Combiner` — should be zero hits
