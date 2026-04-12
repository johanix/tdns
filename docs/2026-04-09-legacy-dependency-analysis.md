# Legacy File Dependency Analysis — tdns/v2/legacy_*.go

**Date**: 2026-04-09, updated 2026-04-12
**Scope**: All `tdns/v2/legacy_*.go` files + `mptypes.go` (newly
reclassified as legacy)
**Goal**: Identify which legacy files can be deleted and which still
have non-legacy callers that must be cleaned up first. A file is
"legacy" if its *content* belongs in tdns-mp, not tdns — regardless
of whether non-legacy tdns code currently references it.

## Method

1. Extracted all exported symbols from each `legacy_*.go` file.
2. Grepped the entire `tdns-project/` tree for references.
3. Classified each reference as:
   - **Self-reference**: within another `legacy_*.go` file or
     `mptypes.go` (does not prevent deletion).
   - **Live v2 non-legacy reference**: from a non-legacy file in
     `tdns/v2/`. These are *tendrils* — MP-specific call sites in
     non-legacy code that must be cleaned up before deletion.
   - **Commented-out reference**: inside `/* */` or `//`. Does not
     count.
   - **tdns-mp/v2 reference**: tdns-mp defines its own parallel
     copies; these references don't keep tdns legacy files alive.

Note: **mptypes.go is now counted as legacy** for reference
classification (2026-04-12 update). References from mptypes.go
to other legacy files are self-references, not tendrils.

Critical lessons from the analysis:
- Grep hits in `main_initfuncs.go` were often inside `/* */` blocks.
- tdns-mp/v2 has local copies of almost every symbol — references
  from there resolve to the local copy.
- A file is legacy based on whether its *content* belongs in tdns-mp,
  not on whether it has zero callers. Non-legacy callers are tendrils
  to clean up, not proof of belonging.

## Parallel copies in tdns-mp/v2

The following symbols exist both in `tdns/v2/legacy_*.go` and as
local definitions in `tdns-mp/v2/`:

| Symbol                         | tdns-mp/v2 definition             |
|--------------------------------|-----------------------------------|
| `GetProviderZoneRRtypes`       | `combiner_utils.go:52`            |
| `RegisterProviderZoneRRtypes`  | `combiner_utils.go:39`            |
| `GetCombinerData`              | `combiner_utils.go:151`           |
| `GetCombinerDataNG`            | `combiner_utils.go:219`           |
| `NewMPTransportBridge`         | `hsync_transport.go:191`          |
| `MPTransportBridge` (type)     | `hsync_transport.go:45`           |
| `MPTransportBridgeConfig`      | `hsync_transport.go:126`          |
| `ProviderGroupManager` (type)  | `gossip_types.go:84`              |
| `NewProviderGroupManager`      | `provider_groups.go:22`           |
| `NewGossipStateTable`          | `gossip.go:40`                    |
| `LoadAllContributions`         | `db_combiner_contributions.go:63` |
| `RequestAndWaitForConfig`      | `hsync_utils.go:414`              |
| `RequestAndWaitForAudit`       | `hsync_utils.go:455`              |
| `MPPreRefresh`                 | `hsync_utils.go:1005` (diff sig)  |
| `MPPostRefresh`                | `hsync_utils.go:1141` (diff sig)  |

## ALREADY DELETED (3 files) + MOVED TO DEADCODE (2 files)

Deleted from the filesystem:

 1. `legacy_agent_setup.go`
 2. `legacy_chunk_query_handler.go`
 3. `legacy_chunk_store.go`

Moved to `deadcode_` with `//go:build ignore` (2026-04-12):

 4. `cli/hsync_cmds.go` → `cli/deadcode_hsync_cmds.go` — commands
    ported to tdns-mp/v2/cli/hsync_cmds.go
 5. `cli/hsync_debug_cmds.go` → `cli/deadcode_hsync_debug_cmds.go`
    — query command ported to tdns-mp

## The parentsync exception

`legacy_parentsync_leader.go` is tightly coupled to the provider
group / gossip / transport subsystem. It will remain in tdns
longer than the other legacy files because delegation_sync.go and
parentsync_bootstrap.go have deep `IsLeader()` dependencies.

**Critical finding:** keeping parentsync_leader forces us to also
keep its intra-legacy dependencies:

| Dependency | Reason | Calls |
|---|---|---|
| `legacy_provider_groups.go` | `GetGroup`, `GetGroupForZone` | 9 calls |
| `legacy_gossip.go` | `GroupElectionState` type | 3 uses |
| `legacy_hsync_transport.go` | `EnqueueForCombiner` | 1 call |

This means **the parentsync block is a 4-file cluster that must
be kept or removed together:**

```
  delegation_sync.go ──→ LeaderElectionManager.IsLeader()
  parentsync_bootstrap.go ──→ LeaderElectionManager.IsLeader()
        │
        ▼
  legacy_parentsync_leader.go (1498 lines)
        │
        ├──→ legacy_provider_groups.go (GetGroup, GetGroupForZone)
        ├──→ legacy_gossip.go (GroupElectionState type)
        └──→ legacy_hsync_transport.go (EnqueueForCombiner)
```

However — the reverse is NOT true. The other legacy files that
call parentsync_leader symbols (`legacy_hsyncengine.go`,
`legacy_combiner_chunk.go`, `legacy_combiner_utils.go`,
`legacy_agent_utils.go`) are all in the DELETABLE list. They
depend on parentsync_leader, not the other way around.

**Conclusion:** keeping the parentsync cluster does NOT prevent
deleting the rest of the legacy files. The tendrils flow inward
(from deletable legacy files into the kept cluster), not outward.

## NOT YET DELETABLE

Files with live tendrils from non-legacy code (excluding mptypes.go
which is now classified as legacy).

### legacy_hsync_transport.go — `MPTransportBridge`

Part of the parentsync cluster (kept for now).

| Symbol | File:Line | Category |
|---|---|---|
| `MPTransportBridge` (type) | config.go:529 | struct field |
| `MPTransportBridge` (func param) | main_initfuncs.go:505 | func param |
| `EnqueueForCombiner` | parseconfig.go:782 | call |
| `PeerRegistry` (embedded) | delegation_sync.go:218 | field access |
| `DNSTransport` (embedded) | delegation_sync.go:201,236 | field access |
| `getAllAgentsForZone` (private) | delegation_sync.go:206 | call |

### legacy_parentsync_leader.go — `LeaderElectionManager`

Part of the parentsync cluster (kept for now).

| Symbol | File:Line | Category |
|---|---|---|
| `LeaderElectionManager` (type) | config.go:530 | struct field |
| `LeaderElectionManager` | delegation_sync.go:86,127 | nil check + IsLeader |
| `IsLeader` | delegation_sync.go:87,128 | call |
| `LeaderElectionManager` | parentsync_bootstrap.go:30 | field access |
| `IsLeader` | parentsync_bootstrap.go:48,66 | call |

### legacy_provider_groups.go — `ProviderGroupManager`

Part of the parentsync cluster (kept via parentsync_leader).
**Zero non-legacy tendrils** when mptypes.go is excluded.
Kept only because parentsync_leader calls it 9 times.

### legacy_gossip.go — `GroupElectionState`

Part of the parentsync cluster (kept via parentsync_leader).
**Zero non-legacy tendrils** when mptypes.go is excluded.
Kept only because parentsync_leader uses the `GroupElectionState`
type.

### Tendril summary by non-legacy file

| Non-legacy file | Legacy files touched | Tendrils |
|---|---|---|
| delegation_sync.go | 2 (transport, leader) | 7 |
| config.go | 2 (transport, leader) | 2 struct fields |
| parentsync_bootstrap.go | 1 (leader) | 3 |
| parseconfig.go | 1 (transport) | 1 |
| main_initfuncs.go | 1 (transport) | 1 |

Files fully cleaned up:
- ~~apihandler_agent.go~~ — all legacy references removed
- ~~apirouters.go~~ — remaining references commented out
- ~~mptypes.go~~ — reclassified as legacy (2026-04-12)

## mptypes.go — reclassification as legacy

`mptypes.go` defines ~70 exported symbols. Most are MP-specific
message types and struct definitions.

**`ZoneName` — DONE (moved to structs.go 2026-04-12).** This is a
generic tdns type, not MP-specific. ~800 non-legacy refs. Now lives
in `structs.go`.

### AgentId — detailed tendril inventory

`AgentId` is an MP type (`type AgentId string`, mptypes.go:504).
It must be extracted before mptypes.go can be renamed. 6 non-legacy
files reference it (excluding mptypes.go itself):

| File | Lines | Category |
|---|---|---|
| global.go | 21 | struct field (`Globals.AgentId`) |
| apihandler_agent.go | 132 | type cast (`string(amp.AgentId)`) |
| delegation_sync.go | 232 | closure param type |
| sanitize_data.go | 56,57,72 | generic type param (`ConcurrentMap[AgentId, *Agent]`) |
| mpmethods.go | 49,59,63,79,116,118,136,143,167,361,539,580,618,625 | method signatures, map keys, factory |
| cli/prepargs.go | 103,107,212 | type casts |

**mpmethods.go is by far the heaviest user** (14 refs). Since
mpmethods.go itself contains methods on mptypes types
(`ZoneDataRepo`, `AgentRepo`, `AgentId`), it will likely become
legacy too — or the methods will migrate to tdns-mp. If so, the
remaining non-legacy AgentId refs are just 5 files / ~8 call sites.

**global.go** stores `Globals.AgentId` — the running agent's
identity. This is configuration plumbing, easily changed to
`string` or kept as a type alias re-exported from wherever
AgentId lands.

### ZoneDataRepo — detailed tendril inventory

`ZoneDataRepo` is an MP type (mptypes.go:506). It has a parallel
copy in tdns-mp/v2 (`sde_types.go:58`). Non-legacy refs:

| File | Lines | Category |
|---|---|---|
| config.go | 527 | struct field (`InternalMpConf.ZoneDataRepo`) |
| mpmethods.go | 69,73,79,116,129,136,143,167,263,289,309,328,361,378,580,622,623 | method receiver (17 methods), factory |

**All 17 method definitions live in mpmethods.go.** config.go has
a single struct field. That's it — ZoneDataRepo's external surface
is tiny. The "21 refs" are almost entirely method definitions on
the type, not widespread usage. If mpmethods.go is itself
reclassified as legacy (or its methods move to tdns-mp), config.go
is the only remaining tendril.

### Other high-impact types

| Type | Key non-legacy users |
|---|---|
| `Agent` | mpmethods.go, sanitize_data.go |
| `AgentRegistry` | config.go |
| `SyncStatus` | config.go, apihandler_funcs.go, cli/ddns_cmds.go |
| `AgentMgmtPost/Response` | apihandler_agent.go, config.go |
| `SynchedDataUpdate` | config.go, main_initfuncs.go |
| `ZoneUpdate` | mpmethods.go, parseconfig.go |
| RR tracking types | mpmethods.go exclusively |

**Low-impact types** (1-2 refs, mostly config struct fields):
`ConfirmationDetail`, `CombinerState`, `DnskeyStatus`, edit record
types, `AgentBeatPost/Response`, `AgentPingPost/Response`.

### Extraction strategy

1. `ZoneName` — **DONE**, moved to structs.go.
2. `AgentId` — extract to structs.go (or a new `types.go`).
   Straightforward: no methods except `String()` in mpmethods.go.
3. High-impact types — most are only used by mpmethods.go +
   config.go. If mpmethods.go is reclassified as legacy, only
   config.go struct fields remain. Those can be changed to
   `interface{}` or moved behind an MP interface.
4. The remaining 50+ MP-specific message types stay in
   `legacy_mptypes.go`.

## Missed tendrils — build experiment (2026-04-12)

An attempt to add `//go:build ignore` to all 16 "deletable" files
revealed that the grep-based analysis missed **method definitions on
types**. When a type is defined in file A and a method on that type
is defined in file B, grepping for the method name only finds call
sites — not the fact that removing file B breaks callers of the
method even though file A (and the type) is still present.

The build experiment cascaded: excluding the 16 files produced
undefined symbols in the parentsync cluster and in non-legacy code.
Re-including files to fix each error pulled back nearly every
"deletable" file. **The legacy files are not independently
removable — they form a single interconnected block.**

### Complete tendril inventory (verified by build)

Tendrils from "deletable" files into non-deletable code (non-legacy
files, mptypes.go, and the parentsync cluster):

**Logger variables** (trivial to extract, but pervasive):

| Var | Defined in | Used by (non-deletable) |
|---|---|---|
| `lgSigner` | legacy_signer_msg_handler.go | sign.go, key_state_worker.go, keybootstrapper.go, keystate.go, keystore.go, readkey.go, resigner.go, truststore.go, truststore_verify.go |
| `lgEngine` | legacy_hsyncengine.go | validatorengine.go, mpmethods.go, refreshengine.go |
| `lgAgent` | legacy_agent_utils.go | deadcode_agent_setup.go |

**Functions called from non-legacy code:**

| Function | Defined in | Called from |
|---|---|---|
| `pushKeystateInventoryToAllAgents` | legacy_signer_msg_handler.go | apihandler_funcs.go:80, key_state_worker.go:228 |
| `triggerResign` | key_state_worker.go | apihandler_funcs.go:79 |
| `weAreASigner` (method on `*ZoneData`) | legacy_hsync_utils.go | sign.go:364, key_state_worker.go:246 |

**Methods called from parentsync cluster (kept files):**

| Method | Defined in | Called from |
|---|---|---|
| `IsPeerAuthorized` (on `*MPTransportBridge`) | legacy_agent_authorization.go | legacy_hsync_transport.go:332 |
| `DiscoverAndRegisterAgent` (on `*MPTransportBridge`) | legacy_agent_discovery.go | legacy_hsync_transport.go:403,580,804 |
| `GetZoneAgentData` (on `*AgentRegistry`) | legacy_agent_utils.go | legacy_hsync_transport.go:1905, legacy_parentsync_leader.go:1218,1461 |
| `sendRfiToAgent` (on `*AgentRegistry`) | legacy_hsyncengine.go | legacy_parentsync_leader.go:1240 |

**Types used in non-legacy struct fields:**

| Type | Defined in | Used by |
|---|---|---|
| `ZoneAgentData` | legacy_agent_utils.go | mptypes.go:334 (struct field) |
| `DistributionCache` | deadcode_apihandler_agent_distrib.go | config.go:533, legacy_hsync_transport.go:148 |
| `DistributionSummary` | deadcode_apihandler_agent_distrib.go | mptypes.go:791 |
| `DistributionInfo` | deadcode_apihandler_agent_distrib.go | legacy_hsync_transport.go:293 |
| `ChunkPayloadStore` | deadcode_chunk_store.go | config.go:531, legacy_hsync_transport.go:134 |

### What this means

The legacy block is not a set of independent files — it is a
**single compilation unit** held together by method definitions on
shared types (`*MPTransportBridge`, `*AgentRegistry`, `*ZoneData`)
and shared logger variables. Removing any file that defines a method
on these types breaks all callers of that method, even if the callers
are in other legacy files that we intend to keep.

**Deletion strategy must change:** instead of removing files, we must
either:
1. Move the entire block to tdns-mp at once (the repo split), or
2. Extract individual symbols (logger vars, specific functions) to
   non-legacy stubs, then exclude files one at a time with build
   verification between each step — accepting that most files
   cannot be excluded until the cluster itself is gone.

### Actually deletable (verified by build)

Only these files define no symbols used outside the deletable
cluster:

 1. `legacy_agent_structs.go`           — empty (package decl only)
 2. `legacy_apihandler_transaction.go`  — zero callers
 3. `legacy_db_combiner_edits.go`       — zero callers
 4. `legacy_db_combiner_publish_instructions.go` — zero callers

These 4 can be excluded with `//go:build ignore` right now.
Everything else is wired in.

## Change log

- **2026-04-09**: Initial analysis of 19 legacy files. 3 NOT
  DELETABLE, 16 DELETABLE.
- **2026-04-09 re-verification**: `legacy_hsync_utils.go` moved to
  DELETABLE (parseconfig.go no longer registers callbacks). Count:
  2 NOT DELETABLE, 17 DELETABLE.
- **2026-04-10**: Five additional files renamed to `legacy_`:
  `chunk_query_handler.go`, `chunk_store.go`, `parentsync_leader.go`,
  `apihandler_agent_distrib.go`, `apihandler_transaction.go`. All
  contain MP-only content. Full tendril inventory produced for the
  5 NOT YET DELETABLE files.
  Count: 5 NOT YET DELETABLE (with tendrils), 19 DELETABLE.
- **2026-04-12 (first pass)**: Full re-verification against current
  codebase. 3 DELETABLE files already deleted. Major cleanup in
  apihandler_agent.go removed 14 tendrils across four legacy files.
  cli/hsync_cmds.go references identified as new tendrils.
- **2026-04-12 (second pass)**: Two new criteria applied:
  (a) mptypes.go reclassified as legacy — its references to other
  legacy files no longer count as tendrils. This removes 3 tendrils
  from the NOT DELETABLE inventory (MPTransportBridge, LeaderElection
  Manager, ProviderGroupManager struct fields in mptypes.go).
  Extraction strategy documented for ZoneName/AgentId.
  (b) Parentsync cluster analysis: legacy_parentsync_leader.go has
  HARD dependencies on legacy_provider_groups.go (9 calls),
  legacy_gossip.go (type), and legacy_hsync_transport.go (1 call).
  These 4 files form a cluster that must stay together. However,
  the other 12 deletable legacy files do NOT depend on this cluster
  — they can be deleted independently.
  cli/hsync_cmds.go and cli/hsync_debug_cmds.go moved to deadcode
  (commands ported to tdns-mp). This resolved the last cli tendrils
  blocking deletion of legacy_agent_utils.go and
  legacy_hsync_hello.go.
  Count: 4 NOT DELETABLE (parentsync cluster), 16 DELETABLE,
  3 already deleted, 2 moved to deadcode. mptypes.go pending
  type extraction before rename.
- **2026-04-12 (third pass)**: Detailed tendril inventories added
  for AgentId (6 non-legacy files, heaviest is mpmethods.go with
  14 refs) and ZoneDataRepo (only config.go + mpmethods.go; the
  "21 refs" are almost all method definitions on the type, not
  widespread usage). `ZoneName` moved from mptypes.go to structs.go
  — it is a generic tdns type, not MP-specific. Both repos build
  clean after the move.
- **2026-04-12 (build experiment)**: Added `//go:build ignore` to
  all 16 "deletable" files. Build failed with cascading undefined
  symbols. The grep-based analysis had missed **method definitions
  on shared types** — e.g. `IsPeerAuthorized` is a method on
  `*MPTransportBridge` defined in legacy_agent_authorization.go but
  called from legacy_hsync_transport.go (kept). Re-including files
  to fix each error pulled back nearly every "deletable" file.
  Complete tendril inventory now documented (loggers, functions,
  methods on types, struct field types). Only 4 files are truly
  independently removable. The legacy block is a single
  interconnected compilation unit — removal must be by repo split,
  not file-by-file deletion.
