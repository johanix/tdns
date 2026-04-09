# Legacy File Dependency Analysis — tdns/v2/legacy_*.go

**Date**: 2026-04-09
**Scope**: All 19 `tdns/v2/legacy_*.go` files
**Goal**: Identify which legacy files can be deleted and which still have
live, non-legacy callers inside `tdns/v2/`.

## Method

1. Extracted all top-level exported symbols from each `legacy_*.go` file.
2. Grepped the entire `tdns-project/` tree (tdns, tdns-mp, tdns-apps) for
   references to each symbol.
3. Classified each reference as:
   - **Self-reference**: within another `legacy_*.go` file (does not
     prevent deletion as long as the whole legacy cluster goes together).
   - **Live v2 non-legacy reference**: from a non-legacy file in
     `tdns/v2/`. This is what keeps a legacy file alive.
   - **Commented-out reference**: inside a `/* ... */` block or after
     `//`. Does not count.
   - **tdns-mp/v2 reference**: `tdns-mp/v2/` imports `tdns/v2` as
     `tdns "github.com/johanix/tdns/v2"`, but in practice tdns-mp/v2
     defines its own parallel copies of nearly every symbol in question.
     References from tdns-mp therefore resolve to the local tdns-mp copy,
     not the legacy tdns copy, and do **not** keep tdns/v2 legacy files
     alive.

Critical lesson: an initial grep-only pass produced a longer
"NOT DELETABLE" list. Several of those references turned out to be
inside commented-out `/* */` blocks in `main_initfuncs.go`, and several
others were from `tdns-mp/v2/` where a local copy of the symbol exists.
Both classes must be filtered out to get the true picture.

## Parallel copies in tdns-mp/v2

The following symbols exist both in `tdns/v2/legacy_*.go` and as local
definitions in `tdns-mp/v2/`. tdns-mp callers resolve to the local copy:

| Symbol                         | tdns-mp/v2 definition               |
|--------------------------------|-------------------------------------|
| `GetProviderZoneRRtypes`       | `combiner_utils.go:52`              |
| `RegisterProviderZoneRRtypes`  | `combiner_utils.go:39`              |
| `GetCombinerData`              | `combiner_utils.go:151`             |
| `GetCombinerDataNG`            | `combiner_utils.go:219`             |
| `NewMPTransportBridge`         | `hsync_transport.go:191`            |
| `MPTransportBridge` (type)     | `hsync_transport.go:45`             |
| `MPTransportBridgeConfig`      | `hsync_transport.go:126`            |
| `ProviderGroupManager` (type)  | `gossip_types.go:84`                |
| `NewProviderGroupManager`      | `provider_groups.go:22`             |
| `NewGossipStateTable`          | `gossip.go:40`                      |
| `LoadAllContributions`         | `db_combiner_contributions.go:63`   |
| `RequestAndWaitForConfig`      | `hsync_utils.go:414`                |
| `RequestAndWaitForAudit`       | `hsync_utils.go:455`                |
| `MPPreRefresh`                 | `hsync_utils.go:1005` (diff sig)    |
| `MPPostRefresh`                | `hsync_utils.go:1141` (diff sig)    |

Note the signature fork on `MPPreRefresh`/`MPPostRefresh`:

```go
// tdns/v2 legacy_hsync_utils.go:912
func MPPreRefresh(zd, new_zd *ZoneData)

// tdns-mp/v2 hsync_utils.go:1005
func MPPreRefresh(zd, new_zd *tdns.ZoneData,
                  tm *MPTransportBridge,
                  msgQs *MsgQs,
                  mp *tdns.MultiProviderConf)
```

`tdns/v2/parseconfig.go` previously registered the 2-arg legacy signature,
but recent work removed that registration (see re-verification below).

## NOT DELETABLE (2 files)

These files have at least one live reference from a non-legacy file in
`tdns/v2/`. This list reflects a re-verification pass on 2026-04-09
after recent refactoring.

### legacy_hsync_transport.go

The type `MPTransportBridge` is used as a struct field and function
parameter in several non-legacy files. The constructor
`NewMPTransportBridge` and `MPTransportBridgeConfig` are no longer
called from non-legacy tdns/v2 code — only the type itself keeps this
file alive.

| Symbol                    | Live caller                         |
|---------------------------|-------------------------------------|
| `MPTransportBridge` (type)| `config.go:529` (`Config.MPTransport`) |
|                           | `mptypes.go:150` (`AgentRegistry.MPTransport`) |
|                           | `main_initfuncs.go:505` (`registerPeerAgents` param) |
|                           | `parentsync_leader.go:1488` (`PublishKeyToCombiner` param) |

Status change from first pass: `main_initfuncs.go:345` (which was the
sole cited live caller of `NewMPTransportBridge`) is no longer the
reason this file stays. Multiple additional type-level references were
found.

### legacy_provider_groups.go

The type `ProviderGroupManager` is used in non-legacy code.
`NewProviderGroupManager` is not called from non-legacy tdns/v2.

| Symbol                        | Live caller                      |
|-------------------------------|----------------------------------|
| `ProviderGroupManager` (type) | `apihandler_agent.go:537-538` (`.GetGroupForZone()` call) |
|                               | `mptypes.go:152` (`AgentRegistry` field) |
|                               | `parentsync_leader.go:54` (`LeaderElectionManager` field) |
|                               | `parentsync_leader.go:70` (`SetProviderGroupManager` param) |

Status change from first pass: two additional live call sites in
`parentsync_leader.go` were found.

## DELETABLE (17 files)

All exported symbols are either unreferenced or only referenced from
other `legacy_*.go` files, commented-out code, or tdns-mp/v2 (where a
local copy exists).

 1. `legacy_agent_authorization.go`            — only methods on `MPTransportBridge`
 2. `legacy_agent_discovery.go`                — superseded by tdns-mp/v2
 3. `legacy_agent_discovery_common.go`         — only called by `legacy_agent_discovery.go`
 4. `legacy_agent_setup.go`                    — no live callers
 5. `legacy_agent_structs.go`                  — empty (package decl only)
 6. `legacy_agent_utils.go`                    — no live callers
 7. `legacy_combiner_chunk.go`                 — all callers in `/* */` blocks in `main_initfuncs.go`
 8. `legacy_combiner_utils.go`                 — all callers in `/* */` blocks; tdns-mp has local copies
 9. `legacy_db_combiner_contributions.go`      — all callers in `/* */` blocks; tdns-mp has local copy
10. `legacy_db_combiner_edits.go`              — no live callers
11. `legacy_db_combiner_publish_instructions.go` — no live callers
12. `legacy_gossip.go`                         — tdns-mp has local copy; no live tdns/v2 callers
13. `legacy_hsync_beat.go`                     — superseded by tdns-mp/v2
14. `legacy_hsync_hello.go`                    — superseded by tdns-mp/v2
15. `legacy_hsync_utils.go`                    — parseconfig.go no longer registers `MPPreRefresh`/`MPPostRefresh`; only reference is a comment in `zone_utils.go:747`
16. `legacy_hsyncengine.go`                    — superseded
17. `legacy_signer_msg_handler.go`             — superseded by tdns-mp/v2

### Files reclassified during verification pass

These three were initially flagged NOT DELETABLE because of grep hits in
`main_initfuncs.go`. Manual inspection showed all hits were inside
`/* */` blocks:

- `legacy_combiner_chunk.go`:
  `RegisterCombinerChunkHandler` @ `main_initfuncs.go:556` (inside
  `/* */` lines 520–672),
  `RegisterSignerChunkHandler` @ `main_initfuncs.go:461` (inside
  `/* */` lines 396–519).
- `legacy_combiner_utils.go`:
  `GetProviderZoneRRtypes` @ `main_initfuncs.go:746` (inside `/* */`
  lines 680–792).
- `legacy_db_combiner_contributions.go`:
  `SaveContributions` @ `main_initfuncs.go:716`,
  `LoadAllContributions` @ `main_initfuncs.go:691` (both inside `/* */`
  lines 680–792).

## Caveats before deletion

1. **Method receivers not verified.** This analysis looked at top-level
   exported symbols. It did not verify whether live code calls methods
   defined in these files on types like `*MPTransportBridge` or
   `*AgentRegistry`. For example, `legacy_agent_authorization.go` only
   defines methods on `*MPTransportBridge`; deleting the file removes
   those methods. Before deleting any file whose classification is
   "only methods on X", run a method-name grep against non-legacy code.

2. **Incremental deletion and build between each.** Delete one file at
   a time, then run `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make`
   before moving on. The build will catch anything the grep analysis
   missed (e.g. interface satisfaction, init-time registration, method
   calls via interface).

3. **Start with the safest.** `legacy_agent_structs.go` is empty —
   remove it first as a dry run of the process.

4. ~~`legacy_hsync_utils.go` is the blocker for `parseconfig.go`
   cleanup.~~ Resolved by the 2026-04-09 re-verification: the
   `MPPreRefresh`/`MPPostRefresh` callbacks are no longer registered
   from `parseconfig.go`, and `RequestAndWaitForConfig`/`RequestAndWaitForAudit`
   have no live callers in non-legacy tdns/v2. The file is now deletable.

## Re-verification (2026-04-09)

A second-pass re-check of the three files originally flagged NOT
DELETABLE produced one status change and expanded the caller lists
for the other two:

- **`legacy_hsync_utils.go`: NOT DELETABLE → DELETABLE.** Recent work
  removed the `MPPreRefresh`/`MPPostRefresh` callback registrations
  from `parseconfig.go`. `zone_utils.go:747` still mentions these
  functions, but only inside a comment explaining that the work moved
  to tdns-mp.
- **`legacy_hsync_transport.go`: still NOT DELETABLE** — but for
  different reasons than the first pass identified. The constructor
  `NewMPTransportBridge` is no longer called from non-legacy tdns/v2
  code. What keeps the file alive is the type `MPTransportBridge`
  itself, used in four live sites (see table above).
- **`legacy_provider_groups.go`: still NOT DELETABLE** — two
  additional live callers in `parentsync_leader.go` were found that
  the first pass missed.

Final count: **2 files NOT DELETABLE, 17 files DELETABLE.**