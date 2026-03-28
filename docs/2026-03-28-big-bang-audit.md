# Comprehensive Audit: tdns-mp Agent Extraction

Date: 2026-03-28

## Context

The tdns project has three repos:

- **tdns/** — DNS infrastructure + legacy MP code (still present, not
  yet removed)
- **tdns-mp/** — Multi-provider applications (mpsigner, mpcombiner,
  mpagent, mpcli)
- **tdns-transport/** — Transport abstraction layer

The "big bang" copied ~15,000 lines of agent code from `tdns/v2/` to
`tdns-mp/v2/`. Types that were previously aliases
(`type Foo = tdns.Foo`) were converted to real local struct
definitions. Methods on `*tdns.Config` became methods on
`*tdnsmp.Config`. Methods on `*tdns.ZoneData` became free functions.

This audit covers ALL `.go` files in `tdns-mp/v2/` and
`tdns-mp/cmd/` (~22,000 lines), cross-referenced with `tdns/v2/`
callback and initialization code.

---

## Category 1: Residual `tdns.Conf.Internal.*` References

### 1.1 — `tdns.Conf.Internal.ImrEngine` in hsyncengine.go

- **File**: `tdns-mp/v2/hsyncengine.go:217`
- **Severity**: HIGH
- **Description**: `imr := tdns.Conf.Internal.ImrEngine` — direct
  access to the tdns global. For mpagent,
  `tdns.Conf.Internal.ImrEngine` works because tdns's `MainInit`
  sets it unconditionally for all app types. However, this bypasses
  the injected config pattern. The MPTransportBridge already has a
  `getImrEngine` closure that does the same thing safely.
- **Fix**: Replace with
  `imr := conf.InternalMp.MPTransport.GetImrEngine()` or
  equivalent closure call already wired in `main_init.go:454`.

### 1.2 — `tdns.Conf.Internal.ImrEngine` in agent_utils.go

- **File**: `tdns-mp/v2/agent_utils.go:551`
- **Severity**: HIGH
- **Description**:
  `if imr := tdns.Conf.Internal.ImrEngine; imr != nil {` — same
  pattern. Bypasses injected config, creates hidden coupling to tdns
  global state.
- **Fix**: Pass ImrEngine through the function's existing parameters
  or access via the MPTransportBridge closure.

### 1.3 — `tdns.Conf.MultiProvider` in combiner_utils.go (4 sites)

- **File**: `tdns-mp/v2/combiner_utils.go:143`, `:361`, `:437`,
  `:557`
- **Severity**: MEDIUM
- **Description**:
  `InjectSignatureTXT(zd, tdns.Conf.MultiProvider)` — reads
  MultiProvider config from the tdns global rather than from the
  local `conf` receiver. These functions (`AddCombinerData`,
  `rebuildCombinerData`, etc.) are free functions, not methods on
  `*Config`, so they don't have access to `conf`. The value is
  identical (since `conf.Config` points to `&tdns.Conf`), but it's
  an anti-pattern that will break if the config is ever not the
  global singleton.
- **Fix**: Convert these to methods on `*Config`, or pass the
  MultiProvider config as a parameter.

### 1.4 — `tdns.Conf.MultiProvider` in hsync_utils.go (6 sites)

- **File**: `tdns-mp/v2/hsync_utils.go:586-594`, `:1057`
- **Severity**: MEDIUM
- **Description**: `ourHsyncIdentities()` reads
  `tdns.Conf.MultiProvider.Role`, `.Identity`, `.Agents` directly
  from the global. `MPPreRefresh` at line 1057 calls
  `tdns.InjectSignatureTXT(new_zd, tdns.Conf.MultiProvider)`. Same
  anti-pattern as 1.3.
- **Fix**: Thread `conf` through these functions or pass
  MultiProvider as a parameter.

### 1.5 — `tdns.Conf.MultiProvider` in agent_setup.go

- **File**: `tdns-mp/v2/agent_setup.go:384`
- **Severity**: MEDIUM
- **Description**:
  `privKeyPath := strings.TrimSpace(tdns.Conf.MultiProvider.LongTermJosePrivKey)`
  in `AgentJWKKeyPrep()`. This is a method on `*Config` so it
  could use `conf.Config.MultiProvider` instead.
- **Fix**: Replace `tdns.Conf.MultiProvider` with
  `conf.Config.MultiProvider`.

---

## Category 2: Unconverted Receiver Method Calls

### 2.1 — `zd.LocalDnskeysFromKeystate()` in hsyncengine.go

- **File**: `tdns-mp/v2/hsyncengine.go:167`
- **Severity**: HIGH (compile error or wrong function called)
- **Description**:
  `changed, ds, err := zd.LocalDnskeysFromKeystate()` — calls the
  method on `*tdns.ZoneData` (the tdns version), not the free
  function `LocalDnskeysFromKeystate(zd)` defined in tdns-mp's
  `hsync_utils.go`. The tdns version uses `Conf.Internal.MsgQs`
  (the tdns MsgQs), while the tdns-mp version uses injected MsgQs.
- **Fix**: Change to
  `changed, ds, err := LocalDnskeysFromKeystate(zd)` — the free
  function takes `*tdns.ZoneData` as first parameter.

---

## Category 3: Type Mismatches at Boundaries

### 3.1 — MsgQs: Two Independent Type Definitions

- **File**: `tdns-mp/v2/mp_msg_types.go:11` vs
  `tdns/v2/config.go:548`
- **Severity**: HIGH
- **Description**: Both `tdns.MsgQs` and `tdnsmp.MsgQs` are
  independent struct types with identical structure but different
  channel element types (`tdns.AgentMsgReport` vs
  `tdnsmp.AgentMsgReport`, etc.). The tdns `MainInit` creates a
  `tdns.MsgQs` unconditionally (including for `AppTypeMPAgent`).
  The MP binary creates its own `tdnsmp.MsgQs`. These are
  **separate, unconnected channel sets**. This is actually the
  **correct design** — the MP binary uses its own engines
  (HsyncEngine, SynchedDataEngine) that consume from
  `conf.InternalMp.MsgQs`, not the tdns copy. The tdns-created
  MsgQs sits unused.
- **Risk**: If any tdns code path (reached by MP binary) reads from
  `Conf.Internal.MsgQs` expecting responses that only the tdns-mp
  engines produce, it will block forever. See issue 3.2.

### 3.2 — RequestAndWaitFor* functions use tdns MsgQs

- **File**: `tdns/v2/hsync_utils.go:374,423,465` (tdns side, called
  from tdns-mp)
- **Severity**: HIGH — but **already fixed in tdns-mp copies**
- **Description**: The tdns versions of `RequestAndWaitForEdits`,
  `RequestAndWaitForConfig`, `RequestAndWaitForAudit` read from
  `Conf.Internal.MsgQs`. However, tdns-mp has its **own copies**
  of these functions in `tdns-mp/v2/hsync_utils.go` that take
  `msgQs *MsgQs` as a parameter. The MP code calls the local
  copies, not the tdns versions. **No bug here** — but the tdns
  versions must never be called from MP code paths.
- **Risk**: If any code path accidentally calls the tdns version
  instead of the local copy, it will hang.

### 3.3 — MPPreRefresh/MPPostRefresh Signature Mismatch

- **File**: `tdns-mp/v2/hsync_utils.go:942`, `:1070`
- **Severity**: MEDIUM (currently not registered, so no crash)
- **Description**: The tdns-mp versions take extra parameters:
  `MPPreRefresh(zd, new_zd *tdns.ZoneData, tm *MPTransportBridge, msgQs *MsgQs)`
  (4 params) vs callback signature
  `func(zd, new_zd *ZoneData)` (2 params). Similarly,
  `MPPostRefresh` takes 3 params vs expected 1. These **cannot be
  registered** as `OnZonePreRefresh`/`OnZonePostRefresh` callbacks
  directly.
- **Fix**: Register closures that capture `tm` and `msgQs`, then
  call the 4-param/3-param functions. E.g.:

  ```go
  zd.OnZonePreRefresh = append(zd.OnZonePreRefresh,
      func(zd, new_zd *tdns.ZoneData) {
          MPPreRefresh(zd, new_zd, tm, msgQs)
      })
  ```

### 3.4 — `tdns.Globals.ImrEngine` in apihandler_agent.go

- **File**: `tdns-mp/v2/apihandler_agent.go:769,804,851,873,883,942`
- **Severity**: LOW (works because tdns sets Globals.ImrEngine for
  all app types)
- **Description**: Six references to `tdns.Globals.ImrEngine` in the
  `APIagentDebug` function for IMR-related debug commands. Uses the
  tdns global directly rather than injected config.
- **Fix**: Access via
  `conf.InternalMp.MPTransport.GetImrEngine()` or pass as
  parameter.

---

## Category 4: Incomplete Functionality

### 4.1 — Leader Election Not Implemented

- **File**: `tdns-mp/v2/start_agent.go:67-73`
- **Severity**: HIGH
- **Description**: The entire leader election manager setup is
  replaced with a TODO log message. Missing:
  - `NewLeaderElectionManager` creation
  - `SetOperationalPeersFunc` wiring
  - `SetConfiguredPeersFunc` wiring
  - `SetProviderGroupManager` attachment
  - `OnFirstLoad` callbacks for per-zone leader elections
  - `SetOnLeaderElected` callback (triggers SIG(0) key gen, KEY
    publication, DSYNC bootstrap)
- **Impact**: Delegation sync and SIG(0) key management completely
  non-functional in mpagent.
- **Dependencies**: All necessary support code
  (`parentsync_leader.go`, `gossip.go`, `provider_groups.go`) is
  already copied to tdns-mp. The functions exist locally. This is
  purely a wiring task.
- **Blockers**: `parentSyncAfterKeyPublication` is unexported in
  tdns (see 4.2). `PrepareKeyCache` is unexported in tdns
  (see 4.3).

### 4.2 — `parentSyncAfterKeyPublication` Unavailable

- **File**: `tdns-mp/v2/apihandler_agent.go:798`
- **Severity**: HIGH (blocked functionality)
- **Description**: TODO comment:
  "parentSyncAfterKeyPublication is unexported in tdns — export it
  or move the implementation to tdns-mp." The
  `parentsync-bootstrap` debug command returns an error instead of
  functioning.
- **Fix**: Reimplement locally as method on `*tdnsmp.Config`. The
  called function is in `tdns/v2/parentsync_bootstrap.go` and its
  dependencies are all already available in tdns-mp.

### 4.3 — `importSig0KeyFromPeer` Calls Unexported tdns Functions

- **File**: `tdns-mp/v2/parentsync_leader.go:1092`
- **Severity**: HIGH (blocked functionality)
- **Description**: `importSig0KeyFromPeer` calls
  `tdns.PrepareKeyCache()` which is unexported. This function is
  part of the leader election flow — when a new leader is elected,
  it needs to import SIG(0) keys from peers.
- **Fix**: Either export `PrepareKeyCache` in tdns, or reimplement
  locally.

### 4.4 — Combiner Remove Operation Not Implemented

- **File**: `tdns-mp/v2/apihandler_combiner.go:74`
- **Severity**: LOW
- **Description**: TODO: "Implement remove functionality" — combiner
  data removal API endpoint returns error.
- **Fix**: Implement when needed.

### 4.5 — Agent Cleanup Not Implemented

- **File**: `tdns-mp/v2/agent_utils.go:807`
- **Severity**: LOW
- **Description**: TODO: "Cleanup not yet implemented" — zone
  cleanup for agent.
- **Fix**: Implement when needed.

---

## Category 5: Dual-Write Audit

### 5.1 — initMPAgent() Dual-Write Status

| Field | InternalMp? | Dual-write to Config.Internal? | tdns reads it? |
|-------|:-----------:|:------------------------------:|:--------------:|
| MsgQs | YES (L368) | **NO** | YES — but only via tdns's own engines which MP doesn't use. **OK.** |
| AgentRegistry | YES (L340) | **NO** | YES — some tdns paths. **Potential issue.** |
| ZoneDataRepo | **NO** | **NO** | Unclear — not initialized anywhere in MP. |
| SyncQ | YES (L345, copied) | N/A (shared ref) | YES — shared channel. **OK.** |
| CombinerState | YES (L354) | YES (L357) | YES. **OK.** |
| DistributionCache | YES (L371) | YES (L373) | YES. **OK.** |
| TransportManager | YES (L460) | YES (L462) | YES. **OK.** |
| ChunkPayloadStore | YES (L395) | **NO** | Minor — chunk query mode only. |
| LeaderElectionManager | **NO** (deferred) | **NO** | YES — broken. See 4.1. |

### 5.2 — initMPSigner()/initMPCombiner() Missing Dual-Writes

- **File**: `tdns-mp/v2/main_init.go`
- **Severity**: MEDIUM
- **Description**: Neither `initMPSigner` nor `initMPCombiner`
  dual-writes `TransportManager` to
  `conf.Config.Internal.TransportManager`. If any tdns code path
  reads `Conf.Internal.TransportManager` for signer/combiner
  roles, it gets nil.
- **Current status**: The signer and combiner message handlers in
  tdns-mp use `conf.InternalMp.MPTransport` and
  `conf.InternalMp.TransportManager` exclusively. No known broken
  path, but fragile.
- **Fix**: Add dual-write for TransportManager in both init
  functions, or verify no tdns code reads it for these roles.

---

## Category 6: Config Access Patterns

### 6.1 — No Promoted `conf.Internal.*` Ambiguity

- **Severity**: N/A (non-issue)
- **Description**: The `Config` struct has `*tdns.Config` as an
  **embedded pointer** (anonymous field) and
  `InternalMp InternalMpConf` as a **named field**. This means
  `conf.Internal` unambiguously resolves to `conf.Config.Internal`
  (via embedding). `conf.InternalMp` is a named field. No ambiguity
  exists.

### 6.2 — Mixed Promoted vs Explicit Config Access

- **Files**: `tdns-mp/v2/combiner_msg_handler.go`,
  `combiner_crypto.go`, `signer_msg_handler.go`,
  `signer_transport.go`
- **Severity**: LOW
- **Description**: Some files use `conf.MultiProvider` (promoted)
  while others use `conf.Config.MultiProvider` (explicit). Both
  work identically. Minor inconsistency.
- **Fix**: Standardize to one style (explicit
  `conf.Config.MultiProvider` is clearer).

---

## Category 7: Logger Variables

### 7.1 — No Duplicates Found

- **Severity**: N/A (non-issue)
- **Description**: 13 unique logger variables across 13 files. No
  duplicates. All names distinct: `lg`, `lgAgent`, `lgApi`,
  `lgConnRetry`, `lgConnRetryEngine`, `lgCombiner`, `lgCrypto`,
  `lgElect`, `lgEngine`, `lgGossip`, `lgProviderGroup`,
  `lgSigner`, `lgTransport`.

---

## Category 8: Unused Imports and Dead Code

### 8.1 — `RemoveCombinerDataByRRtype()` Unused

- **File**: `tdns-mp/v2/combiner_utils.go:371-442`
- **Severity**: LOW
- **Description**: 71-line function copied from tdns but never
  called from any tdns-mp code. Similar function
  `ReplaceCombinerDataByRRtype` is used (9 call sites).
- **Fix**: Remove if not needed. (Ask first — may be kept
  intentionally.)

### 8.2 — `restoreUpstreamRRset()` Unused

- **File**: `tdns-mp/v2/combiner_utils.go:621-640`
- **Severity**: LOW
- **Description**: 19-line orphaned helper function, never called.
- **Fix**: Remove if not needed.

### 8.3 — Stale TODO Comment About SyncRequest Type Mismatch

- **File**: `tdns-mp/v2/agent_setup.go:54-55`
- **Severity**: LOW
- **Description**: Comment says "zd.SyncQ assignment skipped —
  tdns.SyncRequest vs local SyncRequest type mismatch." But
  `SyncRequest` is already an alias (`= tdns.SyncRequest` in
  `sde_types.go:168`), so the mismatch doesn't exist.
- **Fix**: Remove stale comment and implement the SyncQ assignment
  if needed.

---

## Category 9: Callback Registration

### 9.1 — PreRefresh/PostRefresh Callbacks NOT Using tdns-mp Versions

- **File**: `tdns-mp/v2/start_agent.go`, `start_combiner.go`
- **Severity**: HIGH
- **Description**: `ParseZones` (in tdns) registers the **tdns
  versions** of `MPPreRefresh`/`MPPostRefresh` as callbacks on
  `OnZonePreRefresh`/`OnZonePostRefresh` (`parseconfig.go:727-728`).
  The tdns-mp versions have different signatures (extra `tm`,
  `msgQs` params) and are **never registered**. For mpagent, the
  tdns callbacks fire and use `tdns.Conf.Internal.MsgQs` and tdns
  globals — which partially works (the tdns-created MsgQs exists
  but isn't consumed by anyone in the MP binary).
- **Impact**: Pre/post refresh analysis and queue sends use the
  wrong MsgQs instance. The tdns SyncQ send in MPPostRefresh
  writes to `zd.SyncQ` which IS shared (same channel), so sync
  messages do get through. But any code in MPPreRefresh that uses
  `Conf.Internal.MsgQs` for RFI requests will hang.
- **Fix**: In `start_agent.go` (or `start_combiner.go`), after
  ParseZones, replace the tdns callbacks with closures that call
  the tdns-mp versions:

  ```go
  zd.OnZonePreRefresh = []func(zd, new_zd *tdns.ZoneData){
      func(zd, new_zd *tdns.ZoneData) {
          MPPreRefresh(zd, new_zd, tm, msgQs)
      },
  }
  ```

### 9.2 — SIGHUP Adds Zones With tdns Callbacks Only

- **Severity**: MEDIUM
- **Description**: On config reload (SIGHUP), `ParseZones` registers
  tdns's `MPPreRefresh`/`MPPostRefresh` for **new** zones. Existing
  zones keep whatever callbacks they had from first load. Since the
  initial callbacks are also the tdns versions (not tdns-mp
  versions), this is consistently wrong but not a regression on
  reload.
- **Fix**: Implement a post-reload hook that replaces callbacks on
  new zones with tdns-mp closures. Or: require full restart to add
  new MP zones (acceptable for current deployment model).

### 9.3 — OnFirstLoad Callbacks Correctly Use Local Functions

- **Severity**: N/A (non-issue)
- **Description**: `start_combiner.go` registers OnFirstLoad
  callbacks that call local tdns-mp functions
  (`SaveContributions`, `LoadAllContributions`, etc.).
  `agent_setup.go` registers OnFirstLoad callbacks that call local
  methods (`conf.publishApiTransport`, `conf.publishDnsTransport`).
  These are correct.

---

## Category 10: Design Flaws in the tdns/tdns-mp Interface

### 10.1 — Dual MsgQs Instances (Design Smell)

- **Severity**: MEDIUM
- **Description**: Both tdns and tdns-mp create MsgQs instances.
  The tdns one (`Conf.Internal.MsgQs`) is created unconditionally
  in `MainInit` and sits unused for MP binaries. The tdns-mp one
  (`conf.InternalMp.MsgQs`) is the real working copy. This is
  wasteful and confusing but functionally correct since the MP
  binary's engines consume from the MP MsgQs exclusively.
- **Risk**: Any future code in tdns that sends to
  `Conf.Internal.MsgQs` expecting MP engines to receive it will
  silently fail.
- **Fix**: Long-term: have tdns skip MsgQs creation for
  `AppTypeMPAgent/Signer/Combiner`. Short-term: document the
  dual-instance pattern.

### 10.2 — Channel-Shared Types Must Remain Aliases

- **Severity**: MEDIUM (constraint, not bug)
- **Description**: `SyncRequest`, `SyncResponse`, `SyncStatus`,
  `HsyncStatus`, `DnskeyStatus` are aliases to tdns types. They
  **must** remain aliases because they're used in channels shared
  between tdns and tdns-mp code (e.g.,
  `zd.SyncQ chan SyncRequest`). If any of these are ever converted
  to real types, the channel operations will fail at compile time.
- **Fix**: Add a comment in `sde_types.go` documenting this
  constraint.

### 10.3 — `CombinerState`, `DistributionCache`, `ChunkPayloadStore`

- **Severity**: LOW
- **Description**: These are aliases to tdns types but are used
  purely within tdns-mp code (no shared channels). They could be
  converted to real local types when tdns-mp diverges. Currently
  harmless as aliases.
- **Fix**: Convert to real types when the big-bang cleanup removes
  the tdns originals.

### 10.4 — No Circular Dependencies

- **Severity**: N/A (non-issue)
- **Description**: Confirmed: tdns has zero imports of tdns-mp.
  Unidirectional dependency is clean and sustainable.

### 10.5 — Missing dns.Fqdn() Normalization in CLI

- **File**: `tdns-mp/v2/cli/combiner_edits_cmds.go:460`
- **Severity**: MEDIUM
- **Description**: `combinerZoneBumpCmd` passes
  `tdns.Globals.Zonename` without `dns.Fqdn()` normalization.
  Other commands in the same file correctly normalize.
- **Fix**: Wrap with `dns.Fqdn()`.

---

## Summary

| Category | HIGH | MEDIUM | LOW | Non-issue |
|----------|:----:|:------:|:---:|:---------:|
| 1. Residual tdns.Conf references | 2 | 4 | — | — |
| 2. Unconverted receiver calls | 1 | — | — | — |
| 3. Type mismatches at boundaries | 1 | 1 | 1 | — |
| 4. Incomplete functionality | 3 | — | 2 | — |
| 5. Dual-write audit | — | 1 | — | — |
| 6. Config access patterns | — | — | 1 | 1 |
| 7. Logger variables | — | — | — | 1 |
| 8. Unused imports / dead code | — | — | 3 | — |
| 9. Callback registration | 1 | 1 | — | 1 |
| 10. Design flaws | — | 3 | 1 | 1 |
| **Totals** | **8** | **10** | **8** | **4** |

---

## Priority Fix Order

1. **Issue 9.1** — PreRefresh/PostRefresh callbacks not using
   tdns-mp versions. This affects every zone refresh cycle.
2. **Issue 2.1** — `zd.LocalDnskeysFromKeystate()` unconverted
   receiver call. Wrong code path executed.
3. **Issue 4.1** — Leader election not wired up. Blocks delegation
   sync entirely.
4. **Issues 1.1, 1.2** — Direct `tdns.Conf.Internal.ImrEngine`
   access. Use injected closures instead.
5. **Issues 4.2, 4.3** — Unexported tdns functions blocking leader
   election and parentsync. Requires either tdns exports or local
   reimplementation.
6. **Issues 1.3, 1.4, 1.5** — `tdns.Conf.MultiProvider` in free
   functions. Thread config through.
7. **Issue 5.2** — Missing TransportManager dual-write for
   signer/combiner roles.
8. Everything else (cleanup, style, dead code).
