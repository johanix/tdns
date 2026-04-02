# AppData Interface Refactor: Replacing InternalMpConf

**Date**: 2026-04-02
**Status**: PLANNED — DO NOT IMPLEMENT UNTIL LEGACY MP CODE IN tdns IS
FULLY RETIRED (see `2026-03-30-mp-removal-from-tdns.md`)

---

## 1. Problem Statement

`InternalMpConf` is a concrete struct defined in `tdns/v2/config.go`.
It is embedded in `InternalConf`, which is itself a field of the global
`Config`. The struct holds state that is entirely specific to the MP
application layer — combiner, signer, and agent coordination
machinery.

This creates two problems:

**Problem 1 — Import direction**: `InternalMpConf` has fields whose
types are defined in `tdns/v2` but only meaningful to the MP layer.
Currently these types live in tdns because of the field declarations.
Moving them to `tdns-mp` is blocked by the struct — you cannot have a
field of type `*T` if `T` is defined in a package you don't import, and
tdns cannot import tdns-mp (circular).

**Problem 2 — Wrong abstraction**: tdns (the DNS server library) encodes
knowledge about a specific application (MP agent) in its core config.
Other applications that build on top of tdns (KDC, KRS, and future apps)
cannot cleanly attach their own per-zone or global state without adding
more fields to tdns structs — which is the wrong layer.

The existing workaround (`KdcDB interface{}`, `KdcConf interface{}` etc.
already in `InternalMpConf`) demonstrates that the problem is
recognized but was patched field-by-field instead of architecturally.

---

## 2. Current State (Before Refactor)

```
tdns/v2/config.go:

  type InternalMpConf struct {
      SyncQ                 chan SyncRequest
      MsgQs                 *MsgQs
      SyncStatusQ           chan SyncStatus
      AgentRegistry         *AgentRegistry         // defined in tdns/v2 legacy file
      ZoneDataRepo          *ZoneDataRepo          // defined in tdns/v2 legacy file
      CombinerState         *CombinerState         // defined in tdns/v2 legacy file
      TransportManager      *transport.TransportManager
      MPTransport           *MPTransportBridge     // defined in tdns/v2 legacy file
      LeaderElectionManager *LeaderElectionManager // defined in tdns/v2 legacy file
      ChunkPayloadStore     ChunkPayloadStore      // interface, defined in tdns/v2
      MPZoneNames           []string
      DistributionCache     *DistributionCache     // defined in tdns/v2 legacy file
      KdcDB                 interface{}            // workaround
      KdcConf               interface{}            // workaround
      KrsDB                 interface{}            // workaround
      KrsConf               interface{}            // workaround
  }

  type InternalConf struct {
      InternalDnsConf
      InternalMpConf        // embedded (field promotion)
      PostParseZonesHook func()
  }
```

The legacy files (`legacy_agent_structs.go`,
`legacy_hsync_transport.go`, `legacy_syncheddataengine.go`, etc.)
define the types. When those files are deleted as part of the MP removal
plan, the types disappear — but the `InternalMpConf` struct definition
remains in `config.go` and must also be cleaned up.

`InternalMpConf` is accessed via `conf.Internal.<field>` throughout
tdns/v2 (58 files reference `.Internal.`), because the struct is
embedded and its fields are promoted.

---

## 3. Target State (After Refactor)

### 3.1 tdns/v2: a single opaque attachment point

Replace the embedded `InternalMpConf` struct with a single
`interface{}` field named `AppData`:

```go
// tdns/v2/config.go

type InternalConf struct {
    InternalDnsConf

    // AppData is an opaque attachment point for application-layer
    // state. tdns does not inspect this field. Applications that build
    // on tdns (e.g. tdns-mp, kdc, krs) store their own structs here.
    // Access requires a type assertion in the application layer.
    AppData interface{}

    // PostParseZonesHook is called after ParseZones completes during
    // reload (SIGHUP or "config reload-zones"). Set by MP apps to
    // register tdns-mp callbacks on newly added zones.
    PostParseZonesHook func()
}
```

`InternalMpConf` is deleted entirely from tdns/v2. The `MsgQs` struct,
`SyncRequest`/`SyncStatus` channel types, and all other types that were
only referenced from `InternalMpConf` are also deleted from tdns/v2 (or
moved to tdns-mp if still needed there).

`SyncQ` on `ZoneData` is a direct field (not inside `InternalMpConf`)
and is unaffected by this change.

### 3.2 tdns-mp/v2: owns its own state struct

tdns-mp defines the concrete struct and stores it in `conf.Internal.AppData`:

```go
// tdns-mp/v2/config.go (or mp_app_data.go)

type MpAppData struct {
    SyncQ                 chan SyncRequest
    MsgQs                 *MsgQs
    SyncStatusQ           chan SyncStatus
    AgentRegistry         *AgentRegistry
    ZoneDataRepo          *ZoneDataRepo
    CombinerState         *CombinerState
    TransportManager      *transport.TransportManager
    MPTransport           *MPTransportBridge
    LeaderElectionManager *LeaderElectionManager
    ChunkPayloadStore     ChunkPayloadStore
    MPZoneNames           []string
    DistributionCache     *DistributionCache
}
```

All types in this struct are defined in tdns-mp (or in tdns-transport
which tdns-mp already imports). No import of tdns for type definitions.

### 3.3 Accessor pattern in tdns-mp

At every place where tdns-mp previously accessed `conf.Internal.<field>`
(via field promotion), it now does a single type assertion to get the
full struct and then accesses fields normally:

```go
func mpConf(conf *tdns.Config) *MpAppData {
    return conf.Internal.AppData.(*MpAppData)
}

// Usage:
mpConf(conf).AgentRegistry.GetZoneAgentData(zone)
mpConf(conf).MsgQs.Command <- cmd
```

The helper function `mpConf()` can be package-level in tdns-mp. It
panics on nil or wrong type, which is appropriate — if AppData is not
set up correctly, the app is misconfigured and should crash at startup,
not limp along with nil dereferences.

### 3.4 types.go in tdns-mp becomes empty or deleted

Once `MpAppData` and all its field types are defined in tdns-mp, the
aliases in `tdns-mp/v2/types.go` that point to `tdns.Foo` are no longer
needed. The file either shrinks to nothing or is deleted entirely.

---

## 4. Scope of Changes

### 4.1 Changes in tdns/v2

| File | Change |
|------|--------|
| `config.go` | Remove `InternalMpConf` struct. Remove `MsgQs` struct. Remove `SyncRequest`, `SyncStatus` channel types if MP-only. Replace embedded `InternalMpConf` in `InternalConf` with `AppData interface{}`. |
| `structs.go` | No change needed for this refactor (ZoneData.SyncQ is a direct field). |
| All other tdns/v2 files | No change — by the time this refactor runs, legacy files are deleted and no tdns/v2 code references `InternalMpConf` fields. |

### 4.2 Changes in tdns-mp/v2

| File | Change |
|------|--------|
| `config.go` | Add `MpAppData` struct (or rename existing `InternalMpConf` mirror). Remove `InternalMp InternalMpConf` field from tdns-mp `Config` (the field was the dual-write mirror; it is no longer needed). |
| `types.go` | Remove all aliases pointing to tdns types. Either delete the file or keep it for any remaining non-type re-exports. |
| `main_init.go` and all call sites | Replace `conf.Config.Internal.<field>` and `conf.InternalMp.<field>` accesses with `mpConf(conf.Config).<field>`. This is the bulk of the change. |
| New file: `mp_app_data.go` (optional) | Define `MpAppData`, the `mpConf()` accessor, and `NewMpAppData()` constructor. |

### 4.3 Changes in other apps (kdc, krs)

Each app that builds on tdns and needs its own global state follows the
same pattern:
- Define `KdcAppData` in the kdc package.
- At init time: `conf.Internal.AppData = &KdcAppData{...}`
- Access via type assertion.

The existing `KdcDB`, `KdcConf`, `KrsDB`, `KrsConf` fields in
`InternalMpConf` disappear (they were workarounds inside the wrong
struct). Each app manages its own state.

---

## 5. Why AppData and Not a Named Interface?

An alternative is to define an interface in tdns/v2:

```go
type AppExtension interface {
    // ???
}
```

But there is nothing useful to put in this interface — the app data
structs have no methods that tdns itself needs to call. The `interface{}`
approach is simpler and honestly more honest: tdns truly doesn't know or
care what is stored there.

If future needs emerge (e.g. a lifecycle method like `OnShutdown()`),
the field can be changed to a named interface at that point.

---

## 6. Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Type assertion panics at runtime if AppData is nil or wrong type | `mpConf()` helper panics with a clear message. This surfaces immediately at startup, not buried in production. |
| Many call sites to update in tdns-mp | Mechanical change — grep for `conf.Internal.` and `conf.Config.Internal.` and `conf.InternalMp.`. Can be done with sed/gorename. |
| Missing a call site | Build fails — the field no longer exists, so the compiler catches everything. |
| Dual-write complexity disappears | The dual-write pattern (`conf.Config.Internal.X = ...; conf.InternalMp.X = ...`) is removed along with `InternalMp`. This simplifies init code significantly. |

---

## 7. Prerequisites (Blocking)

This refactor MUST NOT be started until:

1. **All `legacy_*` files in `tdns/v2/` are deleted** (Phase 2 of
   `2026-03-30-mp-removal-from-tdns.md`).
2. **`config.go` in tdns/v2 has been cleaned** — `InternalMpConf`
   fields referencing deleted types are already removed as part of the
   MP removal plan (Phase 3, Step 3.1).
3. **`main_initfuncs.go` in tdns/v2 no longer writes to
   `conf.Internal.<MP fields>`** (Phase 3, Step 3.3).
4. **tdns-mp dual-write is the sole writer of MP state** — all field
   assignments go through `conf.InternalMp.*` in tdns-mp/v2.

Once the MP removal plan is complete, `InternalMpConf` in tdns/v2
should already be empty or near-empty (stripped of all the removed
types). At that point this refactor is a straightforward cleanup:
rename the remaining shell to `AppData interface{}` and move the
field definitions to tdns-mp.

---

## 8. Implementation Order

When prerequisites are met:

1. Verify that `InternalMpConf` in tdns/v2 contains only fields whose
   types are still defined in tdns/v2 (i.e. the legacy files are gone).
   List any remaining fields.

2. For each remaining field type: determine if it belongs in tdns/v2
   (genuinely generic DNS infra) or in tdns-mp (MP-specific).
   - If it belongs in tdns-mp: move the type definition.
   - If it belongs in tdns/v2 but is not MP-specific: keep it, but move
     it out of `InternalMpConf` to a more appropriate location.

3. Once `InternalMpConf` is empty of tdns-defined types, replace it
   with `AppData interface{}` in `InternalConf`.

4. In tdns-mp: define `MpAppData`, implement `mpConf()` accessor,
   update all call sites. Build must pass.

5. Remove `types.go` aliases in tdns-mp for types now defined locally.

6. Run `go mod tidy` in both repos to verify no phantom dependencies.

7. Update this document to mark as complete.
