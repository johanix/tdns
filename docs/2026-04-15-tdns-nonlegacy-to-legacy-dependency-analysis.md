# Non-legacy tdns/v2 → legacy\_\*.go dependency analysis

**Date**: 2026-04-15  
**Companion**: `tdns-mp/docs/2026-04-15-legacy-dependency-analysis.md` (that document inventories **tdns-mp → tdns**; this one inventories **tdns non-legacy → tdns legacy** within the same `package tdns` / `package cli` roots.)

**Purpose**: Before deleting `tdns/v2/legacy_*.go`, enumerate **edges where non-legacy source files still depend on symbols whose bodies live only in legacy files**. Deleting the legacy file is never enough: each edge needs a **rewrite** (move implementation into a non-legacy file, stub for non-MP builds, delete the call path, or delegate to tdns-mp if you introduce a narrow bridge).

---

## TL;DR

Within **`tdns/v2`** (excluding `legacy_*.go` and `deadcode_*.go`), there is a **small, enumerable set of direct calls** into legacy-defined **functions and methods**. As of this scan, the `v2/` library surface shows:

| Consumer (non-legacy) | Legacy-defined symbol | Notes |
|----------------------|-------------------------|--------|
| `key_state_worker.go` | `pushKeystateInventoryToAllAgents` | Package-level func in `legacy_signer_msg_handler.go` |
| `key_state_worker.go` | `(*ZoneData).weAreASigner` | Method body in `legacy_hsync_utils.go` |
| `apihandler_funcs.go` | `pushKeystateInventoryToAllAgents` | Same |

In **`tdns/v2/cli`**, **`SendAgentMgmtCmd`** lives in **`cli/parentsync_cmds.go`** (shared by parentsync, legacy agent/IMR commands, and `deadcode_hsync_cmds.go`). **`RunZoneList`** lives in **`cli/zone_cmds.go`** (shared by auth zone list, agent zone list, and combiner edits). Part II of the original “non-legacy file depends on legacy-only definition” scan is cleared for these two helpers.

Everything else in `legacy_*.go` is either **only referenced from other legacy files**, from **`deadcode_*.go`**, or appears **not to be called at all from `v2/` non-legacy** (example: `HsyncEngine` in `legacy_hsyncengine.go` has no non-legacy caller in `tdns/v2` — startup for MP agents is expected to go through **tdns-mp**; still re-verify before delete).

**Important caveat**: Many **methods on `*ZoneData`** have bodies only in `legacy_hsync_utils.go` but are invoked **from other legacy files** (not listed above). Those are not “non-legacy → legacy” edges. The tables above are only **non-legacy file → legacy definition** edges.

---

## Methodology

1. **Package model**: All of `tdns/v2/*.go` is `package tdns`. There are **no import edges** between legacy and non-legacy; the compiler resolves symbols across the whole directory. A plain grep for `legacy_` in non-legacy files is useless.

2. **Definition inventory**: Legacy implementations live under `tdns/v2/legacy_*.go` (and `tdns/v2/cli/legacy_*.go` for CLI).

3. **Mechanical grep** (used for this document):
   - Enumerate **exported package-level functions** in `legacy_*.go` and search for `\bName\(` in non-legacy `v2/*.go`.
   - Enumerate a few **high-risk** symbols by name (`pushKeystateInventoryToAllAgents`, `weAreASigner`, `MPPreRefresh`, `HsyncEngine`, …).
   - For **CLI**, search non-`legacy_` `cli/*.go` for calls to helpers known to be defined in `cli/legacy_*.go`.

4. **Limits**: Method calls like `zd.someMethod()` where `someMethod` is **only** defined in legacy are **not** fully enumerated by a cheap script (receiver types vary; false positives on `.Foo(` are common). Treat this document as a **lower bound** on work; the authoritative check is **`go build` after temporarily moving `legacy_*.go` aside** (or deleting one file at a time) and fixing compile errors.

---

## Part I — Direct non-legacy → legacy calls (`tdns/v2`)

### 1. `pushKeystateInventoryToAllAgents`

- **Defined**: `legacy_signer_msg_handler.go` (package-level).
- **Called from**:
  - `key_state_worker.go` — after transitioning a key to `DnskeyStateMpremove` for an `OptMultiProvider` zone.
  - `apihandler_funcs.go` — after successful dnssec-mgmt keystore mutations (`rollover`, `delete`, `setstate`, `clear`).

**Rewrite direction** (not prescriptive, but each option is valid):

- **A.** Move the function body into a **new non-legacy** file (e.g. `keystate_inventory_push.go`) that depends only on `*Config` / `Zones` / whatever the body actually needs, and keep the behavior for the **auth + MP-signer** product path.
- **B.** Replace the body with a **no-op** guarded by `conf.Internal` / transport presence if the **tdns-auth** binary is never supposed to push KEYSTATE inventory anymore (only tdns-mp does). Only safe if product semantics confirm it.
- **C.** Introduce a **narrow hook** on `*Config` (e.g. `conf.OnKeystoreInventoryChanged(zone string)`) implemented from tdns-mp when linked; default empty in tdns — avoids importing tdns-mp from tdns.

### 2. `(*ZoneData).weAreASigner`

- **Defined**: `legacy_hsync_utils.go`.
- **Called from**: `key_state_worker.go` (`maintainStandbyKeys`, `OptMultiProvider` branch).

**Rewrite direction**: Move the method onto `*ZoneData` in a **non-legacy** file (e.g. next to other zone MP reads), or replace the call site with a **db/HSYNC-free** predicate if auth’s standby-key path can use a simpler rule.

---

## Part II — Direct non-legacy → legacy calls (`tdns/v2/cli`)

**`SendAgentMgmtCmd`** — definition in **`cli/parentsync_cmds.go`**; still used from `legacy_agent_cmds.go`, `legacy_agent_imr_cmds.go`, and `deadcode_hsync_cmds.go` via same package.

**`RunZoneList`** — definition in **`cli/zone_cmds.go`**; still used from `legacy_agent_zone_cmds.go` and `legacy_combiner_edits_cmds.go` via same package.

**Rewrite direction** (optional cleanup):

- If you want helpers out of oddly named files, move **`SendAgentMgmtCmd`** / **`RunZoneList`** into **`cli/agent_http_helpers.go`** (or similar), or delete the **tdns** CLIs that still ship MP agent/combiner flows and point users at **tdns-mp** CLIs only.

---

## Part III — Semantic coupling (not “calls legacy”, still blocks naive delete)

Non-legacy files contain **`OptMultiProvider` branches** and MP-adjacent **keystore / delegation** behavior that **assume** HSYNC / KEYSTATE / multi-signer semantics, without necessarily naming a legacy function:

Examples (non-exhaustive; use `rg OptMultiProvider` when editing):

- `key_state_worker.go` — MP gating around key states and inventory push.
- `apihandler_funcs.go` — MP hook after keystore API.
- `sign.go` — `multiProviderGating` around published→active promotion.
- `keystore.go` — `DnskeyStateMpremove` vs `removed` on delete.
- `delegation_sync.go` — `SYNC-DNSKEY-RRSET` branch for MP notifies.

These are **not** fixed by deleting `legacy_*.go` alone; they are **product logic** that must stay correct for **auth + zones that still set `multi-provider: true`** in tdns. The migration goal (“MP-only **code** leaves tdns”) may still require **rewriting** these branches into thin, explicit predicates or callbacks so the **algorithm** lives in tdns-mp.

---

## Part IV — Legacy symbols with no observed non-legacy caller in `v2/`

The following are **high-value** to re-check with `go build` / IDE references before treating as “dead”:

- **`HsyncEngine`**, **`SignerMsgHandler`** (`legacy_hsyncengine.go`, `legacy_signer_msg_handler.go`) — no `HsyncEngine(` reference outside `legacy_hsyncengine.go` under `tdns/v2` in a quick grep. MP binaries may use **tdns-mp** `MainInit` instead of tdns `v2` agent startup.
- **`MPPreRefresh` / `MPPostRefresh`** — defined in `legacy_hsync_utils.go`; **callback registration** (`zd.OnZonePreRefresh` append) was not found in a quick grep of non-legacy `v2/` (may live only in `deadcode_*` or tdns-mp now). Comments in `zone_utils.go` still mention `MPPostRefresh`.

Treat “no grep hit” as **weak evidence** — the compiler pass is definitive.

---

## Part V — Suggested verification order (before `rm legacy_*.go`)

1. **`go test` / `make` in `tdns/cmdv2`** on a branch where `legacy_hsyncengine.go` is renamed out of the build temporarily; fix every undefined symbol; restore file.
2. Repeat **per legacy file** (or cluster by subsystem) if a single rename produces too many errors.
3. Re-run the greps in §Part I–II and update this document’s tables.
4. Only then execute **Phase 10.2-style** deletion commits.

---

## Appendix — Quick grep recipes

```bash
# Exported package-level funcs in v2 legacy (sample)
rg '^func [A-Z][A-Za-z0-9_]*\s*\(' tdns/v2/legacy_*.go

# A specific symbol used outside legacy?
rg 'pushKeystateInventoryToAllAgents' tdns/v2 --glob '!legacy_*'

# CLI: who calls SendAgentMgmtCmd?
rg 'SendAgentMgmtCmd' tdns/v2/cli --glob '!legacy_*'
```

---

## Document status

This is a **point-in-time** mechanical inventory. After any refactor, re-run Part V and update the tables.
