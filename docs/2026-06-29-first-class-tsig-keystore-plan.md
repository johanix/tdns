# First-class TSIG keystore — implementation plan (consolidated 2026-06-29)

Consolidates the original plan, the critical review
([…-plan-review.md](./2026-06-29-first-class-tsig-keystore-plan-review.md)), and the
follow-up design discussion into an implementation-ready spec. **All code refs are
against `tsig-on-replication` @ `6dd2a2b`** and were re-verified (line numbers
shifted since the review — e.g. `6dd2a2b` grew `dynamic_zones.go`).

## Summary

Make TSIG keys **first-class, DB-backed keystore members**, managed like SIG(0)
and DNSSEC (`Sig0KeyStore`/`DnssecKeyStore` tables, the `keystore` CLI group, the
`KeystorePost`/`KeystoreResponse` API). Today TSIG keys live in an in-memory
`map[name]TsigDetails` populated from `keys.tsig` plus a side-channel `keys:` block
in the dynamic-zones YAML — the only key type not in the DB. This work moves them
into the DB with an explicit `origin`/`owner` model, a `keystore tsig` command set,
in-place reconcile-on-reload, no auto-drop, and advisory reference counting.

Layered onto `tsig-on-replication` (PR #269 → `dynamic-zones-mgmt`).

## 0. Already landed in #269 (so the plan doesn't re-propose it)

- **Multi-key inbound ACL** (`9f84831`): `matchACL` returns the **set** of approved
  keys for a source (union of matching entries, N keys), `checkInboundTSIG` accepts
  **any** of them. `v2/acl.go:40`, `v2/tsig_peer.go:139`. This **closes the old
  "dual-key rotation ACL gap"** — rotation's remaining work is operational docs
  only (§11), not inbound-verify code. *(Review #1.)*
- **ACL validation on the dynamic load path** + **full modify rollback** (`6dd2a2b`):
  `v2/dynamic_zones.go` LoadDynamicZoneFiles ValidateACL; ModifyDynamicZone restores
  `oldZd` on persist failure.
- **Inbound TSIG verify, signing, `allow-notify:`/`downstreams:` ACLs** (earlier #269).

## 1. Current state (verified, with refs)

| Thing | Ref |
|------|-----|
| In-memory `TsigKeyStore{mu; keys map[string]TsigDetails}` + `Get/Has/Add/Delete` | `v2/tsig_keys.go:22,33,44,50,61` |
| `TsigDetails{Name,Algorithm,Secret}` | `v2/structs.go:862` |
| Hot path: `tsigKeyProvider` / `SignForPeer` | `v2/tsig_peer.go:31,100` |
| `LoadTsigKeys()` builds store from `conf.Keys.Tsig`, swaps; rejects NOKEY/BLOCKED | `v2/tsig_keys.go:91,97` |
| `validateTsigKeySpec` / `knownTsigAlgo` / `tsigKeyDefined` | `v2/tsig_keys.go:142,131,115` |
| Reload: rebuild config keys then re-merge dynamic YAML keys | `v2/config.go:554,568,571` |
| Dynamic keys persisted in dynamic-zones YAML `keys:` block | `v2/dynamic_zones.go:316` (`DynamicConfigFile`), `:432,509,536` |
| Inline `stageInlineTsigKey`/`commitStagedTsigKey` | `v2/dynamic_zones.go:667,690` |
| Provision/Modify dynamic zone | `v2/dynamic_zones.go:710,891` |
| Catalog `tsig_key` name-only, validated via `tsigKeyDefined` | `v2/catalog.go:383,384`; `ConfigGroupConfig.TsigKey` `config.go:395`; `Catalog.ConfigGroups` `config.go:371` |
| CLI client keystore `ParseTsigKeys(*KeyConf)` → `Globals.TsigKeys` | `v2/tsig_utils.go:10,21` |
| KeyDB + `Tx` + `Begin` | `v2/db.go:283,63`; CRUD `v2/keystore.go:18,302` |
| Schema map + table DDL | `v2/db_schema.go:11,51,68`; `dbSetupTables/dbMigrateSchema/dbMigrateData` `v2/db.go:97,164,120` |
| `keystore` CLI tree (`sig0`/`dnssec`, verbs incl. `generate`,`purge`) | `v2/cli/keystore_cmds.go:48,160,84,196,369` |
| `APIkeystore` (commit in `defer` after handler) | `v2/apihandler_funcs.go:20,35,37,42,59,69` |
| `KeystorePost{Algorithm uint8, KeyType string, Force bool}` / `KeystoreResponse{Dnskeys,Sig0keys}` | `v2/api_structs.go:18,26,25,34,37,42,43` |
| `/keystore` behind shared API key + TLS, Auth+Agent only | `v2/apirouters.go:19,99,100` |
| Boot order (see §5) | `v2/main_initfuncs.go:123,130,215,228` |

**Structural difference:** SIG(0)/DNSSEC are **per-zone** (`(zonename,keyid)` PK,
`--zone` CLI). TSIG is **global** (one secret per name). `keystore tsig` therefore
takes **no `--zone`** — a deliberate UX departure.

## 2. Key model: `origin` vs `owner`

A TSIG key carries two orthogonal attributes:

- **`origin`** — *how it's managed*: `config` | `api`.
  - `config`: declared in `keys.tsig`; DB row is a materialization, reconciled
    against the YAML on reload (§6). Not CLI-deletable (edit YAML).
  - `api`: created/managed via the API/CLI; DB row authoritative. CLI-deletable,
    purgeable.
  - Catalog does **not** create keys, so `origin` is never `catalog`.
- **`owner`** — *what it's for*: an **open string** (seed `config|api|catalog`).
  Governs how a **zero-reference** key is interpreted and audit grouping. Defaults
  to `origin`. **Mutable** post-creation via `keystore tsig setowner` (api-origin)
  or the YAML `owner:` field (config-origin) — never delete+recreate.

| `origin` | `owner` | meaning |
|---|---|---|
| config | config | static key for config zones |
| api | api | dynamic key for local API zones |
| **config** | **catalog** | declared in `keys.tsig`, reconciled — but for catalog consumers, so 0 local refs is expected, never an orphan |
| api | catalog | created via API, earmarked for catalog consumers |

**Consequences:**
- **No auto-drop.** A zero-ref key is valid for both kinds (may be pre-provisioned
  for an upcoming `zone add` or for catalog consumers). Removal is always explicit.
- **Reference counting is advisory only** (§8) — shown in `list`; never an automatic
  deletion trigger. *(Resolves review #3: §2 now says "advisory/shown", not
  "warned on delete"; delete is **refused** while referenced — §9.)*
- **Secrets immutable by default; override is break-glass `--force`** (§7).
- **`delete`/`purge` gate on `origin=api`**; `purge` additionally on `owner=api` and
  zero references.

## 3. Storage: the `TsigKeystore` table

New table in `v2/db_schema.go` `DefaultTables` (`:11`), modelled on
`Sig0KeyStore`/`DnssecKeyStore` (`:51,68`) but name-keyed and without the per-zone /
rollover-state machinery:

```sql
CREATE TABLE IF NOT EXISTS 'TsigKeystore' (
    id          INTEGER PRIMARY KEY,
    keyname     TEXT NOT NULL,   -- canonical (lowercase FQDN), matches the wire name
    algorithm   TEXT NOT NULL,   -- "hmac-sha256", …
    secret      TEXT NOT NULL,   -- base64(std) raw HMAC secret
    origin      TEXT NOT NULL,   -- 'config' | 'api'
    owner       TEXT NOT NULL DEFAULT '',  -- open string; '' resolves to origin at read
    creator     TEXT DEFAULT '', -- audit: tool/user (cf. Sig0/Dnssec 'creator')
    created_at  TEXT DEFAULT '',
    comment     TEXT DEFAULT '',
    UNIQUE (keyname)
)
```

- **Naming (review #13):** SQL table is **`TsigKeystore`** (lowercase `s`) to avoid
  colliding with the Go type `TsigKeyStore` (the in-memory cache). Logs/CRUD refer
  to the table as `TsigKeystore`, the cache as `TsigKeyStore`.
- `keyname` canonicalised via `dns.CanonicalName` on every write/lookup (as the
  cache does today, `tsig_keys.go:38,55`).
- `created_at` text timestamp like `DnssecKeyStore.published_at` (`db_schema.go`).
  Stamp at insert (`time.Now().Format(...)`).

## 4. In-memory cache & lock discipline (review #14)

The Go `TsigKeyStore` (`tsig_keys.go:22`) stays as the **read-through cache**; the
hot path (`Get`/`Has`, `tsigKeyProvider`, `SignForPeer`) is unchanged. New rule for
all mutating paths:

- **Update the cache only AFTER a successful DB commit.** `APIkeystore` commits in a
  `defer` *after* the handler returns (`apihandler_funcs.go:37–46`), so the handler
  (`TsigKeyMgmt`) must **not** mutate the cache inline — instead it returns the
  changed rows and the cache is refreshed in the `defer` on `tx.Commit()` success
  (mirroring how SIG(0)/DNSSEC invalidate their caches on write). Simplest concrete
  approach: collect changed/deleted key names during the tx; after commit succeeds,
  re-`Get` those rows from the DB into the cache (or `Delete` from the cache).
- **Config reconcile** (§6) runs under `confMu` (as `ReloadConfig` already does,
  `config.go:555`) and mutates the cache under `TsigKeyStore.mu` (`tsig_keys.go:23`)
  — it must not interleave a half-built set into the live cache; reconcile in place
  (add/update/delete diff), never swap.

## 5. Boot order (review #9) — explicit

Today (`v2/main_initfuncs.go`): `LoadTsigKeys()` (`:123`) runs **before**
`InitializeKeyDB()` (`:130`), then `ParseZones()` (`:215`), then
`LoadDynamicZoneFiles()` (`:228`). For a DB-backed store this **must change**:

1. **`InitializeKeyDB()`** — move to run **before** TSIG load; creates the
   `TsigKeystore` table via `dbSetupTables` (`db.go:97`).
2. **`LoadTsigKeys()` (rewritten)** — was "build map from `conf.Keys.Tsig` + swap"
   (`tsig_keys.go:91`). Now:
   a. load every `TsigKeystore` row into the cache (incl. `origin=api`);
   b. **sync `conf.Keys.Tsig` → DB** as `origin=config` and **reconcile** (drop
      `origin=config` rows no longer in the YAML; upsert changed — §6);
   c. cache now reflects **config ∪ api**.
3. **`ParseZones()`** — validates references via `tsigKeyDefined` (`tsig_keys.go:115`,
   used at `parseconfig.go:674` and ACL checks `:738,744`). Because step 2 loaded
   `api` rows into the cache, **static zones referencing an api-origin key validate
   correctly** instead of quarantining.
4. **`LoadDynamicZoneFiles()`** — runs the one-time **legacy migration** (§13) first
   (import any YAML `keys:` block → DB, rewrite file), then enqueues dynamic zones.
   Their keys are already in the cache from step 2, so the old per-zone key re-merge
   (`config.go:571`, `loadDynamicTsigKeys`) is **removed**.

## 6. Reconcile-on-reload — three-mode, no silent overwrite (review #10)

`ReloadConfig` (`config.go:554`) currently rebuilds config keys then re-merges the
dynamic YAML keys (`:568,571`). New behaviour (replaces that block) applies the
**same three-mode model as `import`/`purge`** (§9) — a config reload must **never
silently overwrite an existing keystore secret**:

- **Default reload** (a full `config reload`, signal, or `config reload-tsig` with no
  flags), on a **successful** parse only (guard present, `config.go:557`),
  reconciles `origin=config` keys **in place** under `TsigKeyStore.mu` (no swap → no
  window):
  - **Apply the safe subset:** add new config keys (`origin=config`); drop config
    keys removed from the YAML **that are unreferenced**; identical secret = no-op.
  - **Withhold + flag (WARN), apply nothing for these:**
    1. a config key whose **secret/algorithm differs** from the stored row (api- or
       config-origin) — *no silent overwrite*; and
    2. a config key **removed** from the YAML but **still referenced** by a live
       zone (§8) — a referenced key can't be dropped (§9 delete rule).
- **`config reload-tsig --force | --interactive`** resolves the withheld
  **secret-conflicts** (case 1): `--force` overwrites all (sets `origin=config`,
  secret←YAML); `--interactive` prompts per conflict (`overwrite "X"? [y/N]`). This
  is the dedicated command — sibling of the existing **`config reload-zones`**
  (`cli/config_cmds.go:34`) — that carries the flags the signal-driven reload can't.
- Case 2 (removed-but-referenced) is **always** withheld — no `--force` escape;
  the operator must remove the zone's reference first (consistent with delete). The
  zone keeps serving with the old key until then.
- **Collision precedence is thus "config wins via the explicit override", not
  silently:** declaring `foo` in `keys.tsig` when an `origin=api foo` exists with a
  different secret is a case-1 conflict — withheld + flagged on default reload,
  taken over (→ `origin=config`) only on `config reload-tsig --force`/`--interactive`.
  (Identical secret: quiet no-op; the row's `origin` flips to `config` since config
  now declares it.)

## 7. Immutability + override (no silent replace)

- A key's secret/algorithm is **not changed in place by default**. On `add`/`import`
  a name collision with a **differing** secret/algorithm is **withheld and reported**
  (WARN: *"key X has a different secret/algorithm than the stored key; not updated —
  use --force / --interactive"*); an **identical** re-add is an idempotent no-op.
- **`--force`** is the **break-glass** in-place override (see the three-mode model,
  §9). The **preferred** way to roll a key is the **dual-key rotation procedure**
  (§11), which needs no overwrite.
- **Behaviour change to call out (review #2):** today `commitStagedTsigKey`
  (`dynamic_zones.go:690`) **always overwrites** an existing name, and CLI help
  advertises rotation via `zone modify` (`v2/cli/zone_cmds.go`). Under this plan the
  inline `zone add/modify --tsig-*` path becomes **create-if-absent / error on
  differing secret** (§14). Update CLI help and the test that currently *expects*
  overwrite+rollback (`v2/tsig_dynzone_test.go` `TestStageInlineTsigKey`).

## 8. Reference counting (advisory) (review #15)

Refcount of a key = number of live references to its canonical name across **every**
field that holds a TSIG key name. Scan the live **`Zones` map** (not just parsed
config) plus catalog config:

- `PeerConf.Key` in `ZoneData.PrimariesConf` / `Upstreams` / `Notify`
  (`structs.go:208`).
- `AclEntry.Key` in `ZoneData.AllowNotify` / `Downstreams` (`acl.go:25`).
- Catalog: `conf.Catalog.ConfigGroups[].TsigKey` (`config.go:371,395`) — config-level,
  not per-zone.

Rules:
- **Dedupe `Upstreams` vs `PrimariesConf`** (the same key appears in both after
  resolve): count **distinct (zone, field-site)** edges, and report **# zones
  referencing the name** in `list` (a single human-meaningful number).
- Static zones in main config are in the `Zones` map after `ParseZones`; scanning
  `Zones` covers them. (No separate `conf.Zones` scan needed at list time.)
- Used only for `list` display and the `delete` refuse-while-referenced gate (§9).
- **Atomicity caveat (delete).** The refuse-while-referenced check scans the live
  `Zones` map, then deletes. The keystore delete holds `confMu` (§4), **but the
  dynamic-zone mutators (`ProvisionDynamicZone`/`ModifyDynamicZone`/`RemoveDynamicZone`,
  `dynamic_zones.go:710,891` + delete) do NOT take `confMu` today** — verified;
  they mutate the thread-safe `Zones` map directly. So a concurrent
  `zone add … --primary-key K` can start referencing `K` between the check and the
  delete. The outcome is a **recoverable dangling reference** (the new zone fails to
  sign / quarantines on its next reload; fixed by re-adding `K` or repointing the
  zone) — an accepted **low-severity admin-vs-admin race**, no security impact.
  Fully closing it would require the dynamic-zone mutators to also acquire `confMu`;
  **out of scope here** (call out if/when those mutators are revisited).

## 9. CLI: `keystore tsig { list, generate, import, add, setowner, delete, purge }`

Global (no `--zone`). Mirrors `keystore sig0/dnssec` structure
(`cli/keystore_cmds.go:48,160`). **`generate`, not `create`** (review #7 — matches
existing UX, `:84,196`).

| Subcommand | Flags | Behaviour |
|---|---|---|
| `list` | — | name, algorithm, origin, owner, #refs, created. Never the secret. |
| `generate` | `--name`, `--algorithm`, `[--owner]` | server generates the secret (§12). `origin=api`. |
| `import` | `--file`, `--format bind\|nsd`, `[--owner]`, `[--interactive]`, `[--force]`, `[-v]` | extract keys from a config file; three-mode conflicts (§10). `origin=api`. |
| `add` | `--name`, `--algorithm`, `--secret`\|`--secret-file`, `[--owner]`, `[--force]` | add with a known secret. `--secret-file` preferred ([[additive-hardening-keep-cli-paths]]); conflict = error unless `--force` (§7). `origin=api`. |
| `setowner` | `--name`, `--owner` | change `owner` (api-origin only; config via YAML `owner:`). Mirrors `setstate`. |
| `delete` | `--name`, `[-y]` | api-origin only. **Refused while referenced** by any zone (no override; remove the reference first). `-y` skips the confirm prompt. |
| `purge` | `[--interactive]`, `[--force]`, `[-y]` | **dry-run by default** (lists candidates, deletes nothing); candidates = `origin=api` ∧ `owner=api` ∧ zero-ref; three-mode (§10). |

**Three-mode model (the consistency rule for *every* multi-key op — `import`,
`purge`, and config-key reconcile-on-reload, §6):**
- **default** → apply only the **unambiguous / non-destructive** subset; **withhold**
  anything that would clobber/delete an existing key; report; exit non-zero if
  anything withheld. (`import`: imports new keys, withholds conflicts.
  `purge`: every candidate is a delete ⇒ nothing in the safe subset ⇒ pure
  **dry-run**, consistent with DNSSEC purge. **config reload** (§6): add new /
  drop-removed-unreferenced config keys, withhold secret-conflicts + removed-but-
  referenced; the dedicated **`config reload-tsig`** command carries the flags.)
- **`--force`** → apply everything, no prompts.
- **`--interactive`** → prompt per withheld item (`overwrite "X"? [y/N]` /
  `purge "X" (api, 0 refs)? [y/N]`). Requires a TTY; error in non-interactive
  contexts. Mutually exclusive with `--force`.

`purge` reuses the existing **`KeystorePost.Force`** dry-run plumbing
(`api_structs.go:34`, the DNSSEC purge pattern `keystore.go:677`,
`cli/keystore_cmds.go:369`'s "Dry-run by default … --force").

## 10. `import` — formats, extraction, three-mode conflicts (review #21)

- **Formats:** `--format bind` (`key "name" { algorithm …; secret "…"; };`) and
  `--format nsd` (`key:` blocks). Explicit `--format` (auto-detect is a later
  nicety). `tsig-keygen` emits the BIND form.
- **Extractor, not a config parser:** scans the input for key declarations, ignores
  everything else — a bare snippet *or* a whole `named.conf`/`nsd.conf` are the same
  input. Does **not** follow `include`/macros. (95% case: inline key blocks.)
- **Batch:** one file → 0..N keys.
- **Three-mode conflicts (§9):** default imports new + identical-no-op, withholds
  conflicts (report, exit non-zero); `--interactive` prompts per conflict; `--force`
  overwrites all. Conflict detection is **server-side** (CLI lacks the stored secret
  to compare), so `--interactive` is a **two-phase round-trip**: (1) server applies
  the safe subset and returns the conflicting names; (2) CLI prompts, re-submits the
  approved subset with force. The prompt names the key only (no secrets shown).
- **`-v`** lists every found key with its disposition (`imported` / `unchanged` /
  `conflict`). This requires per-key disposition in the API response (§11).
- Reject reserved names `NOKEY`/`BLOCKED` (§12, review #17).

## 11. API wire model (review #12) — exact

Extend `KeystorePost` (`api_structs.go:18`) and `KeystoreResponse` (`:37`). **Do not
overload `Algorithm uint8`** (`:26`, a DNSSEC codepoint).

- `KeystorePost` additions: `TsigKeyname string`, `TsigAlgorithm string`
  (`"hmac-sha256"`), `TsigSecret string` (request-only, never echoed), `Owner string`,
  `Interactive bool`. Reuse existing `Force bool` (`:34`) and `Command/SubCommand`.
- New `Command: "tsig-mgmt"`, `SubCommand ∈ {list,generate,import,add,setowner,delete,purge}`.
  Handler **`kdb.TsigKeyMgmt(tx, kp)`** in `v2/keystore.go` (next to `Sig0KeyMgmt`
  `:18` / `DnssecKeyMgmt` `:302`), dispatched from `APIkeystore` (`apihandler_funcs.go:59,69`).
- `KeystoreResponse` additions (alongside `Dnskeys`/`Sig0keys` maps `:42,43`):
  - `TsigKeys []TsigKeyInfo` — list/result. `TsigKeyInfo{Name, Algorithm, Origin,
    Owner, RefCount int, Created string}` — **no secret**.
  - `TsigImport []TsigKeyDisposition` — per-key import outcome.
    `TsigKeyDisposition{Name, Status string /* imported|unchanged|conflict */}`.
- Authz: inherited `/keystore` gate — shared API key (`apiKeyAuthMiddleware`
  `apirouters.go:19`) over TLS, Auth+Agent (`:99,100`); identical to sig0/dnssec.
  **No mTLS** (server cert only); cross-cutting hardening, its own change (§16).

## 12. Secret generation (`generate`)

New helper in `v2/tsig_keys.go`:

```go
func GenerateTsigSecret(algorithm string) (string, error) // base64(std) of N random bytes
```

`crypto/rand`, N sized to the HMAC output (sha1→20, sha224→28, sha256→32,
sha384→48, sha512→64; matches `tsig-keygen`). Validate `algorithm` via
`knownTsigAlgo` (`tsig_keys.go:131`). **Reject reserved names** `NOKEY`/`BLOCKED` in
`generate`/`add`/`import` and the DB insert path, reusing `validateTsigKeySpec`
(`tsig_keys.go:142,147`) — same rule `LoadTsigKeys` enforces (`:97`) (review #17).

## 13. Migration (review #11) — placement + idempotency

`6dd2a2b`-era code persists dynamic keys in the dynamic-zones YAML `keys:` block
(`DynamicConfigFile`, `dynamic_zones.go:316`; written by `writeDynamicConfigFile`
`:432`, read by `loadDynamicTsigKeys` `:536`). One-shot, automatic migration.

- **Placement:** **not** `dbMigrateData` (`db.go:120` is SQL-only, no `Config`).
  Put it in a startup hook inside **`LoadDynamicZoneFiles`** (`dynamic_zones.go:153`),
  which already has `conf`, the dynamic-config mutex, and `dynamicConfigBroken`
  (`:335`) handling.
- **Steps:** if the loaded `DynamicConfigFile.Keys` is non-empty, import each into
  `TsigKeystore` as `origin=api, owner=api` (idempotent — skip names already in the
  store, e.g. config keys), then **rewrite the dynamic-zones file once** via
  `writeDynamicConfigFile` (which, post-migration, emits no `keys:` block) so
  plaintext secrets don't linger in two places. On a *successful* import only; if
  import fails, leave the block for a retry next start.
- **Idempotent detection:** "already migrated" ⇔ the file has no `keys:` block. No
  separate marker needed.
- Low risk: the YAML `keys:` block is new on this branch; nothing in production
  depends on it.

## 14. Wiring the existing paths

- **`keys.tsig` (config):** synced to DB `origin=config` + reconciled on reload
  (§5/§6). Gains an optional per-entry `owner:` field on `TsigDetails`
  (`structs.go:862`) — `yaml:"owner"`, validated as a free string; empty ⇒ defaults
  to `origin`; an *invalid* (non-string/none today) `owner` never blocks the key
  (advisory metadata). Stored in the DB on first sync and updated on reconcile when
  the YAML changes. *(Review #16.)*
- **Inline `zone add/modify --tsig-*`:** thin wrapper that creates/adds an
  `origin=api, owner=api` key via the keystore path and references it. **Create-if-
  absent / error on differing secret** (§7) — the behaviour change in `commitStagedTsigKey`
  (`dynamic_zones.go:690`); update CLI help and `tsig_dynzone_test.go`.
- **Catalog `tsig_key`:** unchanged — a name reference validated against the store
  (`catalog.go:383,384`); creates no key. (`owner=catalog` keys are how an operator
  pre-provisions.)
- **Retire** the dynamic-zones YAML `keys:` block (§13 migration); drop the reload
  re-merge (`config.go:571`).
- **Operator-facing strings (review #18):** errors that say `keys.tsig` (e.g.
  `parseconfig.go:674`, `catalog.go:388`) should also reference the keystore /
  `keystore tsig`. Sweep these in step 9/CLI.
- **CLI client parser (review #19, §12 F):** `ParseTsigKeys` (`tsig_utils.go:10`)
  already takes `*KeyConf` (same shape as the server's `keys.tsig`), so the **type
  is already shared**; the divergence is **strictness** — `ParseTsigKeys` silently
  skips incomplete entries with no reserved-name/algo checks, while `LoadTsigKeys`
  uses `validateTsigKeySpec`. Unify by having `ParseTsigKeys` call the same
  `validateTsigKeySpec` (`tsig_keys.go:142`). CLI keys stay **file-based** in
  `tdns-cli.yaml` (no DB connection — short-lived client). Own, mostly-orthogonal
  step.

## Implementation status

Project tracking lives in this doc (no Linear). **Update the table below as each
§15 step lands** — set Status, commit on `feat/tsig-first-class`, and a one-line
note if anything diverged from the plan.

| | |
|---|---|
| **Branch** | `feat/tsig-first-class` (cut from `tsig-on-replication` tip when work starts) |
| **Merge target** | `tsig-on-replication` (PR #269 stack) |
| **Started** | 2026-06-29 (`feat/tsig-first-class`) |
| **Overall** | in progress (step 10) |

**Commit workflow (per step):** finish the step → `go test -race ./...` + `go vet` clean
(compile via test/build) → **stop and report** (“step N ready”) so you can review or
redirect → **commit only when you say to** → update Status in the table below.
One commit per §15 step on `feat/tsig-first-class`; no push unless you ask.

## 15. Implementation steps (staged commits)

Each builds, passes `go test -race ./...`, `go vet`-clean; one commit each.
Reconciled with §9 (review #6).

| # | Step | Risk | ~LOC | Status |
|---|---|---|---|---|
| 1 | `TsigKeystore` table in `db_schema.go` + creation; reserved-name/`validateTsigKeySpec` on DB insert | Low | ~50 | done (`d1eb719`) |
| 2 | DB CRUD `TsigKeyMgmt` + cache-after-commit discipline (§4); in-memory store loads from DB | Med | ~220 | done (`c6c21aa`) |
| 3 | Boot reorder (§5): KeyDB before `LoadTsigKeys`; `LoadTsigKeys` = load DB + sync `keys.tsig` (`main_initfuncs.go:123,130`) | Med | ~120 | done (`656afd3`) |
| 4 | Reload reconcile in place, three-mode/no-silent-overwrite (§6); **`config reload-tsig`** CLI + API; **keep** legacy YAML re-merge on reload until step 12 | Med | ~140 | done (`d9f56d3`) |
| 5 | Reference-count scan over `Zones` + catalog groups (§8) | Low | ~70 | done (`35aa8ed`) |
| 6 | API: `tsig-mgmt` command, `KeystorePost`/`KeystoreResponse` TSIG fields + `TsigKeyInfo`/`TsigKeyDisposition` (§11) | Med | ~140 | done (`530d0c6`) |
| 7 | CLI `keystore tsig {list, add, setowner, delete}` + operator-string sweep (§14) | Med | ~200 | done (`4a86dc5`) |
| 8 | `generate` + `GenerateTsigSecret` (§12) | Low | ~70 | done (`e690cd5`) |
| 9 | `import` extractor (BIND/NSD) + three-mode (default/`--interactive`/`--force`) + `-v` (§10) | Med–High | ~250 | done |
| 10 | `purge` three-mode (reuse `Force` dry-run) (§9) | Low | ~70 | pending |
| 11 | Inline `zone add/modify --tsig-*` → create-if-absent (§7/§14); update CLI help + `tsig_dynzone_test.go` | Med | ~120 | pending |
| 12 | Legacy migration hook in `LoadDynamicZoneFiles` (§13); retire YAML `keys:` block; **remove** startup `loadDynamicTsigKeys` and reload YAML re-merge — same commit | Med | ~120 | pending |
| 13 | `owner` end-to-end: `keys.tsig owner:`, `--owner`, `setowner`, list/purge logic (§2/§9) | Low–Med | ~90 | pending |
| 14 | CLI `ParseTsigKeys` strictness unification (§14, review #19) | Low | ~40 | pending |
| 15 | Tests across all of the above | — | ~600 | pending |

Rough total ~2.2k LOC incl. tests (tests bumped from ~400 — import extractors,
reconcile, migration, refcount, immutability, three-mode). **Sequencing keeps a
working build:**
- Steps **1–3:** DB-backed store; legacy YAML paths unchanged on startup/reload.
- Step **4:** DB reconcile on reload + `config reload-tsig`; **YAML re-merge kept**
  as fallback until step 12 (no reload regression for unmigrated installs).
- Steps **5–10:** management surface; legacy paths still in place.
- Step **11:** inline `zone --tsig-*` immutability (behaviour change — call out in
  commit message).
- Step **12:** migration + **single commit** removes all YAML key paths (startup +
  reload); after this, DB is the sole store.

Status values: `pending` → `in progress` → `done (<commit>)` (or `skipped` + note).

## 16. Open / deferred

- **mTLS** — server has TLS, CLI uses the API key alone (no client cert). API-wide
  hardening (`apirouters.go:19`), its own change. *(Review #20: SQLite holds
  plaintext TSIG secrets — consistent with SIG(0)/DNSSEC private keys today; one
  line, accepted.)*
- **`comment` field (review #22):** column exists; v1 sets only `creator`
  (`"tdns-cli"` / API caller). `comment` populated by an optional later `--comment`
  flag; omit from v1.
- **Agent app-type scope (review #23):** `/keystore` is on Auth **and** Agent
  (`apirouters.go:99`). `keystore tsig` ops are available on both for consistency
  with sig0/dnssec; whether tdns-agent meaningfully *uses* TSIG keys is out of scope
  (no behaviour gated on it here).
- **`getDynamicTsigKeysFromZones` walks primaries only** (`dynamic_zones.go:509`):
  after the YAML `keys:` block is retired (§13) this function is **removed**; keys
  referenced only from `allow-notify`/`downstreams` must pre-exist in the store
  anyway (they're never persisted to dynamic YAML). Footnote, no action.

## 17. Rotation (operational — no code)

The dual-key procedure, using existing primitives (the multi-key ACL is already in
the code, §0):

1. `keystore tsig generate/add/import` a **new** key.
2. Add it to the relevant ACL(s) **alongside** the old — `downstreams:` for AXFR,
   `allow-notify:` for NOTIFY — so the server accepts **either** (N-key,
   `matchACL` union `acl.go:40`).
3. Migrate clients/secondaries to sign with the new key (flip `primaries[].key`).
4. When all use the new key, remove the old from the ACL, then `keystore tsig delete`
   it (now unreferenced).

`--force` in-place replacement (§7) exists as a break-glass alternative, not the
recommended path.
