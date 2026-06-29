# First-class TSIG keystore — plan (2026-06-29)

## Summary

Make TSIG keys **first-class, DB-backed keystore members**, managed the same way
SIG(0) and DNSSEC keys already are (`Sig0KeyStore` / `DnssecKeyStore` tables, a
`keystore` CLI group, the `KeystorePost`/`KeystoreResponse` API). Today TSIG keys
live in an in-memory `map[name]TsigDetails` populated from the `keys.tsig` config
block plus a side-channel `keys:` block in the dynamic-zones YAML file. That is
inconsistent with every other key type, and the reload path has to rebuild the
in-memory store from config and re-merge the dynamic keys (commit `bf53aef`,
review finding #4), which leaves a small swap window.

This plan replaces that with a single DB-backed store and a `keystore tsig`
command set, plus a key model that distinguishes **how a key is managed**
(`origin`) from **what it is for** (`owner`).

It is layered onto branch `tsig-on-replication` (PR #269 → base
`dynamic-zones-mgmt`). **It supersedes the interim #4 reload fix** in `bf53aef`.

## 1. Current state (verified against the code)

### TSIG keys today
- `v2/tsig_keys.go`: `TsigKeyStore { mu; keys map[string]TsigDetails }`,
  `TsigDetails {Name, Algorithm, Secret}`. In-memory only.
- Read path (must keep working unchanged): `TsigKeyStore.Get/Has`, used by
  `tsigKeyProvider.hmac` (inbound verify), `SignForPeer` (outbound sign),
  `tsigKeyDefined` (config validation) — `v2/tsig_peer.go`, `v2/tsig_keys.go`.
- Config keys: `LoadTsigKeys()` builds a fresh store from `conf.Keys.Tsig` and
  swaps it in.
- Dynamic keys: API `stageInlineTsigKey`/`commitStagedTsigKey` add to the store,
  and the secret is persisted into the dynamic-zones YAML file's `keys:` block
  (`getDynamicTsigKeysFromZones` / `loadDynamicTsigKeys`).
- Reload (`ReloadConfig`, `bf53aef`): on a successful parse, `LoadTsigKeys()`
  rebuilds config-only, then re-merges persisted dynamic keys. Correct but has a
  brief window where the swapped-in store is config-only.
- Catalog: a config group's `tsig_key` **references a key by name only**
  (`catalog.go`, validated via `tsigKeyDefined`). It does **not** distribute key
  material.

### How SIG(0)/DNSSEC keys are managed (the pattern to mirror)
- DB: `v2/db.go` — `KeyDB { DB *sql.DB; … }`, `Tx`, `kdb.Begin(ctx)` /
  `tx.Commit()` / `tx.Rollback()`.
- Schema: `v2/db_schema.go` — `DefaultTables` map of `CREATE TABLE IF NOT EXISTS`;
  `dbSetupTables()` applies them; `dbMigrateSchema()` adds later columns via
  `ALTER TABLE ADD COLUMN`; `dbMigrateData()` runs one-shot data migrations.
- CRUD: `v2/keystore.go` — `Sig0KeyMgmt(tx, kp)`, `DnssecKeyMgmt(ctx, tx, kp)`;
  `INSERT OR REPLACE` / `SELECT … rows.Scan` / `DELETE`, with a per-key in-memory
  cache invalidated on write.
- CLI: `v2/cli/keystore_cmds.go` — `keystore sig0 {…}` and `keystore dnssec {…}`
  subtrees; handler builds a `KeystorePost` and `SendKeystoreCmd`s it.
- API: `v2/apihandler_funcs.go` `APIkeystore`; `v2/api_structs.go`
  `KeystorePost{Command, SubCommand, …}` / `KeystoreResponse`. Dispatch on
  `Command` (`"sig0-mgmt"`, `"dnssec-mgmt"`), transaction opened per request.
- Secret/key generation: `v2/sig0_utils.go` `GenerateKeyMaterial` (asymmetric,
  via miekg/dns + `crypto/rand`). **No TSIG secret generator exists yet.**

### Important structural difference
SIG(0)/DNSSEC keys are **per-zone**, keyed `(zonename, keyid)`, and their CLI
takes `--zone`. **TSIG keys are global** — one secret per name, zone-independent.
So `keystore tsig` operates on a **global key namespace** (no `--zone`). This is a
deliberate UX departure from `keystore sig0/dnssec`.

## 2. The key model: `origin` vs `owner`

A TSIG key carries two orthogonal attributes (decided after design discussion):

- **`origin`** — *how the key is managed*. Values today: `config` | `api`.
  - `config`: declared in `keys.tsig` YAML; the DB row is a materialization,
    reconciled against the YAML on reload. **Not** CLI-deletable (edit YAML).
  - `api`: created/managed via the API/CLI; the DB row is authoritative. **Is**
    CLI-deletable and purgeable.
  - (Catalog does not create keys today, so `origin` is never `catalog`. If a
    future key-distribution mechanism *pushes* secrets, it adds an `origin` value.)

- **`owner`** — *what the key is for / who consumes it*. An **open enum**:
  `config` | `api` | `catalog` | `{future key-dist infra}` | …. Operator-assignable.
  Governs how a **zero-reference** key is interpreted and how keys are grouped for
  audit. Defaults to `origin` when unspecified.

They are orthogonal. The case that proves it:

| `origin` (managed via) | `owner` (for) | meaning |
|---|---|---|
| config | config | plain static key for local config zones |
| api | api | plain dynamic key for local API zones |
| **config** | **catalog** | declared in `keys.tsig`, reconciled on reload — but its purpose is catalog consumers, so **0 local refs is expected**, never flagged or purged as an orphan |
| api | catalog | created via API, earmarked for catalog consumers |

### Consequences for management
- **No auto-drop.** A zero-reference key is valid for *both* config and dynamic
  keys — it may be pre-provisioned for an upcoming `zone add` or for future
  catalog consumers. Removal is always explicit.
- **Reference counting is advisory only** — shown in `list`, warned on `delete`;
  never an automatic deletion trigger.
- **`delete`** gates on `origin`: only `origin=api` keys are CLI-deletable.
- **`purge`** is strict: candidate = `origin=api` **and** `owner=api` **and**
  zero references. Anything owned by catalog/agent/future, or `origin=config`, is
  never an orphan and is never purged.
- **Revocation:** a `config` key → remove from `keys.tsig` + reload (reconcile
  drops it). An `api` key → `keystore tsig delete`/`purge`. Restart always rebuilds
  from the authoritative sources (YAML + DB), so it is the universal reset.

## 3. Storage: the `TsigKeyStore` table

New table in `db_schema.go`, name-keyed (global), modelled on the existing key
tables but without the per-zone / rollover-state machinery:

```sql
CREATE TABLE IF NOT EXISTS 'TsigKeyStore' (
    id          INTEGER PRIMARY KEY,
    keyname     TEXT NOT NULL,          -- canonical (lowercase FQDN), matches the wire name
    algorithm   TEXT NOT NULL,          -- "hmac-sha256", "hmac-sha512", …
    secret      TEXT NOT NULL,          -- base64 (std) raw HMAC secret
    origin      TEXT NOT NULL,          -- 'config' | 'api'        (management authority)
    owner       TEXT NOT NULL,          -- open enum               (purpose; defaults to origin)
    creator     TEXT,                   -- audit: which tool/user created it (cf. Sig0/Dnssec)
    created_at  TEXT DEFAULT '',
    comment     TEXT DEFAULT '',
    UNIQUE (keyname)
)
```

- `keyname` is canonicalised (`dns.CanonicalName`) on write and lookup, matching
  the in-memory store today.
- `origin` drives reconcile + deletability; `owner` drives zero-ref interpretation
  + audit (both stored explicitly so cleanup has ground truth even when invariants
  break — a deliberate decision).
- `creator` is the existing audit notion (e.g. `"tdns-cli"`), kept distinct from
  `origin`/`owner`.

The in-memory `TsigKeyStore` becomes a **read-through cache** of this table:
populated from the DB at load, write-through on every mutation. All HMAC
sign/verify paths keep reading it via `Get/Has` (no change to the hot path).

## 4. Lifecycle & reconcile

- **Startup:** open KeyDB (table auto-created), load all rows into the in-memory
  cache, then **sync `keys.tsig` → DB** (upsert each as `origin=config`, with the
  declared `owner`), and reconcile (drop `origin=config` rows no longer in the
  YAML). `api` rows are authoritative and loaded as-is. Catalog `tsig_key`
  references are validated (name must resolve to a defined key).
- **Reload:** reconcile `origin=config` rows against `keys.tsig` **in place** under
  one lock — drop removed, upsert changed — leaving `origin=api` rows untouched. No
  store swap → **no window** (this is the proper fix that supersedes `bf53aef`).
- **Mutations** (`create`/`add`/`import`/`delete`/`purge`): DB write inside a `Tx`,
  then update the in-memory cache. `delete`/`purge` honour the `origin`/`owner`
  rules above.
- **Config-key secret duplication:** a `config` key's secret lives in both the YAML
  (the operator's editable declaration) and the DB (the materialized runtime store
  + origin/owner metadata). Intentional: YAML declares, DB materialises.

## 5. Reference counting (advisory)

A key's reference count = number of live references to its (canonical) name across
**every** field that holds a TSIG key name:

- `ZoneData.PrimariesConf[].Key`, `ZoneData.Upstreams[].Key`, `ZoneData.Notify[].Key`
  (all `PeerConf.Key`)
- `ZoneData.AllowNotify[].Key`, `ZoneData.Downstreams[].Key` (both `AclEntry.Key`)
- catalog config groups' `tsig_key`

Used only to inform `list` and to warn on `delete`. Never triggers deletion.

## 6. CLI: `keystore tsig {list, create, import, add, delete, purge}`

Global (no `--zone`). Mirrors the `keystore sig0/dnssec` command/handler structure.

| Subcommand | Flags | Behaviour |
|---|---|---|
| `list` | — | name, algorithm, origin, owner, #refs, created. |
| `create` | `--name`, `--algorithm`, `[--owner]` | server **generates** the secret (random bytes sized to the algorithm, base64); user supplies no secret. `origin=api`. |
| `import` | `--file`, `[--owner]` | bring in an existing key from a standard format (see §9). `origin=api`. |
| `add` | `--name`, `--algorithm`, `--secret` \| `--secret-file`, `[--owner]` | add with a known secret. `--secret-file` preferred; `--secret` kept (exposed; see [#3 decision]). `origin=api`. |
| `delete` | `--name`, `[--force]` | only `origin=api`; warn/refuse if referenced (override with `--force`). |
| `purge` | `[--force]` | drop all `origin=api` **and** `owner=api` **and** zero-ref keys. Never touches config/catalog/other-owner keys. |

Config-origin keys appear in `list` but are not `add/delete/purge`-able here (manage
via `keys.tsig`).

## 7. API: extend `KeystorePost` / `KeystoreResponse`

- New `Command: "tsig-mgmt"`, `SubCommand` ∈ `list|create|import|add|delete|purge`.
- Request fields (add to `KeystorePost` or a focused struct): `Keyname`,
  `Algorithm` (string, e.g. `hmac-sha256`), `Secret`, `Owner`, `Force`.
  `Secret` is request-only, never echoed back.
- Handler `kdb.TsigKeyMgmt(tx, kp)` in `keystore.go`, dispatched from `APIkeystore`.
- Response carries the key list (name, algorithm, origin, owner, refcount,
  created) — **never the secret**.
- **Authz:** same gate as the existing `keystore sig0/dnssec` mutations. *(Confirm
  what that gate is and that it is sufficient for secret-bearing ops.)*

## 8. Secret generation (`create`)

New helper (e.g. `tsig_keys.go`):

```go
func GenerateTsigSecret(algorithm string) (string, error) // base64(std) of N random bytes
```

`crypto/rand`, N sized to the HMAC algorithm's natural block/output:

| algorithm | bytes |
|---|---|
| hmac-sha1 | 20 |
| hmac-sha224 | 28 |
| hmac-sha256 | 32 |
| hmac-sha384 | 48 |
| hmac-sha512 | 64 |

(Matches `tsig-keygen` conventions.)

## 9. Wiring the existing paths onto the keystore

- **`keys.tsig` (config):** synced to DB as `origin=config` at load + reconciled on
  reload (§4). Gains an optional per-entry `owner:` field (so a config key can be
  declared `owner: catalog`).
- **Inline `zone add/modify --tsig-*`:** becomes a thin wrapper that creates/adds
  an `origin=api, owner=api` key (via the keystore path) and references it from the
  zone. **Create-if-absent guard:** supplying a secret for an existing name with a
  *different* value is an **error** (rotation is an explicit `zone modify` /
  `keystore tsig add`), to avoid silently rotating a name shared by other zones
  (keys are name-keyed / global, NSD-style).
- **Catalog `tsig_key`:** unchanged — a name reference, validated against the
  store. No key material created. (`owner=catalog` keys are how an operator
  pre-provisions for catalog consumers.)
- **Retire** the dynamic-zones YAML `keys:` block once keys live in the DB (§11
  migration).

## 10. Implementation steps (staged commits)

Each step builds, passes `go test -race ./...`, and is `go vet`-clean; committed
separately.

| # | Step | Risk | ~LOC |
|---|---|---|---|
| 1 | `TsigKeyStore` table in `db_schema.go` + creation/migration scaffolding | Low | ~40 |
| 2 | DB CRUD `TsigKeyMgmt` + in-memory store as read-through cache (load-from-DB, write-through) | Med | ~200 |
| 3 | Startup: load from DB + sync `keys.tsig`→DB (`origin=config`) with reconcile; replace `LoadTsigKeys` build+swap | Med | ~120 |
| 4 | Reload: in-place config reconcile (supersede `bf53aef`); drop the YAML re-merge + window | Med | ~60 |
| 5 | Reference-count scan helper (all key-name fields + catalog) | Low | ~50 |
| 6 | API: `tsig-mgmt` command + handler dispatch | Low–Med | ~120 |
| 7 | CLI: `keystore tsig {list,add,import,delete,purge}` | Med | ~200 |
| 8 | `create` + `GenerateTsigSecret` | Low | ~60 |
| 9 | Rewire inline `zone add/modify --tsig-*` onto the keystore + create-if-absent guard | Med | ~120 |
| 10 | Migrate YAML-persisted dynamic keys → DB; retire the `keys:` block | Med | ~90 |
| 11 | `owner` end-to-end: `keys.tsig` `owner:`, `--owner`, list/purge logic | Low–Med | ~80 |
| 12 | Tests across the above | — | ~400 |

Rough total: ~1.1–1.4k LOC incl. tests. (Sequencing keeps a working build at each
step: steps 1–4 make the store DB-backed without changing behaviour; 5–8 add the
management surface; 9–11 rewire and migrate.)

## 11. Migration

Existing branches persist dynamic TSIG keys in the dynamic-zones YAML `keys:`
block (from `bf53aef`). One-shot migration:

- On first start with the new code, if the dynamic-zones YAML carries a `keys:`
  block, import each into `TsigKeyStore` as `origin=api, owner=api` (idempotent;
  skip names already present from config), then stop writing/reading that block.
- `dbMigrateData()` is the natural home for the DB side; the YAML side is a
  read-once-then-ignore.
- No production deployments depend on the YAML `keys:` block yet (it is new on this
  feature branch), so this is low-risk.

## 12. Open decisions (to confirm before / during implementation)

1. **`import` format** — proposed: BIND `key "name" { algorithm …; secret "…"; };`
   (named.conf snippet — the natural interchange when peering with BIND/NSD).
   Optionally also `dnssec-keygen` `Khmac…` files. *Pick one to start.*
2. **`owner` assignment surface** — `keys.tsig[].owner:` for config keys, `--owner`
   for CLI; default `owner = origin`. Confirm the value set we seed
   (`config|api|catalog`) and that it is a free string (open enum).
3. **Migration trigger** — automatic on first start (proposed) vs an explicit
   `keystore tsig import-legacy` command.
4. **Authz** — confirm the existing keystore mutation gate and that it is adequate
   for secret-bearing TSIG ops.
5. **Catalog** — confirmed for now: references names only, does **not** distribute
   secrets. (If that changes later, it adds an `origin` value and a reconcile
   source; out of scope here.)

## 13. Relationship to PR #269

- #269 ships the on-the-wire TSIG machinery (sign/verify on replication) and the
  interim reload fix (`bf53aef`).
- This work folds onto the same branch (per decision) and **replaces** the interim
  reload fix with the DB-backed in-place reconcile (step 4). Until step 4 lands,
  `bf53aef` remains correct (self-healing, tiny window).
