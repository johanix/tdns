# Dynamic-Zones Management Interface + TSIG on Zone Replication

**Date:** 2026-06-23
**Status:** Design / implementation plan
**Tree:** this repo (`github.com/johanix/tdns`), package `v2/`, binary built from `cmdv2/auth`
**Related:** [2026-01-21-catalog-zone-support.md](2026-01-21-catalog-zone-support.md) (the dynamic-zones
machinery this exposes was built for the catalog consumer)

## Summary

Two independent, self-contained improvements to tdns-auth, each a pure addition:

- **Improvement 1 — Dynamic-zones management interface.** tdns-auth already has machinery to
  instantiate a zone into the running server with a given config and persist it across restarts —
  but today it is reachable *only* internally, from the catalog-zone consumer. This exposes that
  capability as a proper management surface: `zone add` / `zone delete` / `zone modify` /
  `zone list-dynamic`, on both the API and the CLI. It does not require setting up a catalog.

- **Improvement 2 — TSIG on zone-replication peer transactions.** Every DNS message exchanged
  between replication peers (primary ↔ secondary) is currently unauthenticated where it matters:
  secondary→primary SOA probes and AXFR/IXFR pulls, primary→secondary NOTIFY pushes, and
  secondary→primary AXFR/IXFR requests served by the primary. There is a standing
  `// TODO: Add support for TSIG zone transfers.` at dnsutils.go:29; the catalog path reads a
  configured TSIG key name only to discard it. This adds real per-peer TSIG on **all** of those
  paths — sign outbound, verify inbound — not `transfer.In` alone.

These are sequenced **Improvement 1 first, then Improvement 2** (rationale in §4). Improvement 1
ships a complete, useful interface on its own; a zone whose primary requires no TSIG works end to
end with none of Improvement 2's code. Improvement 2 is then layered on with **no config-syntax
change and no re-provisioning** of zones added before it, because Improvement 1 already uses the
final primary/key syntax (the NOKEY model, §5.B0).

## 1. Current state (verified against the code)

### Dynamic-zones machinery (exists, internal-only)
The catalog consumer's provisioning sequence — `AutoConfigureZonesFromCatalog` (v2/catalog.go:250),
core at catalog.go:376-445 — does, for each new member zone:
1. build a `ZoneData{ZoneName, ZoneType: Secondary, ZoneStore: parseZoneStore(...), Upstream,
   SourceCatalog, Options{OptAutomaticZone:true}}` (literal at catalog.go:376-386),
2. `Zones.Set(name, zd)` (register live),
3. `conf.AddDynamicZoneToConfig(zd)` (persist to the dynamic config file),
4. enqueue a `ZoneRefresher` on `conf.Internal.RefreshZoneCh` (catalog.go:433) — triggers the AXFR.

The persistence path is automatic and survives restart: `AddDynamicZoneToConfig`
(v2/dynamic_zones.go:466) writes the dynamic config; `WriteDynamicZoneFile` (dynamic_zones.go:24,
called post-transfer at refreshengine.go:449) writes the zone; `LoadDynamicZoneFiles`
(dynamic_zones.go:147) re-enqueues on startup. Gated by `ShouldPersistZone` (dynamic_zones.go:121).

Supporting primitives that already exist:
- Live removal: `Zones.Remove(name)` (used at apihandler_catalog.go:215/339, config.go:608).
- Persist remove: `RemoveDynamicZoneFromConfig` (dynamic_zones.go:480).
- List source: `getDynamicZonesFromZonesMap() → []ZoneConf` (dynamic_zones.go:424);
  `ZoneResponse.Zones map[string]ZoneConf` already exists to carry it (api_structs.go:175).
- Forced re-transfer: `ZoneRefresher{Force:true, Wait:true, Response:...}` (structs.go:541-545)
  re-pulls ignoring SOA serial and can confirm synchronously.
- Store defaulting: `parseZoneStore` (catalog.go:474-492) already returns `MapZone` for empty
  *or unknown* input — relevant to the map-only decision (§3, B0).

**What's missing:** no external entry point. The `/api/v1/zone` verbs (apihandler_zone.go) are
bump/sign/reload/list/etc.; `/api/v1/catalog` only manages catalogs; the CLI `zone` group
(cmdv2/cli/zone_cmds.go) has no `add`/`delete`/`modify`. The capability is real but locked to the
catalog code path.

### Zone config / primary (today)
`ZoneConf.Primary` is a plain `IP:port` string — two structs carry it: `ZoneConf` (structs.go:188)
and `TemplateConf` (structs.go:215). It is normalized at parseconfig.go:645
(`zconf.Primary = NormalizeAddress(zconf.Primary)`; `NormalizeAddress` itself is at
parseconfig.go:1382-1396) and is template-applied at parseconfig.go:1010-1011
(`if tmpl.Primary != "" { zconf.Primary = tmpl.Primary }`). A secondary AXFRs on load if the
upstream SOA serial is higher, and on NOTIFY.

### TSIG on zone-replication peers (not implemented)

Replication peers authenticate with TSIG on **every** message in the refresh/notify cycle, not only on
AXFR payload transfer. Today none of these paths apply TSIG:

| Direction | Message | Code path | Today |
|---|---|---|---|
| Secondary → primary | SOA query (serial check before AXFR) | `DoTransfer` (zone_utils.go:84) — plain `dns.Exchange` | No TSIG |
| Secondary → primary | AXFR / IXFR | `ZoneTransferIn` (dnsutils.go:54) — `transfer.In` | No TSIG; TODO at dnsutils.go:29 |
| Primary → secondary | NOTIFY(SOA) | `SendNotify` (notifier.go:95) — `Client.ExchangeContext` | No TSIG |
| Secondary ← primary | NOTIFY(SOA) | `NotifyResponder` (notifyresponder.go:122) — triggers refresh | No TSIG verify |
| Secondary → primary | AXFR / IXFR request | `ZoneTransferOut` (dnsutils.go:222) via queryresponder.go:816 | No TSIG verify; no ACL |

`ZoneTransferIn` is a `ZoneData` method; `zd.KeyDB` is already on the struct — TSIG lookup does not
require a signature change, only `zd.TsigKeyName` (§6.A2). The catalog path already *looks up*
`ConfigGroupConfig.TsigKey` (config.go:395) — only the *application* is a TODO (catalog.go:399-404).
The one existing TSIG store, `Globals.TsigKeys` (global.go:45), is keyed by bare name and used for
catalog-config checks and CLI/reporter clients — **not** auth-server replication paths. tdns-auth
never calls `ParseTsigKeys` at startup; `Config.Keys` has no yaml tag (config.go:56). There is no
per-peer TSIG keystore today.

Outbound NOTIFY targets are plain address strings (`ZoneConf.Notify []string`, copied to
`ZoneData.Downstreams`) with no key field — primary-side TSIG requires structured downstream peers
(§6.A3b), parallel to structured `primary:` on secondaries.

## 2. Why these are pure improvements

- **TSIG on replication peers** closes a long-standing gap. A secondary that cannot sign SOA probes
  and AXFR requests cannot talk to primaries that require TSIG on all messages (typical BIND
  `server-key` setups). A primary that does not verify inbound AXFR or sign outbound NOTIFY cannot
  participate in a TSIG-protected replication relationship from either side. The hooks (config
  fields, a TODO) have been sitting half-present; this finishes them across the full cycle.
- **The dynamic-zones interface** exposes an already-built capability that is currently artificially
  restricted to one caller. Making it generally callable is additive: the catalog path keeps working
  (it is re-pointed at the same shared core), and operators gain runtime zone management without a
  catalog. **Caveat (verified):** the existing dynamic-zone foundation is *already leaky on restart* —
  catalog members lose their `OptAutomaticZone` marker after a reload because `LoadDynamicZoneFiles`
  never re-derives it from the persisted `SourceCatalog`, and a catalog refresh can't heal it (it
  skips zones that already exist, catalog.go:337-340). So Improvement 1 is not a pure addition on top
  of a sound base: it must **fix the marker-reconstruction bug for all dynamic zone types** (B5),
  which is latent today, not only wire up the new API marker.

## 3. Design decisions

| Topic | Decision (2026-06-23) | Rationale |
|---|---|---|
| **Interface scope** | Full CRUD: `add`/`delete`/`modify`/`list-dynamic`, API + CLI — not a one-off `add`. | A management interface should be reasonably complete; most delete/list primitives already exist, so the marginal cost is small. |
| **TSIG scope** | **Per-peer**, keyed `(peer address, key name)`. Not global, not per-zone. Applies to **all replication peer messages**: SOA query, AXFR/IXFR, NOTIFY — sign outbound, verify inbound. | A TSIG key is a bilateral agreement between two *servers* (RFC 8945); the secret belongs to the relationship with the remote endpoint. Partial coverage (AXFR only) fails against real primaries that require TSIG on SOA queries too. Matches BIND's `server { keys ... }` model. |
| **Downstream peer syntax** | Structured `notify: [{addr, key}]`; `key` mandatory, `NOKEY` = unsigned. Hard cutover from bare-string entries (same per-zone ERROR quarantine as `primary:`). **`notify:` is the one canonical name** — the duplicate `downstreams:` field/key is removed in the same migration (§5.B0, §6.A3b). | Primary-side TSIG needs a key per downstream for outbound NOTIFY signing and inbound AXFR verification. Plain `notify: [addr, …]` strings carry no key name. Today `ZoneConf` carries *both* `Notify` and `Downstreams` (structs.go:190-191) — an ambiguity the `PeerConf` migration resolves to one. |
| **Direct-API zones gate** | `zone add` is **refused unless `dynamiczones.dynamic.allowed: true`**; persistence uses `dynamiczones.dynamic.storage` (parallel to catalog's `members.storage`). | The config field `DynamicZonesConf.Dynamic.Allowed` already exists and **defaults false** (config.go:419) but is checked nowhere — so today the gate is silently inert. The interface must honour it or it ships an always-on capability the operator believed they had disabled. |
| **`list-dynamic` scope** | Returns **all persistable dynamic zones** — predicate: `ShouldPersistZone(zd)` (catalog members, catalog zones if persistent, API-managed). **Not** the same predicate as delete/modify: those mutate only `OptApiManagedZone` zones. Catalog members appear in the list (read-only from this API) but cannot be deleted/modified here — use the catalog API for that. | `getDynamicZonesFromZonesMap()` already filters on `ShouldPersistZone`; reusing it is correct once B5 extends that gate for API zones. Using `OptApiManagedZone` for list would hide catalog members and confuse operators who expect to see the full dynamic set. |
| **API `zone add` scope (v1)** | **Secondary zones only** via API/CLI in Improvement 1. Primary zones with `notify:` peers are static-config (or catalog) only until a later extension; wire structs may carry notify peers for Improvement 2 static YAML, but `ProvisionDynamicZone` rejects `type: primary`. | Avoids half-specifying primary+notify on the API surface before TSIG and `PeerConf` notify migration land; catalog and static config cover primary today. |
| **`modify` mutable fields (v1)** | **`primary` addr/key and `options` only.** Not notify/downstreams, DNSSEC policy, update policy, store, or rename (rename = delete+add). Matches B1c scope; catalog group options remain catalog-config territory. | Keeps the first `modify` core small; notify/TSIG changes on primaries are static-config or future work. |
| **Catalog non-map store** | Re-pointing catalog at the map-only core is an **explicit breaking change** for any config group using `store: xfr` or `store: slice`. | `parseZoneStore` silently coerces empty/unknown → map today (catalog.go:474-492), so most groups are unaffected; but an *explicit* non-map store now becomes an ERROR rather than a silent honour. Consistent with no-backwards-compat — but it is a behaviour change, called out here, not buried in a §10 audit. |
| **Primary/key syntax** | Structured `primary: {addr, key}`; `key` **mandatory and explicit**, built-in sentinel `NOKEY` = unauthenticated. No default. | Makes the "no TSIG" choice deliberate and visible; makes the pre-TSIG phase *structural* rather than a special case (see §5.B0). |
| **Invalid `primary.key` handling** | **Per-zone ERROR quarantine, not a fatal parse error.** A missing/empty `key`, or a key name that doesn't resolve, puts *that zone* into ERROR state; the server still starts and other zones are unaffected. | Matches the project's resilient-config-startup rule (config errors are quarantined per-object, never fatal). "Must fail to parse" would abort the whole server — wrong. |
| **Zone store for dynamic zones** | **`MapZone` only**, enforced in the shared `ProvisionDynamicZone` core — applies to **catalog-, API-, and CLI-provisioned** zones alike. Any other store requested → reject (ERROR/error). | `slice` is legacy; `xfr` is not wanted for dynamically managed secondaries. One rule in one place removes the whole re-instantiation problem from `modify` (B1c). `parseZoneStore` already defaults empty/unknown → map, so this is a tightening, not a new behaviour. |
| **Sequencing** | Improvement 1 (interface) first, Improvement 2 (TSIG) second. | One-way dependency: the interface establishes the `PeerConf` syntax TSIG then consumes (doing TSIG first builds those structs twice). The interface also ships standalone value (NOKEY zones work end-to-end with none of TSIG's code). Risk is not the driver — under `risk = probability × consequence` (§7) both halves are Low–Med overall; the one elevated cell is B5b (resurrection race), in the interface half. |

### Why per-peer and not global or per-zone
- **Global is wrong:** `Globals.TsigKeys` keyed by bare name means two unrelated primaries that both
  use the name `transfer-key` (with different secrets) collide — the second registration silently
  overwrites the first.
- **Per-zone is wrong:** it would duplicate one shared secret across several zones that pull from the
  same primary, and cannot express "these N zones all transfer from one peer over one key."
- **Per-peer is right:** the key is a property of the remote endpoint. One upstream may serve many
  zones over one key; `(upstream, name)` is the natural tuple. Note the existing Sig0/DNSKEY stores
  in `KeyDB` are legitimately *per-zone* (a signing key belongs to a zone) — TSIG is a different kind
  of key (transport auth, belongs to a peer), so it gets a sibling store with a different key tuple.

## 4. Sequencing & why the split is safe (verified)

**Implement Improvement 1 → Improvement 2.**

The interface has no hard TSIG dependency:
- The add core's TSIG block (catalog.go:396-405) is a no-op TODO, skipped when no key is set.
- `ZoneTransferIn` already runs a plain unauthenticated `transfer.In` (dnsutils.go:75).

So a zone provisioned with primary key `NOKEY` takes exactly today's working transfer path — the
full interface is usable against unauthenticated primaries with none of Improvement 2's code. Because
Improvement 1 already establishes the final `primary: {addr, key}` syntax (§5.B0), adding TSIG later
is purely "make a non-NOKEY key name resolve" — no syntax change, no re-provisioning of existing
zones.

## 5. Improvement 1 — Dynamic-zones management interface  *(do first)*

**Implementation status (branch `dynamic-zones-mgmt`):**
- ✅ **B0a/B0b/B0c DONE** (2026-06-25) — `PeerConf{Addr,Key,Legacy}` + `NOKEY` const;
  `stringToPeerConfHook` mapstructure decode hook (dead `'Primary'/[]interface` special-case removed);
  `ZoneConf.Primary`→`PeerConf`, `Notify`/`Downstreams`→one `Notify []PeerConf`, `ZoneData.Downstreams`
  →`Notify []PeerConf` (`Upstream` stays `string`); `ZoneRefresher`/`RefreshCounter` plumbed; secondary
  key validation (legacy/missing/non-NOKEY → per-zone ERROR); catalog notify-API wraps as
  `PeerConf{Addr,Key:NOKEY}`; `TemplateConf` left untouched (dead code). All 5 binaries build;
  `peerconf_decode_test.go` proves resilient decode (mixed modern + legacy → whole-file decode succeeds,
  legacy captured as markers).
- ⏳ B6, B1a/b/c, B5a/b, B2, B3, B4 — pending.

### B0. Primary/key syntax — the NOKEY model
Every primary reference always carries a key name; built-in sentinel `NOKEY` means "no TSIG,
unauthenticated." Before the `keys:` block exists (Improvement 2), `NOKEY` is the only resolvable
name — any other key name is a hard "unknown key" parse/validation error. This makes the pre-TSIG
phase structural rather than a warned special case.

- **`NOKEY` is a reserved name.** A `keys.tsig[]` entry whose `name` is `NOKEY` (any case) is
  **rejected at parse** — that key entry, and any zone referencing it, go to ERROR. Otherwise an
  operator-declared key literally named `NOKEY` would be silently unreachable (the sentinel always
  wins the comparison), an invisible footgun. Reserve the name explicitly.

- **Representation: structured YAML**, not a space-separated string. `ZoneConf.Primary` becomes a
  `PeerConf` struct `{Addr, Key}` (shared type with structured `notify:` in Improvement 2), replacing
  the bare string:
  ```yaml
  primary:
    addr: 192.0.2.1:53
    key:  NOKEY        # Improvement 2: any declared key name
  ```
- **`key` is mandatory and explicit — no default.** A missing/empty `key` is a per-zone validation
  failure: that zone goes to **ERROR state** (server still starts), it does **not** default to
  `NOKEY` and does **not** abort config parsing. Forces a deliberate auth choice on every secondary
  while honouring the resilient-startup rule.
- `NormalizeAddress` applies to `.Addr` only. `transfer.In` with key `NOKEY` → don't set
  `transfer.TsigSecret` (today's exact path).
- **Migration (decided): hard cutover, but resilient.** Existing bare-string `primary:` values are
  **rejected** — no auto-read into `{addr, key:NOKEY}`; per the no-backwards-compat convention the
  operator migrates. Critically, the rejection must be a **per-zone ERROR quarantine, not a fatal
  decode failure** — and that is *not* free, because of how config is decoded:
- **A `mapstructure` decode hook is required — NOT a `yaml.Unmarshaler` (verified — this is the
  load-bearing correctness fix, and the obvious-looking approach does not work).** Config is decoded
  in **two stages** (verified at parseconfig.go:65-66 and 286-293): first `yaml.Unmarshal(data,
  &config)` decodes into a generic `map[string]interface{}` — the typed structs are never seen by the
  YAML library — then `mapstructure.NewDecoder(...).Decode(configMap)` converts the map into the typed
  structs. **`mapstructure` does not honor the `yaml.Unmarshaler` interface; it only reads struct
  tags.** Therefore a custom `UnmarshalYAML` method on `PeerConf` would be **dead code — it never
  fires on this path.** A bare string where a `PeerConf` is expected fails *inside* `decoder.Decode`,
  which decodes the **entire** config at once (parseconfig.go:287) — so it still aborts the whole
  file, exactly the outcome we are trying to avoid. (The pre-existing special-cased error string for
  the `Primary`/`[]interface{}` shape at parseconfig.go:289-292 is itself evidence that this failure
  mode lives in `mapstructure`, not in YAML unmarshaling.)
  - **Correct mechanism: a `mapstructure.DecodeHookFunc` registered on the `DecoderConfig`**
    (parseconfig.go:267-271 — there are **zero** decode hooks today; add one via
    `DecodeHook: mapstructure.ComposeDecodeHookFunc(stringToPeerConfHook())`). The hook matches
    `string → PeerConf` and, instead of erroring, returns a **legacy marker** value (e.g.
    `PeerConf{Addr:"", Key:"", Legacy:"<the string>"}`), letting the whole-file decode succeed.
    Per-zone validation then sees the marker and quarantines just that zone to ERROR with a clear
    "primary now requires `{addr, key}`" message.
  - **One hook covers both `primary:` and `notify:`.** For `Notify []PeerConf`, mapstructure invokes
    the hook **element-wise**, so a bare-string element in the list is converted to a `Legacy`-marked
    `PeerConf` the same way — no second hook needed.
  - **Remove the now-obsolete special-case** at parseconfig.go:289-292: once `Primary` is a `PeerConf`
    and the hook absorbs the bare-string/list shapes into legacy markers, the `'Primary'` +
    `[]interface` whole-file error branch no longer triggers and should be deleted (dead branch).
- **Touch points (verified against the code 2026-06-25 — full usage map, ~52 sites across 8 files):**
  `ZoneConf.Primary` type (structs.go:189) changes to `PeerConf`. **`TemplateConf.Primary`
  (structs.go:222) is NOT changed — `TemplateConf` is dead code** (zero live references; the real
  template path is `ZoneConf`-based via `ExpandTemplate(zconf ZoneConf, tmpl *ZoneConf)`, so
  `tmpl.Primary` reads are already `ZoneConf` fields). Leave `TemplateConf` untouched (don't delete
  unused code without asking). `stringToPeerConfHook` + `DecodeHook` wiring on the `DecoderConfig`
  (parseconfig.go:267-271, new); normalize `.Addr` at parseconfig.go:645 (and the `==`/`!=` empty- and
  change-checks at parseconfig.go:636/646 compare `.Addr`); template empty-checks `tmpl.Primary.Addr
  != ""` / `len(tmpl.Notify) > 0` at the real call site (`ExpandTemplate`); `zoneDataToZoneConf`
  persistence (dynamic_zones.go:~311). **`ZoneData.Upstream` STAYS `string`** — it's consumed as a bare
  address by the AXFR machinery (`ZoneTransferIn(zd.Upstream, …)`) and logs (~14 sites); `PeerConf`
  collapses to `.Addr` flowing *into* `Upstream` and rehydrates as `Primary{Addr: zd.Upstream}` on the
  way out. `TsigKeyName` is added alongside `Upstream` later (Improvement 2 step 2), not here.
  `ZoneRefresher.Primary`/`Notify` and `RefreshCounter` also carry these — convert in step. Structured
  `notify:` (Improvement 2, A3b) uses the same `PeerConf` type and the same hook — do not introduce a
  second struct. **Also consolidate the duplicate `ZoneConf.Notify`/`ZoneConf.Downstreams` (structs.go:190-191)
  and `ZoneData.Downstreams` (structs.go:~111) to a single `notify`-named `[]PeerConf` during this
  migration** — `notify:` is canonical, `downstreams:` is removed.
- **Catalog notify-API stays address-only (decided 2026-06-25).** The existing catalog notify
  add/remove/list handlers (`apihandler_catalog.go:627-728`) are string-based (`CatalogPost.Address
  string`, `==` comparisons, `[]string` copy into `CatalogResponse.NotifyAddresses`). When
  `ZoneData.Downstreams` becomes `[]PeerConf`, **wrap internally as `PeerConf{Addr: address, Key:
  NOKEY}`** — the wire API stays address-only, `NotifyAddresses` stays `[]string`, comparisons/append/
  copy operate on `.Addr`. **Do NOT** add a key field to the catalog notify-API: catalog zones
  typically manage edge servers (pure secondaries), not core servers with downstreams, so catalog-
  managed TSIG notify peers is a non-need; adding the TSIG machinery there is overengineering. A
  NOKEY-keyed catalog notify peer *is* the correct NOKEY-model representation, not a workaround. (If
  ever wanted, extending the catalog notify-API with a key is a clean additive change in a later step.)

### B1. Shared cores in v2/dynamic_zones.go
Factor reusable methods so the catalog path and the new API/CLI both call the same code (no
divergence):
- `ProvisionDynamicZone(in DynamicZoneInput) (string, error)` — *add* core, extracted from
  catalog.go:376-445. Steps: **gate on `conf.DynamicZones.Dynamic.Allowed` for API/CLI callers —
  refuse with a clear error when false** (the field exists at config.go:419, defaults false, and is
  checked nowhere today; catalog provisioning is gated by its own `members` config, so the
  `Dynamic.Allowed` check applies to the API/CLI entry path, not the catalog re-point); **reject
  `type: primary`** (API/CLI v1 is secondary-only, §3); validate FQDN
  + non-duplicate (`Zones.Get`); validate the primary's key name (Improvement-1 phase: must be
  `NOKEY`, else "unknown key"); **enforce `MapZone` — reject any other requested store** (single
  chokepoint for the map-only rule, §3); build `ZoneData` (carrying `{addr,key}`); `Zones.Set`;
  `AddDynamicZoneToConfig` (persist under `dynamiczones.dynamic.storage` for API zones, parallel to
  catalog's `members.storage`); enqueue `ZoneRefresher`. Re-point `AutoConfigureZonesFromCatalog` at
  this same core — **so catalog members are also map-only**; the current catalog literal sets
  `ZoneStore: parseZoneStore(storeValue)` (catalog.go:379), which after re-pointing must resolve to
  map or be rejected (an *explicit* non-map store is now an ERROR — the breaking change called out in
  §3).
  `DynamicZoneInput = {Name, Type, Primary{Addr,Key}, Options}` — no `Store` field; store is always
  map. (TSIG secret fields added to the wire structs now, consumed in Improvement 2.)
  - **Async, fire-and-forget enqueue — the core does NOT wait for the AXFR (decided 2026-06-25).**
    `ProvisionDynamicZone` enqueues a `ZoneRefresher` with **no `Wait`, no `Response`** (the existing
    `dynamic_zones.go:225-247` pattern) and **returns immediately** once the zone is registered and
    persisted. It does **not** block on the initial transfer. Rationale: a zone transfer can take a
    long time, and a synchronous core would (a) hang the CLI/API call and (b) serialize the catalog's
    per-member provisioning loop — each `AutoConfigureZonesFromCatalog` member blocking on a full
    AXFR. Both are unacceptable, so the catalog re-point stays a true no-op. The caller observes
    progress by **polling** (`list-dynamic`/`list-zones`) — see the `Provisioning` state field, B2/B3.
  - **Ordering + rollback.** Register before persist; roll back the live registration if persist
    fails: (1) `Zones.Set(name, zd)`; (2) `AddDynamicZoneToConfig(zd)` — **if this fails, `Zones.Remove`
    the just-set zone and return the error** (do not leave a live-but-unpersisted zone that vanishes on
    restart — the catalog "log-and-continue" precedent is wrong for an operator-facing `add`); (3)
    only after persist succeeds, enqueue the `ZoneRefresher`. So a returned success means "registered
    **and** persisted, transfer pending," never "registered but will disappear on reboot."
- `RemoveDynamicZone(name) (string, error)` — *delete* core: verify the zone exists and is a
  dynamic/API-managed zone (refuse to delete statically-configured zones — guard on the marker, B5);
  `Zones.Remove`; **bump the zone's generation counter (B5)** so any in-flight refresh on the captured
  pointer self-aborts at its pre-persist re-check (without this, a mid-flight refresh resurrects the
  files we are about to remove); `RemoveDynamicZoneFromConfig`; best-effort remove the persisted zone
  file; refcounted `DeleteTsigKey` for the upstream key (step 10). Mostly a wrapper over existing
  primitives **plus** the generation bump, which is the new interlock.
- `ModifyDynamicZone(in DynamicZoneInput) (string, error)` — *new* core (no existing equivalent).
  Look up the live `ZoneData`; refuse if not dynamic (the `OptApiManagedZone` guard, B5).
  **Implemented as stale-old + build-new + replace, NOT in-place field mutation** — this eliminates a
  data race by construction (see B5 concurrency below; refresh reads `zd.Upstream` *without* a lock, so
  mutating it under `zd.mu` would still race). Steps:
  (1) bump the old `ZoneData`'s generation counter (B5) so any in-flight refresh on the captured
  pointer self-aborts at its pre-persist re-check; (2) build a **fresh** `ZoneData` with the changed
  params (`Primary{Addr,Key}`, `Options`) carried over from the old one; (3) `Zones.Set(name, newZd)`
  (replace); (4) `AddDynamicZoneToConfig(newZd)` (overwrites the entry); (5) enqueue
  `ZoneRefresher{Force:true}` to re-pull from the (possibly new) upstream.
  Scope (simplified by the map-only decision, §3): **store is fixed at map — no re-instantiation
  subtlety**; renaming is out of scope (that's delete+add) — `modify` = same zone name, change
  transfer parameters (`primary` addr/key, options). **Operator-visible note:** there is a sub-ms
  window between `Zones.Set` replacing the entry where a concurrent query for this zone is REFUSED;
  acceptable for a management op on a secondary that is about to re-AXFR regardless (decided
  2026-06-24).
  - **Key/peer change handling (the keystore must follow the change — A3 gap fix):** changing
    `primary.addr`-IP and/or `primary.key` changes the keystore tuple `(peerIP, key_name)`. Because
    `modify` is delete+re-add, the keystore ops attach to the two halves: the new `ZoneData` adds its
    key, the old tuple is refcount-dropped.
    - *Improvement 1 (no TSIG yet):* the only legal key value is `NOKEY`, so a modify moves only
      `NOKEY` ↔ `NOKEY` — no keystore op, but the validation (must be `NOKEY`) still runs.
    - *Improvement 2:* if the modify supplies a new non-`NOKEY` key (with secret via the API
      `{tsig_*}` fields, or referencing a declared `keys.tsig[]` name), call
      `AddTsigKey(peerIP(newAddr), newKey, …)` for the new tuple **and** refcount-drop the old via
      `DeleteTsigKey(peerIP(oldAddr), oldKey)` (drop only if no other live zone still references the
      old `(peerIP, name)` — same refcount rule as `delete`, step 10). A change to the **IP** or the
      **key name** re-binds under the new `(peerIP, key)` and refcount-drops the old; a **port-only**
      change (same IP, same key) is **not** a keystore change — only the send target moves.
    - Config-declared (`keys:`) keys are never refcount-dropped by a modify (config owns them, step 3).

### B2. API request/response
Extend `ZonePost` (api_structs.go:159) with `Options []string` and the structured primary
(`PeerConf{Addr, Key}`) plus the TSIG secret-bearing fields that Improvement 2 will consume
(`TsigName, TsigSecret, TsigAlgo`). **No `Store` field** — dynamic zones are map-only (§3), so the
wire struct carries no store selector (mirrors B1's `DynamicZoneInput` and B4's omitted `--store`
flag). Reuse the existing `ZoneResponse` (already has `Zones map[string]ZoneConf`, `Status`, `Msg`,
error fields). **Secrets never travel back:** `TsigSecret` is request-only; the response's
`ZoneConf`/`PeerConf` carry key *names*, never secrets (see B5 secret-locality invariant).

**Async-add state field (decided 2026-06-25).** Because `add` is fire-and-forget (B1), the operator
polls for transfer progress — so add **one derived field** `Provisioning string` to `ZoneConf`
(values `"pending"` | `"loading"` | `"ready"` | `"error"`). It is **not** a new `ZoneData` field:
derive it in the `list-zones`/`list-dynamic` handler from the new `ZoneStatus` (B6) plus the existing
error registry:
```go
if zd.Error {
    pp = "error"                       // ConfigError/etc — see ErrorType/ErrorMsg
} else {
    pp = ZoneStatusToString(zd.Status) // "pending" | "loading" | "ready" (B6)
}
```
(`ZoneStatus` is the real positive-lifecycle source built in B6; `Error` takes precedence so a zone
that loaded once and later hit a `RefreshError` reads `"error"`, not `"ready"`. The
`Error`/`ErrorType`/`ErrorMsg` fields carry the failure detail.) An operator does `add` → poll
`list-dynamic` until `Provisioning` leaves `"pending"`/`"loading"`. **Secrets never travel back**
(unchanged): `TsigSecret` is request-only; the response's `ZoneConf`/`PeerConf` carry key *names*,
never secrets.

### B3. API handlers
In `APIzone` (apihandler_zone.go:17, switch at ~56) add four cases mirroring the catalog handler
style (apihandler_catalog.go:52-88), each calling the matching B1 core:
- `case "add":` → `ProvisionDynamicZone`. Returns **immediately** after register+persist+enqueue (the
  AXFR runs async, B1). Response is **accepted + poll hint**: `Status: "accepted"`, `Msg` ≈
  `"provisioning; poll list-dynamic for state"`, with the zone name. The zone is live in the map at
  once (so `delete`/`modify`/`list-dynamic` work immediately); only its data is pending — the operator
  polls `Provisioning` (B2) for `ready`/`error`.
- `case "delete":` → `RemoveDynamicZone`
- `case "modify":` → `ModifyDynamicZone`
- `case "list-dynamic":` → `getDynamicZonesFromZonesMap()` into `ZoneResponse.Zones` (the existing
  `list-zones` lists *all* zones; this lists the **persistable dynamic subset** per
  `ShouldPersistZone` — catalog members and API-managed zones, not static zones). Catalog members
  are **listed but not mutable** through these handlers (delete/modify guard is `OptApiManagedZone`
  only; catalog lifecycle stays on `/api/v1/catalog`).
Guard all with the existing API auth. Mutating verbs validate inputs and return structured errors
(duplicate, not-found, not-dynamic, unknown-key, not-api-managed).

### B4. CLI subcommands (cmdv2/cli/zone_cmds.go)
`zone add`, `zone delete`, `zone modify`, `zone list-dynamic`, mapping to `ZonePost{Command:...}` via
the send helper, following the existing inline `&cobra.Command{Use:...}` idiom (verified at
zone_cmds.go:30+). Shared flags: `--zone --primary-addr --primary-key --options` (delete needs only
`--zone`; list needs none). **No `--store` flag** — dynamic zones are map-only (§3), so a store flag
would be meaningless; omit it rather than accept-and-ignore. Add the `--tsig-*` flags now (inert until
Improvement 2; in Improvement 1 a non-`NOKEY` key is rejected, so define the inert behaviour: the
flags parse and are carried on the wire but provisioning ERRORs on any non-`NOKEY` value — they are
*store-for-later*, not silently dropped).

### B5. Persistence + safety marker  *(the safety boundary — get it right)*
Extend `ShouldPersistZone` (dynamic_zones.go:121) with an explicit third branch so API-managed
zones persist & reload via `LoadDynamicZoneFiles`. Today only catalog-zone and catalog-member
branches exist; the "Future: other dynamic zone types" comment at dynamic_zones.go:138-139 is this
work. After B5:

```go
// OptCatalogZone     → catalog_zones.{allowed, storage}
// OptAutomaticZone   → catalog_members.{allowed, storage}
// OptApiManagedZone  → dynamic.{allowed, storage}   // NEW
```

The marker serves two **different** predicates:
- **`list-dynamic`** — any zone for which `ShouldPersistZone(zd)` is true (catalog + API).
- **`delete` / `modify`** — `OptApiManagedZone` only; refuse static and catalog-managed zones.

**Decided design — dedicated marker, no sentinel overload:**
- Add a new `ZoneOption` **`OptApiManagedZone`** (enums.go; siblings `OptAutomaticZone` @41,
  `OptCatalogZone` @44 — note `OptApiManagedZone` does **not** exist yet, contrary to a casual read).
  Runtime classification then becomes unambiguous: catalog zone → `SourceCatalog != ""`; API zone →
  `OptApiManagedZone == true`; static zone → neither. The `delete`/`modify` guard is a single
  `OptApiManagedZone` check.
- Add a new **`ZoneConf` field `ApiManaged bool`** (structs.go:184-215; `SourceCatalog` already lives
  at structs.go:214 — add the boolean adjacent to it). **Do NOT reuse `SourceCatalog="api"` as a
  sentinel** — `SourceCatalog` is semantically "the name of the catalog that created this zone," and
  a magic string there forces every consumer (lookups, display, the catalog reconciler) to special-
  case it. That is exactly the "accept two meanings for one field" pattern the project forbids. One
  bool with one meaning instead.

**The marker must survive write→reload — and this is a latent bug that already affects CATALOG
zones today (verified). Fix it once, for all dynamic zone types — do not scope the fix to API zones.**

The reviewer caught that this is not merely a risk for the *new* marker; the *existing* catalog path
is already broken on restart:

| Stage | Code | Behaviour today |
|---|---|---|
| Write | `zoneDataToZoneConf` | Writes `SourceCatalog` (dynamic_zones.go:315) but **skips `OptAutomaticZone`** on write (dynamic_zones.go:279 — treated as internal). |
| Reload | `LoadDynamicZoneFiles` | Rebuilds `Options` from `OptionsStrs` **only** (dynamic_zones.go:207-233); **never re-derives `OptAutomaticZone` from `SourceCatalog`**. |
| Persist gate | `refreshengine.go:447-448` | Post-refresh write requires `ShouldPersistZone(zd) && zd.Options[OptAutomaticZone]`. |
| Static-reload spare | `config.go:603-605` | Only zones with `OptAutomaticZone` are spared when absent from static config. |
| Catalog self-heal | `catalog.go:337-340` | A catalog refresh **skips zones that already exist** — so it cannot restore a lost marker. |

Consequence: after a restart, a reloaded catalog member has `SourceCatalog` set but
`OptAutomaticZone` unset → `ShouldPersistZone` returns false → its zone file stops being rewritten,
and `ReloadZoneConfig` no longer spares it. The marker is lost permanently. **This is a pre-existing
bug we inherit; Improvement 1 must fix it generically.**

**Unified marker-reconstruction spec — write every marker, re-derive every marker:**
- *Write* (`zoneDataToZoneConf`): write `SourceCatalog` (already done) **and** new `ApiManaged:
  zd.Options[OptApiManagedZone]` beside it.
- *Reload* (`LoadDynamicZoneFiles`, when rebuilding the zone before enqueue at
  dynamic_zones.go:225-234): re-derive runtime markers from persisted fields —
  `if zconf.SourceCatalog != "" { Options[OptAutomaticZone] = true }` (fixes the catalog bug) and
  `if zconf.ApiManaged { Options[OptApiManagedZone] = true }` (the new path). Both derivations in one
  place.
- *Persist gate* (`refreshengine.go:447-448`): the post-transfer write currently keys on
  `OptAutomaticZone` specifically; **extend it to "any persistable dynamic zone"** so API-managed
  zones (which carry `OptApiManagedZone`, not `OptAutomaticZone`) also get their zone files rewritten.
  Otherwise B5's write/read alone is insufficient — refreshengine would still skip API zones.
- *Static-reload spare* (`config.go:603-605`): this is a **separate path from `LoadDynamicZoneFiles`**
  — `ReloadZoneConfig` runs on SIGHUP/API reload (not startup), re-reads the **static** config, and
  removes any live zone absent from it unless spared. Today the spare check is `OptAutomaticZone`
  only. **It must be widened to `ShouldPersistZone(zd)`** (equivalently `OptAutomaticZone ||
  OptApiManagedZone`). Without this, an API-managed zone — which is never in the static config — is
  `Zones.Remove`d on the **first config reload** (not even a restart). This is the reload-spare gap;
  the refreshengine persist-branch extension above does not cover it because reload and post-transfer
  persist are different code paths.

The canonical write/read matrix (one table the implementer fills and the tests assert against):

| Field / marker | Written by `zoneDataToZoneConf` | Re-derived by `LoadDynamicZoneFiles` | Gate(s) that consume it |
|---|---|---|---|
| `SourceCatalog` (string) | yes @315 | sets `OptAutomaticZone` (NEW) | persist gate, static-reload spare |
| `ApiManaged` (bool, NEW) | NEW, beside @315 | sets `OptApiManagedZone` (NEW) | `ShouldPersistZone` (dynamic branch), delete/modify guard |
| `OptAutomaticZone` | no (internal) | from `SourceCatalog` | `ShouldPersistZone` (catalog_members branch), refreshengine persist, config.go spare (widened to `ShouldPersistZone`) |
| `OptApiManagedZone` | no (internal) | from `ApiManaged` | `ShouldPersistZone` (dynamic branch), delete/modify guard, refreshengine persist, config.go spare (widened to `ShouldPersistZone`) |
| `Primary{Addr,Key}` | yes (struct) | direct | transfer, TSIG lookup |
| `notify` `[]PeerConf` | yes (Improvement 2) | direct | NOTIFY sign, inbound AXFR ACL |

**This reconstruction has the highest *probability* of an incomplete fix in Improvement 1** — but low
*risk* (§7 model), because its *consequence* is ~zero: it's a fix for an **existing** latent bug, so a
wrong implementation leaves managed zones exactly as broken as they are today (work until the first
restart, then silently lose managed status — guard can't distinguish them from static, files stop
persisting), not newly broken. High-probability-of-getting-it-wrong × near-zero-blast-radius = low
risk; the cost of a miss is *non-improvement*, not regression. The verification difficulty is real
(silent failure, needs a restart cycle), which is exactly why probability is high — so: mandatory
restart + guard tests for both zone types. (Contrast B5b, where the new delete/modify triggers give the
resurrection race a non-zero, operator-visible consequence — *that* is the genuinely elevated cell.)

**Restart semantics (decided — make explicit).** On restart, dynamic zones do **not** load their
persisted `.zone` file from disk; they re-AXFR via `LoadDynamicZoneFiles` → `RefreshZoneCh` →
`initialLoadZone` → `FetchFromUpstream` (`ZoneTransferIn("axfr")`, zone_utils.go:234). The singular
`LoadDynamicZoneFile` (dynamic_zones.go:73) is **dead code** — never called. Decision: **keep the
re-AXFR-on-restart model** (it is the working reality) and **delete the dead `LoadDynamicZoneFile`**
rather than wiring it. Document the implication for operators: a TSIG-required primary that is down at
boot, or a very large zone, delays that secondary's availability until the AXFR completes — load from
disk is *not* a fallback today and we are not adding one in this work.

**Concurrency: the refresh goroutine vs delete/modify (a latent resurrection race — verified).** This
is the second inherited bug B5 must fix, distinct from the marker bug above. Verified mechanics:
- Each refresh runs in a **detached goroutine** (`go func(zd *ZoneData, …)`, refreshengine.go:412)
  that captures the `*ZoneData` pointer **at dispatch time**.
- On success it persists: `WriteDynamicZoneFile` + `AddDynamicZoneToConfig` (refreshengine.go:449/456,
  and the ticker path ~679-691) — using the captured pointer, with **no re-check** that the zone still
  exists.
- `Zones` is a sharded `Cmap` (global.go:55) with atomic `Set`/`Remove`/`Get` but **no compound
  atomicity** and **no global lock** to hold across Set+enqueue or Remove.
- `ZoneData` has **no** deletion/stale/generation field, and `ZoneRefresher` has **no** context — the
  goroutine cannot be cancelled and never checks liveness.

Consequence (happens today via catalog reload; the API delete/modify add two more triggers): a
`Zones.Remove` that lands while a refresh is mid-flight does **not** stop the goroutine, which then
re-writes the zone file + dynamic-config entry — **resurrecting a deleted zone** (it reappears from
disk on next restart). Separately, `ModifyDynamicZone` mutating `zd.Upstream` under `zd.mu` would
**race** the refresh, which reads `zd.Upstream` *without* a lock (zone_utils.go:95/217/234) — a
`-race` failure and a possible AXFR from a half-updated target.

**Interlock — one new primitive, one guard:**
- Add `ZoneData.generation atomic.Uint64`. Snapshot `gen := zd.generation.Load()` when dispatching a
  refresh (capture it in the goroutine alongside `zd`).
- **Every removal/replacement bumps it:** `RemoveDynamicZone`, `ModifyDynamicZone` (delete+re-add),
  and `ReloadZoneConfig`'s `Zones.Remove` (config.go:608) all `zd.generation.Add(1)` after touching
  the map.
- **Pre-persist guard** at both persist sites (refreshengine.go:447 and the ticker path): before
  `WriteDynamicZoneFile`/`AddDynamicZoneToConfig`,
  ```go
  if cur, live := Zones.Get(zd.ZoneName); !live || cur != zd || zd.generation.Load() != gen {
      return // zone was deleted or replaced mid-refresh — do not persist (no resurrection)
  }
  ```
  (`cur != zd` also catches the modify replace: the map now holds the *new* `ZoneData`, so the old
  goroutine's pointer fails the identity check and exits.)
- **`modify` avoids the data race by construction** (B1c delete+re-add): no in-flight goroutine ever
  sees a mutated `zd.Upstream`, because the live params live on a *new* `ZoneData` and the old one is
  only ever read by its now-doomed refresh. We therefore do **not** need to add locking to the hot
  AXFR read path.

This interlock is small but load-bearing: it closes the resurrection race for **delete, modify, and
the pre-existing catalog-reload path** at once.

Note on persistence format (verified): the dynamic config is per-zone hardwired, no template.
`zoneDataToZoneConf` serializes each live `ZoneData` into a complete `ZoneConf`;
`writeDynamicConfigFile` (dynamic_zones.go:361) rewrites the whole `zones:` list atomically. The
catalog `ConfigGroupConfig` template is resolved away at provision time and never appears in the
persisted form — so `modify` is cleanly per-zone with no inheritance to reason about. **The persisted
dynamic config also uses the bare-string `Primary`/`Notify` shape today — it needs the same
struct migration as static configs (handled by the shared `stringToPeerConfHook` decode hook, B0).**

### B6. Zone status infrastructure (minimal — field + setter + getter)

The async `add` (B1) needs a queryable "is it loaded yet?" signal. Today that is only inferable from
loose booleans (`zd.Ready`, `zd.FirstZoneLoad`). **Decision (2026-06-25): add a minimal positive-
lifecycle `ZoneStatus` — a new field on `ZoneData` + a setter + a getter. Deliberately not fancy:**
no registry, no derived-field recomputation, no severity ordering (the error registry has all that;
status does not need it). Status (positive lifecycle) and the error registry (faults) are orthogonal;
the API surfaces "error" with precedence (B2). Every zone gets a status (static/catalog included), but
this is a few lines, not infrastructure.

- **`ZoneStatus uint8` enum (enums.go) + `ZoneStatusToString` map:**
  ```go
  ZoneStatusUnknown ZoneStatus = iota // zero value; pre-registration
  ZoneStatusPending                   // registered + enqueued, no data yet
  ZoneStatusLoading                   // transfer/file-load in progress
  ZoneStatusReady                     // data populated (≥1 successful load)
  ```
- **`ZoneData.Status ZoneStatus` field + `SetStatus(s)` setter + `GetStatus()` getter.** `SetStatus`
  takes `zd.mu`, assigns, `Zones.Set(zd.ZoneName, zd)` (same lock discipline as `SetError`, but ~5
  lines — no recompute). `GetStatus` reads under the lock. That's the whole API. At the `new_zd`
  replacement sites (zone_utils.go:167/245) set `new_zd.Status` directly on the struct (match the
  existing `new_zd.Ready = true` pattern) rather than `SetStatus` on the doomed old pointer.
- **Three transition sites** (co-locate with existing markers so status and `Ready` never disagree):
  `Pending` at enqueue (`ProvisionDynamicZone`, `LoadDynamicZoneFiles`, the fresh-zone build
  @refreshengine.go:566); `Loading` at the top of `FetchFromUpstream`/`FetchFromFile`; `Ready` at the
  existing `Ready`/`FirstZoneLoad`-flip sites (zone_utils.go:183/199/259/275, and :167/245). Leave the
  `// this is a lie` stub at :165 as `Pending` (no real data).
- **Do NOT touch `Ready`/`FirstZoneLoad` consumers.** Status is added *alongside*; the existing
  `!zd.Ready` gates are not rewritten (that's a future convergence, §10). Minimal blast radius.
- **API exposure:** `ZoneConf.Provisioning` (B2) = `zd.Error ? "error" : ZoneStatusToString(zd.Status)`.

### Tests (Improvement 1)
- `add` → **returns immediately** (does not block on AXFR) with `Status: accepted`; zone is live in
  the map at once; `list-dynamic` shows `Provisioning: "pending"`, then `"ready"` after the NOKEY AXFR
  (against an unauthenticated primary) completes. Survives restart **with `OptApiManagedZone` re-set
  from persisted `ApiManaged`** (the B5 reload path — the critical case: after restart the zone must
  still be `delete`/`modify`-able and appear in `list-dynamic`).
- `add` then poll → `Provisioning` transitions `pending → ready`; an `add` against an **unreachable**
  primary stays queryable and ends in `Provisioning: "error"` with `ErrorType`/`ErrorMsg` set (the
  async path surfaces failure via state, not via the `add` return).
- **B6 status (unit):** `SetStatus(ZoneStatusLoading)` then `GetStatus()` returns it; a zone carrying
  both `ZoneStatusReady` and a `RefreshError` reports `Provisioning: "error"` (error precedence), and
  clearing the error reverts it to `"ready"` (status and error registry are orthogonal).
- **Add rollback:** if `AddDynamicZoneToConfig` fails after `Zones.Set`, the zone is **not** left live
  — `add` returns an error and the zone is absent from the map (no live-but-unpersisted zone that
  would vanish on restart).
- **Catalog-marker regression (the inherited bug):** provision a catalog member, restart, assert
  `OptAutomaticZone` is re-derived from `SourceCatalog`, the zone still persists (`ShouldPersistZone`
  true), and `ReloadZoneConfig` still spares it. This must pass *after* the B5 fix and would fail
  against today's code.
- **API zone survives a config RELOAD (the reload-spare gap, distinct from restart):** `add` an API
  zone, then trigger `ReloadZoneConfig` (SIGHUP/API reload) with that zone **absent from the static
  config** (it always is). Assert the zone is **still live** afterwards — i.e. the widened
  `ShouldPersistZone(zd)` spare at config.go:603 kept it. Against the un-widened
  `OptAutomaticZone`-only check this fails: the API zone is `Zones.Remove`d on the first reload.
- `add` refused when `dynamiczones.dynamic.allowed: false`; accepted when true.
- `add` with `type: primary` → **rejected** (API v1 secondary-only).
- `add` with a non-map store requested → **rejected** (map-only enforcement, all callers).
- `delete` → gone from live map + persisted config; **refuses to delete a static OR catalog zone**
  (guard is `OptApiManagedZone`); catalog member visible in `list-dynamic` but delete returns
  not-api-managed error.
- `modify` → change upstream → forced re-transfer pulls from new primary. (No store-change case —
  store is fixed at map.)
- `modify` → change `options` only (no addr/key change) → new `ZoneData` carries the updated options,
  zone re-pulls, survives restart. (Covers the second in-scope mutable field, §3.)
- `modify`/`delete` on a static zone → refused with a clear error.
- **Concurrency — resurrection (the inherited race):** `delete` (or a config reload removing the zone)
  while a refresh is mid-flight → after the refresh goroutine completes, the zone file and dynamic
  config entry are **gone** (the pre-persist generation guard fired); the zone does **not** reappear
  on restart.
- **Concurrency — modify is race-free under `-race`:** `modify` while a refresh is in-flight →
  test passes under `go test -race`; the old refresh self-aborts (identity/generation guard), the new
  `ZoneData` AXFRs with the new params; no torn read of `Upstream`.
- `list-dynamic` → returns all zones matching `ShouldPersistZone` (catalog members **and**
  API-managed), not static zones — catalog entries are visible but not mutable via these handlers.
  **Including after a restart** (regression guard for the B5 reload gap).
- **YAML cutover via the `stringToPeerConfHook` decode hook:** a config file containing one
  bare-string `primary:` among several valid zones **decodes successfully** (no whole-file abort), the
  offending zone is in ERROR state, and the other zones load — proves the decode hook preserves
  resilient startup. (Also assert a bare-string element inside a `notify:` list is converted to a
  legacy marker element-wise, quarantining only that zone.)
- parse → a `primary:` with missing/empty `key` puts that zone in ERROR state **but the server still
  starts**; a non-`NOKEY` key is an ERROR-state zone until Improvement 2.

## 6. Improvement 2 — TSIG on zone-replication peer transactions, per-peer scoping  *(do second)*

### Transaction map (full scope — nothing here is optional)

A secondary configured with `primary: {addr, key: K}` and a primary configured with
`notify: [{addr: D, key: K}, …]` share one per-peer keystore entry per remote endpoint. The same
`(peer_addr, key_name)` tuple is used whether this server is signing an outbound message or
verifying an inbound one.

```
Secondary                              Primary
─────────                              ───────
DoTransfer (SOA query)        ──TSIG──►
ZoneTransferIn (AXFR/IXFR)    ──TSIG──►
                              ◄──TSIG──  SendNotify (NOTIFY)
NotifyResponder (verify)      ◄──TSIG──
                              ◄──TSIG──  ZoneTransferOut (verify AXFR request)
```

**Address model — send by `addr:port`, key/match by IP only (decided 2026-06-24).** Two distinct
uses of a peer address, which the current code conflated:
- **Send side:** the configured `primary.addr` / `notify[].addr` is a full `host:port` and is used
  *verbatim* to reach the peer. We must **not** assume the peer listens on `:53` — `DoTransfer`,
  `ZoneTransferIn`, and `SendNotify` send to the exact configured port. (`NormalizeAddress` may still
  default a missing port to `:53`, but an explicit non-53 port is honoured.)
- **Keystore/ACL key side:** the lookup tuple is **`(IP, key_name)` — IP only, port stripped from
  both sides.** Inbound `RemoteAddr()` carries an ephemeral source port that never equals the
  configured listen port, so matching on `host:port` would fail every legitimate peer. Define a helper
  `peerIP(addr) = host-part of net.SplitHostPort(addr)` (bare IP, no port) and use it as the keystore
  key on **both** store and lookup. The keystore tuple is therefore `(peerIP, name)`, **not**
  `(addr:port, name)`.
- **Accepted limitation:** IP-only matching cannot distinguish two replication peers sharing one IP on
  different ports (e.g. two tdns instances on `192.0.2.1:5301` and `:5302` with different keys) — they
  resolve to the same `(IP, name)`. This matches BIND's address-based `server`-ACL behaviour and is an
  accepted constraint, documented rather than worked around.

**Shared signing/verify helpers** (new, e.g. `v2/tsig_peer.go`):
- `SignForPeer(msg, peerAddr, keyName, kdb)` — if `keyName == NOKEY`, no-op; else
  `GetTsigKey(peerIP(peerAddr), keyName)`, set `Client.TsigSecret` / `msg.SetTsig(…)`. `peerAddr` here
  is the configured `addr:port` (send side); only its IP is used for the keystore lookup. Used by all
  outbound paths.
- `VerifyFromPeer(msg, remoteAddr, keyName, kdb)` — if `keyName == NOKEY`, accept unsigned; else
  verify TSIG on `msg` against `(peerIP(remoteAddr), keyName)`. `remoteAddr` is the inbound
  `RemoteAddr()`; its ephemeral port is discarded by `peerIP`. Used by all inbound paths.

Retire `Globals.TsigKeys` for auth replication: load `keys:` block into the per-peer keystore at
startup (A3); catalog/API provisioning call `AddTsigKey`. CLI reporter may keep its own client-side
`ParseTsigKeys` path — out of scope for auth.

### Implementation steps

> **Step ↔ A-label map** (the §7 assessment table and cross-refs elsewhere use the `A`-labels; the
> steps below are the same work, numbered): step 1 = **A1**; step 2 = **A2** (+ the structured
> `notify:` half is **A3b**); step 3 = **A3a** (`keys:` block), with `notify:` cutover = **A3b**;
> step 4 = **A4**; step 5 = **A5**; step 6 = **A6**; step 7 = **A7**; step 8 = **A8**; step 9 =
> **A9**; the test list = **A10**.

1. **(A1) Per-peer TSIG keystore** — add a TSIG store in `KeyDB` (struct at structs.go:~719). DB table
   `TsigKeys(upstream, name, algorithm, secret, owner, …)` UNIQUE(upstream, name), where `owner` ∈
   {`config`, `api`} (drives the refcount-drop discriminator, step 10) + accessors
   `GetTsigKey(upstream, name)` / `AddTsigKey(upstream, name, algo, secret, owner)` (upsert) /
   `DeleteTsigKey(upstream, name)` (scans live `Zones`; drops only when unreferenced and
   `owner="api"`, step 10). Cache key: `peerIP(upstream)+"+"+name` (mirror the Sig0 cache
   convention `zonename+"+"+state` at keystore.go:844). **The accessors key on `peerIP` (bare IP, port
   stripped) — NOT `NormalizeAddress` (which would force `:53`)** — so store and lookup agree
   regardless of the peer's actual port and the inbound ephemeral source port (see address model
   above). (Note: `KeyConf.Tsig []TsigDetails{Name, Algorithm, Secret}` already exists at
   structs.go:809 — that is the *config* shape; the per-peer keystore is the new `(peerIP, name)`
   runtime store.)

2. **`PeerConf` struct + runtime refs** — shared `{Addr, Key}` type for both upstream and downstream
   peers (replaces bare `Primary string` from B0 and bare `Notify []string`):
   ```yaml
   # secondary
   primary:
     addr: 192.0.2.1:53
     key:  transfer-key    # NOKEY = unsigned

   # primary
   notify:
     - addr: 192.0.2.2:53
       key:  transfer-key  # NOKEY = unsigned NOTIFY + accept unsigned AXFR from this peer
   ```
   On `ZoneData`: keep `Upstream string` + add `TsigKeyName string` (secondary); replace
   `Downstreams []string` with **`Notify []PeerConf`** (one canonical name end to end — YAML key
   `notify:`, `ZoneConf.Notify`, `ZoneData.Notify`; `downstreams`/`DownstreamPeers` are gone, per
   §3/B0c). `ZoneRefresher` carries the same fields; assign in refreshengine.

3. **`keys:` config block — explicit binding algorithm.** Tag `Config.Keys`
   (`yaml:"keys" mapstructure:"keys"`); tdns-auth does not call any key-loading routine at startup
   today, so add the load. The config shape **already exists** — `Config.Keys.Tsig []TsigDetails`
   (`KeyConf.Tsig` at structs.go:809, `TsigDetails{Name, Algorithm, Secret}` at structs.go:812-815);
   `keys.tsig[]` throughout this doc refers to that slice. **Pin `Algorithm` as the field name**
   (the DB column / accessor args spell it `algorithm`/`algo` — same value, the lowercase DB column
   maps to the struct's `Algorithm`). No new config struct is defined; only the **load** (parse →
   keystore bind) is new. Binding rule, spelled out:
   - **Startup load ordering (decided 2026-06-25): DB first, then config upserts.** The persistent
     `TsigKeys` table is loaded into the keystore **before** the `keys:` block is bound. The `keys:`
     bind then runs `AddTsigKey(…, owner="config")` for each declared key, which **upserts** —
     overwriting any colliding `(peerIP, name)` row (including a prior `owner="api"` row) with the
     config secret and `owner="config"`. This ordering is what makes **"config wins on reload"**
     automatic and non-special-cased: config is applied last, so it always lands on top. (API-created
     `owner="api"` rows for peers the operator manages purely via API have no config entry to collide
     with and survive untouched.) Concretely: keystore-DB-load → `keys:` bind → zone parse/bind.
   - For each **secondary** zone: `AddTsigKey(peerIP(zconf.Primary.Addr), zconf.Primary.Key,
     algo, secret)` where `(algo, secret)` come from the `keys.tsig[]` entry whose `name ==
     zconf.Primary.Key`. (Keystore keyed by IP; the full `addr:port` is retained on `zd` for sending.)
   - For each **primary** notify peer: `AddTsigKey(peerIP(peer.Addr), peer.Key, algo, secret)`
     likewise.
   - A non-`NOKEY` key name with **no matching `keys.tsig[]` entry** → that zone to per-zone ERROR
     (same quarantine rule as B0). Bare-string `notify:`/`primary:` → per-zone ERROR (handled by the
     shared `stringToPeerConfHook` decode hook, B0).
   - **Config reload:** on `keys.tsig[]` add/change/remove, re-bind — `AddTsigKey` upserts by
     `(peer, name)`; a removed key whose `(peer, name)` is still referenced by a live zone → leave the
     zone in ERROR (do not silently keep stale secret). 
   - **Conflict policy (config vs API):** if an API `AddTsigKey` and a `keys:`-derived bind target the
     same `(peer, name)` with different secrets, **config wins on reload** — and this falls out of the
     load ordering above (config binds last, upserting over the `owner="api"` row), not a special-case
     comparison. The API path is for zones the operator manages entirely via API. Document this; do not
     merge silently.
   - **Reference counting:** the keystore entry for `(peerIP, name)` is shared across all zones
     pulling from that peer IP; `zone delete` / key removal drops it only when no live zone still
     references it (§ step 10). Static `keys:` entries are owned by config, not refcounted away by API
     deletes.

4. **Secondary → primary: SOA probe** — `DoTransfer` (zone_utils.go:84). Many primaries require TSIG
   here; AXFR signing alone is insufficient. **Mechanism caveat (not a one-liner):** the probe today
   uses the **package-level `dns.Exchange(m, upstream)`** (zone_utils.go:101), which has **no
   `TsigSecret` field and cannot verify the response MAC.** To sign+verify the probe, `DoTransfer`
   must switch to a **`dns.Client{TsigSecret: …}`** and call `client.Exchange(m, upstream)`:
   `SignForPeer` sets `msg.SetTsig(name, algo, …)` **and** populates the client's `TsigSecret` map for
   the `(keyname → secret)` it resolves. For `NOKEY`, keep today's plain `dns.Exchange` path
   unchanged (no client, no MAC). So step 4 = "set TSIG on the message **and** move the call onto a
   `dns.Client` carrying the secret," not merely "call `SignForPeer` before `dns.Exchange`."

5. **Secondary → primary: AXFR/IXFR** — `ZoneTransferIn` (dnsutils.go:54): before `transfer.In`,
   set `transfer.TsigSecret` and `msg.SetTsig` via `SignForPeer` (same key as DoTransfer). Remove
   TODO at dnsutils.go:29. *Verify miekg/dns `Transfer.TsigSecret` / `SetTsig` / algorithm constants
   against the vendored version.* **IXFR scope:** production refresh hardcodes `"axfr"`
   (`FetchFromUpstream`, zone_utils.go:234), so the only call signed here is AXFR. The same
   `SignForPeer`/`ZoneTransferIn` helper covers IXFR unchanged **if/when** the IXFR path is ever
   wired — **no separate IXFR work in this plan.** Titles saying "AXFR/IXFR" mean "the one transfer
   helper, which both use," not two code paths.

6. **Secondary ← primary: inbound NOTIFY** — `NotifyResponder` (notifyresponder.go:122): for
   NOTIFY(SOA) that will trigger a zone refresh, call `VerifyFromPeer(dnr.Msg, remoteAddr,
   zd.TsigKeyName, kdb)` using the triggering zone's upstream key. **`NotifyResponder` has no `kdb`
   today (verified) — thread `zd.KeyDB` in** (the zone is already resolved via `FindZone`). If
   `zd.TsigKeyName == NOKEY`, accept unsigned (today's behaviour); else verify and REFUSE + log on
   failure.
   - **Response signing is REQUIRED, not optional (RFC 8945).** When the incoming NOTIFY carried a
     valid TSIG, the NOTIFY response **must** be signed with the **same `(peerIP, key)`** used to
     verify it — an unsigned reply to a signed request is treated as forged by the sender. (Confirm
     the exact miekg/dns server-side mechanism — typically `w.WriteMsg` after `m.SetTsig(...)`, or the
     server auto-signing when the request's TSIG verified — against the vendored API, §10.) For a
     `NOKEY` zone the response stays unsigned.
   - **No address-ACL on NOTIFY (deliberate, asymmetric with A8).** A `NOKEY` secondary accepts and
     acts on a NOTIFY from **any** source (today's behaviour, preserved) — there is intentionally no
     "is this a configured primary?" address check here, unlike the inbound-AXFR ACL (A8). Rationale:
     a NOTIFY only *triggers* a SOA-serial refresh from the secondary's already-configured upstream;
     it cannot inject data, so a spurious NOTIFY costs at most one SOA probe. Authentication is via
     TSIG when a non-`NOKEY` key is configured; address-based rejection is not added. State this so the
     NOTIFY-vs-AXFR asymmetry is a decision, not an oversight.

7. **Primary → secondary: outbound NOTIFY** — `SendNotify` (notifier.go:95): for each target, find
   the `zd.Notify` entry whose **`peerIP(entry.Addr) == peerIP(target)`** (IP-only match), call
   `SignForPeer(m, target, peer.Key, kdb)` before `ExchangeContext` — sending to the entry's full
   `addr:port`.

8. **Primary ← secondary: inbound AXFR/IXFR** — `ZoneTransferOut` (dnsutils.go:222), reached from
   queryresponder.go:816. **The requester address must be plumbed in: today `ZoneTransferOut(w, r)`
   gets the requester only via `w.RemoteAddr()` and does no ACL (verified) — use that, reduced by
   `peerIP`.** Before serving, match `peerIP(w.RemoteAddr())` against the `zd.Notify` peer list
   (IP-only — the requester's ephemeral source port is irrelevant): if no entry matches → REFUSE
   (closes the open AXFR ACL gap); if the matched entry's key is `NOKEY` → serve unsigned; else
   `VerifyFromPeer(r, w.RemoteAddr(), peer.Key, kdb)` and serve only on success. **This IP-only match
   is what makes the ACL work — a `host:port` comparison would reject every real secondary** (its
   source port is never the configured listen port).

9. **Wire catalog path + unify `tsig_key` into `primary.key`** — catalog.go:399-404. Today this block
   looks up `ConfigGroupConfig.TsigKey` against `Globals.TsigKeys`, and on the "found" branch logs
   `"CATALOG: applied TSIG key"` (catalog.go:403) while the actual apply is a TODO (catalog.go:402) —
   **the log is a lie; delete it now** (this is a one-line correctness fix worth doing immediately,
   independent of the rest). Then: map the catalog group's `tsig_key` into the provisioned zone's
   `primary.key` (a single field — **deprecate the parallel `tsig_key`-only path**, do not keep two
   ways to specify the same thing), call `AddTsigKey(peerIP(upstream), name, …, owner="config")`, and
   set `zd.TsigKeyName`.
   - **Re-point the existing catalog config-check.** Today catalog.go:397 *validates* the group's
     `tsig_key` against `Globals.TsigKeys`. Once `Globals.TsigKeys` is no longer populated on auth
     (this step), that check must be re-pointed at the new source of truth — the parsed `keys.tsig[]`
     names (a name-set built when the `keys:` block loads, A3a) — or it always-fails. Don't leave it
     reading the now-empty `Globals.TsigKeys`.

10. **Programmatic provisioning + keystore lifecycle (refcounted).** The keystore entry for
    `(upstream, name)` is shared across all zones pulling from that peer, so create/drop must be
    reference-counted across all three mutating cores.
    - **Refcount mechanism (specified — do not store a counter):** there is no `refcount` column and
      no counter to keep in sync. "Still referenced" is **computed by scanning live `Zones`** at drop
      time: a `(peerIP, name)` is still in use iff some live `ZoneData` has
      `peerIP(zd.Primary.Addr)==peerIP && zd.Primary.Key==name`, **or** any `zd.Notify[i]` matches the
      same tuple. `DeleteTsigKey(peerIP, name)` runs this scan and removes the DB row + cache entry
      **only when the scan finds no remaining reference.** A scan over the sharded `Zones` map at a
      management-op cadence (delete/modify) is cheap; this avoids counter-drift bugs entirely.
    - **Ownership discriminator (config vs API) — one new column.** The `TsigKeys` table gets an
      `owner` field (`"config"` | `"api"`). Config-declared (`keys:`) entries (`owner="config"`) are
      **never** dropped by API add/modify/delete — the scan-and-drop applies only to `owner="api"`
      rows. This is how "config wins / config owns its keys" (step 3 conflict policy) is enforced
      mechanically rather than by convention. On reload, `keys:` binding re-asserts `owner="config"`
      (upsert), overwriting any colliding `owner="api"` row (config-wins).
    - `zone add` with `{tsig_name, tsig_secret, tsig_algo}` → `AddTsigKey(peerIP(upstream), name,
      algo, secret)` (upsert).
    - `zone modify` that changes `(addr, key)` → `AddTsigKey` for the new tuple, refcounted
      `DeleteTsigKey` for the old tuple (B1c key-change handling). Note a port-only change of `addr`
      does **not** change the keystore tuple (IP unchanged) — only the send target moves.
    - `zone delete` → refcounted `DeleteTsigKey(peerIP(upstream), name)`: drop the keystore entry
      **only if no other live zone still references `(peerIP, name)`**.
    - **Config-declared (`keys:`) entries are never dropped by API add/modify/delete** — config owns
      them (step 3); the refcount applies to API-created keystore entries.

### Tests (Improvement 2)
- End-to-end replication with TSIG on **all** paths: SOA probe, AXFR, NOTIFY trigger, inbound AXFR
  verify — use miekg/dns test server or two tdns-auth instances.
- `NOKEY` zone: all paths remain plain/unauthenticated (today's behaviour).
- **Collision test:** two peers, same key name, different secrets → both directions work.
- NOTIFY rejected when TSIG required but missing/invalid; AXFR rejected when requester not in peer
  list or TSIG invalid.
- **NOTIFY response is TSIG-signed** when the request was signed (RFC 8945) — assert the reply carries
  a valid TSIG under the same `(peerIP, key)`; a `NOKEY` zone's reply is unsigned.
- **NOTIFY has no address-ACL:** a `NOKEY` secondary accepts a NOTIFY from an unconfigured source and
  triggers a SOA probe (deliberate, asymmetric with the AXFR ACL — step 6).
- **Refcount + ownership:** two API zones share `(peerIP, name)`; deleting one keeps the key (still
  referenced), deleting both drops it. A `keys:`-declared (`owner=config`) key is **not** dropped by
  any API delete.
- **Load ordering / config-wins:** seed the DB with an `owner="api"` entry for `(peerIP, name)` with
  secret S1, then start/reload with a `keys:` entry for the same `(peerIP, name)` carrying secret S2.
  After load the keystore holds **S2 with `owner="config"`** (config bound last, upserted over the
  api row) — proving config-wins is a consequence of DB-first-then-config ordering, not a comparison.
- **`NOKEY` reserved:** a `keys.tsig[]` entry named `NOKEY` → parse ERROR for that key/zone.
- Restart: the persistent `TsigKeys` DB loads **before** the `keys:` bind and before the first
  refresh/NOTIFY; `TsigKeyName` + downstream peer keys are resolvable when the first transfer fires.

## 7. Assessment (risk / LOC / Claude implementation time)

**Risk model (defined 2026-06-25): `risk = probability × consequence`.**
- **Probability** = chance of shipping a wrong/incomplete implementation *and not noticing* — high when
  the failure is silent, concurrent, or only observable after a restart/reload (weak local
  verification); low when a trivial test catches it on the first run (loud, immediate failure).
- **Consequence** = blast radius if it *is* shipped wrong. **Crucially, fixing an existing latent bug
  has near-zero consequence even if probability is high** — the floor is "stays as broken as today," not
  "newly broken." A high-consequence cell is one where a wrong implementation makes things *worse than
  the status quo* (whole server down, operator-visible corruption, data loss that didn't happen before).
- **Risk is the product**, so a cell is only genuinely risky when *both* terms are non-trivial. "Hard to
  get right" (high probability) or "big blast radius" (high consequence) **alone** is not high risk —
  a common conflation this table now avoids. Effort ≠ risk; consequence-if-loud-and-tested ≠ risk.

LOC = net new + modified, anchored to measured sizes (`ZoneTransferIn` 55 lines @ dnsutils.go:54-109;
catalog provisioning core ~70 lines @ 376-445; `dynamic_zones.go` ~509 lines; `catalog.go` ~773).
"Claude time" = wall-clock to write + self-review + iterate to compiling/passing with build/test in
the loop; excludes the gocpt101 build friction (CGO `-L/usr/lib -lcrypto` + `go clean -cache`), which
adds real wall-clock per tdns build cycle. **Revised 2026-06-25** for the probability×consequence model
— see notes under the table for what moved.

| Item | Prob | Conseq | **Risk** | LOC | Claude time |
|---|---|---|---|---|---|
| **B0a** `PeerConf` struct + **`mapstructure` decode hook** (bare-string → legacy quarantine marker) | Low | High | **Low** | ~55 | 40–60 min |
| **B0b** structured `primary:` wiring + NOKEY + per-zone ERROR on bad/missing key | Low | Med | **Low** | ~40 | 25–40 min |
| **B0c** consolidate duplicate `Notify`/`Downstreams` → one `notify` `[]PeerConf` | Low | Med | **Low** | ~35 | 30–45 min |
| **B1a** `ProvisionDynamicZone` (add core, re-point catalog, map-only + `allowed` gate; async fire-and-forget + persist-fail rollback) | Med | Med | **Med** | ~90 | 40–60 min |
| **B1b** `RemoveDynamicZone` (delete core + generation bump) | Low | Low | **Low** | ~40 | 20–30 min |
| **B1c** `ModifyDynamicZone` (delete+re-add model — race-free; gen bump; key re-bind) | Med | Low | **Low–Med** | ~65 | 40–60 min |
| **B2** `ZonePost`/`ZoneResponse` fields + `ZoneConf.Provisioning` | Low | Low | **Low** | ~15 | 5–10 min |
| **B3** four `APIzone` cases (+ `Provisioning` derivation, accepted-response) | Low | Low | **Low** | ~80 | 30–40 min |
| **B4** four CLI subcommands (inline `cobra.Command`; no `--store`) | Low | Low | **Low** | ~100 | 40–55 min |
| **B5a** unified marker reconstruction (catalog **+** API) + refreshengine persist branch + reload-spare widen | **High** | ~Zero (existing bug; floor = stays-broken) | **Low** | ~60–80 | 60–90 min |
| **B5b** generation-counter interlock + pre-persist guard (kills resurrection race) | **High** | Med (delete/modify add *new* triggers → operator-visible resurrection) | **Med–High** | ~25–35 | 40–60 min |
| **B6** minimal `ZoneStatus` (enum + field + `SetStatus`/`GetStatus` + 3 transition sites) | Low | Low | **Low** | ~40–50 | 25–40 min |
| **Improvement 1 subtotal** | — | — | **Low–Med** (B5b is the one elevated cell) | **~660** | **7.5–9.5 h** |
| **A1** per-peer TSIG keystore (+`owner` column, scan-live-Zones refcount in `DeleteTsigKey`) + shared `SignForPeer`/`VerifyFromPeer` helpers | Med | Med | **Med** | ~160 | 70–100 min |
| **A2** `PeerConf` type; `ZoneData.TsigKeyName`; `ZoneData.Notify []PeerConf`; refresher plumbing | Low | Low | **Low** | ~45 | 30–45 min |
| **A3a** `keys:` block (tag `Config.Keys` + load into keystore at parse; DB-first-then-config ordering) | Low | Low | **Low** | ~40 | 25–35 min |
| **A3b** structured `notify: [{addr,key}]` + hard cutover from bare strings | Low | Med | **Low** | ~40 | 30–40 min |
| **A4** `DoTransfer` SOA probe — sign outbound TSIG (incl. `dns.Exchange`→`dns.Client` switch) | Med | Low | **Low–Med** | ~25 | 25–35 min |
| **A5** `ZoneTransferIn` AXFR/IXFR — sign outbound TSIG | Low | Low | **Low** | ~25 | 25–35 min |
| **A6** `NotifyResponder` — verify inbound NOTIFY TSIG (+ thread `kdb`, sign response per RFC 8945) | Med | Low | **Low–Med** | ~35 | 30–40 min |
| **A7** `SendNotify` — sign outbound NOTIFY TSIG | Low | Low | **Low** | ~25 | 20–30 min |
| **A8** `ZoneTransferOut` — verify inbound AXFR + peer ACL (behaviour change: REFUSE unknown requesters) | Med | Med | **Med** | ~45 | 40–60 min |
| **A9** wire catalog path; retire `Globals.TsigKeys` on auth (+ re-point catalog config-check) | Low | Low | **Low** | ~20 | 15–20 min |
| **A10** tests: all paths + collision + ACL reject + load-ordering/config-wins + refcount/ownership | Med | Low | **Low–Med** | ~165 | 70–100 min |
| **Improvement 2 subtotal** | — | — | **Low–Med** (A1/A8 the elevated cells) | **~625** | **6.5–9 h** |
| **Total** | — | — | **Low–Med** (two elevated cells: B5b, A8; one Med foundation: A1) | **~1285** | **14–18.5 h** |

**What moved after the external review + verification (and why):**
- **B5 split into B5a/B5b (B5b new, 2026-06-24):** beyond the marker-reload fix, there is a *second*
  inherited bug — the detached refresh goroutine (refreshengine.go:412) resurrects a deleted/replaced
  zone because it persists with no liveness re-check (verified). B5b adds a `ZoneData.generation`
  counter + pre-persist guard; `modify` becomes delete+re-add so the modify/refresh data race is gone
  by construction (no locking added to the hot AXFR read path).
- **B0 split into B0a/b/c, +~100 LOC:** the bare-string → struct cutover needs a
  `mapstructure` **decode hook** (string → `PeerConf` legacy marker) or a single legacy `primary:`
  aborts the *whole-file* decode (parseconfig.go:287-292, verified) — defeating resilient startup.
  **Note (2026-06-24): a `yaml.Unmarshaler` does NOT work here** — config decodes `yaml → map →
  mapstructure`, and mapstructure ignores `yaml.Unmarshaler`; the fix must live on the
  `DecoderConfig.DecodeHook`. Plus consolidating the duplicate
  `Notify`/`Downstreams` fields (B0c) lands here, not "later." **(B0a was briefly labelled "High" on
  the old single-axis scale; under the probability×consequence model it is Low — the failure is loud
  and a one-config test catches it on the first run; see the 2026-06-25 re-grade below.)**
- **B5 ↑↑ (now ~55–75 LOC):** not just the new API marker — the catalog marker is **already broken on
  restart today** (verified: `LoadDynamicZoneFiles` never re-derives `OptAutomaticZone` from
  `SourceCatalog`; catalog refresh can't heal it, catalog.go:337-340). B5 is now a unified
  reconstruction fix for all dynamic zone types **plus** extending the refreshengine persist branch
  beyond `OptAutomaticZone`.
- **B1a ↑ slightly:** add the `dynamiczones.dynamic.allowed` gate (config field exists @config.go:419,
  defaults false, checked nowhere — verified) + `dynamic.storage`.
- **Improvement 2 scope (full peer transaction cycle):** TSIG on `transfer.In` alone fails against
  real primaries; SOA probe, NOTIFY, and inbound AXFR verify are all required. `ZoneTransferOut` is
  A8, in scope, and doubles as the AXFR ACL.
- **A3b:** structured `notify:` with mandatory `key` — counterpart to B0's `primary:`.
- **B1c ↓ (High→Med):** map-only decision removes the store-change branch.
- **Removed A4 `*KeyDB` signature change:** `ZoneTransferIn` is a method; use `zd.KeyDB` + shared
  helpers instead.

**What moved in the 2026-06-25 session (decisions #6/#7 + zone status):**
- **Async `zone add` + rollback (B1a, B2, B3):** `add` is fire-and-forget (enqueue + return
  `accepted`, do not block on AXFR) with persist-fail rollback; progress polled via the derived
  `ZoneConf.Provisioning`. Small LOC bumps to B1a/B2/B3.
- **New B6 — minimal `ZoneStatus` (+~45 LOC, Low risk):** field + `SetStatus`/`GetStatus` + 3
  transition sites; the positive-lifecycle source for `Provisioning`. Modelled on `SetError` but
  without the registry. `Ready`/`FirstZoneLoad` consumers left untouched (convergence = future, §10).
- **A1 ↑ (now ~160 LOC):** the keystore gained an `owner` (`config`|`api`) column and a
  **scan-live-Zones** refcount in `DeleteTsigKey` (drop only when unreferenced and `owner="api"`) —
  no counter to drift.
- **A3a — DB-first-then-config load ordering:** persistent `TsigKeys` loaded before the `keys:` bind;
  config `AddTsigKey(owner="config")` upserts last, so "config wins on reload" falls out of ordering,
  not a comparison. Low LOC (mostly sequencing) but a load-bearing invariant; A10 gained the test.
- **Net totals after this session:** Improvement 1 ~590→~660 LOC (B6 + async/rollback); Improvement 2
  ~555→~625 LOC (A1 refcount/owner + ordering + tests). Both subtotals moved up together; their
  relative size is unchanged (near-tie, see comparison below).
- **Risk re-graded to `probability × consequence` (2026-06-25):** the old single-axis "Risk" column
  conflated *probability of getting it wrong* and *blast radius* with risk itself. Re-grading on the
  product **drops B0a, B5a, and most cells to Low** — B0a fails loud (one-config test), B5a is an
  existing-bug fix (consequence ~zero: a miss leaves it as broken as today, not newly broken). **Only
  B5b stays elevated** (high probability × *new* operator-visible consequence from the delete/modify
  triggers), with A1 and A8 as Med. Effort and blast-radius alone are no longer mislabelled as risk.

### Risk commentary (probability × consequence)

The genuinely elevated cells, ranked by **risk = probability × consequence** — not by effort, not by
blast radius alone:

- **B5b resurrection race — the single highest-risk cell (Med–High).** High *probability* (silent,
  concurrent, only observable after a restart/reload — weak local verification) **and** non-trivial
  *consequence*: the detached refresh goroutine re-persists a deleted/replaced zone, and the **new**
  `zone delete`/`zone modify` verbs add operator-reachable triggers to a race that today only fires via
  catalog reload. So a miss here is *operator-visible resurrection* (delete a zone, it comes back) —
  worse than the status quo, not merely "stays broken." Fixed by `ZoneData.generation` + pre-persist
  guard; `modify` = delete+re-add so the modify/refresh data race is gone by construction. **This is
  where verification effort should concentrate:** `delete`/`modify` mid-AXFR, under `go test -race`.
- **A1 keystore + helpers (Med).** Med probability (a new subsystem — table, refcount scan, ownership,
  load ordering — with several moving parts) × Med consequence (a wrong key binding breaks transfers
  for real zones). Loud failure, so testable, but the foundation everything else leans on — get it
  right first.
- **A8 inbound-AXFR ACL + verify (Med).** Med × Med: it's a behaviour change (REFUSE unknown
  requesters, replacing today's open `ZoneTransferOut`) and the IP-only match is easy to get subtly
  wrong — but it fails *loud* (a real secondary gets REFUSED, immediately visible), so probability of
  an *unnoticed* miss is bounded. Document the behaviour change for operators.

**Low-risk despite looking scary (the conflations this model corrects):**
- **B0a decode mechanism — Low risk, not High.** *Consequence* is high (a wrong fix aborts the whole
  config / server-won't-start), but *probability* of an unnoticed miss is low: the failure is **loud
  and immediate**, and a one-config test (one modern zone + one legacy bare-string zone → server comes
  up with only the legacy zone in ERROR) settles it on the first run. The only non-obvious part — that
  a `yaml.Unmarshaler` never fires and you need a `mapstructure` decode hook — is a *design*-time catch,
  already made. High consequence + low probability = low risk.
- **B5a marker reload — Low risk, high effort.** High *probability* of an incomplete fix (silent;
  needs a restart cycle to verify), but *consequence* ≈ zero: it fixes an **existing** latent bug
  (catalog markers are already lost on restart today), so a miss leaves things exactly as broken as
  now, never worse. The cost of failure is *non-improvement*, not regression. It feels risky only
  because the probability term is high — but effort ≠ risk. Still needs the restart + guard tests
  (for both zone types) to actually bank the improvement.
- **A4–A8 as an integration set — Low–Med, mostly a repeated pattern.** SOA/AXFR/NOTIFY sign/verify
  must all use the same `(peer, key)` lookup; fixing one path alone leaves refresh broken against
  TSIG-required primaries. But once A1's shared `SignForPeer`/`VerifyFromPeer` helpers are right, each
  path is a near-mechanical application, and every failure is loud (transfer fails / MAC mismatch).
  Use the helpers everywhere — no one-off TSIG — to keep probability low.

**Non-risk call-outs (behaviour to document, not risk to mitigate):**
- **B1a behavioural drift:** catalog re-point + map-only tightening is a deliberate breaking change for
  non-map catalog groups (§3); diff before/after. Loud and intended, not risky.
- **Notify/primary syntax cutover (A3b/B0):** every config with bare-string `notify:`/`primary:` needs
  migration to `[{addr, key}]` — same hard-cutover rule, same `stringToPeerConfHook` (element-wise for
  lists). Loud (un-migrated zone → ERROR, server still starts), so low probability of an unnoticed miss.

### Which half is the larger project? (comparison)

The two halves are a **near-tie on raw size** — ~660 vs ~625 LOC, 7.5–9.5 h vs 6.5–9 h. Under
`risk = probability × consequence` both are **Low–Med overall**; what differs is *where* the
probability and consequence live, not the bottom-line risk.

| Axis | Improvement 1 (dynamic-zones) | Improvement 2 (TSIG) | Larger |
|---|---|---|---|
| LOC / Claude-time | ~660 / 7.5–9.5 h | ~625 / 6.5–9 h | ≈ tie (I1 slightly) |
| Files touched | ~10 | ~14 | **I2** |
| Overall risk (prob × conseq) | Low–Med | Low–Med | ≈ tie |
| Highest-risk cell | **B5b** (Med–High) — high prob × *new* operator-visible consequence | A1 / A8 (Med) — Med prob × Med, but loud | **I1** (one genuinely elevated cell) |
| Probability profile | **higher** — silent / concurrent / restart-reload failures, weak local verification | **lower** — loud failures (transfer fails, REFUSED, MAC mismatch), easy to observe | I1 more prob |
| Consequence profile | mostly **~zero** (B5a/B0a fix existing bugs or fail loud); only B5b adds *new* blast radius | mostly **low** (additive, NOKEY = today's path); A1/A8 Med | ≈ tie |
| Nature of the work | mostly editing existing concurrent / persistence-critical code; fixes two *inherited* races (one of which, B5b, the new verbs re-trigger) | mostly additive — new file, new table, paths gated by `key!=NOKEY`; barely touches the dangerous machinery | — |
| Local verifiability | poorer — races/persistence need the NetBSD testbed; `-race` helps but restart/reload don't fully exercise on this dev box (drives I1's higher *probability*) | better — `key=NOKEY` is today's working path untouched; two-instance E2E is a known harness | — |
| Biggest single cell | B5a (~60–80; high prob, ~zero conseq → **Low risk**, high effort) | A1 (~160; Med, the keystore+helpers foundation) | — |
| External unknowns | none material | miekg/dns TSIG API (§10) — a *known* unknown, de-risked once up front | **I2** |

**One-line verdict: TSIG is the bigger *build*; dynamic-zones is the harder-to-*verify*.** TSIG has more
surface area (files, the largest test cell A10, a new keystore with refcount/owner/load-ordering), but
it is overwhelmingly additive and its failures are loud and local. Dynamic-zones is slightly smaller in
LOC and carries the higher *probability* term — its work is silent-failing persistence/concurrency code
that's weakest to verify on this dev machine. But higher probability is **not** higher risk: B5a/B0a
have near-zero or loud consequences, so only **B5b** (high probability × a *new*, operator-visible
consequence) is genuinely elevated. Net: the two halves are comparable in risk; they differ in *where*
the difficulty sits — TSIG in breadth, dynamic-zones in verification-confidence.

### Sequencing (re-confirmed: Improvement 1 first)

The doc's order (1 → 2) holds, primarily on dependency — **not** on a risk gap (under the
probability×consequence model the two halves are comparable in risk):

- **Hard dependency direction is one-way (the real driver).** Improvement 1 establishes the final
  `primary: {addr,key}` / `notify: [{addr,key}]` syntax and the `PeerConf` type (B0). Improvement 2
  *consumes* that with no syntax change and no re-provisioning. Doing TSIG first would mean inventing
  the peer structs anyway, then reworking them under the dynamic-zones migration — wasted motion.
- **Tackle the higher-*probability* work while context is freshest.** Improvement 1 holds the
  silent-failing persistence/concurrency cells (B5b especially, plus the high-probability-but-low-risk
  B5a/B0a). Doing them first — before TSIG layers more behaviour onto the same transfer paths — means
  you are not debugging a resurrection race *through* a TSIG ACL. (This is a probability/verification
  argument, not a "front-load the risk" one — only B5b is genuinely elevated, and it lives here.)
- **Improvement 1 ships a complete, useful interface on its own** (NOKEY zones work end-to-end with
  none of Improvement 2's code), so finishing it first banks a shippable, independently-testable
  milestone before the broader TSIG surface begins.
- **The inherited B5 bugs exist *today*** (catalog state already degrades on restart, B5a; the
  resurrection race already fires via catalog reload, B5b) — fixing them first stops live (if
  low-consequence for B5a) buggery sooner, independent of the new feature.

**Counter-argument considered (and rejected):** "do the broad additive thing (TSIG) first to bank an
easy win." Rejected on dependency, not risk: TSIG has *no* standalone value without the `PeerConf`
syntax it depends on, so it cannot ship first regardless of how loud-and-testable its failures are.

## 8. Files touched (summary)

**Improvement 1:**
- v2/structs.go (`PeerConf` type (with `Legacy` field for the decode-hook marker);
  `ZoneConf.Primary`/`TemplateConf.Primary` → `PeerConf` @~189/~222; **consolidate
  `ZoneConf.Notify`/`ZoneConf.Downstreams` @190-191 and `ZoneData.Downstreams` @~111 → one
  `notify`-named `[]PeerConf`**; new `ZoneConf.ApiManaged bool` next to `SourceCatalog` @214; new
  `ZoneData.Status ZoneStatus` field (B6); new `ZoneConf.Provisioning string` (B2))
- v2/enums.go (new `OptApiManagedZone` ZoneOption + its string mapping; **new `ZoneStatus` enum +
  `ZoneStatusToString` + `ZoneData.SetStatus`/`GetStatus` — minimal, B6**)
- v2/zone_utils.go + v2/refreshengine.go (B6 status transitions: `Pending` at enqueue, `Loading` at
  fetch start, `Ready` co-located with existing `Ready`/`FirstZoneLoad` flips @zone_utils.go
  167/183/199/245/259/275)
- v2/parseconfig.go (**`stringToPeerConfHook` + `DecodeHook` on the `DecoderConfig` @267-271**;
  **delete the now-dead `'Primary'`/`[]interface` special-case @289-292**; structured primary @645;
  per-zone ERROR on missing/bad/legacy key; template apply at the real call site @595-604 (NOT
  @1010-1011, which is the `ExpandTemplate` definition); `dynamiczones.dynamic.allowed`/`.storage`
  honoured)
- v2/dynamic_zones.go (`ProvisionDynamicZone`/`RemoveDynamicZone`/`ModifyDynamicZone`; map-only +
  `allowed` gate; persist `PeerConf` + `ApiManaged` in `zoneDataToZoneConf` @315; **unified
  marker re-derivation in `LoadDynamicZoneFiles` @225-234** — `OptAutomaticZone` from `SourceCatalog`
  AND `OptApiManagedZone` from `ApiManaged`; persist gate `ShouldPersistZone` @121; **delete dead
  `LoadDynamicZoneFile` @73**)
- v2/refreshengine.go (**extend the post-transfer persist branch @447-448 beyond `OptAutomaticZone`**
  so API-managed zones also rewrite their zone files)
- v2/config.go (**`ReloadZoneConfig` static-reload spare @603-605 must be widened from
  `OptAutomaticZone` to `ShouldPersistZone(zd)`** — otherwise API-managed zones, which carry
  `OptApiManagedZone` not `OptAutomaticZone`, are absent from the re-read static config and get
  `Zones.Remove`d on every reload (B5 reload-spare gap, fixed here))
- v2/catalog.go (re-point `AutoConfigureZonesFromCatalog` @376-445 at the shared add core; map-only
  now applies; **delete the false "applied TSIG key" log @403**)
- v2/api_structs.go (`ZonePost` @159 / `ZoneResponse` @169 fields)
- v2/structs.go (`ZoneConf.Provisioning string` — derived async-add state, B2)
- v2/apihandler_zone.go (four `case` handlers in the switch @56; **`add` returns `accepted` + poll
  hint**; derive `Provisioning` (`pending`|`ready`|`error`) from `zd.Error`/`zd.RefreshCount` in the
  `list-zones`/`list-dynamic` builder @218-237)
- cmdv2/cli/zone_cmds.go (four subcommands, inline `&cobra.Command{Use:...}` @30+; no `--store`)
- cmdv2/auth/*.sample.yaml (migrate sample `primary:`/`notify:` to structured form; document
  `dynamiczones.dynamic.allowed`)

**Improvement 2:**
- v2/tsig_peer.go (new: `SignForPeer`, `VerifyFromPeer`, `NOKEY` sentinel)
- v2/keystore.go + v2/db_schema.go (per-peer TSIG table + accessors)
- v2/structs.go (`PeerConf`; `ZoneData.TsigKeyName`, `ZoneData.Notify []PeerConf`; `ZoneRefresher` fields)
- v2/config.go + v2/parseconfig.go (`keys:` tag; structured `notify:`; bind keys at parse)
- v2/zone_utils.go (`DoTransfer` — A4 sign)
- v2/dnsutils.go (`ZoneTransferIn` sign — A5; `ZoneTransferOut` verify — A8)
- v2/notifier.go (`SendNotify` sign — A7)
- v2/notifyresponder.go (inbound NOTIFY verify — A6)
- v2/queryresponder.go (AXFR path: `ZoneTransferOut` already has `w.RemoteAddr()`; reduce via
  `peerIP` for the ACL/verify — no new param needed)
- v2/catalog.go (wire TSIG → `primary.key` + keystore — A9)
- v2/refreshengine.go (assign peer/key fields onto `ZoneData`)
- v2/dynamic_zones.go (persist `PeerConf{addr,key}` for `primary` + `notify` peers)
- v2/tsig_peer.go (`peerIP(addr)` helper — bare-IP keystore/ACL key)
- v2/global.go / v2/tsig_utils.go (stop using `Globals.TsigKeys` on auth replication path)

## 9. Decisions (all resolved 2026-06-23, incl. external-review round)
- **Static-config migration (B0): hard cutover, resilient.** Bare-string `primary:`/`notify:` values
  are **rejected** (no auto-read), but as a **per-zone ERROR**, not a fatal parse error — achieved via
  a **`mapstructure` decode hook** (`stringToPeerConfHook`, string → `PeerConf{Legacy:…}`) on the
  `DecoderConfig`, **not** a `yaml.Unmarshaler` (which never fires: decode is `yaml → map →
  mapstructure`, and mapstructure ignores the YAML interface — verified). The hook records a legacy
  marker so the whole-file decode succeeds and per-zone validation quarantines just that zone (without
  it, one legacy value aborts the whole-file decode, verified at parseconfig.go:287-292).
- **Canonical peer field: `notify:`.** The duplicate `downstreams:` field/key is **removed** in the
  `PeerConf` migration (B0c) — one name, one `[]PeerConf`.
- **Direct-API zones gate:** `zone add` honours `dynamiczones.dynamic.allowed` (default false,
  currently inert) and persists under `dynamiczones.dynamic.storage`.
- **Marker reload (B5): unified fix for ALL dynamic zone types.** `LoadDynamicZoneFiles` re-derives
  `OptAutomaticZone` from `SourceCatalog` (fixes a *latent catalog bug*) **and** `OptApiManagedZone`
  from the new `ApiManaged` bool; the refreshengine persist branch is extended beyond
  `OptAutomaticZone`. Marker is a dedicated `ApiManaged` bool, **not** a `SourceCatalog="api"`
  sentinel.
- **Restart semantics:** keep re-AXFR-on-restart (the working reality); **delete the dead
  `LoadDynamicZoneFile`**; do not add load-from-disk. Document the boot-time-primary-down implication.
- **CLI (B4):** inline `&cobra.Command{Use:...}` idiom; **no `--store` flag** (map-only).
- **`modify` store-change (B1c): n/a** — map-only, store cannot change.
- **Async `zone add` (decided 2026-06-25):** `add` is **fire-and-forget** — register + persist +
  enqueue, then return immediately; it does **not** wait for the initial AXFR (a transfer can be slow,
  and a synchronous core would hang the CLI and serialize catalog-member provisioning). Progress is
  **polled**: a derived `ZoneConf.Provisioning` field (`pending`|`loading`|`ready`|`error`) surfaced
  via `list-dynamic`/`list-zones`, computed as `zd.Error ? "error" : ZoneStatusToString(zd.Status)`.
  The `add` response is `accepted` + a poll hint. **Rollback:** if persist fails after `Zones.Set`,
  the live zone is removed and `add` errors — never a live-but-unpersisted zone.
- **Zone status infra (B6, decided 2026-06-25): minimal — field + setter + getter.** A new
  `ZoneData.Status ZoneStatus` (`pending`/`loading`/`ready`) + `SetStatus`/`GetStatus`, modelled on
  `SetError` but without the registry/derived-field machinery. Orthogonal to the error registry (API
  surfaces `error` with precedence). `Ready`/`FirstZoneLoad` consumers are left untouched; converging
  them onto `ZoneStatus` is a future follow-up, not this work.
- **TSIG transaction scope: full replication cycle.** SOA probe, AXFR/IXFR, NOTIFY — sign outbound,
  verify inbound; not `transfer.In` alone. Shared `SignForPeer`/`VerifyFromPeer`, no one-off TSIG.
- **Inbound AXFR ACL (A8):** requester must match a configured `notify:` peer; unknown requesters
  REFUSED (replaces today's open `ZoneTransferOut`). A NOTIFY-only peer still needs a list entry.
- **Peer address model (B4, decided 2026-06-24):** **send** to the configured full `addr:port` (never
  assume `:53`); **key the keystore and match the ACL on IP only** (`peerIP(addr)` = port stripped,
  on both store and lookup), because the inbound source port is ephemeral. Keystore tuple is
  `(peerIP, key_name)`. Accepted limitation: two peers sharing one IP on different ports cannot be
  distinguished (matches BIND's address-based `server`-ACL model).
- **Catalog `tsig_key` → `primary.key`:** single field on provisioned zones; the parallel
  `tsig_key`-only path is deprecated; the false "applied TSIG key" log is deleted now.
- **`keys:` conflict policy + load ordering (ordering decided 2026-06-25):** startup loads the
  persistent `TsigKeys` DB **first**, then binds the `keys:` block (`AddTsigKey(owner="config")`
  upserts). Because config binds last, on a `(peerIP, name)` collision **config wins on reload**
  automatically — no special-case comparison. API-set (`owner="api"`) keys are for API-managed zones
  and survive when no config entry collides; keystore entries are reference-counted across zones
  sharing a peer IP.
- **`Globals.TsigKeys` retirement:** auth replication uses **only** the `KeyDB` per-peer store; the
  CLI reporter / `notifyreporter` client path may keep `Globals.TsigKeys` (out of scope for auth).
- **API `zone add` scope (v1):** secondary zones only; `ProvisionDynamicZone` rejects primary.
- **`modify` scope (v1):** `primary` addr/key + `options` only; no notify, policy, store, or rename.
- **TSIG inline secrets:** zone `add`/`modify` may carry `{tsig_name, tsig_secret, tsig_algo}` for
  the upstream peer (Improvement 2); notify peers reference key **names** from `keys.tsig[]` only —
  no inline secret on notify entries (same model as static secondaries).

## 10. Remaining verify-before-coding items (not blockers — confirm at implementation time)
- **miekg/dns TSIG API:** confirm `Transfer.TsigSecret`, `Client.TsigSecret`, `msg.SetTsig`, the
  inbound verify helper, TSIG-on-response, and algorithm constants against the *vendored* version —
  all of A4–A8 depend on this.
- **B1a catalog store audit:** check whether any real catalog config requests a non-map store (the
  map-only tightening is then a deliberate breaking change to announce, not a silent one).
- **IXFR:** production refresh still hardcodes `"axfr"` (`FetchFromUpstream`, zone_utils.go:234); when
  IXFR is wired, A5 signing applies to IXFR via the same helper.
- **`tsig_key` yaml tag (decide in A9):** `ConfigGroupConfig.TsigKey` uses a snake_case `tsig_key`
  tag (config.go:395), contrary to the project's lowercase-no-underscore YAML convention. A9 is
  already touching this field's handling — either fix the tag to `tsigkey` in the same pass (a
  config-breaking rename, consistent with the hard cutover) or explicitly note it's being left. Don't
  silently leave the inconsistency unremarked.
- **Operator ERROR strings:** draft the exact quarantine messages for legacy bare-string
  `primary:`/`notify:`, missing/empty `key`, and unknown key name — surfaced via `list-zones` /
  zone ERROR state.
- **Future (not this work): converge `Ready`/`FirstZoneLoad` onto `ZoneStatus` (B6).** B6 adds
  `ZoneStatus` alongside the existing lifecycle booleans without rewriting their consumers (the
  `!zd.Ready` gates stay). A later cleanup could make `ZoneStatus` the single source and retire the
  booleans — a broad refactor, deliberately out of scope here.

## 11. Operator migration (hard cutover — ships with B0)

This is a config-breaking change on upgrade (small, absorbable per the project's no-backwards-compat
rule — installed base is ~operator-controlled). The operator migrates their own configs; the server
quarantines un-migrated zones rather than refusing to start. Ship this as a one-paragraph upgrade
note + migrated `*.sample.yaml`:

- **`primary:` — bare string → struct.** Every secondary zone:
  ```yaml
  # before
  primary: 192.0.2.1:53
  # after  (key is mandatory — choose NOKEY explicitly for "no TSIG")
  primary:
    addr: 192.0.2.1:53
    key:  NOKEY
  ```
- **`notify:` — bare string list → struct list** (primary zones). `downstreams:` is **removed**; fold
  any `downstreams:` entries into `notify:`:
  ```yaml
  # before
  notify: [192.0.2.2:53, 192.0.2.3:53]
  # after
  notify:
    - { addr: 192.0.2.2:53, key: NOKEY }
    - { addr: 192.0.2.3:53, key: NOKEY }
  ```
- **What an un-migrated zone does:** loads into **ERROR state** (visible via `list-zones`), server
  still starts, other zones unaffected. The ERROR message names the field and the required shape.
- **Adding TSIG (Improvement 2):** declare a `keys:` block and replace `NOKEY` with the key name on
  the relevant `primary`/`notify` entries — no other config change, no re-provisioning.
