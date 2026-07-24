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

## Implementation status (2026-06-28) — Improvement 2 (§6) COMPLETE

All nine §6 steps are implemented on branch `tsig-on-replication` (one commit per
step; each builds, passes `go test -race ./...`, and is `go vet`-clean):

| Step | Commit | Note |
|------|--------|------|
| 1 keys: store | `ce5edcd` | name→secret `TsigKeyStore`, NOKEY/BLOCKED reserved |
| 2 ip-spec ACL | `a11b0fb`,`05ca2a8` | `net/netip`; BLOCKED supersedes, first-match-wins |
| — helpers | `946486d` | keystore-backed `TsigProvider`, `SignForPeer`, `peerIP` |
| 3 SOA probe sign | `0437828` | `DoTransfer` per-attempt `up.Key` |
| 4 AXFR/IXFR sign | `f58c205` | `ZoneTransferIn` |
| 6 outbound NOTIFY sign | `7890be5` | `SendNotify`; threads `conf` (tdns-mp deferred-break) |
| **5+7 inbound verify** | `d68acff` | NOTIFY(SOA) `allow-notify` + AXFR `downstreams`; one provider on the auth `dns.Server` does verify + RFC 8945 response signing. **Combined** because they share all wiring. |
| 8 catalog wiring | `1a92b0d` | `tsig_key` → `primaries[].key`; false "applied" log deleted |
| 9 API/CLI + lifecycle | `5c9f771` | inline `tsig_name/secret/algo` on `zone add`/`modify`, upsert + **persist** to the dynamic config file's `keys:` block (survives restart) |

**Operator-visible behaviour change (hard cutover, step 7):** an empty
`downstreams:` ACL now **denies all AXFR/IXFR** (tdns previously served transfers
to anyone). Every zone that should serve transfers needs an explicit
`downstreams:` after deploy. See §11 migration.

**Deferred (per this plan):** ACL flags on the API (`--allow-notify`/`--downstreams`
are static-config-only in v1); TSIG key auto-drop (a never-dropped name store is
acceptable). tdns-mp must update its 4 `Notifier` call sites + the `DoTransfer`/
`FetchFromUpstream`/`ZoneTransferIn` callers when it bumps the pinned `tdns/v2`.

## Revision note (2026-06-28) — two model changes supersede parts of this plan

1. **Multi-primary + hostname resolution** (separate PR; see
   `2026-06-26-multi-primary-and-hostname-resolution-plan.md`). Scalar `primary:` → list
   **`primaries: []PeerConf`**; `ZoneData.Upstream` → `PrimariesConf` (as-written, persisted) +
   `Upstreams` (resolved `addr:port`, runtime-only); hostnames resolve via the in-process IMR at
   parse/load; SOA-probe and AXFR iterate the list with per-primary fallback. **There is no scalar
   `ZoneData.TsigKeyName`** — the per-peer key is `.Key` on each `primaries[]` / `Upstreams[]`
   entry, signed per attempt in the loop. Read every singular `primary` / `zd.Upstream` below as
   the list form.

2. **TSIG is now NSD-aligned, not per-peer** (decided 2026-06-28). The per-peer `(peerIP, name)`
   keystore is **dropped**; §6 is rewritten, and §3's "why per-peer" plus several §9 decisions are
   superseded (marked). Headline of the new model:
   - a **`keys:` block** maps **name → {algorithm, secret}** (globally-unique names; the *only*
     secret store; = NSD `key:`);
   - **four directional zone fields**, two per role — "initiate to an endpoint" (carries a key it
     **uses** to sign) vs "accept from a class" (carries a key it **requires**):

     | field | = NSD | role | entry |
     |---|---|---|---|
     | `primaries:` (exists) | request-xfr | secondary: pull from | `{addr, key}` |
     | `allow-notify:` (new) | allow-notify | secondary: who may NOTIFY me | `{ip-spec, key｜NOKEY｜BLOCKED}` |
     | `notify:` (exists) | notify | primary: who I notify | `{addr, key}` |
     | `downstreams:` (back) | provide-xfr | primary: who may AXFR from me | `{ip-spec, key｜NOKEY｜BLOCKED}` |

   - **ip-spec** = single IP, CIDR `1.2.3.4/24`, mask `1.2.3.4&255.255.255.0`, range `a-b`, or
     `0.0.0.0/0`/`::/0` for any. The ACL is an **ordered list**: a matching `BLOCKED` denies
     (supersedes), else first address-match wins (`NOKEY` → unsigned accepted; `<name>` → require a
     valid TSIG under that name). This is what lets you key on **TSIG only** (`0.0.0.0/0 K`) or
     **address only** (`1.2.3.4 NOKEY`) — key and address are independent conditions.
   - `downstreams:` **returns** — not as the old `notify:` synonym, but as the **transfer ACL**
     (provide-xfr). Inbound NOTIFY becomes `allow-notify:` (same shape) — this subsumes the old
     open question about NOTIFY key selection.
   - **Defaults:** empty `downstreams:` → **deny** (serve no AXFR — a hard cutover, since tdns
     serves AXFR to anyone today); empty `allow-notify:` → **accept NOTIFY from the configured
     `primaries:` set**.
   - This **dissolves** the "why per-peer" rationale, the persisted per-peer keystore, most of its
     refcounting, and the hostname-keystore-keying problem entirely.
   - **Familiar-terminology aliases** (`provide-xfr:`/`allow-transfer:` → `downstreams:`,
     `request-xfr:`/`upstreams:` → `primaries:`) are a **later, input-only** addition — accepted on
     input via a small key-normalization pass on the raw decoded map (before mapstructure, where the
     PeerConf hook lives), canonical name used in docs/output, `alias + canonical on one zone` →
     per-zone ERROR. **Not in v1.**

   Full model and steps in §6.

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
require a signature change (the per-entry key name on `primaries[]`/`Upstreams[]` resolves to a
secret in the `keys:` store — see §6, revised). The catalog path already *looks up*
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
| **TSIG scope** (revised 2026-06-28) | **NSD-aligned**: secrets keyed by **name** (a `keys:` block, name→secret), peer **authorization** as separate address ACLs (`allow-notify:` / `downstreams:`). Applies to **all replication messages** — SOA query, AXFR/IXFR, NOTIFY — sign outbound (by key name), verify inbound (ACL address-match + key name from the wire). **Reverses the per-peer `(peerIP, name)` keystore** (see §6, §3 "why per-peer"). | A TSIG key name is on the wire and identifies one secret (RFC 8945), so name-keying is the standard model; address authorization is a distinct concern best expressed as an ordered ip-spec ACL (NSD `provide-xfr`/`allow-notify`). Drops the per-peer store, its refcounting, and the hostname-keystore problem. |
| **Primary-side fields** (revised 2026-06-28) | Two distinct fields: **`notify: [{addr, key}]`** — who I notify (single endpoints, key signs the NOTIFY); and **`downstreams: []AclEntry`** — who may AXFR from me (the provide-xfr ACL: ip-spec + key｜NOKEY｜BLOCKED). `notify:` stays the canonical NOTIFY-target name; **`downstreams:` returns**, but as the **transfer ACL**, not a `notify:` synonym. (Multi-primary already cleaned up the old `Notify`/`Downstreams` duplication; B0's "one canonical name" still holds for the *notify-target* list.) | NSD keeps "who I notify" and "who may transfer from me" as **separate** lists — they genuinely differ (a signer/monitor may pull without being notified; a `/24` may pull). Deriving the xfr-ACL from `notify:` (the old plan) conflates them. |
| **Direct-API zones gate** | `zone add` is **refused unless `dynamiczones.dynamic.allowed: true`**; persistence uses `dynamiczones.dynamic.storage` (parallel to catalog's `members.storage`). | The config field `DynamicZonesConf.Dynamic.Allowed` already exists and **defaults false** (config.go:419) but is checked nowhere — so today the gate is silently inert. The interface must honour it or it ships an always-on capability the operator believed they had disabled. |
| **`list-dynamic` scope** | Returns **all persistable dynamic zones** — predicate: `ShouldPersistZone(zd)` (catalog members, catalog zones if persistent, API-managed). **Not** the same predicate as delete/modify: those mutate only `OptApiManagedZone` zones. Catalog members appear in the list (read-only from this API) but cannot be deleted/modified here — use the catalog API for that. | `getDynamicZonesFromZonesMap()` already filters on `ShouldPersistZone`; reusing it is correct once B5 extends that gate for API zones. Using `OptApiManagedZone` for list would hide catalog members and confuse operators who expect to see the full dynamic set. |
| **API `zone add` scope (v1)** | **Secondary zones only** via API/CLI in Improvement 1. Primary zones with `notify:` peers are static-config (or catalog) only until a later extension; wire structs may carry notify peers for Improvement 2 static YAML, but `ProvisionDynamicZone` rejects `type: primary`. | Avoids half-specifying primary+notify on the API surface before TSIG and `PeerConf` notify migration land; catalog and static config cover primary today. |
| **`modify` mutable fields (v1)** | **`primary` addr/key and `options` only.** Not notify/downstreams, DNSSEC policy, update policy, store, or rename (rename = delete+add). Matches B1c scope; catalog group options remain catalog-config territory. | Keeps the first `modify` core small; notify/TSIG changes on primaries are static-config or future work. |
| **Catalog non-map store** | Re-pointing catalog at the map-only core is an **explicit breaking change** for any config group using `store: xfr` or `store: slice`. | `parseZoneStore` silently coerces empty/unknown → map today (catalog.go:474-492), so most groups are unaffected; but an *explicit* non-map store now becomes an ERROR rather than a silent honour. Consistent with no-backwards-compat — but it is a behaviour change, called out here, not buried in a §10 audit. |
| **Primary/key syntax** (revised 2026-06-28) | `primaries: [{addr, key}]` — a **list** (multi-primary), each entry `{addr, key}`; `key` **mandatory and explicit**, sentinel `NOKEY` = unauthenticated. The key is the **name** referenced from the `keys:` block. | List for redundancy (multi-primary); mandatory key makes "no TSIG" deliberate; name-referenced secret per the NSD model. (B0 shipped the struct; multi-primary made it a list.) |
| **Invalid `primary.key` handling** | **Per-zone ERROR quarantine, not a fatal parse error.** A missing/empty `key`, or a key name that doesn't resolve, puts *that zone* into ERROR state; the server still starts and other zones are unaffected. | Matches the project's resilient-config-startup rule (config errors are quarantined per-object, never fatal). "Must fail to parse" would abort the whole server — wrong. |
| **Zone store for dynamic zones** | **`MapZone` only**, enforced in the shared `ProvisionDynamicZone` core — applies to **catalog-, API-, and CLI-provisioned** zones alike. Any other store requested → reject (ERROR/error). | `slice` is legacy; `xfr` is not wanted for dynamically managed secondaries. One rule in one place removes the whole re-instantiation problem from `modify` (B1c). `parseZoneStore` already defaults empty/unknown → map, so this is a tightening, not a new behaviour. |
| **Sequencing** | Improvement 1 (interface) first, Improvement 2 (TSIG) second. | One-way dependency: the interface establishes the `PeerConf` syntax TSIG then consumes (doing TSIG first builds those structs twice). The interface also ships standalone value (NOKEY zones work end-to-end with none of TSIG's code). Risk is not the driver — under `risk = probability × consequence` (§7) both halves are Low–Med overall; the one elevated cell is B5b (resurrection race), in the interface half. |

### Why per-peer and not global or per-zone  *(superseded 2026-06-28 — see §6 "Why name-keyed")*

This subsection argued for a per-peer `(peerIP, name)` keystore. **That decision is reversed.** The
NSD-aligned model keys the secret by **name** (globally, from the `keys:` block) and expresses peer
*authorization* separately as an address ACL — which both simplifies the store (no per-peer table, no
refcounting, no hostname-keystore-keying) and is the standard, operator-familiar decomposition. The
original concern ("two peers reuse the same wire key-name with different secrets") is avoided by
naming the two relationships distinctly, and NSD doesn't support it either. Rationale in full at §6.

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
- ✅ **B6 DONE** (2026-06-25) — `ZoneStatus` enum (`Unknown`/`Pending`/`Loading`/`Ready`) +
  `ZoneStatusToString`; `ZoneData.Status` field + `SetStatus`/`GetStatus` (mirrors `SetError` lock
  discipline, no registry). Three transition sites: `Pending` at fresh-zone build (refreshengine.go),
  `Loading` at `FetchFromUpstream`/`FetchFromFile` start, `Ready` co-located with the `Ready`-flip hard
  flips (set directly under `zd.mu`, not via `SetStatus`, to avoid re-lock). `zonestatus_test.go`
  proves set/get + orthogonality with the error registry (Ready+RefreshError → derives "error";
  clearing reverts to "ready"). `Ready`/`FirstZoneLoad` consumers untouched.
- ✅ **B1a/B1b/B1c DONE** (2026-06-25) — `DynamicZoneInput` + three shared cores in `dynamic_zones.go`:
  `ProvisionDynamicZone` (gate on `dynamic.allowed` for API callers; reject `type:primary` + non-NOKEY
  key + duplicate; map-only; `OptApiManagedZone` marker; `Status:Pending`; register → persist →
  **rollback on persist failure** → fire-and-forget enqueue, returns "poll list-dynamic"),
  `RemoveDynamicZone` (`OptApiManagedZone` guard; `generation.Add(1)` after `Zones.Remove`; drop config
  + zone file), `ModifyDynamicZone` (guard; delete+re-add — fresh `ZoneData`, old `generation.Add(1)`;
  `Force` re-pull). Pulled forward from B5: `ZoneData.generation atomic.Uint64` field +
  `OptApiManagedZone` enum (the **pre-persist guard half** of B5b is still pending). **Deviation from
  doc (approved 2026-06-25):** catalog path NOT fully re-pointed at the shared core (it carries
  `SourceCatalog`/`OptAutomaticZone`/group options the input struct doesn't); instead the §3 map-only
  break is applied surgically in `AutoConfigureZonesFromCatalog` (literal `ZoneStore: MapZone` + ERROR
  log on explicit non-map store). `dynamic_zones_cores_test.go` covers gate/reject/happy/duplicate/
  delete-guard+bump/modify-replace+bump.
- ✅ **B5a DONE** (2026-06-25) — `ZoneConf.ApiManaged bool` field; `ShouldPersistZone` third branch
  (`OptApiManagedZone` → `dynamic.{allowed,storage}`); `zoneDataToZoneConf` writes `ApiManaged` +
  skips `OptApiManagedZone`/`OptAutomaticZone` from `OptionsStrs` (internal markers); marker
  re-derivation in `LoadDynamicZoneFiles` (`OptAutomaticZone` ← `SourceCatalog` **fixes the latent
  catalog bug**, `OptApiManagedZone` ← `ApiManaged`); refreshengine **both** persist branches widened
  `ShouldPersistZone(zd) && OptAutomaticZone` → `ShouldPersistZone(zd)`; `ReloadZoneConfig` spare
  widened to `ShouldPersistZone(zd)` (closes the reload-spare gap) + `generation.Add(1)` on its
  `Zones.Remove`.
- ✅ **B5b DONE** (2026-06-25) — `zoneStillLive(zd, gen)` helper (live && same-pointer &&
  same-generation); refresh goroutine snapshots `gen := zd.generation.Load()` at dispatch; pre-persist
  guard `&& zoneStillLive(zd, gen)` at the goroutine persist site, and `&& zoneStillLive(zd,
  zd.generation.Load())` at the ticker persist site (reduces to identity check — ticker re-fetches
  `zd` fresh). `dynamic_zones_b5_test.go` covers write-side, ShouldPersistZone branch, zoneStillLive
  (bump/replace/remove all fail the guard), marker re-derivation. Full suite green under `-race`.
  **TESTBED CHECKPOINT NEEDED** (the silent-failure cases — survive-restart marker reload,
  delete/modify mid-AXFR resurrection — require the running server on NetBSD VMs; not provable on this
  dev box).
- ✅ **B2/B3/B4 DONE** (2026-06-25) — **Improvement 1 feature-complete.** B2: `ZonePost` gains
  `Primary PeerConf`, `Options []string`, inert `Tsig{Name,Secret,Algo}`; `ZoneConf.Provisioning`
  display field. B3: four `APIzone` cases (`add`→`ProvisionDynamicZone` returns `accepted`+poll-hint,
  `delete`→`RemoveDynamicZone`, `modify`→`ModifyDynamicZone`, `list-dynamic`→`getDynamicZonesFromZonesMap`
  enriched with `Provisioning`); the four commands are exempted from the zone-must-exist pre-check;
  `zoneProvisioning(zd)` derivation (error precedence) also wired into `list-zones`. B4: `zone add`/
  `delete`/`modify`/`list-dynamic` CLI subcommands (flags `--zone --primary-addr --primary-key
  --options`, inert `--tsig-*`, no `--store`; `dns.Fqdn` normalization). Tests:
  `apihandler_zone_provisioning_test.go`. All 5 binaries build; full v2 suite green under `-race`.
- **Remaining for Improvement 1:** testbed verification only (the §B5 silent-failure cases:
  survive-restart marker reload; delete/modify mid-AXFR resurrection — need the running server on the
  NetBSD VMs). Sample-config migration to structured `primary:`/`notify:` (§8 / §11) when convenient.

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
  way out. *(Superseded 2026-06-28: multi-primary made `ZoneData.Upstream` → `PrimariesConf`/`Upstreams []PeerConf`; the per-entry key carries the TSIG key name, and there is **no** scalar `TsigKeyName` — see the revision note.)*
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
  - **Key/peer change handling:**
    - *Improvement 1 (no TSIG yet):* the only legal key value is `NOKEY`, so a modify moves only
      `NOKEY` ↔ `NOKEY` — no key op, but the validation (must be `NOKEY`) still runs.
    - *Improvement 2 (NSD model — revised 2026-06-28):* a key change just sets a new **key name** on
      the `primaries[]` entry — the secret lives in the name-keyed `keys:` store, so there is **no
      per-peer re-bind** (the old `(peerIP, key_name)` rebind/refcount machinery is gone). If the
      modify carries `{tsig_*}`, it upserts that name→secret; an old API-owned name is dropped by the
      name-reference scan (§6 step 1) when no live zone still names it (config-owned names are never
      dropped). A port- or IP-only change touches only the send target, not the key.

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

## 6. Improvement 2 — TSIG on zone-replication peer transactions  *(do second)* — NSD-aligned (rewritten 2026-06-28)

### Model

One secret store and four directional fields:

- **`keys:` block** — `name → {algorithm, secret}`, globally-unique names; the **only** secret
  store. Both sign and verify look the secret up **by name** (the name is on the wire — the TSIG
  RR owner). `KeyConf.Tsig []TsigDetails{Name, Algorithm, Secret}` already exists (structs.go:809);
  this just tags + loads it. No per-peer `(peerIP, name)` store.
- **Secondary:** `primaries: []PeerConf{addr, key}` (multi-primary; the key NAME signs our outbound
  SOA/AXFR to that primary) and `allow-notify: []AclEntry` (who may NOTIFY us).
- **Primary:** `notify: []PeerConf{addr, key}` (the key NAME signs our outbound NOTIFY) and
  `downstreams: []AclEntry` (who may AXFR from us).
- **`AclEntry{ ip-spec, key }`**, `key ∈ {<name>, NOKEY, BLOCKED}`, `ip-spec` ∈ {IP, CIDR `/24`,
  mask `&m`, range `a-b`, `0.0.0.0/0`/`::/0`}.

### Transaction map (sign outbound by key-name; verify inbound by ACL + key-name)

```
Secondary                              Primary
─────────                              ───────
DoTransfer (SOA query)        ──TSIG──►            sign with primaries[i].key
ZoneTransferIn (AXFR/IXFR)    ──TSIG──►            sign with primaries[i].key
                              ◄──TSIG──  SendNotify   sign with notify[j].key
NotifyResponder (verify)      ◄──TSIG──            allow-notify ACL, then verify
                              ◄──TSIG──  ZoneTransferOut
ZoneTransferOut (serve)       ◄────────            downstreams ACL, then verify
```

- **Outbound:** each peer entry carries a key NAME → look up the secret in `keys:` → sign (NOKEY →
  plain, today's path). The multi-primary SOA-probe / AXFR loops sign **per attempt** with the
  current `up.Key`.
- **Inbound:** match `peerIP(srcAddr)` against the ACL (`allow-notify` / `downstreams`); the matched
  entry's `key` field decides — `NOKEY` → accept unsigned; `<name>` → the request's TSIG must name
  that key and verify against the `keys:` secret; `BLOCKED` → deny. The key name for verification
  comes from the **request's** TSIG RR; the source IP selects the ACL entry (and thus accept/deny +
  required key).

**Send vs match (unchanged in spirit):** send to the configured full `addr:port` (never assume
`:53`); match the ACL on **IP only** (`peerIP(srcAddr)` = port stripped), because the inbound source
port is ephemeral. ip-spec ranges (`/24`, mask, range) match the source IP against the prefix. (The
old "two peers on one IP, different ports, different keys" limitation is moot — the address ACL and
the key are now independent, and the key name is carried on the wire.)

### Shared helpers (new, e.g. `v2/tsig_peer.go`)

- `SignForPeer(msg, keyName, kdb)` — if `keyName == NOKEY`, no-op; else look up the secret **by
  name** in the `keys:`-loaded store, `msg.SetTsig(name, algo, …)` and set the client/transfer
  `TsigSecret`. Used by all outbound paths. (No `peerAddr` needed — the secret is name-keyed.)
- `VerifyFromPeer(msg, kdb)` — read the TSIG RR's key name from `msg`, look up the secret by name,
  verify the MAC; return ok/fail. The caller has already done the ACL address-match (below).
- `matchACL(acl []AclEntry, srcIP) (allow bool, requiredKey string)` — ordered scan: a `BLOCKED`
  whose `ip-spec` matches `srcIP` → deny (supersedes); else the first `ip-spec` match → `(true,
  key)`; no match → deny. ip-spec parsing: `net.ParseCIDR` for CIDR/`/0`; small parsers for mask
  `a&m` and range `a-b`; a bare IP is a `/32`/`/128`.
- `peerIP(addr)` — host part of `net.SplitHostPort(addr)` (bare IP, port stripped), used to reduce
  the inbound `RemoteAddr()` for the ACL match.

Retire `Globals.TsigKeys` for auth replication: the `keys:` block is the name→secret store; catalog/
API provisioning upsert into it by name. CLI reporter may keep its own client-side `ParseTsigKeys`
path — out of scope for auth.

### Implementation steps

> **A-label map** (the §7 assessment table uses `A`-labels): step 1 = **A1**+**A3a** (keystore +
> `keys:` block, now merged into one name→secret store); step 2 = the new **ACL** machinery; steps
> 3–7 = **A4–A8**; step 8 = **A9**; step 9 = key/ACL lifecycle. The old **A2** (`PeerConf` struct)
> shipped with multi-primary + B0 and is no longer a step here.

1. **`keys:` block — the name→secret store.** Tag `Config.Keys` (`yaml:"keys" mapstructure:"keys"`);
   the shape exists (`KeyConf.Tsig []TsigDetails{Name, Algorithm, Secret}` at structs.go:809). Load
   `keys.tsig[]` into a **name-keyed** store at startup (auth loads no keys today). Sign and verify
   both look the secret up **by name** — no `(peerIP, name)` tuple, no per-peer DB table.
   - `NOKEY` is reserved: a `keys.tsig[]` entry named `NOKEY` (any case) → ERROR.
   - A peer/ACL referencing a non-`NOKEY` key name with **no matching `keys.tsig[]` entry** → that
     zone to per-zone ERROR (same quarantine rule as B0).
   - **API-created keys** (`zone add --tsig-*`) upsert a name→secret entry; persist them with an
     `owner` discriminator (`config`|`api`) if API-key auto-drop is wanted. Auto-drop, if kept, is a
     **name-reference scan** of live `Zones` (much simpler than the old per-peer scan): drop an
     `owner="api"` key when no live zone's `primaries[].key` / `notify[].key` / ACL entry still names
     it. Config-declared keys are config-owned and never auto-dropped. (Whether to implement
     auto-drop at all in v1 is a small detail — a never-dropped name store is also acceptable.)
   - **Config wins on reload** still falls out of load order: DB-load → `keys:` bind (upsert by name)
     → zone parse. Because the keystore is now name-keyed, the conflict is `name` vs `name` — config,
     bound last, lands on top.

2. **ip-spec type + ordered-ACL matcher** (new; shared by `allow-notify:` and `downstreams:`). Parse
   `1.2.3.4`, `1.2.3.4/24`, `1.2.3.4&255.255.255.0`, `1.2.3.4-1.2.3.25`, and `0.0.0.0/0` / `::/0`
   (`net.ParseCIDR` does CIDR/`/0`; mask and range are small parsers; a bare IP is a host route).
   Each `AclEntry` is `{spec, key｜NOKEY｜BLOCKED}`. `matchACL(acl, srcIP)` scans in order: a matching
   `BLOCKED` denies (supersedes); else the first `spec` match wins. YAML form: a string
   `"1.2.3.4/24 transfer-key"` reads closest to NSD (or a struct `{spec, key}` — pick one and run it
   through a decode hook like `stringToPeerConfHook`). `allow-notify:`/`downstreams:` are both
   `[]AclEntry` on `ZoneConf`/`ZoneData`/`ZoneRefresher`.

3. **Secondary → primary: SOA probe** — `DoTransfer` already iterates `zd.Upstreams` (multi-primary).
   For each attempt, `SignForPeer(m, up.Key, kdb)` and move the call onto a `dns.Client{TsigSecret:…}`
   + `client.Exchange` — the package-level `dns.Exchange` has **no `TsigSecret` and can't verify the
   response MAC**. `NOKEY` keeps today's plain path (no client, no MAC).

4. **Secondary → primary: AXFR/IXFR** — `ZoneTransferIn`, per attempt in `FetchFromUpstream`'s loop:
   `SignForPeer` sets `transfer.TsigSecret` + `msg.SetTsig` for `up.Key` before `transfer.In`. Remove
   TODO at dnsutils.go:29. *Verify miekg/dns `Transfer.TsigSecret` / `SetTsig` / algorithm constants
   against the vendored version.* Production refresh hardcodes `"axfr"` (zone_utils.go:234), so AXFR
   is the only call signed; IXFR uses the same helper if/when wired.

5. **Secondary ← primary: inbound NOTIFY** — `NotifyResponder` (notifyresponder.go:122; thread
   `zd.KeyDB` in — it has none today). Match `peerIP(remoteAddr)` against `allow-notify:`
   (**empty ⇒ accept from the resolved `primaries:` IPs**, so operators needn't restate their
   primary list). On `BLOCKED` / no match → **ignore** (NOTIFY is low-stakes — it only triggers a
   probe against the secondary's own TSIG-protected primaries; log, don't act). On an allow match:
   `NOKEY` → accept unsigned; `<name>` → `VerifyFromPeer` (REFUSE + log on bad MAC). **Sign the NOTIFY
   response** with the same key when the request was signed (RFC 8945; for a `NOKEY` path it stays
   unsigned). The key for verification is named in the request's TSIG RR; the ACL entry only gates
   accept/deny and which name is *required*.

6. **Primary → secondary: outbound NOTIFY** — `SendNotify` (notifier.go:95): for each `notify[]`
   target, `SignForPeer(m, entry.Key, kdb)` before `ExchangeContext`, sending to the entry's full
   `addr:port`.

7. **Primary ← secondary: inbound AXFR/IXFR (the `downstreams:` ACL — the substantive change)** —
   `ZoneTransferOut` (dnsutils.go:222, reached from queryresponder.go:816, has `w.RemoteAddr()` and
   does no ACL today). Match `peerIP(w.RemoteAddr())` against `downstreams:`: **empty ⇒ DENY** (closes
   today's open-AXFR gap — a hard cutover); `BLOCKED` / no match → REFUSE; match key `NOKEY` → serve
   unsigned; `<name>` → `VerifyFromPeer` and serve only on a valid MAC. This is the NSD `provide-xfr`
   model — `downstreams: 0.0.0.0/0 transfer-key` (anyone with the key) and `downstreams: 1.2.3.4
   NOKEY` (this host, no TSIG) both fall out of the ip-spec + key fields.

8. **Wire catalog path** — catalog.go:399-404: map the group's `tsig_key` onto the provisioned
   zone's `primaries[].key` name (the `keys:` store holds the secret); **delete the false "applied
   TSIG key" log** (catalog.go:403) now (a one-line correctness fix, independent of the rest).
   Re-point the existing `tsig_key` config-check from the (now-unused-on-auth) `Globals.TsigKeys` to
   the parsed `keys.tsig[]` name-set, or it always-fails.

9. **API/CLI + key lifecycle.** `zone add`/`modify` carry `{tsig_name, tsig_secret, tsig_algo}` →
   upsert a `keys:` (name→secret) entry and reference it from `primaries[].key`. Key auto-drop, if
   implemented, is the name-reference scan from step 1 (`owner="api"` only). ACL flags
   (`--downstreams` / `--allow-notify`) are added if/when the API surfaces primary-side management;
   v1 may keep the ACLs static-config-only. Note a port-only change of a primary's `addr` does not
   change the key (it's name-keyed) — only the send target moves.

### Why name-keyed + address ACLs (supersedes the old "why per-peer")

- The TSIG key name is **on the wire** (the TSIG RR owner) and both sides must agree on it per
  relationship, so a name identifies **one** secret. Keying secrets by name (NSD `key:`) is the
  standard model and removes the per-peer store, its refcounting, and the hostname-keystore-keying
  problem (old decision A) entirely.
- The old `(peerIP, name)` tuple existed only to disambiguate "two peers using the same wire
  key-name with different secrets" — a case you avoid by giving the two relationships distinct names,
  and one NSD can't express either. Dropping it is a net simplification.
- **Address authorization is a separate concern from the key**, expressed as an ordered ACL of
  ip-specs (NSD `allow-notify`/`provide-xfr`). That independence is what lets you key on TSIG only
  (`0.0.0.0/0 K`) **or** address only (`1.2.3.4 NOKEY`).

### Tests (Improvement 2)
- End-to-end with TSIG on all paths (SOA probe, AXFR, NOTIFY, inbound AXFR verify) — miekg/dns test
  server or two tdns-auth instances. Multi-primary: the secondary signs **per attempt** with the
  current primary's key.
- `NOKEY` end to end stays plain/unauthenticated (today's behaviour).
- **ACL (`downstreams:`):** `0.0.0.0/0 K` (key-only) admits any source with key K; `1.2.3.4 NOKEY`
  (addr-only) admits that host unsigned; a `BLOCKED` entry supersedes a following allow; an unmatched
  source → REFUSE. **Empty `downstreams:` → AXFR REFUSED.**
- **ACL (`allow-notify:`):** empty ⇒ NOTIFY accepted from a configured primary's IP, ignored from a
  stranger; an explicit entry with `<name>` requires a valid TSIG.
- **NOTIFY response is TSIG-signed** when the request was; `NOKEY` reply unsigned.
- **`keys:` by name:** a `keys.tsig[]` entry named `NOKEY` → ERROR; a peer/ACL referencing an
  undefined key name → that zone ERROR; config-wins on reload (config bound last upserts the name).
- Restart: the `keys:` store (DB + config) is loaded before the first refresh/NOTIFY, so every
  referenced key name resolves when the first transfer fires.

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

> **Improvement-2 rows superseded (2026-06-28).** The A1–A10 breakdown above reflects the old
> per-peer-keystore design; the NSD-aligned model (§6) re-shapes it: **A1** shrinks (a name→secret
> store, no per-peer DB table / refcount); **A2** is gone (`PeerConf` shipped with B0 + multi-primary;
> no `TsigKeyName`); a **new ACL row** (ip-spec type + ordered matcher, shared by `allow-notify:` /
> `downstreams:`) is added; **A8** becomes the `downstreams:` ACL and **A6** the `allow-notify:` ACL.
> Net direction is **smaller** (the keystore/refcount removals outweigh the ACL additions), but the
> per-row numbers above should be re-estimated against §6's steps before use.

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

**Improvement 2 (NSD-aligned — revised 2026-06-28):**
- v2/tsig_peer.go (new: `SignForPeer(msg, keyName, kdb)`, `VerifyFromPeer(msg, kdb)`, `peerIP(addr)`,
  `NOKEY` sentinel)
- v2/tsig_keys.go (new: the **name→secret** store — load `keys.tsig[]`; `GetTsigKey(name)`;
  optional persist + `owner` discriminator + name-reference auto-drop for API keys). **No per-peer
  `(peerIP, name)` table.**
- v2/acl.go (new: `AclEntry{ip-spec, key}`, ip-spec parse/match (CIDR/mask/range/any), ordered
  `matchACL`, `BLOCKED`)
- v2/structs.go (`ZoneConf`/`ZoneData`/`ZoneRefresher`: add `AllowNotify []AclEntry` +
  `Downstreams []AclEntry`. **No `ZoneData.TsigKeyName`** — keys are on `primaries[]`/`notify[]`.)
- v2/config.go + v2/parseconfig.go (`keys:` tag + load into the name store; decode/validate
  `allow-notify:`/`downstreams:`; a referenced-but-undefined key name → zone ERROR)
- v2/zone_utils.go (`DoTransfer` — sign per `up.Key` in the multi-primary loop)
- v2/dnsutils.go (`ZoneTransferIn` sign per `up.Key`; `ZoneTransferOut` — `downstreams:` ACL + verify)
- v2/notifier.go (`SendNotify` — sign with `notify[].key`)
- v2/notifyresponder.go (inbound NOTIFY — `allow-notify:` ACL (empty ⇒ accept from `primaries:`) +
  verify; thread `zd.KeyDB`)
- v2/queryresponder.go (AXFR path: `ZoneTransferOut` already has `w.RemoteAddr()`; reduce via
  `peerIP` for the `downstreams:` match/verify — no new param)
- v2/catalog.go (map group `tsig_key` → `primaries[].key` name; delete the false "applied TSIG key"
  log; re-point the `tsig_key` check at `keys.tsig[]`)
- v2/refreshengine.go (assign `AllowNotify`/`Downstreams` onto `ZoneData`)
- v2/global.go / v2/tsig_utils.go (stop using `Globals.TsigKeys` on the auth replication path)

## 9. Decisions (all resolved 2026-06-23, incl. external-review round)
- **Static-config migration (B0): hard cutover, resilient.** Bare-string `primary:`/`notify:` values
  are **rejected** (no auto-read), but as a **per-zone ERROR**, not a fatal parse error — achieved via
  a **`mapstructure` decode hook** (`stringToPeerConfHook`, string → `PeerConf{Legacy:…}`) on the
  `DecoderConfig`, **not** a `yaml.Unmarshaler` (which never fires: decode is `yaml → map →
  mapstructure`, and mapstructure ignores the YAML interface — verified). The hook records a legacy
  marker so the whole-file decode succeeds and per-zone validation quarantines just that zone (without
  it, one legacy value aborts the whole-file decode, verified at parseconfig.go:287-292).
- **Canonical NOTIFY-target field: `notify:`** (B0c) — one `[]PeerConf` for *who I notify*.
  **Revised 2026-06-28:** `downstreams:` returns as a *separate* field — the **transfer ACL**
  (provide-xfr), not a `notify:` synonym — and `allow-notify:` is added as the inbound-NOTIFY ACL.
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
- **Inbound AXFR ACL (revised 2026-06-28 — the `downstreams:` ACL):** served only if
  `peerIP(requester)` matches a `downstreams:` entry (ip-spec + key｜NOKEY｜BLOCKED, ordered, BLOCKED
  supersedes); **empty `downstreams:` ⇒ DENY** (closes today's open `ZoneTransferOut`). This is a
  *separate* ACL from `notify:` (NSD `provide-xfr`), **not** "match a configured notify peer."
- **Inbound NOTIFY (revised 2026-06-28 — the `allow-notify:` ACL):** matched against `allow-notify:`;
  **empty ⇒ accept from the configured `primaries:` IPs**; a non-NOKEY entry requires a valid TSIG.
  Supersedes the old single-key `zd.TsigKeyName` verify and the "no address-ACL on NOTIFY" stance.
- **Address model (revised 2026-06-28):** **send** to the configured full `addr:port` (never assume
  `:53`); **match ACLs on IP only** (`peerIP` = port stripped) via ip-spec (IP/CIDR/mask/range).
  **Secrets are keyed by name, not `(peerIP, name)`** — the old per-peer keystore tuple is dropped.
- **Catalog `tsig_key` → `primaries[].key`:** map the group key-name onto the provisioned zone's
  primary key (name-referenced in `keys:`); delete the false "applied TSIG key" log now.
- **`keys:` load ordering (decided 2026-06-25, simplified 2026-06-28):** DB-load → `keys:` bind
  (upsert by **name**) → zone parse. Config binds last, so on a **name** collision config wins on
  reload — no special-case comparison. API keys (`owner="api"`) survive when no config name collides;
  optional auto-drop is a **name-reference** scan of live `Zones`.
- **`Globals.TsigKeys` retirement:** auth replication uses **only** the `keys:` name→secret store; the
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
- **`primary:` → `primaries:` (multi-primary, separate PR).** The struct above became a **list**;
  see `2026-06-26-multi-primary-and-hostname-resolution-plan.md` for that cutover. Read the `primary:`
  examples above as a one-element `primaries:` list.
- **Adding TSIG (Improvement 2, NSD-aligned — revised 2026-06-28):**
  - declare a **`keys:`** block (`name → {algorithm, secret}`) and replace `NOKEY` with the **key
    name** on the relevant `primaries[]` / `notify[]` entries (the entry references the name; the
    secret lives in `keys:`);
  - add a **`downstreams:`** ACL on every primary that should serve AXFR — **this is a hard cutover:
    with `downstreams:` empty, AXFR is now REFUSED to everyone** (tdns serves AXFR openly today).
    Entries are `ip-spec key｜NOKEY｜BLOCKED`, e.g. `203.0.113.0/24 transfer-key`, `192.0.2.9 NOKEY`,
    `0.0.0.0/0 BLOCKED`;
  - optionally add **`allow-notify:`** (same shape) to restrict who may NOTIFY a secondary — empty
    means "accept from the configured `primaries:`."
  - An un-migrated zone that needs a key it can't resolve, or names an undefined key, → ERROR
    (visible via `list-zones`), server still starts.
