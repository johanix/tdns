# Multi-Primary Upstreams + Hostname Resolution

**Date:** 2026-06-26
**Status:** Design / implementation plan
**Tree:** this repo (`github.com/johanix/tdns`), package `v2/`, binary built from `cmdv2/auth`
**Branch:** `dynamic-zones-mgmt` (follow-on to the dynamic-zones management interface;
not yet merged — this change is intrinsic to making that interface usable in the
field)
**Related:** [2026-06-23-dynamic-zones-interface-and-tsig-transfers.md](2026-06-23-dynamic-zones-interface-and-tsig-transfers.md)
(established the `PeerConf` / NOKEY model this builds on)

## Summary

Today a secondary zone has exactly **one** primary (`zd.Upstream`, a scalar
`string`), handed straight to the SOA-probe and AXFR code, which connects to a
single address. Two problems follow:

1. **No redundancy.** Real DNS infrastructure always has more than one primary.
   tdns can only express one.
2. **A hostname primary that resolves to multiple addresses (e.g. A + AAAA) only
   ever tries one of them, and gives up on failure.** This surfaced on a test box
   with no outbound IPv6 route: `zone add --primary-addr nsa.johani.org:53` (a name
   with both A and AAAA) picked the AAAA, hit `no route to host`, and never fell
   back to the working A address. A sibling zone using a v4-only name worked fine.

The fix is **not** "teach the transfer code to resolve hostnames." The real defect
is that **`Primary` is a scalar when it must be a list.** Once the primary is a
list of upstreams, expanding a hostname into several `addr:port` tuples is trivial
— there is already a slist to store them in.

This plan:
- Renames `primary:` → **`primaries:`** (a `[]PeerConf` list). No siblings.
- Resolves each entry's address **at config-parse/load time** (every startup and
  reload), turning a hostname into one-or-more `addr:port` tuples (the per-entry
  key copied to each). Re-resolved on every load, so the address set tracks DNS
  changes over time.
- Makes the SOA-probe and AXFR paths **iterate the resolved list**, advancing to
  the next address on **transport errors only** (no route / refused / timeout),
  honouring any DNS response as-is.
- Keeps the operator's **as-written** entries (hostnames and IPs) for persistence;
  the resolved addresses are runtime-only and never frozen to disk.

## 1. Operating principles (why the design is shaped this way)

These come from how experienced DNS operators actually run infrastructure, and
they drive every decision below:

- **DNS infrastructure must not depend on DNS resolution working.** A nameserver
  has to keep working precisely when resolution has broken down. Operators
  therefore *choose* to configure primaries by **IP address**, even though the
  software is free to accept hostnames.
- **A nameserver may still support hostnames** — that freedom is fine to offer; it
  just must not become a runtime dependency. So: accept a hostname, but resolve it
  **at config-parse time** (a moment when a resolution failure can be surfaced
  loudly and quarantined), not during transfers. After expansion the runtime path
  is pure-IP and resolution-independent, honouring the first principle.
- **There is always more than one primary, for redundancy.** The data model must
  be a list, not a scalar. Once it is a list, hostname-expansion is "append the
  resolved addresses to the list" — no special machinery.
- **Get the server running and the zone served.** A primary that fails to resolve
  must not take down a zone that has other, working primaries. Partial failure is a
  *visibility* signal, not a service-impacting error.

## 2. Current state (verified against the code 2026-06-26)

`ZoneData.Upstream` is a single `string` (structs.go:121), holding the configured
primary's address with a default port appended — **never resolved**. It is set
only from config, always as `NormalizeAddress(zr.Primary.Addr)`
(refreshengine.go:247/319/576, dynamic_zones.go:592/719, catalog.go:382), where
`Primary` is a `PeerConf` (`{Addr, Key, Legacy}`, the structured form from the
prior PR). Two send sites consume it directly:

- **SOA probe** — `DoTransfer` (zone_utils.go:84): `dns.Exchange(m, upstream)` at
  zone_utils.go:101, a single destination.
- **AXFR/IXFR** — `ZoneTransferIn` (dnsutils.go:54): `transfer.In(msg, upstream)` at
  dnsutils.go:75, reached from `FetchFromUpstream` (zone_utils.go:217) which passes
  `zd.Upstream` at zone_utils.go:237.

Both hand a `host:port` string to the vendored miekg/dns (`johanix/dns`), which
calls Go's dialer. The dialer resolves a hostname but connects to **one** address
— for the UDP SOA probe it never falls back; for the TCP AXFR it falls back only on
TCP-connect failure, not on a DNS-level failure. So a multi-address hostname primary
is a single point of failure even though the redundancy exists in DNS.

`NormalizeAddress` (parseconfig.go:1453) appends a default `:53` and does **no**
resolution — a hostname survives it unchanged.

`RefreshCounter.Upstream` and `RefreshCounter.Notify` (refreshengine.go:46-47) are
**write-only / dead** (verified: read nowhere; the ticker re-refreshes via
`zd.Upstream`). They are deleted as part of this work (decided — see §4).

`TemplateConf` (structs.go:252) is dead code (never instantiated; templates use
`[]ZoneConf` / `map[string]ZoneConf`). Its `Primary` field is irrelevant here and
is left untouched.

## 3. Design decisions

| Topic | Decision (2026-06-26) | Rationale |
|---|---|---|
| **Scalar → list** | `primary: PeerConf` → **`primaries: []PeerConf`** everywhere (config, refresher, input, wire). YAML key renamed; **no siblings**. | The actual defect: a primary is a redundant *set*, not one thing. A list makes hostname-expansion trivial. |
| **Resolution timing** | **At config-parse/load time**, re-resolved on every startup/reload — NOT at transfer time, NOT cached once-and-for-all. | Honours "infra must not depend on resolution at runtime" while picking up address changes over time. A parse-time failure can be quarantined loudly. |
| **Hostname allowed** | A `primaries:` entry's `addr` may be an IP **or** a hostname (both with `:port`). Hostname → all resolved `addr:port`, **v4 before v6**. | The software offers the freedom; operators choose IPs. v4-first directly fixes the broken-outbound-v6 case (the working family is tried first) and is harmless on healthy dual-stack. |
| **Resolution source** (revised 2026-06-28) | **The in-process IMR** — `conf.Internal.ImrEngine.DefaultRRsetFetcher` for A + AAAA — NOT `net.LookupHost`. Because the IMR engine goroutine starts *after* `ParseZones`/`LoadDynamicZoneFiles` in `MainInit`, `MainInit` now calls `conf.InitImrEngine()` synchronously before `ParseZones` (idempotent, first-init-wins; the per-app `StartXxx` reuses the instance and adds trust anchors + listeners). | Primaries must resolve the way **tdns itself** resolves names — through its own recursive resolver, with the root hints / stubs / validation tdns is configured with — not via the OS stub resolver, whose configuration tdns does not control. **This reverses the original `net.LookupHost` decision** (the earlier rationale — "resolve the way the box's OS resolves" — was rejected: the relevant resolver is tdns's, not the OS's). |
| **Partial resolution** | Some entries resolve, some don't, **≥1 address results → zone is SERVED** + a visibility-only **`ConfigWarning`** naming the unresolved entries. **Zero addresses → `ConfigError`** (service-impacting, zone quarantined). | Get the server running and the zone served. One dead name must not kill a zone with working primaries. The warning makes the degradation visible without degrading service. |
| **Two ZoneData fields** | `ZoneData.PrimariesConf []PeerConf` (as-written, **persisted**, re-resolved each load) **and** `ZoneData.Upstreams []PeerConf` (resolved `addr:port`, **runtime-only**). | The hostname is the durable thing; addresses are derived and ephemeral. Persisting resolved addresses would freeze them and contradict re-resolution on restart. |
| **Transfer fallback** (revised 2026-06-28) | Both paths **iterate `Upstreams`** until one yields what's needed. **AXFR**: advance on ANY failure — transport error, a REFUSED/NOTAUTH/SERVFAIL xfr rcode, or bad zone data; stop on the first success; all-failed → error. **SOA probe**: advance on a transport error OR a non-usable rcode (REFUSED/SERVFAIL/NXDOMAIN/empty); stop on a usable NOERROR+SOA; if every primary answered but none was usable → quiet back-off (no transfer, no error); all-unreachable → hard error. | Multiple **primaries** are independent servers, not addresses of one server: `allow-transfer` ACLs routinely differ per primary, so a REFUSED from one says nothing about a sibling. Terminating on REFUSED would defeat the very redundancy multi-primary exists to provide. **Reverses the earlier "retry on transport errors only, honour any DNS response" decision** — which wrongly conflated multiple distinct primaries with multiple addresses of one server, and so dropped the `isTransportError` distinction entirely. |
| **Loop location** | The fallback loop lives in the **callers** (`DoTransfer`, `FetchFromUpstream`); `ZoneTransferIn` keeps its single-`upstream string` signature. | Smaller change; `clarifyXfrError` and the envelope-read loop stay intact. |
| **Scope** | The transfer-path fix (the resolved-list loop) benefits EVERY secondary — static config, catalog, **and** API-added — because they all reach `DoTransfer`/`FetchFromUpstream` via `zd.Upstreams`. **Multi-*primary*** (a list the operator writes) is added for **static + API** zones; **catalog members get multi-*address* only** (see catalog row). | The latent bug was never dynamic-zones-specific; the interface just made it easy to trip. Fix it where it actually lives. |
| **Catalog scope (minimal — decided 2026-06-26)** | `ConfigGroupConfig.Upstream` stays a **single scalar `string`** (no config-group schema change, no catalog-YAML cutover). At catalog auto-config (`catalog.go:382`) that scalar is run through **`resolvePrimaries`** to populate `zd.Upstreams`, **and `zd.PrimariesConf` is set to `[{scalarUpstream, NOKEY}]`** (the as-written form, so the catalog member persists + re-resolves like any dynamic zone). Note: catalog does not map `tsig_key` into that key today — it is `NOKEY` until TSIG lands. | Catalog members are edge secondaries that pull from *one* provider primary — per-member multi-primary lists are a redundancy model nobody deploys (same over-engineering rejected for the catalog notify-API in Improvement 1). But the **reported bug** (hostname → one address, no fallback) absolutely hits catalog members, so they need the multi-*address* expansion. This delivers the fix where it's needed without the part that's overkill. |
| **Empty / invalid list** | `primaries: []` (or all-`NOKEY`-but-no-addr) on a **secondary** → `ConfigError` ("no primary configured"), zone quarantined, server still starts. A `primaries:` on a **primary** zone is ignored (warn). | Same service-impacting semantics as today's "secondary has no primary" check, just list-shaped. |
| **Dedup of resolved tuples** | After expansion, **dedup the resolved `(addr:port)` set** (two entries, or a hostname + its own IP, can yield the same address). Keep first occurrence (preserves v4-first ordering and the first-seen key). | Avoids probing the same address twice per refresh and avoids a spurious duplicate in `Upstreams`. Dedup is on `addr:port`; a genuine `(addr, differing-key)` collision is flagged (TSIG-relevant, §3 note below). |
| **CLI key scope** | `--primaries` is a comma-separated list; **one `--primary-key` applies to all** entries on the CLI. Per-primary keys remain expressible via YAML/API (the structured `[]PeerConf`). | A primary set usually shares one TSIG key; per-primary CLI syntax (`a:53/K1,b:53/K2`) is clunky and rarely needed. The structured paths still allow it. |
| **Dead RefreshCounter fields** | **Delete** `RefreshCounter.Upstream` and `RefreshCounter.Notify` and their 6 write sites. | Verified write-only / read-nowhere. Converting a dead scalar to a dead list is pointless. (Operator-approved 2026-06-26.) |
| **miekg/dns built-in fallback** | Not relied upon. | Go's dialer picks one address (UDP: no fallback; TCP: connect-failure only). Insufficient for DNS-level robustness; we do explicit resolve-to-list + per-address retry. |

### 3.1 Cross-cutting clarifications (added 2026-06-26 after plan review)

- **Resolution runs on EVERY ingress path, not just static parse.** `resolvePrimaries`
  is called wherever as-written primaries enter or re-enter the runtime:
  (1) `ParseZones` (static config, initial + `ReloadZoneConfig`);
  (2) `LoadDynamicZoneFiles` (persisted dynamic zones on startup);
  (3) `ProvisionDynamicZone` (API `zone add` with a hostname — must resolve at
  add time, not only on the next restart);
  (4) `ModifyDynamicZone` (API `zone modify`);
  (5) catalog auto-config (the single scalar, per the catalog row).
  Missing any one leaves hostname primaries broken on that path only. Phase
  ownership is called out in §9.

- **IMR availability at parse time (added 2026-06-28).** Resolution uses the
  in-process IMR (`conf.Internal.ImrEngine`). In `MainInit` the resolve sites run
  *before* the per-app `StartXxx` brings up the IMR engine goroutine, so `MainInit`
  calls `conf.InitImrEngine()` synchronously before `ParseZones`. `InitImrEngine`
  primes the cache with root hints and is idempotent; the later
  `StartEngine("ImrEngine", …)` reuses the instance and adds trust anchors +
  listeners. The early init is gated on `conf.Imr.Active` and is non-fatal: if the
  IMR is disabled or fails to init, `resolvePrimaries` gets a nil IMR and reports
  hostname entries as unresolved (literal-IP primaries are unaffected — they are
  never queried). Consequence to document for operators: **with the IMR disabled,
  primaries must be IP literals.** Resolution still depends only on init-time
  IMR availability, not on runtime resolution during transfers (principle 1 holds).

- **NOTIFY-triggered refresh must NOT blank `Upstreams`/`PrimariesConf`.** An inbound
  NOTIFY enqueues a **minimal** `ZoneRefresher` (no primary fields). The refreshengine
  merge guard becomes `len(zr.PrimariesConf) > 0` (was `zr.Primary.Addr != ""`); when
  false, the zone **keeps its existing `zd.Upstreams` AND `zd.PrimariesConf`** rather
  than wiping them. (`ZoneRefresher` carries both forms — as-written and resolved —
  per §5; both are set on a config-bearing merge and both preserved on a NOTIFY
  merge.) Getting this wrong would erase a zone's upstreams on every NOTIFY — called
  out explicitly in P3/P4.

- **Re-resolution cadence: reload/restart only.** Addresses are re-resolved at
  parse/load/reload — **not** on the refresh ticker, **not** on record TTL. A
  mid-life DNS change to a primary's address requires a config reload (or restart).
  This is a deliberate consequence of principle 1 (no runtime resolution
  dependency); document it for operators. A future "re-resolve on ticker" is
  possible but explicitly out of scope.

- **Supersedes the TSIG doc's scalar primary/key model.** The related TSIG plan
  (Improvement 2) used singular `primary: {addr, key}` and a scalar
  `ZoneData.TsigKeyName string`. **This plan supersedes both:** the config key is
  `primaries: []PeerConf`, and the **per-peer TSIG key lives on each `Upstreams[]`
  entry** (the key is copied to every address a hostname expands to). When the TSIG
  loops land, the transfer fallback already has `up.Key` per address — no scalar
  `TsigKeyName` is needed. The TSIG doc should be cross-referenced/updated so
  Improvement 2 builds on `Upstreams []PeerConf` rather than reintroducing a scalar.
  (The `(peerIP, key_name)` keystore tuple from the TSIG doc is unchanged and
  aligned — a hostname expanding to N addresses yields N `(addr, sameKey)` tuples.)

- **`(addr, differing-key)` collision.** If two `primaries:` entries expand to the
  same address but carry **different** keys, that is a genuine ambiguity (which key
  for that peer?). Dedup keeps the first; the second is dropped with a
  `ConfigWarning`. Inert in Improvement 1 (all keys are `NOKEY`); relevant when TSIG
  lands.

- **NOTIFY source validation is OUT OF SCOPE here.** Inbound NOTIFY
  (`notifyresponder.go`) accepts any sender and triggers a refresh using the zone's
  configured `Upstreams`. Validating the NOTIFY source against the primary set is a
  *security policy* decision that belongs with Improvement 2 (TSIG), where NOTIFY
  authentication is already in scope. v1 behaviour: **any sender triggers a refresh;
  the refresh still only pulls from the configured `Upstreams`** (a spurious NOTIFY
  costs at most one SOA probe against the real primaries). Stated so it's a decision,
  not an omission.

- **No stickiness in v1 (intentional).** Every SOA check and AXFR starts at the
  first `Upstreams` entry. A permanently-bad first address adds one failed-probe of
  latency per refresh interval before falling through to a working sibling. This is
  accepted for v1; "remember last-good address" is a possible future optimization,
  not done here.

## 4. Blast radius (verified — ~60 sites, 9 files)

Counts per group (full per-site map captured during planning; the non-mechanical
ones are spelled out in the phases):

- **A. `ZoneConf.Primary`** → `Primaries`: 11 sites (parse validation, normalize,
  template apply, refresher build, persistence read).
- **B. `ZoneData.Upstream`** → `Upstreams`: 14 sites (the biggest group — the two
  transfer sites + many logs + persistence + the modify carry-forward).
- **C. `ZoneRefresher.Primary`** → **two fields `PrimariesConf` (as-written) +
  `Primaries` (resolved)**: 9 sites (4 overlap A/B); the Primary→Upstream flow in
  refreshengine, **including the NOTIFY-refresh merge guard** (`zr.Primary.Addr != ""`
  → `len(zr.PrimariesConf) > 0`; on a config-bearing merge set both `zd.PrimariesConf`
  and `zd.Upstreams`; on an empty NOTIFY merge preserve both).
- **D. `RefreshCounter.Upstream`/`.Notify`**: 6 dead writes → **deleted**.
- **E. Persistence** (`zoneDataToZoneConf`, `LoadDynamicZoneFiles`): 3 sites.
  `zoneDataToZoneConf` must write **`PrimariesConf` with its per-entry keys**
  (NOT reconstructed from resolved `Upstreams`, NOT hardcoded `Key: NOKEY`) — else
  API/catalog keys are lost on restart once TSIG lands.
- **F. API + CLI** (`ZonePost.Primary`→`Primaries`, APIzone add/modify, the
  **`--primaries`** comma-list flag (replacing `--primary-addr`),
  RunZoneAdd/Modify, list display rendering the list): ~12 sites.
- **G. `DynamicZoneInput.Primary`** in the cores: 11 sites — **plus a
  `resolvePrimaries` call in `ProvisionDynamicZone` and `ModifyDynamicZone`** so an
  API-added hostname primary resolves at add time, not only on the next restart.
- **H. Helpers**: `resolvePrimaries` + `expandPrimaryEntry` (IMR A/AAAA lookup),
  `sortV4First`, `buildUpstreams` — built on `imr.DefaultRRsetFetcher`,
  `net.ParseIP`, `net.JoinHostPort`/`SplitHostPort` (all already in use). Plus
  the early `conf.InitImrEngine()` in `MainInit` before `ParseZones`.
- **I. `ErrorType` enum**: 4 edits to add `ConfigWarning` (const,
  `ErrorTypeToString`, `errorTypeReportOrder`; **NOT** `serviceImpactingErrors`).
- **J. Catalog** (`catalog.go:382`, the auto-config `&ZoneData{Upstream: …}` and the
  inline `ZoneRefresher{Primary: …}` enqueue at catalog.go:428): run the
  single `ConfigGroupConfig.Upstream` scalar through `resolvePrimaries` → populate
  `Upstreams`. `ConfigGroupConfig.Upstream` itself **stays a scalar** (no
  config-group schema change). ~2 sites.

**The 12 non-mechanical sites** (scalar→list is not a rename) are the parse
validation loops, the resolution point (parseconfig.go:673-675 area), the template
is-set test, the two transfer loops, the single-value upstream logs, the
"primary changed/provided?" guards in modify, the persistence as-written decision,
the list-zones display pick, and the CLI flag change. Each is addressed in the
phase that owns it.

## 5. Data model (final)

```
ZoneConf:
  Primaries []PeerConf            // YAML primaries: — as written (IP or host:port)

ZoneData:
  PrimariesConf []PeerConf        // as-written; PERSISTED; re-resolved each load
  Upstreams     []PeerConf        // resolved addr:port tuples; RUNTIME ONLY
  // (Upstream string is removed)

ZoneRefresher:
  PrimariesConf []PeerConf        // AS-WRITTEN; copied to zd.PrimariesConf on merge
  Primaries     []PeerConf        // RESOLVED; copied to zd.Upstreams on merge

DynamicZoneInput.Primaries []PeerConf
ZonePost.Primaries        []PeerConf

RefreshCounter:                   // Upstream + Notify fields DELETED (dead)
```

**`ZoneRefresher` carries BOTH forms** — the as-written `PrimariesConf` and the
resolved `Primaries` — because both must reach `ZoneData`: the as-written form to
persist, the resolved form to transfer. A refresher with only the resolved list
would leave `zd.PrimariesConf` with no source (and P5 persistence nothing to write).

**Merge rule (refreshengine):**
- `len(zr.PrimariesConf) > 0` (config load / reload / dynamic add+modify): set
  `zd.PrimariesConf = zr.PrimariesConf` **and** `zd.Upstreams = zr.Primaries`.
- `len(zr.PrimariesConf) == 0` (NOTIFY-triggered refresh — minimal refresher):
  **preserve both** `zd.PrimariesConf` and `zd.Upstreams` (do not blank them).

Flow: `primaries: [{foo.bar:53, K}]` → parse-time `resolvePrimaries` →
`zr.PrimariesConf = [{foo.bar:53,K}]`, `zr.Primaries = [{1.2.3.4:53,K},{[2001::53]:53,K}]`
→ merge sets `zd.PrimariesConf` (persisted) + `zd.Upstreams` (transferred). Transfer
loop iterates `zd.Upstreams`; persistence writes `zd.PrimariesConf`.

## 6. Resolution helper

```go
// resolvePrimaries expands each as-written entry into one-or-more addr:port
// tuples, copying the per-entry key to each. A literal IP passes through
// unchanged (no lookup). Hostnames resolve via the in-process IMR (A then
// AAAA). Returns Resolved plus Unresolved (entries that produced NO address)
// plus KeyCollisions (for the ConfigWarning / ConfigError decision).
func resolvePrimaries(ctx context.Context, imr *Imr, primaries []PeerConf) PrimaryResolveResult
```

- Split `host:port` (default `:53`). If `net.ParseIP(host) != nil` → emit
  `{host:port, key}` unchanged (literal IP, never queried).
- Else resolve through the IMR: `imr.DefaultRRsetFetcher(ctx, fqdn, A)` and
  `… AAAA`, collect the addresses **v4 first**, emit `{addr:port, key}` per
  result. A name that resolves to nothing (lookup error, empty, or no IMR
  available) is appended to `Unresolved`. A 10s per-entry timeout bounds startup.
- **Dedup** the resolved tuples on `addr:port`, keeping the first occurrence (so
  v4-first ordering and the first-seen key survive). If a later duplicate carries a
  **different key** than the kept one, drop it and record it for a `ConfigWarning`
  (the `(addr, differing-key)` ambiguity, §3.1 — inert under all-`NOKEY`).
- Caller decision: `len(resolved) == 0` → `ConfigError` (quarantine). `len(resolved)
  > 0 && (len(unresolved) > 0 || key-collision)` → `ConfigWarning` (served).
  Otherwise clean.
- This helper is the single resolution chokepoint called from all five ingress
  paths (§3.1): `ParseZones`, `LoadDynamicZoneFiles`, `ProvisionDynamicZone`,
  `ModifyDynamicZone`, and catalog auto-config (on the catalog scalar).

## 7. Transfer fallback (the behaviour fix) — revised 2026-06-28

Both `DoTransfer` (SOA) and `FetchFromUpstream` (AXFR) loop over `zd.Upstreams`,
but the **stop condition differs** because multiple primaries are independent
servers (per-primary ACLs differ), so a refusal from one is not a refusal from
all. There is **no `isTransportError` distinction** — that idea was dropped (it
wrongly treated a REFUSED as "honour, don't retry," which defeats redundancy).

**AXFR** (`FetchFromUpstream`) — retry on *any* failure:

```
for _, up := range zd.Upstreams:
    new_zd = fresh ZoneData                 // per-attempt, so a failed try can't pollute
    err = new_zd.ZoneTransferIn(up.Addr, …) // transport err, REFUSED/NOTAUTH rcode, or bad data
    if err != nil: record err; continue     // a sibling may still serve us
    success; break
if !transferred: return all-failed-error    // every primary failed
```

**SOA probe** (`DoTransfer`) — advance until a *usable* SOA:

```
sawResponse = false
for _, up := range zd.Upstreams:
    r, err = dns.Exchange(SOA, up.Addr)
    if err != nil: record err; continue            // transport: try next
    sawResponse = true
    if NOERROR && answer[0] is SOA: return decision(serial)   // usable → stop
    else: continue                                 // REFUSED/SERVFAIL/NXDOMAIN/empty → try next
if sawResponse: return false, 0, nil               // all answered, none usable → quiet back-off
return all-unreachable-error                        // nobody answered
```

- `dns.Exchange` returns `err != nil` only for transport failures; any DNS
  response (incl. REFUSED) is `(*dns.Msg, nil)`. So `err != nil` → next address;
  a response is inspected for a usable SOA, else we move on.
- AXFR transport failure can surface at `transfer.In` or as an `envelope.Error`
  mid-stream; both come back as the `ZoneTransferIn` error, so both retry.
  `zd.Data` is reset at the start of each `ZoneTransferIn` (dnsutils.go:68-71) and
  `new_zd` is rebuilt per attempt, so a partial/failed transfer cannot pollute the
  next try **or** the live zone — `zd.IncomingSerial` is only updated in the hard
  flip, after a success.
- `clarifyXfrError` already names the **address that failed** (per-attempt) — it
  is passed the current `up.Addr` each iteration.

## 8. `ConfigWarning` error type

Add a visibility-only warning, mirroring `DelegationSyncWarning`:
- `enums.go` const block — add `ConfigWarning` after `DelegationSyncWarning`.
- `ErrorTypeToString` — `ConfigWarning: "config-warning"`.
- `errorTypeReportOrder` — append (low severity).
- **NOT** added to `serviceImpactingErrors` / rollover gating sets — omission =
  the zone keeps serving. This is the established pattern for the `*Warning` types.

Partial-resolution → `SetError(ConfigWarning, "primary %q did not resolve (serving
from N of M)", …)`. Zero → `SetError(ConfigError, …)` (existing, service-impacting).

## 9. Phased plan

Each phase: code → `cd tdns/cmdv2 && GOROOT=/opt/local/lib/go make` → `go test
-race` → update this doc's phase status → show diff → wait for OK → commit + push.
Risk graded as `probability × consequence` (see the dynamic-zones doc §7 for the
model).

| Phase | Scope | ~LOC | Prob | Conseq | Risk |
|---|---|---|---|---|---|
| **P1** | `ConfigWarning` enum (4 edits) + `resolvePrimaries` helper (incl. dedup) + unit test | ~80 | Low | Low | **Low** |
| **P2** | Struct migration `Primary`→`Primaries`/`PrimariesConf`/`Upstreams`; delete dead `RefreshCounter` fields; all mechanical rename sites (A/C/F/G non-transfer) | ~120 | Low | Low | **Low** (compiler-guided; tree won't build until complete) |
| **P3** | Resolution on **all five ingress paths**: parseconfig secondary-zone block (per-element Legacy/empty/key loops + resolve + ConfigWarning/ConfigError), `LoadDynamicZoneFiles`, **`ProvisionDynamicZone` + `ModifyDynamicZone`**, **catalog auto-config scalar (J)**; **`ZoneRefresher` carries both `PrimariesConf` (as-written) + `Primaries` (resolved); refreshengine merge sets `zd.PrimariesConf` + `zd.Upstreams` when `len(zr.PrimariesConf) > 0`, preserves both when empty (NOTIFY)** | ~130 | Med | Med | **Med** — resolution logic + partial-fail semantics + the both-fields merge/NOTIFY-preservation guard |
| **P4** | Transfer fallback loops in `DoTransfer` + `FetchFromUpstream`: AXFR retries on ANY failure (incl. REFUSED — per-primary ACLs differ); SOA advances until a usable answer; per-attempt error messages (`clarifyXfrError` names the failed address); fresh `new_zd` per attempt keeps a failed try from corrupting `IncomingSerial` | ~90 | Med | Med | **Med** — the actual bug fix; the stop-condition (which failures retry vs honour) is the subtle part |
| **P5** | Persistence: `zoneDataToZoneConf` writes **`PrimariesConf` with per-entry keys** (as-written, NOT resolved, NOT hardcoded `NOKEY`); round-trip test asserts hostname + key survive and re-resolve on reload | ~35 | Low | Med | **Low–Med** — must persist as-written *with keys* |
| **P6** | API/CLI: `--primaries` comma-list (one key for all), `RunZoneAdd/Modify` build `[]PeerConf`, **list-zones / list-dynamic render the as-written `PrimariesConf` list (the hostnames the operator wrote, not resolved addresses) + surface `config-warning`**; migrate `*.sample.yaml` `primary:`→`primaries:` | ~80 | Low | Low | **Low** |

**Total ~515 LOC.** P1+P2 land together (foundation); P5+P6 together (surface) —
so ~4 review checkpoints. (Up from ~460 after the plan-review amendments folded in
catalog, the extra resolution call sites, persist-with-keys, and the NOTIFY guard.)

## 10. Tests

- **P1:** `resolvePrimaries` — literal IP passthrough (no lookup); a hostname
  expands to its addresses with v4 before v6 and the key copied to each; an entry
  that doesn't resolve lands in `unresolved`; port is preserved; **dedup** collapses
  a repeated `addr:port` (keeping first); a `(addr, differing-key)` duplicate is
  dropped + flagged.
- **P3:** parse a zone with a bad-resolving + good-resolving primary → zone served,
  `ConfigWarning` set, `Upstreams` holds the good addresses. Parse a zone whose only
  primary doesn't resolve → `ConfigError`, quarantined, server still starts. Empty
  `primaries: []` on a secondary → `ConfigError`. A legacy bare-string element in
  `primaries:` → that zone ERROR (per-element). **`zone add` with a hostname primary
  resolves at add time** (not only on the next restart). **A NOTIFY-triggered refresh
  (minimal `ZoneRefresher`, no primaries) does NOT blank `zd.Upstreams`.** **A
  catalog member with a hostname upstream expands to multiple addresses.**
- **P4:** transfer fallback (`transfer_fallback_test.go`, SOA path with a real
  UDP test server) — first address gives a transport error (closed port), second
  succeeds → probe succeeds; **a REFUSED from the first primary advances to the
  second** (the bug fix: per-primary ACLs differ, so REFUSED must not terminate);
  every primary REFUSED → quiet back-off (no transfer, no error); all unreachable
  → error; no-upstreams → error (both `DoTransfer` and `FetchFromUpstream`). The
  AXFR loop shares the iteration pattern; a full AXFR test server is deferred.
- **P5** (`TestZoneDataToZoneConf_PersistsAsWrittenPrimaries`): `zoneDataToZoneConf`
  on a zone whose as-written primary is a **hostname with a non-NOKEY key** and
  whose resolved `Upstreams` are addresses → the persisted `Primaries` is the
  **hostname + key**, NOT the resolved addresses and NOT forced `NOKEY`. Tested at
  the serialization level (`ProvisionDynamicZone` rejects non-NOKEY keys in
  Improvement 1); persisting the hostname is what lets reload re-resolve it.
- **P6** (`TestSampleZonesConfigDecodes`, `TestSampleTemplatesConfigIsValidYAML`):
  the shipped `*.sample.yaml` are migrated to `primaries:`/`notify:` struct lists
  and decode with no Legacy markers. CLI: `--primaries` is a comma-list building a
  `[]PeerConf` (one `--primary-key` applied to all); `list-zones`/`list-dynamic`
  render the as-written `primaries` list and surface `config-warning` *distinctly*
  from service-impacting errors — a warning zone stays a normal row with an
  annotation (via the new exported `ErrorTypeIsServiceImpacting`), not an ERROR row,
  and `list-dynamic` now carries the zone's error/warning state.

## 11. Verify-before-coding (not blockers — confirm at implementation time)

- **Stop condition (resolved 2026-06-28):** AXFR retries on *every* failure, so
  no transport-vs-DNS error classification is needed. The SOA probe only needs
  `dns.Exchange`'s clean split (`err != nil` ⟺ transport failure; any DNS response
  is `(*dns.Msg, nil)`), which holds for the vendored dialer. The earlier
  `isTransportError` helper was dropped.
- **IXFR:** production refresh hardcodes `"axfr"` (FetchFromUpstream,
  zone_utils.go:234); the loop applies to AXFR. IXFR, when wired, uses the same
  loop via `ZoneTransferIn`.
- **Sample-config cutover (done in P6):** hard cutover — a bare-string or
  `primary:`-keyed entry goes to ERROR; operators migrate to `primaries:` (a list
  of `{addr, key}`). The shipped `*.sample.yaml` were migrated, **and their
  bare-string `notify:` entries too** — those were a leftover from the B0
  PeerConf migration and would have quarantined the example zones; the same
  struct form fixes both. `TestSampleZonesConfigDecodes` is a regression guard so
  the samples can't silently rot out of struct-sync again.

  **Operator upgrade note:** any existing config using `primary: "ip:port"` (or a
  bare-string `notify:`) must change to the list-of-`{addr, key}` form, e.g.
  `primaries:\n  - addr: "ip:port"\n    key: NOKEY`.
