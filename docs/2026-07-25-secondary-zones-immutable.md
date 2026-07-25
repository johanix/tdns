# Secondary zones are immutable — MUST-NOT-MODIFY invariant + audit

**Date:** 2026-07-25
**Status:** PROPOSED — design agreed in discussion; this doc records the
mutation-vector audit that validates the fix surface. Not implemented.
**Origin:** surfaced while cooking the inbound-IXFR plan
(`2026-07-25-inbound-ixfr-plan.md`). A confirmed serial-bump bug on secondaries
turned out to be one instance of a whole missing invariant. This is a
**prerequisite** for inbound IXFR (which needs a correct outbound/inbound
serial-space contract), but stands on its own as a correctness fix.
**Base:** main @ 138c9ce / 78a83ff.

---

## 1. The invariant

A **secondary** serves a copy of a zone whose authoritative source is upstream.
The absolute rule is **MUST NOT MODIFY**: what a secondary serves — content
*and* SOA serial — must match what it received, so that multiple secondaries of
the same primary are interchangeable (redundancy, load-balancing, genetic
diversity across implementations).

The gating question is not "is this zone signed" — it is **"did *we* originate
this content?"** Signing is just one origination vector. The one sanctioned
exception is a **signing secondary** (`inline-signing`): it deliberately
transforms upstream content by adding locally-generated RRSIGs, so its content —
and therefore its serial — legitimately diverges from upstream. Everything else
a secondary might do to its own content is a bug.

**The predicate:** within tdns-auth, `zoneMayOriginateContent(zd) = (ZoneType ==
Primary) || Options[OptInlineSigning]`. This single notion drives all three
fixes below — but only under the app-scope in §1.1.

Motivating failure (real): a signed zone distributed by two masters downstream
of the signer — one BIND9 (no serial bump), one tdns-auth (bumps +1 per
refresh). Edge nodes NOTIFY'd by both always see a higher serial from tdns and
so *always* fetch from tdns, silently collapsing the redundant pair. Not
acceptable.

## 1.1 Scope: tdns-auth ONLY (this is the load-bearing constraint)

This invariant is about **tdns-auth**, in its Primary and Secondary roles, and
**nothing else**. `v2/` is a shared library that other apps build on
(`Globals.App.Type` is one of a partitioned enum — core tdns 1–16 incl.
`AppTypeAuth`/`AppTypeAgent`; tdns-mp 17–32; tdns-nm 33–48; tdns-es 49–64), so a
naive change here would silently reach every derived app the next time it bumps
its tdns pin. That must not happen: several derived apps **deliberately** mutate
a zone while holding the Secondary role, for good reasons —

- **tdns-mpcombiner** makes select edits to a zone despite being a Secondary
  (that is its whole job);
- **tdns-mpagent** has its own special permissions;
- **tdns-agent** already carries Secondary special-cases in this very code
  (`Globals.App.Type != AppTypeAgent` guards in `zone_utils.go`/`refreshengine.go`).

Therefore **all three fixes below are conditioned on
`Globals.App.Type == AppTypeAuth`**. On any other app type they are complete
no-ops — the option normalizer changes nothing, the serial keeps its existing
behavior, the API gate refuses nothing — so those apps' own, deliberately
different, mutation rules are preserved unchanged. The invariant is
"a *tdns-auth* secondary must not modify," not "a secondary must not modify."

## 2. The audit — every mutation vector, classified

Method: enumerate every call site that stages content and publishes, advances
the SOA serial, or stores a snapshot (`publishWorkingSetLocked`, `publishLocked`,
`publishSync`, `publishNow`, `runPublisher`, `BumpSerial(Only)`, `snapshot.Store`,
`nextOutboundSerial`, `CurrentSerial = / ++`), then trace each to the *source*
that triggers it and the condition that enables it.

The publish calls themselves are generic chokepoints — they publish whatever was
staged. What matters is the **source** and its **enabler**:

| # | Mutation source | Enabler today | Fires on a pure secondary? | Handled by |
|---|---|---|---|---|
| 1 | **Refresh serial bump** — `applyRefreshReplacementLocked` non-first-load does `CurrentSerial++` unconditionally | *nothing* — role/option-independent | **YES — the bug.** Even a zero-option secondary bumps +1 per refresh | **Fix A** (serial mirror) |
| 2 | **DDNS** (RFC 2136 UPDATE) | `OptAllowUpdates` / `OptAllowChildUpdates` ([updateresponder.go](../v2/updateresponder.go)) | only if option set (no role check; config doesn't reject it) | **Fix B** (normalizer off) |
| 3 | **Transport signals** — `CreateTransportSignalRRs` → commit/publish ([tsignal.go](../v2/tsignal.go), refresh postpass, `RepopulateDynamicRRs`) | `OptAddTransportSignal` | only if option set | **Fix B** |
| 4 | **Delegation sync — zone-publishing parts** — SIG(0) **KEY** (`Sig0KeyPreparation`), **CSYNC** (`SyncZoneDelegationViaNotify`) | each gated on `OptAllowUpdates`; parent-side child-apply on `OptAllowChildUpdates` | no — those options are already off (turned off as #2) | **Fix B, via #2** (no separate delsync gate) |
| 4b | Delegation sync — **CDS** publish (`PublishCdsRRs`, InternalUpdate, bypasses allow-updates) | `OptDelSyncChild` | no — `SynthesizeCdsRRs` is empty ⇒ no-op without local DNSKEYs; sanctioned on a signing secondary | n/a (no-op) |
| 4c | Delegation sync — **sending** (bootstrap KEY to parent, NOTIFY, UPDATE) | `OptDelSyncParent`/`OptDelSyncChild` | sends outward; **does not mutate the served zone** | out of scope (§4 note) |
| 5 | **DNSSEC signing / KSK-ZSK rollover / resign** ([sign.go](../v2/sign.go), ksk_rollover_*, resign engine) | `OptOnlineSigning`/`OptInlineSigning` **and** `SetupZoneSigning`'s role gate: a non-primary signs *only* with `inline-signing` | only if `inline-signing` — the **sanctioned** signing secondary | **kept** (the exception); Fix A treats it as an originator |
| 6 | **Catalog *consumption*** — auto-create/delete **member** zones from a catalog ([catalog.go:270](../v2/catalog.go), [apihandler_catalog.go:330](../v2/apihandler_catalog.go)) | `OptCatalogMemberAutoCreate`/`Delete` | yes — and **desired**: it provisions *other* zones, never mutates the catalog zone (RFC 9432; the whole point) | **allow, no gating** (§4) |
| 6b | **Catalog *authoring*** — `version.<catalog>` TXT injection / in-catalog member mgmt (`CreateCatalogZone`, [apihandler_catalog.go](../v2/apihandler_catalog.go)) | reached only via the author/create path | no — that path is primary-of-catalog by construction; a secondary catalog is created via AXFR, never `CreateCatalogZone` | n/a (not reachable for a secondary) |
| 7 | **API `bump`** — two external entry points: the zone handler ([apihandler_zone.go:70](../v2/apihandler_zone.go)) and the refresh-engine `bumpch` handler ([refreshengine.go:880](../v2/refreshengine.go)) | *none* — no role check at either | **YES** | **Fix C** (origination gate) |
| 8 | **Other API origination actions** — `sign-zone`, `resign-zone`, `policy-set`/`change-policy`, `generate-nsec` | none role-aware | **YES** | **Fix C** |
| 9 | **JWK / A-AAAA / TLSA publication** ([ops_jwk.go](../v2/ops_jwk.go), ops_a_aaaa, ops_tlsa; InternalUpdate) | tied to transport-signal / signing / agent-role features | only via those features (should be off) | **Fix B** (via §5 confirmation) |
| — | Primary file load (`ParseZoneFromReader`), secondary AXFR-in serial (`ZoneTransferIn` → new_zd), `InstallInitialSnapshot` re-baseline | role-correct by construction | n/a | no change |

**Conclusion:** exactly one mutation vector is role/option-independent — the
refresh serial bump (#1). Every other origination path is **option-gated**, so
forcing the origination options off at parse time (Fix B) neutralizes them
through the *existing* runtime gates, with no new per-feature runtime checks. The
two explicit-action vectors (#7/#8) are neither option nor role gated and need an
API-side gate (Fix C). Signing (#5) is already role-aware and is the one
sanctioned exception.

The scariest case — SIG(0) KEY publication being **default-on** (opt-out) — is
safe only because it is reached solely through the delegation-sync setup, which
*is* delsync-option-gated; turning those options off for a secondary stops it.

## 3. The fix — one predicate, three homes (no sprinkling)

**Every fix below first checks `Globals.App.Type == AppTypeAuth` and is a no-op
otherwise** (§1.1). The signatures/call sites take `appType` into account so the
shared library's behavior for tdns-agent, tdns-mpcombiner, tdns-mpagent, etc. is
byte-for-byte unchanged.

1. **Option normalizer (Fix B)** — a single `normalizeOptionsForRole(appType,
   zonetype, opts) → (opts, softErr)` that, **for AppTypeAuth only**, and for a
   non-`inline-signing` secondary, turns
   **off** the origination options (§4) and records a **soft** `SetError` so the
   operator sees the misconfig while the zone keeps serving. Verified soft:
   `SetError` only writes the error registry + derived fields; it does **not**
   touch `Status`, and serving gates on `GetStatus() != Ready`
   ([dnsutils.go:265](../v2/dnsutils.go)), not on the registry. Because every
   runtime path already gates on its option, turning off just three options
   (`allow-updates`, `allow-child-updates`, `add-transport-signal`) neutralizes
   vectors 2 and 3 directly, and vector 4's zone-publishing parts fall out for
   free (they are themselves gated on `allow-updates`/`allow-child-updates`).
   Vector 6 (catalog) is deliberately left ON, and vector 9 is covered by its
   feature options. All with zero new runtime gates.
   - Must be invoked from **every** option-finalization site, not just the
     static parser: [parseconfig.go](../v2/parseconfig.go) (static + reload),
     dynamic-zone add ([dynamic_zones.go](../v2/dynamic_zones.go)), dynamic
     primary, catalog auto-create, and the template-expansion union — else an
     API/catalog-created secondary bypasses the gate.
   - Recompute each parse: `ClearError` when the config is now clean, `SetError`
     when not, using a dedicated message/`ErrorType` so it doesn't collide with
     other `ConfigError`s (fixing the YAML clears the flag on reload).

2. **Refresh serial mirror (Fix A)** — in `applyRefreshReplacementLocked`,
   replace the unconditional non-first `CurrentSerial++` with:
   `(AppType==Auth && !mayOriginate) ? CurrentSerial = new_zd.IncomingSerial :
   CurrentSerial++`. A tdns-auth pure secondary mirrors the upstream serial
   verbatim; a primary, an inline-signing secondary, **or any non-auth app**
   advances exactly as today. **This is not option-driven and is NOT covered by
   Fix B** — it must land regardless. Also gate the refresh-engine
   `unixtime`/`persist` overrides ([refreshengine.go](../v2/refreshengine.go)),
   under the same AppTypeAuth condition, so a tdns-auth pure secondary never
   rewrites the serial in *any* mode (MUST-NOT-MODIFY absolute, not just
   keep-mode). The `CurrentSerial++` default preserves current behavior for
   every non-auth app.

3. **API origination gate (Fix C)** — the zone API handler and the `bumpch`
   handler consult the same predicate and, **when `Globals.App.Type ==
   AppTypeAuth`**, refuse the origination subset (`bump`, `sign-zone`,
   `resign-zone`, `policy-set`/`change-policy`, `generate-nsec`) for a secondary.
   Not a blanket secondary-refusal: `freeze`/`thaw`/`write-zone` are legitimate
   secondary ops (pause refresh, snapshot to disk) and stay allowed. On non-auth
   apps the gate is absent, so tdns-mp/agent API semantics are unchanged.

## 4. Option classification

**Turn OFF for a non-inline-signing secondary (origination):**
`allow-updates`, `allow-child-updates`, `add-transport-signal`.

**NOT gated here — `delegation-sync-parent` / `delegation-sync-child`.** These do
*not* need turning off for the mutation invariant, because the delegation-sync
operations that actually publish into the zone are themselves gated on
`allow-updates` / `allow-child-updates`, which are already off:
- child KEY publication (`Sig0KeyPreparation`) publishes only
  `if Options[OptAllowUpdates]` ([delegation_sync.go:302](../v2/delegation_sync.go));
- child CSYNC publication (`SyncZoneDelegationViaNotify`) likewise
  ([delegation_sync.go:521](../v2/delegation_sync.go));
- parent-side child-delegation apply goes through the CHILD-UPDATE path, gated on
  `allow-child-updates`;
- the one delsync publish that bypasses `allow-updates` (CDS via
  `PublishCdsRRs`, InternalUpdate) is a **no-op without local DNSKEYs**
  (`SynthesizeCdsRRs` → `len==0 → return nil`, [ops_cds.go:61](../v2/ops_cds.go)),
  so it does nothing on a non-signing secondary and is the sanctioned case on a
  signing one.

Everything else `delegation-sync-*` does is *send* (bootstrap the SIG(0) key to
the parent, NOTIFY, UPDATE) — outward signalling that does not touch the served
zone, hence outside this MUST-NOT-MODIFY invariant. (Whether a tdns-auth
*secondary* should be sending delegation-sync signals to a parent at all is a
separate, non-mutation question — arguably the primary's job — and is
deliberately **out of scope** here; flag as a possible future soft-warning, not
a gate in this doc.)

**Keep:**
- `inline-signing` — the sanctioned signing secondary (Fix A treats it as an
  originator so it may bump).
- **`catalog-zone`, `catalog-member-auto-create`, `catalog-member-auto-delete`
  — explicitly ALLOWED on a secondary.** These are NOT origination of the
  catalog zone's content. A tdns-auth secondary of a catalog zone mirrors the
  catalog verbatim (MUST-NOT-MODIFY still holds for the catalog zone itself) and
  then *consumes* it to auto-create / auto-delete the **member** zones it
  references ([catalog.go:270](../v2/catalog.go),
  [apihandler_catalog.go:330](../v2/apihandler_catalog.go)). That provisioning
  acts on *other* zones, never on the catalog zone — and it is the entire point
  of catalog zones (RFC 9432): a secondary that couldn't consume a catalog would
  make the feature pointless. The only in-catalog-zone mutation (the
  `version.<catalog>` TXT injection) lives solely on the `CreateCatalogZone`
  author path, which is a primary-of-catalog operation a secondary never runs,
  so it needs no gating for the secondary case.
- Serving-behavior options (`fold-case`, `black-lies`, minimal-responses, etc.)
  are unaffected.

`dont-publish-key`/`dont-publish-jwk` become moot once delsync is off (KEY/JWK
publication is only reached through delsync), so they need no special handling —
but stating that explicitly avoids a future "why isn't this gated" question.

## 5. Residuals to confirm at implementation

The audit classified every vector I could trace to a definite enabler. Two
low-risk items warrant a confirming glance during implementation rather than
being taken on faith:

- **JWK / A-AAAA / TLSA publication (#9):** tied to transport-signal / signing /
  agent-role features (all off for a pure auth secondary), but I did not trace
  every caller. Confirm none fires on a pure secondary.
- **`bumpch` vs handler bump:** confirm both external bump paths are gated (there
  may be effectively one).

(The delegation-sync question is resolved, not a residual: its zone-publishing
paths are gated on `allow-updates`/`allow-child-updates` — verified at
[delegation_sync.go:302/521](../v2/delegation_sync.go) — and the one bypassing
path, CDS, is a no-op without local DNSKEYs.)

None of these is expected to reveal a *fourth* unconditional vector; #1 (refresh
serial) remains the only role/option-independent mutation found.

## 6. Testing

- **Fix A (mutation-verified):** non-signing secondary, upstream serial jumps
  N→M across two refreshes → served serial == M (mirror), not prev+1; fails on
  current code, passes on the fix. Plus: signing (inline) secondary still
  advances; `unixtime`/`persist` on a pure secondary does not rewrite the serial.
- **Fix B:** a secondary configured with each origination option → option ends
  up off, soft `ConfigError` present, zone still `Ready`/served; reload with a
  clean config clears the error. Cover the dynamic-zone-add path too.
- **Catalog not regressed (the §4 correction):** a secondary catalog zone with
  `catalog-member-auto-create`/`-auto-delete` keeps those options ON and still
  provisions/deprovisions member zones from the catalog contents — no soft
  error, no gating. (Guards against re-introducing the mistake of treating
  catalog consumption as origination.)
- **Fix C:** `bump` (both entry points) and the other origination actions →
  refused for a secondary, allowed for a primary; `freeze`/`thaw`/`write-zone`
  still allowed for a secondary.
- **App-scope (the §1.1 guarantee, must be explicit):** with
  `Globals.App.Type != AppTypeAuth` (drive a test with, e.g., `AppTypeAgent`),
  a Secondary carrying origination options keeps them on, its serial advances
  exactly as before, and the API origination actions are not refused — proving
  all three gates are no-ops off tdns-auth so tdns-agent / tdns-mpcombiner /
  tdns-mpagent behavior is unchanged.
- Gate: full `v2` `-race`, gofmt, cmdv2 binaries build via gmake.

## 7. Relationship to other work

- **Prerequisite for inbound IXFR** (`2026-07-25-inbound-ixfr-plan.md`): the
  serial-space contract (served/outbound `CurrentSerial` vs upstream
  `IncomingSerial`) that IXFR-in's SOA handling depends on only makes sense once
  the secondary serial actually mirrors upstream. Land this first.
- Independent of the IXFR-out work already merged (#328).
- Suggested single PR `feature/secondary-zones-immutable`: normalizer (Fix B) +
  serial mirror (Fix A) + API gate (Fix C) + tests. Its own branch, landing
  ahead of inbound IXFR.
