# Secondary zones are immutable — MUST-NOT-MODIFY invariant + audit

**Date:** 2026-07-25, revised 2026-07-26 (rev 2, rev 2.1, rev 2.2 same day)
**Status:** PROPOSED — design agreed in discussion; rev 2 incorporates a
code-verified re-audit of every claim in rev 1. Not implemented.
**Origin:** surfaced while cooking the inbound-IXFR plan
(`2026-07-25-inbound-ixfr-plan.md`). A confirmed serial-bump bug on secondaries
turned out to be one instance of a whole missing invariant. This is a
**prerequisite** for inbound IXFR (which needs a correct outbound/inbound
serial-space contract), but stands on its own as a correctness fix.
**Base:** main @ 0536be8 (originally audited against 138c9ce / 78a83ff; the
`feature/secondary-zones-immutable` branch is forward-merged from main and
carries this doc).

---

## 0. What changed in rev 2

Rev 1's central conclusion — "exactly one mutation vector is role/option-
independent; every other origination path is option-gated, so forcing the
options off neutralizes them through the *existing* runtime gates" — does not
survive contact with the code. The first half is right. The second half is not,
because the existing gates sit at **call sites**, and the applier they feed
(`ZoneUpdater`) accepts anything flagged `InternalUpdate` regardless of options.

| # | Change | Why |
|---|---|---|
| 1 | **New vector: DSYNC publication** (`SetupZoneSync` → `PublishDsyncRRs`), gated on `delegation-sync-parent` alone | §4 of rev 1 concluded delsync needed no gating; DSYNC is the counterexample |
| 2 | **New vector: the `InternalUpdate` applier bypass** | Structural. `allow-updates` is a call-site convention, not an applier gate |
| 3 | **New vector: `resignWorkingSetSOAIfSigned` has no role gate** | Runs on *every* publish incl. the refresh path; `online-signing` on a secondary re-signs upstream content |
| 4 | **Corrected vector 6b: catalog authoring IS reachable via the API** | Rev 1 said "not reachable for a secondary". The catalog API handlers mutate the named zone with no role check |
| 5 | **New Fix D** — fail-closed gate in the ZoneUpdater applier | Enforcement moves to the chokepoint; option-stripping becomes visibility, not enforcement |
| 6 | **New Fix E** — role gate on `resignWorkingSetSOAIfSigned` | See 3 |
| 7 | **`delegation-sync-parent` added to the turn-off list** (now 4 options, was 3) | See 1 |
| 8 | **Fix A widened**: persist/unixtime suppression at six sites, not two | Rev 1 named only the refresh-engine overrides |
| 9 | **New: `outbound_soa_serial` becomes per-zone** (config schema change) | It is server-global today, so it cannot be role-scoped at config level at all |
| 10 | **Fix C widened**: second handler, catalog handler, `policy-reset`, freeze/thaw refusal + the missing `return`s | Rev 1's action list was short by several, and the guards it relied on don't return |
| 11 | **Migration section rewritten** — severity is per-serial-mode, not universal | In the default `keep` mode the backwards jump already happens at every restart today |
| 12 | **New: forced-transfer contract** | Force must apply whatever upstream has; today it works for a lower serial only incidentally, and no-ops on an equal one |
| 13 | **New: diagnostics** (`zone desc` / `zone list -v` serial visibility) | There is currently no way to see the split-brain that motivated this work |
| 14 | Residuals #9 and #2 **resolved** | Zero callers, and dead code, respectively |

**Rev 2.1 (2026-07-26, later the same day)** — closes §12 items 2, 3 and 5 after
a full `OptOnlineSigning` consumer survey (~40 sites):

- **`online-signing` joins the turn-off list (now five).** With local keys —
  the only keys tdns-auth has — it is unsafe and plain wrong on a secondary:
  two further role-ungated mutation vectors found (5c, 5d in §2), plus a
  response-path and an outbound-transfer failure mode. Fix E alone would make
  things *worse* (§3, Fix E). The legitimate form — signing at the edge with
  **distributed** keys — is the tdns-nm/tdns-es future and will most likely be
  a new app, which §1.1 already accommodates untouched.
- **Enforcement framing refined:** Fix D backstops only the UpdateQ class of
  publishers; for the direct-under-`zd.mu` class the normalizer *is* the
  enforcement (§2 conclusion).
- Item 3 decided: stale persisted serials are **cleared**. Item 5 decided:
  freeze/thaw `return`s land as a **separate commit in the same PR**.

**Rev 2.2 (2026-07-26)** — closes §12 item 1: per-zone `outbound_soa_serial`
is **folded into this PR** (own commit pair, first). The invasiveness scoping
showed ~120–180 lines + tests, not the feared doubling — template propagation
is free via `ExpandTemplate`'s generic gap-fill, the six read sites are lines
Fix A edits anyway, and the `OutgoingSerials` table is already per-zone.
Details in §5. Full implementation scope estimate added as §14: ~450–550
production LOC over ~14 files + ~1,200–1,600 test LOC, net ~+2,000/−200 in
9–10 commits.

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
Primary) || Options[OptInlineSigning]`. This single notion drives every fix
below — but only under the app-scope in §1.1.

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

Therefore **every fix below is conditioned on
`Globals.App.Type == AppTypeAuth`**. On any other app type they are complete
no-ops — the option normalizer changes nothing, the serial keeps its existing
behavior, the API gate refuses nothing, the applier gate drops nothing — so
those apps' own, deliberately different, mutation rules are preserved unchanged.
The invariant is "a *tdns-auth* secondary must not modify," not "a secondary
must not modify."

**A worked example of why this matters (rev 2).** A likely production shape is
that all DSYNC/keystate receivers live in a **tdns-agent**: the agent listens for
generalised NOTIFYs and UPDATEs, holds the receiver SIG(0) private key, and feeds
results into a database. It then emits "please insert these RRs into the zone at
the primary" — including the public half of its own SIG(0) key. Under §1.1 that
agent is `AppTypeAgent` and is untouched by everything here: it keeps its keys,
keeps processing keystate, keeps its own rules. The RRs it asks for enter the
parent zone **at the primary** and reach the secondaries by AXFR. That is
MUST-NOT-MODIFY working exactly as intended, and it is the reason the app-scope
constraint is not merely defensive bookkeeping.

**A second worked example (rev 2.1): the future edge signer.** Signing at a
secondary is not inherently wrong — with **distributed** keys (the correct keys
delivered to the edge, rather than locally minted ones) it is a legitimate
architecture, and it is exactly what the tdns-nm ("node manager") and tdns-es
("edge signer") projects are about (today mostly standalone; intended to
leverage tdns-transport like tdns-mp does, once the tdns-mp/tdns-transport
refactoring lands). When that project resumes it will most likely be a **new
app** — with its own AppType from the already-partitioned enum (nm 33–48 /
es 49–64 reserved) — and every gate in this doc is then automatically a no-op
for it, zero refactoring required. What §4 turns off is `online-signing` on
**tdns-auth**, whose only keys are local; the edge-signing future is
unaffected by construction.

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
| 1 | **Refresh serial bump** — `applyRefreshReplacementLocked` non-first-load does `CurrentSerial++` unconditionally ([zone_mutation.go:355](../v2/zone_mutation.go)) | *nothing* — role/option-independent | **YES — the bug.** Even a zero-option secondary bumps +1 per refresh | **Fix A** |
| 2 | **DDNS** (RFC 2136 UPDATE) | `OptAllowUpdates` / `OptAllowChildUpdates` ([updateresponder.go](../v2/updateresponder.go)) | only if option set (no role check; config doesn't reject it) | **Fix B** + **Fix D** |
| 3 | **Transport signals** — `CreateTransportSignalRRs` → commit/publish ([tsignal.go](../v2/tsignal.go), refresh postpass, `RepopulateDynamicRRs`, [signal_republish.go:149](../v2/signal_republish.go)) | `OptAddTransportSignal` | only if option set | **Fix B** + **Fix D** |
| 4 | **Delegation sync — child-side publishing** — SIG(0) **KEY** (`Sig0KeyPreparation`), **CSYNC** (`SyncZoneDelegationViaNotify`) | each gated on `OptAllowUpdates` ([delegation_sync.go:302](../v2/delegation_sync.go)); parent-side child-apply on `OptAllowChildUpdates` | no — those options are already off (turned off as #2) | **Fix B, via #2** + **Fix D** |
| 4b | Delegation sync — **CDS** publish (`PublishCdsRRs`, InternalUpdate) | `OptDelSyncChild` | no — `SynthesizeCdsRRs` is empty ⇒ no-op without local DNSKEYs; sanctioned on a signing secondary | n/a (no-op); passes **Fix D** via `mayOriginate` |
| 4c | Delegation sync — **sending** (bootstrap KEY to parent, NOTIFY, UPDATE) | `OptDelSyncParent`/`OptDelSyncChild` | sends outward; **does not mutate the served zone** | out of scope (§4 note) |
| **4d** | **Delegation sync — DSYNC publication** (`SetupZoneSync` → `PublishDsyncRRs`, [zone_utils.go:773](../v2/zone_utils.go), [ops_dsync.go:16](../v2/ops_dsync.go)) — publishes `_dsync.<zone>` DSYNC + address RRs via InternalUpdate | **`OptDelSyncParent` alone.** No `allow-updates` check. Unlike CDS it is **not** a no-op without local DNSKEYs — it synthesizes from `delegationsync.parent.schemes` | **YES** | **Fix B** (delsync-parent joins the turn-off list) + **Fix D** |
| 5 | **DNSSEC signing / KSK-ZSK rollover / resign** ([sign.go](../v2/sign.go), ksk_rollover_*, resign engine) | `OptOnlineSigning`/`OptInlineSigning` **and** `SetupZoneSigning`'s role gate: a non-primary signs *only* with `inline-signing` ([zone_utils.go:1107](../v2/zone_utils.go)) | only if `inline-signing` — the **sanctioned** signing secondary | **kept** (the exception); Fix A treats it as an originator |
| **5b** | **Per-publish SOA re-sign** — `resignWorkingSetSOAIfSigned` ([zone_mutation.go:186](../v2/zone_mutation.go)) re-signs the apex SOA inside `publishWorkingSetLocked`, i.e. on **every publish including the refresh path** | `OptOnlineSigning` or `OptInlineSigning` — **no role gate**, unlike #5. `EnsureActiveDnssecKeys` will *generate* keys if absent | **YES**, on a secondary carrying `online-signing` | **Fix B** (rev 2.1: option normalized off) + **Fix E** |
| **5c** | **DNSKEY injection on refresh (rev 2.1)** — `CollectDynamicRRs` ([zone_utils.go:894](../v2/zone_utils.go)) pulls local DNSKEYs from the keystore and repopulates them into the served zone after **every refresh** | `OptOnlineSigning` or `OptInlineSigning` (outer gate also admits `OptAllowUpdates`) — **no role gate** | **YES**, with `online-signing` | **Fix B** (rev 2.1). NOT Fix-D-covered: publishes via the refresh working set, not UpdateQ |
| **5d** | **Key-state-driven whole-zone re-sign (rev 2.1)** — `maintainStandbyKeys` / key-state transitions → `triggerResign` ([key_state_worker.go:405](../v2/key_state_worker.go)) → `ResignQ` → `resignNow` → `SignZone(force=true)` ([resigner.go:52](../v2/resigner.go)); `maintainStandbyKeys` also **mints standby KSKs/ZSKs** for every signing zone ([key_state_worker.go:267](../v2/key_state_worker.go)) | `OptOnlineSigning` or `OptInlineSigning` — key_state_worker.go, resigner.go and sign.go contain **zero** role checks; the only role gate is in `SetupZoneSigning` ([zone_utils.go:1107](../v2/zone_utils.go)), which is just one of **two** ResignQ senders | **YES**, with `online-signing` — the largest mutation vector in the audit: wholesale re-sign of upstream content with locally generated keys | **Fix B** (rev 2.1). NOT Fix-D-covered: `SignZone` publishes directly under `zd.mu` |
| 6 | **Catalog *consumption*** — auto-create/delete **member** zones from a catalog ([catalog.go:270](../v2/catalog.go), [apihandler_catalog.go:330](../v2/apihandler_catalog.go)) | `OptCatalogMemberAutoCreate`/`Delete` | yes — and **desired**: it provisions *other* zones, never mutates the catalog zone (RFC 9432; the whole point) | **allow, no gating** (§4) |
| **6b** | **Catalog *authoring* via the API** — `handleCatalogZoneAdd`/`Delete`/group add/remove → `regenerateCatalogZone` → `stageRRsetLocked` + `publishLocked` ([apihandler_catalog.go:541](../v2/apihandler_catalog.go)) | **none.** The handlers take a catalog zone name and mutate it; no role check anywhere on the path | **YES.** *(Rev 1 said "not reachable for a secondary" — that was wrong; only the `CreateCatalogZone` author path was considered)* | **Fix C** |
| 7 | **API `bump`** — the zone handler ([apihandler_zone.go:70](../v2/apihandler_zone.go)); the refresh-engine `bumpch` handler ([refreshengine.go:880](../v2/refreshengine.go)) is **dead code**, see §11 | *none* — no role check | **YES** | **Fix C** |
| 8 | **Other API origination actions** — `sign-zone`, `resign-zone`, `policy-set`, `change-policy`, **`policy-reset`**, `generate-nsec`; and in the *second* handler, **`publish-dsync-rrset` / `unpublish-dsync-rrset`** ([apihandler_zone.go:933](../v2/apihandler_zone.go)) | none role-aware | **YES** | **Fix C** |
| 9 | **JWK / A-AAAA / TLSA / SVCB / URI publication** ([ops_jwk.go](../v2/ops_jwk.go), ops_a_aaaa, ops_tlsa, ops_svcb, ops_uri) | — | **NO — resolved.** These have **zero callers** anywhere in tdns `v2/`+`cmdv2/`; they are library surface for the derived apps | n/a (cannot fire on tdns-auth) |
| **10** | **The `InternalUpdate` applier bypass** — [zone_updater.go:147](../v2/zone_updater.go): `if zd.Options[OptAllowUpdates]` **or** `ur.InternalUpdate`. **Every** `ops_*` publisher sets `InternalUpdate: true` (jwk, a_aaaa, dsync, key, uri, cds, tlsa, csync, svcb) as do ksk_rollover_ds_notify and signal_republish | *none at the applier.* `allow-updates` is a **call-site** convention only | **YES** — for any caller that doesn't self-gate (4d today; anything added tomorrow) | **Fix D** |
| — | **Child-delegation scanning** — `ScannerEngine` enqueues CHILD-UPDATE from CDS/CSYNC child scans ([scanner.go:192](../v2/scanner.go)) | `OptAllowChildUpdates`, enforced at the applier ([zone_updater.go:120](../v2/zone_updater.go)) | no | Fix B covers it — listed because it is an origination *source* independent of `delegation_sync.go`, i.e. evidence the table is a hand-enumeration, not a call-graph closure |
| — | Primary file load (`ParseZoneFromReader`), secondary AXFR-in serial (`ZoneTransferIn` → new_zd), `InstallInitialSnapshot` re-baseline | role-correct by construction | n/a | no change |

**Conclusion (revised).** Exactly one mutation vector is role/option-independent
— the refresh serial bump (#1). But the rev-1 corollary is withdrawn: the other
origination paths are gated at their **call sites**, and the applier they feed
accepts anything marked `InternalUpdate` (#10). Option-stripping therefore
neutralizes only those callers that happen to check their option first. Vector
4d is the proof: the audit checked the `delegation_sync.go` call sites and got
them right, and DSYNC still slipped through because it is reached from
`SetupZoneSync` instead. **Enforcement belongs at the applier (Fix D); option
normalization (Fix B) is the operator-facing visibility layer.**

**Rev 2.1 refinement:** that division of labour holds only for the **UpdateQ
class** of publishers. A second class publishes **directly under `zd.mu`** and
never touches `UpdateQ` — `SignZone` ([sign.go:790](../v2/sign.go)),
`PublishDnskeyRRs` ([ops_dnskey.go:26](../v2/ops_dnskey.go)),
`CollectDynamicRRs` (via the refresh working set) — so Fix D cannot backstop
it. For that class there is no applier chokepoint and **the option normalizer
is itself the enforcement**, which is why the turn-off list must be right
(five options, §4) and why Fix E exists as defence in depth.

## 3. The fixes — one predicate, five homes

**Every fix below first checks `Globals.App.Type == AppTypeAuth` and is a no-op
otherwise** (§1.1). Signatures and call sites take `appType` into account so the
shared library's behavior for tdns-agent, tdns-mpcombiner, tdns-mpagent, etc. is
byte-for-byte unchanged.

### Fix A — refresh serial mirror + outbound-mode suppression

In `applyRefreshReplacementLocked`, replace the unconditional non-first
`CurrentSerial++` with `(AppType==Auth && !mayOriginate) ? CurrentSerial =
new_zd.IncomingSerial : CurrentSerial++`. A tdns-auth pure secondary mirrors the
upstream serial verbatim; a primary, an inline-signing secondary, **or any
non-auth app** advances exactly as today. **Not option-driven, NOT covered by
Fix B — it must land regardless.**

**Widened in rev 2.** MUST-NOT-MODIFY is absolute, not keep-mode-only, so the
`unixtime`/`persist` machinery must not touch a tdns-auth pure secondary's serial
in *any* mode. That is **six sites**, not the two rev 1 named:

| | Site | Action |
|---|---|---|
| write | [zone_mutation.go:336](../v2/zone_mutation.go) (`publishWorkingSetLocked`) | skip `SaveOutgoingSerial` |
| write | [zone_mutation.go:356](../v2/zone_mutation.go) (`applyRefreshReplacementLocked`) | skip `SaveOutgoingSerial` |
| restore | [refreshengine.go:133](../v2/refreshengine.go) (initial load) | skip `LoadOutgoingSerial` restore |
| restore | [refreshengine.go:799](../v2/refreshengine.go) (post-refresh) | skip `LoadOutgoingSerial` restore |
| unixtime | [refreshengine.go:123](../v2/refreshengine.go) and [:790](../v2/refreshengine.go) | skip the override |
| unixtime | `nextOutboundSerial` unixtime branch ([zone_utils.go:682](../v2/zone_utils.go)) | skip |

Additionally, **clear** any stale persisted row for a zone that is a tdns-auth
secondary rather than leaving it inert-but-present — otherwise the inflated
legacy value sits in the KeyDB waiting for a future relaxation of one of these
gates to resurrect it.

### Fix B — option normalizer (visibility layer)

A single `normalizeOptionsForRole(appType, zonetype, opts) → (opts, softErr)`
that, **for AppTypeAuth only**, and for a non-`inline-signing` secondary, turns
**off** the origination options (§4) and records a **soft** error so the operator
sees the misconfig while the zone keeps serving.

**Rev 2.2 note:** the normalizer's duty extends beyond `ZoneOption`s — the §5
per-zone `OutboundSoaSerial` field is a string, not an option, so an explicit
`persist`/`unixtime` on a secondary is warned-about-and-cleared either by
widening this signature to take the serial mode too, or by a sibling helper
invoked from the same call sites. Implementer's choice; the invariant is that
every call site below covers both.

Rev 2 changes:

- **Five options, not three** — rev 2 added `delegation-sync-parent`; rev 2.1
  adds `online-signing` after the full consumer survey. See §4.
- **Use `ConfigWarning`, not `ConfigError`.** Rev 1 verified that `SetError`
  does not touch `Status` — correct — but `ConfigError` is in
  `serviceImpactingErrors` ([enums.go:348](../v2/enums.go)), documented as "a
  NOTIFY/UPDATE/query handler should refuse with SERVFAIL". Today only the CLI
  reads that, so it is display-only; the moment anyone wires up the documented
  intent, every secondary with a stray `allow-updates` starts SERVFAILing. Use
  `ConfigWarning` (the existing non-fatal precedent,
  [dynamic_zones.go:936](../v2/dynamic_zones.go)) or a new non-service-impacting
  type. Note `zoneProvisioning` renders any `zd.Error` as `"error"`, so a
  service-impacting choice also parks these zones permanently in the error column
  of `zone list`.
- **Message wording is part of the fix.** The normalizer warning, the Fix C
  refusal and the Fix D log line must all name the same reason — origination on
  a secondary — so an operator gets one story from three places rather than three
  unrelated denials. For `online-signing` specifically, the warning should
  additionally suggest `inline-signing` as the almost-certainly intended option.

**Call sites (revised — rev 1's list was incomplete and the wrong shape):**

- [parseconfig.go:904](../v2/parseconfig.go) (static + reload) — see the ordering
  constraint in §6.
- **`ModifyDynamicZone` ([dynamic_zones.go:1029](../v2/dynamic_zones.go))** — not
  named in rev 1, and the most dangerous omission: secondary-only, API-driven,
  builds a fresh options map, `Zones.Set` directly. Without it,
  `zone modify --options allow-updates` re-enables exactly what was stripped.
- `ProvisionDynamicZone` ([dynamic_zones.go:805](../v2/dynamic_zones.go)) and the
  dynamic-primary path.
- Catalog auto-create, and the template-expansion union.
- **The refresher chokepoint** — all three live-option assignments are
  `zd.Options = zr.Options` in the refresh-engine refresher handler
  ([refreshengine.go:282](../v2/refreshengine.go),
  [:391](../v2/refreshengine.go), [:608](../v2/refreshengine.go)). Normalizing
  here covers far more than enumerating callers. **Caveat:** `ZoneType` is
  late-bound at [refreshengine.go:398](../v2/refreshengine.go)
  (`if zr.ZoneType != 0`), so normalization must run on the *effective* type after
  that assignment — and must handle a Primary→Secondary flip on reload, which rev
  1 did not consider.

**Note the API path is a second parser, not merely another call site.**
`zone add`/`zone modify` build options via `zoneOptionsFromStrings`
([apihandler_zone.go:427](../v2/apihandler_zone.go)), which bypasses
`parseZoneOptions` entirely — no dependency validation, no error recording. Any
discipline that lives only in `parseZoneOptions` does not apply to API-created
zones.

### Fix C — API origination gate

The zone API handler, the **second** zone handler, and the **catalog** handler
consult the predicate and, **when `Globals.App.Type == AppTypeAuth`**, refuse
origination for a secondary.

Refused subset:

- Handler 1: `bump`, `sign-zone`, `resign-zone`, `policy-set`, `change-policy`,
  **`policy-reset`**, `generate-nsec`.
- Handler 2: **`publish-dsync-rrset`, `unpublish-dsync-rrset`**
  ([apihandler_zone.go:933](../v2/apihandler_zone.go)).
- Catalog handler: the four **authoring** entry points that reach
  `regenerateCatalogZone`
  ([apihandler_catalog.go:285/320/437/461](../v2/apihandler_catalog.go)).
  Catalog *consumption* stays fully enabled — see §4.
- **`freeze` / `thaw`** — see below.
- `write-zone` stays **allowed**: [zone_utils.go:374](../v2/zone_utils.go) depends
  only on `OptDirty`/`force`, no option coupling, and dumping a transferred zone
  to disk is a legitimate secondary operation.

**freeze/thaw (rev 2 correction).** Rev 1 listed these as legitimate secondary
ops that "stay allowed", on the rationale that freeze pauses refresh. It does
not: `OptFrozen` is consumed in exactly one place,
[updateresponder.go:194](../v2/updateresponder.go) — it gates DDNS and nothing
else. On a tdns-auth secondary, where `allow-updates` is always off after Fix B,
it is functionally inert. **Refuse both.**

Doing so requires fixing a pre-existing bug in the same handler: the `freeze`
and `thaw` precondition checks set `resp.Error = true` **but never `return`**
([apihandler_zone.go:146-176](../v2/apihandler_zone.go)). Execution falls through
to `zd.SetOption(OptFrozen, …)` and then overwrites `resp.Msg` with a success
string, so the caller receives `Error: true` *and* "Zone X is now frozen", with
the state changed anyway. Adding the `return`s is safe — the handler's deferred
JSON encoder still writes the response, and it is the pattern the other cases
already use. This is a behaviour change on the **primary** path too (freeze on a
primary without `allow-updates` currently freezes anyway; afterwards it genuinely
refuses) and belongs in the PR description. No idempotency regression: the
"already frozen" case already returned `Error: true`.

**Ordering within the handler:** the role refusal must come **before** the
`allow-updates` precondition. After Fix B a tdns-auth secondary always has
`allow-updates` off, so the generic "does not allow updates" message would fire
first and send the operator to enable an option the normalizer will immediately
strip again.

### Fix D — fail-closed applier gate (NEW, and the structural one)

**Placement:** [zone_updater.go:88-93](../v2/zone_updater.go), immediately after
`zd` is resolved and before the command switch. One place, not per-case.

**Scope:** `ZONE-UPDATE` and `CHILD-UPDATE` only. `TRUSTSTORE-UPDATE` must pass
through untouched — it writes the keystore via `TruststorePost`, never zone
content. `DEFERRED-UPDATE` already errors out; `PING` is handled before `zd` is
resolved.

**Rule:** for `AppTypeAuth && !mayOriginate(zd)`, drop the request and do not
apply. Every other app type and every primary: unchanged, byte-for-byte.

**Predicate:** `mayOriginate` (Primary or inline-signing) — the same predicate as
everything else, no new concept. This is load-bearing: an inline-signing secondary
legitimately publishes CDS ([ops_cds.go:82](../v2/ops_cds.go)) and CSYNC
([ops_csync.go:29](../v2/ops_csync.go)) through this path, and `mayOriginate` lets
it through.

**Why this cannot break signing:** DNSSEC signing does **not** traverse the
applier. `PublishDnskeyRRs` ([ops_dnskey.go:26](../v2/ops_dnskey.go)) stages
directly under `zd.mu` behind its own gate (`allow-updates || online-signing ||
inline-signing`) and never touches `UpdateQ`. Verified.

**Log level: ERROR, framed as an invariant violation**, matching the existing
precedent a few lines below at [zone_updater.go:125](../v2/zone_updater.go). Once
Fix B strips the options, *nothing* should ever reach this gate; a hit means some
path bypassed the option system, i.e. a code bug. ERROR-with-that-framing also
keeps it out of the operator-facing error registry, so it cannot collide with Fix
B's warning.

**Blast radius:** from the full enumeration of `InternalUpdate: true` setters, the
legitimate set through this path on a pure tdns-auth secondary is empty; on an
inline-signing secondary `mayOriginate` admits everything. It bites exactly the
zones intended and nothing else. It is nonetheless a behaviour change on a path
that today accepts every internal update unconditionally, and internal updates are
how much of tdns's machinery talks to itself — so it warrants a deliberate `-race`
run and live testbed validation, not unit tests alone.

### Fix E — role gate on the per-publish SOA re-sign (NEW)

`resignWorkingSetSOAIfSigned` ([zone_mutation.go:186](../v2/zone_mutation.go))
gates on `OptOnlineSigning || OptInlineSigning` with **no role check**, unlike
`SetupZoneSigning` ([zone_utils.go:1107](../v2/zone_utils.go)) which has one — and
it runs inside `publishWorkingSetLocked`, i.e. on every publish including the
refresh path. A tdns-auth secondary carrying `online-signing` (not inline) is not
an originator under the predicate, so Fix A mirrors its serial, but this would
still re-sign the upstream SOA with locally generated keys
(`EnsureActiveDnssecKeys` generates them if absent). Apply the same role gate.

**Resolved (rev 2.1): `online-signing` is normalized off; Fix E stays as
defence in depth.** The consumer survey (~40 sites) showed Fix E alone would
make things *worse*, via an interlock with the outbound-transfer guard: today
the locally-signed SOA (this vector) lets `ZoneTransferOut`'s fail-closed check
pass, so downstreams receive a zone whose SOA RRSIG comes from a key absent
from the DNSKEY RRset — bogus, but flowing. Gate the re-sign without turning
the option off, and the SOA is no longer signed, so
[dnsutils.go:299](../v2/dnsutils.go) sees a to-be-signed zone with an unsigned
SOA and **refuses every outbound transfer** — the secondary silently stops
feeding its downstreams. Beyond that, vectors 5c/5d fire regardless of Fix E,
and the response path ([queryresponder.go:179](../v2/queryresponder.go)) either
signs synthesized denial NSECs with local keys (BOGUS negatives) or, when
upstream is unsigned, SERVFAILs every stored RRset. There is no coherent
"inert" state; off is the only correct one. See §4 for the rationale and the
edge-signer future this deliberately does not foreclose.

## 4. Option classification

**Turn OFF for a non-inline-signing tdns-auth secondary (origination) — five:**
`allow-updates`, `allow-child-updates`, `add-transport-signal`,
**`delegation-sync-parent`**, **`online-signing`** (rev 2.1).

**`delegation-sync-parent` (rev 2 — reversed from rev 1).** Rev 1 excluded it,
reasoning that every delsync path that publishes into the zone is itself gated on
`allow-updates`/`allow-child-updates`. Those specific claims are **correct** and
were re-verified:

- child KEY publication (`Sig0KeyPreparation`) publishes only
  `if Options[OptAllowUpdates]` ([delegation_sync.go:302](../v2/delegation_sync.go)),
  and that one gate covers the parent's UPDATE-receiver key prep too
  (`ParentSig0KeyPrep` funnels into the same function), so with `allow-updates`
  off it is a clean no-op, keygen included;
- child CSYNC publication (`SyncZoneDelegationViaNotify`) likewise
  ([delegation_sync.go:521](../v2/delegation_sync.go));
- parent-side child-delegation apply goes through the CHILD-UPDATE path, gated on
  `allow-child-updates` and enforced at the applier;
- CDS via `PublishCdsRRs` bypasses `allow-updates` but is a **no-op without local
  DNSKEYs** (`SynthesizeCdsRRs` → `len==0 → return nil`,
  [ops_cds.go:61](../v2/ops_cds.go)).

What was wrong is the **inference** drawn from them — "therefore delsync as a
whole needs no gating". Vector 4d is the counterexample. The rule is therefore
stated positively: **`delegation-sync-parent` is off on a tdns-auth secondary**,
because publishing DSYNC is the primary's job (or an agent's, per §1.1); the
`allow-updates` gating above is defence in depth, not the justification.

**Intended consequence, recorded deliberately:** `delegation-sync-parent` also
gates **KeyState EDNS(0) processing on incoming queries**
([defaultqueryhandlers.go:56](../v2/defaultqueryhandlers.go)). Turning it off
disables that on a tdns-auth secondary, and that is correct: the KeyState response
is signed with the receiver's SIG(0) key, the receiver is either the primary or an
agent, the keystore is not replicated by AXFR, and the one path that would
generate a key locally is `allow-updates`-gated and therefore off. A tdns-auth
secondary can never hold that key in any deployment, so leaving the processing on
would produce **unsigned** KeyState responses — worse than not answering.

**`online-signing` (rev 2.1 — closes §12 item 2).** On tdns-auth the only keys
available are **local** ones, and signing upstream content with local keys is
unsafe and plain wrong — the option unlocks, with no role check anywhere:
whole-zone re-signing via the ResignQ path (vector 5d, the largest in the
audit), standby-key minting, per-refresh DNSKEY injection (5c), the per-publish
SOA re-sign (5b), BOGUS ephemeral signing of denial NSECs, and SERVFAIL of
every response when upstream is unsigned. The *concept* — a secondary signing
with **distributed** keys — is legitimate and is exactly the tdns-nm / tdns-es
project (§1.1, second worked example); when that resumes it will most likely be
a new app with its own AppType, which this design accommodates untouched, or a
deliberate refactor made with better knowledge of the requirements. Nothing
here forecloses it. The normalizer warning should suggest `inline-signing` as
the likely intended option.

**NOT gated here — `delegation-sync-child`.** Its zone-publishing paths are
genuinely `allow-updates`/`allow-child-updates`-gated (above) and Fix D backstops
them, so it needs no separate treatment. Whether a tdns-auth *secondary* should be
*sending* delegation-sync signals to a parent at all remains a separate,
non-mutation question — arguably the primary's job — and stays **out of scope**;
flag as a possible future soft-warning, not a gate in this doc.

**Keep:**

- `inline-signing` — the sanctioned signing secondary (Fix A treats it as an
  originator so it may bump; Fix D admits it).
- **`catalog-zone`, `catalog-member-auto-create`, `catalog-member-auto-delete`
  — explicitly ALLOWED on a secondary.** These are NOT origination of the catalog
  zone's content. A tdns-auth secondary of a catalog zone mirrors the catalog
  verbatim (MUST-NOT-MODIFY still holds for the catalog zone itself) and then
  *consumes* it to auto-create / auto-delete the **member** zones it references
  ([catalog.go:270](../v2/catalog.go),
  [apihandler_catalog.go:330](../v2/apihandler_catalog.go)). That provisioning acts
  on *other* zones, never on the catalog zone — and it is the entire point of
  catalog zones (RFC 9432): a secondary that couldn't consume a catalog would make
  the feature pointless. **What must be gated is catalog *authoring* via the API
  (vector 6b), which is a different code path and is handled by Fix C.**
- Serving-behavior options (`fold-case`, `black-lies`, minimal-responses, etc.)
  are unaffected.

`dont-publish-key`/`dont-publish-jwk` become moot once the KEY/JWK publication
paths are unreachable, so they need no special handling — stating that explicitly
avoids a future "why isn't this gated" question.

## 5. Config model change: `outbound_soa_serial` must become per-zone

**This is a schema change and the largest single item in rev 2.**

`outbound_soa_serial` is **server-global** today: [config.go:223](../v2/config.go)
→ `applyOutboundSoaSerial(kdb, …)` ([parseconfig.go:609](../v2/parseconfig.go)) →
`kdb.OutboundSoaSerial`, which every zone reads off the shared KeyDB
([zone_mutation.go:336](../v2/zone_mutation.go),
[zone_utils.go:680](../v2/zone_utils.go),
[refreshengine.go:121](../v2/refreshengine.go) and
[:788](../v2/refreshengine.go)).

Consequence: **the rule "a secondary must not persist its serial" cannot be
expressed at config level.** A server hosting primaries *and* secondaries has one
setting; rejecting `persist` for a secondary would break the co-hosted primaries.

Resolution (both parts land in this PR — see the sequencing decision below):

1. **The schema change:** `outbound_soa_serial` becomes a **per-zone** setting —
   in practice per **template**, since that is how zone policy is curated. The
   global value becomes the default (empty per-zone field = inherit). This is
   the right model independent of this invariant: outbound serial policy is a
   property of a zone's role and downstream contract, not of the server process.

2. **Suppression regardless of source:** the effective mode — whether set
   per-zone, inherited from a template, or defaulted from the global — is
   *suppressed* for a tdns-auth pure secondary at the six Fix A sites. An
   **explicit** per-zone `persist`/`unixtime` on a secondary additionally gets a
   Fix B-style normalizer warning (see below); a secondary merely *inheriting* a
   global `persist`/`unixtime` is covered by a one-time startup warning naming
   the zones where the mode is being suppressed, so the operator sees it either
   way.

**Sequencing DECIDED (rev 2.2): folded into this PR.** The invasiveness scoping
showed the "roughly doubles the PR" fear was wrong — three facts collapse the
cost:

1. **Template propagation is free.** `ExpandTemplate`
   ([parseconfig.go:1261](../v2/parseconfig.go)) generically gap-fills new
   `ZoneConf` fields, so a new `OutboundSoaSerial string` field is
   template-inheritable with zero template code. The gap-fill zero-value caveat
   does not bite: an explicit `keep` under a `persist` template wins ("keep" is
   non-zero; a bool field would have been trapped).
2. **The six read sites are lines Fix A already edits** — switching them to an
   effective-mode helper (zone-level if set, else global; suppressed for an
   auth pure secondary) is the same diff, not new surface.
3. **Storage is already per-zone** (`OutgoingSerials` keyed by zone); only the
   mode is global. Sole change: create the table unconditionally
   (`CREATE IF NOT EXISTS`) instead of only when the global mode is persist.

Genuinely new surface: the `ZoneConf` field
(`validate:"omitempty,oneof=keep unixtime persist"`, empty = inherit global) +
`ZoneData` field + effective-mode helper (~15 lines) + `ZoneRefresher` field
with copies at the ParseZones construction and the three refresher assignment
sites (the same three sites Fix B's chokepoint touches; always-copy is safe
since empty = inherit) + the dynamic-zone round-trip (2 lines) + tests.
Estimate ~120–180 lines of code plus tests. Land as its own commit pair within
the PR: schema+plumbing first, then Fix A's reads via the helper.

Bonuses: this section's "cannot be expressed at config level" premise inverts —
a secondary carrying an explicit `persist`/`unixtime` becomes per-zone-visible
misconfig the Fix B normalizer warns about and clears; and §8 needs no
re-derivation, since an empty field inherits the global and every existing
config keeps byte-identical semantics.

**Deliberate non-feature:** no API knob in `zone add`/`zone modify` — templates
carry outbound-serial policy ("in practice per template"); API-created
secondaries inherit the default. Recorded as a decision, not an omission.
`zone desc`/`zone list -v` should display the effective mode and its source
(zone / template / global), synergizing with §7.

## 6. Ordering and the persisted-config round-trip

**Ordering vs `activateUpdatePolicy`.** [parseconfig.go:904](../v2/parseconfig.go)
parses options; [:918](../v2/parseconfig.go) then calls `activateUpdatePolicy`,
which itself mutates the options map (sets `OptAllowUpdates`/`OptAllowChildUpdates`
false for `none`/empty policy types) and **returns a hard error → `broken_zones` →
the zone is quarantined** when `allow-child-updates` is set without a
`delegationbackend` ([parseconfig.go:1205](../v2/parseconfig.go)). If the
normalizer runs *after* it, a secondary configured that way is hard-quarantined
instead of receiving the promised soft warning — defeating the central safety
promise of Fix B. **The normalizer must run between 904 and 918.**
`activateUpdatePolicy` is arguably its natural home: it is already the post-parse
option-adjustment stage.

This ordering does double duty. The delegation-sync setup block keys off the
freshly-parsed `options` map ([parseconfig.go:1065](../v2/parseconfig.go)); with
the normalizer running earlier, `OptDelSyncParent` is already false for a
secondary, the block is skipped, and `SetupZoneSync` never registers at all — so
vector 4d is closed at parse time with no additional wiring.

**The persisted-config round-trip (must not silently rewrite operator intent).**
`zoneDataToZoneConf` ([dynamic_zones.go:452](../v2/dynamic_zones.go)) serializes
the **live** `zd.Options`, and `AddDynamicZoneToConfig` runs on every successful
refresh of a persistable dynamic zone
([refreshengine.go:839](../v2/refreshengine.go)), rewriting the whole dynamic
config file from the live `Zones` map. If the normalizer mutates live options, the
persisted config **permanently loses** `allow-updates`, after which the warning
clears and the misconfiguration becomes invisible — the operator's stated intent
silently deleted.

Rev 1's model ("recompute each parse; fixing the YAML clears the flag") assumes
YAML is truth. For static zones it is; for dynamic zones the file is *regenerated
from state*. The normalizer must therefore keep **as-configured** options separate
from **effective** options, with the serializer writing the as-configured set. This
is the same class of problem the config-reload policy guardrail work wrestled with.

## 7. Diagnostics — make the split-brain visible

There is currently no way to see, from tdns, the condition that motivated this
work: two masters disagreeing about a zone's serial. Add it.

- **`zone list -v`** — show our outbound serial (`CurrentSerial`) and our inbound
  serial (`IncomingSerial`) side by side. Free: both are already on `ZoneData`, no
  network.
- **`zone desc <zone>`** — additionally probe **every configured primary** and show
  each one's SOA serial individually. Plumbing exists (`populateZoneDescDetail`,
  [apihandler_zone.go:388](../v2/apihandler_zone.go), with `ZoneConf` as carrier).
  `DoTransfer` already performs the TSIG/XoT-correct SOA probe and returns the
  serial ([zone_utils.go:170-175](../v2/zone_utils.go)), but short-circuits on the
  first usable upstream, so this needs a small read-only extraction that probes all
  of them.

Per-primary output is the point: *this* master says 42, *that* one says 5000 is the
direct diagnostic for §1's motivating failure, and it doubles as the pre-upgrade
check for §8. Single-zone only — the probe costs a query per primary, which is fine
for `zone desc` and not for bulk listing.

## 8. Migration — severity is per-serial-mode

Rev 1 had no migration section; rev 2's first draft over-stated the risk. The
corrected analysis:

In the default **`keep`** mode there is **no restore path at all** —
[refreshengine.go:121](../v2/refreshengine.go) switches only on `unixtime` and
`persist`. So on every restart today a tdns-auth secondary already does `firstLoad
→ CurrentSerial = new_zd.CurrentSerial` = the upstream serial. **The backwards jump
already happens at every restart, today, in the default mode.** The inflation only
accumulates between restarts, at +1 per refresh. Fix A does not introduce a new
event there; it stops the re-inflation afterwards.

| Mode | Today at restart | After Fix A | Migration risk |
|---|---|---|---|
| `keep` (default) | already resets to upstream serial | same, and stops re-inflating | **none new** |
| `persist` | persisted serial survives, zone stays ahead | drops to upstream serial | **one-time backwards jump** |
| `unixtime` | serial is a Unix timestamp, enormously ahead | drops to upstream serial | **largest one-time jump** |

The two modes that create a migration event are exactly the two that must not apply
to a secondary at all (§5) — which is the argument for the change, not against it.

**Why a downstream sticks.** A tdns downstream refuses at
[zone_utils.go:172](../v2/zone_utils.go) (`soa.Serial <= zd.IncomingSerial`);
BIND/NSD do the same under RFC 1982. NOTIFY does not rescue it — a NOTIFY carrying
a lower serial is ignored. The downstream serves stale data until upstream climbs
past the old value, which may be never.

**Who is exposed.** Only zones that are (i) tdns-auth secondaries in
`persist`/`unixtime` mode *and* (ii) themselves masters for someone. A leaf
secondary is unaffected — nobody transfers from it and caches do not compare SOA
serials. That intersection is precisely the distribution tier from §1.

**Required (Fix A companion):** on the first mirror, if the incoming serial is
below the previous `CurrentSerial`, log at ERROR with zone, old serial, new serial
and the operator action. This converts a silent stall into a loud one.

**Operator remedy (documented, verified):** a forced retransfer on each downstream
— `tdns-cli zone reload --force <zone>` → `ZonePost.Force` → `ReloadZone` →
`ZoneRefresher.Force` → `Refresh(force)` → [zone_utils.go:75](../v2/zone_utils.go)
`if do_transfer || force`, which bypasses the serial comparison. Non-tdns
downstreams need their own (BIND: `rndc retransfer`). Use §7's `zone desc` to build
the list before upgrading.

**Explicitly rejected:** a transition mode that keeps bumping until upstream
overtakes. It never converges in the BIND/tdns pair that motivated the doc, and it
perpetuates the bug it exists to kill.

## 9. The forced-transfer contract

**Requirement: a forced transfer MUST perform the transfer and apply whatever the
upstream has — including a serial that is lower than, or equal to, our own.** With
strict passthrough this is the operator's only remedy (§8) and the only escape
hatch from a wedged secondary; it must not chicken out at the starting gate.

Current state, verified:

- **Lower serial: works, but only incidentally.** `DoTransfer` returns
  `(false, serial, nil)` — no error — for a lower upstream serial
  ([zone_utils.go:172](../v2/zone_utils.go)), and [:75](../v2/zone_utils.go) is
  `if do_transfer || force`, so the forced path reaches `FetchFromUpstream` and
  applies it. Nothing pins this. That `<=` is one plausible "tightening" away from
  silently breaking the sole migration remedy — silently, because the forced
  transfer would report success and change nothing.
- **Equal serial: broken.** [FetchFromUpstream:313](../v2/zone_utils.go) discards
  the transfer when `new_zd.IncomingSerial == zd.IncomingSerial`. So
  `zone reload --force` on an already-current zone is a **silent no-op** — force
  does not mean force. Consequence beyond migration: force cannot be used on the
  secondary itself to apply the mirror early (moot for the upgrade, since an upgrade
  is a restart and restart = first load = immediate mirror, but wrong).

**Required:** make the contract explicit in code, pin it with a regression test for
the lower-serial case specifically, and fix the equal-serial no-op so that `force`
genuinely re-fetches and re-applies.

## 10. Testing

- **Fix A (mutation-verified):** non-signing secondary, upstream serial jumps N→M
  across two refreshes → served serial == M (mirror), not prev+1; fails on current
  code, passes on the fix. Plus: signing (inline) secondary still advances;
  `unixtime`/`persist` on a pure secondary does not rewrite the serial at **any** of
  the six sites; the persisted row is cleared.
- **Per-zone `outbound_soa_serial` (§5):** zone-level value wins over template;
  template fills a gap when the zone is silent; explicit `keep` under a
  `persist` template wins (the gap-fill zero-value caveat does not bite);
  empty everywhere → global default applies; a config-reload flip of the
  per-zone value takes effect; the field round-trips through the dynamic-zone
  config file (`zoneDataToZoneConf` serialize + re-parse); an explicit
  `persist`/`unixtime` on a secondary draws the normalizer warning; a primary
  with per-zone `persist` persists while a co-hosted global-`keep` primary does
  not (per-zone independence).
- **Fix B:** a secondary configured with each of the five origination options →
  option ends up off, soft `ConfigWarning` present, zone still `Ready`/served;
  reload with a clean config clears it. Cover the dynamic-zone add **and modify**
  paths, and the API (`zoneOptionsFromStrings`) path.
- **Ordering (§6):** a secondary with `allow-child-updates` and no
  `delegationbackend` gets the soft warning, **not** a `broken_zones` quarantine.
- **Config round-trip (§6):** a dynamic secondary with `allow-updates` in its
  persisted config still has it in the file after several refresh cycles; the
  warning does not silently disappear.
- **Vector 4d:** a secondary with `delegation-sync-parent` publishes **no**
  `_dsync.<zone>` DSYNC RRset and no address RRs; `SetupZoneSync` does not register.
- **Vectors 5b/5c/5d (`online-signing` normalized + Fix E):** a secondary
  configured with `online-signing` has the option normalized off (warning
  suggests `inline-signing`), generates no keys, injects no DNSKEYs on refresh,
  is never whole-zone re-signed via the ResignQ path, and does not re-sign the
  upstream SOA across refreshes; outbound transfer of the (now unsigned-mirror)
  zone is **not** refused by the `ZoneTransferOut` signed-zone guard.
- **Vector 6b (Fix C):** the catalog authoring API refuses against a secondary
  catalog zone.
- **Catalog not regressed (the §4 carve-out):** a secondary catalog zone with
  `catalog-member-auto-create`/`-auto-delete` keeps those options ON and still
  provisions/deprovisions member zones — no warning, no gating. (Guards against
  re-introducing the mistake of treating catalog consumption as origination.)
- **Fix C:** the origination actions in **both** zone handlers are refused for a
  secondary, allowed for a primary; `write-zone` still allowed; `freeze`/`thaw`
  refused with the *role* reason, not the allow-updates reason; the added `return`s
  are covered (error responses no longer carry a success `Msg` and no longer change
  state).
- **Fix D:** an `InternalUpdate` ZONE-UPDATE against a pure secondary is dropped and
  logged; the same request against a primary and against an inline-signing secondary
  is applied; `TRUSTSTORE-UPDATE` is unaffected.
- **Forced transfer (§9):** a forced transfer applies a **lower** upstream serial; a
  forced transfer with an **equal** serial re-fetches rather than no-opping.
- **App-scope (the §1.1 guarantee, must be explicit):** with
  `Globals.App.Type != AppTypeAuth` (drive a test with, e.g., `AppTypeAgent`), a
  Secondary carrying origination options keeps them on, its serial advances exactly
  as before, the API origination actions are not refused, and the applier gate drops
  nothing — proving all five fixes are no-ops off tdns-auth so tdns-agent /
  tdns-mpcombiner / tdns-mpagent behavior is unchanged.
- Gate: full `v2` `-race`, gofmt, cmdv2 binaries build via gmake, plus live
  validation on the foffe testbed for Fix D (see its blast-radius note).

## 11. Resolved residuals

Rev 1 listed two items to confirm at implementation. Both are now settled, and one
is better than hoped:

- **JWK / A-AAAA / TLSA (#9):** not merely "does not fire" — `PublishJWKRR`,
  `PublishTlsaRR`, `PublishAddrRR`, `PublishSvcbRR` and `PublishUriRR` have **zero
  callers** anywhere in tdns `v2/` or `cmdv2/`. They are library surface for the
  derived apps and cannot fire on tdns-auth at all. This independently reinforces
  §1.1.
- **`bumpch` vs handler bump (#7):** `BumpZoneCh` is created
  ([main_initfuncs.go:190](../v2/main_initfuncs.go)) and read
  ([refreshengine.go:855](../v2/refreshengine.go)) but **nothing ever sends on it**
  — the path is dead code. There is one live bump entry point,
  [apihandler_zone.go:70](../v2/apihandler_zone.go). Gate both anyway; it is free.

## 12. Open items

Still open (does not block starting implementation):

4. **"Pause refresh" on a secondary** — parked for a later discussion. (The
   idea, for that discussion: an operator control to stop refreshing from a
   known-bad upstream while continuing to serve the current data — the
   capability rev 1's incorrect freeze rationale accidentally described. It does
   not exist today; `OptFrozen` gates DDNS only. Explicitly **not** built here.)

Closed since rev 2 (rulings 2026-07-26):

1. **§5 sequencing** — CLOSED (rev 2.2): per-zone `outbound_soa_serial` is
   **folded into this PR** as its own commit pair; invasiveness scoping showed
   ~120–180 lines + tests, not the feared doubling. Details in §5.
2. **`online-signing` normalization** — CLOSED (rev 2.1): normalized **off** on
   a tdns-auth secondary; Fix E stays as defence in depth; the distributed-key
   edge-signer future (tdns-nm/tdns-es) is deliberately not foreclosed. See §4.
3. **Stale persisted serials** — CLOSED: **clear them out** (Fix A does so).
5. **Freeze/thaw missing `return`s** — CLOSED: **separate commit in the same
   PR**, ahead of the Fix C commit that depends on it.

## 13. Relationship to other work

- **Prerequisite for inbound IXFR** (`2026-07-25-inbound-ixfr-plan.md`): the
  serial-space contract (served/outbound `CurrentSerial` vs upstream
  `IncomingSerial`) that IXFR-in's SOA handling depends on only makes sense once the
  secondary serial actually mirrors upstream. Land this first.
- Independent of the IXFR-out work already merged (#328).
- Suggested single PR `feature/secondary-zones-immutable`: per-zone
  `outbound_soa_serial` (§5, own commit pair, first) + Fix A (serial mirror +
  six-site suppression via the effective-mode helper) + Fix B (normalizer) +
  Fix C (freeze/thaw `return`s as a separate commit, then the API gate) + Fix D
  (applier gate) + Fix E (re-sign role gate) + §7 diagnostics + §9
  forced-transfer contract + tests. Its own branch, landing ahead of inbound
  IXFR. (Branch forward-merged from main and carrying this doc as of rev 2.)

## 14. Implementation scope estimate (rev 2.2)

Per work item, in §13's commit order:

| # | Work item | Files touched (non-test) | Code LOC (±) |
|---|---|---|---|
| 1 | Per-zone `outbound_soa_serial` (§5) | structs.go (ZoneConf + ZoneData fields), refreshengine.go (ZoneRefresher + 3 copy sites), parseconfig.go (zr construction, unconditional table), zone_utils.go (effective-mode helper), dynamic_zones.go (round-trip ×2) | ~50 |
| 2 | Fix A — mirror + six-site suppression + row-clear + backwards-jump ERROR | zone_mutation.go, refreshengine.go ×2 blocks, zone_utils.go (`nextOutboundSerial`, `mayOriginate` helper), db_outgoing_serial.go (delete func) | ~85 |
| 3 | Fix B — normalizer + serial-mode sibling + ~7 call sites + as-configured/effective split | new option_normalize.go (or parseoptions.go), parseconfig.go, dynamic_zones.go, dynamic_primary.go, refreshengine.go (chokepoint ×3 + effective-type caveat), structs.go + dynamic_zones.go (as-configured storage + serializer) | ~105 |
| 4 | Freeze/thaw `return`s (own commit) | apihandler_zone.go | ~6 |
| 5 | Fix C — both zone handlers + catalog handler + freeze/thaw role refusal | apihandler_zone.go, apihandler_catalog.go (cleanest as one gate in `regenerateCatalogZone` + handler messages) | ~55 |
| 6 | Fix D — applier gate | zone_updater.go | ~15 |
| 7 | Fix E — re-sign role gate | zone_mutation.go | ~5 |
| 8 | §7 diagnostics — serials in `list -v`, all-primaries probe in `desc`, mode display | zone_utils.go (probe extraction from `DoTransfer` — the one real refactor), apihandler_zone.go, structs.go (carrier fields), cli/zone_cmds.go | ~115 |
| 9 | §9 forced-transfer — equal-serial fix needs `force` **threaded into `FetchFromUpstream`** (signature change; it does not take force today) | zone_utils.go + call sites | ~15 |
| 10 | §5 startup warning (global persist/unixtime + auth secondaries) | parseconfig.go | ~12 |

**Totals:**

- **Production code: ~450–550 LOC** added/changed across **~14 files**. Heavy
  concentration — zone_utils.go, refreshengine.go, zone_mutation.go,
  apihandler_zone.go, parseconfig.go and dynamic_zones.go are each touched by
  2–4 items — which argues for the §13 commit ordering being strictly serial,
  not parallelized.
- **Tests: ~1,200–1,600 LOC** in **7–9 new/extended test files** (§10's matrix
  is genuinely large: mirror semantics, six-site suppression, normalizer ×
  5 options × 4 ingress paths, ordering-vs-quarantine, config round-trip, both
  API handlers, applier gate, forced transfer, per-zone mode × 8 cases,
  app-scope proof).
- **Existing-test fallout: ~100–200 LOC adjusted** — anything asserting
  `CurrentSerial++` on refresh (e.g. `ixfr_test.go` drives
  `applyRefreshReplacementLocked` directly) plus publish-path tests.
- **Net diff: roughly +2,000 / −200 over ~20–24 files, in 9–10 commits** — the
  same order of magnitude as the outbound-IXFR PR (#328); a solid multi-session
  PR, not a monster.

**Uncertainty drivers, in order of risk:**

1. **The as-configured vs effective options mechanism (item 3)** — the one open
   design choice (§6). If it turns into threading a second options
   representation through more places than `zoneDataToZoneConf`, item 3 grows
   by 50–100 LOC.
2. **The `DoTransfer` probe extraction (item 8)** — refactoring a live transfer
   path for read-only reuse; mechanically simple but it touches the most
   battle-hardened function in the set.
3. **Fix D's blast radius is not a LOC risk** (15 lines) — it is a *validation*
   cost: the doc requires foffe testbed time on top of `-race`, which is
   wall-clock, not diff size.
