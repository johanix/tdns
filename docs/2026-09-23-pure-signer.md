# A pure signer: tdns-signer with one way in

**Written 2026-09-23.** Scoping analysis, for review. Nothing is implemented.
Line references are to main at `e223451b`. Builds on #558, which records how to
give `tdns-signer` an app type of its own; this document answers the question
that comes after it: what the signer should stop doing, where each of those
things lives, and what it costs to remove them without touching tdns-auth,
tdns-agent or tdns-mp.

**Status:** analysis. Decisions taken before writing: the signer keeps CDS
publication and child-side delegation sync; the management API keeps key
management, zone provisioning, operational verbs and read-only inspection.

## Summary

- **The removal is moderate work if it is done as runtime gates, and large if
  it is done as compile-time absence.** Gates keyed on a new `AppTypeSigner`
  come to roughly 600–800 lines of non-test code plus tests (§8), in six stages
  that each leave tdns-auth, tdns-agent and tdns-mp unchanged by construction.
  Compile-time absence means build-tagging about 35 files (~11,500 lines) and
  splitting five shared dispatch points; §7 measures what the linker already
  does for free.
- **Nothing in the code stops tdns-signer from originating content today, and the
  existing guard cannot be made to.** The secondary-immutability machinery
  answers one binary question, "may this zone originate content?", and answers
  *yes* for every `inline-signing` zone (`v2/zone_origination.go:49`). Every
  signer zone is inline-signing. So on tdns-signer today DNS UPDATE, API
  `update`, `allow-child-updates`, `childsync`, catalog authoring and dynamic
  primaries all work (§2). A pure signer needs its own gates at the entry
  points, not a tighter version of that predicate.
- **Child-side delegation sync, which the signer keeps, does not work fully on
  a signing secondary.** Four existing defects (§5): an NS or glue change that
  arrives by transfer never triggers a parent sync (#731); the DS engine's CDS
  is dropped by every inbound AXFR (#732); the CSYNC for the NOTIFY scheme is published
  only with `allow-updates` (#557), which a pure signer refuses; and CDNSKEY is
  never generated. They affect tdns-signer as it is today and inline-signing
  secondaries on tdns-auth, independently of this change, and should be fixed
  first.
- **Dropping an engine from `StartSigner` is not enough on its own.** The
  queues those engines drain are created unconditionally in `MainInit`, and
  their producers block when nobody reads them. Without a scanner, the sixth
  NOTIFY(DNSKEY) stalls all NOTIFY processing, including the upstream's
  NOTIFY(SOA) that the signer lives on (§4.1).

## 1. What "pure" means

A pure signer has one source of zone content and one kind of output.

| | |
|---|---|
| **Content in** | AXFR/IXFR from the zone's upstreams, prompted by NOTIFY(SOA) or the refresh timer |
| **Content out** | the signed zone, by AXFR/IXFR to downstreams, announced by NOTIFY(SOA); answers to queries |
| **Content it adds** | what signing requires, and what the parent needs from the zone's signer: DNSSEC material (RRSIG, NSEC/NSEC3, NSEC3PARAM, DNSKEY, the SOA serial), CDS (and CDNSKEY, §5 D4), the apex SIG(0) KEY for the UPDATE delegation-sync scheme, CSYNC for the NOTIFY scheme, ZONEMD if `publish-zonemd` |
| **Talks to the parent** | as a child only: UPDATE, NOTIFY(CDS/CSYNC) or the DSYNC API, towards the parent's advertised DSYNC target |
| **Operator interface** | management API: keys and rollovers, adding and removing secondary zones, refresh, reload, re-sign, status, inspection |

Everything else goes:

| Remove | What it is today |
|---|---|
| DNS UPDATE | the whole inbound path: ZONE-UPDATE (`allow-updates`), CHILD-UPDATE (`allow-child-updates`), TRUSTSTORE-UPDATE (child SIG(0) key upload) |
| content edits over the API | `/zone update`, catalog authoring, `delegation export` |
| primary zones | static `type: primary`, `/zone add` of a primary, persisted dynamic primaries, `/catalog create` |
| DSYNC publication | the `childsync` option: DSYNC, SVCB, URI, TXT and the receiver KEY published into the zone; KeyState answering |
| DSYNC receivers | UPDATE (above), the DSYNC API listener, NOTIFY(CDS/CSYNC) acting as a parent |
| scanning | `ScannerEngine`, poll scanning, NOTIFY(DNSKEY) |
| other originators | `add-transport-signal`, `use-hsyncparam`, `online-signing`, `multi-provider`, both proxies |

Note the option names, which run the opposite way from what they describe
(`v2/enums.go:135-173`): **`parentsync`** (old alias `delegation-sync-child`)
is the *child* side and stays; **`childsync`** (old alias
`delegation-sync-parent`) is the *parent* side and goes. #558's suggestion to
refuse `delegation-sync-child` on a signer is superseded by the decision to
keep child-side sync.

## 2. Where tdns-signer stands today

`cmdv2/signer/main.go:82` sets `AppTypeAuth` and calls `conf.StartAuth()`
(`v2/main_initfuncs.go:292`). There is no `StartSigner`. The signer runs every
tdns-auth engine: APIdispatcher, DsyncApiListener, ValidatorEngine, ImrEngine,
RefreshEngine, Notifier, AuthQueryEngine, ScannerEngine, ZoneUpdaterEngine,
UpdateHandler, DelegationSyncher, DSEngine, NotifyHandler, DnsEngine,
ResignerEngine, KeyStateWorker.

The design that keeps secondaries immutable, `docs/2026-07-25-secondary-zones-immutable.md`,
sanctions an inline-signing secondary adding RRSIGs, and by its Fix D CDS and
CSYNC. The code implements it as one predicate:

```go
// v2/zone_origination.go:42-50
func zoneMayOriginateContent(zd *ZoneData) bool {
	...
	if Globals.App.Type != AppTypeAuth {
		return true
	}
	return zd.ZoneType == Primary || zd.Options[OptInlineSigning]
}
```

So an inline-signing secondary on tdns-auth is treated exactly like a primary.
The consequences for the signer:

- The option normaliser strips nothing (`v2/zone_option_normalize.go:93`), so
  `allow-updates`, `allow-child-updates`, `allow-api-updates`, `childsync`,
  `add-transport-signal` and `online-signing` all survive on a signer zone.
- The API's origination gate (`v2/apihandler_zone.go:72`,
  `originationAPICommands` at `v2/zone_origination.go:65`) passes everything,
  and `update` is not in that list anyway.
- The ZoneUpdater's origination check (`v2/zone_updater.go:236`) admits every
  ZONE-UPDATE and CHILD-UPDATE.
- `UpdateResponder` checks only `allow-updates` / `allow-child-updates`
  (`v2/updateresponder.go:259, 279, 295, 308`), so DDNS into a signer zone is
  accepted whenever the option is set. `guide/app-tdns-signer.md` ("Do not
  enable inbound updates on a signer") is the only thing that says otherwise.
- Nothing on the dynamic-zone or catalog paths checks the app type:
  `/zone add` creates a primary whenever `dynamiczones.dynamic.allowed`
  includes `primary` (`v2/dynamic_zones.go:813`), and `/catalog create`
  creates a primary catalog zone on every app type
  (`v2/apihandler_catalog.go:112`, `ZoneType: Primary` at
  `v2/zone_utils.go:2562`).

## 3. Inventory: what has to go, and where it lives

Each row says where the capability enters and what kind of change removes it.
The **Tier** column is defined in §6: **S** = only signer code (`StartSigner`,
`cmdv2/signer`, or a new signer-only function in v2); **G** = a gate in shared
v2 code that fires only for `AppTypeSigner`; **R** = restructuring shared code.

### 3.1 DNS UPDATE

| Piece | Entry | Tier |
|---|---|---|
| Opcode dispatch | `createAuthDnsHandler` captures `conf.Internal.DnsUpdateQ` (`v2/do53.go:315`); registered handlers first (`:436-478`), then the queue (`:483`), else NOTIMP (`:489-494`) | S |
| Consumer | `UpdateHandler` → `UpdateResponder` (`v2/updateresponder.go:50, 126`), started at `v2/main_initfuncs.go:318` | S |
| Classification, SIG(0), policy | `updateresponder.go:229-425`; `sig0_validate.go`, `update_policy_eval.go`, `bootstrap_ceremony.go`, `child_key_rebootstrap.go`, `truststore_verify.go` | unreachable once the consumer is gone |
| Parent-first NS removal | `answerOwnDelegationUpdate` (`updateresponder.go:532`) → `applyParentFirst` (`delegation_parent_first.go:252`) | unreachable |

`DnsUpdateQ` is created for every app (`v2/main_initfuncs.go:217`, buffer
100), and the send at `do53.go:483` blocks. Not starting `UpdateHandler` is
therefore not enough: 100 UPDATEs later, request goroutines pile up. Setting
`conf.Internal.DnsUpdateQ = nil` in `StartSigner` before `DnsEngine` starts
turns UPDATE into NOTIMP with no library change. `DnsEngine` is its only other
reader (`grep DnsUpdateQ`: `do53.go:315`, `updateresponder.go:51`, and the
creation site).

### 3.2 Content edits over the management API

The API offers no single place to enforce this. Each handler decodes its own
request and applies changes directly (full per-command inventory in Appendix A).
The signer's decisions:

| Route / command | Signer | Why |
|---|---|---|
| `/zone update` (`apihandler_zone.go:105` → `ApiZoneUpdate`, `zone_update_api.go:35`) | **refuse** | the content channel; also drives `applyParentFirst` |
| `/zone add` with type primary, or with any refused option (`:345`; options come raw from `zoneOptionsFromStrings`, `:620`) | **refuse** | provisioning a secondary stays; a primary or a content option does not |
| `/zone modify` with a refused option (`:386`, `ModifyDynamicZone` `dynamic_zones.go:1117`) | **refuse** | same back door as `add` |
| `/zone freeze`, `thaw` (`:250`, `:289`) | **refuse** | meaningful only with `allow-updates`/`allow-child-updates` (`:266`, `:296`), both refused; an explicit refusal gives the true reason |
| `/zone proxy-key` (`:221`) | **refuse** | needs `parentsync-proxy`, an agent option |
| `/zone/childsync` (route, `apirouters.go:103`) | **drop route** | parent-side DSYNC publication |
| `/dsync-api/credential`, `/dsync-api/cert-credential` (`apirouters.go:110-111`) | **drop routes** | credentials for the DSYNC API receiver |
| `/catalog` (route, `apirouters.go:96`) | **drop route** | catalog *authoring*; consuming a catalog is not an API function (§9 Q2) |
| `/delegation export` (`apihandler_funcs.go:582`) | **refuse** | parent side; writes a file at a client-chosen server path |
| `/scanner/poll` (`apirouters.go:128`) | **drop route** | scanner |
| everything else | keep | key management, `/zone/parentsync` (child side), `/delegation status|sync`, rollover, `bump`, `sign-zone`, `resign-zone`, policy commands, `reload`, `write-zone`, journal, `/config`, `/command`, `/debug`, `/imr`, `/keystore`, `/truststore` |

Route removal is Tier S: a `SetupSignerAPIRouter` that registers only the kept
routes. The command refusals inside `/zone` and `/delegation` are Tier G,
because those handlers are shared with tdns-auth and tdns-agent.

`/truststore child-sig0-mgmt` stays whole. It is mostly parent-side (trusting
child keys that authorise CHILD-UPDATE), but it also records a manually trusted
parent receiver key, which the child side uses to verify KeyState answers
(`keystate_verify.go:93-107`). It changes the truststore, never zone content.

### 3.3 Primary zones

| Path | Entry | Tier |
|---|---|---|
| static config | model: the agent's refusal at `v2/parseconfig.go:1359-1368` (`SetError(ConfigError)`, `continue`) | G |
| `/zone add` primary | `ProvisionDynamicZone`, `v2/dynamic_zones.go:807` | G |
| persisted dynamic primaries at boot | `LoadDynamicZoneFiles`, `v2/dynamic_zones.go:170-260` | G |
| `/catalog create` | route dropped (3.2) | S |
| `config check` | `v2/cli/config_check_cmds.go:990-997` predicts the agent's refusal; needs the same for the signer | G (CLI) |

### 3.4 DSYNC publication (parent side)

| Piece | Entry | Tier |
|---|---|---|
| `childsync` option → `SetupZoneSync` branch → `PublishDsyncRRs`, `ParentSig0KeyPrep` | `v2/zone_utils.go:1880-1959`; `ops_dsync.go:120, 372` | G (refuse the option) |
| KeyState EDNS(0) answering | `v2/defaultqueryhandlers.go:56-80`, gated on `childsync` | inert once the option is refused |
| API publish/unpublish | `/zone/childsync` | S (route) |

### 3.5 DSYNC receivers and scanning

| Piece | Entry | Tier |
|---|---|---|
| DSYNC API listener | `StartDsyncApiListener`, started at `v2/main_initfuncs.go:301` | S (not started) |
| NOTIFY(CDS/CSYNC) as a parent | `v2/notifyresponder.go:333-349` → `ScannerQ` | S (registered refusal, 4.1) |
| NOTIFY(DNSKEY) | `notifyresponder.go:351-367` → `ScannerQ`; no ACL check | S (registered refusal) |
| `ScannerEngine` | `v2/scanner.go:157`, started at `main_initfuncs.go:316` | S (not started) |
| CHILD-UPDATE and TRUSTSTORE-UPDATE arms of the ZoneUpdater | `v2/zone_updater.go:251, 491` | G (backstop, 4.3) |

Whether a zone accepts NOTIFY(CDS/CSYNC) depends on *content*: the parent zone's
own data must hold a DSYNC record advertising NOTIFY for that type
(`notifyresponder.go:29-55, 265`), not on the `childsync` option. A signer
that signs a parent zone whose upstream publishes `_dsync` records would
therefore act as a DSYNC NOTIFY receiver for that zone's children. The refusal
must be keyed on the app type, not on the option.

### 3.6 Zone options

Allowed on a pure signer: `inline-signing` (required), `parentsync`,
`dont-publish-key`, `black-lies`, `publish-zonemd`, `verify-zonemd`,
`request-ixfr`, `no-request-ixfr`, and the catalog options if Q2 allows
consumption.

Refused, as a `ConfigError` on the zone: `allow-updates`, `allow-child-updates`,
`allow-api-updates`, `childsync`, `childsync-proxy`, `parentsync-proxy`,
`add-transport-signal`, `use-hsyncparam`, `online-signing`, `multi-provider`.

Zone options are read in four places, and the refusal has to apply to all
four (Tier G):

1. `parseZoneOptions`, `v2/parseoptions.go:160-431` (static config, reload);
2. `normalizeOptionsForRole`, `v2/zone_option_normalize.go:88`, also called
   from `dynamic_zones.go:908, 1236` and `refreshengine.go:756, 903, 1060`;
3. the API's `zoneOptionsFromStrings`, `v2/apihandler_zone.go:620-632`, which
   accepts any known option name;
4. catalog config-group options, `v2/catalog.go:419-424`, a raw
   `StringToZoneOption` lookup.

The one-place answer is a signer branch in `normalizeOptionsForRole`, which
already sits on paths 1, 2 and the dynamic add/modify path. Its contract today
is to strip and warn, and for a signer it should refuse. Paths 3 and 4 need
their own call.

### 3.7 Config blocks

| Block | Signer |
|---|---|
| `parentsync:` | keep; `parentsync.schemes` is required with the option (`zone_utils.go:1969-1975`) |
| `childsync:` (all of it: schemes, api, policies) | refuse, or warn and ignore; validation at `config_validate.go:162-167` |
| `scanner:` | warn and ignore (read only through viper, `scanner.go:160-183`) |
| `dynamiczones:` | keep; refuse `primary` in `dynamic.allowed` |
| `catalog:` | keep for consumption if Q2 allows it |
| `imrengine:` | keep, and **required on** when any zone has `parentsync` (§5 D5) |
| `validator:` | ignore; the engine is dead code (nothing sends on `ValidatorCh`) |

## 4. What stays, and what it needs

| Engine | Stays | Note |
|---|---|---|
| RefreshEngine, Notifier, AuthQueryEngine, DnsEngine | yes | the pipeline |
| NotifyHandler | yes | NOTIFY(SOA) only (4.1) |
| ResignerEngine, KeyStateWorker, DSEngine | yes | signing, rollover, CDS |
| ZoneUpdaterEngine | **yes, restricted** (4.3) | CDS, CSYNC and the apex KEY go through it |
| DelegationSyncher | yes | child arms only; it has no parent-side arm |
| ImrEngine | yes | parentsync needs it (§5 D5) |
| APIdispatcher | yes | with `SetupSignerAPIRouter` |
| UpdateHandler, ScannerEngine, DsyncApiListener | **no** | |
| ValidatorEngine | optional | dead code either way |

### 4.1 NOTIFY

`ScannerQ` is created for every app with a buffer of 5
(`v2/main_initfuncs.go:216`). `NotifyResponder` sends to it with a select that
waits only for the context (`notifyresponder.go:333-367`), inside the single
goroutine that serves all NOTIFYs (`notifyresponder.go:95-108`). With no
scanner draining it, the sixth NOTIFY(DNSKEY) — which needs no ACL — blocks
NOTIFY(SOA) for every zone until shutdown. A nil `ScannerQ` does not help:
the send then never proceeds.

The fix needs no library change. `RegisterNotifyHandler`
(`v2/registration.go:143`) takes a qtype, and registered handlers run before
the queue (`v2/do53.go:365-420`). `StartSigner` registers one handler each for
CDS, CSYNC and DNSKEY that answers REFUSED with an EDE and returns nil, so the
request never reaches `DnsNotifyQ`.

### 4.2 IMR

Child-side sync needs the IMR. `DELEGATION-SYNC-SETUP` waits for
`ImrReady` indefinitely, warning after a timeout
(`v2/delegation_sync.go:947`, `deferForImr`). `ResolveParentVia(nil)` returns
`ErrNoImrEngine` (`v2/delsync_update.go:168`), and the rollover engine gets no
push plan without it (`v2/ksk_rollover_ds_push.go:331`). The signer's sample
config sets `imrengine: active: false` (`cmdv2/signer/tdns-signer.sample.yaml:90`).
A signer zone with `parentsync` and no IMR should be a config error.

### 4.3 ZoneUpdater, restricted

Signing does not use the ZoneUpdater: `PublishDnskeyRRs` stages directly under
`zd.mu` (`v2/ops_dnskey.go:88-96`), and so do the signer and re-signer. But
every internal publisher the signer keeps does go through it, as a
ZONE-UPDATE with `InternalUpdate` set:

- CDS: `publishCDSAndWait` → `applyInternalUpdateAndWait` (`v2/ds_engine.go:489, 526-551`);
- CSYNC: `publishCsyncRR` (`v2/ops_csync.go:123`);
- the apex SIG(0) KEY: `Sig0KeyPreparation` → `PublishKeyRRs` (`v2/ops_key.go:15`).

So the engine stays. Once 3.1 and 3.2 are gated, its non-internal producers are
unreachable on the signer. A backstop at the loop head (`zone_updater.go:236`)
still makes the signer's contract visible in one place: on
`AppTypeSigner`, admit only ZONE-UPDATE with `InternalUpdate`, and refuse
CHILD-UPDATE, TRUSTSTORE-UPDATE and any ZONE-UPDATE carrying `PreAuthorized`.
Restricting the admitted RR types (CDS, CDNSKEY, CSYNC, apex KEY) is possible,
but duplicates what the entry-point gates already guarantee.

### 4.4 Why not a third origination class

A tempting design is to turn `zoneMayOriginateContent` into a three-way
answer: none, signing-derived only, full. It would put the signer's contract
where the secondary contract already lives. Two things argue against it.

- The predicate's callers ask different questions. Some ask "may this zone's
  serial diverge from upstream" (serial mirror, `zone_mutation.go:697, 822, 867`;
  `refresh_run.go:115`), and the answer is yes for a signer. Others ask "may
  this zone be restitched or renewed" (`nsec_restitch.go:74`, `sign_renew.go:233`),
  also yes. Of its 20 call sites in v2, nine ask "may content arrive from
  somewhere other than upstream": the API gates (`apihandler_zone.go:73, 259,
  291, 1296`, `apihandler_catalog.go:503`), the applier (`zone_updater.go:236,
  657`) and transactions (`zone_tx.go:137, 354`). Those are the channels §3
  gates at their entry points anyway. A third class would force every caller
  to choose, for no change in behaviour at the other eleven.
- It is load-bearing for tdns-mp. Its doc comment says so: the derived apps
  rely on the predicate standing down for them.

So the recommendation is to leave the predicate answering yes for the signer's
inline-signing zones, which is correct for every caller that asks about
serials and signatures, and gate the content channels at their entry points.

## 5. Defects in child-side sync on a signing secondary

These exist today, on tdns-signer and on any inline-signing secondary with
`parentsync` on tdns-auth. They are not caused by this change, but a pure
signer that "keeps child-side delegation sync" does not deliver it until they
are fixed. None is keyed on the app type, so the fixes change tdns-auth too,
and should: an inline-signing secondary there has the same defects.

**D1 — An NS or glue change that arrives by transfer never reaches the parent.**
The only automatic `SYNC-DELEGATION` is queued by the ZoneUpdater after a
*non-internal* ZONE-UPDATE (`v2/zone_updater.go:464`). Transfers bypass the
ZoneUpdater (`zone_utils.go:1185-1215` → `zone_mutation.go:811`).
`SetupZoneSync` runs at first load and on reload, never per refresh
(`parseconfig.go:1530-1553`, `refreshengine.go:1098-1110`). The only code that
diffs delegation data on an inbound transfer is the parentsync-proxy's pre-refresh
hook (`delsync_proxy.go:73-136`), which is agent-only. On a signer, whose only
input is a transfer, NS/glue sync therefore happens only when an operator runs
`/delegation sync`. The fix: a post-refresh hook for secondaries with
`parentsync` that runs `DelegationDataChangedNG` (`delegation_utils.go:365`)
and enqueues `SYNC-DELEGATION`, as the proxy hook does. Filed as #731.

**D2 — The DS engine's CDS is dropped by every inbound AXFR.** An AXFR
rebuilds the working set from the transfer (`zone_mutation.go:930`) and puts
back only what `CollectDynamicRRs` returns (`zone_mutation.go:940`,
`zone_utils.go:2032`): DNSKEY, the apex SIG(0) KEY, transport signals, and CDS
*only* for an owned multi-provider zone (`ownedZoneCDS`, `ds_engine.go:579`).
`followKeysWithCDS` does not restore it, because it returns early when no CDS
is served (`ds_engine.go:448`). The rollover engine re-publishes on its next
push, and its own comment records the churn
(`ksk_rollover_automated.go:265-270`). IXFR keeps local records
(`ixfr_in.go:729-745`), and a signing secondary requests IXFR by default since
#548. So the window is limited to the first load, an upstream that answers
IXFR with a full transfer, and any fallback to AXFR. During that window a parent
that scans for CDS sees none. The fix is to carry the DS engine's
current CDS through `CollectDynamicRRs` for signing zones, as it already does for
owned zones. Filed as #732.

**D3 — CSYNC is published only with `allow-updates`.**
`SyncZoneDelegationViaNotify` publishes the CSYNC under `if
zd.Options[OptAllowUpdates]` (`delegation_sync.go:566`), then sends
NOTIFY(CSYNC) regardless. A pure signer refuses `allow-updates`, so the
NOTIFY scheme would send the parent to look for a CSYNC that does not exist.
Filed as #557.

**D4 — CDNSKEY is never generated.** v2 builds CDS only. CDNSKEY appears in
signal-name republishing (`signal_republish.go:77`) and in the apex-retention
list (`zone_updater.go:116`), nowhere else. "Keeps CDS/CDNSKEY" currently
means CDS. Whether to add CDNSKEY is a DS-engine question (the DS models in
`docs/2026-09-13-ds-engine-design.md`), not a signer one.

**D5 — The sample config cannot run parentsync.** See 4.2. This is a
documentation defect, plus a missing config check.

## 6. Tiers of change

**Tier S — signer-only code.** Runs only in tdns-signer, so it cannot affect
another app. `StartSigner` belongs in v2 (`main_initfuncs.go`, next to
`StartAuth`), as #558 step 4 has it. It is new code that nothing else calls.

- `StartSigner`: `StartAuth` minus UpdateHandler, ScannerEngine and
  DsyncApiListener, plus `conf.Internal.DnsUpdateQ = nil` before DnsEngine,
  and the three NOTIFY refusals (4.1).
- `SetupSignerAPIRouter`: the kept routes only (3.2).
- `AppTypeSigner` itself, with its strings (#558 steps 1–2).
- A signer config check run only for `AppTypeSigner`: IMR on if any zone has
  `parentsync`; `childsync:` refused; `primary` refused in `dynamic.allowed`.
- `cmdv2/signer/main.go`, the sample configs, `guide/app-tdns-signer.md`.

**Tier G — gates in shared code, keyed on `AppTypeSigner`.** Each is an
`if Globals.App.Type == AppTypeSigner` (or `case`) at a site the other apps
also pass through. They are behaviour-neutral for those apps by construction,
and each needs a test that pins both arms.

- The #558 conversion: 18 `AppTypeAuth` sites to an `IsAuthoritativeAppType`
  predicate, plus the parse-based guard test. Current line numbers, which have
  moved since #558 was filed, are in Appendix B. Neutral for every existing
  app, and the prerequisite for everything else here.
- Primary refusal: static config, `/zone add`, persisted dynamic zones (3.3).
- Option refusal: `normalizeOptionsForRole`, `zoneOptionsFromStrings`, catalog
  group options (3.6).
- API command refusals in `/zone` and `/delegation` (3.2).
- ZoneUpdater backstop (4.3).
- `config check` in the CLI.

**Tier R — restructuring shared code.**

- D1 and D2 (§5) change the refresh path and `CollectDynamicRRs` for every
  signing secondary. That is intended, but it is not neutral for tdns-auth.
- Compile-time absence (§7).

## 7. Compile-time absence

The request was to size both options. Doing this with Go build tags or package
splits is what makes it expensive. The linker already does part of it, and
this section measures how much.

**Structure.** v2's top level is one package, `tdns`: 260 non-test files,
110,139 lines. It has no feature build tags today, only OS ones
(`reuseport_*.go`, `proc_status_other.go`). Code of the signer's removal set
lives in about 35 files:

| Area | Lines | Files |
|---|---|---|
| UPDATE receiver (DDNS, child, trust) | 2,735 | `updateresponder`, `update_policy_eval`, `bootstrap_ceremony`, `child_key_rebootstrap`, `truststore_verify`, `delegation_parent_first` |
| scanner | 2,408 | `scanner*.go` |
| proxies | 2,053 | `childsync_proxy`, `delsync_proxy*`, `parent_push_engine` |
| DSYNC API server and credentials | ~1,300 | `dsync_api_*` except `dsync_api_client.go` (child side, kept), `apihandler_dsync_api*` |
| delegation backends | 1,229 | `delegation_backend*.go` |
| catalog authoring API | 771 | `apihandler_catalog.go` |
| DSYNC publication | 630 | `ops_dsync.go` |
| dynamic primaries | 510 | `dynamic_primary.go` |
| API zone update | 202 | `zone_update_api.go` |

It is also interleaved with kept code in `zone_updater.go` (CHILD-UPDATE and
TRUSTSTORE-UPDATE arms), `zone_utils.go` (`SetupZoneSync`'s childsync and
proxy branches), `zone_hooks.go` (refresh hooks registered on every zone),
`apihandler_zone.go` (the `/zone` command switch), `notifyresponder.go` and
`sig0_validate.go`.

**What the linker already drops.** Go's linker removes functions that
nothing reachable references. To measure it, three builds of `tdns-signer`
were made from `e223451b` in a scratch module (recipe in Appendix C), counting
`T` symbols in `github.com/johanix/tdns/v2`:

| Build | Binary | tdns/v2 functions | What left |
|---|---|---|---|
| today's `main.go` (`StartAuth`) | 29.19 MB | 3,785 | — |
| engines started one by one, minus UpdateHandler, ScannerEngine, DsyncApiListener | 28.68 MB | 3,496 | ~140 function families: `UpdateResponder`, `ApproveUpdate`/`ApproveChildUpdate`/`ApproveTrustUpdate`, `ValidateUpdate`, `TrustUpdate`, `FindSig0KeyViaDNS`, `ScannerEngine` and nearly all `(*Scanner)` methods, CSYNC processing, the DSYNC API server and its authentication |
| the above plus a signer-only router (no `/catalog`, `/zone/childsync`, `/dsync-api/*`, `/scanner/poll`) | 28.45 MB | 3,358 | catalog authoring, DSYNC credential management, the childsync API |

**What stays linked, and why.** After the third build these are still present,
each reachable from something the signer keeps:

| Still linked | Reached through |
|---|---|
| `ApiZoneUpdate`, `queueApiZoneUpdate` | the `/zone` handler's `update` case |
| `ProvisionDynamicZone`'s primary path, `provisionDynamicPrimary` | the `/zone` handler's `add` case |
| `ApplyChildUpdateToZoneData`, the three `DelegationBackend.ApplyChildUpdate` | `ZoneUpdaterEngine`'s CHILD-UPDATE arm |
| `PublishDsyncRRs`, `BuildDsyncPublication` | `SetupZoneSync`'s childsync branch |
| all of childsync-proxy and parentsync-proxy | `registerStandardRefreshHooks`, which registers both on every zone |
| `AutoConfigureZonesFromCatalog`, `ParseCatalogZone` | the refresh engine (catalog consumption; may be wanted, Q2) |

**Three ways to finish the job.**

- **(a) Reachability pruning, no build tags.** Split the five dispatch points
  above so the signer's entry points do not reference the removed arms. For
  example, a `/zone` command table from which the signer's router builds its own
  handler; ZoneUpdater arms looked up by command; hook registration that
  depends on the zone's options instead of being unconditional. Pin the result
  with a test that builds tdns-signer and asserts, by `go tool nm`, that a
  named list of symbols is absent. Medium: each split is a refactor of shared
  code, but it is also an improvement in its own right. Cost to other apps:
  none if the split is behaviour-preserving, which their existing tests check.
- **(b) Build tags.** `//go:build !puresigner` on the ~35 files, with a
  `puresigner` stub file for every symbol that kept code references. The
  stubs are the cost: the interleaved sites above need either stubs or
  restructuring anyway. Every v2 test run then needs both tag sets, and CI
  doubles for v2. Not recommended: it adds a permanent build dimension, and
  buys little over (a).
- **(c) Package split.** Move the receivers into subpackages. Methods on
  `*ZoneData` and `*KeyDB` cannot be defined outside package `tdns`, and most
  of this code is such methods. This is the largest option and not
  recommended.

**Recommendation.** Do the runtime gates (Tiers S and G). They already make the
removed code unreachable from the network: an engine that is not started
cannot be reached, and UPDATE answers NOTIMP. Then do (a) when there is a
reason to shrink the binary's attack surface, and treat "absent from the binary"
as a property a test checks, rather than a build configuration.

## 8. Staging and size

Each stage is one PR and leaves every app working. Sizes are non-test lines,
estimated from the sites above, not measured.

| # | Stage | Tier | Size | Depends on |
|---|---|---|---|---|
| 0 | D1 (#731), D2 (#732), D3 (#557) | R | D1 ~150, D2 ~40, D3 ~10 | — |
| 1 | #558 steps 1–4: `AppTypeSigner`, predicate over the 18 sites, guard test, `StartSigner` as an exact clone of `StartAuth`, CLI role wiring | S + G | ~200 | — |
| 2 | `StartSigner` drops UpdateHandler, ScannerEngine, DsyncApiListener; UPDATE → NOTIMP; NOTIFY(CDS/CSYNC/DNSKEY) refused | S | ~60 | 1 |
| 3 | refuse primary zones (static, dynamic, persisted) and the refused options on all four paths; signer config check | G + S | ~150 | 1 |
| 4 | `SetupSignerAPIRouter`; `/zone` and `/delegation` command refusals | S + G | ~150 | 1 |
| 5 | ZoneUpdater backstop | G | ~30 | 2, 3, 4 |
| 6 | guide, samples, `main.go` comment | — | docs | 2–5 |
| 7 | (optional) reachability pruning, symbol test | R | ~400–800 | 5 |

Stages 1–6 total about 600–800 lines, plus perhaps as much again in tests.
Stage 1 is the only one that touches many sites, and it is mechanical. The
rest are small, local, and keyed on the new type. Stage 0 is independent,
benefits tdns-auth as well, and should come first: without D1–D3, stage 2's
"keeps child-side sync" is not true.

Stage 1 makes the signer behave identically to tdns-auth. That is what makes
stages 2–5 attributable one at a time, the order #558 recommends. A live
pipeline run (upstream → signer → downstream, with a KSK roll against a
parent) after each of stages 2–5 is the test that matters. Each stage's unit
tests pin the gate. The pipeline shows that nothing the signer still needs
went with it.

## 9. Open questions

- **Q1. Plain secondaries on a signer.** A zone without `inline-signing` is
  served unsigned (`guide/app-tdns-signer.md`). On a pure signer that zone
  has no purpose. Refuse it, or allow it as a pass-through? The predicate from
  stage 1 keeps it immutable either way.
- **Q2. Catalog consumption.** Catalog member zones are created as plain
  secondaries with the config group's raw options (`catalog.go:405-424`), and
  a config group has no `dnssecpolicy` (`config.go:769-775`). So a member
  cannot be inline-signed, and catalog consumption provisions zones the
  signer cannot sign. Refuse `catalog-zone` on the signer until config groups
  can carry a policy?
- **Q3. UPDATE answer.** NOTIMP via a nil queue is free. REFUSED with an EDE
  saying "this is a signer" needs a registered UPDATE handler
  (`RegisterUpdateHandler`, `registration.go:258`), about 20 lines. The EDE is
  kinder to an operator who pointed a DDNS client at the wrong server.
- **Q4. `bump`, `write-zone`, journal `purge`.** Kept above as operational.
  `bump` advances the serial with no content change, which on a signer only
  forces a downstream re-transfer. Journal `purge` discards internal deltas
  (CDS, KEY) not yet written to the file, which on a secondary is harmless
  after D2.
- **Q5. Who owns NS/glue sync.** Only the signer can publish a signed CSYNC,
  or a KEY the parent will see in the served zone, so the signer owns
  delegation sync for both DS and NS. That makes D1 a precondition, not a
  nicety. Is that the intended split, or should NS sync stay with the
  operator's own tooling at the upstream?
- **Q6. CLI role name.** #558 notes that tdns-mp already claims the role name
  `signer` in the CLI registry. The pure signer needs a role name for
  `config check` and `tdns-ncli`. Which one?

## Appendix A: management API commands the signer keeps

From a survey of every handler registered by `SetupAPIRouter`
(`v2/apirouters.go:79`):

- `/zone` (`apihandler_zone.go`): `bump` :81, `write-zone`/`sync` :97,
  `get-name` :123, `get-delegation` :145, `journal` (`zone_journal.go:384-412`),
  `sign-zone` :184, `resign-zone` :192, `policy-set` :200, `change-policy` :207,
  `policy-reset` :214, `zonemd` :228, `show-nsec-chain` :243, `reload` :309,
  `list-zones` :319, `add` (secondary, allowed options) :345, `delete` :377,
  `modify` (allowed options) :386, `list-dynamic` :405.
- `/zone/parentsync`: `status`, `bootstrap`, `roll-key`, `inquire`
  (`apihandler_zone.go:1159-1227`).
- `/keystore`: all of `sig0-mgmt`, `dnssec-mgmt`, `tsig-mgmt`,
  `list-algorithms`, `list-policies`. `dnssec-mgmt clear` and `policy-cleanup`
  strip RRSIGs and re-sign, which is the signer's own content.
- `/truststore`: all.
- `/delegation`: `status` :540, `sync` :561.
- `/rollover/*`, `/config/paths`, `/imr`, `/command`, `/config`, `/debug`,
  `/ping`: all.

## Appendix B: `AppTypeAuth` sites at `e223451b`

18 non-test sites. #558's line numbers have moved. Classes: (a) positive, (b)
negated — a new type flips it, (c) case list whose default drops a new type.

| Site | Class | A new type without the predicate would |
|---|---|---|
| `zone_refresh_state.go:325` | b | never expire a secondary (`HasExpired` always false) |
| `zone_origination.go:46` | b | stand down every origination gate |
| `zone_option_normalize.go:93` | b | skip option normalisation |
| `parseconfig.go:1661`, `:1672` | b | lose the serial-suppression warnings |
| `main_initfuncs.go:136` | c | get no KeyDB |
| `parseconfig.go:729` | c | skip `ParseAuthOptions` |
| `parseconfig.go:752` | c | get no KeyDB, and no KeyDB refresh on reload |
| `config_validate.go:206` | c | skip the `db.file` check |
| `config_validate.go:178` | a | nothing (the default arm matches) |
| `zone_utils.go:1967` | a | lose child-side delegation sync setup |
| `apirouters.go:99`, `:119`, `:138` | a | lose `/keystore` and the rest, `/rollover/*`, `/imr` |
| `parseconfig.go:779` | a | lose `ServerSVCB` (transport signals; refused anyway) |
| `v2/cli/config_check_cmds.go:308` | a | (CLI default) |
| `cmdv2/auth/main.go:27`, `cmdv2/signer/main.go:82` | assignment | — |

`zone_utils.go:1965` carries the comment "Combiner and signer roles don't do
child delegation sync". It refers to the tdns-mp signer, and needs rewording
once `AppTypeSigner` exists.

## Appendix C: reproducing the linker measurement

In a scratch directory, copy `cmdv2/signer/{main.go,go.mod,go.sum}`, point the
`replace` lines at an absolute `v2/`, and add a `version.go` defining
`appVersion`, `appName` and `appDate`. `algs.list` needs no generated files,
because `metadata_algs.go` registers through `init` and nothing references it.
Build with `CGO_ENABLED=1 go build`. For the second and third builds,
replace `conf.StartAuth` with the kept engines started one by one (they are
all exported, except `loadDynamicZonesIfConfigured`, which the measurement
leaves out), and replace `SetupAPIRouter` with a router registering only the kept
handlers. Compare `go tool nm <binary> | grep ' T ' | grep tdns/v2` across the
builds, after folding closure suffixes (`.funcN`, `.deferwrapN`,
`.gowrapN`) into their parent function. Inlining renames some closures between
builds, so the counts are approximate and the named families are the result.
