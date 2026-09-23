# Delegation sync on refresh: the proxy's detector for every child

**Written 2026-09-23.** Merged as #734. Line references are to main at
`f255d19a`. For #731, which it widens: the gap is not specific to signing
secondaries. Any `parentsync` zone whose content changes by a refresh, whether
a transfer or a zone-file reload, never tells its parent about an NS or glue
change.

**Status:** merged as #734, after an external review (adopt; the predicate
for multi-provider zones and the reason this is independent of KLO are now
pinned, and Q-c is decided). Stage 1 is in review (#740); stages 2 and 3 are
implemented on a branch stacked on it (§10), not yet run live (L1, L2).
Amended 2026-09-23, at the end.

## Summary

- tdns-agent already detects delegation changes in every incoming zone
  (parentsync-proxy). A pre-refresh hook compares the served zone with the
  incoming one, and a post-refresh hook queues `PROXY-SYNC`. The hooks are
  attached to every zone on every app. Only their gate keeps them to the
  proxy.
- **Opening that gate to `parentsync` zones as it stands would be unsafe.**
  The proxy compares DNSKEY, CDS and the DS derived from the DNSKEYs. On a zone
  that signs its own content, those are ours, and they are put back only after
  the swap. After an AXFR from an unsigned upstream, the incoming zone has
  none, so the comparison reports every DS removed. The child's default
  delta UPDATE would then delete the zone's DS at the parent. This was checked
  with a test: one `DS … NONE` in the UPDATE for the zone's only KSK.
- **Proposal:** the same hooks, with a second mode for children.
  - It compares NS and glue only.
  - It acts by comparing the zone's NS and glue with the parent
    (`AnalyseZoneDelegation` without its DS step), not by sending the
    difference between two versions.
  - It leaves DS out of what it sends.
  - It retries a failure the way the proxy does.
  - It runs once at startup as well, which the child side has never done.

  Proxy mode is unchanged. Size: about 180 lines of non-test code and 350 of
  tests.
- The three questions asked about this (answered in §6–§8):
  - **Does tdns-agent do the right thing?** In steady state, yes. One
    deviation: it re-sends to the parent on every restart.
  - **Does tdns-auth?** Per configuration:
    - **Unsigned primary:** partly. NS and glue reach the parent only when they
      change by DNS UPDATE or the API, and a failed sync is not retried.
    - **Signing primary:** the same, and in addition, under the default
      `rollover.method: none`, no DS reaches the parent without a manual
      `delegation sync`.
    - **Signing secondary:** no. NS and glue never reach the parent, and the
      CDS is lost at every AXFR.
  - **Should this wait for key lifecycle ownership (KLO)?** No: the NS and
    glue sync proposed here is independent of it. The CDS half (#732) is not,
    and should be coordinated with it.

## 1. How the agent detects a delegation change

All in `v2/delsync_proxy.go`.

| Step | Where | What |
|---|---|---|
| Attach | `registerStandardRefreshHooks`, `v2/zone_hooks.go:69` | Called from all six zone-construction paths, for every zone on every app (`parseconfig.go:1024`, `dynamic_zones.go:961, 1276`, `dynamic_primary.go:466`, `catalog.go:434`, `refreshengine.go:1120`). |
| Gate | the closures, `:72-95` | `parentsync-proxy`, read under `zd.mu` at every refresh, so a reload takes effect without a restart. |
| Compare | `ProxyDelegationPreRefresh`, `:103` | Before the swap, served zone against incoming zone: apex CDS and CSYNC, NS and glue plus DS (`DelegationDataChangedNG`), DNSKEY (`DnskeysChangedNG`). Stored in `zd.ProxyRefreshAnalysis`. |
| Act | `ProxyDelegationPostRefresh`, `:175` | After the swap: a non-blocking send of `PROXY-SYNC` to the syncher. |
| Send | `v2/delegation_sync.go:168-187`, `proxySync` `:841` | Waits for the IMR. Builds one sync plan (`SyncRoleProxy`) and walks UPDATE, API and NOTIFY in the operator's order. |
| Retry | `:810-857` | 30 s, 2 m, 8 m, 30 m. A retry is dropped when a later sync has succeeded. |
| Startup | `ProxyStartupReconcile`, `v2/delsync_proxy_update.go:471` | Queued from `SetupZoneSync` (`zone_utils.go:2013`). Compares the served zone with the parent, and sends only if they differ. |

The hooks run on both refresh paths: `FetchFromUpstream`, for AXFR and IXFR
alike (`v2/zone_utils.go:1186`), and `FetchFromFile` (`:740`).

## 2. Why the gate cannot simply be opened

The proxy serves the zone of a primary that signs it. Every record the proxy
compares comes from upstream. A zone that signs its own content is different:
its DNSKEYs, its CDS and the DS derived from them are its own. They are
restored only after the swap (`CollectDynamicRRs`,
`applyRefreshReplacementLocked`).

**After an AXFR from an unsigned upstream, the incoming zone has none of
them.** With a served zone holding a KSK and a CDS, and an incoming zone with
the same NS and glue and a higher serial:

| Comparison | Reports |
|---|---|
| `DelegationDataChangedNG` (`v2/delegation_utils.go:366`) | changed, 0 NS adds, 0 NS removes, **1 DS remove**, `NewDSKnown` false |
| `DnskeysChangedNG` (`:609`) | changed |
| proxy analysis | CDS, CSYNC and DNSKEY changed |

Handed to the child's `SYNC-DELEGATION`, that becomes, in delta mode (the
child's default, `childUpdateMode`), an UPDATE whose one record is
`<zone> 0 NONE DS …`: a delete of the zone's DS at the parent
(`buildDelegationUpdate`, `v2/delsync_update.go:82-87`). Measured with a scratch
test against this tree.

After an IXFR, the incoming zone is the published snapshot plus the delta
(`materializeForIxfr`). It still carries our DNSKEYs and CDS, so none of this
fires. The same zone gives a different answer depending on the transfer type.

`DelegationDataChangedNG` itself must keep its DS part. tdns-mp calls it from
its own pre-refresh hook (`tdns-mp v2/hsync_utils.go:1307`), for zones whose
DNSKEYs do come from upstream (the combiner).

## 3. The child's trigger today

- **The only automatic `SYNC-DELEGATION`** is queued by the ZoneUpdater after
  an applied ZONE-UPDATE that is not internal (`v2/zone_updater.go:464`). That
  means DNS UPDATE and the API only.
- **It sends a difference between two versions.** A failure is logged and
  dropped (`v2/delegation_sync.go:88`). Nothing asks again. The comment
  saying "the next load re-detects it" (`v2/zone_updater.go:463`) is not true:
  nothing at load compares the zone with the parent.
- **At load**, `SetupZoneSync` queues `DELEGATION-SYNC-SETUP` for the UPDATE
  scheme (`v2/zone_utils.go:1966-1990`). That bootstraps the SIG(0) key and
  polls KeyState. The poll "does not start a delegation sync"
  (`v2/parentsync_bootstrap.go:117-119`). For the NOTIFY scheme, nothing is
  queued.

This is #722's failure shape on the child side. The proxy fixed it with a
startup reconcile, replace-form UPDATEs and retries. The child has none of
them.

## 4. Proposal

### 4.1 One hook pair, two modes

Rename `registerProxyDelegationHooks` to `registerDelegationChangeHooks`. The
closures pick a mode at each refresh:

| Mode | When | Compares | Acts |
|---|---|---|---|
| proxy | `parentsync-proxy` | as today: CDS, CSYNC, NS and glue, DNSKEY | `PROXY-SYNC`, as today |
| child | `parentsync`, not `multi-provider`, and the app gate `SetupZoneSync` uses for `parentsync` (`v2/zone_utils.go:1966`; `AppTypeAuth` today, the #558 predicate later) | **NS and glue only** | `REFRESH-SYNC-DELEGATION` (4.3) |

The two options are already mutually exclusive (`v2/parseoptions.go:408`).
Multi-provider zones are left to tdns-mp's own hooks.

**The child-mode predicate, stated once:** `parentsync` and not
`multi-provider` and not `parentsync-proxy`, on the authoritative app types
(`AppTypeAuth` today; the #558 predicate, which adds tdns-signer, later). Every
place that queues or runs `REFRESH-SYNC-DELEGATION` uses this one function:
the post-refresh closure, the startup queue (4.5) and the syncher arm (4.3).

It is **not** the condition of `SetupZoneSync`'s `parentsync` branch
(`v2/zone_utils.go:1966-1968`). That branch also admits a registered
multi-provider agent app with a `multi-provider` zone (pinned by
`TestZoneSyncSetupRunsForARegisteredMultiProviderAgentApp`), for KLO S5's
setup on the tdns-mp agent. Anything queued inside that branch would reach
every multi-provider agent, not only the elected leader, and send around
tdns-mp's leader gate (KLO Q2).

Child mode compares no DNSKEY, CDS or DS, for any zone. For a zone that signs
its own content, those are ours (§2). For a zone that does not sign, tdns
holds no keys, so its DS intent is unknown, and the parent's DS is not ours to
change (`compareParentDS`, `v2/delegation_utils.go:297`). Either way, DS is
the DS engine's and the rollover engine's to send. §7 says how much of that
happens today.

### 4.2 A comparison of NS and glue alone

Move the NS and glue part of `DelegationDataChangedNG`
(`v2/delegation_utils.go:400-494`) into its own function. Child mode calls it.
`DelegationDataChangedNG` calls it and then runs its DS block unchanged, so
the proxy and tdns-mp see no difference.

The pre-refresh closure in child mode records only a bool, "NS or glue
changed". The action does not use the comparison's contents (4.3).

### 4.3 Act by comparing with the parent

After the swap, child mode queues `REFRESH-SYNC-DELEGATION`. The syncher's arm:

1. **Refuses a zone that fails the child-mode predicate** (4.1), a
   `multi-provider` or owned zone above all, so a stray request cannot send.
2. **Waits for the IMR**, as the `PROXY-SYNC` arm does (`delegation_sync.go:176-185`).
3. **Compares the served zone's NS and glue with the parent.** This is
   `AnalyseZoneDelegation` without its DS step (`compareParentDS`,
   `v2/delegation_utils.go:236`). A parameter or a split function; the NS and
   glue steps are shared. The DS fields are then empty and `NewDSKnown` is
   false by construction: `declareDelegationFromChild` deliberately takes no DS
   (`v2/delegation_utils.go:47-59`), and only `compareParentDS` sets them. This
   also saves the parent DS query and the DS-intent lookup.
4. **Stops if in sync.** Otherwise it calls `SyncZoneDelegation`.
5. **Retries a failure** (4.4).

**Why compare with the parent rather than send the difference:**

- **What gets sent is measured against what the parent holds.** A withdrawn
  nameserver is removed at the parent even if an earlier sync failed, or the
  withdrawal happened while the server was down.
- **Asking twice sends once.** That matters because a primary's file reload
  can replay a change the UPDATE path has already synced. KLO's leader uses
  the same rule for the same reason (tdns-mp
  `docs/2026-09-13-key-lifecycle-ownership-design.md` §4.1: "the explicit sync
  analyses first and sends only a difference").
- **The comparison of versions only decides whether to ask the parent.** It is
  cheap and needs no network. The parent is queried only after an NS or glue
  change, not after every content change.

**Why leave DS out (decided, Q-c).** The trigger is NS and glue, so the action
is too. DS belongs to the DS engine and the rollover engine. Sending it here
would make this path a second DS sender beside the rollover engine, with its
own view of the DS set. During a multi-DS roll, that view could undo a DS the
rollover had just placed. DS engine design step 2 (KLO §6, S6) moves the
rollover engine's pushes into the syncher, and that is the place to decide how
DS and NS syncs combine. Every scheme supports "DS unknown":

- **delta UPDATE** carries no DS records;
- **replace UPDATE** with `NewDSKnown` false leaves the parent's DS untouched
  (`v2/childsync_utils.go:350-351`);
- **the API client's consistency check** accepts an empty DS delta
  (`v2/dsync_api_client.go:808`);
- **NOTIFY** sends NOTIFY(CDS) only for a DS delta (`v2/delegation_sync.go:621`),
  so only NOTIFY(CSYNC) goes.

The NOTIFY scheme still depends on #557: the CSYNC that NOTIFY(CSYNC) points to
is published only with `allow-updates`.

### 4.4 Retries

Rename `proxySyncRetryDelays`, `nextProxySyncRetry`, `proxyRetrySuperseded` and
`zd.proxyLastSyncOK` (`v2/delegation_sync.go:810-835`, `v2/structs.go:217`) to
general names. Both arms use them. Same delays, same superseding rule.

### 4.5 Startup

In child mode, the first load compares nothing, because there is no served
zone yet (`DelegationDataChangedNG` returns false). So `SetupZoneSync` queues
one `REFRESH-SYNC-DELEGATION` after `DELEGATION-SYNC-SETUP`, for every scheme,
**gated on the child-mode predicate (4.1) and not placed inside the
`parentsync` branch's condition**. A multi-provider agent still gets its SETUP
and gets no `REFRESH-SYNC-DELEGATION`.
Because it compares with the parent, it sends nothing when the parent is
already in sync, and it catches changes made while the server was down:
file edits, and syncs that ran out of retries. It is the child's version of
`ProxyStartupReconcile`.

With the UPDATE scheme, a sync that reaches the parent before the SIG(0)
bootstrap is accepted is refused. The walk moves to the next scheme, or the
retry covers it.

## 5. What changes, per app

| App / zone | Today | With this |
|---|---|---|
| tdns-agent, `parentsync-proxy` | as §1 | unchanged |
| tdns-auth primary, `parentsync`, change by UPDATE or API | ZoneUpdater `SYNC-DELEGATION`, no retry | unchanged (Q2) |
| tdns-auth primary, `parentsync`, zone-file edit + reload | nothing | NS/glue synced after the reload |
| tdns-auth signing secondary / tdns-signer, `parentsync` | nothing | NS/glue synced after the transfer |
| any `parentsync` child, restart | SIG(0) bootstrap only | plus one compare-with-parent |
| multi-provider zones (tdns-mp) | tdns-mp's hooks | unchanged |

## 6. Question 1: does tdns-agent do the right thing today?

In steady state, yes:

- It detects a change on either transfer type and forwards it over whichever
  scheme works.
- It retries for about forty minutes.
- It keeps NS withdrawals across a failed sync (#724: `proxyParentOnlyNS` and
  replace form).

Two things are not as the code describes them:

- **Every restart re-sends.** On the first load there is no served zone, so
  the comparison reports CDS, CSYNC and DNSKEY all changed
  (`DnskeysChangedNG` returns true when the served zone is not ready,
  `v2/delegation_utils.go:614-624`; checked with a scratch test). The
  post-refresh hooks the first load deferred then run (`v2/refreshengine.go:341, 446`),
  and each proxied zone queues a `PROXY-SYNC`. That happens alongside
  `ProxyStartupReconcile`, whose comment says it catches drift "WITHOUT
  re-sending on every restart" (`v2/delsync_proxy_update.go:461`).

  Bad, but idempotent: replace UPDATEs repeat harmlessly, and a repeated
  NOTIFY costs the parent a scan. It is also, by accident, what makes the log's
  "the next change or a restart will try again" (`v2/delegation_sync.go:853`)
  true. The fix is to skip the proxy's comparison on a first load, since the
  startup reconcile already covers it. That is a change to tdns-agent, so it
  is left out of this proposal (Q-a, #735).
- **Out of scope, noted.** The proxy's UPDATE and API derive the DS set from the
  served SEP DNSKEYs (`currentDelegationRRs`, `v2/delsync_proxy_update.go:403`),
  not from the primary's CDS. A primary whose CDS says something else (a
  delete, or a KSK it is not ready to put at the parent) is not followed.

## 7. Question 2: does tdns-auth do the right thing today?

Per configuration, for a zone with `parentsync`. "Yes" means the change
reaches the parent with nobody running `delegation sync` by hand.

**What all three have in common: NS and glue.**

| Change arrives by | Reaches the parent? |
|---|---|
| DNS UPDATE or API `update` | Yes: ZoneUpdater → `SYNC-DELEGATION`, delta by default. NS removals go to the parent first (`applyParentFirst`). A failure is dropped with no retry (`v2/delegation_sync.go:88`). |
| Zone-file edit, picked up by `zone reload`, SIGHUP, config reload or the daily re-stat (`FindSoaRefresh`, `v2/refreshengine.go:1438`) | **No.** `FetchFromFile` runs the pre- and post-refresh hooks, but only the proxy mode is attached. |
| Inbound transfer (a secondary's only way in) | **No**, for the same reason. |
| Anything, while the server was down | **No.** Startup bootstraps the SIG(0) key and never compares with the parent (§3). |

**What differs: DS.** It depends on `rollover.method` in the zone's DNSSEC
policy.

- **`multi-ds`:** the rollover engine keeps the parent's DS in step with its
  target and pushes it itself, with its own scheme selection and retries. That
  path is not examined here.
- **`none`**, which is the default: `rollover.method` unset parses as `none`
  (`v2/ksk_rollover_policy.go:403-404`). **Nothing sends DS to the parent
  automatically**, neither the first DS after the zone is signed nor a KSK
  changed by hand:
  - The rollover engine returns at once for `none`
    (`v2/ksk_rollover_automated.go:87-89`).
  - The DS engine serves a CDS only once delegation sync has asked for one
    (`v2/ds_engine.go:443-448`), and delegation sync asks only on the NOTIFY
    scheme, for a sync that carries a DS difference
    (`v2/delegation_sync.go:621-622`). Only an explicit `delegation sync`, or a
    DNS UPDATE that changes DNSKEYs, produces such a sync.
  - Until then, a parent that scans for CDS finds none.

  The DS engine design names the gap: its step 3, periodic reconciliation of
  each zone's DS target with the parent (`docs/2026-09-13-ds-engine-design.md`),
  is not implemented. Filed as #736.

### 7.1 Unsigned primary

**Partly.**

- **NS and glue:** synced when the change comes by UPDATE or the API. Not
  synced when it comes by a zone-file edit or while the server was down. A
  failed sync is not retried.
- **DS:** nothing to do.
- **Schemes:** NOTIFY is left out of the plan for an unsigned zone
  (`zoneIsSigned`, `v2/delegation_sync_plan.go:383`), so only UPDATE and API
  are used.

### 7.2 Signing primary

**Partly, and not at all for DS under the default policy.**

- **NS and glue:** as for the unsigned primary. The NOTIFY scheme also has
  #557: the CSYNC is published only with `allow-updates`, so a zone changed
  through the API alone (`allow-api-updates`) gets a NOTIFY(CSYNC) with no
  CSYNC behind it.
- **DS:** fine with `multi-ds`. With `none`, nothing is sent until an operator
  runs `delegation sync` (above).
- **CDS:** survives a zone-file reload. Every applied ZONE-UPDATE, the DS
  engine's internal ones included, is written to the journal
  (`v2/zone_updater.go:944`), and a reload merges the journal back over the
  file (`MergeJournalOverNewFile`, `ReplayPersistedDeltas`,
  `v2/refreshengine.go:576, 643`).

### 7.3 Signing secondary (bump-on-the-wire)

**No.**

- **NS and glue:** never synced. Transfers are its only input (#731).
- **DS:** as for the signing primary: fine with `multi-ds`, manual with `none`.
  The signer's sample policies set no `rollover.method`
  (`cmdv2/signer/tdns-signer.sample.yaml:139`), so they are `none`.
- **CDS:** lost at every AXFR (#732). A secondary has no journal merge on
  transfer, and a signing secondary requests IXFR by default but falls back to
  AXFR.
- **CSYNC:** the same loss, and #557.
- **CDNSKEY:** never generated.
- **The signer's sample config turns the IMR off**
  (`cmdv2/signer/tdns-signer.sample.yaml:90`), and delegation sync cannot run
  without it (`docs/2026-09-23-pure-signer.md` §4.2).

The design fixes the NS and glue rows for all three. It leaves DS where it is:
the DS engine's step 3 is the DS counterpart of §4.5's compare-with-parent,
and S6 (§8) is where the two senders meet. Routing the UPDATE and API path
through the same compare-with-parent command, to get retries, is Q-b.

## 8. Question 3: fix this before key lifecycle ownership is complete?

Yes. The NS and glue sync proposed here is independent of KLO, and **the
independence comes from this command never sending DS**. It does not come
from KLO being about multi-provider zones: S1a, S1b, S2 and S6 are tdns
changes, and S6 (DS engine design step 2) moves the rollover engine's parent
pushes into this same syncher. That is why Q-c is decided as "leave DS out".

- **It never sends DS, for any zone.** The DS engine and the rollover engine
  keep that job, and S6 is where DS and NS syncs get combined. The shared retry
  helpers (4.4) are something S6 can use.
- **It never queues or sends for a `multi-provider` zone** (the predicate in
  4.1, at every place the command is queued or run). tdns-mp keeps its own
  pre-refresh hook, and its leader gate (KLO Q2) sees no second sender.
- **It does not touch the keystore interface or DS intent.** The analysis it
  runs skips the DS step (4.3), so `DSIntentForZone`, which KLO S2 made
  owner-aware, is not even called.
- **`DelegationDataChangedNG` keeps its behaviour** (4.2), so tdns-mp's call
  site sees no change.

What should be coordinated with KLO is **#732**, the CDS lost on AXFR. KLO
arrow 1 (§4.1, S5) already restores the CDS of an owned multi-provider zone in
`CollectDynamicRRs` (`ownedZoneCDS`). Extending that to tdns's own signing
zones reads the DS engine's content: the `ds` column, or, during a rollover,
the rollover target. That is KLO's territory, and the fix should follow KLO's
arrow-1 mechanism rather than invent a second one.

KLO is paused at the moment. Nothing here needs it restarted.

## 9. Tests

| # | Test |
|---|---|
| T1 | Child mode, signer after AXFR: the served zone has DNSKEY and CDS, the incoming zone has neither, same NS and glue. No trigger. And the arm, run on that zone anyway against a fake parent holding its DS, sends nothing that touches DS. (The case §2 measured, with the opposite outcome.) |
| T2 | Child mode: an added NS with glue, a removed NS, and a changed glue address each trigger; a serial-only change does not. Run on the AXFR shape and the IXFR shape. |
| T3 | No DS in what is sent: with the parent holding a different DS and a different NS set, the analysis reports only the NS difference; the delta UPDATE carries no DS record, the replace UPDATE has `NewDSKnown` false and leaves DS alone, and the API payload declares no DS. |
| T4 | NS and glue in sync, DS different: nothing is sent. |
| T5 | Retry: a failure is re-queued on the proxy's schedule; a retry is dropped after a later success. Both arms. |
| T6 | Gates: a `parentsync-proxy` zone still runs proxy mode with all four comparisons (the existing `delsync_proxy_*_test.go` stay green unchanged); `multi-provider` and no-`parentsync` zones run neither mode. The syncher arm refuses a `multi-provider` zone handed to it directly. |
| T7 | `FetchFromFile` on a primary with `parentsync` and an edited file triggers. |
| T8 | Startup: first load queues one `REFRESH-SYNC-DELEGATION` after `DELEGATION-SYNC-SETUP`; a parent already in sync gets nothing. A registered multi-provider agent app with a `parentsync` + `multi-provider` zone queues SETUP and no `REFRESH-SYNC-DELEGATION`. |
| L1 | Live: tdns-signer behind an unsigned primary. The primary adds an NS; the parent follows. The signer's KSK stays at the parent across an AXFR. |
| L2 | Live: a tdns-auth primary with an edited zone file and `zone reload`; the parent follows. Restart with an offline edit; the parent follows once, and not again on the next restart. |

## 10. Staging

| # | Change | Size (non-test) | Status |
|---|---|---|---|
| 1 | The NS-and-glue comparison as its own function; `DelegationDataChangedNG` calls it. No change in behaviour. | ~40 | in review, #740 |
| 2 | Child mode and its predicate, `REFRESH-SYNC-DELEGATION` with the NS-and-glue analysis, shared retry helpers. | ~110 | implemented, stacked on #740 |
| 3 | The startup compare-with-parent from `SetupZoneSync`. | ~20 | implemented, stacked on #740 |

Stage 1 is a refactor with no change in behaviour, and the existing tests pin
it. Stages 2 and 3 can go in one PR. #557 is independent, but needed before
the NOTIFY scheme's NS sync means anything.

## 11. Open questions

- **Q-a.** Skip the proxy's comparison on a first load, so a restart stops
  re-sending (§6). It changes tdns-agent: filed as #735. It has to follow
  #737's B2: until the startup reconcile has a DS dimension, the re-send is
  what resyncs DS at restart.
- **Q-b.** Move the ZoneUpdater's `SYNC-DELEGATION` (UPDATE and API changes) to
  the compare-with-parent command, for its retries? Parent-first NS removal
  and `ParentSyncDone` have to keep working, so it is not a one-line change.
- **Q-c.** Decided: leave DS out of the refresh-triggered sync (4.3, §8).
- **Q-d.** The proxy follows the primary's DNSKEYs rather than its CDS for DS
  (§6). Filed as #737, with the rule already agreed in
  `docs/2026-08-23-proxy-delegation-sync-scope.md` (B1, B2): deliver CDS or
  CDNSKEY when present, no DS opinion when a signed child has none, and
  remove the parent's DS for a child with no DNSKEY RRset.

## Amendment, 2026-09-23: stage 1, and what the code showed (#731)

- **Stage 1 needed tests of its own.** §10 says the existing tests pin it.
  They pinned only `NsAdds`, `NsRemoves` and the proxy's `NsOrGlueChanged`.
  Nothing asserted `DelegationDataChangedNG`'s glue deltas, the record form of
  a removal, or its DS block, which tdns-mp reads. Stage 1 adds them first
  (`v2/delegation_changed_ng_test.go`).
- **Names.** The NS-and-glue comparison is `diffNSAndGlue`. The apex lookup it
  shares with `DelegationDataChangedNG` is `delegationApexes`.
- **Pinned as found.** An in-bailiwick nameserver that stays in the NS set but
  loses every record has its glue listed for removal, while the delegation is
  reported unchanged. Stage 1 keeps that.
- **4.3 is a split, not a parameter.** tdns-mp calls `AnalyseZoneDelegation`
  with one argument.
- **4.4 and T6.** The rename in 4.4 reaches `delsync_proxy_retry_test.go`,
  which T6 says stays unchanged. Decided 2026-09-23: rename the references
  there and in `use_hsyncparam_test.go`, and change no assertion.
- **4.5 runs on reload too.** `SetupZoneSync` also runs when the configuration
  of a loaded zone is reloaded, so the compare-with-parent runs then as well.
  An in-sync parent gets nothing.
- **Sizes.** The non-test estimates hold. Tests come to about 500–600 lines,
  not 350: no fake parent exists for `AnalyseZoneDelegation` (T1, T3, T4, T8),
  and the syncher arm needs a seam, because `SyncZoneDelegation` discovers
  DSYNC through the IMR.

## Amendment, 2026-09-23: stages 2 and 3 as built (#731)

- **Where.** `v2/delsync_refresh.go`: `childDelegationSyncPredicate`, the
  two-mode `registerDelegationChangeHooks` (moved from `delsync_proxy.go`), the
  child-mode hooks and the `REFRESH-SYNC-DELEGATION` arm. The analysis is
  `analyseNSAndGlue`, split out of `AnalyseZoneDelegation` (4.3). The retry
  helpers are `delegationSyncRetryDelays`, `nextDelegationSyncRetry`,
  `delegationSyncRetrySuperseded` and `zd.delegationLastSyncOK` (4.4).
- **The trigger reads the delta lists, not `InSync`.** A nameserver that stays
  but loses every record has its glue listed while `InSync` stays true (stage
  1's pinned case), so a trigger read from `InSync` would miss it.
- **No DS query.** The arm never asks the parent for DS, which is what makes
  "skipped, not stripped" (4.3) testable.
- **In sync counts as a success.** A parent found in sync drops an older retry,
  as a sent difference does: either way the parent holds what the zone says.
- **Log wording.** The child-mode hooks log `parentsync: NS or glue changed in
  a refresh ...`; the arm logs `DelegationSyncher: refresh sync ...`. Neither
  matches `request for delegation sync` or `SyncZoneDelegation completed`. The
  per-scheme lines inside `SyncZoneDelegation` are shared with the UPDATE and
  API path, as before.
- **Tests.** §9's T1-T8 in `v2/delsync_refresh_test.go`, plus the IMR wait.
  The analysis runs against a fake parent on a local UDP port; presetting the
  parent, its NS names and its addresses skips the IMR. L1 and L2 have not
  been run.
