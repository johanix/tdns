# Delegation sync on refresh: the proxy's detector for every child

**Written 2026-09-23.** Proposal, for review. Line references are to main at
`f255d19a`. For #731, which it widens: the gap is not specific to signing
secondaries. Any `parentsync` zone whose content changes by a refresh, whether
a transfer or a zone-file reload, never tells its parent about an NS or glue
change.

**Status:** proposal. Nothing is implemented.

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
  - It acts by comparing the zone with the parent (`AnalyseZoneDelegation`),
    not by sending the difference between two versions.
  - It leaves DS out of what it sends.
  - It retries a failure the way the proxy does.
  - It runs once at startup as well, which the child side has never done.

  Proxy mode is unchanged. Size: about 180 lines of non-test code and 350 of
  tests.
- The three questions asked about this (answered in §6–§8):
  - **Does tdns-agent do the right thing?** In steady state, yes. One
    deviation: it re-sends to the parent on every restart.
  - **Does a tdns-auth primary?** Only for changes that arrive by DNS UPDATE or
    the API, and even then a failed sync is not retried. Zone-file edits never
    reach the parent.
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

Child mode compares no DNSKEY, CDS or DS, for any zone. For a zone that signs
its own content, those are ours (§2). For a zone that does not sign, tdns
holds no keys, so its DS intent is unknown, and the parent's DS is not ours to
change (`compareParentDS`, `v2/delegation_utils.go:297`). Either way, DS
reaches the parent through the DS engine and the rollover engine.

### 4.2 A comparison of NS and glue alone

Move the NS and glue part of `DelegationDataChangedNG`
(`v2/delegation_utils.go:400-494`) into its own function. Child mode calls it.
`DelegationDataChangedNG` calls it and then runs its DS block unchanged, so
the proxy and tdns-mp see no difference.

The pre-refresh closure in child mode records only a bool, "NS or glue
changed". The action does not use the comparison's contents (4.3).

### 4.3 Act by comparing with the parent

After the swap, child mode queues `REFRESH-SYNC-DELEGATION`. The syncher's arm:

1. **Waits for the IMR**, as the `PROXY-SYNC` arm does (`delegation_sync.go:176-185`).
2. **Compares the served zone with the parent** (`AnalyseZoneDelegation`).
3. **Removes DS from the result:** `DSAdds`, `DSRemoves` and `NewDS` are
   cleared, `NewDSKnown` is set false, and `InSync` is recomputed from NS and
   glue.
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

**Why leave DS out.** The trigger is NS and glue, so the action is too. DS
belongs to the DS engine and the rollover engine. DS engine design step 2 (KLO
§6, S6) moves the rollover engine's pushes into the syncher, and that is the
place to decide how DS and NS syncs combine. Every scheme supports "DS
unknown":

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
one `REFRESH-SYNC-DELEGATION` after `DELEGATION-SYNC-SETUP`, for every scheme.
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

  The result is not wrong: replace UPDATEs repeat harmlessly, a repeated
  NOTIFY costs the parent a scan, and it is also what makes the log's "the
  next change or a restart will try again" (`v2/delegation_sync.go:853`)
  true. But it is load on the parent at every restart, and the code says
  otherwise. The fix is to skip the proxy's comparison on a first load, since
  the reconcile covers it. That is a change to tdns-agent, so it is left out
  of this proposal (Q-a).
- **Out of scope, noted.** The proxy's UPDATE and API derive the DS set from the
  served SEP DNSKEYs (`currentDelegationRRs`, `v2/delsync_proxy_update.go:403`),
  not from the primary's CDS. A primary whose CDS says something else (a
  delete, or a KSK it is not ready to put at the parent) is not followed.

## 7. Question 2: does a tdns-auth primary do the right thing today?

Partly:

| Change arrives by | Reaches the parent? |
|---|---|
| DNS UPDATE or API `update` | Yes: ZoneUpdater → `SYNC-DELEGATION`, delta by default. NS removals go to the parent first (`applyParentFirst`). A failure is dropped with no retry (`v2/delegation_sync.go:88`). |
| Zone-file edit, picked up by `zone reload`, SIGHUP, config reload or the daily re-stat (`FindSoaRefresh`, `v2/refreshengine.go:1438`) | **No.** `FetchFromFile` runs the pre- and post-refresh hooks, but only the proxy mode is attached. |
| Anything, while the server was down | **No.** Startup bootstraps the SIG(0) key and never compares with the parent (§3). |
| Its own KSK changes | Through the rollover engine and the DS engine; not in scope here. |

The design fixes the second and third rows. The first keeps its path. Routing
it through the same compare-with-parent command, to get retries, is Q-b.

## 8. Question 3: fix this before key lifecycle ownership is complete?

Yes. The NS and glue sync proposed here is independent of KLO:

- **KLO is about multi-provider zones.** It moves their key state machine to
  tdns-mp (KLO §2, D1). Child mode excludes `multi-provider` zones, and
  tdns-mp keeps its own pre-refresh hook.
- **For tdns's own zones, it leaves DS alone.** The DS engine and the rollover
  engine keep that job. The one planned change there, the rollover engine's
  pushes moving into the syncher (KLO §6, S6, not started), is where DS and NS
  syncs get combined. The shared retry helpers (4.4) are something S6 can use.
- **It does not touch the keystore interface or DS intent.** `AnalyseZoneDelegation`'s
  DS comparison, which KLO S2 made owner-aware, runs but its result is
  discarded.
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
| T1 | Child mode, signer after AXFR: the served zone has DNSKEY and CDS, the incoming zone has neither, same NS and glue. No trigger. (The case §2 measured, with the opposite outcome.) |
| T2 | Child mode: an added NS with glue, a removed NS, and a changed glue address each trigger; a serial-only change does not. Run on the AXFR shape and the IXFR shape. |
| T3 | The DS strip: from an `AnalyseZoneDelegation` result carrying NS and DS differences, the delta UPDATE carries no DS record, the replace UPDATE leaves DS alone, and the API payload declares no DS. |
| T4 | In sync after the strip, with a DS difference only: nothing is sent. |
| T5 | Retry: a failure is re-queued on the proxy's schedule; a retry is dropped after a later success. Both arms. |
| T6 | Gates: a `parentsync-proxy` zone still runs proxy mode with all four comparisons (the existing `delsync_proxy_*_test.go` stay green unchanged); `multi-provider` and no-`parentsync` zones run neither mode. |
| T7 | `FetchFromFile` on a primary with `parentsync` and an edited file triggers. |
| T8 | Startup: first load queues one `REFRESH-SYNC-DELEGATION` after `DELEGATION-SYNC-SETUP`; a parent already in sync gets nothing. |
| L1 | Live: tdns-signer behind an unsigned primary. The primary adds an NS; the parent follows. The signer's KSK stays at the parent across an AXFR. |
| L2 | Live: a tdns-auth primary with an edited zone file and `zone reload`; the parent follows. Restart with an offline edit; the parent follows once, and not again on the next restart. |

## 10. Staging

| # | Change | Size (non-test) |
|---|---|---|
| 1 | The NS-and-glue comparison as its own function; `DelegationDataChangedNG` calls it. No change in behaviour. | ~40 |
| 2 | Child mode, `REFRESH-SYNC-DELEGATION` with the DS strip, shared retry helpers. | ~110 |
| 3 | The startup compare-with-parent from `SetupZoneSync`. | ~20 |

Stage 1 is a refactor with no change in behaviour, and the existing tests pin
it. Stages 2 and 3 can go in one PR. #557 is independent, but needed before
the NOTIFY scheme's NS sync means anything.

## 11. Open questions

- **Q-a.** Skip the proxy's comparison on a first load, so a restart stops
  re-sending (§6)? It changes tdns-agent. A separate issue if wanted.
- **Q-b.** Move the ZoneUpdater's `SYNC-DELEGATION` (UPDATE and API changes) to
  the compare-with-parent command, for its retries? Parent-first NS removal
  and `ParentSyncDone` have to keep working, so it is not a one-line change.
- **Q-c.** Leave DS out of the refresh-triggered sync (recommended), or send it
  as `delegation sync` does? Sending it would make this path a second DS
  pusher beside the rollover engine, until S6.
- **Q-d.** The proxy follows the primary's DNSKEYs rather than its CDS for DS
  (§6). File it?
