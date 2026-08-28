# Review: DSYNC API, one sync plan (#343)

**Superseded for merge readiness** by
[`2026-08-25-pr343-dsync-api-proxy-rereview.md`](2026-08-25-pr343-dsync-api-proxy-rereview.md)
(against `041c6e7e`). This file is the review of `26079e39`.

**Date:** 2026-08-25
**PR:** [#343](https://github.com/johanix/tdns/pull/343)
**Branch:** `feature/dsync-api-proxy` @ `26079e39`
**Base:** `main`
**Size:** 20 files, +2515 / −332 (of which ~1300 lines are tests)
**Lens:** safety, correctness, and possible improvements. Same bar as
[#390](https://github.com/johanix/tdns/pull/390) / [#391](https://github.com/johanix/tdns/pull/391):
what a nameserver can serve that is wrong, a bearer credential posted to
an attacker, or a parent told to delete the DS of a signed child. Not
style.

A batch pass on 24 Aug covered this PR among eight
([`2026-08-24-open-pr-review.md`](2026-08-24-open-pr-review.md),
[`2026-08-24-open-pr-rereview.md`](2026-08-24-open-pr-rereview.md)). This
is a dedicated review of the current head, including #377 and #378 which
have been merged into the branch.

Scope for the proxy’s DS source:
[`2026-08-23-proxy-delegation-sync-scope.md`](2026-08-23-proxy-delegation-sync-scope.md)
(B1/B2 deferred until this lands).

---

## Verdict

**Approve.** The two merge blockers from the 24 Aug pass stay closed:
API is not planned off an unvalidated DSYNC lookup, and the proxy does
not declare a DS set derived from SEP-flagged DNSKEYs. #377’s readiness
latch and #378’s per-scheme publish are in and look right. The viper
read of `child.schemes` that would have silently emptied the plan in
tdns-auth / tdns-agent is gone.

Nothing here serves a bogus RRset or posts a credential to a spoofed
endpoint. Three correctness holes remain in the new ladder and in the
startup path that is supposed to drive it. They are real; they are not
the class that blocked #390 / #391.

| # | Finding | Severity | Nature |
|---|---------|----------|--------|
| 1 | Vacuous NOTIFY still stops the walk for a signed zone with no CDS/CSYNC | Should fix | Default schemes put NOTIFY first; UPDATE/API never run |
| 2 | `findDsync` still matches CSYNC\|ANY; the PR emits NOTIFY(CDS) | Should fix | Parent advertising only NOTIFY(CDS) is skipped |
| 3 | Startup reconcile never sees parent DS for a proxy zone | Should fix | Empty-DS API repair does not run on restart if NS already matches |
| 4 | UPDATE replace still hashes SEP DNSKEYs; unsigned UPDATE does not withdraw DS | Improvement | Known B1; API and UPDATE disagree on the unsigned case |

Off for a zone without `delegation-sync-proxy` / `delegation-sync-child`.
No cross-repo callers of the deleted `BestSyncScheme`.

---

## FINDING 1 — Vacuous NOTIFY still stops the walk (should fix)

The planner already knows a successful NOTIFY that the parent cannot
act on ends the ladder:

```348:362:v2/delegation_sync_plan.go
	// THE gate that makes NOTIFY different from the other two. NOTIFY carries
	// no data -- it says "come re-scan me" -- and what the parent then reads is
	// CDS/CSYNC, which it can only act on if it validates. For an unsigned zone
	// there is nothing for the parent to validate, so a NOTIFY is a no-op that
	// nonetheless looks like a success.
	//
	// That matters here specifically because this is a LADDER: a vacuous
	// success stops it, ...
	if !zoneIsSigned(zd) {
		plan.Skipped = append(plan.Skipped, SkippedScheme{"NOTIFY",
			"zone is unsigned; a NOTIFY would leave the parent nothing it can validate"})
```

That gate covers unsigned. It does not cover the proxy’s common case: a
DSYNC-unaware primary that signs (DNSKEYs in the AXFR) and publishes
neither CDS nor CSYNC. `zoneIsSigned` is true, NOTIFY stays in the plan,
`emitProxyNotifies` sends NOTIFY(CDS) and/or NOTIFY(CSYNC) on a
DNSKEY/NS change, `ProxyNotifyParent` returns nil, and `walkSyncPlan`
stops.

Sample configs put NOTIFY first (`cmdv2/agent/tdns-agent.sample.yaml`:
`schemes: [ notify, update ]`). For that order the new UPDATE and API
transports never run after a change the parent cannot consume from a
scan.

This is not a regression versus `BestSyncScheme` (that also lived with
the preferred scheme). It is the remaining half of the hole this PR’s
ladder was written to close. Unsigned is tested
(`delegation_sync_plan_test.go`); signed-without-CDS is not.

**Fix:** on the proxy role, skip NOTIFY unless the served zone actually
has CDS or CSYNC (the records the parent will look for). Keep the
unsigned gate for the child path. Alternatively treat a NOTIFY that
enqueued nothing, or a proxy NOTIFY for a zone with no CDS/CSYNC, as a
walk failure so UPDATE/API still run. Do not rank NOTIFY last: operator
order is the documented rule.

---

## FINDING 2 — NOTIFY matching is still CSYNC\|ANY (should fix)

```266:269:v2/delegation_sync_plan.go
		// NOTIFY is only actionable for the types that can be signalled about;
		// this preserves the filter BestSyncScheme applied for years.
		if wantNotifyType && drr.Type != dns.TypeCSYNC && drr.Type != dns.TypeANY {
			continue
```

The test rejects `NOTIFY(DS)` and never mentions `NOTIFY(CDS)`. Emission
sends `NOTIFY(CDS)` whenever CDS or DNSKEY changed
(`delsync_proxy.go:216–219`, `delegation_sync.go:613–618`).

A parent that advertises only `DSYNC NOTIFY CDS` is reported as “parent
does not advertise NOTIFY”. A parent that advertises `NOTIFY(CSYNC)` is
matched, then sent CDS notifies it may ignore.

Same filter as the deleted chooser, so not a regression. The PR now
emits CDS more often (startup synthesis, DNSKEY-driven proxy NOTIFY),
so the mismatch is load-bearing.

**Fix:** treat `TypeCDS` the same as `TypeCSYNC` in `findDsync` when
`wantNotifyType` is set. Prefer a record whose type matches the signal
about to be sent if several NOTIFY DSYNC RRs exist.

---

## FINDING 3 — Startup reconcile cannot see a stale parent DS (should fix)

The API path’s one DS statement is “no DNSKEY RRset → declare empty DS”
(`delsync_proxy_api.go:183–190`). That is the repair for “unsigned
child, DS at the parent”. It only runs if `ProxyApiParent` runs.

`ProxyStartupReconcile` bails out when `AnalyseZoneDelegation` says
`InSync` (`delsync_proxy_update.go:314–316`). For a proxy zone
`compareParentDS` returns without looking at the parent DS, because
there are no keystore KSKs:

```177:180:v2/delegation_utils.go
		if !intent.Known {
			lgDns.Debug("AnalyseZoneDelegation: no keystore KSKs for this zone; leaving the parent DS alone",
				"zone", zd.ZoneName)
			return nil
		}
```

NS and glue matching is enough for `InSync`. An agent that restarts
while the child is unsigned and the parent still holds a DS sends
nothing, even with API in the plan. The PR description still talks
about startup synthesis carrying the un-signing so that DS is removed;
after `0636f105` the payload no longer reads the analysis, and the
InSync gate never reaches the payload.

Steady-state un-signing still works: DNSKEY removal is a transfer
change, `zoneIsSigned` becomes false, NOTIFY is skipped, API runs.
Startup of an already-unsigned zone is the hole.

**Fix:** for `SyncRoleProxy`, treat “parent has DS and the child has no
DNSKEY RRset” as out of sync (or skip the InSync gate when API is a
candidate and `!hasDnskeyRRset()`). Do not derive a DS set from
DNSKEYs; that is B1.

---

## FINDING 4 — UPDATE replace still hashes SEP keys (improvement)

`proxyCurrentDelegationRRs` still builds `newDS` from SEP-flagged
apex DNSKEYs (`delsync_proxy_update.go:275–281`) and feeds
`CreateChildReplaceUpdate`, which sets `dsKnown` from `len(newDS) > 0`.
A flags-256 CSK therefore does **not** delete parent DS (empty slice,
`dsKnown=false`). A multi-DS rollover can still send a set that omits
the DS the roll just placed. That is the existing main defect B1 is
meant to replace, and the scope doc says to land #343 first so B1
touches both transports once.

The new split: API withdraws DS for an unsigned child; UPDATE replace
does not. With `schemes: [notify, update]` and no API, finding 1 plus
this one means an un-signing is a NOTIFY skip followed by an UPDATE
that leaves the parent DS in place.

Leave it for B1. Do not re-introduce SEP-derived DS on the API path
while waiting.

---

## What looks right

**One discovery, shared walk.** `BuildParentSyncPlan` runs
`DsyncDiscovery` once. `walkSyncPlan` is shared by proxy and child,
checks `ctx` before each candidate, continues past runtime failures,
and publishes `UpdateResult` only from a succeeding child UPDATE
(`delegation_sync.go:442–450`). The old NOTIFY fallback that
re-derived the preferred scheme and then refused to send NOTIFY cannot
recur.

**API credential gate.** `planConsiderApi` requires
`res.Validated` unless `allow-insecure` (`delegation_sync_plan.go:317–321`).
URI/TXT validation at the discovered target is not treated as a
substitute. Same switch as `DiscoverDsyncApiEndpoint`. Test:
`TestPlanApiRequiresAValidatedDsyncLookup`. HTTPS, no redirects, and
cert verification are unchanged in the client.

**API DS predicate.** Absence of the DNSKEY RRset, not an empty derived
set. SEP is ignored. `GetOwner` failure is unknown, not unsigned
(`hasDnskeyRRset` returns true). Tests cover no DNSKEY, SEP KSK, and
flags-256 CSK.

**Payload source.** Served zone via `proxyCurrentDelegationRRs`, not
`DelegationDataChangedNG`’s empty `New*` fields. Analysis is the
trigger. Documented and tested.

**Credentials.** `CredentialForChild(parent, child)` is most-specific
wins; a generic parent entry remains the fallback. Proxy, plan, and
child API all use it. Not a confused-deputy: the POST names
`zd.ZoneName`.

**Typed config.** Schemes come from `DelegationSyncConfig().Child.Schemes`,
not viper. A source-level test fails the file if a viper read of this
block returns. That was a silent total failure in the daemons.

**IMR wait (#377).** `ImrReadiness` is store-then-announce, `sync.Once`
on close, nil-safe. Proxy commands defer until `Published()` rather
than skipping. Re-enqueue is a separate goroutine so the syncher cannot
deadlock on its own queue. Cancellation actually exits (goroutine-count
test). Unbounded wait if the IMR never comes is intentional.

**Per-scheme DSYNC (#378).** `SetupZoneSync` always calls
`PublishDsyncRRs`. Guard is inside, per scheme. Working set is a copy
with no spare capacity. `_dsync` owner with no DSYNC RRset is an empty
start, not a panic.

**`BestSyncScheme` / `net.LookupHost`.** Deleted. Address resolution
goes through `resolveDsyncTarget` / the IMR.

**Role split.** `updateGateBlocked` is proxy-only (§10.8 KEY
bootstrap). A child with a missing signing key fails at send and the
walk continues. `zoneIsSigned` includes online/inline signing options
so a tdns-auth child is not called unsigned.

---

## Non-blocking

- Additive `PublishDsyncRRs` may append a second SVCB at the UPDATE
  target when a new scheme is added; glue A/AAAA are deduped, SVCB is
  not. Helper tests only; `PublishDsyncRRs` itself is not driven
  through the updater.
- Child `SyncZoneDelegationViaNotify` keys CDS NOTIFY on
  `DSAdds`/`DSRemoves` only, not `DNSKEYAdds`/`DNSKEYRemoves`. Same
  vacuous-success shape as finding 1, on the child path.
- `ProxyNotifyParent` / `emitProxyNotifies`: a cancelled send still
  returns nil, so shutdown can look like success.
- `ProxyApiParent` returning “nothing to declare” is walk success. Rare
  (an apex with NS should produce at least an NS RRset).
- Child-side `DELEGATION-STATUS` / `SYNC-DELEGATION` still call
  `imr()` without the readiness gate. Pre-existing; #377 only covers
  the two PROXY commands.
- `pushDSRRsetViaApi` (rollover) still uses `CredentialFor(parent)`
  without a child. Fine for tdns-auth; a proxy-only child-specific
  credential row would not match. Out of this PR’s send path.

Fold nothing extra in. B1 (CDS as DS source on both proxy transports)
and B2 (in-sync = parent DS vs CDS-implied) stay the follow-ups the
scope doc already scheduled after this merge.
