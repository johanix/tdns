# Re-review: #343 DSYNC API / one sync plan

**Date:** 2026-08-25 (second pass)
**Prior review:** [`2026-08-25-pr343-dsync-api-proxy-review.md`](2026-08-25-pr343-dsync-api-proxy-review.md) (against `26079e39`)
**PR:** [#343](https://github.com/johanix/tdns/pull/343)
**Branch:** `feature/dsync-api-proxy` @ `041c6e7e`
**Lens:** did the four findings close, and did the fix commits introduce
anything new.

New commits since `26079e39`:

- `69b5dbb3` — both halves of NOTIFY planning (findings 1 and 2).
- `041c6e7e` — unsigned child with a parent DS is out of sync (finding 3).

---

## Verdict

**Approve.** Findings 1–3 are closed in the code, not only in the commit
messages. Each has a test that calls the helper rather than re-deriving
the condition. Finding 4 is unchanged and was never a hold (B1). No new
correctness hole.

| # | First-pass finding | Now |
|---|--------------------|-----|
| 1 | Vacuous NOTIFY stops the walk for a signed zone with no CDS/CSYNC | **Closed.** Proxy role skips NOTIFY unless the served zone has CDS or CSYNC. Child role is untouched. |
| 2 | `findDsync` matched CSYNC\|ANY; PR emits NOTIFY(CDS) | **Closed.** CDS is accepted. NOTIFY(DS) still is not. |
| 3 | Startup reconcile never saw parent DS for a proxy zone | **Closed.** `unmanagedZoneNeedsDSRepair` sets `InSync=false`. No DS set is derived. |
| 4 | UPDATE replace still hashes SEP DNSKEYs | **Unchanged.** B1. API still withdraws; UPDATE replace still does not. |

The 24 Aug blockers (API DNSSEC gate, no SEP-derived DS on the API path)
stay closed.

---

## Finding 1 — closed

```407:410:v2/delegation_sync_plan.go
	if role == SyncRoleProxy && !zoneHasCdsOrCsync(zd) {
		plan.Skipped = append(plan.Skipped, SkippedScheme{"NOTIFY",
			"proxied zone publishes neither CDS nor CSYNC; a NOTIFY would leave the parent nothing to read"})
		return
	}
```

`zoneHasCdsOrCsync` is the presence of either RRset. An unreadable apex
returns true (unknown, not absence), same shape as `hasDnskeyRRset`.
The unsigned gate still runs first, so a never-signed proxy is skipped
there and never reaches this test.

`TestPlanNotifyNeedsSomethingTheParentCanRead` drives the skip through
`planConsiderNotify` with `SyncRoleProxy` and asserts the child role
does not apply the same skip. `TestZoneHasCdsOrCsync` covers neither /
CDS / CSYNC / unreadable apex.

They scoped it to the proxy, which is what the first pass asked for. A
tdns-auth child with no CDS yet still plans NOTIFY.

---

## Finding 2 — closed

```279:281:v2/delegation_sync_plan.go
		if wantNotifyType &&
			drr.Type != dns.TypeCDS && drr.Type != dns.TypeCSYNC && drr.Type != dns.TypeANY {
			continue
```

No preference among CDS/CSYNC/ANY: `emitProxyNotifies` sends both
signals to the same target list, so choosing would decide nothing.
`TestFindDsyncAcceptsNotifyCDS` accepts CDS/CSYNC/ANY and still rejects
NOTIFY(DS).

---

## Finding 3 — closed

```168:178:v2/delegation_utils.go
func unmanagedZoneNeedsDSRepair(apex *OwnerData, parentDS []dns.RR) bool {
	if len(parentDS) == 0 {
		return false
	}
	if apex == nil || apex.RRtypes == nil {
		return false
	}
	return len(apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY).RRs) == 0
}
```

Called only on `!intent.Known` (every proxied zone). Sets `InSync=false`
and returns without filling `NewDS` / `DSAdds`. A flags-256 CSK is
signed. An unreadable apex is not a withdrawal.

`TestUnsignedChildWithParentDSNeedsRepair` hits the helper: unsigned +
parent DS, unsigned + no parent DS, SEP-signed, CSK, nil apex.

Startup of an already-unsigned zone with matching NS now reaches
`SyncWithParent`. The empty-DS statement still only goes out on the API
path; that is finding 4.

---

## Finding 4 — unchanged

`proxyCurrentDelegationRRs` still builds `newDS` from SEP-flagged
DNSKEYs. `CreateChildReplaceUpdate` still sets `dsKnown` from
`len(newDS) > 0`. Leave it for B1.

---

## Nothing new that should block

`compareParentDS`’s godoc now sits on `unmanagedZoneNeedsDSRepair`
(`delegation_utils.go:150–168`). Same class as the #390 leftover that
was later restored. Not a behaviour bug.

The child-role test in `TestPlanNotifyNeedsSomethingTheParentCanRead`
swallows a panic from `resolveDsyncTarget(nil, …)`. Only the skip
reason is asserted; that is enough for the gate.
