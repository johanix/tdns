# Rollover Timing Engine Audit — `rollover-notify-scheme` branch

**Repo head:** `7633367` ("Merge remote-tracking branch 'origin/main' into
rollover-notify-scheme") — branch is 13 commits ahead of `main`,
implementing phases 1–10 of a NOTIFY-scheme rollover path. New files:
`ksk_rollover_ds_notify.go`, `ksk_rollover_schemes.go`,
`ksk_rollover_cds_cleanup.go`, `rollover_engine_deps.go`. Phase 1 was
an "extract orchestrator-agnostic push engine" refactor.
**Spec:** `tdns/guide/rapid-key-rollover.md` §4
**Scope:** `tdns/v2/` only (skipping `tdns-mp/`)
**Date:** 2026-05-02
**Compares against:** `tdns/docs/2026-05-02-rollover-timing-report.md`
(audit at head `ddc5615`, pre-NOTIFY work).

> **Methodology.** The per-equation findings below were produced
> against the spec without consulting the prior report. The
> "Differences from prior report" section at the end is the only part
> written with both audits side-by-side.

---

> **RESOLVED (2026-07-01).** This audit re-confirmed the E3/E12/E13
> divergence on the `rollover-notify-scheme` branch; it is now **fixed** in
> current `main` / `feat/tsig-first-class`. `T_publish` subtracts the DNSKEY
> TTL: `tPublish := tRoll.Add(-(deps.PropagationDelay + dnskeyTTL))`
> (`ksk_rollover_automated.go:1162`), `dnskeyTTL = min(TTLS.DNSKEY,
> TTLS.MaxServed)` (or observed served TTL) via `effectiveServedDnskeyTTL`
> (`:1400`). Landed as **W1** (`e120dc4`) + tests **W8** (`ed47876`),
> merged via **PR #212** (`rollover-timing-fixes-1`). The NOTIFY-specific
> `parent_prop` caveat (the E6 note below) is operator guidance, not a code
> bug — it remains open as a documentation item. Verdicts below retained as
> the historical audit record.

## E1 — DS-side cache-flush invariant: `T_DS_pub_n + parent_prop + DS_TTL ≤ T_roll_n`

**Verdict:** UNCLEAR (structurally implied iff E10 holds; E10 is *not*
validated).

E1 is not enforced as an explicit comparison. The pipeline ensures
the parent has the right keys far enough in advance via the multi-DS
lead time E8.

- Pipeline-fill: `ksk_rollover_automated.go:130-145` runs while
  `CountKskInRolloverPipeline < num`.
- DS submission target: `ksk_rollover_ds_push.go:143-176`
  (`ComputeTargetDSSetForZone`) produces one DS per SEP key in states
  `created, ds-published, standby, published, active, retired`.
- Both the UPDATE path (`pushDSRRsetViaUpdate`) and the new NOTIFY
  path (`pushDSRRsetViaNotify`) derive their RRset from the same
  `loadTargetKSKsForRollover` rows
  (`ksk_rollover_ds_push.go:71-83`), so the two schemes describe an
  identical set of keys.
- The push fires on idle ticks when `kskIndexPushNeeded(...)` returns
  true (`ksk_rollover_automated.go:188-203`).

**Note specific to NOTIFY path:** `parent_prop` now bundles "child
publishes CDS at apex → child secondaries serve CDS → parent fetches
CDS → parent's DS RRset is updated → parent secondaries serve new
DS." This is a longer chain than the UPDATE path (which collapses
the first three hops). §4.2 defines `parent_prop` as starting at
"child sent UPDATE / NOTIFY accepted by parent," consistent with
this — but the operator estimate in `rollover.ds-publish-delay` may
need a larger value when NOTIFY is the chosen scheme. Nothing in
the engine tells the operator this.

---

## E3 — DNSKEY-side cache-flush invariant: `T_DNSKEY_pub_n + child_prop + DNSKEY_TTL ≤ T_roll_n`

**Verdict:** DIVERGES.

E3 is the invariant E12 is supposed to schedule against. Because E12
schedules `T_roll − propagationDelay` (no `DNSKEY_TTL` term — see
E12), E3 is satisfied only when `DNSKEY_TTL ≤ 0`, which never
happens. **Operational consequence:** validators that fetched the
DNSKEY RRset in the last `DNSKEY_TTL` window before `T_roll_n` may
serve cached responses missing `DNSKEY_n`, causing bogus until the
cache flushes.

---

## E5 — `retirement_period ≥ min(DNSKEY_TTL, KSK.SigValidity)`

**Verdict:** UNCLEAR (typically holds; not validated).

`effective_margin = max(clamping.margin, max_observed_ttl)` at
`ksk_rollover_automated.go:1167-1183`:

```go
func effectiveMarginForZone(kdb *KeyDB, zone string, pol *DnssecPolicy) (time.Duration, error) {
    margin := pol.Clamping.Margin
    maxTTL, err := LoadZoneSigningMaxTTL(kdb, zone)
    ...
    ttlDur := time.Duration(maxTTL) * time.Second
    if ttlDur > margin { return ttlDur, nil }
    return margin, nil
}
```

In steady state
`max_observed_ttl ≥ DNSKEY_TTL ≥ min(DNSKEY_TTL, KSK.SigValidity)`,
so E5 holds. **Quiet-failure mode:** if an operator sets
`clamping.margin < min(DNSKEY_TTL, KSK.SigValidity)` AND the engine
runs before any zone has been signed (so `max_observed_ttl = 0`),
`retirement_period = clamping.margin` can violate E5. The §4.5.1
note explicitly calls for a config-load check; it isn't there.
`warnDnssecPolicyCoupling` (`ksk_rollover_policy.go:377-395`) does
not cover E5.

---

## E6 — `T_DS_pub_n = T_roll_{n−N+1} + retirement_period`

**Verdict:** MATCHES (UPDATE path) / MATCHES with parent-controlled
latency caveat (NOTIFY path).

Trigger sequence:

1. Retired → removed at `ksk_rollover_automated.go:526-536`, gated on
   `now.Sub(*k.RetiredAt) >= eff` where
   `eff = effectiveMarginForZone(...)`.
2. `triggerResign` re-signs without DNSKEY_{n−1} at line 539.
3. `completeRolloverWithdraw` (`ksk_rollover_automated.go:1189`)
   returns the zone to idle.
4. Next idle tick: `ComputeTargetDSSetForZone` recomputes target DS
   set (`ksk_rollover_automated.go:194`); `kskIndexPushNeeded` arms
   `pendingParentPush`; that handler calls
   `PushDSRRsetForRollover(pushCtx, deps)` at line 230.

What changed on this branch: instead of `PushWholeDSRRset`, the
engine now calls the new dispatcher `PushDSRRsetForRollover`
(`ksk_rollover_ds_push.go:202-306`), which dispatches one or both of
UPDATE and NOTIFY based on the parent's DSYNC RRset and
`pol.Rollover.DsyncSchemePreference`.

The trigger event (local retired → removed) is unchanged, so the
spec timing relation E6 is still respected for the UPDATE path:
`T_DS_pub_n` = trigger time + parent_prop.

**Caveat for the NOTIFY path:** "parent's DS RRset contains DS_n"
is no longer "engine sent UPDATE + parent_prop" but "parent fetched
and applied CDS," which is parent-controlled. The engine's
`pendingParentObserve` loop (`ksk_rollover_automated.go:265+`) waits
for the parent's DS to actually contain the expected set, so
correctness is preserved even if parent CDS-fetch latency is
unpredictable. But "T_DS_pub_n at exactly
T_roll_{n−N+1} + retirement_period" is no longer guaranteed under
NOTIFY — it can be later by the parent's CDS-fetch interval.

---

## E10 — `(N − 1) × KSK_lifetime ≥ retirement_period + parent_prop + DS_TTL`

**Verdict:** MISSING.

No config-load validation. `warnDnssecPolicyCoupling`
(`ksk_rollover_policy.go:377-395`) does not check it. The
`fillRolloverDurations` change on this branch
(`ksk_rollover_policy.go:317-328`) only adds the
`dsync-scheme-preference` enum check; nothing for E10.

**Operational consequence if violated:** the parent's DS RRset will
be replaced (drop DS_{n−1}, add DS_{n+N−1}) too late before
`T_roll_n`, leaving validators with stale DS caches that don't yet
include `DS_n`.

---

## E11 — production rule of thumb

**Verdict:** MISSING. No warning emitted when `N` is too small
relative to `(retirement_period + parent_prop + DS_TTL) / KSK_lifetime`.

---

## E12 — `T_DNSKEY_pub_n = T_roll_n − child_prop − DNSKEY_TTL`

**Verdict:** **DIVERGES** (this is still the headline finding).

`ksk_rollover_automated.go:957-967`:

```go
lifetime := time.Duration(pol.KSK.Lifetime) * time.Second
for i, k := range dsPubs {
    // Promotion position: i=0 is the next-up (slot 1),
    // i=1 is after that (slot 2), etc.
    tRoll := activeAt.Add(time.Duration(i+1) * lifetime)
    tPublish := tRoll.Add(-propagationDelay)
    if now.Before(tPublish) {
        break
    }
    ...
```

Function header at `ksk_rollover_automated.go:869-873` still
documents the wrong formula:

```go
// TransitionRolloverKskDsPublishedToStandby advances each SEP key from
// ds-published to standby exactly when its DNSKEY needs to be in the
// served zone for cache-flush safety: T_publish_i = T_roll_i -
// propagationDelay, where T_roll_i = active.active_at + i × KSK.Lifetime
```

Function signature `(conf, kdb, now, propagationDelay)` at line 891
still has no `DNSKEY_TTL` parameter. `propagationDelay` is sourced
from `kasp.propagation_delay` only at `key_state_worker.go:30-40`
(unchanged). The `− DNSKEY_TTL` term is still missing.

For the testbed (`child_prop = 1m`, `DNSKEY_TTL = 5m`,
`KSK_lifetime = 10m`): the engine publishes new DNSKEYs at
`T_roll − 1m` instead of `T_roll − 6m`. Validators that cached the
DNSKEY RRset in the 5-minute window before `T_DNSKEY_pub_n` may
carry stale caches across `T_roll_n` and reject `RRSIG_n`.

---

## E13 — effective `DNSKEY_TTL = min(ttls.dnskey, ttls.max_served)`

**Verdict:** DIVERGES (computed for the served wire TTL via the clamp
pipeline, but not consumed by E12).

The clamp pipeline at `ksk_rollover_clamp.go:298-318` computes
`min(UnclampedTTL, K·margin if K>0, MaxServedTTL if >0)` and applies
it during `SignRRset`. `effectiveMarginForZone` reads
`max_observed_ttl` afterwards. But the served TTL never reaches
`TransitionRolloverKskDsPublishedToStandby`, which still receives only
`propagationDelay`. No callers compute `min(ttls.dnskey,
ttls.max_served)` for the rollover-engine path.

---

## §4.4 — parent's DS RRset is always exactly N records, cycling A↔B atomically

**Verdict:** MATCHES (UPDATE path) / **UNCLEAR (NOTIFY path)** —
parent-side atomicity is out of the engine's control.

UPDATE path (unchanged from prior audit):

1. **Pipeline-fill targets N.** `ksk_rollover_automated.go:130-145`.
   `CountKskInRolloverPipeline` (`ksk_rollover_pipeline.go:140`)
   counts SEP keys in
   `{created, ds-published, standby, published, active, retired}` —
   the same set `ComputeTargetDSSetForZone` publishes.
2. **Atomic A→B transition.** `BuildChildWholeDSUpdate`
   (`ksk_rollover_ds_push.go:38-66`) issues a single `*dns.Msg` with
   `RemoveRRset` (DEL ANY DS) + `Insert`. RFC 2136 commits the update
   section as one transaction.
3. **Pipeline-fill runs *before* the idle-branch DS push** within
   the same `RolloverAutomatedTick`. After retired→removed drops
   local pipeline to N−1, the next tick generates KSK_{n+N−1} first,
   then the UPDATE is built containing the correct N records.

NOTIFY path:

1. The child publishes a whole-RRset CDS replacement at its apex via
   `pushDSRRsetViaNotify` (`ksk_rollover_ds_notify.go:84-93`):
   anti-CDS ClassANY delete + ClassINET adds. So the **child's
   served CDS** is N records, set atomically by the
   internal-update queue.
2. NOTIFY(CDS) is dispatched to the parent's DSYNC NOTIFY target.
3. **The parent then has to fetch CDS and update its DS RRset.** This
   is parent-controlled (RFC 8078 §4). Whether the parent applies
   the CDS-derived DS RRset atomically — and whether it does so
   without a transient "fewer than N" state — depends on the parent
   implementation. The §4.4 wording ("the same DNS UPDATE drops
   DS_{n−1} and adds DS_{n+N−1}") was written assuming the UPDATE
   path; it does not directly cover NOTIFY.

In practice most parent implementations replace DS atomically on
seeing new CDS, so the contract is upheld by convention. But the
engine cannot guarantee atomicity at the parent in the NOTIFY case,
only at the child's CDS publication.

**Auto-mode parallel dispatch.** When both UPDATE and NOTIFY are
advertised under "auto", `PushDSRRsetForRollover` runs both
goroutines in parallel (`ksk_rollover_ds_push.go:261-286`). Each
re-derives the target set via `loadTargetKSKsForRollover`, which
reads the keystore at slightly different moments. Window is
microseconds in normal operation; under heavy state-transition
pressure it could differ. The two paths could in principle write
divergent sets to the parent — UPDATE writes immediately, NOTIFY
takes effect only when the parent fetches CDS later. Not a §4
violation per se, but worth documenting.

**CDS-cleanup transient.** `cleanupCdsAfterConfirm`
(`ksk_rollover_cds_cleanup.go:45-107`) unpublishes the engine's CDS
RRset after the parent confirms — there is a window where the
parent has DS but the child no longer has CDS. That is a regression
to no-CDS-published, not a violation of the parent-side N-records
contract.

---

## §4.5(b) — child-side DNSKEY removal happens *before* parent DS UPDATE

**Verdict:** MATCHES.

Sequence within `pendingChildWithdraw`:

1. `ksk_rollover_automated.go:530` —
   `UpdateDnssecKeyState(kdb, zone, k.KeyTag, DnskeyStateRemoved)`:
   local DNSKEY_{n−1} removed from served set.
2. `ksk_rollover_automated.go:539` — `triggerResign(conf, zone)`:
   zone re-signed by KSK_n.
3. `ksk_rollover_automated.go:542` — `completeRolloverWithdraw`
   clears `rollover_in_progress` and sets `rolloverPhaseIdle`.
4. **Next tick:** idle branch (`ksk_rollover_automated.go:188`)
   recomputes target DS set, arms `pendingParentPush`, fires
   `PushDSRRsetForRollover`.

Local DNSKEY removal + zone re-sign always precede the parent push
by at least one tick. Dispatcher choice (UPDATE / NOTIFY / both)
does not affect ordering — both schemes run from the same
pendingParentPush handler entry.

---

## Out-of-band findings

1. **E12's docstring still documents the wrong formula** at
   `ksk_rollover_automated.go:869-873`. Unchanged on this branch.

2. **`TransitionRolloverKskDsPublishedToStandby` is still
   signature-bottlenecked.** The Phase 1 "extract
   orchestrator-agnostic push engine" refactor introduced
   `RolloverEngineDeps` (`rollover_engine_deps.go:20`) which now
   bundles `Imr`, `KDB`, `Zone`, `Policy`, `NotifyQ`,
   `InternalUpdateQ`. The DS-published→standby transition function
   is *not* migrated to `RolloverEngineDeps` — it still takes
   `(conf, kdb, now, propagationDelay)`. The deps refactor was a
   logical opportunity to plumb a DNSKEY TTL through; it didn't.

3. **Auto-mode parallel dispatch and the E1 budget.** The dispatcher
   accepts a push as successful if *either* path returns NOERROR
   (`aggregateRolloverPushResults` at
   `ksk_rollover_ds_push.go:312-350`, "any-success-wins"). The
   effective `T_DS_pub_n` is the *earlier* of the two paths'
   delivery times — UPDATE typically wins. Multi-scheme parallel
   dispatch tightens E1's lead-time budget rather than loosening it.
   Not a §4 issue but worth noting.

4. **Indefinite softfail for "waiting-for-parent."** The dispatcher
   maps `errNoUsableScheme` (parent advertises neither UPDATE nor
   NOTIFY for the chosen preference) to
   `SoftfailChildConfigWaitingForParent` with a 1h cap and no
   hardfail (`ksk_rollover_ds_push.go:217-232`). If the parent
   misconfigures DSYNC permanently, the engine retries forever
   without escalating. Stretches `T_DS_pub_n` unboundedly past
   `T_roll_n` and the engine has no way to alert that E1 is
   impossible to satisfy. This is a deliberate design choice
   (post-overhaul model) but invisible to §4 timing math.

---

## Summary

| Item | Verdict |
|------|---------|
| E1  (DS-side invariant) | UNCLEAR (depends on E10) |
| E2  (E1 rearranged) | UNCLEAR |
| E3  (DNSKEY-side invariant) | DIVERGES (consequence of E12) |
| E4  (E3 rearranged) | DIVERGES |
| E5  (retirement_period sizing) | UNCLEAR (typically holds; not validated) |
| E6  (T_DS_pub_n trigger/timing) | MATCHES (UPDATE) / MATCHES with parent-controlled latency caveat (NOTIFY) |
| E7  (E6 rearranged) | MATCHES |
| E8  (lead_DS) | UNCLEAR (depends on E10) |
| E9  (E1+E8) | UNCLEAR |
| E10 (cadence constraint) | MISSING (no config-load validation) |
| E11 (rule-of-thumb warning) | MISSING |
| **E12 (DNSKEY ds-published→standby)** | **DIVERGES — missing −DNSKEY_TTL term (unchanged from prior audit)** |
| E13 (effective DNSKEY_TTL) | DIVERGES (computed for clamp; not consumed by E12) |
| §4.4 (parent DS RRset contract) | MATCHES (UPDATE) / **UNCLEAR (NOTIFY — parent-side atomicity out of engine control)** |
| §4.5(b) (action ordering) | MATCHES |

## Top-3 findings to fix first

1. **E12 is wrong.** Same as prior audit — the NOTIFY branch did not
   touch `TransitionRolloverKskDsPublishedToStandby`. The Phase 1
   `RolloverEngineDeps` refactor was a near-miss opportunity to
   plumb a DNSKEY TTL through; consider folding the E12 fix into
   the same migration so the function signature changes once.

2. **E10 has no config-load validation.** Same as prior audit. The
   addition of `dsync-scheme-preference` enum validation shows the
   policy-load path is being touched on this branch; this is a good
   moment to add E10 alongside.

3. **§4.4 contract under NOTIFY needs spec clarification.** New
   finding for this branch. The §4.4 wording ("the same DNS
   UPDATE") implicitly assumes UPDATE; with NOTIFY, atomicity at
   the parent depends on the parent's CDS handler. Either extend
   §4.4 to cover NOTIFY (state that "atomicity at the parent is
   the parent's responsibility once CDS is published") or document
   the assumption that all NOTIFY-supporting parents are
   RFC 8078-compliant for atomic DS replacement.

---

## Differences from prior report

The prior report (`tdns/docs/2026-05-02-rollover-timing-report.md`,
audit at `ddc5615`) and this one were produced against the same
spec. The differences below reflect only what changed in the code
between `ddc5615` and `7633367`.

### Verdicts changed

- **E6: MATCHES → MATCHES with NOTIFY caveat.** Prior report:
  "MATCHES (timing) / MATCHES (trigger)". The trigger and
  engine-side timing are still correct, but the NOTIFY scheme adds
  parent-controlled CDS-fetch latency between "engine submits the
  push" and "parent's DS RRset is updated." T_DS_pub_n is no longer
  bounded above by `engine_submit_time + parent_prop` under NOTIFY
  — it depends on when the parent decides to fetch CDS.

- **§4.4: MATCHES → MATCHES (UPDATE) / UNCLEAR (NOTIFY).** Prior
  report's only caveat was wire-shape (DEL ANY + INSERT vs surgical
  remove-one-add-one). This audit adds a more substantive caveat:
  in the NOTIFY path, the child publishes CDS atomically but the
  parent's DS-RRset transition is governed by the parent's CDS
  handler, not by a child-issued UPDATE. RFC 8078 implementations
  typically replace DS atomically, but the engine cannot guarantee
  it. The prior wire-shape caveat still applies to the UPDATE path
  and is no longer mentioned because it didn't change.

### Verdicts unchanged

- **E1, E3, E4, E5, E7–E11, E12, E13, §4.5(b):** identical verdicts.
  None of the relevant code paths were touched on this branch:

  - `TransitionRolloverKskDsPublishedToStandby` is byte-for-byte
    unchanged (now at `ksk_rollover_automated.go:891` instead of
    `:776` because of new content above; the formula at
    `:962` is identical to the prior `:847`).
  - `effectiveMarginForZone` unchanged.
  - `warnDnssecPolicyCoupling` unchanged. No new validations for
    E5, E10, or E11.
  - `key_state_worker.go` unchanged (no diff vs main).
  - `ops_dnskey.go` unchanged (no diff vs main).

### New observations not in prior report

1. **NOTIFY path adds a parent-fetch hop to `parent_prop`.** E1 may
   need a larger operator estimate of `rollover.ds-publish-delay`
   when NOTIFY is the chosen scheme. The engine doesn't help the
   operator size this.

2. **Auto-mode parallel dispatch.** UPDATE and NOTIFY run in
   parallel goroutines and the dispatcher accepts the earlier of
   the two as success. Tightens E1's lead-time budget; not a spec
   issue.

3. **Indefinite softfail for "waiting-for-parent."** Permanent
   parent DSYNC misconfiguration causes the engine to retry forever
   without alerting. Stretches T_DS_pub_n unboundedly past
   T_roll_n.

4. **`RolloverEngineDeps` refactor.** Phase 1 introduced a deps
   bundle (`rollover_engine_deps.go`) but did not migrate
   `TransitionRolloverKskDsPublishedToStandby` to use it. The
   function signature still has no path to a DNSKEY TTL.

### Observations from prior report no longer relevant

- **Out-of-band #3 (prior):** "completeRolloverWithdraw adds
  one-tick latency to E6." Still true, but unchanged on this
  branch and not specifically a notify-scheme finding. Dropped to
  avoid noise; the fact that the trigger fires from the local
  retired→removed transition still holds.

- **Out-of-band #4 (prior):** "RemoveRRset + Insert in single
  *dns.Msg may be rejected by some commercial registries." Still
  true, but unchanged on this branch. Notably, the new NOTIFY
  scheme is now an alternative *for exactly this case* — registries
  that don't accept the UPDATE wire shape can advertise NOTIFY
  instead and the engine will route around the rejection. This
  isn't called out in the §4 spec, but it's a strong operational
  argument for the NOTIFY path's existence.

### Top-3 list re-prioritized

Prior: [E12, E10, E5]. This audit: [E12, E10, **§4.4 NOTIFY
clarification**]. E5 dropped to fourth not because it became less
important, but because the §4.4 NOTIFY question is the most
actionable open question specific to this branch's work — it will
either be resolved by spec text or by an engine guard, and it
shouldn't ship without a decision. E5 fix is unchanged from the
prior recommendation.
