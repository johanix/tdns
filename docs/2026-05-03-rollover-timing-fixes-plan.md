# Rollover Timing Engine Fixes — Implementation Plan

**Date:** 2026-05-03
**Base branch:** `rollover-notify-scheme`
**Scope:** `tdns/v2/` only
**Drives off:** `tdns/docs/2026-05-02-rollover-timing-report.md` and
`tdns/docs/2026-05-02-rollover-timing-report-rollover-notify-scheme.md`

---

## Recommendation: where to fix

Fix on `rollover-notify-scheme` directly.

`rollover-overhaul` is already merged into main (PR #207, commit
`104a8bf`); it is not a parallel feature branch. `rollover-notify-scheme`
is 13 commits ahead of main and is what will eventually merge.
Per-equation findings are byte-identical between main and notify-scheme:
phases 1–10 of the notify work didn't touch
`TransitionRolloverKskDsPublishedToStandby`, `effectiveMarginForZone`,
`warnDnssecPolicyCoupling`, or `key_state_worker.go`.

Phase 1's `RolloverEngineDeps` refactor is a near-perfect seam for the
E12 fix — the deps struct already carries `Policy`. Fixing on main first
would mean redoing the same plumbing and resolving conflicts on rebase.

---

## Workstreams

### W1 — E12/E13 fix: plumb DNSKEY TTL into the DS-published→standby transition

**Spec:** `T_DNSKEY_pub_n = T_roll_n − child_prop − DNSKEY_TTL`. The
`− DNSKEY_TTL` term is currently missing — `tPublish := tRoll.Add(-propagationDelay)`
at `ksk_rollover_automated.go:1004-1005`.

**Approach:**

- Migrate `TransitionRolloverKskDsPublishedToStandby` to take a
  `*RolloverEngineDeps` (or a thin subset) instead of
  `(conf, kdb, now, propagationDelay)`. Reuse the Phase 1 pattern.
- Compute `dnskeyTTL = effectiveServedDnskeyTTL(pol)` per zone:
  - If both `pol.TTLS.DNSKEY > 0` and `pol.TTLS.MaxServed > 0`:
    `min(pol.TTLS.DNSKEY, pol.TTLS.MaxServed)` (E13).
  - If only one is set: that one.
  - Otherwise: `LoadZoneSigningMaxTTL(kdb, zone)` (observed from served
    headers).
  - If still zero (zone never signed yet): defer this transition for
    this zone this tick, retry next tick. Don't `SetError` — the
    condition is transient and clears after first SignZone.
- Compute `tPublish := tRoll.Add(-(propagationDelay + dnskeyTTL))`.
- Update the docstring at `ksk_rollover_automated.go:912-933` to state
  the corrected formula and remove the "Why not" justification of the
  bug.

**Files:** `ksk_rollover_automated.go`, `key_state_worker.go`,
`ksk_rollover_policy.go` (helper).

**Complexity:** Low-medium.

**Risk:** Medium. Pushes DNSKEY publication earlier by `DNSKEY_TTL`.
Zones in flight across an upgrade will see a different timing curve.
Operationally correct (this *is* the cache-flush invariant), but
visible.

**LOC:** ~+60 / −10 / Δ50.

---

### W2 — E5/E10/E11 config-load validation, per-zone reporting

**Spec:**
- E5: `retirement_period ≥ min(DNSKEY_TTL, KSK.SigValidity)`
- E10: `(N − 1) × KSK_lifetime ≥ retirement_period + parent_prop + DS_TTL`
- E11: warn if `N` is impractically tight against the same ratio

**Approach:**

- Add `validateDnssecPolicyTimingInvariants(policyName, *DnssecPolicy)`
  called from `parseDnssecPolicy` after `fillRolloverDurations`.
- E5 hard error (when clamping enabled):
  `clamping.margin < min(ttls.dnskey, ksk.sig-validity)`.
- E10 cannot be checked at config-load — it depends on the parent's DS
  TTL, which is observable, not configured. Strategy:
  - At zone init (OnFirstLoad / parent-agent setup, ASAP), issue an
    explicit DS query to the parent agent for the zone apex.
  - Cache the observed TTL on `zd.ParentDSTTLObserved uint32`.
  - Run E10 check immediately when the value arrives.
  - Re-run E10 if the observed TTL changes on a subsequent observe poll.
- New optional `ttls.ds` policy field as override (testbed
  determinism, parents whose DS isn't yet observable). No fallback to
  `ttls.dnskey` approximation.
- E11 warning: `NumDS < ceil((retirement_period + parent_prop + DS_TTL) / KSK.Lifetime) + 1`.
- All violations: `zd.SetError(RolloverPolicyViolation, msg)`. Zone keeps
  serving normally; only automated rollover progression is gated. Cleared
  when the condition resolves (e.g., parent DS TTL observation drops, or
  policy reload fixes the violation).

**Files:** `ksk_rollover_policy.go`, `structs.go` (`Ttls.DS`,
`zd.ParentDSTTLObserved`), zone init path, possibly a new
`ksk_rollover_validation.go`.

**Complexity:** Medium. The arithmetic is trivial; the parent-DS-TTL
plumbing is the bulk of the work.

**Risk:** Low-medium. Per-zone gating means no server-wide failure mode.
Zones with policy violations stop progressing rollover but otherwise
serve normally.

**LOC:** ~+180 / −5 / Δ175.

---

### W4 — Immediate `zd.SetError` on `errNoUsableScheme`

**Background:** Dispatcher maps `errNoUsableScheme` (parent advertises
no scheme matching `dsync-scheme-preference`) to
`SoftfailChildConfigWaitingForParent` and retries forever. No
operator-visible signal.

**Approach:**

- On entering the softfail-waiting-for-parent state for a zone:
  `zd.SetError(RolloverPolicyViolation, "parent advertises no DSYNC scheme matching policy preference <X>; rollover blocked")`.
- Engine continues to retry forever (unchanged from current behavior —
  parent may fix DSYNC at any time).
- On next dispatch where parent advertises a usable scheme: clear the
  error (`zd.ClearError(RolloverPolicyViolation)`).
- No timeout, no hardfail transition. The error is purely an
  operator-visibility signal.

**Files:** `ksk_rollover_ds_push.go`, possibly
`ksk_rollover_categories.go`.

**Complexity:** Low.

**Risk:** Low.

**LOC:** ~+25 / −5 / Δ20.

---

### W5 — Hoist keystore load before parallel dispatch

**Background:** Auto-mode dispatch runs UPDATE and NOTIFY paths in
parallel. Each calls `loadTargetKSKsForRollover` independently;
microseconds apart, but under heavy state-transition pressure they could
write divergent DS sets.

**Approach:** Hoist the keystore load to before the parallel dispatch
in `PushDSRRsetForRollover`. Pass the resolved
`[]*DnssecKeyWithTimestamps` (or computed RRset) into both
`pushDSRRsetViaUpdate` and `pushDSRRsetViaNotify` as a parameter. Both
paths now describe identical sets by construction.

**Files:** `ksk_rollover_ds_push.go`.

**Complexity:** Low.

**Risk:** Low. Strictly tightens an existing race; no semantics change
in the no-race case.

**LOC:** ~+25 / −20 / Δ5.

---

### W6 — NOTIFY scheme parent_prop guidance

**Background:** Under NOTIFY, `parent_prop` includes "parent fetches CDS"
— a longer chain than UPDATE. Operators may need a different
`rollover.ds-publish-delay` value but the engine doesn't tell them.

**Approach:**

- New optional policy field `rollover.parent-cds-poll-estimate`
  (default `1m`, reflecting that NOTIFY exists to make parent CDS
  fetches near-instant).
- When NOTIFY is the only viable scheme (`force-notify`, or
  `prefer-notify` and parent only advertises NOTIFY), substitute
  `parent-cds-poll-estimate` for `parent_prop` in the E10 check.
- Emit one INFO log per policy at load when NOTIFY-only resolves.

**Files:** `structs.go`, `ksk_rollover_policy.go`.

**Complexity:** Low.

**Risk:** Low.

**LOC:** ~+40 / 0 / Δ40.

---

### W7 — `RolloverEngineDeps` migration follow-through

**Background:** Phase 1 introduced `RolloverEngineDeps` but didn't
migrate every rollover-engine entry point. Consistency follow-through.

**Approach:** Audit all functions called from `KeyStateWorker` /
`checkAndTransitionKeys` that take `(conf, kdb, ...)` signatures and
migrate to `*RolloverEngineDeps`. Cap the scope to functions called
directly from those entry points.

**Files:** `ksk_rollover_automated.go`, `key_state_worker.go`, possibly
`ksk_rollover_zone_state.go`.

**Complexity:** Medium. Pure refactor, but wide.

**Risk:** Low — refactor only — but adds noise to the diff.

**LOC:** ~+80 / −60 / Δ20.

---

### W8 — Tests

For each fix:

- W1: timing-math test asserting
  `tPublish == tRoll − child_prop − DNSKEY_TTL`.
- W2: policy-load tests for E5, E10, E11 acceptance and rejection
  cases; parent-DS-TTL observation flow.
- W4: immediate-flag-on-detection test, clear-on-recovery test.
- W5: best-effort race regression (hard to write reliably).
- W9: multi-error coexistence test, CLI gating tests.

Plus a single rollover-invariant smoke test that loads a representative
testbed policy and asserts E1, E5, E10 all hold.

**LOC:** ~+280 / 0 / Δ280.

---

### W9 — Multi-error infrastructure + auto-rollover CLI gating

**Background:** `zd.SetError` is single-error-only today (one
`ErrorType` + one `ErrorMsg` per zone, `enums.go:234`). The unified
per-zone visibility model (W2 + W4) needs `zd` to carry multiple
simultaneous errors without a priority rule.

**Approach:**

**Part 1 — `SetError` evolves to a slice/map-backed registry:**

- New field `zd.Errors map[ErrorType]ZoneError` (or slice, depending on
  how often we read).
- `SetError(errtype, msg, args...)` upserts that category (replaces
  prior msg for same type, doesn't touch other types).
- New `ClearError(errtype)` clears one category.
- `ClearError(NoError)` (or new `ClearAllErrors`) clears all.
- `zd.Error bool` and `zd.ErrorType` become derived for back-compat
  with the ~20 existing read sites in refresh-engine, notify-responder,
  query handlers, and apihandler_zone.

**Part 2 — New `RolloverPolicyViolation` error category:**

- Add to `ErrorType` enum in `enums.go`.
- Add string mapping `"rollover-policy"`.
- Set by W2 (E5/E10) and W4 (waiting-for-parent), cleared on resolution.

**Part 3 — Auto-rollover CLI gating:**

- `auto-rollover status`: prepend "automated rollovers not possible due
  to: <msg>" if `RolloverPolicyViolation` is set.
- `auto-rollover when`: emit "blocked: <msg>" instead of computing.
- `auto-rollover asap`: refuse with non-zero exit + the error message.
- `auto-rollover cancel`, `reset`, `unstick`: still functional with a
  warning header.
- `zone list`: render multi-error correctly.

**Files:** `enums.go`, `structs.go`, `apihandler_zone.go`, all CLI
rollover files, `refreshengine.go`, `notifyresponder.go`,
`defaultqueryhandlers.go`, `updateresponder.go`, `catalog.go`,
`parseoptions.go`, `dynamic_zones.go`, `zone_utils.go`.

**Complexity:** Medium. Wide blast radius. Back-compat derived fields
keep most call sites untouched.

**Risk:** Medium.

**LOC:** ~+180 / −20 / Δ160.

---

## Dropped from earlier drafts: §4.4 NOTIFY clarification

Earlier drafts proposed a spec edit (and code log) to distinguish
UPDATE-based and NOTIFY-based parent DS atomicity. Dropped: the trust
model is identical — a parent receiving DNS UPDATE for DS is just as
free to ignore/cherry-pick as one receiving NOTIFY(CDS). In practice
parents don't differentiate.

---

## Aggregate LOC

| Workstream | Adds | Deletes | Net Δ |
|---|---|---|---|
| W1 (E12/E13)             | +60  | −10  | +50  |
| W2 (E5/E10/E11 + per-zone) | +180 | −5   | +175 |
| W4 (waiting-for-parent)  | +25  | −5   | +20  |
| W5 (auto-mode race)      | +25  | −20  | +5   |
| W6 (NOTIFY guidance)     | +40  | 0    | +40  |
| W7 (deps migration)      | +80  | −60  | +20  |
| W8 (tests)               | +280 | 0    | +280 |
| W9 (multi-error + CLI)   | +180 | −20  | +160 |
| **Total**                | **+870** | **−120** | **+750** |

For reference: notify-scheme branch was +2179/−116. This plan is ~1/3.

---

## Merge order

1. W9 — multi-error infrastructure + new `RolloverPolicyViolation`
   category. Must land first — W2 and W4 depend on it.
2. W2 — policy validation + parent DS-TTL query + per-zone error
   reporting.
3. W4 — immediate `zd.SetError` on `errNoUsableScheme`.
4. W6 — NOTIFY operator guidance.
5. W1 — E12/E13 fix.
6. W5 — auto-mode race tightening.
7. W7 — deps migration follow-through.
8. W8 — tests interleaved with each workstream.

---

## Complexity analysis

| Dimension                | Rating       | Notes |
|---|---|---|
| Algorithmic complexity   | Low          | All changes are arithmetic on parsed values. |
| State-machine complexity | Low          | No new dispatcher transitions; W4 just flags. |
| Cross-file coupling      | Medium       | W9 has wide blast radius; W7 ripples through entry points. |
| Test surface             | Medium       | Timing math testable; parallel-dispatch race not. |
| Spec-vs-code alignment   | High         | Whole point is to close spec gaps. |

## Risk analysis

| Risk | Severity | Likelihood | Mitigation |
|---|---|---|---|
| W1 timing change visible to running zones | Medium | Medium | Document; this is the correctness fix. |
| W9 multi-error API change breaks existing read sites | Medium | Medium | Back-compat derived `Error`/`ErrorType` fields. |
| W2 parent-DS-TTL query never resolves (parent unreachable at init) | Medium | Low | Defer E10 check, retry on observe poll. Zone keeps serving; rollover gated until check passes. |
| W7 scope creep | Medium | Medium | Hard cap to functions called from `KeyStateWorker`. |
| Plan misreads spec (E12 off by sign or term) | High | Low | W8 unit test asserts exact §4.7 formula. |

## Key invariant (from spec §4)

The whole audit boils down to two cache-flush invariants. Implementation
must satisfy both:

- E1 (DS side):
  `T_DS_pub_n + parent_prop + DS_TTL ≤ T_roll_n`
- E3 (DNSKEY side):
  `T_DNSKEY_pub_n + child_prop + DNSKEY_TTL ≤ T_roll_n`

Currently E3 is violated by `DNSKEY_TTL` (the missing term in E12).
W1 fixes this directly. E1 is structurally implied by E10/E8 once W2
validates.
