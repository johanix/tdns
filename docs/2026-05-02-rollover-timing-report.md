# Rollover Timing Engine Audit

**Repo head:** `ddc5615` ("guide/rapid-key-rollover: address review on §4
timing equations")
**Spec:** `tdns/guide/rapid-key-rollover.md` §4
**Scope:** `tdns/v2/` only (skipping `tdns-mp/`)
**Date:** 2026-05-02

---

## E1 — DS-side cache-flush invariant: `T_DS_pub_n + parent_prop + DS_TTL ≤ T_roll_n`

**Verdict:** UNCLEAR (structurally satisfied iff E10 holds; E10 is *not*
validated — see below).

E1 is not enforced as an explicit comparison anywhere. It is implied by
the multi-DS lead time E8, which is in turn determined by
`(N − 1) × KSK_lifetime − retirement_period`. The relevant chain of
code is:

- Pipeline-fill: `ksk_rollover_automated.go:103-118` generates new KSKs
  while `CountKskInRolloverPipeline < num`.
- DS submission target: `ksk_rollover_ds_push.go:64-143`
  (`ComputeTargetDSSetForZone`) produces one DS per SEP key in states
  `created, ds-published, standby, published, active, retired`.
- The push fires on idle ticks when `kskIndexPushNeeded(...)` returns
  true (`ksk_rollover_automated.go:162-176`).

There is no runtime check
`T_DS_pub_n + parent_prop + DS_TTL ≤ T_roll_n`; the engine relies on
the operator having configured `N`, `KSK_lifetime`, and
`retirement_period` correctly. For testbed values it holds with ~9.5m
of headroom (per §4.10), but a bad config (small N, fast cadence)
silently violates E1.

---

## E3 — DNSKEY-side cache-flush invariant: `T_DNSKEY_pub_n + child_prop + DNSKEY_TTL ≤ T_roll_n`

**Verdict:** DIVERGES.

E3 is the invariant that E12 is supposed to schedule against. Because
E12 is implemented as `T_roll − propagationDelay` (no `DNSKEY_TTL`
term — see E12 below), E3 is satisfied only when `DNSKEY_TTL ≤ 0`,
which never happens. In the testbed `DNSKEY_TTL = 5m`, so
`T_DNSKEY_pub_n + child_prop + DNSKEY_TTL = T_roll_n + DNSKEY_TTL`,
i.e., the invariant is violated by `DNSKEY_TTL`. **Operational
consequence:** validators that fetched the DNSKEY RRset in the last
`DNSKEY_TTL` window before `T_roll_n` may serve cached responses
missing `DNSKEY_n`, causing bogus until the cache flushes.

---

## E5 — `retirement_period ≥ min(DNSKEY_TTL, KSK.SigValidity)`

**Verdict:** UNCLEAR (typically holds by accident; not validated).

`effective_margin` is implemented as
`max(clamping.margin, max_observed_ttl)` at
`ksk_rollover_automated.go:1035-1046`:

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

`max_observed_ttl` is recorded from served (post-clamp) RRset headers
during `SignZone`. In steady state
`max_observed_ttl ≥ DNSKEY_TTL ≥ min(DNSKEY_TTL, KSK.SigValidity)`,
so E5 holds. **Divergence:** there is no startup check. An operator
who sets `clamping.margin < min(DNSKEY_TTL, KSK.SigValidity)` AND runs
before any zone has been signed (so `max_observed_ttl = 0`) will get
a `retirement_period = clamping.margin`, which can violate E5. The
§4.5.1 note explicitly calls for this to be a config-load check; it
isn't one.

---

## E6 — `T_DS_pub_n = T_roll_{n−N+1} + retirement_period`

**Verdict:** MATCHES (timing) / MATCHES (trigger).

The State A → State B atomic remove+add is implemented as a
whole-RRset replacement triggered by the local retired → removed
transition:

1. Retired → removed at `ksk_rollover_automated.go:466-479`, gated on
   `now.Sub(*k.RetiredAt) >= effectiveMarginForZone(...)`. This fires
   at `T_roll_{n−N+1} + retirement_period` (KSK_{n−1} retired at
   `T_roll_n` and removed `retirement_period` later — equivalently
   `T_roll_{n−N+1} + retirement_period` for the slot whose DS is
   being added).
2. `triggerResign` re-signs zone without DNSKEY_{n−1} (line 479).
3. `completeRolloverWithdraw` (`ksk_rollover_automated.go:1052`)
   returns the zone to idle.
4. The next idle tick recomputes the target DS set
   (`ksk_rollover_automated.go:167`) and arms a push.
   `PushWholeDSRRset` (`ksk_rollover_ds_push.go:148`) sends the
   whole-RRset replacement.

The trigger is correctly the local retired → removed transition, not
some other event. The exact DS-publish moment is
`T_remove + (one tick latency) + parent_prop`, but the *engine
timestamp* of the action matches E6.

---

## E10 — `(N − 1) × KSK_lifetime ≥ retirement_period + parent_prop + DS_TTL`

**Verdict:** MISSING.

No code path validates E10. Searched `ksk_rollover_policy.go` (the
config-load point) and the only related logic is
`warnDnssecPolicyCoupling` at `ksk_rollover_policy.go:347`, which
warns about `ttls.dnskey` vs `ksk.lifetime` coupling but does not
check E10. **Operational consequence if violated:** the parent's DS
RRset will be replaced (drop DS_{n−1}, add DS_{n+N−1}) too late
before `T_roll_n`, leaving validators with stale DS caches that don't
yet include `DS_n`. Symptom: bogus during the rollover window for a
fraction of validators equal to the cache-fill rate.

---

## E11 — production rule of thumb

**Verdict:** MISSING.

No warning is emitted when `N` is too small relative to
`(retirement_period + parent_prop + DS_TTL) / KSK_lifetime`.
`warnDnssecPolicyCoupling` does not cover this.

---

## E12 — `T_DNSKEY_pub_n = T_roll_n − child_prop − DNSKEY_TTL`

**Verdict:** **DIVERGES.** (This is the headline finding.)

`ksk_rollover_automated.go:842-852`:

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

The function header at `ksk_rollover_automated.go:754-758` explicitly
documents the wrong formula:

```go
// TransitionRolloverKskDsPublishedToStandby advances each SEP key from
// ds-published to standby exactly when its DNSKEY needs to be in the
// served zone for cache-flush safety: T_publish_i = T_roll_i -
// propagationDelay, where T_roll_i = active.active_at + i × KSK.Lifetime
```

`propagationDelay` is sourced from `kasp.propagation_delay` only
(`key_state_worker.go:30-40`). The function has no parameter for
`DNSKEY_TTL` at all — its signature
`(conf, kdb, now, propagationDelay)` (`ksk_rollover_automated.go:776`)
makes the served DNSKEY TTL structurally inaccessible.

Spec §4.7 requires
`T_DNSKEY_pub_n = T_roll_n − child_prop − DNSKEY_TTL`. The
`− DNSKEY_TTL` term is missing.

For the testbed (`child_prop = 1m`, `DNSKEY_TTL = 5m`,
`KSK_lifetime = 10m`): the engine publishes the new DNSKEY at
`T_roll − 1m` instead of `T_roll − 6m`. Validators that cached the
DNSKEY RRset in the 5-minute window before `T_DNSKEY_pub_n` may
carry stale caches across `T_roll_n` and reject `RRSIG_n`. **This is
the bug the §4 spec was written to flag.**

---

## E13 — effective `DNSKEY_TTL = min(ttls.dnskey, ttls.max_served)`

**Verdict:** DIVERGES (E13 is computed for the served wire TTL via
the clamp pipeline, but the value is **not** consumed by E12).

The clamp pipeline computes the served TTL at
`ksk_rollover_clamp.go:298-318`, taking
`min(UnclampedTTL, K·margin if K>0, MaxServedTTL if >0)`, with
`MaxServedTTL` from `pol.TTLS.MaxServed`
(`ksk_rollover_clamp.go:174`). That value is applied to RRset headers
during `SignRRset` and observed by `LoadZoneSigningMaxTTL` for the
`effective_margin` calculation.

But E12's call site does not use it.
`TransitionRolloverKskDsPublishedToStandby` only receives
`propagationDelay`. Even if E12 were corrected to subtract a DNSKEY
TTL, no caller currently passes one in, and there is no
`min(ttls.dnskey, ttls.max_served)` expression in the rollover-engine
path. **Operational consequence:** even fixing E12 requires plumbing
the clamped DNSKEY TTL through to this function.

---

## §4.4 — parent's DS RRset is always exactly N records, cycling A↔B atomically

**Verdict:** MATCHES (with one caveat).

Three pieces conspire correctly:

1. **Pipeline-fill targets N.** `ksk_rollover_automated.go:104-118`:

```go
num := pol.Rollover.NumDS
for {
    n, err := CountKskInRolloverPipeline(kdb, zone)
    ...
    if n >= num { break }
    kid, _, err := GenerateKskRolloverCreated(...)
}
```

`CountKskInRolloverPipeline` (`ksk_rollover_pipeline.go:139`) counts
SEP keys in
`{created, ds-published, standby, published, active, retired}` —
the same set `ComputeTargetDSSetForZone` publishes. So local pipeline
size = parent DS-set cardinality.

2. **Atomic A→B transition.** `BuildChildWholeDSUpdate`
   (`ksk_rollover_ds_push.go:24-48`) issues a single `*dns.Msg`
   containing both `RemoveRRset` (DEL ANY DS at owner) and `Insert`
   of the new set. RFC 2136 commits the update section as one
   transaction; from the parent's view it is atomic.

3. **Pipeline-fill runs *before* the idle-branch DS push** within
   the same `RolloverAutomatedTick` (lines 104-118 precede line 162).
   After retired→removed drops local pipeline to N−1, the next tick
   generates KSK_{n+N−1} *first*, then `ComputeTargetDSSetForZone`
   includes its DS, then the UPDATE is built. The whole-RRset UPDATE
   arrives at the parent containing the correct N records.

**Caveat — wire-level "DEL ANY + INSERT" is not literally an atomic
remove-this-one-and-add-that-one operation.** The spec describes the
transition as "drop DS_{n−1} and add DS_{n+N−1}" but the
implementation drops *all* N records and replaces them. The committed
result is identical (N records, with the right contents), and from a
serving-secondary view it is a single atomic update. But §4.4's
wording suggests a more surgical update; an operator reading the wire
might be surprised. Marking MATCHES because the contract on the
parent's served RRset (always N, cycles between A and B) is upheld.

---

## §4.5(b) — child-side DNSKEY removal happens *before* parent DS UPDATE

**Verdict:** MATCHES.

Sequence within `pendingChildWithdraw`:

1. `ksk_rollover_automated.go:470` —
   `UpdateDnssecKeyState(kdb, zone, k.KeyTag, DnskeyStateRemoved)`:
   local DNSKEY_{n−1} removed from served set (`PublishDnskeyRRs`
   filters out `removed`).
2. `ksk_rollover_automated.go:479` — `triggerResign(conf, zone)`:
   zone re-signed by KSK_n (no signatures from KSK_{n−1}).
3. `ksk_rollover_automated.go:482` — `completeRolloverWithdraw`
   clears `rollover_in_progress` and sets `rolloverPhaseIdle`. Also
   calls `triggerResign` (line 1074).
4. **Next tick:** idle branch (`ksk_rollover_automated.go:162`)
   recomputes target DS set, arms `pendingParentPush`, fires
   `PushWholeDSRRset`.

So local DNSKEY removal + zone re-sign always precede the parent
UPDATE by at least one tick (and by `triggerResign`'s actual
completion). Order is correct per §4.5(b).

---

## Out-of-band findings

1. **E12's docstring documents the wrong formula.**
   `ksk_rollover_automated.go:754-758` declares the formula as
   `T_publish = T_roll - propagationDelay` and even justifies "why
   not": this is not a stale comment from a prior implementation, it
   describes the present (incorrect) behaviour as the design intent.
   Fixing E12 requires editing both code and this docstring.

2. **`TransitionRolloverKskDsPublishedToStandby` is
   signature-bottlenecked.** It accepts only
   `(conf, kdb, now, propagationDelay)`. It cannot consult
   `pol.TTLS.Dnskey` or `pol.TTLS.MaxServed` without a signature
   change, even though `pol` is already available via
   `Zones.Get(zoneName).DnssecPolicy` inside the loop
   (`ksk_rollover_automated.go:794-798`). The fix is local (compute
   `min(ttls.dnskey, ttls.max_served)` from the per-zone policy and
   subtract it in addition to `propagationDelay`).

3. **`completeRolloverWithdraw` adds one-tick latency to E6.** The
   State A → State B UPDATE doesn't fire in the same tick as
   retired→removed; it fires on the next idle tick that evaluates
   `kskIndexPushNeeded`. With check-interval = 1m this is ≤ 1m of
   slop. Acceptable, but the spec language ("the same DNS UPDATE
   drops DS_{n−1} and adds DS_{n+N−1}") might be read to imply
   same-tick. Worth a clarifying note in the spec.

4. **`m.RemoveRRset` followed by `m.Insert` in a single `*dns.Msg`**
   is wire-correct under RFC 2136 §3.4, but some primaries (notably
   some commercial registries) reject UPDATEs that mix DEL ANY +
   INSERT for the same RRset. Not a §4 issue, but operationally
   relevant for the multi-DS pipeline.

---

## Summary

| Item | Verdict |
|------|---------|
| E1  (DS-side invariant) | UNCLEAR (depends on E10) |
| E2  (E1 rearranged) | UNCLEAR |
| E3  (DNSKEY-side invariant) | DIVERGES (consequence of E12) |
| E4  (E3 rearranged) | DIVERGES |
| E5  (retirement_period sizing) | UNCLEAR (typically holds; not validated) |
| E6  (T_DS_pub_n trigger/timing) | MATCHES |
| E7  (E6 rearranged) | MATCHES |
| E8  (lead_DS) | UNCLEAR (depends on E10) |
| E9  (E1+E8) | UNCLEAR |
| E10 (cadence constraint) | MISSING (no config-load validation) |
| E11 (rule-of-thumb warning) | MISSING |
| **E12 (DNSKEY ds-published→standby)** | **DIVERGES — missing −DNSKEY_TTL term** |
| E13 (effective DNSKEY_TTL) | DIVERGES (computed for clamp; not consumed by E12) |
| §4.4 (parent DS RRset contract) | MATCHES |
| §4.5(b) (action ordering) | MATCHES |

## Top-3 findings to fix first

1. **E12 is wrong (`tPublish = tRoll − propagationDelay`, missing
   `− DNSKEY_TTL`).** `ksk_rollover_automated.go:847`. This is the
   canonical bug §4 was written to expose: every rollover where a
   validator queries DNSKEY in the last `DNSKEY_TTL` before
   `T_roll_n` risks bogus until cache flush. On the testbed
   (`DNSKEY_TTL = 5m`, `child_prop = 1m`, `KSK_lifetime = 10m`), the
   engine publishes new DNSKEYs ~5 minutes too late. Fix: extend the
   function signature to accept the per-zone served DNSKEY TTL =
   `min(pol.TTLS.Dnskey, pol.TTLS.MaxServed)` and subtract it on top
   of `propagationDelay`. Update the docstring (it documents the bug
   as the intended behaviour). Also propagate this change to **E13**
   consumption — there is currently no caller computing the clamped
   DNSKEY TTL.

2. **E10 has no config-load validation.** Operators can trivially
   configure a policy where
   `(N − 1) × KSK_lifetime < retirement_period + parent_prop + DS_TTL`
   and the engine will silently violate the DS-side cache-flush
   invariant. Symptoms only appear during a rollover, so policies
   can be deployed for days before failing. Add a hard error in
   `ksk_rollover_policy.go`'s policy load (alongside
   `warnDnssecPolicyCoupling`). Note that `DS_TTL` is observable,
   not configured; the validator can either use `ds-publish-delay`
   as an upper-bound proxy (per §4.9) or fall back to a conservative
   default if no observation is recorded yet.

3. **E5 is not validated and has a quiet-failure mode at first-run.**
   `effective_margin = max(clamping.margin, max_observed_ttl)`
   correctly satisfies E5 *after* the first sign pass populates
   `max_observed_ttl`. Before that — including the first rollover
   after a fresh deployment, or after `LoadZoneSigningMaxTTL`
   returns 0 due to a DB quirk — the engine uses `clamping.margin`
   alone, which an operator can set below
   `min(DNSKEY_TTL, KSK.SigValidity)`. Add the explicit policy-load
   check `clamping.margin ≥ min(ttls.dnskey, ksk.sig_validity)` per
   §4.5.1's recommendation.
