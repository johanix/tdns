package tdns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// EvaluateRolloverPolicyInvariants checks the §4 cache-flush invariants
// and the production rule-of-thumb (E5, E10, E11) against the live
// state of zd and pol. Violations are surfaced via
// zd.SetError(RolloverPolicyViolation, ...); when no violation exists,
// any prior RolloverPolicyViolation is cleared.
//
// Inputs the function reads:
//
//   - pol.KSK.Lifetime, KSK.SigValidity
//   - pol.Rollover.NumDS
//   - pol.Rollover.DsPublishDelay (proxy for parent_prop, per §4.9)
//   - pol.Clamping.{Enabled, Margin}
//   - pol.TTLS.{DNSKEY, MaxServed, DS}
//   - zd.ParentDSTTLObserved
//
// Behaviour when DS_TTL is not yet known (pol.TTLS.DS == 0 AND
// zd.ParentDSTTLObserved == 0): E10/E11 are deferred (no error
// raised, but no clearance either if E10/E11 were the active
// condition). E5 is checked unconditionally — it does not depend on
// the parent DS TTL.
//
// Multiple violations coexist as a single concatenated error message
// (the multi-error registry already separates by category; one
// category per call site keeps the operator's mental model simple).
func EvaluateRolloverPolicyInvariants(zd *ZoneData, pol *DnssecPolicy) {
	if zd == nil || pol == nil || pol.Rollover.Method == RolloverMethodNone {
		return
	}

	var msgs []string

	if m := checkE5(pol); m != "" {
		msgs = append(msgs, m)
	}

	dsTTL, dsTTLKnown := resolveDSTTL(zd, pol)
	if dsTTLKnown {
		if m := checkE10(pol, dsTTL); m != "" {
			msgs = append(msgs, m)
		}
		if m := checkE11(pol, dsTTL); m != "" {
			msgs = append(msgs, m)
		}
	}

	if len(msgs) == 0 {
		zd.ClearError(RolloverPolicyViolation)
		return
	}
	zd.SetError(RolloverPolicyViolation, "%s", strings.Join(msgs, "; "))
}

// resolveDSTTL returns the DS TTL the engine should use for E10/E11.
// Override (pol.TTLS.DS) wins over observation (zd.ParentDSTTLObserved)
// when both are set: the operator may have explicit knowledge that the
// observation doesn't capture (e.g., parent's DS RRset cached behind
// a CDN with a shorter TTL than the authoritative answer).
func resolveDSTTL(zd *ZoneData, pol *DnssecPolicy) (time.Duration, bool) {
	if pol.TTLS.DS > 0 {
		return time.Duration(pol.TTLS.DS) * time.Second, true
	}
	if zd != nil && zd.ParentDSTTLObserved > 0 {
		return time.Duration(zd.ParentDSTTLObserved) * time.Second, true
	}
	return 0, false
}

// checkE5: retirement_period ≥ min(DNSKEY_TTL, KSK.SigValidity).
//
// retirement_period is implemented as effective_margin =
// max(clamping.margin, max_observed_ttl) — see effectiveMarginForZone.
// The lower bound at config-load time is clamping.margin (when
// clamping is enabled); max_observed_ttl can only push it higher. So
// E5 is satisfied iff clamping.margin >= min(DNSKEY_TTL, sig-validity)
// when clamping is enabled.
//
// When clamping is disabled, retirement_period defaults to the
// observed TTL alone, which is post-clamp — implicit E5 satisfaction
// when the operator has set non-zero TTLs in policy. Skip the check
// in that case to avoid false positives at startup.
func checkE5(pol *DnssecPolicy) string {
	if !pol.Clamping.Enabled || pol.Clamping.Margin <= 0 {
		return ""
	}
	dnskeyTTL := time.Duration(pol.TTLS.DNSKEY) * time.Second
	sigVal := time.Duration(pol.KSK.SigValidity) * time.Second
	if dnskeyTTL == 0 && sigVal == 0 {
		return ""
	}
	floor := dnskeyTTL
	if sigVal > 0 && (floor == 0 || sigVal < floor) {
		floor = sigVal
	}
	if pol.Clamping.Margin >= floor {
		return ""
	}
	return fmt.Sprintf("E5: clamping.margin (%s) < min(ttls.dnskey, ksk.sig-validity) (%s); "+
		"retirement period too short to flush DNSKEY/RRSIG caches before next rollover",
		pol.Clamping.Margin, floor)
}

// checkE10: (N − 1) × KSK.Lifetime ≥ retirement_period + parent_prop + DS_TTL.
//
// retirement_period at config-load is clamping.margin (the operator-
// controllable lower bound; effective_margin only ever grows this).
// parent_prop is approximated by rollover.ds-publish-delay (§4.9), plus
// rollover.parent-cds-poll-estimate when force-notify is the chosen
// scheme — under NOTIFY-only the parent has to fetch CDS before
// updating its DS RRset, which adds latency on top of ds-publish-delay.
// DS_TTL is the resolved value from resolveDSTTL.
func checkE10(pol *DnssecPolicy, dsTTL time.Duration) string {
	n := pol.Rollover.NumDS
	if n < 2 {
		return ""
	}
	kskLifetime := time.Duration(pol.KSK.Lifetime) * time.Second
	if kskLifetime <= 0 {
		return ""
	}
	retirement := pol.Clamping.Margin
	parentProp := pol.Rollover.DsPublishDelay
	if pol.Rollover.DsyncSchemePreference == DsyncSchemePreferenceForceNotify {
		parentProp += pol.Rollover.ParentCdsPollEstimate
	}
	required := retirement + parentProp + dsTTL
	available := time.Duration(n-1) * kskLifetime
	if available >= required {
		return ""
	}
	return fmt.Sprintf("E10: (N-1)*KSK.Lifetime (%s = %d * %s) < retirement_period + parent_prop + DS_TTL "+
		"(%s = %s + %s + %s); parent DS replacement too late before next rollover",
		available, n-1, kskLifetime,
		required, retirement, parentProp, dsTTL)
}

// checkE11: production rule of thumb — N should comfortably exceed
// (retirement_period + parent_prop + DS_TTL) / KSK.Lifetime. Warning
// (not error): "comfortably" is operator judgement.
//
// We flag when the ratio of available to required lead time is below
// 1.25 (i.e., less than 25% headroom). Exact threshold is somewhat
// arbitrary; the spec doesn't pin a number.
func checkE11(pol *DnssecPolicy, dsTTL time.Duration) string {
	n := pol.Rollover.NumDS
	if n < 2 {
		return ""
	}
	kskLifetime := time.Duration(pol.KSK.Lifetime) * time.Second
	if kskLifetime <= 0 {
		return ""
	}
	parentProp := pol.Rollover.DsPublishDelay
	if pol.Rollover.DsyncSchemePreference == DsyncSchemePreferenceForceNotify {
		parentProp += pol.Rollover.ParentCdsPollEstimate
	}
	required := pol.Clamping.Margin + parentProp + dsTTL
	if required <= 0 {
		return ""
	}
	available := time.Duration(n-1) * kskLifetime
	if available*4 >= required*5 {
		// At least 25% headroom — comfortable.
		return ""
	}
	return fmt.Sprintf("E11: N=%d gives only %s of lead time vs %s required (less than 25%% headroom); "+
		"consider raising rollover.num-ds or KSK.lifetime",
		n, available, required)
}

// ObserveParentDSTTL queries the parent agent for the zone's DS RRset
// and records the observed TTL on zd.ParentDSTTLObserved. After the
// observation the function re-evaluates E10/E11 via
// EvaluateRolloverPolicyInvariants. Failures are logged and do not
// raise a policy violation — the engine retries on every observe poll.
//
// Safe to call repeatedly. Pol may be nil (no-op).
func ObserveParentDSTTL(ctx context.Context, zd *ZoneData, pol *DnssecPolicy) {
	if zd == nil || pol == nil || pol.Rollover.Method == RolloverMethodNone {
		return
	}
	if pol.Rollover.ParentAgent == "" {
		return
	}
	rrs, err := QueryParentAgentDS(ctx, zd.ZoneName, pol.Rollover.ParentAgent)
	if err != nil {
		lgRollover.Debug("rollover: parent DS observation failed",
			"zone", zd.ZoneName, "agent", pol.Rollover.ParentAgent, "err", err)
		return
	}
	ttl := minDSTTL(rrs)
	if ttl == 0 {
		return
	}
	if zd.ParentDSTTLObserved != ttl {
		lgRollover.Info("rollover: parent DS TTL observed",
			"zone", zd.ZoneName, "ttl", ttl, "agent", pol.Rollover.ParentAgent)
		zd.ParentDSTTLObserved = ttl
	}
	EvaluateRolloverPolicyInvariants(zd, pol)
}

// recordParentDSTTLObservation updates zd.ParentDSTTLObserved from the
// DS records returned by a successful parent-agent poll and re-runs
// EvaluateRolloverPolicyInvariants. No-op when the zone is not in the
// Zones map (defensive — observe poll callers always have a registered
// zone). Safe to call from any rollover-engine code path that has
// already issued QueryParentAgentDS.
func recordParentDSTTLObservation(zone string, pol *DnssecPolicy, rrs []dns.RR) {
	zd, ok := Zones.Get(zone)
	if !ok || zd == nil {
		return
	}
	ttl := minDSTTL(rrs)
	if ttl == 0 {
		return
	}
	if zd.ParentDSTTLObserved != ttl {
		lgRollover.Info("rollover: parent DS TTL observed",
			"zone", zone, "ttl", ttl)
		zd.ParentDSTTLObserved = ttl
		Zones.Set(zone, zd)
	}
	EvaluateRolloverPolicyInvariants(zd, pol)
}

// minDSTTL returns the smallest TTL among DS RRs in rrs (seconds).
// Zero if no DS records found. Using min keeps the validator
// pessimistic — caches that hold the longest-TTL record dominate
// invalidation latency, but the smallest TTL bounds when the *first*
// validator might re-fetch.
func minDSTTL(rrs []dns.RR) uint32 {
	var min uint32
	for _, rr := range rrs {
		if _, ok := rr.(*dns.DS); !ok {
			continue
		}
		t := rr.Header().Ttl
		if min == 0 || t < min {
			min = t
		}
	}
	return min
}
