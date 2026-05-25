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
//   - pol.KSK.Lifetime, SigValidity.DNSKEY
//   - pol.Rollover.NumDS
//   - pol.Rollover.DsPublishDelay (proxy for parent_prop, per §4.9)
//   - pol.Clamping.{Enabled, Margin}
//   - pol.TTLS.{DNSKEY, MaxServed, DS}
//   - zd.ParentDSTTLObserved
//
// Behaviour when DS_TTL is not yet known (pol.TTLS.ParentDS == 0 AND
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

	// Two severities, one combined error category each:
	//   - RolloverPolicyViolation: E5 (hard) and E10 (hard).
	//   - RolloverPolicyWarning: E11 (rule of thumb).
	//
	// E5 is config-only (no DS_TTL needed); E10/E11 require a
	// resolved DS_TTL. When DS_TTL is unknown (parent unreachable
	// at zone init, no ttls.parent-ds override, no prior observation),
	// we can only freshly evaluate E5 — so we must NOT clobber any
	// prior E10/E11 state. Strategy:
	//
	//   * Always evaluate E5 immediately.
	//   * If DS_TTL known: evaluate all three, write the combined
	//     fresh state for both categories.
	//   * If DS_TTL unknown: write a refreshed E5-only state on
	//     the violation category, but *only if the E5 result has
	//     toggled* — otherwise leave the category alone so any
	//     prior E10 message is preserved. The warning category is
	//     left entirely alone.
	e5 := checkE5(pol)
	dsTTL, dsTTLKnown := resolveDSTTL(zd, pol)

	if !dsTTLKnown {
		// Best-effort E5-only update. We can clear the violation
		// only if E5 passes AND the prior message (if any) was
		// E5-only. We don't have provenance, so the safe choice is:
		// only modify the category when E5 is currently failing
		// (set fresh E5 message) — never clear, since clearing
		// might drop a prior E10 we can't re-confirm. Same for
		// warnings: leave alone.
		if e5.Failed() {
			zd.SetError(RolloverPolicyViolation, "%s", e5.Message)
		}
		// else: leave both categories alone.
		return
	}

	var violations, warnings []string
	if e5.Failed() {
		violations = append(violations, e5.Message)
	}
	if r := checkE10(pol, dsTTL); r.Failed() {
		violations = append(violations, r.Message)
	}
	if r := checkE11(pol, dsTTL); r.Failed() {
		warnings = append(warnings, r.Message)
	}

	if len(violations) == 0 {
		zd.ClearError(RolloverPolicyViolation)
	} else {
		zd.SetError(RolloverPolicyViolation, "%s", strings.Join(violations, "; "))
	}
	if len(warnings) == 0 {
		zd.ClearError(RolloverPolicyWarning)
	} else {
		zd.SetError(RolloverPolicyWarning, "%s", strings.Join(warnings, "; "))
	}
}

// resolveDSTTL returns the DS TTL the engine should use for E10/E11.
// Override (pol.TTLS.ParentDS) wins over observation (zd.ParentDSTTLObserved)
// when both are set: the operator may have explicit knowledge that the
// observation doesn't capture (e.g., parent's DS RRset cached behind
// a CDN with a shorter TTL than the authoritative answer).
func resolveDSTTL(zd *ZoneData, pol *DnssecPolicy) (time.Duration, bool) {
	if pol.TTLS.ParentDS > 0 {
		return time.Duration(pol.TTLS.ParentDS) * time.Second, true
	}
	if zd != nil && zd.ParentDSTTLObserved > 0 {
		return time.Duration(zd.ParentDSTTLObserved) * time.Second, true
	}
	return 0, false
}

// InvariantResult is the output of one §4 invariant check. Empty
// Message means "this invariant passes (or is not applicable)" — the
// runtime path uses the message-or-empty contract directly. Suggestion
// is operator-actionable remediation text used by `auto-rollover
// validate`; the runtime path discards it.
type InvariantResult struct {
	Message    string
	Suggestion string
}

func (r InvariantResult) Failed() bool { return r.Message != "" }

// Public wrappers for the §4 invariant checks. Used by the
// `auto-rollover validate` CLI command (in package tdns/cli) which
// needs to run the same checks against an offline-parsed policy.
func CheckE5(pol *DnssecPolicy) InvariantResult                       { return checkE5(pol) }
func CheckE10(pol *DnssecPolicy, dsTTL time.Duration) InvariantResult { return checkE10(pol, dsTTL) }
func CheckE11(pol *DnssecPolicy, dsTTL time.Duration) InvariantResult { return checkE11(pol, dsTTL) }

// checkE5: retirement_period ≥ min(DNSKEY_TTL, SigValidity.DNSKEY), per
// spec §4.5.1. DNSKEY_TTL here is the **served** TTL (E13 form,
// min(ttls.dnskey, ttls.max_served)), NOT the operator-configured
// ttls.dnskey alone — validators can only cache DNSKEY for as long
// as the served TTL says. Sizing E5 against the unclamped
// ttls.dnskey would punish operators who use a high configured TTL
// with a clamping-driven low served TTL (the rapid-rollover pattern:
// long RRSIG validity for weekend safety + short served TTL for
// rollover cadence).
//
// retirement_period is implemented as effective_margin =
// max(clamping.margin, max_observed_ttl). The lower bound at
// config-load time is clamping.margin; max_observed_ttl can only
// push it higher. So E5 is satisfied iff clamping.margin ≥
// min(servedDnskeyTTL, sig-validity) when clamping is enabled.
//
// When clamping is disabled, retirement_period defaults to the
// observed TTL alone, which is post-clamp — implicit E5 satisfaction
// when the operator has set non-zero TTLs in policy. Skip the check
// in that case to avoid false positives at startup.
func checkE5(pol *DnssecPolicy) InvariantResult {
	if !pol.Clamping.Enabled || pol.Clamping.Margin <= 0 {
		return InvariantResult{}
	}
	dnskeyTTL := configuredServedDnskeyTTL(pol)
	sigVal := time.Duration(pol.SigValidity.DNSKEY) * time.Second
	if dnskeyTTL == 0 && sigVal == 0 {
		return InvariantResult{}
	}
	floor := dnskeyTTL
	if sigVal > 0 && (floor == 0 || sigVal < floor) {
		floor = sigVal
	}
	if pol.Clamping.Margin >= floor {
		return InvariantResult{}
	}
	return InvariantResult{
		Message: fmt.Sprintf("E5: clamping.margin (%s) < min(served DNSKEY_TTL, sigvalidity.dnskey) (%s); "+
			"retirement period too short to flush DNSKEY/RRSIG caches before next rollover",
			pol.Clamping.Margin, floor),
		Suggestion: fmt.Sprintf("Raise clamping.margin to ≥ %s, OR lower min(ttls.dnskey, ttls.max_served) and/or sigvalidity.dnskey so their min is ≤ %s.",
			floor, pol.Clamping.Margin),
	}
}

// configuredServedDnskeyTTL returns the served DNSKEY TTL derivable
// from policy alone (no runtime keystore observation). Used by E5
// at config-load time. Resolution order matches the wire-shape spec
// in §4.8 / E13:
//
//   - both ttls.dnskey and ttls.max_served set → min of the two
//   - only one set → that one
//   - neither set → 0 (caller treats as "skip")
//
// effectiveServedDnskeyTTL (in ksk_rollover_automated.go) is the
// runtime variant: same resolution + LoadZoneSigningMaxTTL fallback.
// They share intent; we keep two helpers because the runtime caller
// has a kdb and zone, the config-time caller doesn't.
func configuredServedDnskeyTTL(pol *DnssecPolicy) time.Duration {
	dnskey := pol.TTLS.DNSKEY
	maxServed := pol.TTLS.MaxServed
	switch {
	case dnskey > 0 && maxServed > 0:
		if dnskey < maxServed {
			return time.Duration(dnskey) * time.Second
		}
		return time.Duration(maxServed) * time.Second
	case dnskey > 0:
		return time.Duration(dnskey) * time.Second
	case maxServed > 0:
		return time.Duration(maxServed) * time.Second
	}
	return 0
}

// checkE10: (N − 1) × KSK.Lifetime ≥ retirement_period + parent_prop + DS_TTL + standby_time.
//
// retirement_period at config-load is clamping.margin (the operator-
// controllable lower bound; effective_margin only ever grows this).
// parent_prop is approximated by rollover.ds-publish-delay (§4.9), plus
// rollover.parent-cds-poll-estimate when force-notify is the chosen
// scheme — under NOTIFY-only the parent has to fetch CDS before
// updating its DS RRset, which adds latency on top of ds-publish-delay.
// DS_TTL is the resolved value from resolveDSTTL. standby_time is the
// configured pause between published→standby (cache-flush done) and
// standby→active (AtomicRollover); it eats into the same lead-time
// budget, so the cadence has to fit it too.
func checkE10(pol *DnssecPolicy, dsTTL time.Duration) InvariantResult {
	n := pol.Rollover.NumDS
	if n < 2 {
		return InvariantResult{}
	}
	kskLifetime := time.Duration(pol.KSK.Lifetime) * time.Second
	if kskLifetime <= 0 {
		return InvariantResult{}
	}
	retirement := pol.Clamping.Margin
	parentProp := pol.Rollover.DsPublishDelay
	if pol.Rollover.DsyncSchemePreference == DsyncSchemePreferenceForceNotify {
		parentProp += pol.Rollover.ParentCdsPollEstimate
	}
	standbyTime := pol.Rollover.StandbyTime
	required := retirement + parentProp + dsTTL + standbyTime
	available := time.Duration(n-1) * kskLifetime
	if available >= required {
		return InvariantResult{}
	}
	// Cheapest single-knob fix: raise N to make available ≥ required.
	requiredN := int(required/kskLifetime) + 2 // ceil(required/L)+1
	return InvariantResult{
		Message: fmt.Sprintf("E10: (N-1)*KSK.Lifetime (%s = %d * %s) < retirement_period + parent_prop + DS_TTL + standby_time "+
			"(%s = %s + %s + %s + %s); parent DS replacement too late before next rollover",
			available, n-1, kskLifetime,
			required, retirement, parentProp, dsTTL, standbyTime),
		Suggestion: fmt.Sprintf("Raise rollover.num-ds to ≥ %d, OR raise ksk.lifetime, OR lower clamping.margin/rollover.ds-publish-delay/ttls.parent-ds/rollover.standby-time.",
			requiredN),
	}
}

// checkE11: production rule of thumb — N should comfortably exceed
// (retirement_period + parent_prop + DS_TTL) / KSK.Lifetime. Warning
// (not error): "comfortably" is operator judgement.
//
// We flag when the ratio of available to required lead time is below
// 1.25 (i.e., less than 25% headroom). Exact threshold is somewhat
// arbitrary; the spec doesn't pin a number.
func checkE11(pol *DnssecPolicy, dsTTL time.Duration) InvariantResult {
	n := pol.Rollover.NumDS
	if n < 2 {
		return InvariantResult{}
	}
	kskLifetime := time.Duration(pol.KSK.Lifetime) * time.Second
	if kskLifetime <= 0 {
		return InvariantResult{}
	}
	parentProp := pol.Rollover.DsPublishDelay
	if pol.Rollover.DsyncSchemePreference == DsyncSchemePreferenceForceNotify {
		parentProp += pol.Rollover.ParentCdsPollEstimate
	}
	required := pol.Clamping.Margin + parentProp + dsTTL + pol.Rollover.StandbyTime
	if required <= 0 {
		return InvariantResult{}
	}
	available := time.Duration(n-1) * kskLifetime
	if available*4 >= required*5 {
		// At least 25% headroom — comfortable.
		return InvariantResult{}
	}
	return InvariantResult{
		Message: fmt.Sprintf("E11: N=%d gives only %s of lead time vs %s required (less than 25%% headroom); "+
			"consider raising rollover.num-ds or KSK.lifetime",
			n, available, required),
		Suggestion: "Raise rollover.num-ds by 1 or extend ksk.lifetime to gain headroom against transient delays.",
	}
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
// Zero if no DS records found.
//
// Why min and not max: a compliant parent emits one TTL across the
// entire DS RRset (RFC 1035 §3.2.1: all records of an RRset share
// the same TTL), so min == max in the common case. For a
// non-compliant parent emitting mixed TTLs, RFC 2181 §5.2 requires
// resolvers to treat the RRset as a single unit and not break it up;
// the only sane behavior is to evict the whole RRset on the smallest
// TTL (a cache cannot keep individual records past their stated
// expiration). So validator caches in practice flush the entire DS
// RRset at min(TTLs), making min — not max — the actual upper bound
// on cache retention. Using max would over-pessimize E10/E11 lead
// times based on a TTL the cache will never actually honor.
//
// See guide/rollover-timing-equations.md §6 for the same discussion.
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

type sigValidityFloorBand int

const (
	sigValidityFloorOK sigValidityFloorBand = iota
	sigValidityFloorWarning
	sigValidityFloorError
)

func checkSigValidityFloorBand(validity, servedTTL, propagationDelay time.Duration) sigValidityFloorBand {
	if servedTTL == 0 {
		return sigValidityFloorOK
	}
	if validity == 0 {
		return sigValidityFloorError
	}
	h := servedTTL + propagationDelay
	if validity <= 2*h {
		return sigValidityFloorError
	}
	if validity < 4*h {
		return sigValidityFloorWarning
	}
	return sigValidityFloorOK
}

func configuredServedTTLForSigValidity(pol *DnssecPolicy, which string) time.Duration {
	switch which {
	case "dnskey":
		return configuredServedDnskeyTTL(pol)
	case "ds":
		if pol.TTLS.DS == 0 {
			return 0
		}
		return time.Duration(pol.TTLS.DS) * time.Second
	default:
		if pol.TTLS.MaxServed == 0 {
			return 0
		}
		return time.Duration(pol.TTLS.MaxServed) * time.Second
	}
}

// UpdateSigValidityFloor applies config-load or runtime sig-validity floor
// checks and sets/clears DnssecError / DnssecPolicyWarning on zd.
// When runtime is true, maxObservedTTL is the bound for all three values.
func UpdateSigValidityFloor(zd *ZoneData, pol *DnssecPolicy, propagationDelay time.Duration, maxObservedTTL uint32, runtime bool, isLarge func(uint8) bool) {
	if zd == nil || pol == nil {
		return
	}
	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return
	}

	var hardMsgs, warnMsgs []string

	if runtime {
		if maxObservedTTL == 0 {
			zd.ClearError(DnssecPolicyWarning)
			zd.ClearError(DnssecError)
			return
		}
		served := time.Duration(maxObservedTTL) * time.Second
		for _, spec := range []struct {
			label string
			secs  uint32
		}{
			{"sigvalidity.default", pol.SigValidity.Default},
			{"sigvalidity.dnskey", pol.SigValidity.DNSKEY},
			{"sigvalidity.ds", pol.SigValidity.DS},
		} {
			validity := time.Duration(spec.secs) * time.Second
			switch checkSigValidityFloorBand(validity, served, propagationDelay) {
			case sigValidityFloorError:
				hardMsgs = append(hardMsgs, fmt.Sprintf("%s (%s) ≤ 2×(servedTTL+propagationDelay) with servedTTL=%s",
					spec.label, validity, served))
			case sigValidityFloorWarning:
				warnMsgs = append(warnMsgs, fmt.Sprintf("%s (%s) < 4×(servedTTL+propagationDelay) with servedTTL=%s",
					spec.label, validity, served))
			}
		}
	} else {
		for _, spec := range []struct {
			label    string
			secs     uint32
			whichTTL string
		}{
			{"sigvalidity.default", pol.SigValidity.Default, "default"},
			{"sigvalidity.dnskey", pol.SigValidity.DNSKEY, "dnskey"},
			{"sigvalidity.ds", pol.SigValidity.DS, "ds"},
		} {
			served := configuredServedTTLForSigValidity(pol, spec.whichTTL)
			validity := time.Duration(spec.secs) * time.Second
			if served == 0 {
				continue
			}
			switch checkSigValidityFloorBand(validity, served, propagationDelay) {
			case sigValidityFloorError:
				hardMsgs = append(hardMsgs, fmt.Sprintf("%s (%s) ≤ 2×(servedTTL+propagationDelay) with servedTTL=%s",
					spec.label, validity, served))
			case sigValidityFloorWarning:
				warnMsgs = append(warnMsgs, fmt.Sprintf("%s (%s) < 4×(servedTTL+propagationDelay) with servedTTL=%s",
					spec.label, validity, served))
			}
		}
	}

	if len(hardMsgs) == 0 {
		zd.ClearError(DnssecError)
	} else {
		zd.SetError(DnssecError, "sig-validity floor: %s", strings.Join(hardMsgs, "; "))
	}
	warnMsgs = appendDnssecPolicyWarnings(warnMsgs, pol, isLarge)
	if len(warnMsgs) == 0 {
		zd.ClearError(DnssecPolicyWarning)
	} else {
		zd.SetError(DnssecPolicyWarning, "%s", strings.Join(warnMsgs, "; "))
	}
}
