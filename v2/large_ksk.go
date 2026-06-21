/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Large KSK support: per-role policy algorithms and bulk-signing warnings.
 */

package tdns

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// LargeAlgDSMetrics returns the total number of individual large-alg DS RRs
// encountered in referrals. Prefer LargeKskImrMetricsSnapshot.
func LargeAlgDSMetrics() uint64 {
	var n uint64
	for i := range imrDSDLargeRRByAlg {
		n += imrDSDLargeRRByAlg[i].Load()
	}
	return n
}

// buildLargeAlgorithmSet resolves the dnssec.large_algorithms names into the
// derived codepoint lookup. Unlike split_algorithms (pure allowlist data, where
// an unregistered name can never be requested), this list actively drives the
// IMR's transport decision, so an unknown name is a hard config error rather
// than a silent skip.
func buildLargeAlgorithmSet(names []string) (map[uint8]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	m := make(map[uint8]bool, len(names))
	for _, name := range names {
		alg := dns.StringToAlgorithm[strings.ToUpper(strings.TrimSpace(name))]
		if alg == 0 {
			return nil, fmt.Errorf("dnssec.large_algorithms: unknown algorithm %q (not registered in this binary)", name)
		}
		m[alg] = true
	}
	return m, nil
}

// IsLargeAlgorithm reports whether alg is listed in dnssec.large_algorithms.
func (conf *Config) IsLargeAlgorithm(alg uint8) bool {
	if conf == nil || conf.Internal.LargeAlgorithms == nil {
		return false
	}
	return conf.Internal.LargeAlgorithms[alg]
}

// buildSplitAlgorithmSet converts the dnssec.split_algorithms config
// (kskAlgName -> []zskAlgName) into the derived lookup kskAlg -> set of
// permitted zskAlgs. Unknown algorithm names are skipped with a warning so
// a typo gates rather than silently permits. Returns nil if no pairs are
// configured (the fail-closed default: only same-algorithm policies pass).
func buildSplitAlgorithmSet(in map[string][]string) map[uint8]map[uint8]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[uint8]map[uint8]bool, len(in))
	for kskName, zskNames := range in {
		kskAlg := dns.StringToAlgorithm[strings.ToUpper(strings.TrimSpace(kskName))]
		if kskAlg == 0 {
			lgConfig.Warn("dnssec.split_algorithms: unknown KSK algorithm, ignored", "algorithm", kskName)
			continue
		}
		set := out[kskAlg]
		if set == nil {
			set = make(map[uint8]bool, len(zskNames))
			out[kskAlg] = set
		}
		for _, zskName := range zskNames {
			zskAlg := dns.StringToAlgorithm[strings.ToUpper(strings.TrimSpace(zskName))]
			if zskAlg == 0 {
				lgConfig.Warn("dnssec.split_algorithms: unknown ZSK algorithm, ignored", "ksk", kskName, "zsk", zskName)
				continue
			}
			set[zskAlg] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// resolveCompletenessMode validates dnssec.completeness and returns the
// canonical mode. Empty defaults to "strict" (the conservative,
// §4035-conformant choice). An unrecognized value is a hard config error —
// a typo here silently changing signing semantics would be dangerous.
func resolveCompletenessMode(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", CompletenessStrict:
		return CompletenessStrict, nil
	case CompletenessRelaxed:
		return CompletenessRelaxed, nil
	default:
		return "", fmt.Errorf("invalid dnssec.completeness %q (want %q or %q)", s, CompletenessStrict, CompletenessRelaxed)
	}
}

// validateSplitAlgorithm enforces the KSK/ZSK split-algorithm gate. Same
// algorithm always passes. A differing pair must be listed in the allowlist
// (kskAlg -> permitted zskAlgs); otherwise it is rejected (fail closed).
func validateSplitAlgorithm(policyName string, kskAlg, zskAlg uint8, allowed map[uint8]map[uint8]bool) error {
	if kskAlg == zskAlg {
		return nil
	}
	kskName := dns.AlgorithmToString[kskAlg]
	zskName := dns.AlgorithmToString[zskAlg]
	if allowed[kskAlg][zskAlg] {
		return nil
	}
	return fmt.Errorf("policy %q: KSK algorithm %s may not pair with ZSK algorithm %s; not listed in dnssec.split_algorithms", policyName, kskName, zskName)
}

// resolvePolicyRoleAlgorithms parses the top-level and per-role algorithm fields.
func resolvePolicyRoleAlgorithms(policyName string, dp *DnssecPolicyConf) (defaultAlg, kskAlg, zskAlg uint8, err error) {
	defaultAlg = dns.StringToAlgorithm[strings.TrimSpace(strings.ToUpper(dp.Algorithm))]
	if defaultAlg == 0 {
		return 0, 0, 0, fmt.Errorf("policy %q: unknown algorithm %q", policyName, dp.Algorithm)
	}
	kskAlg = defaultAlg
	if s := strings.TrimSpace(dp.KSK.Algorithm); s != "" {
		kskAlg = dns.StringToAlgorithm[strings.ToUpper(s)]
		if kskAlg == 0 {
			return 0, 0, 0, fmt.Errorf("policy %q: unknown KSK algorithm %q", policyName, s)
		}
	}
	zskAlg = defaultAlg
	if s := strings.TrimSpace(dp.ZSK.Algorithm); s != "" {
		zskAlg = dns.StringToAlgorithm[strings.ToUpper(s)]
		if zskAlg == 0 {
			return 0, 0, 0, fmt.Errorf("policy %q: unknown ZSK algorithm %q", policyName, s)
		}
	}
	return defaultAlg, kskAlg, zskAlg, nil
}

// bulkSigningAlgorithmAndRole returns the algorithm that signs non-DNSKEY RRsets
// and a short role label for operator messages.
func bulkSigningAlgorithmAndRole(pol *DnssecPolicy) (alg uint8, role string) {
	if pol == nil {
		return 0, ""
	}
	if pol.Mode == DnssecPolicyModeCSK {
		return pol.Algorithm, "CSK"
	}
	return pol.ZSKAlgorithm, "ZSK"
}

func largeAlgBulkWarningMsg(pol *DnssecPolicy, isLarge func(uint8) bool) string {
	if pol == nil || isLarge == nil {
		return ""
	}
	alg, role := bulkSigningAlgorithmAndRole(pol)
	if alg == 0 || !isLarge(alg) {
		return ""
	}
	name := dns.AlgorithmToString[alg]
	if name == "" {
		name = "unknown"
	}
	return "large algorithm " + name + " signs the bulk of the zone (" + role + " role); whole-zone signatures inflated"
}

// appendDnssecPolicyWarnings merges sig-validity headroom warnings with the
// large-algorithm bulk-signing warning into one DnssecPolicyWarning message.
func appendDnssecPolicyWarnings(warnMsgs []string, pol *DnssecPolicy, isLarge func(uint8) bool) []string {
	if msg := largeAlgBulkWarningMsg(pol, isLarge); msg != "" {
		warnMsgs = append(warnMsgs, msg)
	}
	return warnMsgs
}

// WarnLargeAlgZoneSigningRole sets DnssecPolicyWarning when a newly generated
// ZSK or CSK uses a large algorithm. KSK generation is the supported pattern.
func WarnLargeAlgZoneSigningRole(zd *ZoneData, keytype string, alg uint8, isLarge func(uint8) bool) {
	if zd == nil || isLarge == nil || !isLarge(alg) {
		return
	}
	if keytype != "ZSK" && keytype != "CSK" {
		return
	}
	msg := largeAlgBulkWarningMsg(zd.DnssecPolicy, isLarge)
	if msg == "" {
		return
	}
	var parts []string
	for _, e := range zd.ErrorList() {
		if e.Type == DnssecPolicyWarning && e.Msg != "" && e.Msg != msg {
			parts = append(parts, e.Msg)
		}
	}
	parts = append(parts, msg)
	zd.SetError(DnssecPolicyWarning, "%s", strings.Join(parts, "; "))
}

// WarnLargeAlgKskReusedAsZsk covers the runtime case where no real ZSK exists.
func WarnLargeAlgKskReusedAsZsk(zd *ZoneData, alg uint8, isLarge func(uint8) bool) {
	if zd == nil || isLarge == nil || !isLarge(alg) {
		return
	}
	name := dns.AlgorithmToString[alg]
	if name == "" {
		name = "unknown"
	}
	msg := "large algorithm " + name + " signs the bulk of the zone (KSK reused as ZSK); whole-zone signatures inflated"
	var parts []string
	for _, e := range zd.ErrorList() {
		if e.Type == DnssecPolicyWarning && e.Msg != "" && e.Msg != msg {
			parts = append(parts, e.Msg)
		}
	}
	parts = append(parts, msg)
	zd.SetError(DnssecPolicyWarning, "%s", strings.Join(parts, "; "))
}
