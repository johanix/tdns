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

	algorithms "github.com/johanix/tdns/v2/algorithms"
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

// buildLargeAlgorithmSet resolves the dnssec.large_algorithms entries into the
// derived codepoint lookup. Each entry is either an exact algorithm name
// (e.g. "MLDSA44") or a name prefix with a trailing "*" (e.g. "MLDSA*") that
// matches every known algorithm sharing that prefix — convenient for whole
// families (MLDSA44/65/87, the MAYO/SNOVA variants, ...) without spelling out
// each member. Matching is case-insensitive and resolves against the algorithm
// metadata registry (see resolveLargeAlgorithms), so a name the IMR recognizes
// but cannot itself sign with still counts — an IMR must recognize large
// algorithms in the DS records of zones it does not host. Unlike
// split_algorithms (pure allowlist data), this list actively drives the IMR's
// transport decision, so an entry that matches nothing is a hard config error,
// not a silent skip.
func buildLargeAlgorithmSet(names []string) (map[uint8]bool, error) {
	return resolveLargeAlgorithms(names, largeAlgorithmCatalog())
}

// largeAlgorithmCatalog is the name->codepoint universe that
// dnssec.large_algorithms resolves against: every DNSSEC-capable algorithm the
// binary knows of, whether it carries a real implementation or only metadata.
// Metadata-only entries are intentionally included so a config naming an
// algorithm (or family) this binary cannot itself sign with is still honored
// for the IMR's DS-driven transport choice. Names are the registry's canonical
// uppercase form.
func largeAlgorithmCatalog() map[string]uint8 {
	names := algorithms.SupportedDNSSEC()
	cat := make(map[string]uint8, len(names))
	for _, n := range names {
		if num, ok := algorithms.AlgorithmNumber(n); ok {
			cat[n] = num
		}
	}
	return cat
}

// resolveLargeAlgorithms resolves dnssec.large_algorithms entries against the
// given name->codepoint catalog. An entry ending in "*" is a name prefix
// (matching every catalog name that starts with the text before the "*"); any
// other entry is an exact name. Matching is case-insensitive. Every entry must
// resolve to at least one codepoint: an unknown exact name, or a prefix that
// matches nothing in the catalog, is a hard config error (almost always a
// misspelling). Returns (nil, nil) for an empty list.
func resolveLargeAlgorithms(names []string, catalog map[string]uint8) (map[uint8]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	m := make(map[uint8]bool, len(names))
	for _, raw := range names {
		entry := strings.ToUpper(strings.TrimSpace(raw))
		if entry == "" {
			continue
		}
		if strings.HasSuffix(entry, "*") {
			prefix := strings.TrimSuffix(entry, "*")
			matched := 0
			for name, num := range catalog {
				if strings.HasPrefix(name, prefix) {
					m[num] = true
					matched++
				}
			}
			if matched == 0 {
				return nil, fmt.Errorf("dnssec.large_algorithms: prefix %q matches no known DNSSEC algorithm (check spelling)", raw)
			}
			continue
		}
		num, ok := catalog[entry]
		if !ok {
			return nil, fmt.Errorf("dnssec.large_algorithms: unknown algorithm %q (not in the algorithm metadata registry)", raw)
		}
		m[num] = true
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

// validateRoleCapabilities rejects a policy that assigns an algorithm to
// a DNSSEC role it is not permitted to fill: the KSK algorithm must have
// ForKSK, the ZSK algorithm must have ForZSK. This blocks, for example, a
// large-signature code-based algorithm (ForKSK, not ForZSK) from being
// used as a zone-signing key, where its signature would bloat every RRSIG.
// A rejected policy is kept but marked unusable via DnssecPolicy.Error,
// like the other parse-time policy validations.
func validateRoleCapabilities(policyName string, kskAlg, zskAlg uint8) error {
	// CapsReal (not Caps): a policy that signs must name algorithms this
	// binary can actually generate and sign with, not ones it merely holds
	// metadata for. A server registers metadata for every algorithm but
	// links an implementation only for those in its algs.list.
	kskCaps, ok := algorithms.CapsReal(kskAlg)
	if !ok {
		return fmt.Errorf("policy %q: KSK algorithm %s (%d) is not a usable (implemented) algorithm in this binary",
			policyName, dns.AlgorithmToString[kskAlg], kskAlg)
	}
	if !kskCaps.ForKSK {
		return fmt.Errorf("policy %q: algorithm %s (%d) is not permitted as a KSK",
			policyName, dns.AlgorithmToString[kskAlg], kskAlg)
	}
	zskCaps, ok := algorithms.CapsReal(zskAlg)
	if !ok {
		return fmt.Errorf("policy %q: ZSK algorithm %s (%d) is not a usable (implemented) algorithm in this binary",
			policyName, dns.AlgorithmToString[zskAlg], zskAlg)
	}
	if !zskCaps.ForZSK {
		return fmt.Errorf("policy %q: algorithm %s (%d) is not permitted as a ZSK",
			policyName, dns.AlgorithmToString[zskAlg], zskAlg)
	}
	return nil
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

// resolvePolicyRoleAlgorithmNames returns a policy's effective role algorithm
// NAMES (upper-cased), applying the same default→KSK/ZSK fallback as
// resolvePolicyRoleAlgorithms but WITHOUT resolving names to codepoints. A pure
// client (tdns-cli config check) cannot resolve this deployment's
// runtime-assigned PQ codepoints, so it compares these names against the running
// server's registered algorithms instead of a local table. Empty → "".
func resolvePolicyRoleAlgorithmNames(dp *DnssecPolicyConf) (defaultAlg, kskAlg, zskAlg string) {
	norm := func(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }
	defaultAlg = norm(dp.Algorithm)
	kskAlg = defaultAlg
	if s := norm(dp.KSK.Algorithm); s != "" {
		kskAlg = s
	}
	zskAlg = defaultAlg
	if s := norm(dp.ZSK.Algorithm); s != "" {
		zskAlg = s
	}
	return defaultAlg, kskAlg, zskAlg
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
//
// zdLocked signals that the caller already holds zd.mu (the publish-path SOA
// re-sign reaches this via EnsureActiveDnssecKeys(zdLocked=true)). When true the
// error read/write is routed through the *Locked variants so this does NOT
// re-acquire zd.mu and self-deadlock — Go mutexes are not reentrant.
func WarnLargeAlgZoneSigningRole(zd *ZoneData, keytype string, alg uint8, isLarge func(uint8) bool, zdLocked bool) {
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
	errList := zd.ErrorList
	setErr := zd.SetError
	if zdLocked {
		errList = zd.errorListLocked
		setErr = zd.setErrorLocked
	}
	var parts []string
	for _, e := range errList() {
		if e.Type == DnssecPolicyWarning && e.Msg != "" && e.Msg != msg {
			parts = append(parts, e.Msg)
		}
	}
	parts = append(parts, msg)
	setErr(DnssecPolicyWarning, "%s", strings.Join(parts, "; "))
}

// WarnLargeAlgKskReusedAsZsk covers the runtime case where no real ZSK exists.
// See WarnLargeAlgZoneSigningRole for the zdLocked contract.
func WarnLargeAlgKskReusedAsZsk(zd *ZoneData, alg uint8, isLarge func(uint8) bool, zdLocked bool) {
	if zd == nil || isLarge == nil || !isLarge(alg) {
		return
	}
	name := dns.AlgorithmToString[alg]
	if name == "" {
		name = "unknown"
	}
	msg := "large algorithm " + name + " signs the bulk of the zone (KSK reused as ZSK); whole-zone signatures inflated"
	errList := zd.ErrorList
	setErr := zd.SetError
	if zdLocked {
		errList = zd.errorListLocked
		setErr = zd.setErrorLocked
	}
	var parts []string
	for _, e := range errList() {
		if e.Type == DnssecPolicyWarning && e.Msg != "" && e.Msg != msg {
			parts = append(parts, e.Msg)
		}
	}
	parts = append(parts, msg)
	setErr(DnssecPolicyWarning, "%s", strings.Join(parts, "; "))
}
