/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Large KSK support: per-role policy algorithms and bulk-signing warnings.
 */

package tdns

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

var largeAlgDSObserved atomic.Uint64

// LargeAlgDSMetrics returns how often the IMR saw a cached parent DS with a
// large algorithm number before querying the child DNSKEY (Part B).
func LargeAlgDSMetrics() uint64 {
	return largeAlgDSObserved.Load()
}

func noteLargeAlgDSObserved() {
	largeAlgDSObserved.Add(1)
}

// dnskeyQueryForceTCP returns true when a cached parent DS RRset signals a large
// child KSK algorithm and the IMR should fetch the child DNSKEY over TCP.
func (imr *Imr) dnskeyQueryForceTCP(qname string, qtype uint16) bool {
	if imr == nil || imr.Cache == nil || qtype != dns.TypeDNSKEY {
		return false
	}
	ds := imr.Cache.Get(qname, dns.TypeDS)
	if ds == nil || ds.RRset == nil {
		return false
	}
	for _, rr := range ds.RRset.RRs {
		d, ok := rr.(*dns.DS)
		if !ok || !imr.isLargeAlgorithm(d.Algorithm) {
			continue
		}
		noteLargeAlgDSObserved()
		lgDns.Info("large-alg DS observed; will query child DNSKEY over TCP",
			"zone", qname, "alg", d.Algorithm)
		return true
	}
	return false
}

func buildLargeAlgorithmSet(algs []uint8) map[uint8]bool {
	if len(algs) == 0 {
		return nil
	}
	m := make(map[uint8]bool, len(algs))
	for _, a := range algs {
		m[a] = true
	}
	return m
}

// IsLargeAlgorithm reports whether alg is listed in dnssec.large_algorithms.
func (conf *Config) IsLargeAlgorithm(alg uint8) bool {
	if conf == nil || conf.Internal.LargeAlgorithms == nil {
		return false
	}
	return conf.Internal.LargeAlgorithms[alg]
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
