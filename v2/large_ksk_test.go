package tdns

import (
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func TestResolvePolicyRoleAlgorithms(t *testing.T) {
	dp := DnssecPolicyConf{
		Algorithm: "ECDSAP256SHA256",
	}
	dp.KSK.Algorithm = "RSASHA512"
	dp.ZSK.Lifetime = "30d"
	alg, ksk, zsk, err := resolvePolicyRoleAlgorithms("test", &dp)
	if err != nil {
		t.Fatal(err)
	}
	if alg != dns.ECDSAP256SHA256 {
		t.Fatalf("default alg = %d, want ECDSAP256SHA256", alg)
	}
	if ksk != dns.RSASHA512 {
		t.Fatalf("ksk alg = %d, want RSASHA512", ksk)
	}
	if zsk != dns.ECDSAP256SHA256 {
		t.Fatalf("zsk alg = %d, want inherited ECDSAP256SHA256", zsk)
	}
}

// Uses RSASHA512 as the stand-in for a "large KSK" algorithm: the PQ
// algorithms (FALCON512, MAYO1, …) are registered at runtime by the
// application via algorithms.Register, so they are absent from
// dns.StringToAlgorithm inside the v2 package test binary. The gating
// logic is algorithm-agnostic — any pair of distinct codepoints exercises
// it identically.
func TestValidateSplitAlgorithm(t *testing.T) {
	// Same algorithm always passes, even with no allowlist.
	if err := validateSplitAlgorithm("p", dns.ED25519, dns.ED25519, nil); err != nil {
		t.Fatalf("same-alg pair must pass with nil allowlist: %v", err)
	}
	// Differing pair fails closed when no allowlist is configured.
	if err := validateSplitAlgorithm("p", dns.RSASHA512, dns.ED25519, nil); err == nil {
		t.Fatal("mixed pair must be rejected without an allowlist")
	}
	allowed := buildSplitAlgorithmSet(map[string][]string{
		"RSASHA512": {"ED25519", "ECDSAP256SHA256"},
	})
	// Listed pair passes.
	if err := validateSplitAlgorithm("p", dns.RSASHA512, dns.ED25519, allowed); err != nil {
		t.Fatalf("listed mixed pair must pass: %v", err)
	}
	// Same KSK, ZSK not in its list, fails.
	if err := validateSplitAlgorithm("p", dns.RSASHA512, dns.ECDSAP384SHA384, allowed); err == nil {
		t.Fatal("unlisted ZSK for an allowlisted KSK must be rejected")
	}
	// KSK not in the allowlist at all, fails.
	if err := validateSplitAlgorithm("p", dns.ECDSAP256SHA256, dns.ED25519, allowed); err == nil {
		t.Fatal("KSK absent from allowlist must be rejected")
	}
}

func TestBuildSplitAlgorithmSet(t *testing.T) {
	if buildSplitAlgorithmSet(nil) != nil {
		t.Fatal("nil input must yield nil set")
	}
	// Unknown algorithm names are dropped, not promoted to a permit.
	got := buildSplitAlgorithmSet(map[string][]string{
		"NOSUCHALG": {"ED25519"},
		"RSASHA512": {"ED25519", "BOGUS"},
	})
	if got == nil {
		t.Fatal("valid KSK entry must survive")
	}
	if _, ok := got[dns.ECDSAP256SHA256]; ok {
		t.Fatal("unrelated alg must not be present")
	}
	set := got[dns.RSASHA512]
	if !set[dns.ED25519] {
		t.Fatal("RSASHA512->ED25519 must be permitted")
	}
	if len(set) != 1 {
		t.Fatalf("BOGUS ZSK must be dropped, set = %v", set)
	}
}

func TestParseDnssecPolicyConfSplitGate(t *testing.T) {
	dp := DnssecPolicyConf{Algorithm: "RSASHA512"}
	dp.ZSK.Algorithm = "ED25519"
	dp.KSK.Lifetime = "forever"
	dp.ZSK.Lifetime = "forever"
	// No allowlist -> mixed pair rejected by the split-algorithm gate.
	_, err := parseDnssecPolicyConfImpl("mixed", &dp, true, nil)
	if err == nil || !strings.Contains(err.Error(), "split_algorithms") {
		t.Fatalf("parse must reject mixed pair via the split gate, got %v", err)
	}
	// With the pair allowlisted, the gate passes (any later error is from
	// downstream policy validation, not the split gate).
	allowed := buildSplitAlgorithmSet(map[string][]string{"RSASHA512": {"ED25519"}})
	_, err = parseDnssecPolicyConfImpl("mixed", &dp, true, allowed)
	if err != nil && strings.Contains(err.Error(), "split_algorithms") {
		t.Fatalf("allowlisted pair must pass the split gate, got %v", err)
	}
}

func TestLargeAlgBulkWarning(t *testing.T) {
	isLarge := func(alg uint8) bool { return alg == dns.RSASHA512 }
	pol := &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		Algorithm:    dns.ECDSAP256SHA256,
		KSKAlgorithm: dns.RSASHA512,
		ZSKAlgorithm: dns.ECDSAP256SHA256,
	}
	if msg := largeAlgBulkWarningMsg(pol, isLarge); msg != "" {
		t.Fatalf("large KSK + small ZSK should not warn, got %q", msg)
	}
	pol.ZSKAlgorithm = dns.RSASHA512
	if msg := largeAlgBulkWarningMsg(pol, isLarge); msg == "" {
		t.Fatal("large ZSK should warn")
	}
}

func TestIsLargeAlgorithmConfig(t *testing.T) {
	conf := &Config{}
	conf.Internal.LargeAlgorithms = buildLargeAlgorithmSet([]uint8{dns.RSASHA512})
	if !conf.IsLargeAlgorithm(dns.RSASHA512) {
		t.Fatal("RSASHA512 should be large")
	}
	if conf.IsLargeAlgorithm(dns.ED25519) {
		t.Fatal("ED25519 should not be large")
	}
}

func TestGenKeyLifetimeEmpty(t *testing.T) {
	lt, err := GenKeyLifetime("")
	if err != nil {
		t.Fatal(err)
	}
	if lt.Lifetime != 0 {
		t.Fatalf("empty lifetime = %d, want 0 (unset CSK)", lt.Lifetime)
	}
}

func TestLargeKskImrMetrics(t *testing.T) {
	resetLargeKskImrMetricsForTest()
	t.Cleanup(resetLargeKskImrMetricsForTest)

	imr := &Imr{largeAlgs: map[uint8]bool{dns.RSASHA512: true}}

	smallDS := &dns.DS{
		Hdr:       dns.RR_Header{Name: "small.example.", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		Algorithm: dns.ED25519,
	}
	imr.noteDSEncountered([]dns.RR{smallDS})

	largeDS := &dns.DS{
		Hdr:       dns.RR_Header{Name: "large.example.", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		Algorithm: dns.RSASHA512,
	}
	imr.noteDSEncountered([]dns.RR{largeDS, largeDS})

	imr.noteDNSKEYLookup(false)
	imr.noteDNSKEYLookup(true)

	m := LargeKskImrMetricsSnapshot()
	if m.DSEncounteredTotal != 2 || m.DSEncounteredLarge != 1 {
		t.Fatalf("DS metrics = %+v, want total=2 large RRsets=1", m)
	}
	if len(m.DSDLargeRRByAlgorithm) != 1 || m.DSDLargeRRByAlgorithm[0].Algorithm != dns.RSASHA512 ||
		m.DSDLargeRRByAlgorithm[0].Count != 2 {
		t.Fatalf("per-alg DS RR metrics = %+v, want RSASHA512 x2", m.DSDLargeRRByAlgorithm)
	}
	if LargeAlgDSMetrics() != 2 {
		t.Fatalf("LargeAlgDSMetrics = %d, want 2 large DS RRs", LargeAlgDSMetrics())
	}
	if m.DNSKEYLookupTotal != 2 || m.DNSKEYLookupForcedTCP != 1 {
		t.Fatalf("DNSKEY metrics = %+v, want total=2 forced=1", m)
	}
}

func TestImrDnskeyQueryForceTCP(t *testing.T) {
	imr := &Imr{largeAlgs: map[uint8]bool{dns.RSASHA512: true}}
	if imr.dnskeyQueryForceTCP("example.com.", dns.TypeA) {
		t.Fatal("non-DNSKEY query must not force TCP")
	}
	if imr.dnskeyQueryForceTCP("example.com.", dns.TypeDNSKEY) {
		t.Fatal("no cached DS must not force TCP")
	}

	qname := "example.com."
	logger := log.New(os.Stderr, "", 0)
	rrcache := cache.NewRRsetCache(logger, false, false)
	ds := &dns.DS{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeDS,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Algorithm: dns.RSASHA512,
	}
	rrcache.Set(qname, dns.TypeDS, &cache.CachedRRset{
		Name:       qname,
		RRtype:     dns.TypeDS,
		Expiration: time.Now().Add(time.Hour),
		RRset: &core.RRset{
			Name:   qname,
			RRtype: dns.TypeDS,
			Class:  dns.ClassINET,
			RRs:    []dns.RR{ds},
		},
	})
	imr.Cache = rrcache
	if !imr.dnskeyQueryForceTCP(qname, dns.TypeDNSKEY) {
		t.Fatal("cached large-alg parent DS must force TCP for child DNSKEY")
	}
}
