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

func TestDnssecPolicyToInfo(t *testing.T) {
	// Healthy policy: names resolved, lifetimes rendered, no error.
	healthy := DnssecPolicy{
		Name:         "good",
		Algorithm:    dns.ED25519,
		KSKAlgorithm: dns.RSASHA512,
		ZSKAlgorithm: dns.ED25519,
		Mode:         DnssecPolicyModeKSKZSK,
		KSK:          KeyLifetime{Lifetime: foreverLifetimeSecs},
		CSK:          KeyLifetime{Lifetime: 0},
		ZSK:          KeyLifetime{Lifetime: 3600},
		Rollover:     RolloverPolicy{Method: RolloverMethodMultiDS},
	}
	info := DnssecPolicyToInfo(healthy)
	if info.PolicyError != "" {
		t.Fatalf("healthy policy must have empty PolicyError, got %q", info.PolicyError)
	}
	if info.KSKAlgorithm != "RSASHA512" || info.ZSKAlgorithm != "ED25519" {
		t.Fatalf("alg names = ksk %q zsk %q", info.KSKAlgorithm, info.ZSKAlgorithm)
	}
	if info.KSKLifetime != "forever" {
		t.Fatalf("KSK forever sentinel = %q, want \"forever\"", info.KSKLifetime)
	}
	if info.ZSKLifetime != "1h0m0s" {
		t.Fatalf("ZSK lifetime = %q, want 1h0m0s", info.ZSKLifetime)
	}
	if info.RolloverMethod != "multi-ds" {
		t.Fatalf("rollover = %q, want multi-ds", info.RolloverMethod)
	}

	// Broken policy: error carried; unset algorithm renders as "-".
	broken := DnssecPolicy{Name: "bad", Error: "unknown algorithm \"FOOBAR\""}
	bi := DnssecPolicyToInfo(broken)
	if bi.PolicyError == "" {
		t.Fatal("broken policy must carry PolicyError")
	}
	if bi.Algorithm != "-" || bi.KSKAlgorithm != "-" {
		t.Fatalf("unset algs should render as \"-\", got %q / %q", bi.Algorithm, bi.KSKAlgorithm)
	}
	if bi.KSKLifetime != "none" {
		t.Fatalf("zero lifetime = %q, want none", bi.KSKLifetime)
	}
}

func TestExpandTemplateDnssecPolicyPrecedence(t *testing.T) {
	tmpl := &ZoneConf{DnssecPolicy: "default"}

	// Zone with its own policy: keeps it (template does not clobber).
	z, err := ExpandTemplate(ZoneConf{Name: "z1.", DnssecPolicy: "pq-mayo"}, tmpl, AppTypeAuth)
	if err != nil {
		t.Fatal(err)
	}
	if z.DnssecPolicy != "pq-mayo" {
		t.Fatalf("zone policy = %q, want pq-mayo (zone must win over template)", z.DnssecPolicy)
	}

	// Zone without a policy: inherits the template's.
	z, err = ExpandTemplate(ZoneConf{Name: "z2."}, tmpl, AppTypeAuth)
	if err != nil {
		t.Fatal(err)
	}
	if z.DnssecPolicy != "default" {
		t.Fatalf("zone policy = %q, want inherited default", z.DnssecPolicy)
	}
}

func TestParseExtendedDuration(t *testing.T) {
	ok := map[string]time.Duration{
		"14d":   14 * 24 * time.Hour,
		"90d":   90 * 24 * time.Hour,
		"2w":    2 * 7 * 24 * time.Hour,
		"1w":    7 * 24 * time.Hour,
		"168h":  168 * time.Hour, // stdlib unit still works
		"30m":   30 * time.Minute,
		"1h30m": 90 * time.Minute,
		" 7d ":  7 * 24 * time.Hour, // trimmed
	}
	for in, want := range ok {
		got, err := parseExtendedDuration(in)
		if err != nil {
			t.Fatalf("parseExtendedDuration(%q) err = %v", in, err)
		}
		if got != want {
			t.Fatalf("parseExtendedDuration(%q) = %v, want %v", in, got, want)
		}
	}
	for _, bad := range []string{"1.5d", "xd", "d", "", "1y", "-7d", "-2w"} {
		if _, err := parseExtendedDuration(bad); err == nil {
			t.Fatalf("parseExtendedDuration(%q) should have errored", bad)
		}
	}
}

func TestResolveZonePolicyRef(t *testing.T) {
	policies := map[string]DnssecPolicy{
		"good":   {Name: "good"},
		"broken": {Name: "broken", Error: "unknown algorithm \"FOOBAR\""},
	}
	// Healthy policy is usable, no error.
	if usable, msg := resolveZonePolicyRef("good", policies); !usable || msg != "" {
		t.Fatalf("good: usable=%v msg=%q, want true,\"\"", usable, msg)
	}
	// Broken policy: not usable, message names it broken with the reason.
	usable, msg := resolveZonePolicyRef("broken", policies)
	if usable {
		t.Fatal("broken policy must not be usable")
	}
	if !strings.Contains(msg, "is broken") || !strings.Contains(msg, "FOOBAR") {
		t.Fatalf("broken msg = %q, want it to mention broken + the reason", msg)
	}
	// Missing policy: not usable, distinct "does not exist" message.
	usable, msg = resolveZonePolicyRef("nope", policies)
	if usable {
		t.Fatal("missing policy must not be usable")
	}
	if !strings.Contains(msg, "does not exist") {
		t.Fatalf("missing msg = %q, want \"does not exist\"", msg)
	}
}

func TestIsLargeAlgorithmConfig(t *testing.T) {
	conf := &Config{}
	set, err := buildLargeAlgorithmSet([]string{"RSASHA512"})
	if err != nil {
		t.Fatalf("buildLargeAlgorithmSet: %v", err)
	}
	conf.Internal.LargeAlgorithms = set
	if !conf.IsLargeAlgorithm(dns.RSASHA512) {
		t.Fatal("RSASHA512 should be large")
	}
	if conf.IsLargeAlgorithm(dns.ED25519) {
		t.Fatal("ED25519 should not be large")
	}
}

func TestBuildLargeAlgorithmSetUnknown(t *testing.T) {
	// Unknown name is a hard error (unlike split_algorithms, which skips).
	if _, err := buildLargeAlgorithmSet([]string{"NOSUCHALG"}); err == nil {
		t.Fatal("unknown algorithm name must be a hard error")
	}
	// Empty list is fine (no large algorithms configured).
	set, err := buildLargeAlgorithmSet(nil)
	if err != nil || set != nil {
		t.Fatalf("empty list: set=%v err=%v, want nil,nil", set, err)
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
	if m.DNSKEYLookupTotal != 2 || m.DNSKEYLookupBypassed != 1 {
		t.Fatalf("DNSKEY metrics = %+v, want total=2 bypassed=1", m)
	}
}

// cacheWithLargeDS returns an RRset cache seeded with a large-algorithm parent
// DS for qname.
func cacheWithLargeDS(t *testing.T, qname string) *cache.RRsetCacheT {
	t.Helper()
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
	return rrcache
}

func TestParseDNSKEYTransportPolicy(t *testing.T) {
	cases := map[string]DNSKEYTransportPolicy{
		"":                DNSKEYTransportUseDSSignal, // empty -> default
		"use_ds_signal":   DNSKEYTransportUseDSSignal,
		"FORCE_UDP":       DNSKEYTransportForceUDP, // case-insensitive
		"try_encrypted":   DNSKEYTransportTryEncrypted,
		"force_encrypted": DNSKEYTransportForceEncrypted,
	}
	for in, want := range cases {
		got, err := parseDNSKEYTransportPolicy(in)
		if err != nil {
			t.Fatalf("parse(%q) err = %v", in, err)
		}
		if got != want {
			t.Fatalf("parse(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := parseDNSKEYTransportPolicy("bogus"); err == nil {
		t.Fatal("parse(bogus) should error")
	}
}

func TestDnskeyTransportBypass(t *testing.T) {
	qname := "example.com."

	// use_ds_signal: bypass only when cached DS is large.
	imr := &Imr{largeAlgs: map[uint8]bool{dns.RSASHA512: true}}
	if imr.dnskeyTransportBypass(qname, dns.TypeA) {
		t.Fatal("non-DNSKEY query must never bypass")
	}
	if imr.dnskeyTransportBypass(qname, dns.TypeDNSKEY) {
		t.Fatal("use_ds_signal with no cached DS must not bypass")
	}
	imr.Cache = cacheWithLargeDS(t, qname)
	if !imr.dnskeyTransportBypass(qname, dns.TypeDNSKEY) {
		t.Fatal("use_ds_signal with large cached DS must bypass")
	}

	// force_udp: never bypass, even with a large DS.
	imrUDP := &Imr{
		largeAlgs:       map[uint8]bool{dns.RSASHA512: true},
		dnskeyTransport: DNSKEYTransportForceUDP,
		Cache:           cacheWithLargeDS(t, qname),
	}
	if imrUDP.dnskeyTransportBypass(qname, dns.TypeDNSKEY) {
		t.Fatal("force_udp must never bypass")
	}

	// try_encrypted / force_encrypted: always bypass DNSKEY, DS irrelevant.
	for _, pol := range []DNSKEYTransportPolicy{DNSKEYTransportTryEncrypted, DNSKEYTransportForceEncrypted} {
		i := &Imr{dnskeyTransport: pol} // no cache, no large algs
		if !i.dnskeyTransportBypass(qname, dns.TypeDNSKEY) {
			t.Fatalf("%s must bypass for DNSKEY regardless of DS", pol)
		}
		if i.dnskeyTransportBypass(qname, dns.TypeA) {
			t.Fatalf("%s must not bypass non-DNSKEY", pol)
		}
	}
}

func TestPreferredDNSKEYTransport(t *testing.T) {
	mkServer := func(ts ...core.Transport) *cache.AuthServer {
		s := cache.NewAuthServer("ns.example.")
		s.Transports = ts
		return s
	}

	// Prefers DoQ over DoT over DoH.
	imr := &Imr{dnskeyTransport: DNSKEYTransportTryEncrypted}
	if got := imr.preferredDNSKEYTransport(mkServer(core.TransportDo53, core.TransportDoT, core.TransportDoQ)); got != core.TransportDoQ {
		t.Fatalf("want DoQ, got %v", got)
	}
	if got := imr.preferredDNSKEYTransport(mkServer(core.TransportDo53, core.TransportDoT)); got != core.TransportDoT {
		t.Fatalf("want DoT, got %v", got)
	}

	// try_encrypted with no encrypted transport falls back to TCP.
	if got := imr.preferredDNSKEYTransport(mkServer(core.TransportDo53)); got != core.TransportDo53TCP {
		t.Fatalf("try_encrypted no-encrypted want TCP, got %v", got)
	}

	// force_encrypted with no encrypted transport returns 0 (fail).
	imrForce := &Imr{dnskeyTransport: DNSKEYTransportForceEncrypted}
	if got := imrForce.preferredDNSKEYTransport(mkServer(core.TransportDo53)); got != 0 {
		t.Fatalf("force_encrypted no-encrypted want 0, got %v", got)
	}
	if got := imrForce.preferredDNSKEYTransport(mkServer(core.TransportDo53, core.TransportDoT)); got != core.TransportDoT {
		t.Fatalf("force_encrypted with DoT want DoT, got %v", got)
	}
}
