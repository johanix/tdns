package tdns

import (
	"log"
	"os"
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
