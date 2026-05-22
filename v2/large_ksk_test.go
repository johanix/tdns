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
	imr.noteDSEncountered([]dns.RR{largeDS})

	imr.noteDNSKEYLookup(false)
	imr.noteDNSKEYLookup(true)

	m := LargeKskImrMetricsSnapshot()
	if m.DSEncounteredTotal != 2 || m.DSEncounteredLarge != 1 {
		t.Fatalf("DS metrics = %+v, want total=2 large=1", m)
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
