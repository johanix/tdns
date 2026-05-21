package tdns

import (
	"testing"

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

func TestImrDnskeyQueryForceTCP(t *testing.T) {
	imr := &Imr{largeAlgs: map[uint8]bool{dns.RSASHA512: true}}
	if imr.dnskeyQueryForceTCP("example.com.", dns.TypeA) {
		t.Fatal("non-DNSKEY query must not force TCP")
	}
	if imr.dnskeyQueryForceTCP("example.com.", dns.TypeDNSKEY) {
		t.Fatal("no cached DS must not force TCP")
	}
}
