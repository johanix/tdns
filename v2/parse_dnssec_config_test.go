package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// dnssecConfWith builds a minimal DnssecConf for parseDnssecConfig tests.
func policyConf(alg, kskAlg, zskAlg string) DnssecPolicyConf {
	dp := DnssecPolicyConf{Algorithm: alg}
	dp.KSK.Algorithm = kskAlg
	dp.KSK.Lifetime = "forever"
	dp.ZSK.Algorithm = zskAlg
	dp.ZSK.Lifetime = "forever"
	dp.SigValidity.Default = "2w"
	return dp
}

func TestParseDnssecConfig(t *testing.T) {
	conf := &Config{}
	conf.Dnssec.LargeAlgorithms = []string{"RSASHA512"}
	conf.Dnssec.SplitAlgorithms = map[string][]string{"RSASHA512": {"ED25519"}}
	conf.Dnssec.Policies = map[string]DnssecPolicyConf{
		// Healthy same-algorithm policy.
		"plain": policyConf("ED25519", "", ""),
		// Healthy mixed pair, permitted by split_algorithms.
		"split-ok": policyConf("ED25519", "RSASHA512", "ED25519"),
		// Mixed pair NOT in split_algorithms → broken (Error set).
		"split-bad": policyConf("ED25519", "ECDSAP256SHA256", "ED25519"),
		// Unknown algorithm → broken.
		"bad-alg": policyConf("FOOBAR", "", ""),
	}

	if err := conf.parseDnssecConfig(); err != nil {
		t.Fatalf("parseDnssecConfig: %v", err)
	}

	// large_algorithms resolved.
	if !conf.IsLargeAlgorithm(dns.RSASHA512) {
		t.Fatal("RSASHA512 should be a large algorithm")
	}

	pols := conf.Internal.DnssecPolicies

	// Healthy policies present, no error.
	for _, name := range []string{"plain", "split-ok"} {
		p, ok := pols[name]
		if !ok {
			t.Fatalf("policy %q missing", name)
		}
		if p.Error != "" {
			t.Fatalf("policy %q should be healthy, got error %q", name, p.Error)
		}
	}

	// Broken policies present WITH an error (quarantined, not dropped).
	for _, name := range []string{"split-bad", "bad-alg"} {
		p, ok := pols[name]
		if !ok {
			t.Fatalf("broken policy %q must still be present", name)
		}
		if p.Error == "" {
			t.Fatalf("policy %q should carry an error", name)
		}
	}

	// Builtin default injected when not configured.
	if _, ok := pols["default"]; !ok {
		t.Fatal("builtin default policy should be injected")
	}

	// Idempotent rebuild: a second call with the bad policies removed drops
	// them from the map (no stale survivors from the prior parse).
	delete(conf.Dnssec.Policies, "split-bad")
	delete(conf.Dnssec.Policies, "bad-alg")
	if err := conf.parseDnssecConfig(); err != nil {
		t.Fatalf("parseDnssecConfig (2nd): %v", err)
	}
	if _, ok := conf.Internal.DnssecPolicies["split-bad"]; ok {
		t.Fatal("removed policy must not survive a re-parse")
	}
}
