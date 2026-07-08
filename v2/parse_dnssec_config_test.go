package tdns

import (
	"crypto"
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"

	algorithms "github.com/johanix/tdns/v2/algorithms"
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
	if _, ok := conf.Internal.DnssecPolicies["bad-alg"]; ok {
		t.Fatal("removed policy must not survive a re-parse")
	}
}

// kskOnlyStub is a minimal dns.Algorithm used only to give the role
// enforcement test an algorithm that is ForKSK but not ForZSK. It never
// signs or verifies anything; the policy parser only resolves its name
// and consults its capabilities.
type kskOnlyStub struct{}

func (kskOnlyStub) Number() uint8       { return kskOnlyStubNum }
func (kskOnlyStub) Name() string        { return kskOnlyStubName }
func (kskOnlyStub) Hash() crypto.Hash   { return 0 }
func (kskOnlyStub) Generate(int) (crypto.PrivateKey, error) {
	return nil, errors.New("kskOnlyStub: not implemented")
}
func (kskOnlyStub) PublicKeyFromWire([]byte) (crypto.PublicKey, error) {
	return nil, errors.New("kskOnlyStub: not implemented")
}
func (kskOnlyStub) PublicKeyToWire(crypto.PublicKey) ([]byte, error) {
	return nil, errors.New("kskOnlyStub: not implemented")
}
func (kskOnlyStub) ReadPrivateKey(map[string]string) (crypto.PrivateKey, error) {
	return nil, errors.New("kskOnlyStub: not implemented")
}
func (kskOnlyStub) PrivateKeyToString(crypto.PrivateKey) (string, error) {
	return "", errors.New("kskOnlyStub: not implemented")
}
func (kskOnlyStub) Verify(crypto.PublicKey, []byte, []byte) error {
	return errors.New("kskOnlyStub: not implemented")
}
func (kskOnlyStub) SignaturePostProcess(sig []byte) ([]byte, error) { return sig, nil }

const (
	kskOnlyStubNum  uint8 = 245
	kskOnlyStubName       = "KSKONLYSTUB"
)

var kskOnlyStubRegistered bool

func registerKSKOnlyStub(t *testing.T) {
	t.Helper()
	if kskOnlyStubRegistered {
		return
	}
	// Register a real algorithm (so its name resolves via
	// dns.StringToAlgorithm in the policy parser) that is permitted as a
	// KSK but NOT as a ZSK.
	algorithms.Register(kskOnlyStubNum, kskOnlyStub{},
		algorithms.Capabilities{ForSIG0: true, ForDNSSEC: true, ForKSK: true, ForZSK: false},
		algorithms.Facts{})
	kskOnlyStubRegistered = true
}

// TestParseDnssecConfig_RoleEnforcement verifies that a policy assigning
// a KSK-only algorithm to the ZSK role is rejected (Error set, kept but
// unusable), while using it as the KSK is accepted.
func TestParseDnssecConfig_RoleEnforcement(t *testing.T) {
	registerKSKOnlyStub(t)

	conf := &Config{}
	// Permit BOTH mixed pairings via split_algorithms so the split check
	// passes and the role check is the only thing that can reject a
	// policy — otherwise validateSplitAlgorithm (which runs first) would
	// mask the role violation we are trying to test.
	//   zsk-role-bad: KSK=ED25519, ZSK=KSKONLYSTUB → ED25519 allows KSKONLYSTUB
	//   ksk-role-ok:  KSK=KSKONLYSTUB, ZSK=ED25519 → KSKONLYSTUB allows ED25519
	conf.Dnssec.SplitAlgorithms = map[string][]string{
		"ED25519":      {kskOnlyStubName},
		kskOnlyStubName: {"ED25519"},
	}
	conf.Dnssec.Policies = map[string]DnssecPolicyConf{
		// KSK-only alg used as ZSK → must be rejected on role grounds.
		"zsk-role-bad": policyConf("ED25519", "ED25519", kskOnlyStubName),
		// KSK-only alg used as KSK, ED25519 ZSK → healthy.
		"ksk-role-ok": policyConf("ED25519", kskOnlyStubName, "ED25519"),
	}

	if err := conf.parseDnssecConfig(); err != nil {
		t.Fatalf("parseDnssecConfig: %v", err)
	}
	pols := conf.Internal.DnssecPolicies

	bad, ok := pols["zsk-role-bad"]
	if !ok {
		t.Fatal("broken policy zsk-role-bad must still be present (quarantined)")
	}
	if bad.Error == "" {
		t.Fatal("policy zsk-role-bad should carry a role-violation error")
	}
	if !strings.Contains(bad.Error, "ZSK") {
		t.Errorf("zsk-role-bad error should mention the ZSK role, got %q", bad.Error)
	}

	good, ok := pols["ksk-role-ok"]
	if !ok {
		t.Fatal("policy ksk-role-ok missing")
	}
	if good.Error != "" {
		t.Errorf("policy ksk-role-ok should be healthy, got error %q", good.Error)
	}
}
