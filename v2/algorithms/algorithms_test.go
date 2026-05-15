package algorithms

import (
	"testing"

	"github.com/miekg/dns"
)

func TestBuiltinsPreRegistered(t *testing.T) {
	for _, want := range []struct {
		num  uint8
		name string
	}{
		{dns.RSASHA256, "RSASHA256"},
		{dns.RSASHA512, "RSASHA512"},
		{dns.ECDSAP256SHA256, "ECDSAP256SHA256"},
		{dns.ECDSAP384SHA384, "ECDSAP384SHA384"},
		{dns.ED25519, "ED25519"},
	} {
		num, ok := AlgorithmNumber(want.name)
		if !ok {
			t.Errorf("AlgorithmNumber(%q) not registered", want.name)
			continue
		}
		if num != want.num {
			t.Errorf("AlgorithmNumber(%q) = %d, want %d",
				want.name, num, want.num)
		}
		name, ok := AlgorithmName(want.num)
		if !ok {
			t.Errorf("AlgorithmName(%d) not registered", want.num)
			continue
		}
		if name != want.name {
			t.Errorf("AlgorithmName(%d) = %q, want %q",
				want.num, name, want.name)
		}
	}
}

func TestSupportedSIG0_IncludesBuiltins(t *testing.T) {
	got := SupportedSIG0()
	wantContains := []string{"RSASHA256", "RSASHA512", "ECDSAP256SHA256",
		"ECDSAP384SHA384", "ED25519"}
	for _, w := range wantContains {
		if !contains(got, w) {
			t.Errorf("SupportedSIG0() = %v; missing %q", got, w)
		}
	}
}

func TestSupportedDNSSEC_IncludesBuiltins(t *testing.T) {
	got := SupportedDNSSEC()
	wantContains := []string{"RSASHA256", "RSASHA512", "ECDSAP256SHA256",
		"ECDSAP384SHA384", "ED25519"}
	for _, w := range wantContains {
		if !contains(got, w) {
			t.Errorf("SupportedDNSSEC() = %v; missing %q", got, w)
		}
	}
}

func TestRegisterMetadata_NewAlgorithm(t *testing.T) {
	// Use a codepoint that's clearly not in use anywhere (private
	// experimental tail of the unassigned range).
	const testNum uint8 = 249
	const testName = "TESTALG-249"

	RegisterMetadata(testNum, testName, Capabilities{ForSIG0: true})

	if num, ok := AlgorithmNumber(testName); !ok || num != testNum {
		t.Errorf("after RegisterMetadata: AlgorithmNumber(%q) = %d, %v; want %d, true",
			testName, num, ok, testNum)
	}
	caps, ok := Caps(testNum)
	if !ok {
		t.Fatal("after RegisterMetadata: Caps not registered")
	}
	if !caps.ForSIG0 || caps.ForDNSSEC {
		t.Errorf("Caps = %+v; want {ForSIG0:true, ForDNSSEC:false}", caps)
	}
	if !contains(SupportedSIG0(), testName) {
		t.Errorf("SupportedSIG0() should contain %q", testName)
	}
	if contains(SupportedDNSSEC(), testName) {
		t.Errorf("SupportedDNSSEC() should not contain %q", testName)
	}
}

func TestRegisterMetadata_ConflictPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic on duplicate codepoint")
		}
	}()
	// dns.RSASHA256 is already registered by init().
	RegisterMetadata(dns.RSASHA256, "SHOULD-NOT-REGISTER",
		Capabilities{ForSIG0: true})
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
