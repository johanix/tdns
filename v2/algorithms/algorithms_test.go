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

// record() promotion semantics. These exercise the shared internal
// recorder directly (avoiding a full dns.Algorithm stub); Register and
// RegisterMetadata both funnel through it, and the metadata→real
// promotion is the behavior the generator design depends on.

func TestRecord_MetadataThenRealPromotes(t *testing.T) {
	const num = 240
	const name = "PROMOTE-TEST"
	caps := Capabilities{ForSIG0: true, ForDNSSEC: true, ForZSK: true}

	// First: metadata-only.
	record(num, name, caps, false)
	if e, ok := byNumber[num]; !ok || e.real {
		t.Fatalf("after metadata record: entry real=%v ok=%v; want real=false", e.real, ok)
	}
	// Then: a real registration of the same codepoint/name/caps promotes.
	record(num, name, caps, true)
	e, ok := byNumber[num]
	if !ok || !e.real {
		t.Fatalf("after real record: entry real=%v ok=%v; want real=true", e.real, ok)
	}
	if got, _ := AlgorithmNumber(name); got != num {
		t.Errorf("byName mapping wrong after promotion: %d, want %d", got, num)
	}
}

func TestRecord_RepeatedMetadataIsNoop(t *testing.T) {
	const num = 241
	const name = "REPEAT-META"
	caps := Capabilities{ForSIG0: true}
	record(num, name, caps, false)
	// A second identical metadata record must not panic (harmless no-op).
	record(num, name, caps, false)
	if e := byNumber[num]; e.real {
		t.Errorf("repeated metadata should stay metadata-only, got real=true")
	}
}

func TestRecord_DifferentNameSameCodepointPanics(t *testing.T) {
	const num = 242
	defer func() {
		if recover() == nil {
			t.Error("expected panic when re-registering a codepoint under a different name")
		}
	}()
	record(num, "NAME-A", Capabilities{}, false)
	record(num, "NAME-B", Capabilities{}, false) // different name → panic
}

func TestRecord_CapabilityMismatchPanics(t *testing.T) {
	const num = 243
	const name = "CAPS-MISMATCH"
	defer func() {
		if recover() == nil {
			t.Error("expected panic on metadata/impl capability mismatch")
		}
	}()
	record(num, name, Capabilities{ForDNSSEC: true, ForZSK: true}, false)
	record(num, name, Capabilities{ForDNSSEC: true, ForKSK: true}, true) // caps differ → panic
}

func TestRecord_TwoRealPanics(t *testing.T) {
	const num = 244
	const name = "DOUBLE-REAL"
	caps := Capabilities{ForSIG0: true}
	defer func() {
		if recover() == nil {
			t.Error("expected panic on a second real registration of one codepoint")
		}
	}()
	record(num, name, caps, true)
	record(num, name, caps, true) // second real → panic
}

func TestSupportedKSK_ZSK_IncludeBuiltins(t *testing.T) {
	ksk := SupportedKSK()
	zsk := SupportedZSK()
	// Classical builtins are usable in either role.
	for _, name := range []string{"RSASHA256", "ECDSAP256SHA256", "ED25519"} {
		if !contains(ksk, name) {
			t.Errorf("SupportedKSK missing builtin %q", name)
		}
		if !contains(zsk, name) {
			t.Errorf("SupportedZSK missing builtin %q", name)
		}
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
