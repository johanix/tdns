package algorithms

import (
	"crypto"
	"testing"

	"github.com/johanix/tdns/v2/algorithms/mldsa44"
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
		{dns.ED448, "ED448"},
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
		"ECDSAP384SHA384", "ED25519", "ED448"}
	for _, w := range wantContains {
		if !contains(got, w) {
			t.Errorf("SupportedSIG0() = %v; missing %q", got, w)
		}
	}
}

func TestSupportedDNSSEC_IncludesBuiltins(t *testing.T) {
	got := SupportedDNSSEC()
	wantContains := []string{"RSASHA256", "RSASHA512", "ECDSAP256SHA256",
		"ECDSAP384SHA384", "ED25519", "ED448"}
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

	RegisterMetadata(testNum, testName, Capabilities{ForSIG0: true}, Facts{})

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
		Capabilities{ForSIG0: true}, Facts{})
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
	record(num, name, caps, Facts{}, false)
	if e, ok := byNumber[num]; !ok || e.real {
		t.Fatalf("after metadata record: entry real=%v ok=%v; want real=false", e.real, ok)
	}
	// Then: a real registration of the same codepoint/name/caps promotes.
	record(num, name, caps, Facts{}, true)
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
	record(num, name, caps, Facts{}, false)
	// A second identical metadata record must not panic (harmless no-op).
	record(num, name, caps, Facts{}, false)
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
	record(num, "NAME-A", Capabilities{}, Facts{}, false)
	record(num, "NAME-B", Capabilities{}, Facts{}, false) // different name → panic
}

func TestRecord_CapabilityMismatchPanics(t *testing.T) {
	const num = 243
	const name = "CAPS-MISMATCH"
	defer func() {
		if recover() == nil {
			t.Error("expected panic on metadata/impl capability mismatch")
		}
	}()
	record(num, name, Capabilities{ForDNSSEC: true, ForZSK: true}, Facts{}, false)
	record(num, name, Capabilities{ForDNSSEC: true, ForKSK: true}, Facts{}, true) // caps differ → panic
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
	record(num, name, caps, Facts{}, true)
	record(num, name, caps, Facts{}, true) // second real → panic
}

// TestFactsCarriedThrough verifies static Facts survive registration and
// surface in All(), and that a metadata entry lacking facts is filled in
// when the later real registration supplies them (promotion).
func TestFactsCarriedThrough(t *testing.T) {
	const num = 245
	const name = "FACTS-TEST"
	caps := Capabilities{ForSIG0: true, ForDNSSEC: true, ForKSK: true, ForZSK: true}
	facts := Facts{PubKeyBytes: 100, SigBytes: 200, SecurityLevel: 3, Maturity: "candidate", Description: "d"}

	// Metadata first with no facts, then a real registration carrying facts.
	record(num, name, caps, Facts{}, false)
	record(num, name, caps, facts, true)

	if got := byNumber[num].facts; got != facts {
		t.Fatalf("facts not filled in on promotion: got %+v want %+v", got, facts)
	}
	for _, a := range All() {
		if a.Number == num {
			if a.Facts != facts {
				t.Errorf("All() facts = %+v; want %+v", a.Facts, facts)
			}
			return
		}
	}
	t.Errorf("codepoint %d (real) missing from All()", num)
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

// ML-DSA-44 is in every binary: this test binary has no generated
// registration code, as a build without an algs.list has none.
func TestMLDSA44IsBuiltIn(t *testing.T) {
	if num, ok := AlgorithmNumber("MLDSA44"); !ok || num != 18 {
		t.Fatalf("AlgorithmNumber(MLDSA44) = %d, %v; want 18, true", num, ok)
	}
	caps, ok := CapsReal(MLDSA44)
	if !ok {
		t.Fatal("CapsReal(18): ML-DSA-44 is not registered as real")
	}
	if want := (Capabilities{ForSIG0: true, ForDNSSEC: true, ForKSK: true, ForZSK: true}); caps != want {
		t.Errorf("caps = %+v, want %+v", caps, want)
	}
	if got := dns.AlgorithmToString[MLDSA44]; got != "MLDSA44" {
		t.Errorf("dns.AlgorithmToString[18] = %q, want MLDSA44", got)
	}
	found := false
	for _, a := range All() {
		if a.Number == MLDSA44 {
			found = true
			if a.Facts.SigBytes != 2420 || a.Facts.PubKeyBytes != 1312 {
				t.Errorf("facts = %+v, want the ML-DSA-44 sizes", a.Facts)
			}
		}
	}
	if !found {
		t.Error("All() does not list ML-DSA-44")
	}

	// Wired into miekg/dns: a key generates, signs and verifies.
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: 257, Protocol: 3, Algorithm: MLDSA44}
	priv, err := key.Generate(0)
	if err != nil {
		t.Fatalf("ML-DSA-44 is recorded but not wired into miekg/dns: %v", err)
	}
	txt := &dns.TXT{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}, Txt: []string{"x"}}
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm: MLDSA44, KeyTag: key.KeyTag(), SignerName: "example.", Inception: 1, Expiration: 2}
	if err := sig.Sign(priv.(crypto.Signer), []dns.RR{txt}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := sig.Verify(key, []dns.RR{txt}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// Generated registration code registers ML-DSA-44 again when it comes from
// an older genalgs or from a dnssec-algorithms checkout that still has the
// row, possibly with the capabilities of an older checkout (KSK only). That
// is ignored; the built-in registration stands.
func TestRegisteringABuiltInAgainIsIgnored(t *testing.T) {
	kskOnly := Capabilities{ForSIG0: true, ForDNSSEC: true, ForKSK: true}
	RegisterMetadata(MLDSA44, "MLDSA44", kskOnly, Facts{})
	Register(MLDSA44, mldsa44.New(), kskOnly, Facts{})
	if caps, ok := CapsReal(MLDSA44); !ok || !caps.ForZSK {
		t.Errorf("CapsReal(18) = %+v, %v after the repeats; the built-in registration must stand", caps, ok)
	}

	if !isSelfRegistered(dns.ED448, "ED448") {
		t.Error("ED448 is not marked as registered by this package")
	}
	if isSelfRegistered(dns.ED25519, "ED25519") {
		t.Error("ED25519 is a miekg/dns built-in, not registered by this package")
	}
	if isSelfRegistered(MLDSA44, "SOMETHING-ELSE") {
		t.Error("a different name at 18 must not count as the built-in")
	}
}

// ED448 is not a miekg/dns built-in: it has to be registered for real, or it
// is listed as usable and fails at the first key.
func TestED448RegisteredForReal(t *testing.T) {
	if _, ok := CapsReal(dns.ED448); !ok {
		t.Fatal("CapsReal(ED448) not registered as real")
	}
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET}, Flags: 257, Protocol: 3, Algorithm: dns.ED448}
	if _, err := k.Generate(0); err != nil {
		t.Fatalf("ED448 is recorded but not wired into miekg/dns: %v", err)
	}
}
