package tdns

import (
	"testing"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// TestTrustUpdateRcodeMapping asserts D-8: the UPDATE-receiver rcode/EDE
// mapping matches delegation-mgmt-via-ddns-02. Unknown key → BADKEY(17);
// known-but-not-trusted (with a verified signature) → REFUSED + EDE
// KEY-KNOWN-NOT-TRUSTED; a located key whose signature did NOT verify keeps
// BADSIG and is never treated as trusted (the added defense-in-depth guard).
func TestTrustUpdateRcodeMapping(t *testing.T) {
	zd := &ZoneData{}

	t.Run("unknown key -> BADKEY", func(t *testing.T) {
		// ValidateUpdate leaves the RcodeBadSig default when no key is located.
		us := &UpdateStatus{ValidationRcode: dns.RcodeBadSig}
		if err := zd.TrustUpdate(nil, us); err == nil {
			t.Fatal("expected error for an unknown/unsigned key")
		}
		if us.ValidationRcode != dns.RcodeBadKey {
			t.Errorf("ValidationRcode = %d, want BADKEY(%d)", us.ValidationRcode, dns.RcodeBadKey)
		}
		if us.RejectionEDE != edns0.EDESig0KeyNotKnown {
			t.Errorf("RejectionEDE = %d, want EDESig0KeyNotKnown(%d)", us.RejectionEDE, edns0.EDESig0KeyNotKnown)
		}
		if us.ValidatedByTrustedKey {
			t.Error("ValidatedByTrustedKey must be false")
		}
	})

	t.Run("known but not trusted -> REFUSED + EDE514", func(t *testing.T) {
		us := &UpdateStatus{
			Validated:       true, // a signature verified...
			ValidationRcode: dns.RcodeSuccess,
			Signers: []Sig0UpdateSigner{{
				Name:  "child.example.",
				KeyId: 111,
				// ...but the key is neither trusted, DNSSEC-validated, nor an upload.
				Sig0Key: &Sig0Key{Name: "child.example.", Keyid: 111},
			}},
		}
		if err := zd.TrustUpdate(nil, us); err == nil {
			t.Fatal("expected error for a known-but-not-trusted key")
		}
		if us.ValidationRcode != dns.RcodeRefused {
			t.Errorf("ValidationRcode = %d, want REFUSED(%d)", us.ValidationRcode, dns.RcodeRefused)
		}
		if us.RejectionEDE != edns0.EDESig0KeyKnownButNotTrusted {
			t.Errorf("RejectionEDE = %d, want EDESig0KeyKnownButNotTrusted(%d)", us.RejectionEDE, edns0.EDESig0KeyKnownButNotTrusted)
		}
		if us.ValidatedByTrustedKey {
			t.Error("ValidatedByTrustedKey must be false")
		}
	})

	t.Run("trusted key + bad signature -> BADSIG, not accepted", func(t *testing.T) {
		us := &UpdateStatus{
			Validated:       false,           // signature did NOT verify
			ValidationRcode: dns.RcodeBadSig, // set by ValidateUpdate
			RejectionEDE:    edns0.EDESig0BadSignature,
			Signers: []Sig0UpdateSigner{{
				Name:    "child.example.",
				KeyId:   222,
				Sig0Key: &Sig0Key{Name: "child.example.", Keyid: 222, Trusted: true}, // trusted key
			}},
		}
		if err := zd.TrustUpdate(nil, us); err == nil {
			t.Fatal("expected error: a trusted key with a forged signature must not be accepted")
		}
		if us.ValidationRcode != dns.RcodeBadSig {
			t.Errorf("ValidationRcode = %d, want BADSIG(%d) preserved", us.ValidationRcode, dns.RcodeBadSig)
		}
		if us.ValidatedByTrustedKey {
			t.Error("a forged signature over a trusted key's tag must NOT set ValidatedByTrustedKey")
		}
		if us.SignatureType == "by-trusted" {
			t.Error("SignatureType must not be by-trusted for an unverified signature")
		}
	})

	t.Run("trusted key + valid signature -> accepted", func(t *testing.T) {
		us := &UpdateStatus{
			Validated:       true,
			ValidationRcode: dns.RcodeSuccess,
			Signers: []Sig0UpdateSigner{{
				Name:    "child.example.",
				KeyId:   333,
				Sig0Key: &Sig0Key{Name: "child.example.", Keyid: 333, Trusted: true},
			}},
		}
		if err := zd.TrustUpdate(nil, us); err != nil {
			t.Fatalf("trusted key + valid signature should be accepted: %v", err)
		}
		if !us.ValidatedByTrustedKey {
			t.Error("ValidatedByTrustedKey must be true")
		}
		if us.SignatureType != "by-trusted" {
			t.Errorf("SignatureType = %q, want by-trusted", us.SignatureType)
		}
	})
}
