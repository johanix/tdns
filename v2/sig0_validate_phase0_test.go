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
				Name:      "child.example.",
				KeyId:     111,
				Validated: true, // ...this signer's own signature verified...
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
				Name:      "child.example.",
				KeyId:     333,
				Validated: true, // this signer's own signature verified
				Sig0Key:   &Sig0Key{Name: "child.example.", Keyid: 333, Trusted: true},
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

	// Multi-SIG(0) cross-signer confusion. ValidateUpdate's discovery loop
	// appends a signer for every SIG RR matched on SignerName+KeyTag alone, and
	// its verification loop breaks on the first success — so a later entry can
	// name a trusted key whose signature was never verified. An attacker pairs a
	// genuine signature from their own untrusted key with a forged SIG naming a
	// trusted key; only the aggregate us.Validated is true. TrustUpdate must NOT
	// grant "by-trusted" off the unverified entry, or the untrusted-KEY-delete
	// refusal in ApproveTrustUpdate (gated on ValidatedByTrustedKey) is defeated.
	t.Run("forged SIG naming a trusted key must not confer trust", func(t *testing.T) {
		us := &UpdateStatus{
			Validated:       true, // aggregate: signer[0]'s signature verified
			ValidationRcode: dns.RcodeSuccess,
			Signers: []Sig0UpdateSigner{
				{
					// The attacker's own key: signature genuinely verified,
					// but the key is not trusted.
					Name:      "attacker.example.",
					KeyId:     111,
					Validated: true,
					Sig0Key:   &Sig0Key{Name: "attacker.example.", Keyid: 111},
				},
				{
					// Forged SIG naming a trusted key: located during discovery
					// by name+keytag, but its signature was NEVER verified.
					Name:      "child.example.",
					KeyId:     222,
					Validated: false,
					Sig0Key:   &Sig0Key{Name: "child.example.", Keyid: 222, Trusted: true},
				},
			},
		}
		if err := zd.TrustUpdate(nil, us); err == nil {
			t.Fatal("expected error: an unverified trusted-key SIG must not confer trust")
		}
		if us.ValidatedByTrustedKey {
			t.Error("ValidatedByTrustedKey must be false — the trusted key's signature was never verified")
		}
		if us.SignatureType == "by-trusted" {
			t.Errorf("SignatureType = %q, must not be by-trusted", us.SignatureType)
		}
		// Falls through to the known-but-not-trusted tail: a signature did
		// verify, but no *verified* signer is trusted.
		if us.ValidationRcode != dns.RcodeRefused {
			t.Errorf("ValidationRcode = %d, want REFUSED(%d)", us.ValidationRcode, dns.RcodeRefused)
		}
	})
}
