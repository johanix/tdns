package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// TestTrustUpdateIsIndependentOfSignerOrder pins the contract that the
// per-signer Validated fix exists to guarantee: when more than one signer in a
// dual-signed rollover UPDATE has verified its own signature, TrustUpdate must
// find the trusted one and confer "by-trusted" status REGARDLESS of the order
// the signers appear in.
//
// Before the fix, ValidateUpdate's verification loop broke on the first
// success, so every later signer kept Validated=false and TrustUpdate skipped
// it on the !key.Validated guard — making the outcome depend on SIG RR order.
// The loop now marks every signer whose own signature verified, so both
// orderings below must reach the same verdict.
func TestTrustUpdateIsIndependentOfSignerOrder(t *testing.T) {
	zd := &ZoneData{}

	untrusted := Sig0UpdateSigner{
		Name:      "child.example.",
		KeyId:     111,
		Validated: true, // its own signature verified...
		Sig0Key:   &Sig0Key{Name: "child.example.", Keyid: 111},
	}
	trusted := Sig0UpdateSigner{
		Name:      "child.example.",
		KeyId:     222,
		Validated: true, // ...and so did this one
		Sig0Key:   &Sig0Key{Name: "child.example.", Keyid: 222, Trusted: true},
	}

	for _, tc := range []struct {
		name    string
		signers []Sig0UpdateSigner
	}{
		{"trusted key signs first", []Sig0UpdateSigner{trusted, untrusted}},
		{"trusted key signs second", []Sig0UpdateSigner{untrusted, trusted}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			us := &UpdateStatus{
				Validated:       true,
				ValidationRcode: dns.RcodeSuccess,
				Signers:         tc.signers,
			}
			if err := zd.TrustUpdate(nil, us); err != nil {
				t.Fatalf("TrustUpdate returned error: %v", err)
			}
			if !us.ValidatedByTrustedKey {
				t.Error("ValidatedByTrustedKey = false; the trusted signer must confer trust in either order")
			}
			if us.SignatureType != "by-trusted" {
				t.Errorf("SignatureType = %q, want \"by-trusted\"", us.SignatureType)
			}
		})
	}
}

// TestTrustUpdateSkipsUnverifiedSigner is the security counterpart: a signer
// that did NOT verify its own signature must never confer trust, even when it
// names a trusted key. This is what the per-signer Validated guard in
// TrustUpdate protects, and the fix above must not weaken it — a forged SIG
// naming a trusted key still fails Verify() and keeps Validated=false.
func TestTrustUpdateSkipsUnverifiedSigner(t *testing.T) {
	zd := &ZoneData{}
	us := &UpdateStatus{
		Validated:       true, // an untrusted key's signature did verify
		ValidationRcode: dns.RcodeSuccess,
		Signers: []Sig0UpdateSigner{
			{
				Name: "child.example.", KeyId: 111, Validated: true,
				Sig0Key: &Sig0Key{Name: "child.example.", Keyid: 111},
			},
			{
				// Forged SIG naming a trusted key: never verified.
				Name: "child.example.", KeyId: 222, Validated: false,
				Sig0Key: &Sig0Key{Name: "child.example.", Keyid: 222, Trusted: true},
			},
		},
	}
	if err := zd.TrustUpdate(nil, us); err == nil {
		t.Fatal("expected an error: no verified signer is trusted")
	}
	if us.ValidatedByTrustedKey {
		t.Error("ValidatedByTrustedKey must be false: the trusted key's signature was never verified")
	}
}
