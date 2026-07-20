package tdns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestTrustUpdateIsIndependentOfSignerOrder pins TrustUpdate's half of the
// contract: GIVEN that more than one signer is already marked Validated, the
// trusted one must confer "by-trusted" status regardless of its position.
//
// NOTE ON COVERAGE: this test builds UpdateStatus by hand and therefore does
// NOT exercise the per-signer marking fix in verifySigners — it passes both
// with and without it, because TrustUpdate already iterated every signer. It
// documents the consuming end of the contract only. The test that actually
// fails without the fix is TestVerifySignersMarksEverySigner below.
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

// mkTestSigner builds a signer whose SIG is inside its validity window. The
// signature bytes are irrelevant: these tests substitute sig0Verify, because
// the real miekg/dns verifier cannot be driven to verify two SIG(0) RRs in one
// message (see the sig0Verify doc comment).
func mkTestSigner(name string, keyid uint16, trusted bool) Sig0UpdateSigner {
	now := uint32(time.Now().UTC().Unix())
	sig := &dns.SIG{}
	sig.Inception = now - 300
	sig.Expiration = now + 300
	sig.KeyTag = keyid
	sig.SignerName = name
	return Sig0UpdateSigner{
		Name:    name,
		KeyId:   keyid,
		Sig:     sig,
		Sig0Key: &Sig0Key{Name: name, Keyid: keyid, Trusted: trusted},
	}
}

// stubSig0Verify substitutes the SIG(0) verifier for the duration of a test.
// fail lists the KeyIds whose verification should fail; everything else
// verifies. The original verifier is restored on cleanup.
func stubSig0Verify(t *testing.T, fail ...uint16) {
	t.Helper()
	orig := sig0Verify
	t.Cleanup(func() { sig0Verify = orig })
	failing := make(map[uint16]bool, len(fail))
	for _, k := range fail {
		failing[k] = true
	}
	sig0Verify = func(sig *dns.SIG, key *dns.KEY, msgbuf []byte) error {
		if failing[sig.RRSIG.KeyTag] {
			return dns.ErrSig
		}
		return nil
	}
}

// TestVerifySignersMarksEverySigner is the test that fails without the fix.
//
// verifySigners must mark EVERY signer whose own signature verified, not just
// the first. The pre-fix loop broke on first success, leaving every later
// signer at Validated=false — which made TrustUpdate's verdict depend on SIG
// RR order, since it skips signers on !key.Validated. Reverting the fix (a
// `break` after the first success) makes this test fail on the second signer.
//
// This cannot be driven through a real signed message: miekg/dns's SIG.Verify
// only ever verifies the LAST record in the packed buffer, so in practice the
// first signer that verifies is also the last and the ordering behaviour is
// unreachable. Hence the sig0Verify seam.
func TestVerifySignersMarksEverySigner(t *testing.T) {
	stubSig0Verify(t) // both signatures verify

	// A dual-signed rollover UPDATE: same child zone, two keys.
	us := &UpdateStatus{
		Signers: []Sig0UpdateSigner{
			mkTestSigner("child.example.", 111, false), // new, not yet trusted
			mkTestSigner("child.example.", 222, true),  // old, trusted
		},
	}

	verifySigners(us, nil)

	for i := range us.Signers {
		if !us.Signers[i].Validated {
			t.Errorf("Signers[%d] (keyid %d): Validated = false, want true; "+
				"every signer whose own signature verified must be marked",
				i, us.Signers[i].KeyId)
		}
	}

	// Aggregate status: first success wins and is not churned by later signers.
	if !us.Validated {
		t.Error("us.Validated = false, want true")
	}
	if us.ValidationRcode != dns.RcodeSuccess {
		t.Errorf("us.ValidationRcode = %d, want NOERROR", us.ValidationRcode)
	}
	if us.RejectionEDE != 0 {
		t.Errorf("us.RejectionEDE = %d, want 0", us.RejectionEDE)
	}
}

// TestVerifySignersFailureDoesNotDowngradeEarlierSuccess covers the other half
// of removing the `break`: now that the loop keeps going, a LATER failing
// signer must not overwrite the aggregate status an earlier success recorded.
// That is what the !us.Validated guards on each failure path protect.
func TestVerifySignersFailureDoesNotDowngradeEarlierSuccess(t *testing.T) {
	stubSig0Verify(t, 222) // the second signer's signature does NOT verify

	us := &UpdateStatus{
		Signers: []Sig0UpdateSigner{
			mkTestSigner("child.example.", 111, true), // verifies
			mkTestSigner("child.example.", 222, true), // fails
		},
	}

	verifySigners(us, nil)

	if !us.Signers[0].Validated {
		t.Error("Signers[0]: Validated = false, want true (its signature verified)")
	}
	if us.Signers[1].Validated {
		t.Error("Signers[1]: Validated = true, want false (its signature did not verify)")
	}
	if !us.Validated {
		t.Error("us.Validated = false; a later failure must not clear an earlier success")
	}
	if us.ValidationRcode != dns.RcodeSuccess {
		t.Errorf("us.ValidationRcode = %d, want NOERROR; a later failure must not downgrade it", us.ValidationRcode)
	}
	if us.RejectionEDE != 0 {
		t.Errorf("us.RejectionEDE = %d, want 0; a later failure must not set a rejection EDE", us.RejectionEDE)
	}
	if us.SignerName != "child.example." {
		t.Errorf("us.SignerName = %q, want %q", us.SignerName, "child.example.")
	}
}
