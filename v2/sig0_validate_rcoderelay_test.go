package tdns

import (
	"testing"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// TestTrustUpdateDefaultsRcodeWhenUnvalidated covers the defensive default in
// TrustUpdate's !us.Validated branch.
//
// The branch previously relied on ValidateUpdate having run first and left a
// non-success ValidationRcode behind. A caller that reaches TrustUpdate with a
// fresh UpdateStatus{} would return an error while ValidationRcode was still
// its zero value (RcodeSuccess), and UpdateResponder relays that value
// directly — so the child would receive NOERROR for an update the receiver
// actually rejected.
func TestTrustUpdateDefaultsRcodeWhenUnvalidated(t *testing.T) {
	zd := &ZoneData{}

	// A fresh UpdateStatus, as if TrustUpdate were called without
	// ValidateUpdate having set its fail-closed default first.
	us := &UpdateStatus{
		Validated: false,
		Signers: []Sig0UpdateSigner{
			{Name: "child.example.", KeyId: 111, Sig0Key: &Sig0Key{Name: "child.example.", Keyid: 111}},
		},
	}
	if us.ValidationRcode != dns.RcodeSuccess {
		t.Fatalf("precondition: zero-valued ValidationRcode should be RcodeSuccess, got %d", us.ValidationRcode)
	}

	if err := zd.TrustUpdate(nil, us); err == nil {
		t.Fatal("expected an error: no signature verified")
	}
	if us.ValidationRcode == dns.RcodeSuccess {
		t.Error("ValidationRcode is still NOERROR while TrustUpdate returned an error; " +
			"the responder would answer NOERROR for a rejected update")
	}
	if us.ValidationRcode != dns.RcodeBadSig {
		t.Errorf("ValidationRcode = %d, want BADSIG(%d)", us.ValidationRcode, dns.RcodeBadSig)
	}
	if us.RejectionEDE != edns0.EDESig0BadSignature {
		t.Errorf("RejectionEDE = %d, want EDESig0BadSignature(%d)", us.RejectionEDE, edns0.EDESig0BadSignature)
	}
}

// TestTrustUpdatePreservesRecordedRcode is the counterpart: when ValidateUpdate
// HAS recorded a specific failure (e.g. BADTIME for clock skew), the defensive
// default must not overwrite it with the generic BADSIG.
func TestTrustUpdatePreservesRecordedRcode(t *testing.T) {
	zd := &ZoneData{}
	us := &UpdateStatus{
		Validated:       false,
		ValidationRcode: dns.RcodeBadTime,
		RejectionEDE:    edns0.EDESig0BadTime,
		Signers: []Sig0UpdateSigner{
			{Name: "child.example.", KeyId: 111, Sig0Key: &Sig0Key{Name: "child.example.", Keyid: 111}},
		},
	}

	if err := zd.TrustUpdate(nil, us); err == nil {
		t.Fatal("expected an error: no signature verified")
	}
	if us.ValidationRcode != dns.RcodeBadTime {
		t.Errorf("ValidationRcode = %d, want BADTIME(%d) preserved", us.ValidationRcode, dns.RcodeBadTime)
	}
	if us.RejectionEDE != edns0.EDESig0BadTime {
		t.Errorf("RejectionEDE = %d, want EDESig0BadTime(%d) preserved", us.RejectionEDE, edns0.EDESig0BadTime)
	}
}

// TestApplyValidationFailureRelaysRecordedRcodeAndEDE is the test for the
// responder fix: the rejection path must relay whatever ValidateUpdate /
// TrustUpdate recorded, not a hardcoded rcode + EDE. Reverting the fix (a
// hardcoded SERVFAIL + EDESig0KeyNotKnown, as the ValidateUpdate path had)
// fails the FORMERR case below.
func TestApplyValidationFailureRelaysRecordedRcodeAndEDE(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rcode uint8
		ede   uint16
	}{
		{"unsigned/malformed -> FORMERR", dns.RcodeFormatError, edns0.EDESig0FormatError},
		{"unknown key -> BADKEY", dns.RcodeBadKey, edns0.EDESig0KeyNotKnown},
		{"known but untrusted -> REFUSED", dns.RcodeRefused, edns0.EDESig0KeyKnownButNotTrusted},
		{"bad signature -> BADSIG", dns.RcodeBadSig, edns0.EDESig0BadSignature},
		{"clock skew -> BADTIME", dns.RcodeBadTime, edns0.EDESig0BadTime},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := new(dns.Msg)
			m.SetUpdate("example.")

			applyValidationFailure(m, &UpdateStatus{ValidationRcode: tc.rcode, RejectionEDE: tc.ede})

			if m.Rcode != int(tc.rcode) {
				t.Errorf("response rcode = %d, want %d", m.Rcode, tc.rcode)
			}
			opt := m.IsEdns0()
			if opt == nil {
				t.Fatal("no OPT RR on the response; the EDE was not attached")
			}
			var got uint16
			var found bool
			for _, o := range opt.Option {
				if ede, ok := o.(*dns.EDNS0_EDE); ok {
					got, found = ede.InfoCode, true
				}
			}
			if !found {
				t.Fatal("no EDE option on the response")
			}
			if got != tc.ede {
				t.Errorf("EDE info code = %d, want %d", got, tc.ede)
			}

			// The rejection must actually be sendable. BADSIG/BADKEY/BADTIME
			// are extended rcodes: Pack() refuses Rcode > 0xF without an OPT
			// RR to carry the upper bits, and WriteMsg's error is discarded
			// by both rejection paths — an unpackable reply reaches the child
			// as a TIMEOUT, not a rejection.
			wire, err := m.Pack()
			if err != nil {
				t.Fatalf("rejection does not pack: %v", err)
			}
			var rt dns.Msg
			if err := rt.Unpack(wire); err != nil {
				t.Fatalf("packed rejection does not unpack: %v", err)
			}
			if rt.Rcode != int(tc.rcode) {
				t.Errorf("rcode after wire round-trip = %d, want %d", rt.Rcode, tc.rcode)
			}
		})
	}
}

// TestApplyValidationFailureZeroEDEStillPacks: an EDE of 0 means "none
// recorded" and must not be attached as if it were a real extended error —
// but an extended rcode (here BADSIG=16) must STILL produce a packable
// message, which requires an OPT RR even without an EDE option in it. This
// is the combination no current caller produces (every extended-rcode path
// also records an EDE); the helper must not depend on that staying true.
func TestApplyValidationFailureZeroEDEStillPacks(t *testing.T) {
	m := new(dns.Msg)
	m.SetUpdate("example.")

	applyValidationFailure(m, &UpdateStatus{ValidationRcode: dns.RcodeBadSig, RejectionEDE: 0})

	if m.Rcode != dns.RcodeBadSig {
		t.Errorf("response rcode = %d, want BADSIG(%d)", m.Rcode, dns.RcodeBadSig)
	}
	if opt := m.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if _, ok := o.(*dns.EDNS0_EDE); ok {
				t.Error("an EDE was attached for RejectionEDE=0")
			}
		}
	}
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("BADSIG rejection without an EDE does not pack: %v", err)
	}
	var rt dns.Msg
	if err := rt.Unpack(wire); err != nil {
		t.Fatalf("packed rejection does not unpack: %v", err)
	}
	if rt.Rcode != dns.RcodeBadSig {
		t.Errorf("rcode after wire round-trip = %d, want BADSIG(%d)", rt.Rcode, dns.RcodeBadSig)
	}
}

// TestValidateUpdateUnsignedSetsFormError pins the source of what the responder
// relays for an UPDATE with an empty Additional section: FORMERR + a
// format-error EDE, rather than anything resembling "key not known". A child
// that receives "key not known" is directed at bootstrapping a key, which does
// not fix a malformed message.
func TestValidateUpdateUnsignedSetsFormError(t *testing.T) {
	zd := &ZoneData{}
	us := &UpdateStatus{}

	r := new(dns.Msg)
	r.SetUpdate("example.")
	r.Extra = nil // no OPT, no SIG

	if err := zd.ValidateUpdate(r, us); err == nil {
		t.Fatal("expected an error for an UPDATE with no signature")
	}
	if us.ValidationRcode != dns.RcodeFormatError {
		t.Errorf("ValidationRcode = %d, want FORMERR(%d)", us.ValidationRcode, dns.RcodeFormatError)
	}
	if us.RejectionEDE != edns0.EDESig0FormatError {
		t.Errorf("RejectionEDE = %d, want EDESig0FormatError(%d)", us.RejectionEDE, edns0.EDESig0FormatError)
	}
	if us.Validated || us.ValidatedByTrustedKey {
		t.Error("Validated/ValidatedByTrustedKey must both be false for an unsigned UPDATE")
	}
}

// TestApplyValidationFailureFailsClosedOnSuccessRcode covers the guard that the
// ApproveUpdate rejection path depends on.
//
// ApproveUpdate only returns an error for an unknown update type, and it
// reaches that with validation having SUCCEEDED — so us.ValidationRcode is
// RcodeSuccess there. Relaying it raw (as that path did before it was routed
// through applyValidationFailure) answers NOERROR for an update that was never
// applied: the child records the change as landed. That is the same
// wire-protocol lie the finalRcode logic further down UpdateResponder exists to
// prevent for policy-rejected updates.
func TestApplyValidationFailureFailsClosedOnSuccessRcode(t *testing.T) {
	m := new(dns.Msg)
	m.SetUpdate("example.")

	applyValidationFailure(m, &UpdateStatus{ValidationRcode: dns.RcodeSuccess})

	if m.Rcode == dns.RcodeSuccess {
		t.Fatal("a rejected UPDATE was answered NOERROR; applyValidationFailure must fail closed")
	}
	if m.Rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %d, want SERVFAIL(%d)", m.Rcode, dns.RcodeServerFailure)
	}
	if _, err := m.Pack(); err != nil {
		t.Errorf("fail-closed response did not pack: %v", err)
	}
}
