package tdns

import (
	"encoding/base64"
	"testing"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// validChildKeyRR returns a well-formed KEY RR string (ED25519) suitable for a
// structurally-valid child key in the truststore.
func validChildKeyRR(t *testing.T) string {
	t.Helper()
	rr, err := dns.NewRR("child.example. 3600 IN KEY 256 3 15 " + base64.StdEncoding.EncodeToString(make([]byte, 32)))
	if err != nil {
		t.Fatalf("build KEY RR: %v", err)
	}
	return rr.String()
}

// TestChildKeyStateMap asserts K-4: the internal truststore state → keystate-03
// KEY-STATE code map. Codes 7 and 8 are dormant Phase 2 stubs and are not
// exercised here. Note that validated and trusted are independent (technical
// vs policy), so validated=1,trusted=0 is a first-class state → 10.
func TestChildKeyStateMap(t *testing.T) {
	valid := validChildKeyRR(t)

	cases := []struct {
		name     string
		key      *Sig0Key
		manual   bool
		wantCode uint8
	}{
		{
			name:     "trusted -> KEY_TRUSTED(4)",
			key:      &Sig0Key{Keystr: valid, Validated: true, Trusted: true},
			wantCode: edns0.KeyStateTrusted,
		},
		{
			name:     "structurally broken KEY -> KEY_INVALID(6)",
			key:      &Sig0Key{Keystr: "this is not a valid KEY RR", Trusted: false},
			wantCode: edns0.KeyStateInvalid,
		},
		{
			name:     "empty keystr -> KEY_INVALID(6)",
			key:      &Sig0Key{Keystr: "", Trusted: false},
			wantCode: edns0.KeyStateInvalid,
		},
		{
			// The technical-vs-policy case: technically validated, but trust
			// withheld pending a manual/policy step.
			name:     "validated=1,trusted=0 -> KEY_BOOTSTRAP_MANUAL(10)",
			key:      &Sig0Key{Keystr: valid, Validated: true, Trusted: false},
			wantCode: edns0.KeyStateBootstrapManualRequired,
		},
		{
			name:     "not validated + manual policy -> KEY_BOOTSTRAP_MANUAL(10)",
			key:      &Sig0Key{Keystr: valid, Validated: false, Trusted: false},
			manual:   true,
			wantCode: edns0.KeyStateBootstrapManualRequired,
		},
		{
			name:     "not validated + auto policy -> KEY_BOOTSTRAP_AUTO(9)",
			key:      &Sig0Key{Keystr: valid, Validated: false, Trusted: false},
			manual:   false,
			wantCode: edns0.KeyStateBootstrapAutoOngoing,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := childKeyState(c.key, c.manual)
			if got != c.wantCode {
				t.Errorf("childKeyState = %d (%s), want %d (%s)",
					got, edns0.KeyStateToString(got), c.wantCode, edns0.KeyStateToString(c.wantCode))
			}
		})
	}
}

// TestGetKeyStatusNotFound asserts a key absent from the truststore → KEY_UNKNOWN(5).
func TestGetKeyStatusNotFound(t *testing.T) {
	kdb := newTestKeyDB(t)
	resp, err := kdb.GetKeyStatus("child.example.", 4242)
	if err != nil {
		t.Fatalf("GetKeyStatus: %v", err)
	}
	if resp.KeyState != uint8(edns0.KeyStateUnknown) {
		t.Errorf("KeyState = %d, want 5 (KEY_UNKNOWN)", resp.KeyState)
	}
	if resp.KeyID != 4242 {
		t.Errorf("KeyID = %d, want 4242", resp.KeyID)
	}
}

// TestProcessKeyStateTransientStoreError asserts K-4 code 1: a transient
// truststore failure on an inquiry → KEY_TEMPORARY_FAILURE(1), not KEY_UNKNOWN.
func TestProcessKeyStateTransientStoreError(t *testing.T) {
	kdb := newTestKeyDB(t)
	// Force a store failure: a closed DB makes Sig0TrustMgmt error.
	if err := kdb.DB.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	resp, err := kdb.ProcessKeyState(&edns0.KeyStateOption{KeyID: 4242, KeyState: uint8(edns0.KeyStateInquiryKey)}, "child.example.")
	if err != nil {
		t.Fatalf("ProcessKeyState: %v", err)
	}
	if resp.KeyState != uint8(edns0.KeyStateTemporaryFailure) {
		t.Errorf("KeyState = %d, want 1 (KEY_TEMPORARY_FAILURE)", resp.KeyState)
	}
	if resp.KeyData != 0 {
		t.Errorf("KeyData = %d, want 0", resp.KeyData)
	}
}

// TestNewKeyStateInquiryQTYPE asserts K-5: the child's KeyState inquiry is a
// QTYPE=KEY query carrying a KeyState option with KEY-STATE=INTENT_INQUIRE_KEY(2).
func TestNewKeyStateInquiryQTYPE(t *testing.T) {
	m := newKeyStateInquiryMsg("child.example.", 4242)

	if len(m.Question) != 1 {
		t.Fatalf("Question count = %d, want 1", len(m.Question))
	}
	if m.Question[0].Qtype != dns.TypeKEY {
		t.Errorf("Qtype = %s, want KEY", dns.TypeToString[m.Question[0].Qtype])
	}
	if m.Question[0].Name != "child.example." {
		t.Errorf("Qname = %q, want child.example.", m.Question[0].Name)
	}

	opt := m.IsEdns0()
	if opt == nil {
		t.Fatal("no OPT RR on inquiry")
	}
	ks, found := edns0.ExtractKeyStateOption(opt)
	if !found {
		t.Fatal("KeyState option missing from inquiry")
	}
	if ks.KeyState != uint8(edns0.KeyStateInquiryKey) {
		t.Errorf("KeyState = %d, want 2 (INTENT_INQUIRE_KEY)", ks.KeyState)
	}
	if ks.KeyID != 4242 {
		t.Errorf("KeyID = %d, want 4242", ks.KeyID)
	}
}
