package edns0

import (
	"testing"
)

// TestKeyStateCodepoints03 pins the KeyState codepoints to the
// draft-berra-dnsop-keystate-03 registry. Phase 0 (K-1) reassigned codes 0
// and 1 — which carried sender bootstrap-request meanings in keystate-02 — to
// the receiver protocol-level responses KEY_REQUEST_MALFORMED and
// KEY_TEMPORARY_FAILURE, and removed the invented code 11 (BootstrapAutoPending).
func TestKeyStateCodepoints03(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"KEY_REQUEST_MALFORMED", KeyStateRequestMalformed, 0},
		{"KEY_TEMPORARY_FAILURE", KeyStateTemporaryFailure, 1},
		{"INTENT_INQUIRE_KEY", KeyStateInquiryKey, 2},
		{"KEY_TRUSTED", KeyStateTrusted, 4},
		{"KEY_UNKNOWN", KeyStateUnknown, 5},
		{"KEY_INVALID", KeyStateInvalid, 6},
		{"KEY_REFUSED", KeyStateRefused, 7},
		{"KEY_VALIDATION_FAILED", KeyStateValidationFail, 8},
		{"KEY_BOOTSTRAP_AUTO", KeyStateBootstrapAutoOngoing, 9},
		{"KEY_BOOTSTRAP_MANUAL", KeyStateBootstrapManualRequired, 10},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d (keystate-03 registry)", c.name, c.got, c.want)
		}
	}
}

// TestKeyStateMalformedRoundTrip round-trips a KEY_REQUEST_MALFORMED(0)
// response option on the wire and asserts the -03 value survives, KEY-ID is
// echoed, and KEY-DATA is 0.
func TestKeyStateMalformedRoundTrip(t *testing.T) {
	opt := CreateKeyStateOption(4242, uint8(KeyStateRequestMalformed), 0, "bad")
	parsed, err := ParseKeyStateOption(opt)
	if err != nil {
		t.Fatalf("ParseKeyStateOption: %v", err)
	}
	if parsed.KeyState != 0 {
		t.Errorf("KeyState wire value = %d, want 0 (KEY_REQUEST_MALFORMED)", parsed.KeyState)
	}
	if parsed.KeyID != 4242 {
		t.Errorf("KeyID = %d, want 4242 (echoed)", parsed.KeyID)
	}
	if parsed.KeyData != 0 {
		t.Errorf("KeyData = %d, want 0", parsed.KeyData)
	}
}

// TestKeyStateToString03 asserts the -02 sender-request labels are gone and
// the -03 protocol-level labels are present, and that the removed code 11
// falls through to the unassigned default.
func TestKeyStateToString03(t *testing.T) {
	if got := KeyStateToString(uint8(KeyStateRequestMalformed)); got != "Request Malformed" {
		t.Errorf("KeyStateToString(0) = %q, want %q", got, "Request Malformed")
	}
	if got := KeyStateToString(uint8(KeyStateTemporaryFailure)); got != "Temporary Failure" {
		t.Errorf("KeyStateToString(1) = %q, want %q", got, "Temporary Failure")
	}
	// Code 11 is unassigned in -03 → not in the map → the "Unknown State"
	// default, never the -02 "Auto Bootstrap Pending" label.
	if got := KeyStateToString(11); got != "Unknown State (11)" {
		t.Errorf("KeyStateToString(11) = %q, want the unassigned default %q", got, "Unknown State (11)")
	}
}
