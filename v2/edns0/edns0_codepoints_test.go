package edns0

import "testing"

// Two local options sharing a code are indistinguishable on the wire: a
// receiver reads whichever one it happens to look for and parses the other's
// payload as though it were its own. That is what happened to KEYSTATE and
// PROVIDERSYNC, both at 65002, because PROVIDERSYNC was declared in its own
// file where nothing adding to the central table could see it.
//
// This is the test that makes keeping them in one block worth doing. A new
// option copy-pasted onto an existing code fails here rather than on the wire.
func TestLocalOptionCodesAreUnique(t *testing.T) {
	codes := map[uint16]string{}

	for name, code := range map[string]uint16{
		"OOTS":                 EDNS0_OOTS_OPTION_CODE,
		"KEYSTATE":             EDNS0_KEYSTATE_OPTION_CODE,
		"REPORT":               EDNS0_REPORT_OPTION_CODE,
		"CHUNK":                EDNS0_CHUNK_OPTION_CODE,
		"CHUNK_QUERY_ENDPOINT": EDNS0_CHUNK_QUERY_ENDPOINT_CODE,
		"PROVIDERSYNC":         EDNS0_PROVIDERSYNC_OPTION_CODE,
	} {
		if prev, taken := codes[code]; taken {
			t.Errorf("option code %d is used by both %s and %s;"+
				" on the wire they are the same option", code, prev, name)
			continue
		}
		codes[code] = name
	}
}

// The codes must also sit in the private-use range. A local option outside it
// is squatting on space IANA may allocate to someone else, which breaks
// differently and later: the option keeps working until somebody else's
// software starts sending the same code for another purpose.
func TestLocalOptionCodesAreInPrivateUseRange(t *testing.T) {
	for name, code := range map[string]uint16{
		"OOTS":                 EDNS0_OOTS_OPTION_CODE,
		"KEYSTATE":             EDNS0_KEYSTATE_OPTION_CODE,
		"REPORT":               EDNS0_REPORT_OPTION_CODE,
		"CHUNK":                EDNS0_CHUNK_OPTION_CODE,
		"CHUNK_QUERY_ENDPOINT": EDNS0_CHUNK_QUERY_ENDPOINT_CODE,
		"PROVIDERSYNC":         EDNS0_PROVIDERSYNC_OPTION_CODE,
	} {
		if code < localOptionCodeFirst || code > localOptionCodeLast {
			t.Errorf("%s uses code %d, outside the local/private-use range %d-%d",
				name, code, localOptionCodeFirst, localOptionCodeLast)
		}
	}
}

// TestEDECodeValues pins the numeric value of the private EDE codes.
//
// These go on the wire and are quoted verbatim in the drafts and design docs,
// so they are part of the interface, not an implementation detail. They are
// also unusually easy to break: the block is defined as `513 + iota`, so
// prepending any constant to it renumbers every code silently. That is exactly
// what happened — a standard RFC 8914 code was added at the head of the block,
// pushing EDESig0KeyNotKnown from its documented 513 to 514 and dragging the
// rest of the block with it. Every existing test asserted symbolically, so
// nothing caught it.
//
// If this test fails, do not "fix" it by updating the numbers: check whether a
// constant was added to the head of the private block in edns0_ede.go.
func TestEDECodeValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  uint16
		want uint16
	}{
		// The two codes the delegation-mgmt-via-ddns draft names directly.
		{"EDESig0KeyNotKnown", EDESig0KeyNotKnown, 513},
		{"EDESig0KeyKnownButNotTrusted", EDESig0KeyKnownButNotTrusted, 514},

		// Block anchors: these catch a shift introduced anywhere in the middle.
		{"EDEDelegationSyncNotSupported", EDEDelegationSyncNotSupported, 515},
		{"EDEZoneFrozen", EDEZoneFrozen, 516},
		{"EDETsigValidationFailure", EDETsigValidationFailure, 523},
		{"EDESig0BadTime", EDESig0BadTime, 527},
		{"EDESig0BadSignature", EDESig0BadSignature, 528},
		{"EDESig0FormatError", EDESig0FormatError, 529},

		// The remaining two draft-named bootstrap-state codes (D-8), appended
		// at the end of the block on 2026-09-02.
		{"EDESig0KeyValidationFailed", EDESig0KeyValidationFailed, 541},
		{"EDESig0ManualBootstrapRequired", EDESig0ManualBootstrapRequired, 542},

		// The standard code must keep its RFC 8914 value and must not be part
		// of the private sequence.
		{"EDEDNSSECBogus", EDEDNSSECBogus, 6},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

// The three ddns-02 bootstrap-state EDEs must all render, since the
// UPDATE responder puts the string on the wire as EXTRA-TEXT.
func TestBootstrapStateEDEStrings(t *testing.T) {
	for _, code := range []uint16{EDESig0KeyKnownButNotTrusted, EDESig0KeyValidationFailed, EDESig0ManualBootstrapRequired} {
		if s, ok := EDECodeToString[code]; !ok || s == "" {
			t.Errorf("EDE %d has no string", code)
		}
	}
}
