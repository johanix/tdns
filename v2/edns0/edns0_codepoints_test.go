package edns0

import "testing"

// TestLocalOptionCodesAreUnique guards against two tdns-local EDNS(0) options
// claiming the same option code. They are all carried as dns.EDNS0_LOCAL and
// dispatched purely on Code, so a collision means one option is silently parsed
// as the other — EDNS0_PROVIDERSYNC_OPTION_CODE and EDNS0_KEYSTATE_OPTION_CODE
// both held 65002, so a ProviderSync option would have been read as a KeyState
// option. Nothing in the compiler catches that; this test does.
//
// Add every new tdns-local option code here as well as in edns0_defs.go.
func TestLocalOptionCodesAreUnique(t *testing.T) {
	codes := map[string]uint16{
		"EDNS0_OOTS_OPTION_CODE":          EDNS0_OOTS_OPTION_CODE,
		"EDNS0_KEYSTATE_OPTION_CODE":      EDNS0_KEYSTATE_OPTION_CODE,
		"EDNS0_REPORT_OPTION_CODE":        EDNS0_REPORT_OPTION_CODE,
		"EDNS0_CHUNK_OPTION_CODE":         EDNS0_CHUNK_OPTION_CODE,
		"EDNS0_CHUNK_QUERY_ENDPOINT_CODE": EDNS0_CHUNK_QUERY_ENDPOINT_CODE,
		"EDNS0_PROVIDERSYNC_OPTION_CODE":  EDNS0_PROVIDERSYNC_OPTION_CODE,
	}

	seen := make(map[uint16]string, len(codes))
	for name, code := range codes {
		if other, dup := seen[code]; dup {
			t.Errorf("option code %d claimed by both %s and %s — one of them must move to a free code point",
				code, other, name)
			continue
		}
		seen[code] = name
	}

	// The local range is the private-use space; a code outside it would collide
	// with an IANA assignment instead.
	for name, code := range codes {
		if code < 65001 || code > 65534 {
			t.Errorf("%s = %d is outside the tdns-local private-use range 65001-65534", name, code)
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

		// The standard code must keep its RFC 8914 value and must not be part
		// of the private sequence.
		{"EDEDNSSECBogus", EDEDNSSECBogus, 6},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}
