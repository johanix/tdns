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
