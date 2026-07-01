package tdns

import "testing"

// TestZoneStoreRoundTrip pins the serialization contract: a store written with
// the canonical token must parse back to the same ZoneStore. This is the bug
// that shipped — the write side used the display form ("MapZone") which the
// reader rejected.
func TestZoneStoreRoundTrip(t *testing.T) {
	for _, s := range []ZoneStore{MapZone, SliceZone, XfrZone} {
		tok := zoneStoreConfigToken(s)
		if got := parseZoneStore(tok); got != s {
			t.Errorf("round-trip failed: %v -> %q -> %v", s, tok, got)
		}
	}
}

// TestZoneStoreCanonicalToken pins the canonical tokens. They must be exactly
// what parseZoneStore considers canonical (lowercase), or the dirty-detection
// in LoadDynamicZoneFiles would re-flag and re-persist on every load.
func TestZoneStoreCanonicalToken(t *testing.T) {
	want := map[ZoneStore]string{MapZone: "map", SliceZone: "slice", XfrZone: "xfr"}
	for s, tok := range want {
		if got := zoneStoreConfigToken(s); got != tok {
			t.Errorf("zoneStoreConfigToken(%v) = %q, want %q", s, got, tok)
		}
	}
}

// TestParseZoneStoreTolerant verifies the reader accepts both the canonical
// tokens and the legacy display forms the daemon used to persist, so existing
// dynamic-config files load cleanly.
func TestParseZoneStoreTolerant(t *testing.T) {
	cases := map[string]ZoneStore{
		"map":       MapZone,
		"MapZone":   MapZone, // legacy display form (the shipped bug)
		"mapzone":   MapZone,
		"slice":     SliceZone,
		"SliceZone": SliceZone,
		"xfr":       XfrZone,
		"XfrZone":   XfrZone,
		"  Map  ":   MapZone, // trimmed + case-insensitive
		"":          MapZone, // unset defaults to map
		"bogus":     MapZone, // unknown defaults to map (with a warning)
	}
	for in, want := range cases {
		if got := parseZoneStore(in); got != want {
			t.Errorf("parseZoneStore(%q) = %v, want %v", in, got, want)
		}
	}
}
