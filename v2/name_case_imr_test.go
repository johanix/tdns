/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Resolver-side name handling: what comes back from OTHER servers.
 *
 * A resolver controls neither the case an authoritative server stores its names
 * in nor, once it randomises query case (0x20), the case it gets back. Records
 * in one response need not agree with each other either: a parent whose zone
 * file spells a delegation's NS owner and its DS owner differently serves them
 * back exactly that way. tdns itself does that as of the boundary work in
 * #417, which preserves the spelling a zone file used instead of folding it.
 */
package tdns

import (
	"testing"
)

// ZoneMatchesSelector is the one predicate both IMR dump handlers filter with.
// It became load-bearing for case when ZoneMap started folding its keys: the
// zone-backoff dump was still comparing a now-canonical key against the filter
// as the operator typed it, so a mixed-case zone argument returned an empty
// dump. Both handlers go through here now, so the two cannot drift again.
func TestZoneMatchesSelectorIgnoresCase(t *testing.T) {
	for _, tc := range []struct {
		zone, exact, suffix string
		want                bool
		why                 string
	}{
		{"example.com.", "example.com.", "", true, "exact match"},
		{"example.com.", "EXAMPLE.COM.", "", true, "filter in another case"},
		{"EXAMPLE.COM.", "example.com.", "", true, "key in another case"},
		{"example.com.", "example.org.", "", false, "different zone"},

		{"www.example.com.", "", "example.com.", true, "suffix match"},
		{"www.example.com.", "", "EXAMPLE.COM.", true, "suffix in another case"},
		{"example.com.", "", "example.com.", true, "suffix matches the zone itself"},
		{"dsync.se.", "", "sync.se.", false, "never a partial label"},

		{"example.com.", "", "", true, "no filter selects everything"},
		{"example.com.", "example.com.", "other.", true, "exact wins over suffix"},
	} {
		if got := ZoneMatchesSelector(tc.zone, tc.exact, tc.suffix); got != tc.want {
			t.Errorf("ZoneMatchesSelector(%q, %q, %q) = %v, want %v -- %s",
				tc.zone, tc.exact, tc.suffix, got, tc.want, tc.why)
		}
	}
}
