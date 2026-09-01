/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package core

import "testing"

// ExtractDistributionIDFromQNAME decides whether a QNAME belongs to a zone and,
// if it does, hands back the label in front of it. It asked
// strings.HasSuffix(qname, zone) and then strings.TrimSuffix(qname, zone),
// which is wrong twice over:
//
//   - a byte suffix is not a bailiwick test. evila1b2kdc.example.com. ends with
//     kdc.example.com., so a name in a DIFFERENT zone passed, and the trim then
//     returned "evila1b2" as though it were a distribution ID from this one.
//   - it is case-sensitive, so a1b2.KDC.example.com. was refused outright.
//
// Both directions matter: refusing everything would "fix" the first and break
// the second, so the accepting cases are as load-bearing as the rejecting ones.
func TestExtractDistributionIDIsBoundedByLabelsAndIgnoresCase(t *testing.T) {
	const zone = "kdc.example.com."

	for _, tc := range []struct {
		qname string
		want  string
		why   string
	}{
		{"a1b2.kdc.example.com.", "a1b2", "the ordinary case"},
		{"a1b2.KDC.example.com.", "a1b2", "zone part in another case"},
		{"A1B2.kdc.example.com.", "A1B2", "the ID keeps its own case: it is an identifier, not a name we fold"},
		{"a1b2.KDC.EXAMPLE.COM.", "a1b2", "all of it in another case"},
		{"x.y.kdc.example.com.", "x.y", "more than one label in front"},
	} {
		got, err := ExtractDistributionIDFromQNAME(tc.qname, zone)
		if err != nil {
			t.Errorf("ExtractDistributionIDFromQNAME(%q, %q): %v -- %s", tc.qname, zone, err, tc.why)
			continue
		}
		if got != tc.want {
			t.Errorf("ExtractDistributionIDFromQNAME(%q, %q) = %q, want %q -- %s",
				tc.qname, zone, got, tc.want, tc.why)
		}
	}

	for _, tc := range []struct{ qname, why string }{
		{"evila1b2kdc.example.com.", "ends with the zone name but is NOT inside it: a byte " +
			"suffix accepted this and returned \"evila1b2\" as a distribution ID"},
		{"EVILA1B2KDC.EXAMPLE.COM.", "the same, and case must not rescue it"},
		{"kdc.example.com.", "the zone itself carries no distribution ID"},
		{"KDC.EXAMPLE.COM.", "the zone itself, spelled differently"},
		{"a1b2.other.example.com.", "a different zone entirely"},
	} {
		if got, err := ExtractDistributionIDFromQNAME(tc.qname, zone); err == nil {
			t.Errorf("ExtractDistributionIDFromQNAME(%q, %q) = %q with no error -- %s",
				tc.qname, zone, got, tc.why)
		}
	}

	// The zone may be given without its trailing dot; the qname likewise.
	if got, err := ExtractDistributionIDFromQNAME("a1b2.kdc.example.com", "kdc.example.com"); err != nil || got != "a1b2" {
		t.Errorf("relative forms: got (%q, %v), want (\"a1b2\", nil)", got, err)
	}
}
