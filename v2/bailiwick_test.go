package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

func nsRR(t *testing.T, owner, target string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(owner + " 3600 IN NS " + target)
	if err != nil {
		t.Fatalf("building NS %s -> %s: %v", owner, target, err)
	}
	return rr
}

// In-bailiwick means "at or below the zone cut", and that has to be decided on
// whole labels. A bare suffix match accepts a name in a different zone whose
// text happens to end the same way -- the delegation-sync code then looks for
// glue that cannot exist there, and the drift comparison is made against
// nothing.
func TestBailiwickNSComparesOnLabelBoundaries(t *testing.T) {
	const zone = "example.com."

	cases := []struct {
		target string
		want   bool
		why    string
	}{
		{"ns.example.com.", true, "ordinary in-bailiwick nameserver"},
		{"example.com.", true, "the apex itself is at the zone cut"},
		{"a.b.example.com.", true, "deeper in the zone"},

		// The bug: a suffix match spans the label boundary.
		{"ns.notexample.com.", false, "different zone; suffix matches across a label"},
		{"notexample.com.", false, "different zone entirely"},

		// DNS names are case-insensitive; the suffix match was not.
		{"NS.EXAMPLE.COM.", true, "case must not matter"},

		{"ns.example.net.", false, "unrelated zone"},
		{"ns.example.com.evil.", false, "zone name appears, but not as a suffix"},
	}

	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			got, err := BailiwickNS(zone, []dns.RR{nsRR(t, zone, tc.target)})
			if err != nil {
				t.Fatalf("BailiwickNS: %v", err)
			}
			in := len(got) == 1
			if in != tc.want {
				t.Errorf("BailiwickNS(%q, %q) in-bailiwick = %v, want %v (%s)",
					zone, tc.target, in, tc.want, tc.why)
			}
		})
	}
}

// The whole set is filtered in one pass, keeping only the in-bailiwick members.
func TestBailiwickNSFiltersAMixedRRset(t *testing.T) {
	const zone = "example.com."
	rrs := []dns.RR{
		nsRR(t, zone, "ns1.example.com."),
		nsRR(t, zone, "ns1.provider.net."),
		nsRR(t, zone, "ns.notexample.com."),
		nsRR(t, zone, "ns2.example.com."),
	}

	got, err := BailiwickNS(zone, rrs)
	if err != nil {
		t.Fatalf("BailiwickNS: %v", err)
	}
	want := map[string]bool{"ns1.example.com.": true, "ns2.example.com.": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want exactly %v", got, want)
	}
	for _, ns := range got {
		if !want[ns] {
			t.Errorf("%q should not be in-bailiwick for %q", ns, zone)
		}
	}
}
