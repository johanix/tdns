package cache

import "testing"

// A DS lives in the parent zone, so backfillDS must ask the parent's servers.
// Asking the zone's own servers gets a correct REFUSED, which was then booked as
// a lame delegation and disabled the zone entirely.
func TestParentOf(t *testing.T) {
	cases := []struct{ in, want string }{
		{"child.example.", "example."},
		{"a.b.c.example.", "b.c.example."},
		{"example.", "."},
		{".", "."},
	}
	for _, tc := range cases {
		if got := parentOf(tc.in); got != tc.want {
			t.Errorf("parentOf(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
