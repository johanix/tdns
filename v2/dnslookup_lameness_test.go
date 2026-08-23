package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// A DS is parent-side data, so a child's own server refusing a DS query for
// itself is behaving correctly and must not be marked lame. Marking it removed
// the only address of a single-server zone and disabled the zone entirely.
func TestRefusalIndicatesLameness(t *testing.T) {
	cases := []struct {
		name  string
		qtype uint16
		rcode int
		want  bool
	}{
		{"DS refused by the child's own server", dns.TypeDS, dns.RcodeRefused, false},
		{"DS notauth by the child's own server", dns.TypeDS, dns.RcodeNotAuth, false},

		// Genuine lameness must still be recorded, or a really lame server is
		// retried forever.
		{"A refused", dns.TypeA, dns.RcodeRefused, true},
		{"NS notauth", dns.TypeNS, dns.RcodeNotAuth, true},
		{"SOA refused", dns.TypeSOA, dns.RcodeRefused, true},

		// A DS query failing for other reasons still counts: those are not the
		// "wrong server for this qtype" case.
		{"DS servfail", dns.TypeDS, dns.RcodeServerFailure, true},
		{"DS notimp", dns.TypeDS, dns.RcodeNotImplemented, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := refusalIndicatesLameness(tc.qtype, tc.rcode); got != tc.want {
				t.Errorf("refusalIndicatesLameness(%s, %s) = %v, want %v",
					dns.TypeToString[tc.qtype], dns.RcodeToString[tc.rcode], got, tc.want)
			}
		})
	}
}
