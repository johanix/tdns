package tdns

import "testing"

// TestXfrErrorRcode pins the translation of miekg/dns AXFR "bad xfr rcode: N"
// errors to their mnemonics, so dog prints REFUSED/SERVFAIL/... instead of a
// bare number.
func TestXfrErrorRcode(t *testing.T) {
	cases := []struct {
		errstr string
		want   string
		ok     bool
	}{
		{"dns: bad xfr rcode: 5", "REFUSED", true},
		{"dns: bad xfr rcode: 2", "SERVFAIL", true},
		{"dns: bad xfr rcode: 9", "NOTAUTH", true},
		{"dns: bad xfr rcode: 3", "NXDOMAIN", true},
		{"dns: bad xfr rcode: 0", "NOERROR", true},
		{"dns: bad xfr rcode: 250", "rcode 250", true}, // unknown code → numeric fallback
		{"dns: connection refused", "", false},
		{"some other error", "", false},
		{"dns: bad xfr rcode: notanumber", "", false},
	}
	for _, c := range cases {
		got, ok := xfrErrorRcode(c.errstr)
		if ok != c.ok || got != c.want {
			t.Errorf("xfrErrorRcode(%q) = (%q, %v), want (%q, %v)", c.errstr, got, ok, c.want, c.ok)
		}
	}
}
