/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package debug

import (
	"testing"

	"github.com/miekg/dns"
)

func packSOAResponse(t *testing.T, apex string, rcode int, withSOA bool) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(apex, dns.TypeSOA)
	m.Response = true
	m.Rcode = rcode
	if withSOA {
		m.Answer = []dns.RR{&dns.SOA{
			Hdr:     dns.RR_Header{Name: apex, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
			Ns:      "ns." + apex,
			Mbox:    "hostmaster." + apex,
			Serial:  1,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  60,
		}}
	}
	w, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return w
}

// validSOAResponse must accept only a well-formed NOERROR answer that carries
// the apex SOA — the "correct" criterion the QPS finder counts against. A
// SERVFAIL, a NOERROR with no SOA, or garbage bytes all count as NOT correct
// (so a server replying fast with SERVFAIL cannot inflate the QPS number).
func TestValidSOAResponse(t *testing.T) {
	apex := dns.Fqdn("axfr.net")
	cases := []struct {
		name string
		wire []byte
		want bool
	}{
		{"noerror+soa", packSOAResponse(t, apex, dns.RcodeSuccess, true), true},
		{"servfail", packSOAResponse(t, apex, dns.RcodeServerFailure, true), false},
		{"noerror-no-soa", packSOAResponse(t, apex, dns.RcodeSuccess, false), false},
		{"malformed", []byte{0x00, 0x01, 0x02}, false},
	}
	for _, c := range cases {
		if got := validSOAResponse(c.wire, apex); got != c.want {
			t.Errorf("%s: validSOAResponse = %v, want %v", c.name, got, c.want)
		}
	}
}
