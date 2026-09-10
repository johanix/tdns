/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func nsecSet(owner string, bitmap []uint16) *core.RRset {
	return &core.RRset{
		Name:   owner,
		Class:  dns.ClassINET,
		RRtype: dns.TypeNSEC,
		RRs: []dns.RR{&dns.NSEC{
			Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 900},
			NextDomain: "\000." + owner,
			TypeBitMap: bitmap,
		}},
	}
}

// CompactDenialNXDOMAIN is a check on the shape of the proof and nothing
// else: the NSEC has to be owned by the qname and carry exactly the NXDOMAIN
// bitmap. It must not be fooled by an NSEC at another name, by a NODATA
// proof at the qname, or by the absence of signatures.
func TestCompactDenialNXDOMAIN(t *testing.T) {
	soa := &core.RRset{Name: "example.", Class: dns.ClassINET, RRtype: dns.TypeSOA}
	nxdomain := []uint16{dns.TypeNSEC, dns.TypeRRSIG, dns.TypeNXNAME}
	nodata := []uint16{dns.TypeA, dns.TypeNSEC, dns.TypeRRSIG}

	cases := []struct {
		name string
		neg  []*core.RRset
		want bool
	}{
		{"nxname NSEC at qname", []*core.RRset{soa, nsecSet("nosuch.example.", nxdomain)}, true},
		{"qname spelled differently", []*core.RRset{soa, nsecSet("NoSuch.Example.", nxdomain)}, true},
		{"nodata NSEC at qname", []*core.RRset{soa, nsecSet("nosuch.example.", nodata)}, false},
		{"nxname NSEC at another owner", []*core.RRset{soa, nsecSet("other.example.", nxdomain)}, false},
		{"nxname beside a real type", []*core.RRset{soa, nsecSet("nosuch.example.", []uint16{dns.TypeA, dns.TypeNSEC, dns.TypeRRSIG, dns.TypeNXNAME})}, false},
		{"SOA only", []*core.RRset{soa}, false},
		{"nil set", []*core.RRset{nil, soa}, false},
		{"nothing", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CompactDenialNXDOMAIN("nosuch.example.", tc.neg); got != tc.want {
				t.Fatalf("CompactDenialNXDOMAIN = %v, want %v", got, tc.want)
			}
		})
	}
}
