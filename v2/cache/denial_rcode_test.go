/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// The proof must match the rcode. A name error needs a proof that the name
// does not exist; an answer of no data a proof that it exists without the
// type. An NSEC at the name shows that it exists, unless it is an RFC 9824
// compact denial, and it proves no data only when neither the type nor CNAME
// is in its bitmap (RFC 4035 section 5.4, RFC 6840 section 4.3).
// ValidateDenial and ProveDenial agree, and the rcode a Secure verdict
// carries is the one its proof supports.
func TestNSECProofMatchesTheRcode(t *testing.T) {
	const www = "www." + negZone
	atWWW := func(types string) string { return www + " 300 IN NSEC zzz." + negZone + " " + types }
	compact := www + " 300 IN NSEC \\000." + www + " RRSIG NSEC NXNAME"
	apex := negZone + " 300 IN NSEC zzz." + negZone + " SOA NS RRSIG NSEC DNSKEY" // covers www and *.neg.example.
	cases := []struct {
		name      string
		qname     string
		qtype     uint16
		rcode     uint8
		nsec      string
		want      ValidationState
		wantRcode uint8
	}{
		{"no data at the name", www, dns.TypeAAAA, dns.RcodeSuccess, atWWW("A RRSIG NSEC"), ValidationStateSecure, dns.RcodeSuccess},
		{"no data at the name, as a name error", www, dns.TypeAAAA, dns.RcodeNameError, atWWW("A RRSIG NSEC"), ValidationStateBogus, dns.RcodeNameError},
		{"no data at the apex, as a name error", negZone, dns.TypeA, dns.RcodeNameError, apex, ValidationStateBogus, dns.RcodeNameError},
		{"a CNAME at the name", www, dns.TypeA, dns.RcodeSuccess, atWWW("CNAME RRSIG NSEC"), ValidationStateBogus, dns.RcodeSuccess},
		{"a CNAME at the name, as a name error", www, dns.TypeA, dns.RcodeNameError, atWWW("CNAME RRSIG NSEC"), ValidationStateBogus, dns.RcodeNameError},
		{"the type at the name", www, dns.TypeA, dns.RcodeSuccess, atWWW("A RRSIG NSEC"), ValidationStateBogus, dns.RcodeSuccess},
		{"a compact denial", www, dns.TypeA, dns.RcodeSuccess, compact, ValidationStateSecure, dns.RcodeNameError},
		{"a compact denial, as a name error", www, dns.TypeA, dns.RcodeNameError, compact, ValidationStateSecure, dns.RcodeNameError},
		{"a name error", www, dns.TypeA, dns.RcodeNameError, apex, ValidationStateSecure, dns.RcodeNameError},
		{"a name error, as no data", www, dns.TypeA, dns.RcodeSuccess, apex, ValidationStateBogus, dns.RcodeSuccess},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache := negCache(t)
			s := newNegSigner(t, rrcache)
			sets := signedDenial(t, s, c.nsec)
			agreeDenial(t, rrcache, negZone, c.qname, c.qtype, c.rcode, sets, c.want)
			if v, _ := rrcache.ValidateDenial(context.Background(), c.qname, c.qtype, c.rcode, sets, nil); v.Rcode != c.wantRcode {
				t.Errorf("rcode %s, want %s", dns.RcodeToString[int(v.Rcode)], dns.RcodeToString[int(c.wantRcode)])
			}
		})
	}
}

// NSEC3 proofs already matched the rcode (RFC 5155 section 8): pinned beside
// the NSEC rules.
func TestNSEC3ProofMatchesTheRcode(t *testing.T) {
	cases := []struct {
		name  string
		qname string
		qtype uint16
		rcode uint8
		recs  []*dns.NSEC3
		want  ValidationState
	}{
		{"a name error, as no data", n3NX, dns.TypeA, dns.RcodeSuccess, n3NameError(0, 0), ValidationStateBogus},
		{"no data, as a name error", n3WWW, dns.TypeMX, dns.RcodeNameError,
			[]*dns.NSEC3{synthNSEC3(secZone, n3WWW, false, 0, 0, "", dns.TypeA, dns.TypeRRSIG)}, ValidationStateBogus},
		{"a CNAME at the name", n3WWW, dns.TypeA, dns.RcodeSuccess,
			[]*dns.NSEC3{synthNSEC3(secZone, n3WWW, false, 0, 0, "", dns.TypeCNAME, dns.TypeRRSIG)}, ValidationStateBogus},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache, k := secCache(t)
			agreeDenial(t, rrcache, secZone, c.qname, c.qtype, c.rcode, n3Denial(t, k, c.recs...), c.want)
		})
	}
}
