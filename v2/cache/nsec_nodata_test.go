/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// rrFromString parses one record.
func rrFromString(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return rr
}

// signedDenial is negZone's SOA and each NSEC, every RRset signed by s.
func signedDenial(t *testing.T, s *negSigner, nsecs ...string) []*core.RRset {
	t.Helper()
	sets := []*core.RRset{s.sign(t, negSOA(t))}
	for _, n := range nsecs {
		sets = append(sets, s.sign(t, rrFromString(t, n)))
	}
	return sets
}

type denialCase struct {
	name  string
	qname string
	qtype uint16
	rcode uint8
	nsecs []string
	want  ValidationState
}

func runDenialCases(t *testing.T, cases []denialCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache := negCache(t)
			s := newNegSigner(t, rrcache)
			state, _, _ := rrcache.ValidateNegativeResponse(context.Background(), c.qname, c.qtype, c.rcode,
				signedDenial(t, s, c.nsecs...), nil)
			if state != c.want {
				t.Errorf("%s %s rcode %s: %s, want %s", c.qname, dns.TypeToString[c.qtype], dns.RcodeToString[int(c.rcode)],
					ValidationStateToString[state], ValidationStateToString[c.want])
			}
		})
	}
}

// ent.neg.example. holds no records and has a descendant, x.ent.neg.example.:
// an empty non-terminal. An NSEC covering it whose next name lies below it
// proves no data for any type. It proves no name error.
func TestNSECEmptyNonTerminalNoData(t *testing.T) {
	const ent = "ent." + negZone
	entCover := "a." + negZone + " 300 IN NSEC x." + ent + " A RRSIG NSEC"
	// The apex NSEC covers *.neg.example., the wildcard at the closest
	// encloser a name error proof for ent would read from entCover.
	apex := negZone + " 300 IN NSEC a." + negZone + " SOA NS RRSIG NSEC DNSKEY"
	runDenialCases(t, []denialCase{
		{"no data", ent, dns.TypeA, dns.RcodeSuccess, []string{entCover}, ValidationStateSecure},
		{"no data, DS", ent, dns.TypeDS, dns.RcodeSuccess, []string{entCover}, ValidationStateSecure},
		{"name error", ent, dns.TypeA, dns.RcodeNameError, []string{entCover, apex}, ValidationStateBogus},
		{"a cover whose next name is not below qname", ent, dns.TypeA, dns.RcodeSuccess,
			[]string{"a." + negZone + " 300 IN NSEC f." + negZone + " A RRSIG NSEC"}, ValidationStateBogus},
	})
}

// x.wild.neg.example. does not exist, and *.wild.neg.example. answers for it
// with an A and nothing else. A query for another type is answered NODATA,
// proved by an NSEC covering the name and the wildcard's own NSEC.
func TestNSECWildcardNoData(t *testing.T) {
	const (
		wild = "wild." + negZone
		q    = "x." + wild
	)
	wcNSEC := func(types string) string { return "*." + wild + " 300 IN NSEC a." + wild + " " + types }
	cover := "a." + wild + " 300 IN NSEC z." + wild + " A RRSIG NSEC"
	runDenialCases(t, []denialCase{
		{"two records", q, dns.TypeAAAA, dns.RcodeSuccess, []string{wcNSEC("A RRSIG NSEC"), cover}, ValidationStateSecure},
		{"one record in both roles", q, dns.TypeAAAA, dns.RcodeSuccess,
			[]string{"*." + wild + " 300 IN NSEC z." + wild + " A RRSIG NSEC"}, ValidationStateSecure},
		{"the wildcard has the type", q, dns.TypeA, dns.RcodeSuccess, []string{wcNSEC("A RRSIG NSEC"), cover}, ValidationStateBogus},
		{"the wildcard has a CNAME", q, dns.TypeAAAA, dns.RcodeSuccess, []string{wcNSEC("CNAME RRSIG NSEC"), cover}, ValidationStateBogus},
		{"the wildcard has NS and no SOA", q, dns.TypeAAAA, dns.RcodeSuccess, []string{wcNSEC("NS RRSIG NSEC"), cover}, ValidationStateBogus},
		{"the wildcard at another encloser", q, dns.TypeAAAA, dns.RcodeSuccess,
			[]string{"*." + negZone + " 300 IN NSEC a." + negZone + " A RRSIG NSEC", cover}, ValidationStateBogus},
		{"no cover", q, dns.TypeAAAA, dns.RcodeSuccess, []string{wcNSEC("A RRSIG NSEC")}, ValidationStateBogus},
		{"name error", q, dns.TypeAAAA, dns.RcodeNameError, []string{wcNSEC("A RRSIG NSEC"), cover}, ValidationStateBogus},
	})
}
