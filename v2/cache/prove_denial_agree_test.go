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

// zoneRecords returns the NSEC and NSEC3 records of sets that zone signed and
// that validate: what the chain walk, which checks signatures with the zone's
// keys, hands ProveDenial and ProveWildcardAnswer.
func zoneRecords(t *testing.T, rrcache *RRsetCacheT, zone string, sets []*core.RRset) ([]*dns.NSEC, []*dns.NSEC3) {
	t.Helper()
	var nsecs []*dns.NSEC
	var nsec3s []*dns.NSEC3
	for _, set := range sets {
		if set == nil || (set.RRtype != dns.TypeNSEC && set.RRtype != dns.TypeNSEC3) {
			continue
		}
		zs := signedBy(set, zone)
		if zs == nil {
			continue
		}
		copied := &core.RRset{Name: zs.Name, Class: zs.Class, RRtype: zs.RRtype, RRs: zs.RRs, RRSIGs: zs.RRSIGs}
		if state, err := rrcache.ValidateRRset(context.Background(), copied, nil); err != nil || state != ValidationStateSecure {
			continue
		}
		for _, rr := range zs.RRs {
			switch r := rr.(type) {
			case *dns.NSEC:
				nsecs = append(nsecs, r)
			case *dns.NSEC3:
				nsec3s = append(nsec3s, r)
			}
		}
	}
	return nsecs, nsec3s
}

// agreeDenial checks that ProveDenial, on the records of sets that validate,
// comes to what ValidateDenial does on sets, and to want.
func agreeDenial(t *testing.T, rrcache *RRsetCacheT, zone, qname string, qtype uint16, rcode uint8, sets []*core.RRset, want ValidationState) {
	t.Helper()
	resolver, _ := rrcache.ValidateDenial(context.Background(), qname, qtype, rcode, sets, nil)
	nsecs, nsec3s := zoneRecords(t, rrcache, zone, sets)
	walk := ProveDenial(qname, qtype, rcode, zone, nsecs, nsec3s)
	if walk.State != want {
		t.Errorf("ProveDenial: %s, want %s", ValidationStateToString[walk.State], ValidationStateToString[want])
	}
	if walk.State != resolver.State || walk.Rcode != resolver.Rcode || walk.EDECode != resolver.EDECode {
		t.Errorf("ProveDenial %s rcode %d EDE %d, ValidateDenial %s rcode %d EDE %d",
			ValidationStateToString[walk.State], walk.Rcode, walk.EDECode,
			ValidationStateToString[resolver.State], resolver.Rcode, resolver.EDECode)
	}
}

// ProveDenial is the reading ValidateDenial makes of the records that
// validate. On the same NSEC3 records they agree (RFC 5155 section 8).
func TestProveDenialAgreesNSEC3(t *testing.T) {
	const optOut = 1
	kidDS := func(flags uint8, k *zoneKey, t *testing.T, match bool) []*core.RRset {
		if match {
			return n3Denial(t, k, synthNSEC3(secZone, secKid, false, 0, 0, "", dns.TypeNS))
		}
		return n3Denial(t, k, apexNSEC3(secZone), synthNSEC3(secZone, secKid, true, flags, 0, ""))
	}
	cases := []struct {
		name  string
		qname string
		qtype uint16
		rcode uint8
		sets  func(t *testing.T, k *zoneKey) []*core.RRset
		want  ValidationState
	}{
		{"name error", n3NX, dns.TypeA, dns.RcodeNameError, func(t *testing.T, k *zoneKey) []*core.RRset {
			return n3Denial(t, k, n3NameError(0, 0)...)
		}, ValidationStateSecure},
		{"name error through Opt-Out", n3NX, dns.TypeA, dns.RcodeNameError, func(t *testing.T, k *zoneKey) []*core.RRset {
			return n3Denial(t, k, n3NameError(optOut, 0)...)
		}, ValidationStateInsecure},
		{"name error without the wildcard cover", n3NX, dns.TypeA, dns.RcodeNameError, func(t *testing.T, k *zoneKey) []*core.RRset {
			return n3Denial(t, k, n3NameError(0, 0)[:2]...)
		}, ValidationStateBogus},
		{"no data", n3WWW, dns.TypeMX, dns.RcodeSuccess, func(t *testing.T, k *zoneKey) []*core.RRset {
			return n3Denial(t, k, synthNSEC3(secZone, n3WWW, false, 0, 0, "", dns.TypeA, dns.TypeRRSIG))
		}, ValidationStateSecure},
		{"no data, the type exists", n3WWW, dns.TypeA, dns.RcodeSuccess, func(t *testing.T, k *zoneKey) []*core.RRset {
			return n3Denial(t, k, synthNSEC3(secZone, n3WWW, false, 0, 0, "", dns.TypeA, dns.TypeRRSIG))
		}, ValidationStateBogus},
		{"over the iteration limit", n3NX, dns.TypeA, dns.RcodeNameError, func(t *testing.T, k *zoneKey) []*core.RRset {
			return n3Denial(t, k, n3NameError(0, DefaultNSEC3MaxIterations+1)...)
		}, ValidationStateInsecure},
		{"the wildcard cover owned in another zone", n3NX, dns.TypeA, dns.RcodeNameError, func(t *testing.T, k *zoneKey) []*core.RRset {
			recs := n3NameError(0, 0)
			recs[2].Hdr.Name = dns.SplitDomainName(recs[2].Hdr.Name)[0] + ".other." + secZone
			return n3Denial(t, k, recs...)
		}, ValidationStateBogus},
		{"no DS, a matching NSEC3", secKid, dns.TypeDS, dns.RcodeSuccess, func(t *testing.T, k *zoneKey) []*core.RRset {
			return kidDS(0, k, t, true)
		}, ValidationStateSecure},
		{"no DS, an Opt-Out span", secKid, dns.TypeDS, dns.RcodeSuccess, func(t *testing.T, k *zoneKey) []*core.RRset {
			return kidDS(optOut, k, t, false)
		}, ValidationStateInsecure},
		{"no DS, a cover without Opt-Out", secKid, dns.TypeDS, dns.RcodeSuccess, func(t *testing.T, k *zoneKey) []*core.RRset {
			return kidDS(0, k, t, false)
		}, ValidationStateBogus},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache, k := secCache(t)
			agreeDenial(t, rrcache, secZone, c.qname, c.qtype, c.rcode, c.sets(t, k), c.want)
		})
	}
}

// The same for NSEC records: name errors (RFC 4035 section 5.4), no data at
// the name, at an empty non-terminal and at a wildcard (nsecNoData), and RFC
// 9824 compact denials.
func TestProveDenialAgreesNSEC(t *testing.T) {
	const (
		ent  = "ent." + negZone
		wild = "wild." + negZone
		q    = "x." + wild
	)
	entCover := "a." + negZone + " 300 IN NSEC x." + ent + " A RRSIG NSEC"
	apex := negZone + " 300 IN NSEC a." + negZone + " SOA NS RRSIG NSEC DNSKEY"
	wcNSEC := func(types string) string { return "*." + wild + " 300 IN NSEC a." + wild + " " + types }
	cover := "a." + wild + " 300 IN NSEC z." + wild + " A RRSIG NSEC"
	compact := func(types string) string {
		return "nosuch." + negZone + " 300 IN NSEC \\000.nosuch." + negZone + " " + types
	}
	cases := []struct {
		name  string
		qname string
		qtype uint16
		rcode uint8
		nsecs []string
		want  ValidationState
	}{
		{"name error, the apex NSEC covers both", "www." + negZone, dns.TypeA, dns.RcodeNameError,
			[]string{negZone + " 300 IN NSEC zzz." + negZone + " SOA NS RRSIG NSEC DNSKEY"}, ValidationStateSecure},
		{"name error, no cover", "www." + negZone, dns.TypeA, dns.RcodeNameError,
			[]string{"b." + negZone + " 300 IN NSEC c." + negZone + " A RRSIG NSEC"}, ValidationStateBogus},
		{"no data at the name", "a." + negZone, dns.TypeMX, dns.RcodeSuccess,
			[]string{"a." + negZone + " 300 IN NSEC b." + negZone + " A RRSIG NSEC"}, ValidationStateSecure},
		{"no data, the type exists", "a." + negZone, dns.TypeA, dns.RcodeSuccess,
			[]string{"a." + negZone + " 300 IN NSEC b." + negZone + " A RRSIG NSEC"}, ValidationStateBogus},
		{"no DS at a delegation", "a." + negZone, dns.TypeDS, dns.RcodeSuccess,
			[]string{"a." + negZone + " 300 IN NSEC b." + negZone + " NS RRSIG NSEC"}, ValidationStateSecure},
		{"empty non-terminal, no data", ent, dns.TypeA, dns.RcodeSuccess, []string{entCover}, ValidationStateSecure},
		{"empty non-terminal, no DS", ent, dns.TypeDS, dns.RcodeSuccess, []string{entCover}, ValidationStateSecure},
		{"empty non-terminal, name error", ent, dns.TypeA, dns.RcodeNameError, []string{entCover, apex}, ValidationStateBogus},
		{"wildcard, no data", q, dns.TypeAAAA, dns.RcodeSuccess, []string{wcNSEC("A RRSIG NSEC"), cover}, ValidationStateSecure},
		{"wildcard, one record in both roles", q, dns.TypeAAAA, dns.RcodeSuccess,
			[]string{"*." + wild + " 300 IN NSEC z." + wild + " A RRSIG NSEC"}, ValidationStateSecure},
		{"wildcard, the type exists", q, dns.TypeA, dns.RcodeSuccess, []string{wcNSEC("A RRSIG NSEC"), cover}, ValidationStateBogus},
		{"wildcard with a CNAME", q, dns.TypeAAAA, dns.RcodeSuccess, []string{wcNSEC("CNAME RRSIG NSEC"), cover}, ValidationStateBogus},
		{"wildcard with NS and no SOA", q, dns.TypeAAAA, dns.RcodeSuccess, []string{wcNSEC("NS RRSIG NSEC"), cover}, ValidationStateBogus},
		{"wildcard at another encloser", q, dns.TypeAAAA, dns.RcodeSuccess,
			[]string{"*." + negZone + " 300 IN NSEC a." + negZone + " A RRSIG NSEC", cover}, ValidationStateBogus},
		{"compact denial, name error", "nosuch." + negZone, dns.TypeA, dns.RcodeSuccess,
			[]string{compact("RRSIG NSEC NXNAME")}, ValidationStateSecure},
		{"compact denial, no data", "nosuch." + negZone, dns.TypeMX, dns.RcodeSuccess,
			[]string{compact("A RRSIG NSEC")}, ValidationStateSecure},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache := negCache(t)
			s := newNegSigner(t, rrcache)
			agreeDenial(t, rrcache, negZone, c.qname, c.qtype, c.rcode, signedDenial(t, s, c.nsecs...), c.want)
		})
	}
}

// With no NSEC or NSEC3 record, nothing is proven.
func TestProveDenialWithoutRecords(t *testing.T) {
	for _, rcode := range []uint8{dns.RcodeSuccess, dns.RcodeNameError} {
		if v := ProveDenial("www."+negZone, dns.TypeA, rcode, negZone, nil, nil); v.State != ValidationStateBogus {
			t.Errorf("rcode %d: %s, want bogus", rcode, ValidationStateToString[v.State])
		}
	}
}
