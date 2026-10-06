/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"testing"

	"github.com/miekg/dns"
)

// negZone delegates kid.neg.example. The NSEC at the cut is the zone's, and
// in canonical order it covers every name below the cut. Those names are the
// child's: the NSEC proves nothing about them, nor about any type at the cut
// but the DS (RFC 4035 section 5.4, RFC 6840 section 4.1). With a DS at the
// cut that is Bogus; without one the child is proven unsigned, and the denial
// is Insecure, as NSEC3 has it. ValidateDenial and ProveDenial agree.
func TestNSECAtAZoneCutProvesNothingBelowIt(t *testing.T) {
	const (
		kid    = "kid." + negZone
		kidWWW = "www." + kid
	)
	cut := func(types string) string { return kid + " 300 IN NSEC zzz." + negZone + " " + types }
	signedCut, unsignedCut := cut("NS DS RRSIG NSEC"), cut("NS RRSIG NSEC")
	cases := []struct {
		name  string
		qname string
		qtype uint16
		rcode uint8
		nsec  string
		want  ValidationState
	}{
		{"below a signed cut, no data", kidWWW, dns.TypeA, dns.RcodeSuccess, signedCut, ValidationStateBogus},
		{"below a signed cut, name error", kidWWW, dns.TypeA, dns.RcodeNameError, signedCut, ValidationStateBogus},
		{"at a signed cut, another type", kid, dns.TypeA, dns.RcodeSuccess, signedCut, ValidationStateBogus},
		{"at a signed cut, the DS it lists", kid, dns.TypeDS, dns.RcodeSuccess, signedCut, ValidationStateBogus},
		{"below an unsigned cut, no data", kidWWW, dns.TypeA, dns.RcodeSuccess, unsignedCut, ValidationStateInsecure},
		{"below an unsigned cut, name error", kidWWW, dns.TypeA, dns.RcodeNameError, unsignedCut, ValidationStateInsecure},
		{"at an unsigned cut, another type", kid, dns.TypeA, dns.RcodeSuccess, unsignedCut, ValidationStateInsecure},
		// What the NSEC at a cut is for: no DS there (RFC 4035 section 5.2).
		{"at an unsigned cut, no DS", kid, dns.TypeDS, dns.RcodeSuccess, unsignedCut, ValidationStateSecure},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache := negCache(t)
			s := newNegSigner(t, rrcache)
			agreeDenial(t, rrcache, negZone, c.qname, c.qtype, c.rcode, signedDenial(t, s, c.nsec), c.want)
		})
	}
}

// Below a DNAME the zone holds no names either: they are redirected. The NSEC
// at the DNAME proves nothing about them (RFC 6840 section 4.1). At the DNAME
// itself it is an ordinary NSEC.
func TestNSECAtADNAMEProvesNothingBelowIt(t *testing.T) {
	const d = "d." + negZone
	dname := d + " 300 IN NSEC e." + negZone + " DNAME RRSIG NSEC"
	apex := negZone + " 300 IN NSEC a." + negZone + " SOA NS RRSIG NSEC DNSKEY"
	for _, c := range []struct {
		name  string
		qname string
		qtype uint16
		rcode uint8
		want  ValidationState
	}{
		{"below the DNAME, name error", "x." + d, dns.TypeA, dns.RcodeNameError, ValidationStateBogus},
		{"below the DNAME, no data", "x." + d, dns.TypeA, dns.RcodeSuccess, ValidationStateBogus},
		{"at the DNAME, no data", d, dns.TypeA, dns.RcodeSuccess, ValidationStateSecure},
	} {
		t.Run(c.name, func(t *testing.T) {
			rrcache := negCache(t)
			s := newNegSigner(t, rrcache)
			agreeDenial(t, rrcache, negZone, c.qname, c.qtype, c.rcode, signedDenial(t, s, dname, apex), c.want)
		})
	}
}

// A DS is the zone above's data. A zone's own denial of the DS at its apex,
// NSEC or NSEC3, is the child side answering: Bogus. The zone above's
// denial of the same DS is the proof that counts.
func TestADSIsDeniedByTheZoneAbove(t *testing.T) {
	t.Run("NSEC, the zone itself", func(t *testing.T) {
		rrcache := negCache(t)
		s := newNegSigner(t, rrcache)
		apex := negZone + " 300 IN NSEC zzz." + negZone + " SOA NS RRSIG NSEC DNSKEY"
		agreeDenial(t, rrcache, negZone, negZone, dns.TypeDS, dns.RcodeSuccess, signedDenial(t, s, apex), ValidationStateBogus)
	})
	t.Run("NSEC3, the zone itself", func(t *testing.T) {
		rrcache, k := secCache(t)
		agreeDenial(t, rrcache, secZone, secZone, dns.TypeDS, dns.RcodeSuccess, n3Denial(t, k, apexNSEC3(secZone)), ValidationStateBogus)
	})
	t.Run("NSEC3, the zone above", func(t *testing.T) {
		rrcache, k := secCache(t)
		sets := n3Denial(t, k, synthNSEC3(secZone, secKid, false, 0, 0, "", dns.TypeNS))
		agreeDenial(t, rrcache, secZone, secKid, dns.TypeDS, dns.RcodeSuccess, sets, ValidationStateSecure)
	})
}

// NSEC3 already read a zone cut so (nsec3Proof.closestEncloser, noData):
// pinned beside the NSEC rules, which now match it.
func TestNSEC3AtAZoneCutProvesNothingBelowIt(t *testing.T) {
	const ns1 = "ns1." + secKid
	for _, c := range []struct {
		name  string
		ds    bool
		qname string
		rcode uint8
		want  ValidationState
	}{
		{"below a signed cut, no data", true, ns1, dns.RcodeSuccess, ValidationStateBogus},
		{"below a signed cut, name error", true, ns1, dns.RcodeNameError, ValidationStateBogus},
		{"at a signed cut, another type", true, secKid, dns.RcodeSuccess, ValidationStateBogus},
		{"below an unsigned cut, no data", false, ns1, dns.RcodeSuccess, ValidationStateInsecure},
		{"below an unsigned cut, name error", false, ns1, dns.RcodeNameError, ValidationStateInsecure},
		{"at an unsigned cut, another type", false, secKid, dns.RcodeSuccess, ValidationStateInsecure},
	} {
		t.Run(c.name, func(t *testing.T) {
			types := []uint16{dns.TypeNS, dns.TypeRRSIG}
			if c.ds {
				types = append(types, dns.TypeDS)
			}
			rrcache, k := secCache(t)
			sets := n3Denial(t, k,
				apexNSEC3(secZone),
				synthNSEC3(secZone, secKid, false, 0, 0, "", types...),
				synthNSEC3(secZone, ns1, true, 0, 0, ""),
				synthNSEC3(secZone, "*."+secKid, true, 0, 0, ""),
			)
			agreeDenial(t, rrcache, secZone, c.qname, dns.TypeA, c.rcode, sets, c.want)
		})
	}
}

// nsecAboveCut is about names strictly below the NSEC's owner.
func TestNSECAboveCut(t *testing.T) {
	nsec := func(owner, types string) *dns.NSEC {
		return rrFromString(t, owner+" 300 IN NSEC zzz."+negZone+" "+types).(*dns.NSEC)
	}
	for _, c := range []struct {
		name string
		rr   *dns.NSEC
		of   string
		want bool
	}{
		{"a cut, a name below", nsec("kid."+negZone, "NS RRSIG NSEC"), "a.kid." + negZone, true},
		{"a cut, the cut itself", nsec("kid."+negZone, "NS RRSIG NSEC"), "kid." + negZone, false},
		{"a cut, a sibling", nsec("kid."+negZone, "NS RRSIG NSEC"), "kie." + negZone, false},
		{"a DNAME, a name below", nsec("d."+negZone, "DNAME RRSIG NSEC"), "a.d." + negZone, true},
		{"an apex, a name below", nsec(negZone, "SOA NS RRSIG NSEC DNSKEY"), "a." + negZone, false},
		{"an ordinary name, a name below", nsec("a."+negZone, "A RRSIG NSEC"), "b.a." + negZone, false},
	} {
		if got := nsecAboveCut(dns.CanonicalName(c.of), c.rr); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
