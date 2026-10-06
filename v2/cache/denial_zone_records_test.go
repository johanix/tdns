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

// otherZone is a signed zone that has nothing to do with the denials below.
const otherZone = "other.test."

// A denial is read from the records of the zone that denies, the one its SOA
// names. An NSEC of another zone counts for nothing, however it is signed:
// the last NSEC of a chain, and the NSEC of a zone of one name, cover names
// far outside their zone in canonical order. The answer is not used, as for
// the NSEC3 records of TestValidateDenialNSEC3ThatDoesNotCount.
func TestValidateDenialNSECThatDoesNotCount(t *testing.T) {
	const www = "www." + negZone
	foreign := map[string]string{
		"the NSEC of a zone of one name": otherZone + " 300 IN NSEC " + otherZone + " A RRSIG NSEC",
		"the last NSEC of another zone":  "zzz." + otherZone + " 300 IN NSEC " + otherZone + " A RRSIG NSEC",
	}
	for name, nsec := range foreign {
		for _, rcode := range []uint8{dns.RcodeNameError, dns.RcodeSuccess} {
			t.Run(name+"/"+dns.RcodeToString[int(rcode)], func(t *testing.T) {
				rrcache := negCache(t)
				s := newNegSigner(t, rrcache)
				other := newZoneKey(t, rrcache, otherZone, true)
				auth := []*core.RRset{s.sign(t, negSOA(t)), other.sign(t, rrFromString(t, nsec))}
				v, err := rrcache.ValidateDenial(context.Background(), www, dns.TypeA, rcode, auth, nil)
				if v.State == ValidationStateSecure || err == nil {
					t.Errorf("state %s, err %v: want an answer that is not used", ValidationStateToString[v.State], err)
				}
			})
		}
	}

	// A zone signed with NSEC3 was reached the same way: the NSEC branch was
	// read whenever an NSEC counted.
	t.Run("beside the SOA of a zone signed with NSEC3", func(t *testing.T) {
		rrcache, k := secCache(t)
		other := newZoneKey(t, rrcache, otherZone, true)
		auth := []*core.RRset{k.sign(t, soaFor(t, secZone)), other.sign(t, rrFromString(t, foreign["the NSEC of a zone of one name"]))}
		v, err := rrcache.ValidateDenial(context.Background(), n3WWW, dns.TypeA, dns.RcodeNameError, auth, nil)
		if v.State == ValidationStateSecure || err == nil {
			t.Errorf("state %s, err %v: want an answer that is not used", ValidationStateToString[v.State], err)
		}
	})

	// The zone above can sign a record named in the zone below when the
	// resolver does not hold the zone below as Secure: its signature then
	// validates. It still does not count: the zone's NSEC chain is its own.
	t.Run("signed by the zone above", func(t *testing.T) {
		rrcache := negCache(t)
		above := newZoneKey(t, rrcache, "example.", true)
		rrcache.ZoneMap.Set("example.", &Zone{ZoneName: "example.", State: ValidationStateSecure})
		s := newNegSigner(t, rrcache)
		auth := []*core.RRset{s.sign(t, negSOA(t)), above.sign(t, negNSEC(t))}
		v, err := rrcache.ValidateDenial(context.Background(), www, dns.TypeA, dns.RcodeNameError, auth, nil)
		if v.State == ValidationStateSecure || err == nil {
			t.Errorf("state %s, err %v: want an answer that is not used", ValidationStateToString[v.State], err)
		}
	})
}

// Another zone's records beside the zone's own proof change nothing: the
// zone's records decide, and they are what ProveDenial reads too.
func TestValidateDenialReadsTheZonesOwnNSEC(t *testing.T) {
	const www = "www." + negZone
	rrcache := negCache(t)
	s := newNegSigner(t, rrcache)
	other := newZoneKey(t, rrcache, otherZone, true)
	own := s.sign(t, negNSEC(t))
	stranger := other.sign(t, rrFromString(t, otherZone+" 300 IN NSEC "+otherZone+" A RRSIG NSEC"))
	auth := []*core.RRset{s.sign(t, negSOA(t)), stranger, own}

	agreeDenial(t, rrcache, negZone, www, dns.TypeA, dns.RcodeNameError, auth, ValidationStateSecure)

	// The stranger alone proves nothing, and the answer is not used.
	agreeDenial(t, rrcache, negZone, www, dns.TypeA, dns.RcodeNameError, auth[:2], ValidationStateBogus)
}
