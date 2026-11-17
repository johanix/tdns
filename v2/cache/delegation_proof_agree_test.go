/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// ProveDelegation is the reading cutProof makes of the records that validate.
// On the same records, the chain walk (which checks signatures with keys of
// its own and hands ProveDelegation what verified) and the resolver must come
// to the same answer.
func TestProveDelegationAgreesWithCutProof(t *testing.T) {
	const optOut = 1
	nsec := func(owner, next string, types ...uint16) *dns.NSEC {
		return &dns.NSEC{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
			NextDomain: next, TypeBitMap: types}
	}
	type setsFunc func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) []*core.RRset
	signed := func(rrs ...func() dns.RR) setsFunc {
		return func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			var sets []*core.RRset
			for _, rr := range rrs {
				sets = append(sets, k.sign(t, rr()))
			}
			return sets
		}
	}
	rr := func(r dns.RR) func() dns.RR { return func() dns.RR { return r } }
	cases := []struct {
		name  string
		qname string
		sets  setsFunc
		want  DelegationProof
	}{
		{"NSEC, NS and no DS", secKid, signed(rr(nsec(secKid, "z."+secZone, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC))), DelegationInsecure},
		{"NSEC, NS and DS", secKid, signed(rr(nsec(secKid, "z."+secZone, dns.TypeNS, dns.TypeDS, dns.TypeRRSIG, dns.TypeNSEC))), DelegationNone},
		{"NSEC, no NS", secKid, signed(rr(nsec(secKid, "z."+secZone, dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC))), DelegationNone},
		{"NSEC, NS and SOA", secKid, signed(rr(nsec(secKid, "z."+secZone, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC))), DelegationNone},
		{"NSEC covering the name", secKid, signed(rr(nsec("a."+secZone, "z."+secZone, dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC))), DelegationUnproven},
		{"NSEC3 match, NS and no DS", secKid, signed(rr(nsec3In(secZone, secKid, false, 0, 0, dns.TypeNS))), DelegationInsecure},
		{"NSEC3 match, NS and DS", secKid, signed(rr(nsec3In(secZone, secKid, false, 0, 0, dns.TypeNS, dns.TypeDS, dns.TypeRRSIG))), DelegationNone},
		{"NSEC3 match, no NS", secKid, signed(rr(nsec3In(secZone, secKid, false, 0, 0, dns.TypeA, dns.TypeRRSIG))), DelegationNone},
		{"NSEC3 Opt-Out cover", secKid, signed(rr(apexNSEC3(secZone)), rr(nsec3In(secZone, secKid, true, optOut, 0, dns.TypeA, dns.TypeRRSIG))), DelegationInsecure},
		{"NSEC3 cover without Opt-Out", secKid, signed(rr(apexNSEC3(secZone)), rr(nsec3In(secZone, secKid, true, 0, 0, dns.TypeA, dns.TypeRRSIG))), DelegationNone},
		{"NSEC3 closest encloser, no cover", secKid, signed(rr(apexNSEC3(secZone))), DelegationUnproven},
		{"NSEC3 closest encloser that is a delegation", "sub." + secKid, signed(rr(nsec3In(secZone, secKid, false, 0, 0, dns.TypeNS)),
			rr(nsec3In(secZone, "sub."+secKid, true, optOut, 0, dns.TypeA, dns.TypeRRSIG))), DelegationUnproven},
		{"NSEC3 over the iteration limit", secKid, signed(rr(nsec3In(secZone, secKid, false, 0, DefaultNSEC3MaxIterations+1, dns.TypeNS))), DelegationUnjudged},
		{"NSEC3 proof that runs out of hashes", strings.Repeat("a.", 110) + secZone, signed(
			rr(synthNSEC3(secZone, secZone, false, 0, 0, "", dns.TypeNS, dns.TypeSOA)),
			rr(synthNSEC3(secZone, secZone, false, 0, 0, "00", dns.TypeNS, dns.TypeSOA)),
			rr(synthNSEC3(secZone, secZone, false, 0, 0, "0000", dns.TypeNS, dns.TypeSOA))), DelegationUnjudged},
		{"signed by the child", secKid, func(t *testing.T, rrcache *RRsetCacheT, _ *zoneKey) []*core.RRset {
			return []*core.RRset{newZoneKey(t, rrcache, secKid, false).sign(t, nsec3In(secZone, secKid, false, 0, 0, dns.TypeNS))}
		}, DelegationUnproven},
		{"signed with a stray key", secKid, func(t *testing.T, _ *RRsetCacheT, _ *zoneKey) []*core.RRset {
			return []*core.RRset{strayKey(t, secZone).sign(t, nsec3In(secZone, secKid, false, 0, 0, dns.TypeNS))}
		}, DelegationUnproven},
		{"unsigned", secKid, func(t *testing.T, _ *RRsetCacheT, _ *zoneKey) []*core.RRset {
			return []*core.RRset{unsigned(nsec(secKid, "z."+secZone, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC))}
		}, DelegationUnproven},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache, k := secCache(t)
			sets := c.sets(t, rrcache, k)

			// The chain walk's view: the records whose signature by the zone
			// verifies.
			var nsecs []*dns.NSEC
			var nsec3s []*dns.NSEC3
			for _, set := range sets {
				zs := signedBy(set, secZone)
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
			walk := ProveDelegation(c.qname, secZone, nsecs, nsec3s)
			resolver := delegationProofOf(rrcache.cutProof(context.Background(), c.qname, sets, nil))
			if walk != c.want {
				t.Errorf("ProveDelegation: %s, want %s", walk, c.want)
			}
			if resolver != walk {
				t.Errorf("cutProof: %s, ProveDelegation: %s", resolver, walk)
			}
		})
	}
}

// ProveDelegation reads only names below the zone the records are from.
func TestProveDelegationOutsideTheZone(t *testing.T) {
	rec := nsec3In(secZone, secKid, false, 0, 0, dns.TypeNS)
	for _, name := range []string{secZone, "example.", "kid.other.example."} {
		if got := ProveDelegation(name, secZone, nil, []*dns.NSEC3{rec}); got != DelegationUnproven {
			t.Errorf("%s: %s, want unproven", name, got)
		}
	}
}
