/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"crypto"
	"errors"
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// strayKey signs for zone with a key the resolver does not hold, as anyone
// without the zone's key can.
func strayKey(t *testing.T, zone string) *zoneKey {
	t.Helper()
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 256, Protocol: 3, Algorithm: dns.ED25519}
	p, err := k.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	return &zoneKey{zone: zone, key: k, priv: p.(crypto.Signer)}
}

// dsQuestionCounter is a fetcher that gets no answer, and counts the DS
// questions. A DNSKEY question, which validating a stray signature asks, is not
// one.
type dsQuestionCounter struct{ n int }

func (f *dsQuestionCounter) fetch(_ context.Context, _ string, qtype uint16, _ map[string]*AuthServer) (*core.RRset, error) {
	if qtype == dns.TypeDS {
		f.n++
	}
	return nil, errors.New("no answer")
}

const base32hexDigits = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

// hashStep is the base32hex hash one step after h, or before it for a negative
// step.
func hashStep(h string, step int) string {
	b := []byte(h)
	for i := len(b) - 1; i >= 0; i-- {
		switch j := strings.IndexByte(base32hexDigits, b[i]) + step; {
		case j >= len(base32hexDigits):
			b[i] = base32hexDigits[0]
		case j < 0:
			b[i] = base32hexDigits[len(base32hexDigits)-1]
		default:
			b[i] = base32hexDigits[j]
			return string(b)
		}
	}
	return string(b)
}

// nsec3In is an NSEC3 in zone matching name, or, with cover, covering it with an
// interval that holds its hash and no other.
func nsec3In(zone, name string, cover bool, flags uint8, iterations uint16, types ...uint16) *dns.NSEC3 {
	h := dns.HashName(name, dns.SHA1, iterations, "")
	owner := h
	if cover {
		owner = hashStep(h, -1)
	}
	return &dns.NSEC3{Hdr: dns.RR_Header{Name: owner + "." + zone, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
		Hash: dns.SHA1, Flags: flags, Iterations: iterations, HashLength: 20, NextDomain: hashStep(h, 1), TypeBitMap: types}
}

func apexNSEC3(zone string) *dns.NSEC3 {
	return nsec3In(zone, zone, false, 0, 0, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM)
}

// flatten lays RRsets out as a message section.
func flatten(sets ...*core.RRset) []dns.RR {
	var rrs []dns.RR
	for _, s := range sets {
		rrs = append(append(rrs, s.RRs...), s.RRSIGs...)
	}
	return rrs
}

// An NSEC3-signed parent proves a cut the NSEC3 way (RFC 5155 section 8.9): a
// matching NSEC3, or a closest encloser proof whose covering NSEC3 has Opt-Out.
func TestNSEC3ProofOfAZoneCut(t *testing.T) {
	const optOut = 1
	withRec := func(rec *dns.NSEC3, edit func(*dns.NSEC3)) *dns.NSEC3 { edit(rec); return rec }
	cases := []struct {
		name  string
		qname string
		sets  func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) []*core.RRset
		want  cutEvidence
	}{
		{"matching, NS and no DS", secKid, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, nsec3In(secZone, secKid, false, 0, 0, dns.TypeNS))}
		}, evidenceInsecureCut},
		{"matching, NS and DS", secKid, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, nsec3In(secZone, secKid, false, 0, 0, dns.TypeNS, dns.TypeDS, dns.TypeRRSIG))}
		}, evidenceNoCut},
		{"matching, no NS", secKid, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, nsec3In(secZone, secKid, false, 0, 0, dns.TypeA, dns.TypeRRSIG))}
		}, evidenceNoCut},
		{"Opt-Out span covering the name", secKid, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, apexNSEC3(secZone)), k.sign(t, nsec3In(secZone, secKid, true, optOut, 0, dns.TypeA, dns.TypeRRSIG))}
		}, evidenceInsecureCut},
		{"covering without Opt-Out", secKid, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, apexNSEC3(secZone)), k.sign(t, nsec3In(secZone, secKid, true, 0, 0, dns.TypeA, dns.TypeRRSIG))}
		}, evidenceNoCut},
		{"closest encloser with no covering NSEC3", secKid, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, apexNSEC3(secZone))}
		}, evidenceNone},
		{"Opt-Out span with no closest encloser", secKid, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, nsec3In(secZone, secKid, true, optOut, 0, dns.TypeA, dns.TypeRRSIG))}
		}, evidenceNone},
		{"closest encloser that is a delegation", "sub." + secKid, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, nsec3In(secZone, secKid, false, 0, 0, dns.TypeNS)),
				k.sign(t, nsec3In(secZone, "sub."+secKid, true, optOut, 0, dns.TypeA, dns.TypeRRSIG))}
		}, evidenceNone},
		{"unknown hash algorithm", secKid, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, withRec(nsec3In(secZone, secKid, false, 0, 0, dns.TypeNS), func(r *dns.NSEC3) { r.Hash = 2 }))}
		}, evidenceNone},
		{"unknown flags", secKid, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, withRec(nsec3In(secZone, secKid, false, 0, 0, dns.TypeNS), func(r *dns.NSEC3) { r.Flags = 2 }))}
		}, evidenceNone},
		{"iterations over the limit", secKid, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, nsec3In(secZone, secKid, false, 0, maxNSEC3Iterations+1, dns.TypeNS))}
		}, evidenceUnjudged},
		{"signed by the child", secKid, func(t *testing.T, rrcache *RRsetCacheT, _ *zoneKey) []*core.RRset {
			return []*core.RRset{newZoneKey(t, rrcache, secKid, false).sign(t, nsec3In(secZone, secKid, false, 0, 0, dns.TypeNS))}
		}, evidenceNone},
		{"signed with a stray key", secKid, func(t *testing.T, _ *RRsetCacheT, _ *zoneKey) []*core.RRset {
			return []*core.RRset{strayKey(t, secZone).sign(t, nsec3In(secZone, secKid, false, 0, 0, dns.TypeNS))}
		}, evidenceNone},
		{"unsigned", secKid, func(t *testing.T, _ *RRsetCacheT, _ *zoneKey) []*core.RRset {
			return []*core.RRset{unsigned(nsec3In(secZone, secKid, false, 0, 0, dns.TypeNS))}
		}, evidenceNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache, k := secCache(t)
			if got := rrcache.cutProof(context.Background(), c.qname, c.sets(t, rrcache, k), nil); got != c.want {
				t.Errorf("got %s, want %s", evidenceToString[got], evidenceToString[c.want])
			}
		})
	}
}

// Through the DS question: an Opt-Out span proves kid an insecure delegation,
// and the unsigned data below it is served. This was unjudged before, as every
// NSEC3 denial was.
func TestUnsignedDataBelowAnOptOutDelegationIsInsecure(t *testing.T) {
	rrcache, k := secCache(t)
	seedDSDenial(t, rrcache, secKid, k.sign(t, soaFor(t, secZone)), k.sign(t, apexNSEC3(secZone)),
		k.sign(t, nsec3In(secZone, secKid, true, 1, 0, dns.TypeA, dns.TypeRRSIG)))
	if state := validateUnsigned(t, rrcache, kidWWW+" 300 IN A 192.0.2.2", nil); state != ValidationStateInsecure {
		t.Fatalf("state %s, want insecure", ValidationStateToString[state])
	}
	if z, ok := rrcache.ZoneMap.Get(secKid); !ok || z.GetState() != ValidationStateInsecure {
		t.Errorf("the proven insecure delegation %s is not in ZoneMap as insecure", secKid)
	}
}

// A DS signed with a key the zone does not have validates Indeterminate. Below a
// secure zone that is no reason to serve unsigned data.
func TestADSSignedWithAStrayKeyIsBogus(t *testing.T) {
	rrcache, _ := secCache(t)
	ds := strayKey(t, secZone).sign(t, rrFrom(t, secKid+" 300 IN DS 4242 15 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"))
	rrcache.Set(secKid, dns.TypeDS, &CachedRRset{Name: secKid, RRtype: dns.TypeDS, RRset: ds,
		Context: ContextAnswer, State: ValidationStateIndeterminate, Expiration: time.Now().Add(5 * time.Minute)})
	if state := validateUnsigned(t, rrcache, kidWWW+" 300 IN A 192.0.2.2", nil); state != ValidationStateBogus {
		t.Fatalf("state %s, want bogus", ValidationStateToString[state])
	}
}

// Where the zone above is not held Secure, a DS whose chain cannot be followed
// stays unjudged: this is an island of trust whose parent the resolver has no
// key for, and its DS may well be signed by one.
func TestAnUnfollowableDSAboveAnIslandIsUnjudged(t *testing.T) {
	rrcache := negCache(t)
	newZoneKey(t, rrcache, secZone, false)
	rrcache.ZoneMap.Set(secZone, &Zone{ZoneName: secZone, State: ValidationStateSecure})
	ds := strayKey(t, "example.").sign(t, rrFrom(t, secZone+" 300 IN DS 4242 15 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"))
	rrcache.Set(secZone, dns.TypeDS, &CachedRRset{Name: secZone, RRtype: dns.TypeDS, RRset: ds,
		Context: ContextAnswer, State: ValidationStateIndeterminate, Expiration: time.Now().Add(5 * time.Minute)})
	if state := validateUnsigned(t, rrcache, secWWW+" 300 IN A 192.0.2.1", nil); state != ValidationStateIndeterminate {
		t.Fatalf("state %s, want indeterminate", ValidationStateToString[state])
	}
}

// The validator enters a zone as Indeterminate, or with its DS's state, when a
// step in its chain cannot be followed -- which, below a secure zone, anyone who
// can drop a DS question arranges. Unsigned data below such an entry is judged
// from the secure zone, and a zone held Bogus serves no unsigned data.
func TestAnUnjudgedEntryBelowASecureZoneDecidesNothing(t *testing.T) {
	for name, state := range map[string]ValidationState{
		"indeterminate": ValidationStateIndeterminate,
		"no verdict":    ValidationStateNone,
		"bogus":         ValidationStateBogus,
	} {
		t.Run(name, func(t *testing.T) {
			rrcache, _ := secCache(t)
			rrcache.ZoneMap.Set(secKid, &Zone{ZoneName: secKid, State: state})
			if got := validateUnsigned(t, rrcache, kidWWW+" 300 IN A 192.0.2.2", (&dsQuestionCounter{}).fetch); got != ValidationStateBogus {
				t.Errorf("state %s, want bogus", ValidationStateToString[got])
			}
		})
	}
}

// What a referral to kid without a DS makes of the child, by the state of the
// zone above it. Only a Secure parent asks the parent side anything.
func TestReferralChildStateTakesTheParentsState(t *testing.T) {
	servers := func(rrcache *RRsetCacheT, zone string) {
		rrcache.ServerMap.Set(zone, map[string]*AuthServer{"ns." + zone: NewAuthServer("ns." + zone)})
	}
	withZone := func(zone string, state ValidationState) func(*testing.T, *RRsetCacheT) {
		return func(_ *testing.T, rrcache *RRsetCacheT) {
			rrcache.ZoneMap.Set(zone, &Zone{ZoneName: zone, State: state})
			servers(rrcache, zone)
		}
	}
	belowSecure := func(state ValidationState) func(*testing.T, *RRsetCacheT) {
		return func(t *testing.T, rrcache *RRsetCacheT) {
			newZoneKey(t, rrcache, "example.", true)
			withZone("example.", ValidationStateSecure)(t, rrcache)
			withZone(secZone, state)(t, rrcache)
		}
	}
	cases := []struct {
		name      string
		setup     func(t *testing.T, rrcache *RRsetCacheT)
		want      ValidationState
		entered   bool
		questions bool
	}{
		{"no zone above, no trust anchor", func(*testing.T, *RRsetCacheT) {}, ValidationStateIndeterminate, true, false},
		{"no zone above, a trust anchor elsewhere", func(t *testing.T, rrcache *RRsetCacheT) {
			newZoneKey(t, rrcache, "other.", true)
		}, ValidationStateInsecure, true, false},
		{"insecure parent", withZone(secZone, ValidationStateInsecure), ValidationStateInsecure, true, false},
		{"indeterminate parent", withZone(secZone, ValidationStateIndeterminate), ValidationStateIndeterminate, true, false},
		{"bogus parent", withZone(secZone, ValidationStateBogus), ValidationStateNone, false, false},
		{"unjudged parent below a secure zone", belowSecure(ValidationStateNone), ValidationStateNone, false, true},
		{"indeterminate parent below a secure zone", belowSecure(ValidationStateIndeterminate), ValidationStateNone, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache := negCache(t)
			c.setup(t, rrcache)
			f := &dsQuestionCounter{}
			state, entered := rrcache.ReferralChildState(context.Background(), secKid, nil, f.fetch)
			if entered != c.entered || (entered && state != c.want) {
				t.Errorf("got %s (entered %v), want %s (entered %v)",
					ValidationStateToString[state], entered, ValidationStateToString[c.want], c.entered)
			}
			if asked := f.n > 0; asked != c.questions {
				t.Errorf("%d DS question(s) asked, want questions %v", f.n, c.questions)
			}
		})
	}
}

// Below a Secure parent the child is entered only as proven, and the parent
// side is asked for the DS only when the referral carries no proof.
func TestReferralChildStateBelowASecureParent(t *testing.T) {
	nsecAtKid := func() dns.RR { return rrFrom(t, secKid+" 300 IN NSEC "+secWWW+" NS RRSIG NSEC") }
	cases := []struct {
		name      string
		child     string
		setup     func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) []dns.RR
		ctx       context.Context
		want      ValidationState
		entered   bool
		questions bool
	}{
		{name: "the referral's NSEC proves no DS", setup: func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []dns.RR {
			return flatten(k.sign(t, nsecAtKid()))
		}, want: ValidationStateInsecure, entered: true},
		{name: "the referral's NSEC3 Opt-Out span proves no DS", setup: func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []dns.RR {
			return flatten(k.sign(t, apexNSEC3(secZone)), k.sign(t, nsec3In(secZone, secKid, true, 1, 0, dns.TypeA, dns.TypeRRSIG)))
		}, want: ValidationStateInsecure, entered: true},
		{name: "a stripped NSEC, and no answer to the DS question", setup: func(t *testing.T, _ *RRsetCacheT, _ *zoneKey) []dns.RR {
			return flatten(unsigned(nsecAtKid()))
		}, questions: true},
		{name: "an NSEC signed by the child", setup: func(t *testing.T, rrcache *RRsetCacheT, _ *zoneKey) []dns.RR {
			return flatten(newZoneKey(t, rrcache, secKid, false).sign(t, nsecAtKid()))
		}, questions: true},
		{name: "an NSEC for another name", setup: func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []dns.RR {
			return flatten(k.sign(t, rrFrom(t, secWWW+" 300 IN NSEC zzz."+secZone+" NS RRSIG NSEC")))
		}, questions: true},
		{name: "the DS question answered with a secure DS", setup: func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) []dns.RR {
			ds := k.sign(t, rrFrom(t, secKid+" 300 IN DS 4242 15 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"))
			rrcache.Set(secKid, dns.TypeDS, &CachedRRset{Name: secKid, RRtype: dns.TypeDS, RRset: ds,
				Context: ContextAnswer, State: ValidationStateSecure, Expiration: time.Now().Add(5 * time.Minute)})
			return nil
		}, want: ValidationStateSecure, entered: true},
		{name: "the DS question answered with a proof of none", setup: func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) []dns.RR {
			seedDSDenial(t, rrcache, secKid, k.sign(t, soaFor(t, secZone)), k.sign(t, nsecAtKid()))
			return nil
		}, want: ValidationStateInsecure, entered: true},
		{name: "the DS question answered with a stray-key denial", setup: func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) []dns.RR {
			seedDSDenial(t, rrcache, secKid, k.sign(t, soaFor(t, secZone)), strayKey(t, secZone).sign(t, nsecAtKid()))
			return nil
		}},
		{name: "a stub or forward zone in between", child: "sub." + secKid, setup: func(t *testing.T, rrcache *RRsetCacheT, _ *zoneKey) []dns.RR {
			rrcache.ConfiguredZone = func(name string) bool { return core.EqualNames(name, secKid) }
			return nil
		}, want: ValidationStateInsecure, entered: true},
		{name: "asked from inside another referral's questions", ctx: context.WithValue(context.Background(), dsProofKey{}, true),
			setup: func(*testing.T, *RRsetCacheT, *zoneKey) []dns.RR { return nil }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache, k := secCache(t)
			authority := c.setup(t, rrcache, k)
			child, ctx := c.child, c.ctx
			if child == "" {
				child = secKid
			}
			if ctx == nil {
				ctx = context.Background()
			}
			f := &dsQuestionCounter{}
			state, entered := rrcache.ReferralChildState(ctx, child, authority, f.fetch)
			if entered != c.entered || (entered && state != c.want) {
				t.Errorf("got %s (entered %v), want %s (entered %v)",
					ValidationStateToString[state], entered, ValidationStateToString[c.want], c.entered)
			}
			if asked := f.n > 0; asked != c.questions {
				t.Errorf("%d DS question(s) asked, want questions %v", f.n, c.questions)
			}
		})
	}
}
