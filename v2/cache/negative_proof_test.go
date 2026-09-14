/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"crypto"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// negZone is the zone every denial below comes from.
const negZone = "neg.example."

func negSOA(t *testing.T) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(negZone + " 300 IN SOA ns." + negZone + " hostmaster." + negZone + " 1 7200 1800 604800 300")
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

// negNSEC denies www.neg.example. and the wildcard: the apex NSEC points past both.
func negNSEC(t *testing.T) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(negZone + " 300 IN NSEC zzz." + negZone + " SOA NS RRSIG NSEC DNSKEY")
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

// negSigner is a key the cache holds as Secure for negZone, so an RRset it signs
// validates Secure for real.
type negSigner struct {
	key  *dns.DNSKEY
	priv crypto.Signer
}

func newNegSigner(t *testing.T, rrcache *RRsetCacheT) *negSigner {
	t.Helper()
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: negZone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 256, Protocol: 3, Algorithm: dns.ED25519}
	p, err := k.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	rrcache.DnskeyCache.Set(negZone, k.KeyTag(), &CachedDnskeyRRset{Name: negZone, Keyid: k.KeyTag(),
		State: ValidationStateSecure, Dnskey: *k, Expiration: time.Now().Add(time.Hour)})
	return &negSigner{key: k, priv: p.(crypto.Signer)}
}

func (s *negSigner) sign(t *testing.T, rrs ...dns.RR) *core.RRset {
	t.Helper()
	sig := &dns.RRSIG{Algorithm: dns.ED25519, KeyTag: s.key.KeyTag(), SignerName: negZone,
		Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
		Expiration: uint32(time.Now().Add(time.Hour).Unix())}
	if err := sig.Sign(s.priv, rrs); err != nil {
		t.Fatal(err)
	}
	h := rrs[0].Header()
	return &core.RRset{Name: h.Name, Class: dns.ClassINET, RRtype: h.Rrtype, RRs: rrs, RRSIGs: []dns.RR{sig}}
}

func unsigned(rrs ...dns.RR) *core.RRset {
	h := rrs[0].Header()
	return &core.RRset{Name: h.Name, Class: dns.ClassINET, RRtype: h.Rrtype, RRs: rrs}
}

func negCache(t *testing.T) *RRsetCacheT {
	t.Helper()
	rrcache := testCache(t)
	rrcache.DnskeyCache = NewDnskeyCache() // not the process-wide one
	return rrcache
}

// The baseline the fixes must not break: a denial whose records validated is a
// secure denial.
func TestNegativeProofFromValidatedRecordsIsSecure(t *testing.T) {
	rrcache := negCache(t)
	s := newNegSigner(t, rrcache)
	auth := []*core.RRset{s.sign(t, negSOA(t)), s.sign(t, negNSEC(t))}

	state, _, err := rrcache.ValidateNegativeResponse(context.Background(), "www."+negZone, dns.TypeA, dns.RcodeNameError, auth, nil)
	if err != nil {
		t.Fatalf("ValidateNegativeResponse: %v", err)
	}
	if state != ValidationStateSecure {
		t.Fatalf("state %s, want secure", ValidationStateToString[state])
	}
}

// A denial from a zone the resolver holds as insecure is served, but it proves
// nothing. It used to fall through to the NSEC coverage checks and come back
// Secure -- and the answer went out with AD from a zone with no chain of trust.
func TestNegativeProofFromAnInsecureZoneIsInsecure(t *testing.T) {
	rrcache := negCache(t)
	rrcache.ZoneMap.Set(negZone, &Zone{ZoneName: negZone, State: ValidationStateInsecure})
	// Signed by a key nobody vouches for, the way an island of trust is: the
	// RRSIGs are there, the chain above them is not.
	s := newNegSigner(t, rrcache)
	auth := []*core.RRset{s.sign(t, negSOA(t)), s.sign(t, negNSEC(t))}

	state, _, err := rrcache.ValidateNegativeResponse(context.Background(), "www."+negZone, dns.TypeA, dns.RcodeNameError, auth, nil)
	if err != nil {
		t.Fatalf("ValidateNegativeResponse: %v", err)
	}
	if state != ValidationStateInsecure {
		t.Fatalf("state %s, want insecure: a denial from an insecure zone must not earn AD", ValidationStateToString[state])
	}
}

// An unsigned NSEC placed beside a validly signed SOA used to satisfy the
// coverage checks, which looked at every NSEC in the authority section: a forged
// denial, answered with AD.
func TestAnUnsignedNSECBesideASignedSOAProvesNothing(t *testing.T) {
	rrcache := negCache(t)
	s := newNegSigner(t, rrcache)
	auth := []*core.RRset{s.sign(t, negSOA(t)), unsigned(negNSEC(t))}

	state, _, _ := rrcache.ValidateNegativeResponse(context.Background(), "www."+negZone, dns.TypeA, dns.RcodeNameError, auth, nil)
	if state == ValidationStateSecure {
		t.Fatal("an unsigned NSEC was accepted as a secure proof of non-existence")
	}
}

// In a zone known to be signed, a denial with every signature stripped is bogus,
// not an insecure answer to pass along.
func TestAStrippedDenialFromASecureZoneIsBogus(t *testing.T) {
	rrcache := negCache(t)
	rrcache.ZoneMap.Set(negZone, &Zone{ZoneName: negZone, State: ValidationStateSecure})
	auth := []*core.RRset{unsigned(negSOA(t)), unsigned(negNSEC(t))}

	state, _, err := rrcache.ValidateNegativeResponse(context.Background(), "www."+negZone, dns.TypeA, dns.RcodeNameError, auth, nil)
	if err != nil {
		t.Fatalf("ValidateNegativeResponse: %v", err)
	}
	if state != ValidationStateBogus {
		t.Fatalf("state %s, want bogus", ValidationStateToString[state])
	}
}
