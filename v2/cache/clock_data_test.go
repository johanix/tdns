/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// On a clock set to 2010, a record cached with TTL 300 is stamped and served
// in 2010, and is gone once the clock moves 301 s on. A backoff set at the same
// moment runs on real time, and is still in force.
func TestCacheExpiryFollowsTheTestClock(t *testing.T) {
	_, path := useFaketime(t, faketime2010)
	rrcache := negCache(t)
	rr := rrFrom(t, secWWW+" 300 IN A 192.0.2.1")
	rrcache.Set(secWWW, dns.TypeA, &CachedRRset{Name: secWWW, RRtype: dns.TypeA, Context: ContextAnswer,
		State: ValidationStateInsecure, RRset: &core.RRset{Name: secWWW, Class: dns.ClassINET, RRtype: dns.TypeA, RRs: []dns.RR{rr}}})

	c := rrcache.Get(secWWW, dns.TypeA)
	if c == nil {
		t.Fatalf("%s A: not cached", secWWW)
	}
	if !near(c.Expiration, faketime2010.Add(300*time.Second), 2*time.Second) {
		t.Errorf("expiration %v, want about %v: stamped in data time", c.Expiration, faketime2010.Add(300*time.Second))
	}
	if ttl := c.RemainingTTL(Now()); ttl < 297 || ttl > 300 {
		t.Errorf("served TTL %d, want about 300", ttl)
	}

	z := &Zone{ZoneName: secZone}
	z.RecordZoneAddressFailureForRcode("192.0.2.53", core.TransportDo53, dns.RcodeRefused, false)
	if z.IsZoneAddrXportAvailable("192.0.2.53", core.TransportDo53) {
		t.Fatal("test setup: a REFUSED server is available at once")
	}

	writeFaketime(t, path, faketime2010.Add(301*time.Second))
	if c := rrcache.Get(secWWW, dns.TypeA); c != nil {
		t.Errorf("%s A still cached 301 s on in data time, expiring %v", secWWW, c.Expiration)
	}
	if z.IsZoneAddrXportAvailable("192.0.2.53", core.TransportDo53) {
		t.Error("the backoff was lifted by a jump of the test clock: backoffs run on real time")
	}
}

// signAt signs rrs with a signature valid from inception to expiration.
func (k *zoneKey) signAt(t *testing.T, inception, expiration time.Time, rrs ...dns.RR) *core.RRset {
	t.Helper()
	sig := &dns.RRSIG{Algorithm: dns.ED25519, KeyTag: k.key.KeyTag(), SignerName: k.zone,
		Inception: uint32(inception.Unix()), Expiration: uint32(expiration.Unix())}
	if err := sig.Sign(k.priv, rrs); err != nil {
		t.Fatal(err)
	}
	h := rrs[0].Header()
	return &core.RRset{Name: h.Name, Class: dns.ClassINET, RRtype: h.Rrtype, RRs: rrs, RRSIGs: []dns.RR{sig}}
}

// A signature from 2010 validates on a 2010 clock, and the TTL it caps is its
// remaining lifetime at that time: not zero, and not a wrapped uint32. On real
// time the same signature has long expired.
func TestA2010SignatureValidatesOnA2010Clock(t *testing.T) {
	sign := func(k *zoneKey) *core.RRset {
		return k.signAt(t, faketime2010.Add(-time.Hour), faketime2010.Add(10*time.Minute),
			rrFrom(t, secWWW+" 3600 IN A 192.0.2.1"))
	}

	rrcache, k := secCache(t)
	if state, err := rrcache.ValidateRRset(context.Background(), sign(k), nil); err != nil || state != ValidationStateBogus {
		t.Fatalf("on real time: %s, %v; want bogus, the signature expired in 2010", ValidationStateToString[state], err)
	}

	useFaketime(t, faketime2010)
	rrcache, k = secCache(t)
	rrset := sign(k)
	state, err := rrcache.ValidateRRset(context.Background(), rrset, nil)
	if err != nil || state != ValidationStateSecure {
		t.Fatalf("on a 2010 clock: %s, %v; want secure", ValidationStateToString[state], err)
	}
	if ttl := rrset.RRs[0].Header().Ttl; ttl > 600 || ttl < 590 {
		t.Errorf("TTL %d, want the signature's remaining lifetime, about 600", ttl)
	}
}
