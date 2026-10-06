/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"strconv"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// lifeZone is the zone the entries below come from.
const lifeZone = "life.example."

// lifeSOA is lifeZone's SOA with the given TTL and MINIMUM.
func lifeSOA(t *testing.T, ttl, minimum uint32) dns.RR {
	t.Helper()
	return rrFrom(t, lifeZone+" "+strconv.Itoa(int(ttl))+" IN SOA ns."+lifeZone+" hostmaster."+lifeZone+
		" 1 7200 1800 604800 "+strconv.Itoa(int(minimum)))
}

// rrsetOf is rrs as an RRset, unsigned.
func rrsetOf(rrs ...dns.RR) *core.RRset {
	h := rrs[0].Header()
	return &core.RRset{Name: h.Name, Class: dns.ClassINET, RRtype: h.Rrtype, RRs: rrs}
}

// storeDenial caches a denial of <qname, qtype> in context ctx with the SOA
// soa and the proof records proof, each in an RRset of its own, and returns
// the lifetime the cache gave it (CachedRRset.Ttl).
func storeDenial(t *testing.T, rrcache *RRsetCacheT, qname string, qtype uint16, ctx CacheContext, soa *core.RRset, proof ...*core.RRset) time.Duration {
	t.Helper()
	auth := append([]*core.RRset{soa}, proof...)
	rcode := uint8(dns.RcodeNameError)
	if ctx == ContextNoErrNoAns {
		rcode = dns.RcodeSuccess
	}
	rrcache.Set(qname, qtype, &CachedRRset{Name: qname, RRtype: qtype, Rcode: rcode, RRset: soa, NegAuthority: auth,
		Context: ctx, State: ValidationStateInsecure, Expiration: Now().Add(24 * time.Hour)})
	c := rrcache.Peek(qname, qtype)
	if c == nil {
		t.Fatalf("%s %s: not cached", qname, dns.TypeToString[qtype])
	}
	return time.Duration(c.Ttl) * time.Second
}

// A denial is cached for its negative TTL (RFC 2308 section 5): the smaller
// of the SOA's TTL and its MINIMUM field, and no longer than any record of
// the proof served with it. What the caller passes as Expiration does not
// lengthen it. The SOA as an answer of its own lives for its own TTL.
func TestADenialLivesForItsNegativeTTL(t *testing.T) {
	useFaketime(t, faketime2010)
	const www = "www." + lifeZone
	nsec := func(ttl uint32) *core.RRset {
		return rrsetOf(rrFrom(t, lifeZone+" "+strconv.Itoa(int(ttl))+" IN NSEC zzz."+lifeZone+" SOA NS RRSIG NSEC DNSKEY"))
	}
	cases := []struct {
		name    string
		ctx     CacheContext
		soaTTL  uint32
		minimum uint32
		nsecTTL uint32
		want    time.Duration
	}{
		{"MINIMUM below the SOA's TTL, NXDOMAIN", ContextNXDOMAIN, 3600, 300, 3600, 300 * time.Second},
		{"MINIMUM below the SOA's TTL, NODATA", ContextNoErrNoAns, 3600, 300, 3600, 300 * time.Second},
		{"the SOA's TTL below MINIMUM", ContextNXDOMAIN, 200, 300, 3600, 200 * time.Second},
		{"a proof record below both", ContextNXDOMAIN, 3600, 300, 120, 120 * time.Second},
		{"MINIMUM 0: not cached", ContextNXDOMAIN, 3600, 0, 3600, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache := negCache(t)
			got := storeDenial(t, rrcache, www, dns.TypeA, c.ctx, rrsetOf(lifeSOA(t, c.soaTTL, c.minimum)), nsec(c.nsecTTL))
			if got != c.want {
				t.Errorf("lifetime %v, want %v", got, c.want)
			}
		})
	}

	t.Run("the SOA as an answer", func(t *testing.T) {
		rrcache := negCache(t)
		rrcache.Set(lifeZone, dns.TypeSOA, &CachedRRset{Name: lifeZone, RRtype: dns.TypeSOA, RRset: rrsetOf(lifeSOA(t, 3600, 300)),
			Context: ContextAnswer, State: ValidationStateInsecure})
		if c := rrcache.Get(lifeZone, dns.TypeSOA); c == nil || c.Ttl != 3600 {
			t.Errorf("the SOA itself: %+v, want it for its own TTL of 3600 s", c)
		}
	})

	t.Run("gone once its negative TTL has passed", func(t *testing.T) {
		_, path := useFaketime(t, faketime2010)
		rrcache := negCache(t)
		storeDenial(t, rrcache, www, dns.TypeA, ContextNXDOMAIN, rrsetOf(lifeSOA(t, 3600, 300)), nsec(3600))
		writeFaketime(t, path, faketime2010.Add(299*time.Second))
		if rrcache.Get(www, dns.TypeA) == nil {
			t.Fatal("gone before its negative TTL")
		}
		writeFaketime(t, path, faketime2010.Add(301*time.Second))
		if c := rrcache.Get(www, dns.TypeA); c != nil {
			t.Errorf("still cached 301 s on, expiring %v", c.Expiration)
		}
	})
}

// cache-min-ttl and cache-max-ttl bound a denial's negative TTL as any other.
func TestADenialsNegativeTTLWithinTheTTLLimits(t *testing.T) {
	useFaketime(t, faketime2010)
	const www = "www." + lifeZone
	nsec := rrsetOf(rrFrom(t, lifeZone+" 3600 IN NSEC zzz."+lifeZone+" SOA NS RRSIG NSEC DNSKEY"))
	for _, c := range []struct {
		name   string
		limits TTLLimits
		want   time.Duration
	}{
		{"cache-min-ttl raises it", TTLLimits{Min: 600}, 600 * time.Second},
		{"cache-max-ttl lowers it", TTLLimits{Max: 100}, 100 * time.Second},
	} {
		t.Run(c.name, func(t *testing.T) {
			withTTLLimits(t, c.limits)
			rrcache := negCache(t)
			if got := storeDenial(t, rrcache, www, dns.TypeA, ContextNXDOMAIN, rrsetOf(lifeSOA(t, 3600, 300)), nsec); got != c.want {
				t.Errorf("lifetime %v, want %v", got, c.want)
			}
		})
	}
}
