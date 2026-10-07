/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * How long a denial the resolver caches lives, and the TTL it is served with.
 */
package tdns

import (
	"crypto"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// lifetimeSigner returns a function that signs an RRset with a key the
// resolver holds as a Secure trust anchor for zone, with a signature valid
// from an hour before now until until. The RRSIG carries the RRset's TTL, as
// one in a response does.
func lifetimeSigner(t *testing.T, imr *Imr, zone string) func(set []dns.RR, until time.Time) []dns.RR {
	t.Helper()
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: 257, Protocol: 3, Algorithm: dns.ED25519}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	imr.Cache.DnskeyCache.Set(zone, key.KeyTag(), &cache.CachedDnskeyRRset{Name: zone, Keyid: key.KeyTag(),
		State: cache.ValidationStateSecure, TrustAnchor: true, Dnskey: *key, Expiration: cache.Now().Add(30 * 24 * time.Hour)})
	return func(set []dns.RR, until time.Time) []dns.RR {
		t.Helper()
		h := set[0].Header()
		sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: h.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: h.Ttl},
			TypeCovered: h.Rrtype, Algorithm: dns.ED25519, Labels: uint8(dns.CountLabel(h.Name)), OrigTtl: h.Ttl,
			Inception: uint32(cache.Now().Add(-time.Hour).Unix()), Expiration: uint32(until.Unix()),
			KeyTag: key.KeyTag(), SignerName: zone}
		if err := sig.Sign(priv.(crypto.Signer), set); err != nil {
			t.Fatal(err)
		}
		return append(append([]dns.RR{}, set...), sig)
	}
}

// lifetimeReply is an authoritative negative answer to <qname, qtype>.
func lifetimeReply(qname string, qtype uint16, rcode int, ns []dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.Response = true
	m.Authoritative = true
	m.Rcode = rcode
	m.Ns = ns
	return m
}

// A denial is cached for its negative TTL, the smaller of the SOA's TTL and
// its MINIMUM (RFC 2308 section 5), not for the SOA's TTL. handleNegative
// computed it, and the cache used to recompute the lifetime from the SOA's
// TTL alone. The SOA, cached as an answer of its own, keeps its TTL.
func TestHandleNegativeCachesForTheNegativeTTL(t *testing.T) {
	const zone = "signed.example."
	_, imr, _ := validatorScanner(t)
	sign := lifetimeSigner(t, imr, zone)
	week := cache.Now().Add(7 * 24 * time.Hour)
	soa := sign(rrs(t, zone+" 3600 IN SOA ns."+zone+" h."+zone+" 7 3600 600 604800 300"), week)
	apex := sign(rrs(t, zone+" 3600 IN NSEC zzz."+zone+" SOA NS RRSIG NSEC DNSKEY"), week)
	for _, c := range []struct {
		qname string
		qtype uint16
		rcode int
	}{
		{"nope." + zone, dns.TypeA, dns.RcodeNameError},
		{zone, dns.TypeTXT, dns.RcodeSuccess},
	} {
		ns := append(append([]dns.RR{}, soa...), apex...)
		if _, _, ok := imr.handleNegative(c.qname, c.qtype, lifetimeReply(c.qname, c.qtype, c.rcode, ns), core.TransportDo53, zone); !ok {
			t.Fatalf("%s %s: not used", c.qname, dns.TypeToString[c.qtype])
		}
		e := imr.Cache.Get(c.qname, c.qtype)
		if e == nil {
			t.Fatalf("%s %s: not cached", c.qname, dns.TypeToString[c.qtype])
		}
		if e.Ttl != 300 {
			t.Errorf("%s %s: cached for %d s, want 300 (the SOA's MINIMUM)", c.qname, dns.TypeToString[c.qtype], e.Ttl)
		}
	}
	if s := imr.Cache.Get(zone, dns.TypeSOA); s == nil || s.Ttl != 3600 {
		t.Errorf("the SOA itself: %+v, want it cached for its TTL of 3600 s", s)
	}
}
