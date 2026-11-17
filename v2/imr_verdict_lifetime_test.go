/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"sync/atomic"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
)

// A denial cached Indeterminate -- its signer's key could not be followed --
// lives for its negative TTL: nothing authenticated it. Validated again as it
// is served, once the key can be followed, it is Secure, and from then on it
// lives no longer than the signatures over its proof allow, counted from when
// it was cached: here 60 s, not the hour of its negative TTL. The verdict
// shortens its life; it never extends it. On a 2010 data clock.
func TestADenialValidatedLaterLivesNoLongerThanItsSignatures(t *testing.T) {
	path := startTestDataClock(t, faketime2010)
	const nx = "nx." + ltZone
	from, week, in60s := faketime2010.Add(-time.Hour), faketime2010.Add(7*24*time.Hour), faketime2010.Add(60*time.Second)
	ksk, zsk := newFwdSecKey(t, ltZone), newFwdSecKey(t, ltZone)
	soa := fwdSecRR(t, ltZone+" 3600 IN SOA ns."+ltZone+" h."+ltZone+" 1 7200 1800 604800 3600")
	denial := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}
	denial.Ns = append(zsk.signAt(t, from, week, soa),
		zsk.signAt(t, from, in60s, fwdSecRR(t, ltZone+" 3600 IN NSEC zzz."+ltZone+" SOA NS RRSIG NSEC DNSKEY"))...)
	short := dns.Copy(ksk.dnskey).(*dns.DNSKEY)
	short.Hdr.Ttl = 1
	withoutZSK := &dns.Msg{Answer: ksk.signAt(t, from, week, short)}
	withZSK := &dns.Msg{Answer: ksk.signAt(t, from, week, dns.Copy(ksk.dnskey), dns.Copy(zsk.dnskey))}
	var keysBack atomic.Bool
	var asked atomic.Int32
	addr, port := startForwardUpstreamFunc(t, func(qname string, qtype uint16) *dns.Msg {
		switch {
		case qname == nx && qtype == dns.TypeA:
			asked.Add(1)
			return denial
		case qname == ltZone && qtype == dns.TypeDNSKEY && keysBack.Load():
			return withZSK
		case qname == ltZone && qtype == dns.TypeDNSKEY:
			return withoutZSK
		}
		return nil
	})
	imr := newForwardTestImr(t, []ImrForwardConf{{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}}})
	imr.Cache.DnskeyCache = cache.NewDnskeyCache() // not the process-wide one
	imr.DnskeyCache = imr.Cache.DnskeyCache
	if err := imr.Cache.PrimeFromHintsOnly(""); err != nil {
		t.Fatalf("PrimeFromHintsOnly: %v", err)
	}
	imr.addDirectDNSKEYTrustAnchors(map[string][]*dns.DNSKEY{ltZone: {ksk.dnskey}})

	askLifetime(t, imr, nx, dns.TypeA)
	c := imr.Cache.Get(nx, dns.TypeA)
	if c == nil || c.State != cache.ValidationStateIndeterminate {
		t.Fatalf("the denial is not cached as indeterminate: %+v", c)
	}
	if c.Ttl != 3600 {
		t.Errorf("cached Indeterminate for %d s, want its negative TTL of 3600", c.Ttl)
	}
	cachedAt := c.Expiration.Add(-time.Duration(c.Ttl) * time.Second)

	keysBack.Store(true)
	writeFaketimeFile(t, path, faketime2010.Add(10*time.Second)) // the DNSKEY RRset without the ZSK has expired
	m := askLifetime(t, imr, nx, dns.TypeA)
	if m.Rcode != dns.RcodeNameError || !m.AuthenticatedData {
		t.Fatalf("the ZSK known: %s AD=%v, want NXDOMAIN with AD", dns.RcodeToString[m.Rcode], m.AuthenticatedData)
	}
	if ttl := servedTTL(m); ttl > 50 {
		t.Errorf("served with TTL %d, want at most the 50 s its proof's signatures have left", ttl)
	}
	c = imr.Cache.Get(nx, dns.TypeA)
	if c == nil || c.State != cache.ValidationStateSecure {
		t.Fatalf("the cached denial was not updated to secure: %+v", c)
	}
	if limit := cachedAt.Add(61 * time.Second); c.Expiration.After(limit) {
		t.Errorf("Secure, it expires at %v, want no later than its proof's signatures, %v", c.Expiration, limit)
	}

	writeFaketimeFile(t, path, faketime2010.Add(61*time.Second))
	askLifetime(t, imr, nx, dns.TypeA)
	if n := asked.Load(); n != 2 {
		t.Errorf("61 s on: asked upstream %d times, want 2", n)
	}
}
