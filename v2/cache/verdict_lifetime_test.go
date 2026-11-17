/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A verdict reached after an entry was stored bounds its life as it would
// have, had it been reached then: an entry made Secure lives no longer than
// its signatures allow, counted from when it was stored. A verdict never
// extends an entry's life. The caller's copy follows the stored entry.
func TestAVerdictReachedLaterShortensAnEntryNeverExtendsIt(t *testing.T) {
	_, path := useFaketime(t, faketime2010)
	rrcache := negCache(t)
	k := newZoneKey(t, rrcache, secZone, true)
	soa := k.signAt(t, sigFrom, inAWeek, rrFrom(t, secZone+" 3600 IN SOA ns."+secZone+" h."+secZone+" 1 7200 1800 604800 3600"))
	proof := k.signAt(t, sigFrom, in60s, rrFrom(t, secZone+" 3600 IN NSEC zzz."+secZone+" SOA NS RRSIG NSEC DNSKEY"))
	const nx = "nx." + secZone
	rrcache.Set(nx, dns.TypeA, &CachedRRset{Name: nx, RRtype: dns.TypeA, Rcode: dns.RcodeNameError, RRset: soa,
		NegAuthority: []*core.RRset{soa, proof}, Context: ContextNXDOMAIN, State: ValidationStateIndeterminate})
	judged := rrcache.Get(nx, dns.TypeA)
	if judged.Ttl != 3600 {
		t.Fatalf("Indeterminate, cached for %d s, want its negative TTL of 3600", judged.Ttl)
	}
	storedAt := judged.Expiration.Add(-time.Hour)

	writeFaketime(t, path, faketime2010.Add(10*time.Second))
	if !rrcache.SetVerdict(judged, ValidationStateSecure, 0, "") {
		t.Fatal("the verdict was not stored")
	}
	c := rrcache.Get(nx, dns.TypeA)
	if c == nil || c.State != ValidationStateSecure {
		t.Fatalf("after the verdict: %+v, want Secure", c)
	}
	if limit := storedAt.Add(61 * time.Second); c.Expiration.After(limit) {
		t.Errorf("Secure, it expires at %v, want no later than its proof's signatures, %v", c.Expiration, limit)
	}
	if !judged.Expiration.Equal(c.Expiration) || judged.Ttl != c.Ttl {
		t.Errorf("the caller's copy expires at %v (%d s), the entry at %v (%d s)", judged.Expiration, judged.Ttl, c.Expiration, c.Ttl)
	}

	// Indeterminate again: the life the signatures left it is not given back.
	capped := c.Expiration
	if !rrcache.SetVerdict(c, ValidationStateIndeterminate, 0, "") {
		t.Fatal("the second verdict was not stored")
	}
	if c := rrcache.Get(nx, dns.TypeA); c == nil || !c.Expiration.Equal(capped) {
		t.Errorf("after a verdict that is not Secure: %+v, want the expiry left at %v", c, capped)
	}

	writeFaketime(t, path, faketime2010.Add(61*time.Second))
	if c := rrcache.Get(nx, dns.TypeA); c != nil {
		t.Errorf("still cached 61 s on, expiring %v", c.Expiration)
	}
}
