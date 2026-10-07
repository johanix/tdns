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

// An entry read from the cache, changed, and stored again keeps its expiry:
// storing it again does not give it a new life. Set used to compute the
// expiry afresh from the TTLs, and an entry stamped on every use was never
// let go. Fresh data, in an RRset of its own, is given its full lifetime.
func TestStoringAnEntryAgainKeepsItsExpiry(t *testing.T) {
	_, path := useFaketime(t, faketime2010)
	rrcache := negCache(t)
	set := func() *core.RRset { return rrsetOf(rrFrom(t, secWWW+" 300 IN A 192.0.2.1")) }
	rrcache.Set(secWWW, dns.TypeA, &CachedRRset{Name: secWWW, RRtype: dns.TypeA, RRset: set(), Context: ContextAnswer,
		State: ValidationStateInsecure})
	first := rrcache.Get(secWWW, dns.TypeA).Expiration

	writeFaketime(t, path, faketime2010.Add(200*time.Second))
	c := rrcache.Get(secWWW, dns.TypeA)
	c.EDECode, c.EDEText = 9, "a stamp"
	rrcache.Set(secWWW, dns.TypeA, c)
	if got := rrcache.Get(secWWW, dns.TypeA); got == nil || !got.Expiration.Equal(first) || got.EDECode != 9 {
		t.Errorf("stored again 200 s on: %+v, want the stamp and the expiry left at %v", got, first)
	}

	rrcache.Set(secWWW, dns.TypeA, &CachedRRset{Name: secWWW, RRtype: dns.TypeA, RRset: set(), Context: ContextAnswer,
		State: ValidationStateInsecure})
	if got := rrcache.Get(secWWW, dns.TypeA); got == nil || !got.Expiration.After(first) {
		t.Errorf("fresh data 200 s on: %+v, want a new life past %v", got, first)
	}
}

// ValidateDNSKEYs marks a DNSKEY RRset no DS matches Bogus, and stamps EDE 9
// on the cached entry. MarkRRsetBogus keeps the entry's expiry (#694); the
// stamp, stored with Set, used to give it a new life on every failed
// validation, and the stale RRset was never let go.
func TestTheEDEStampOnABogusDNSKEYRRsetKeepsItsExpiry(t *testing.T) {
	_, path := useFaketime(t, faketime2010)
	rrcache := negCache(t)
	const zone = "kid.example."
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 257, Protocol: 3, Algorithm: dns.ED25519, PublicKey: "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="}
	other := &dns.DNSKEY{Hdr: key.Hdr, Flags: 257, Protocol: 3, Algorithm: dns.ED25519}
	if _, err := other.Generate(256); err != nil {
		t.Fatal(err)
	}
	// A Secure DS for a key the RRset does not hold.
	rrcache.Set(zone, dns.TypeDS, &CachedRRset{Name: zone, RRtype: dns.TypeDS, RRset: rrsetOf(other.ToDS(dns.SHA256)),
		Context: ContextAnswer, State: ValidationStateSecure})
	keys := rrsetOf(key)

	validate := func() {
		t.Helper()
		if got, _ := rrcache.ValidateDNSKEYs(context.Background(), keys, nil); got != ValidationStateBogus {
			t.Fatalf("ValidateDNSKEYs: %s, want bogus", ValidationStateToString[got])
		}
	}
	validate()
	first := rrcache.Peek(zone, dns.TypeDNSKEY)
	if first == nil || first.EDECode != 9 {
		t.Fatalf("the DNSKEY RRset is not cached with EDE 9: %+v", first)
	}

	writeFaketime(t, path, faketime2010.Add(200*time.Second))
	validate()
	if again := rrcache.Peek(zone, dns.TypeDNSKEY); again == nil || again.Expiration.After(first.Expiration) {
		t.Errorf("validated again 200 s on: expires %v, want no later than %v", again.Expiration, first.Expiration)
	}

	writeFaketime(t, path, faketime2010.Add(301*time.Second))
	if c := rrcache.Get(zone, dns.TypeDNSKEY); c != nil {
		t.Errorf("still cached 301 s on, expiring %v", c.Expiration)
	}
}
