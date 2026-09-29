/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"io"
	"log"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A configured stub's server map is configuration, not something learned from
// a referral, and nothing re-learns it: dropped, the stub is gone until a
// restart, while the stub table still keeps its names from any forward above
// it (#832). Each of the three places that drop server maps -- a domain flush,
// a full flush and the expiry of a zone's NS RRset -- must leave it alone, and
// must still drop a learned one beside it.
func TestConfiguredStubServerMapIsKept(t *testing.T) {
	const (
		stub    = "kid.parent.example."
		learned = "other.parent.example."
	)
	mk := func(t *testing.T) *RRsetCacheT {
		t.Helper()
		c := NewRRsetCache(log.New(io.Discard, "", 0), false, false)
		c.StubZone = func(name string) bool { return core.EqualNames(name, stub) }
		if err := c.AddStub(stub, []AuthServer{{Name: "ns." + stub, Addrs: []string{"192.0.2.53"}}}); err != nil {
			t.Fatalf("AddStub: %v", err)
		}
		srv := c.GetOrCreateAuthServer("ns." + learned)
		srv.AddAddr("192.0.2.54")
		if err := c.AddServers(learned, map[string]*AuthServer{"ns." + learned: srv}); err != nil {
			t.Fatalf("AddServers: %v", err)
		}
		// Something cached in each zone, so that a flush of it removes
		// entries: FlushDomain drops server maps only when it removed any.
		for _, zone := range []string{stub, learned} {
			rr, err := dns.NewRR(zone + " 3600 IN DNSKEY 257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=")
			if err != nil {
				t.Fatalf("bad test record: %v", err)
			}
			c.Set(zone, dns.TypeDNSKEY, &CachedRRset{Name: zone, RRtype: dns.TypeDNSKEY, Context: ContextAnswer,
				RRset: &core.RRset{Name: zone, RRtype: dns.TypeDNSKEY, RRs: []dns.RR{rr}}, Expiration: time.Now().Add(time.Hour)})
		}
		return c
	}
	requireMaps := func(t *testing.T, c *RRsetCacheT, what string) {
		t.Helper()
		if m, ok := c.ServerMap.Get(stub); !ok || len(m) == 0 {
			t.Errorf("%s dropped the configured stub's server map", what)
		}
		if _, ok := c.ServerMap.Get(learned); ok {
			t.Errorf("%s kept a learned server map", what)
		}
	}

	t.Run("FlushDomain", func(t *testing.T) {
		c := mk(t)
		if _, err := c.FlushDomain("parent.example.", false); err != nil {
			t.Fatalf("FlushDomain: %v", err)
		}
		if c.Get(stub, dns.TypeDNSKEY) != nil {
			t.Error("the stub zone's cached data survived the flush; only its server map is configuration")
		}
		requireMaps(t, c, "a domain flush")
	})

	t.Run("FlushAll", func(t *testing.T) {
		c := mk(t)
		c.FlushAll()
		requireMaps(t, c, "a full flush")
	})

	t.Run("NS expiry", func(t *testing.T) {
		c := mk(t)
		for _, zone := range []string{stub, learned} {
			rr, err := dns.NewRR(zone + " 60 IN NS ns." + zone)
			if err != nil {
				t.Fatalf("bad test record: %v", err)
			}
			// Stored as it is when its time is up: Set would compute the
			// expiration from the TTL.
			c.RRsets.Set(rrsetKey(zone, dns.TypeNS), CachedRRset{Name: zone, RRtype: dns.TypeNS, Context: ContextAnswer,
				RRset: &core.RRset{Name: zone, RRtype: dns.TypeNS, RRs: []dns.RR{rr}}, Expiration: time.Now().Add(-time.Second)})
			if c.Get(zone, dns.TypeNS) != nil {
				t.Fatalf("an expired NS RRset for %s was served", zone)
			}
		}
		requireMaps(t, c, "the expiry of the zone's NS RRset")
	})

	t.Run("no resolver attached", func(t *testing.T) {
		c := mk(t)
		c.StubZone = nil
		if _, err := c.FlushDomain(stub, false); err != nil {
			t.Fatalf("FlushDomain: %v", err)
		}
		if _, ok := c.ServerMap.Get(stub); ok {
			t.Error("with no StubZone hook, a flush kept a server map: nothing is configuration there")
		}
	})
}
