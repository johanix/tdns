/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"log"
	"os"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// #694: marking an entry bogus must not extend its life. The stale DNSKEY RRset
// of a child that had re-keyed was re-marked bogus on every failed validation,
// Set recomputed its expiry from the TTL each time, and it was never let go.
func TestMarkRRsetBogusKeepsTheExpiry(t *testing.T) {
	rrcache := NewRRsetCache(log.New(os.Stderr, "test ", 0), false, false)
	const zone = "kid.example."
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: 257, Protocol: 3, Algorithm: dns.ED25519, PublicKey: "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="}
	set := &core.RRset{Name: zone, Class: dns.ClassINET, RRtype: dns.TypeDNSKEY, RRs: []dns.RR{key}}
	rrcache.Set(zone, dns.TypeDNSKEY, &CachedRRset{Name: zone, RRtype: dns.TypeDNSKEY, RRset: set, Context: ContextAnswer})

	// Most of its life has gone by: ten seconds left of the hour.
	k := rrsetKey(zone, dns.TypeDNSKEY)
	stored, _ := rrcache.RRsets.Get(k)
	soon := time.Now().Add(10 * time.Second)
	stored.Expiration = soon
	rrcache.RRsets.Set(k, stored)

	rrcache.MarkRRsetBogus(zone, dns.TypeDNSKEY, set, true)

	after, ok := rrcache.RRsets.Get(k)
	if !ok {
		t.Fatal("entry gone after MarkRRsetBogus")
	}
	if after.State != ValidationStateBogus {
		t.Errorf("state %s, want bogus", ValidationStateToString[after.State])
	}
	if after.Expiration.After(soon.Add(time.Second)) {
		t.Errorf("MarkRRsetBogus extended the entry's life: expires in %v, had %v left",
			time.Until(after.Expiration).Round(time.Second), 10*time.Second)
	}
}
