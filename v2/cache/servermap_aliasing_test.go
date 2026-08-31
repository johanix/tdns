/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"log"
	"os"
	"testing"
)

// TestServerMapAccessorsCopy pins the ServerMap invariant (#345): the two
// accessors that hand a zone's server map to a caller which may pass it on to
// a query must both COPY it. IterativeDNSQuery writes into the map it is
// given, so an accessor that returned the stored map would let a read path
// edit the cache in place.
func TestServerMapAccessorsCopy(t *testing.T) {
	rrcache := NewRRsetCache(log.New(os.Stderr, "test ", log.LstdFlags), false, false)
	const zone = "example."
	if err := rrcache.AddStub(zone, []AuthServer{
		{Name: "ns1.example.", Addrs: []string{"192.0.2.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}

	check := func(name string, m map[string]*AuthServer) {
		t.Helper()
		m[ServerKey("intruder.example.")] = NewAuthServer("intruder.example.")
		stored, ok := rrcache.ServerMap.Get(zone)
		if !ok {
			t.Fatalf("%s: zone vanished from the server map", name)
		}
		if _, leaked := stored[ServerKey("intruder.example.")]; leaked {
			t.Errorf("%s returned the STORED map: a caller's write reached the cache", name)
		}
	}

	cp, ok := rrcache.ServerMapCopy(zone)
	if !ok {
		t.Fatalf("ServerMapCopy(%s) missed", zone)
	}
	check("ServerMapCopy", cp)

	_, servers, err := rrcache.FindClosestKnownZone("host." + zone)
	if err != nil {
		t.Fatalf("FindClosestKnownZone: %v", err)
	}
	check("FindClosestKnownZone", servers)
}
