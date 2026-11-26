/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"context"
	"errors"
	"log"
	"maps"
	"os"
	"slices"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// TestPrimeWithHintsCopiesTheRootMap extends the ServerMap invariant (#345) to
// priming, which is where it used to be false: seedFromHints publishes the
// root server map and PrimeWithHints then handed that same map to the fetcher
// — which is IterativeDNSQuery, which writes into the map it is given. The
// published root delegation was editable by the priming query, at the one
// moment every later lookup depends on it.
func TestPrimeWithHintsCopiesTheRootMap(t *testing.T) {
	rrcache := NewRRsetCache(log.New(os.Stderr, "test ", log.LstdFlags), false, false)

	const intruder = "intruder.root."
	var handed map[string]*AuthServer
	fetcher := func(ctx context.Context, qname string, qtype uint16, servers map[string]*AuthServer) (*core.RRset, error) {
		handed = servers
		// What IterativeDNSQuery does with the map it is handed.
		servers[ServerKey(intruder)] = NewAuthServer(intruder)
		return &core.RRset{Name: ".", Class: dns.ClassINET, RRtype: dns.TypeNS}, nil
	}

	if err := rrcache.PrimeWithHints(context.Background(), "", fetcher); err != nil {
		t.Fatalf("PrimeWithHints: %v", err)
	}
	if len(handed) == 0 {
		t.Fatal("the fetcher was handed no root servers")
	}

	stored, ok := rrcache.ServerMap.Get(".")
	if !ok {
		t.Fatal("no root entry in the server map after priming")
	}
	if _, leaked := stored[ServerKey(intruder)]; leaked {
		t.Error("priming handed the fetcher the STORED root map: its write reached the cache")
	}
	if len(stored) == 0 {
		t.Error("root server map is empty after priming")
	}
}

// A configured "." stub is the root's servers, and priming leaves them: when
// its live ". NS" fetch fails after the hints are seeded, when it succeeds,
// and when the root is seeded from the hints alone. The fetch still asks the
// hints' servers. Seeding used to publish the hints under "." whatever was
// there, so the stub was gone from the moment priming began.
func TestPrimingKeepsARootStub(t *testing.T) {
	rrcache := NewRRsetCache(log.New(os.Stderr, "test ", log.LstdFlags), false, false)
	const stubNS = "ns.private-root.test."
	if err := rrcache.AddStub(".", []AuthServer{{Name: stubNS, Addrs: []string{"192.0.2.53"}}}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	rootServers := func() []string {
		stored, _ := rrcache.ServerMap.Get(".")
		return slices.Sorted(maps.Keys(stored))
	}
	want := []string{ServerKey(stubNS)}
	check := func(got []string, when string) {
		t.Helper()
		if !slices.Equal(got, want) {
			t.Errorf("%s the root's servers are %v, want the stub's %v", when, got, want)
		}
	}

	var handed, during []string
	fetch := func(fail bool) RRsetFetcher {
		return func(ctx context.Context, qname string, qtype uint16, servers map[string]*AuthServer) (*core.RRset, error) {
			handed = slices.Sorted(maps.Keys(servers))
			during = rootServers()
			if fail {
				return nil, errors.New("no root server answered")
			}
			return &core.RRset{Name: ".", Class: dns.ClassINET, RRtype: dns.TypeNS}, nil
		}
	}

	if err := rrcache.PrimeWithHints(context.Background(), "", fetch(true)); err == nil {
		t.Fatal("PrimeWithHints succeeded with a failing fetch")
	}
	if !slices.Contains(handed, ServerKey("a.root-servers.net.")) {
		t.Errorf("the priming fetch was handed %v, not the hints' servers", handed)
	}
	check(during, "during the priming fetch")
	check(rootServers(), "after the priming fetch failed")

	if err := rrcache.PrimeWithHints(context.Background(), "", fetch(false)); err != nil {
		t.Fatalf("PrimeWithHints: %v", err)
	}
	check(rootServers(), "after priming")

	if err := rrcache.PrimeFromHintsOnly(""); err != nil {
		t.Fatalf("PrimeFromHintsOnly: %v", err)
	}
	check(rootServers(), "after seeding from the hints alone")
}
