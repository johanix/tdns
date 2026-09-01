/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"context"
	"log"
	"os"
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
