package cache

import (
	"log"
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func tlsaRRset(t *testing.T, owner string) *core.RRset {
	t.Helper()
	rr, err := dns.NewRR(owner + " 120 IN TLSA 3 1 1 " +
		"0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("build TLSA RR: %v", err)
	}
	return &core.RRset{Name: owner, Class: dns.ClassINET, RRtype: dns.TypeTLSA, RRs: []dns.RR{rr}}
}

// TestStubServerTLSAVisibleToLookup: a stub upstream's TLSA is retrievable via
// LookupTLSAForServer. TLSA is cached at cache level (ServerTLSA), decoupled
// from the AuthServer instance — so this works even though AddStub keeps a
// PRIVATE instance and never registers the stub in the shared AuthServerMap.
func TestStubServerTLSAVisibleToLookup(t *testing.T) {
	rrcache := NewRRsetCache(log.Default(), false, false)

	const (
		zone  = "example."
		nsFQ  = "ns1.example."
		owner = "_853._tcp.ns1.example."
	)

	if err := rrcache.AddStub(zone, []AuthServer{
		{Name: nsFQ, Addrs: []string{"192.0.2.1"}, Alpn: []string{"dot"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}

	// The stub must NOT leak into the shared AuthServerMap: sharing that
	// instance is exactly what let AddStub clobber discovered NS state.
	if _, ok := rrcache.AuthServerMap.Get(nsFQ); ok {
		t.Fatalf("stub server %s leaked into AuthServerMap (should be a private ServerMap-only instance)", nsFQ)
	}

	rrcache.StoreTLSAForServer(nsFQ, owner, tlsaRRset(t, owner), ValidationStateSecure)

	got := rrcache.LookupTLSAForServer(nsFQ, owner)
	if got == nil {
		t.Fatal("LookupTLSAForServer returned nil for a stub server: decoupled TLSA cache not consulted")
	}
	if got.State != ValidationStateSecure {
		t.Fatalf("unexpected validation state: got %v, want secure", got.State)
	}
	// Snapshot (used by the IMR dump) sees it too.
	if snap := rrcache.SnapshotTLSAForServer(nsFQ); len(snap) != 1 || snap[owner] == nil {
		t.Fatalf("SnapshotTLSAForServer missing the record: %+v", snap)
	}
}

// TestDiscoverThenStubKeepsGlue is the F2 regression: a stub sharing an NS name
// with IMR discovery must NOT overwrite the discovered addresses on the shared
// AuthServerMap instance (which ordinary recursion dials). Before the decoupling
// fix, AddStub used the shared instance + SetAddrs and clobbered the glue.
func TestDiscoverThenStubKeepsGlue(t *testing.T) {
	rrcache := NewRRsetCache(log.Default(), false, false)
	const nsFQ = "ns1.example."

	// IMR discovery registers ns1 with glue in the shared AuthServerMap.
	disc := NewAuthServer(nsFQ)
	disc.SetAddrs([]string{"192.0.2.10", "192.0.2.11"})
	if err := rrcache.AddServers("child.example.", map[string]*AuthServer{nsFQ: disc}); err != nil {
		t.Fatalf("AddServers: %v", err)
	}
	shared, ok := rrcache.AuthServerMap.Get(nsFQ)
	if !ok || len(shared.Addrs) != 2 {
		t.Fatalf("discovery did not register glue: %+v", shared)
	}

	// A stub for the SAME name with a different address.
	if err := rrcache.AddStub("stub.example.", []AuthServer{
		{Name: nsFQ, Addrs: []string{"203.0.113.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}

	// The shared/discovered instance must be untouched (glue intact, no stub addr).
	shared2, _ := rrcache.AuthServerMap.Get(nsFQ)
	if len(shared2.Addrs) != 2 || shared2.Addrs[0] != "192.0.2.10" || shared2.Addrs[1] != "192.0.2.11" {
		t.Fatalf("stub clobbered discovered glue on the shared instance: %v", shared2.Addrs)
	}
	for _, a := range shared2.Addrs {
		if a == "203.0.113.1" {
			t.Fatalf("stub address leaked onto the shared discovery instance: %v", shared2.Addrs)
		}
	}

	// The stub's own private instance carries the stub address.
	sm, ok := rrcache.ServerMap.Get("stub.example.")
	if !ok || sm[nsFQ] == nil {
		t.Fatalf("stub zone server map missing %s", nsFQ)
	}
	if len(sm[nsFQ].Addrs) != 1 || sm[nsFQ].Addrs[0] != "203.0.113.1" {
		t.Fatalf("stub private instance has wrong addrs: %v", sm[nsFQ].Addrs)
	}
}
