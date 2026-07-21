package cache

import (
	"log"
	"testing"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// TestStubServerTLSAVisibleToLookup guards the fix for the #314 review finding:
// AddStub must register its servers as the shared per-nameserver instance
// (AuthServerMap), not a private ServerMap-only one. Otherwise a TLSA record
// stored via StoreTLSAForServer (which walks ServerMap) is invisible to
// LookupTLSAForServer (which reads AuthServerMap), defeating the server-scoped
// TLSA cache for stub upstreams on the XoT DANE path.
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

	// Sanity: the stub server is reachable through the shared global map, not
	// only through the per-zone ServerMap.
	if s, ok := rrcache.AuthServerMap.Get(nsFQ); !ok || s == nil {
		t.Fatalf("stub server %s not registered in AuthServerMap (shared instance missing)", nsFQ)
	}

	tlsa, err := dns.NewRR(owner + " 120 IN TLSA 3 1 1 " +
		"0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("build TLSA RR: %v", err)
	}
	rrset := &core.RRset{
		Name:   owner,
		Class:  dns.ClassINET,
		RRtype: dns.TypeTLSA,
		RRs:    []dns.RR{tlsa},
	}

	rrcache.StoreTLSAForServer(nsFQ, owner, rrset, ValidationStateSecure)

	got := rrcache.LookupTLSAForServer(nsFQ, owner)
	if got == nil {
		t.Fatal("LookupTLSAForServer returned nil for a stub server: TLSA stored via ServerMap is invisible to the AuthServerMap-backed lookup")
	}
	if got.State != ValidationStateSecure {
		t.Fatalf("unexpected validation state: got %v, want secure", got.State)
	}
	if got.RRset == nil || len(got.RRset.RRs) != 1 {
		t.Fatalf("unexpected cached RRset: %+v", got.RRset)
	}
}
