/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// #832: a parent whose resolver forwards "." and has a stub for the child.
// When the parent changes the child's delegation, invalidateImrDelegations
// (#694) flushes the resolver's view of the child. That flush took the stub's
// server map with it, while the stub table still kept the child's names from
// the forward, so every later lookup in the child went to the closest cached
// zone cut -- none, under a forwarded root -- and failed with
// `no nameservers for zone ""`. The coherence check's DNSKEY lookup was one,
// and the child's second DS change was refused.

const (
	stubFlushParent = "parent.example."
	stubFlushChild  = "kid.parent.example."
)

// stubFlushResolver is a resolver forwarding "." to the upstream double and
// holding a stub for stubFlushChild pointing at the stub double, installed as
// Globals.ImrEngine for the zone updater's flush. The upstream answers NODATA
// for everything in the child; only the stub's server answers its SOA.
type stubFlushResolver struct {
	imr   *Imr
	upLog *upstreamLog
}

func newStubFlushResolver(t *testing.T) *stubFlushResolver {
	t.Helper()
	upAddr, upPort, upLog, stopUp := startTestUpstream(t)
	t.Cleanup(stopUp)
	stubAddr, stubPort, stopStub := startStubAuthServer(t, stubFlushChild)
	t.Cleanup(stopStub)

	imr := newForwardTestImr(t, rootForward(upAddr, upPort))
	imr.FamilyTracker = cache.NewFamilyTracker(10*time.Minute, 10*time.Minute, 30*time.Second, 5)
	// The stub's server is reached through the cache's shared per-transport
	// clients (fixed port); point them at the stub double. The forward has
	// its own client, built for the upstream's port.
	imr.Cache.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, stubPort, nil)
	imr.Cache.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, stubPort, nil)
	if err := imr.Cache.AddStub(stubFlushChild, []cache.AuthServer{
		{Name: "ns." + stubFlushChild, Addrs: []string{stubAddr}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	imr.setZoneTable(imr.ForwardZones(), []string{stubFlushChild}, nil)

	saved := Globals.ImrEngine
	Globals.ImrEngine = imr
	t.Cleanup(func() { Globals.ImrEngine = saved })
	return &stubFlushResolver{imr: imr, upLog: upLog}
}

// childSOA asks the resolver for the child's SOA, as a caller of ImrQuery
// does, and fails the test unless the lookup succeeded.
func (s *stubFlushResolver) childSOA(t *testing.T, when string) *ImrResponse {
	t.Helper()
	resp, err := s.imr.ImrQuery(context.Background(), stubFlushChild, dns.TypeSOA, dns.ClassINET, nil)
	if err != nil {
		t.Fatalf("%s: ImrQuery(%s SOA): %v", when, stubFlushChild, err)
	}
	if resp == nil {
		t.Fatalf("%s: ImrQuery(%s SOA) returned no response", when, stubFlushChild)
	}
	return resp
}

// requireFromStub fails the test unless resp is the stub server's SOA and the
// forward's upstream was never asked for it.
func (s *stubFlushResolver) requireFromStub(t *testing.T, resp *ImrResponse, when string) {
	t.Helper()
	if resp.RRset == nil || len(resp.RRset.RRs) != 1 || resp.RRset.RRs[0].Header().Rrtype != dns.TypeSOA {
		t.Errorf("%s: no SOA from the stub's server (rrset %v, error %q)", when, resp.RRset, resp.ErrorMsg)
	}
	if q := s.upLog.find(stubFlushChild, dns.TypeSOA); len(q) != 0 {
		t.Errorf("%s: the forward's upstream was asked %s SOA %d times; the stub owns that name", when, stubFlushChild, len(q))
	}
}

// The #694 flush must not take the stub with it: the child's second lookup,
// after the parent has changed the child's DS, still goes to the stub.
func TestChangedDelegationKeepsTheChildsStub(t *testing.T) {
	s := newStubFlushResolver(t)

	s.requireFromStub(t, s.childSOA(t, "before the DS change"), "before the DS change")

	// The parent adds the child's DS. The SOA just cached is in the child, so
	// the flush removes entries, which is when it used to drop server maps.
	invalidateImrDelegations(stubFlushParent, []dns.RR{
		mustRR(t, stubFlushChild+" 3600 IN DS 12345 15 2 8BE06F4F1E2DE81BD1A9D0A29C7C79C3E43D83C1C1A6E1E6CA0A77F6CD8D0B0E"),
	})
	if s.imr.Cache.Get(stubFlushChild, dns.TypeSOA) != nil {
		t.Fatal("test setup: the flush left the child's SOA cached, so the next lookup never leaves the cache")
	}
	if m, ok := s.imr.Cache.ServerMap.Get(stubFlushChild); !ok || len(m) == 0 {
		t.Error("the flush of a changed delegation dropped the child's configured stub")
	}

	s.requireFromStub(t, s.childSOA(t, "after the DS change"), "after the DS change")
}

// The fallback: a stub whose servers the cache no longer holds, however they
// were lost, gives its names back to the forward rather than sending them to
// a zone cut that does not exist. Once the stub's servers are back, it takes
// them again.
func TestLostStubFallsBackToTheForward(t *testing.T) {
	s := newStubFlushResolver(t)

	s.imr.Cache.ServerMap.Remove(stubFlushChild)

	s.childSOA(t, "with the stub's servers lost") // fails the test on `no nameservers for zone ""`
	if q := s.upLog.find(stubFlushChild, dns.TypeSOA); len(q) == 0 {
		t.Errorf("with the stub's servers lost, %s SOA was not sent to the forward", stubFlushChild)
	}
	// The validator's fetches decide the same way (RRsetCacheT.Forwarded).
	if servers, ok := s.imr.Cache.ServersFor(stubFlushChild, dns.TypeDNSKEY); !ok || servers != nil {
		t.Errorf("ServersFor(%s DNSKEY) = %d servers, %v; want the forward (none, true)", stubFlushChild, len(servers), ok)
	}

	if err := s.imr.Cache.AddStub(stubFlushChild, []cache.AuthServer{{Name: "ns." + stubFlushChild, Addrs: []string{"192.0.2.53"}}}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	if fz := s.imr.forwardZoneFor("www." + stubFlushChild); fz != nil {
		t.Errorf("with the stub's servers back, www.%s is still forwarded to %s", stubFlushChild, fz.Zone)
	}
}
