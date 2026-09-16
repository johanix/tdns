/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"log"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// Tests for #682: a zone whose nameservers are all out-of-bailiwick gets those
// servers into its cached server map, so a later query into the zone has a
// server to send to on its first pass.
//
// The auth double serves two zones on one loopback address:
//
//	oob.test.    NS ns1.other.test. (out-of-bailiwick, so never glued)
//	other.test.  a stub zone holding ns1.other.test. A <loopback>
const (
	oobZone     = "oob.test."
	oobNSName   = "ns1.other.test."
	oobNSZone   = "other.test."
	oobStubZone = "stub.test."
)

// oobAuthDouble is a loopback authoritative server for oobZone and oobNSZone
// that counts the address queries it receives for oobNSName.
type oobAuthDouble struct {
	host, port string
	nsADelay   time.Duration

	mu       sync.Mutex
	nsAQuery int
}

func (d *oobAuthDouble) nsAQueries() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.nsAQuery
}

func startOOBAuthDouble(t *testing.T, nsADelay time.Duration) *oobAuthDouble {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	d := &oobAuthDouble{nsADelay: nsADelay}
	d.host, d.port, _ = net.SplitHostPort(pc.LocalAddr().String())

	soa := func(zone string) dns.RR {
		return &dns.SOA{
			Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
			Ns:  "ns." + zone, Mbox: "hostmaster." + zone,
			Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 60,
		}
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(oobZone, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if q := r.Question[0]; q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 1),
			})
		} else {
			m.Ns = append(m.Ns, soa(oobZone))
		}
		_ = w.WriteMsg(m)
	})
	mux.HandleFunc(oobNSZone, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		q := r.Question[0]
		if core.EqualNames(q.Name, oobNSName) && q.Qtype == dns.TypeA {
			d.mu.Lock()
			d.nsAQuery++
			d.mu.Unlock()
			time.Sleep(d.nsADelay)
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
				A:   net.ParseIP(d.host),
			})
		} else {
			m.Ns = append(m.Ns, soa(oobNSZone))
		}
		_ = w.WriteMsg(m)
	})

	started := make(chan struct{})
	served := make(chan error, 1)
	srv := &dns.Server{PacketConn: pc, Handler: mux, NotifyStartedFunc: func() { close(started) }}
	go func() { served <- srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("auth double did not start")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.ShutdownContext(ctx); err != nil {
			t.Errorf("auth double shutdown: %v", err)
		}
		select {
		case <-served:
		case <-time.After(5 * time.Second):
			t.Error("auth double serve goroutine did not exit")
		}
	})
	return d
}

// newOOBTestImr returns an IMR whose Do53 clients reach the double, with
// oobNSZone configured as a stub on it so oobNSName can be resolved.
func newOOBTestImr(t *testing.T, d *oobAuthDouble) *Imr {
	t.Helper()
	c := cache.NewRRsetCache(log.New(os.Stderr, "test", log.LstdFlags), false, false)
	c.DNSClient[core.TransportDo53] = core.NewDNSClient(core.TransportDo53, d.port, nil)
	c.DNSClient[core.TransportDo53TCP] = core.NewDNSClient(core.TransportDo53TCP, d.port, nil)
	if err := c.AddStub(oobNSZone, []cache.AuthServer{
		{Name: "ns." + oobNSZone, Addrs: []string{d.host}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub(%s): %v", oobNSZone, err)
	}
	return &Imr{
		Cache: c,
		Quiet: true,
		FamilyTracker: cache.NewFamilyTracker(
			10*time.Minute, 10*time.Minute, 30*time.Second, 5),
	}
}

// cacheNSAddress caches oobNSName's addresses as an earlier lookup would have.
func cacheNSAddress(c *cache.RRsetCacheT, addr string) {
	c.Set(oobNSName, dns.TypeA, &cache.CachedRRset{
		Name: oobNSName, RRtype: dns.TypeA, Context: cache.ContextAnswer,
		State: cache.ValidationStateInsecure, Expiration: time.Now().Add(time.Hour),
		RRset: &core.RRset{Name: oobNSName, Class: dns.ClassINET, RRtype: dns.TypeA,
			RRs: []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: oobNSName, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
				A:   net.ParseIP(addr),
			}}},
	})
	c.Set(oobNSName, dns.TypeAAAA, &cache.CachedRRset{
		Name: oobNSName, RRtype: dns.TypeAAAA, Context: cache.ContextNoErrNoAns,
		State: cache.ValidationStateInsecure, Expiration: time.Now().Add(time.Hour),
	})
}

// cacheDelegation caches zone's NS RRset naming oobNSName, as a referral does.
func cacheDelegation(c *cache.RRsetCacheT, zone string) {
	c.Set(zone, dns.TypeNS, &cache.CachedRRset{
		Name: zone, RRtype: dns.TypeNS, Context: cache.ContextReferral,
		State: cache.ValidationStateIndeterminate, Expiration: time.Now().Add(time.Hour),
		RRset: &core.RRset{Name: zone, Class: dns.ClassINET, RRtype: dns.TypeNS,
			RRs: []dns.RR{&dns.NS{
				Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
				Ns:  oobNSName,
			}}},
	})
}

// oobReferral is the parent's referral to oobZone: NS only, no glue.
func oobReferral(qname string) *dns.Msg {
	ref := new(dns.Msg)
	ref.SetQuestion(qname, dns.TypeA)
	ref.Response = true
	ref.Ns = []dns.RR{&dns.NS{
		Hdr: dns.RR_Header{Name: oobZone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  oobNSName,
	}}
	return ref
}

// storedServerAddrs returns the addresses the zone's CACHED server map holds
// for oobNSName: what the next query into the zone starts from.
func storedServerAddrs(c *cache.RRsetCacheT, zone string) []string {
	best, servers, err := c.FindClosestKnownZone("host." + zone)
	if err != nil || !core.EqualNames(best, zone) {
		return nil
	}
	srv, ok := servers[cache.ServerKey(oobNSName)]
	if !ok {
		return nil
	}
	return srv.GetAddrs()
}

// A referral stores the out-of-bailiwick servers whose addresses it already
// knows, and the next query into the zone has a server on its first pass.
func TestReferralStoresKnownOutOfBailiwickServers(t *testing.T) {
	d := startOOBAuthDouble(t, 0)
	imr := newOOBTestImr(t, d)
	cacheNSAddress(imr.Cache, d.host)

	qname := "a." + oobZone
	rrset, rcode, _, _, err := imr.handleReferral(context.Background(), qname, dns.TypeA,
		oobReferral(qname), false, map[string]bool{}, core.TransportDo53, edns0.PrivacyNone)
	if err != nil || rcode != dns.RcodeSuccess || rrset == nil {
		t.Fatalf("%s A through the referral: rcode=%s rrset=%v err=%v", qname, dns.RcodeToString[rcode], rrset, err)
	}

	if addrs := storedServerAddrs(imr.Cache, oobZone); len(addrs) == 0 {
		t.Fatalf("the cached server map for %s has no %s with addresses after the referral", oobZone, oobNSName)
	}
	next := "b." + oobZone
	_, servers, _ := imr.Cache.FindClosestKnownZone(next)
	if _, _, tuples := imr.prioritizeServers(next, dns.TypeA, servers, edns0.PrivacyNone); len(tuples) == 0 {
		t.Errorf("a later query for %s has no server to send to on its first pass", next)
	}
}

// A referral whose out-of-bailiwick servers have no known addresses resolves
// them in the background, and the result reaches the zone's server map after
// the query that triggered it has returned and its context is gone. Referrals
// that arrive while the lookup runs do not start another one.
func TestReferralResolvesOutOfBailiwickServersInBackground(t *testing.T) {
	d := startOOBAuthDouble(t, 300*time.Millisecond)
	imr := newOOBTestImr(t, d)

	ctx, cancel := context.WithCancel(context.Background())
	qname := "a." + oobZone
	for i := 0; i < 3; i++ {
		// No server has an address yet, so the referral returns at once.
		_, _, cctx, _, err := imr.handleReferral(ctx, qname, dns.TypeA,
			oobReferral(qname), false, map[string]bool{}, core.TransportDo53, edns0.PrivacyNone)
		if err != nil || cctx != cache.ContextReferral {
			t.Fatalf("referral %d: context=%s err=%v", i, cache.CacheContextToString[cctx], err)
		}
	}
	cancel() // the queries that saw the referrals are over

	deadline := time.Now().Add(5 * time.Second)
	for len(storedServerAddrs(imr.Cache, oobZone)) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%s never reached the cached server map for %s (A queries sent: %d)",
				oobNSName, oobZone, d.nsAQueries())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := d.nsAQueries(); n != 1 {
		t.Errorf("%s A was queried %d times for three referrals, want 1", oobNSName, n)
	}
}

// The synchronous fallbacks store the servers they resolve, so the next query
// into the zone does not repeat the lookups.
func TestNSAddressFallbacksStoreServers(t *testing.T) {
	d := startOOBAuthDouble(t, 0)
	imr := newOOBTestImr(t, d)
	cacheNSAddress(imr.Cache, d.host)
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		run  func(zone string)
	}{
		{"expandServerMapWithMissingNS", func(zone string) {
			imr.expandServerMapWithMissingNS(ctx, "host."+zone, dns.TypeA, map[string]*cache.AuthServer{})
		}},
		{"resolveNSAddresses", func(zone string) {
			_, err := imr.resolveNSAddresses(ctx, zone, "host."+zone, dns.TypeA, map[string]*cache.AuthServer{},
				func(map[string]*cache.AuthServer) (bool, error) { return true, nil })
			if err != nil {
				t.Errorf("resolveNSAddresses: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zone := "fallback-" + tc.name[:6] + "." + "test."
			cacheDelegation(imr.Cache, zone)
			if err := imr.Cache.AddServers(zone, map[string]*cache.AuthServer{}); err != nil {
				t.Fatalf("AddServers: %v", err)
			}
			tc.run(zone)
			if addrs := storedServerAddrs(imr.Cache, zone); len(addrs) == 0 {
				t.Errorf("the cached server map for %s has no %s with addresses", zone, oobNSName)
			}
		})
	}
}

// #675: the fallback reports a server it put into the map even when that
// shared server already had its addresses, so the caller retries.
func TestExpandCountsServerThatAlreadyHasAddresses(t *testing.T) {
	d := startOOBAuthDouble(t, 0)
	imr := newOOBTestImr(t, d)
	cacheNSAddress(imr.Cache, d.host)
	cacheDelegation(imr.Cache, oobZone)
	if err := imr.Cache.AddServers(oobZone, map[string]*cache.AuthServer{}); err != nil {
		t.Fatalf("AddServers: %v", err)
	}
	imr.Cache.GetOrCreateAuthServer(oobNSName).AddAddr(d.host)

	sm := map[string]*cache.AuthServer{}
	if got := imr.expandServerMapWithMissingNS(context.Background(), "host."+oobZone, dns.TypeA, sm); got != 1 {
		t.Errorf("expandServerMapWithMissingNS = %d, want 1 (the server it added to the map)", got)
	}
	if len(sm[cache.ServerKey(oobNSName)].GetAddrs()) == 0 {
		t.Errorf("the caller's map has no %s with addresses", oobNSName)
	}
}

// A configured stub keeps the servers the operator named: a fallback that
// resolves the zone's NS names must not add them to the stub's server map.
func TestFallbackLeavesConfiguredStubServers(t *testing.T) {
	d := startOOBAuthDouble(t, 0)
	imr := newOOBTestImr(t, d)
	imr.setZoneTable(nil, []string{oobStubZone}, nil)
	cacheNSAddress(imr.Cache, d.host)
	cacheDelegation(imr.Cache, oobStubZone)
	if err := imr.Cache.AddStub(oobStubZone, []cache.AuthServer{
		{Name: "ns." + oobStubZone, Addrs: []string{"192.0.2.53"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub(%s): %v", oobStubZone, err)
	}

	imr.expandServerMapWithMissingNS(context.Background(), "host."+oobStubZone, dns.TypeA, map[string]*cache.AuthServer{})

	stored, ok := imr.Cache.ServerMapCopy(oobStubZone)
	if !ok || len(stored) != 1 || stored[cache.ServerKey("ns."+oobStubZone)] == nil {
		names := []string{}
		for n := range stored {
			names = append(names, n)
		}
		t.Errorf("stub %s server map = %v, want only ns.%s", oobStubZone, names, oobStubZone)
	}
}
