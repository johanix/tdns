/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"net"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// One address lookup per nameserver name, on every path (nsLookup). The first
// query into a zone whose nameservers are all out-of-bailiwick meets the
// referral, which starts the lookups in the background, and then falls
// straight into a fallback that needs the same addresses. The fallback used to
// send its own queries next to the background ones. Uses the auth double and
// helpers of imr_oob_servers_stored_test.go.

// referralTo is the parent's referral to zone: NS oobNSName only, no glue.
func referralTo(zone, qname string) *dns.Msg {
	ref := new(dns.Msg)
	ref.SetQuestion(qname, dns.TypeA)
	ref.Response = true
	ref.Ns = []dns.RR{&dns.NS{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
		Ns:  oobNSName,
	}}
	return ref
}

// referNoAddress feeds a referral to zone through handleReferral. The server
// has no known address, so it starts the background lookup and returns.
func referNoAddress(t *testing.T, imr *Imr, zone string) {
	t.Helper()
	qname := "a." + zone
	_, _, cctx, _, err := imr.handleReferral(context.Background(), qname, dns.TypeA,
		referralTo(zone, qname), false, map[string]bool{}, core.TransportDo53, edns0.PrivacyNone)
	if err != nil || cctx != cache.ContextReferral {
		t.Fatalf("referral to %s: context=%s err=%v", zone, cache.CacheContextToString[cctx], err)
	}
}

// The synchronous fallback joins the lookup the referral started.
func TestFallbackJoinsReferralLookup(t *testing.T) {
	d := startOOBAuthDouble(t, 300*time.Millisecond)
	imr := newOOBTestImr(t, d)
	referNoAddress(t, imr, oobZone)

	qname := "b." + oobZone
	_, servers, _ := imr.Cache.FindClosestKnownZone(qname)
	if got := imr.expandServerMapWithMissingNS(context.Background(), qname, dns.TypeA, servers); got != 1 {
		t.Errorf("expandServerMapWithMissingNS = %d, want 1", got)
	}
	if n := d.nsAQueries(); n != 1 {
		t.Errorf("%s A was queried %d times, want 1: the fallback did not join the referral's lookup", oobNSName, n)
	}
}

// resolveNSAddresses joins it too.
func TestResolveNSAddressesJoinsReferralLookup(t *testing.T) {
	d := startOOBAuthDouble(t, 300*time.Millisecond)
	imr := newOOBTestImr(t, d)
	referNoAddress(t, imr, oobZone)

	var addrs []string
	done, err := imr.resolveNSAddresses(context.Background(), oobZone, "b."+oobZone, dns.TypeA,
		map[string]*cache.AuthServer{}, func(servers map[string]*cache.AuthServer) (bool, error) {
			if srv := servers[cache.ServerKey(oobNSName)]; srv != nil {
				addrs = srv.GetAddrs()
			}
			return true, nil
		})
	if err != nil || !done || len(addrs) == 0 {
		t.Fatalf("resolveNSAddresses: done=%v err=%v addresses=%v", done, err, addrs)
	}
	if n := d.nsAQueries(); n != 1 {
		t.Errorf("%s A was queried %d times, want 1: resolveNSAddresses did not join the referral's lookup", oobNSName, n)
	}
}

// A shared server that already has addresses needs no query: they came from
// another zone's glue or an earlier lookup. The fallback used to send A and
// AAAA queries for it anyway.
func TestExpandSendsNoQueryForServerWithAddresses(t *testing.T) {
	d := startOOBAuthDouble(t, 0)
	imr := newOOBTestImr(t, d)
	cacheDelegation(imr.Cache, oobZone)
	if err := imr.Cache.AddServers(oobZone, map[string]*cache.AuthServer{}); err != nil {
		t.Fatalf("AddServers: %v", err)
	}
	// The address is on the shared server but not in the RRset cache, so a
	// query for it would reach the double.
	imr.Cache.GetOrCreateAuthServer(oobNSName).AddAddr(d.host)

	if got := imr.expandServerMapWithMissingNS(context.Background(), "host."+oobZone, dns.TypeA,
		map[string]*cache.AuthServer{}); got != 1 {
		t.Errorf("expandServerMapWithMissingNS = %d, want 1", got)
	}
	if n := d.nsAQueries(); n != 0 {
		t.Errorf("%s A was queried %d times, want 0", oobNSName, n)
	}
	if addrs := storedServerAddrs(imr.Cache, oobZone); len(addrs) == 0 {
		t.Errorf("the cached server map for %s has no %s with addresses", oobZone, oobNSName)
	}
}

// A caller that stops waiting leaves the lookup running, and its result is
// stored for the next query.
func TestLookupOutlivesItsWaiter(t *testing.T) {
	d := startOOBAuthDouble(t, 300*time.Millisecond)
	imr := newOOBTestImr(t, d)
	cacheDelegation(imr.Cache, oobZone)
	if err := imr.Cache.AddServers(oobZone, map[string]*cache.AuthServer{}); err != nil {
		t.Fatalf("AddServers: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if got := imr.expandServerMapWithMissingNS(ctx, "host."+oobZone, dns.TypeA,
		map[string]*cache.AuthServer{}); got != 0 {
		t.Errorf("expandServerMapWithMissingNS = %d before the lookup could end, want 0", got)
	}

	deadline := time.Now().Add(5 * time.Second)
	for len(storedServerAddrs(imr.Cache, oobZone)) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%s never reached the cached server map for %s after its waiter gave up", oobNSName, oobZone)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A lookup that comes to need its own name does not wait on itself. Here the
// zone's only nameserver is inside it and has no glue: resolving it starts at
// the zone, whose server map is empty, and falls back to looking the same name
// up. Joining the running lookup would wait until its deadline (twice the
// query budget); it ends at once instead.
func TestLookupNeedingItsOwnNameEndsAtOnce(t *testing.T) {
	d := startOOBAuthDouble(t, 0)
	imr := newOOBTestImr(t, d)
	const (
		zone   = "selfish.test."
		nsname = "ns1.selfish.test."
	)
	imr.Cache.Set(zone, dns.TypeNS, &cache.CachedRRset{
		Name: zone, RRtype: dns.TypeNS, Context: cache.ContextReferral,
		State: cache.ValidationStateIndeterminate, Expiration: time.Now().Add(time.Hour),
		RRset: &core.RRset{Name: zone, Class: dns.ClassINET, RRtype: dns.TypeNS,
			RRs: []dns.RR{&dns.NS{
				Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 3600},
				Ns:  nsname,
			}}},
	})
	if err := imr.Cache.AddServers(zone, map[string]*cache.AuthServer{}); err != nil {
		t.Fatalf("AddServers: %v", err)
	}

	start := time.Now()
	if got := imr.expandServerMapWithMissingNS(context.Background(), "host."+zone, dns.TypeA,
		map[string]*cache.AuthServer{}); got != 0 {
		t.Errorf("expandServerMapWithMissingNS = %d, want 0", got)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("the lookup took %v: it waited on itself", took)
	}
	imr.nsAddrLookups.mu.Lock()
	running := len(imr.nsAddrLookups.running)
	imr.nsAddrLookups.mu.Unlock()
	if running != 0 {
		t.Errorf("%d lookups still running after the fallback returned", running)
	}
}

// Two zones naming the same nameserver share one lookup, and both get the
// server.
func TestTwoZonesShareOneLookup(t *testing.T) {
	d := startOOBAuthDouble(t, 300*time.Millisecond)
	imr := newOOBTestImr(t, d)
	const otherZone = "oob2.test."
	referNoAddress(t, imr, oobZone)
	referNoAddress(t, imr, otherZone)

	deadline := time.Now().Add(5 * time.Second)
	for _, zone := range []string{oobZone, otherZone} {
		for len(storedServerAddrs(imr.Cache, zone)) == 0 {
			if time.Now().After(deadline) {
				t.Fatalf("%s never reached the cached server map for %s", oobNSName, zone)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	if n := d.nsAQueries(); n != 1 {
		t.Errorf("%s A was queried %d times for two zones, want 1", oobNSName, n)
	}
	if got := storedServerAddrs(imr.Cache, otherZone); len(got) == 0 || !net.ParseIP(got[0]).Equal(net.ParseIP(d.host)) {
		t.Errorf("%s holds %s with addresses %v, want %s", otherZone, oobNSName, got, d.host)
	}
}

// Inside a lookup, a referral to a second zone that names the same nameserver
// finds the name on its chain: it must not wait on the running lookup (that is
// waiting on itself), but it still registers the second zone, which gets the
// server when the lookup ends. It used to be left out.
func TestNestedCallForTheSameNameRegistersItsZone(t *testing.T) {
	d := startOOBAuthDouble(t, 300*time.Millisecond)
	imr := newOOBTestImr(t, d)
	const otherZone = "oob2.test."
	cacheDelegation(imr.Cache, oobZone)
	cacheDelegation(imr.Cache, otherZone)

	done := imr.nsLookup(context.Background(), oobNSName, oobZone)

	// As the lookup's own walk would call it: the name is on the chain.
	nested := context.WithValue(context.Background(), nsLookupChainKey{}, []string{cache.ServerKey(oobNSName)})
	select {
	case <-imr.nsLookup(nested, oobNSName, otherZone):
	case <-time.After(time.Second):
		t.Fatal("the nested call waited on the running lookup")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the lookup did not end")
	}
	for _, zone := range []string{oobZone, otherZone} {
		if addrs := storedServerAddrs(imr.Cache, zone); len(addrs) == 0 {
			t.Errorf("the cached server map for %s has no %s with addresses", zone, oobNSName)
		}
	}
	if n := d.nsAQueries(); n != 1 {
		t.Errorf("%s A was queried %d times, want 1", oobNSName, n)
	}
}
