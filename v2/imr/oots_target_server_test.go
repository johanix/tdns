/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// A ServiceMode record's TargetName other than "." is most likely another
// auth server than the nameserver whose signal names it, so it gets an
// AuthServer instance of its own (#1129): one per target name, outside
// AuthServerMap and every zone's ServerMap, carrying only the target
// lookup's addresses and never a signal. The server backoff, RTT and
// counters of an attempt sent to the target are kept there, whichever
// nameserver redirected it; zone lameness stays keyed by the address and
// port dialed.

// targetServer is the instance the resolver holds for target.
func targetServer(t *testing.T, imr *Imr, target string) *cache.AuthServer {
	t.Helper()
	srv, _, ok, _ := imr.endpointAddrs.get(target, time.Now())
	if !ok || srv == nil {
		t.Fatalf("no live instance for the target %s", target)
	}
	return srv
}

// redirectedServer is a nameserver at addr whose DoT a validated signal sends
// to dotTarget at port 1234.
func redirectedServer(name, addr string) *cache.AuthServer {
	return redirectedServerTo(name, addr, core.TransportDoT, dotTarget)
}

// redirectedServerTo is a nameserver at addr whose one transport, t, a
// validated signal sends to target at port 1234.
func redirectedServerTo(name, addr string, t core.Transport, target string) *cache.AuthServer {
	server := cache.NewAuthServer(name)
	server.SetAddrs([]string{addr})
	token := map[core.Transport]string{core.TransportDoT: "dot", core.TransportDo53: "udp"}[t]
	installTransportMap(server, map[string]uint8{token: 30}, map[core.Transport]uint16{t: 1234},
		map[core.Transport]string{t: target}, cache.SignalViaLookup,
		[]cache.SignalHop{{Owner: "_dns." + name, State: cache.ValidationStateSecure}})
	return server
}

// began is whether begin claimed the lookup.
func began(_ []cache.AddressFamily, ok bool) bool {
	return ok
}

// Two nameservers redirected to one target share its instance: a failure at
// the target's address through the first is the second's too, and the
// second's tuple is not offered. Neither nameserver's own instance holds it.
// Each nameserver still counts the answers the target carried for it, and the
// target's instance counts the answers themselves. An attempt tried through
// the first counts as tried for the second: it is the same endpoint.
func TestATargetSharedByTwoNameserversLearnsItsBackoffOnce(t *testing.T) {
	imr, _, dot, _, q := endpointTestRig(t)
	ns1 := redirectedServer("ns1.shared.example.", "192.0.2.1")
	ns2 := redirectedServer("ns2.shared.example.", "192.0.2.2")
	imr.endpointAddrs.set(dotTarget, []string{"192.0.2.53"}, time.Now().Add(time.Hour))
	ctx := context.Background()

	d1, err := imr.endpointFor(ctx, ns1, nil, "192.0.2.1", core.TransportDoT)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := imr.endpointFor(ctx, ns2, nil, "192.0.2.2", core.TransportDoT)
	if err != nil {
		t.Fatal(err)
	}
	if d1.server == nil || d1.server != d2.server || d1.server == ns1 || d1.server == ns2 {
		t.Fatalf("instances %p and %p, want one shared target instance apart from both nameservers", d1.server, d2.server)
	}
	if _, ok := imr.Cache.AuthServerMap.Get(dotTarget); ok {
		t.Error("the target's instance is in AuthServerMap")
	}
	if d1.server.GetSrc() != "target" || len(d1.server.GetTransportWeights()) != 0 || len(d1.server.GetTransportEndpoints()) != 0 {
		t.Errorf("the target's instance: src %q, weights %v, endpoints %v; want src target and no signal",
			d1.server.GetSrc(), d1.server.GetTransportWeights(), d1.server.GetTransportEndpoints())
	}

	// One answer through ns1: counted on the target, and as redirected on ns1.
	if _, _, _, _, err := imr.tryServer(ctx, ns1, nil, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone, attemptSelection{}); err != nil {
		t.Fatalf("through ns1: %v", err)
	}
	if got := lastDial(dot); got != "192.0.2.53:1234" {
		t.Fatalf("through ns1 dialed %q", got)
	}
	target := d1.server
	if got := target.SnapshotTransportStats().Used[core.TransportDoT]; got != 1 {
		t.Errorf("answers on the target %d, want 1", got)
	}
	if st := ns1.SnapshotTransportStats(); st.Redirected[core.TransportDoT] != 1 || st.Used[core.TransportDoT] != 0 {
		t.Errorf("ns1: redirected %v used %v, want 1 redirected and none used", st.Redirected, st.Used)
	}
	if _, ok := target.GetEndpointAddrRTT("192.0.2.53", 1234, core.TransportDoT); !ok {
		t.Error("no RTT on the target's instance")
	}
	if _, ok := ns2.GetEndpointAddrRTT("192.0.2.53", 1234, core.TransportDoT); ok {
		t.Error("the target's RTT is on ns2's instance")
	}

	// The target's address fails through ns1.
	dot.Set("example.", "192.0.2.53:1234", core.FakeResponse{Err: errors.New("i/o timeout")})
	if _, _, _, _, err := imr.tryServer(ctx, ns1, nil, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone, attemptSelection{}); err == nil {
		t.Fatal("through ns1: want a failure")
	}
	for _, s := range []*cache.AuthServer{ns1, ns2} {
		if !s.IsEndpointAddrAvailable("192.0.2.53", 1234, core.TransportDoT) {
			t.Errorf("the target's failure was booked on %s's instance", s.Name)
		}
	}
	if target.IsEndpointAddrAvailable("192.0.2.53", 1234, core.TransportDoT) {
		t.Fatal("the target's failure is not on its instance")
	}
	n := len(dot.Calls())
	if _, _, _, _, err := imr.tryServer(ctx, ns2, nil, "192.0.2.2", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone, attemptSelection{}); err == nil {
		t.Error("through ns2: an attempt at a target backed off through ns1")
	}
	if len(dot.Calls()) != n {
		t.Error("through ns2: dialed the target backed off through ns1")
	}
	serverMap := map[string]*cache.AuthServer{ns2.Name: ns2}
	_, _, tuples := imr.prioritizeServers("example.", dns.TypeA, serverMap, edns0.PrivacyNone)
	for _, tup := range tuples {
		if tup.Transport == core.TransportDoT {
			t.Error("ns2's DoT offered while the shared target is backed off")
		}
	}

	// The record of tried endpoints is the instance dialed: ns1's attempt at
	// the target is ns2's tuple too.
	target.RecordEndpointAddrSuccess("192.0.2.53", 1234, core.TransportDoT)
	tried := map[passTuple]bool{{target, "192.0.2.53", 1234, core.TransportDoT}: true}
	skip := func(s *cache.AuthServer, a string, p uint16, tr core.Transport) bool {
		return tried[passTuple{s, a, p, tr}]
	}
	_, _, tuples = imr.selectServerTuples(ctx, "example.", dns.TypeA, serverMap, edns0.PrivacyNone, false, skip)
	for _, tup := range tuples {
		if tup.Transport == core.TransportDoT {
			t.Error("ns2's DoT offered although ns1 tried the same target endpoint")
		}
	}
}

// A target named like a nameserver the resolver knows keeps a state of its
// own: the nameserver's signal (here a redirect of its own, which a target
// never follows) and its backoff are not the target's, and the target's
// backoff is not the nameserver's. Stubs are not touched either.
func TestATargetNamedLikeANameserverKeepsSeparateState(t *testing.T) {
	imr, _, _, _, _ := endpointTestRig(t)
	ns := imr.Cache.GetOrCreateAuthServer(dotTarget)
	ns.SetAddrs([]string{"192.0.2.53"})
	installTransportMap(ns, map[string]uint8{"dot": 50}, map[core.Transport]uint16{core.TransportDoT: 9853},
		map[core.Transport]string{core.TransportDoT: "elsewhere.example."}, cache.SignalViaLookup,
		[]cache.SignalHop{{Owner: "_dns." + dotTarget, State: cache.ValidationStateSecure}})
	ns.RecordEndpointAddrFailure("192.0.2.53", 0, core.TransportDoT, errors.New("i/o timeout"))
	redirecting := redirectedServer("ns.redirecting.example.", "192.0.2.1")
	imr.endpointAddrs.set(dotTarget, []string{"192.0.2.53"}, time.Now().Add(time.Hour))
	ctx := context.Background()

	d, err := imr.endpointFor(ctx, redirecting, nil, "192.0.2.1", core.TransportDoT)
	if err != nil {
		t.Fatal(err)
	}
	if d.server == ns || !d.redirect || d.addr != "192.0.2.53" || d.port != 1234 {
		t.Fatalf("endpoint %+v (instance %p, nameserver %p): want the target's own instance at 192.0.2.53:1234, the redirecting server's port",
			d, d.server, ns)
	}
	if len(d.server.GetTransportEndpoints()) != 0 {
		t.Errorf("the target's instance carries the same-named nameserver's endpoints %v", d.server.GetTransportEndpoints())
	}
	d.server.RecordEndpointAddrFailure("192.0.2.53", 1234, core.TransportDoT, errors.New("i/o timeout"))
	if !ns.IsEndpointAddrAvailable("192.0.2.53", 1234, core.TransportDoT) {
		t.Error("the target's backoff reached the same-named nameserver")
	}
	if !d.server.IsEndpointAddrAvailable("192.0.2.53", 0, core.TransportDoT) {
		t.Error("the same-named nameserver's backoff reached the target")
	}
	if got, ok := imr.Cache.AuthServerMap.Get(dotTarget); !ok || got != ns {
		t.Error("the nameserver's shared instance was replaced")
	}
}

// The target's instance is kept when its addresses are looked up again: its
// backoff and RTT carry on, and it takes the new addresses.
func TestATargetKeepsItsInstanceAcrossRefreshes(t *testing.T) {
	imr, _, _, _, _ := endpointTestRig(t)
	imr.endpointAddrs.set(dotTarget, []string{"192.0.2.53"}, time.Now().Add(time.Hour))
	first := targetServer(t, imr, dotTarget)
	first.RecordEndpointAddrFailure("192.0.2.53", 1234, core.TransportDoT, errors.New("i/o timeout"))
	first.RecordEndpointAddrRTT("192.0.2.54", 1234, core.TransportDoT, time.Millisecond)

	imr.endpointAddrs.set(dotTarget, []string{"192.0.2.53", "192.0.2.54"}, time.Now().Add(time.Hour))
	again := targetServer(t, imr, dotTarget)
	if again != first {
		t.Fatal("a refresh replaced the target's instance")
	}
	if again.IsEndpointAddrAvailable("192.0.2.53", 1234, core.TransportDoT) {
		t.Error("the backoff did not survive the refresh")
	}
	if _, ok := again.GetEndpointAddrRTT("192.0.2.54", 1234, core.TransportDoT); !ok {
		t.Error("the RTT did not survive the refresh")
	}
	if got := again.GetAddrs(); len(got) != 2 {
		t.Errorf("addresses %v after the refresh, want both", got)
	}
}

// The target's two address families run out apart (F48): when the A records
// run out while the AAAA lookup is still running, the AAAA addresses are
// kept. Both used to be dropped, and the target retried after 30 s.
func TestATargetsAddressFamiliesRunOutApart(t *testing.T) {
	imr := newTestImr(t)
	imr.Quiet = true
	put := func(rr dns.RR, ttl time.Duration) {
		name := rr.Header().Name
		imr.Cache.Set(name, rr.Header().Rrtype, &cache.CachedRRset{Name: name, RRtype: rr.Header().Rrtype,
			Context: cache.ContextAnswer, State: cache.ValidationStateSecure, Ttl: uint32(ttl / time.Second),
			Expiration: time.Now().Add(ttl), RRset: &core.RRset{Name: name, Class: dns.ClassINET,
				RRtype: rr.Header().Rrtype, RRs: []dns.RR{rr}}})
	}
	put(mustRR(t, dotTarget+` 1 IN A 192.0.2.53`), 500*time.Millisecond)
	put(mustRR(t, dotTarget+` 3600 IN AAAA 2001:db8::53`), time.Hour)

	results := imr.lookupEndpointAddrs(dotTarget, endpointFamilies[:])
	if len(results) != 2 || results[0].failed || results[1].failed {
		t.Fatalf("lookup %v, want both families answered", results)
	}
	// The lookup ends a second later, as when the AAAA query took that long.
	later := time.Now().Add(time.Second)
	imr.endpointAddrs.finishLookup(dotTarget, results, later, imr.Cache.NewTargetAuthServer)
	_, addrs, ok, _ := imr.endpointAddrs.get(dotTarget, later)
	if !ok || len(addrs) != 1 || addrs[0] != "2001:db8::53" {
		t.Errorf("after the A records ran out: %v %v, want the AAAA address", addrs, ok)
	}
	imr.endpointAddrs.mu.Lock()
	_, held := imr.endpointAddrs.retry[core.CanonicalizeName(dotTarget)]
	imr.endpointAddrs.mu.Unlock()
	if held {
		t.Error("the target is held back as if its lookup had failed")
	}
}

// Selection asks the family of the address an attempt dials, not the glue's
// (F80): a nameserver with IPv4 glue whose DoT goes to a target with an IPv6
// address is not held back while IPv4 is suspect, and the IPv4 probe is not
// spent on it. A strict query, so that DoT is the one transport in play.
func TestSelectionChecksTheFamilyOfTheAddressDialed(t *testing.T) {
	imr, server, _, _, _ := endpointTestRig(t)
	server.SetAddrs([]string{"192.0.2.1"})
	imr.FamilyTracker = cache.NewFamilyTracker(10*time.Minute, 10*time.Minute, time.Hour, 1)
	imr.FamilyTracker.RecordResult("192.0.2.99", false)
	if !imr.FamilyTracker.IsSuspect(cache.FamilyV4) {
		t.Fatal("setup: IPv4 is not suspect")
	}
	imr.endpointAddrs.set(dotTarget, []string{"2001:db8::53"}, time.Now().Add(time.Hour))
	serverMap := map[string]*cache.AuthServer{pathNS: server}

	_, _, tuples := imr.prioritizeServers("example.", dns.TypeA, serverMap, edns0.PrivacyStrict)
	var dot *ServerAddrXportTuple
	for i := range tuples {
		if tuples[i].Transport == core.TransportDoT {
			dot = &tuples[i]
		}
	}
	if dot == nil {
		t.Fatal("DoT to the IPv6 target held back by the IPv4 glue's suspect family")
	}
	if !imr.FamilyTracker.ShouldProbe(cache.FamilyV4) {
		t.Error("the IPv4 probe was spent on a dial to an IPv6 target")
	}
}

// A glueless nameserver lookup nested in a target's address lookup keeps the
// target lookup's mark (F43): its queries go to every server's default
// endpoint, never through a redirected one.
func TestAGluelessLookupInATargetLookupKeepsTheDefaultEndpoints(t *testing.T) {
	imr := newTestImr(t)
	imr.Quiet = true
	imr.Tuning.QueryBudget = 2 * time.Second
	server := imr.Cache.GetOrCreateAuthServer("ns.example.")
	server.AddAddr("192.0.2.1")
	if err := imr.Cache.AddServers("example.", map[string]*cache.AuthServer{cache.ServerKey("ns.example."): server}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	imr.Cache.DNSClient = map[core.Transport]core.DNSClienter{core.TransportDo53: core.NewFakeDNSClient(core.TransportDo53)}

	const nsname = "ns1.glueless.example."
	var mu sync.Mutex
	var marked, unmarked int
	globalImrOutboundQueryHooksMutex.Lock()
	saved := globalImrOutboundQueryHooks
	globalImrOutboundQueryHooksMutex.Unlock()
	t.Cleanup(func() {
		globalImrOutboundQueryHooksMutex.Lock()
		globalImrOutboundQueryHooks = saved
		globalImrOutboundQueryHooksMutex.Unlock()
	})
	if err := RegisterImrOutboundQueryHook(func(ctx context.Context, qname string, _ uint16, _, _ string, _ core.Transport) error {
		if !core.EqualNames(qname, nsname) {
			return nil
		}
		mu.Lock()
		defer mu.Unlock()
		if defaultEndpointsOnly(ctx) {
			marked++
		} else {
			unmarked++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	done := imr.nsLookup(withDefaultEndpoints(context.Background()), nsname, "glueless.example.")
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the nameserver lookup did not end")
	}
	mu.Lock()
	defer mu.Unlock()
	if marked == 0 && unmarked == 0 {
		t.Fatal("the nameserver lookup sent no query")
	}
	if unmarked > 0 {
		t.Errorf("%d of the nested lookup's queries lost the default-endpoints mark (%d kept it)", unmarked, marked)
	}
}

// A query whose only transport is redirected to a target whose addresses are
// still being looked up: its attempt at the default endpoint failed, and no
// tuple is left. The extra pass waits, within the budget, for the target's
// lookup, and goes to the target once its addresses are in. It used to wait
// only for servers without a signal, so the first strict query to a cold
// target failed.
func TestAnotherPassWaitsForARunningTargetLookup(t *testing.T) {
	imr, server, _, _, _ := endpointTestRig(t)
	server.SetAddrs([]string{"192.0.2.1"})
	imr.Tuning.Discovery.StrictWait = 3 * time.Second
	release := make(chan struct{})
	saved := endpointAddrLookupHook
	endpointAddrLookupHook = func(*Imr, string) ([]string, time.Time) {
		<-release
		return []string{"192.0.2.53"}, time.Now().Add(time.Hour)
	}
	t.Cleanup(func() { endpointAddrLookupHook = saved })
	releaseOnWait(t, release)
	imr.startEndpointLookup(dotTarget)
	server.RecordEndpointAddrFailure("192.0.2.1", 0, core.TransportDoT, errors.New("read: connection refused"))
	serverMap := map[string]*cache.AuthServer{pathNS: server}
	tried := map[passTuple]bool{{server, "192.0.2.1", 0, core.TransportDoT}: true}

	start := time.Now()
	sel := imr.anotherPassAfter(context.Background(), &signalWaitBudget{}, "example.", dns.TypeA, serverMap, edns0.PrivacyStrict, tried)
	if sel == nil {
		t.Fatal("no further pass: the running target lookup was not waited for")
	}
	if len(sel.tuples) != 1 || sel.tuples[0].Transport != core.TransportDoT {
		t.Fatalf("next pass %+v, want the DoT tuple", sel.tuples)
	}
	if d, _ := imr.attemptKey(context.Background(), server, sel.zone, "192.0.2.1", core.TransportDoT, false); !d.redirect || d.addr != "192.0.2.53" {
		t.Errorf("the next pass dials %+v, want the target", d)
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Errorf("waited %v, want only until the lookup ended", waited)
	}
}

// A target's own instance counts the answers it carries, and is the instance
// RedirectTargetServers lists, for stats auth-transports to report and reset.
// The report half of this test is root's TestAuthTransportsListsTargets.
func TestAuthTransportsListsTargetsResolverHalf(t *testing.T) {
	imr, server, _, _, q := endpointTestRig(t)
	imr.endpointAddrs.set(dotTarget, []string{"192.0.2.53"}, time.Now().Add(time.Hour))
	if _, _, _, _, err := imr.tryServer(context.Background(), server, nil, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone, attemptSelection{}); err != nil {
		t.Fatal(err)
	}
	inst := targetServer(t, imr, dotTarget)
	if listed := imr.RedirectTargetServers(); len(listed) != 1 || listed[0] != inst {
		t.Fatalf("RedirectTargetServers %v, want the target's own instance alone", listed)
	}
	if got := inst.SnapshotTransportStats().Used[core.TransportDoT]; inst.GetSrc() != "target" || got != 1 || inst.GetReceivedSignal() != nil {
		t.Errorf("target instance: src %q, %d DoT answers, signal %v; want target, 1, none", inst.GetSrc(), got, inst.GetReceivedSignal())
	}
	if got := server.SnapshotTransportStats().Used[core.TransportDoT]; got != 0 {
		t.Errorf("the nameserver counts %d DoT answers; the target's own instance carries them", got)
	}
}

// A target's A and AAAA run out apart, and one that has run out is looked up
// again while the other's addresses are used (CodeRabbit on #1147): with only
// the AAAA live, an IPv6 path that is down would otherwise leave the target
// unreachable until the AAAA ran out too, though its IPv4 works.
func TestAFamilyThatRunsOutIsLookedUpAgain(t *testing.T) {
	imr, server, _, _, _ := endpointTestRig(t)
	server.SetAddrs([]string{"192.0.2.1"})
	looked := make(chan struct{}, 1)
	saved := endpointAddrLookupHook
	endpointAddrLookupHook = func(*Imr, string) ([]string, time.Time) {
		looked <- struct{}{}
		return []string{"192.0.2.53", "2001:db8::53"}, time.Now().Add(time.Hour)
	}
	t.Cleanup(func() { endpointAddrLookupHook = saved })
	imr.endpointAddrs.set(dotTarget, []string{"192.0.2.53", "2001:db8::53"}, time.Now().Add(time.Hour))
	// The A records run out.
	imr.endpointAddrs.mu.Lock()
	imr.endpointAddrs.entries[core.CanonicalizeName(dotTarget)].fams[cache.FamilyV4].expire = time.Now().Add(-time.Second)
	imr.endpointAddrs.mu.Unlock()

	d, err := imr.endpointFor(context.Background(), server, nil, "192.0.2.1", core.TransportDoT)
	if err != nil {
		t.Fatal(err)
	}
	if !d.redirect || d.addr != "2001:db8::53" {
		t.Errorf("dials %+v, want the target's live AAAA meanwhile", d)
	}
	select {
	case <-looked:
	case <-time.After(2 * time.Second):
		t.Fatal("the target was not looked up again after its A records ran out")
	}
	if ch := imr.endpointAddrs.inflight(dotTarget); ch != nil {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatal("the lookup did not end")
		}
	}
	if _, addrs, ok, stale := imr.endpointAddrs.get(dotTarget, time.Now()); !ok || len(addrs) != 2 || stale {
		t.Errorf("after the lookup: %v known %v stale %v, want both families live", addrs, ok, stale)
	}
}

// A target lookup that ends after the pass's first selection, before the
// running lookups are collected, is not lost (CodeRabbit on #1147): the pass
// selects again once they are collected, and its next pass goes to the
// target.
func TestAnotherPassSeesATargetLookupThatEndedBeforeTheCollection(t *testing.T) {
	imr, server, _, _, _ := endpointTestRig(t)
	server.SetAddrs([]string{"192.0.2.1"})
	if !began(imr.endpointAddrs.begin(dotTarget, time.Now())) {
		t.Fatal("setup: the lookup could not be claimed")
	}
	saved := anotherPassSelectedHook
	anotherPassSelectedHook = func() {
		imr.endpointAddrs.finish(dotTarget, sameExpiry([]string{"192.0.2.53"}, time.Now().Add(time.Hour)), time.Now(), imr.Cache.NewTargetAuthServer)
	}
	t.Cleanup(func() { anotherPassSelectedHook = saved })
	server.RecordEndpointAddrFailure("192.0.2.1", 0, core.TransportDoT, errors.New("read: connection refused"))
	serverMap := map[string]*cache.AuthServer{pathNS: server}
	tried := map[passTuple]bool{{server, "192.0.2.1", 0, core.TransportDoT}: true}

	sel := imr.anotherPassAfter(context.Background(), &signalWaitBudget{}, "example.", dns.TypeA, serverMap, edns0.PrivacyStrict, tried)
	if sel == nil || len(sel.tuples) != 1 || sel.tuples[0].Transport != core.TransportDoT {
		t.Fatalf("next pass %+v, want the DoT tuple to the target", sel)
	}
	if d, _ := imr.attemptKey(context.Background(), server, sel.zone, "192.0.2.1", core.TransportDoT, false); !d.redirect || d.addr != "192.0.2.53" {
		t.Errorf("the next pass dials %+v, want the target", d)
	}
}

// A default endpoint that was tried and failed without a backoff, as a DS
// query refused by a child's server does, does not keep the pass from
// waiting for the running target lookup (CodeRabbit on #1147): the target is
// an endpoint the pass never tried.
func TestATriedDefaultEndpointStillWaitsForTheTarget(t *testing.T) {
	imr, server, _, _, _ := endpointTestRig(t)
	server.SetAddrs([]string{"192.0.2.1"})
	imr.Tuning.Discovery.StrictWait = 3 * time.Second
	release := make(chan struct{})
	saved := endpointAddrLookupHook
	endpointAddrLookupHook = func(*Imr, string) ([]string, time.Time) {
		<-release
		return []string{"192.0.2.53"}, time.Now().Add(time.Hour)
	}
	t.Cleanup(func() { endpointAddrLookupHook = saved })
	releaseOnWait(t, release)
	imr.startEndpointLookup(dotTarget)
	serverMap := map[string]*cache.AuthServer{pathNS: server}
	tried := map[passTuple]bool{{server, "192.0.2.1", 0, core.TransportDoT}: true}

	sel := imr.anotherPassAfter(context.Background(), &signalWaitBudget{}, "example.", dns.TypeDS, serverMap, edns0.PrivacyStrict, tried)
	if sel == nil || len(sel.tuples) != 1 || sel.tuples[0].Transport != core.TransportDoT {
		t.Fatalf("next pass %+v, want the DoT tuple to the target", sel)
	}
	if d, _ := imr.attemptKey(context.Background(), server, sel.zone, "192.0.2.1", core.TransportDoT, false); !d.redirect || d.addr != "192.0.2.53" {
		t.Errorf("the next pass dials %+v, want the target", d)
	}
}

// A refresh whose query for the family still live fails keeps that family's
// addresses (review of #1147, F2): only an answer replaces them. Here the A
// records have run out and are looked up again, and the AAAA query comes
// back Bogus; the AAAA held stays live beside the new A.
func TestAFamilyWhoseRefreshFailsKeepsItsAddresses(t *testing.T) {
	imr := newTestImr(t)
	imr.Quiet = true
	put := func(rr dns.RR, state cache.ValidationState) {
		name := rr.Header().Name
		imr.Cache.Set(name, rr.Header().Rrtype, &cache.CachedRRset{Name: name, RRtype: rr.Header().Rrtype,
			Context: cache.ContextAnswer, State: state, Ttl: 3600,
			Expiration: time.Now().Add(time.Hour), RRset: &core.RRset{Name: name, Class: dns.ClassINET,
				RRtype: rr.Header().Rrtype, RRs: []dns.RR{rr}}})
	}
	put(mustRR(t, dotTarget+` 3600 IN A 192.0.2.54`), cache.ValidationStateSecure)
	put(mustRR(t, dotTarget+` 3600 IN AAAA 2001:db8::99`), cache.ValidationStateBogus)
	now := time.Now()
	imr.endpointAddrs.finish(dotTarget, []endpointAddr{
		{addr: "192.0.2.53", expire: now.Add(-time.Second)},
		{addr: "2001:db8::53", expire: now.Add(time.Hour)},
	}, now.Add(-time.Minute), imr.Cache.NewTargetAuthServer)

	results := imr.lookupEndpointAddrs(dotTarget, endpointFamilies[:])
	if len(results) != 2 || results[0].failed || !slices.Equal(results[0].addrs, []string{"192.0.2.54"}) || !results[1].failed {
		t.Fatalf("lookup %v, want the new A and IPv6 failed", results)
	}
	imr.endpointAddrs.finishLookup(dotTarget, results, time.Now(), imr.Cache.NewTargetAuthServer)
	srv, addrs, ok, stale := imr.endpointAddrs.get(dotTarget, time.Now())
	if !ok || stale || !slices.Contains(addrs, "192.0.2.54") || !slices.Contains(addrs, "2001:db8::53") || len(addrs) != 2 {
		t.Fatalf("after the refresh: %v known %v stale %v, want the new A and the AAAA held", addrs, ok, stale)
	}
	if got := srv.GetAddrs(); len(got) != 2 {
		t.Errorf("the instance's addresses %v, want both", got)
	}
}

// A family that has run out and whose refresh fails is looked up again once
// endpointAddrRetry has passed, not on every query in between; the other
// family's answer is taken meanwhile.
func TestAFamilyThatRanOutAndFailedIsRetriedLater(t *testing.T) {
	var tr endpointAddrTracker
	now := time.Now()
	tr.finish(dotTarget, []endpointAddr{
		{addr: "192.0.2.53", expire: now.Add(time.Minute)},
		{addr: "2001:db8::53", expire: now.Add(time.Hour)},
	}, now, nil)
	later := now.Add(2 * time.Minute)
	if !began(tr.begin(dotTarget, later)) {
		t.Fatal("setup: the refresh could not be claimed")
	}
	tr.finishLookup(dotTarget, []familyLookup{
		{family: cache.FamilyV4, failed: true},
		{family: cache.FamilyV6, addrs: []string{"2001:db8::54"}, expire: later.Add(time.Hour)},
	}, later, nil)
	_, addrs, ok, stale := tr.get(dotTarget, later.Add(time.Second))
	if !ok || stale || len(addrs) != 1 || addrs[0] != "2001:db8::54" {
		t.Fatalf("after the refresh: %v known %v stale %v, want the new AAAA, and the A not due yet", addrs, ok, stale)
	}
	if _, _, _, stale := tr.get(dotTarget, later.Add(endpointAddrRetry+time.Second)); !stale {
		t.Error("the failed family is not due after endpointAddrRetry")
	}
	if !began(tr.begin(dotTarget, later.Add(endpointAddrRetry+time.Second))) {
		t.Error("the failed family's lookup could not be claimed after endpointAddrRetry")
	}
}

// A refresh in which one family is denied and the other fails clears the
// denied family though no new address came in (CodeRabbit on #1147): the
// denial is an answer. The failed family keeps what it holds.
func TestADenialClearsAFamilyWhenTheOtherFails(t *testing.T) {
	var tr endpointAddrTracker
	now := time.Now()
	tr.finish(dotTarget, sameExpiry([]string{"192.0.2.53", "2001:db8::53"}, now.Add(time.Hour)), now, nil)
	later := now.Add(time.Minute)
	tr.finishLookup(dotTarget, []familyLookup{
		{family: cache.FamilyV4},
		{family: cache.FamilyV6, failed: true},
	}, later, nil)
	srv, addrs, ok, _ := tr.get(dotTarget, later)
	if !ok || len(addrs) != 1 || addrs[0] != "2001:db8::53" {
		t.Fatalf("after the refresh: %v known %v, want the AAAA alone", addrs, ok)
	}
	if got := srv.GetAddrs(); len(got) != 1 || got[0] != "2001:db8::53" {
		t.Errorf("the instance's addresses %v, want the AAAA alone", got)
	}
	// Both denied, or the AAAA denied too: the target has no address left.
	tr.finishLookup(dotTarget, []familyLookup{{family: cache.FamilyV6}}, later, nil)
	if _, addrs, ok, _ := tr.get(dotTarget, later); ok {
		t.Errorf("after both families were denied: %v still known", addrs)
	}
	if got := srv.GetAddrs(); len(got) != 0 {
		t.Errorf("the instance still holds %v", got)
	}
}

// A family whose first query fails while the other answers is looked up
// again after endpointAddrRetry, though it held nothing (CodeRabbit on
// #1147): otherwise an IPv4-only resolver would lose the target for as long
// as the AAAA answer lasts.
func TestAFamilyWhoseFirstQueryFailsIsRetried(t *testing.T) {
	var tr endpointAddrTracker
	now := time.Now()
	tr.finishLookup(dotTarget, []familyLookup{
		{family: cache.FamilyV4, failed: true},
		{family: cache.FamilyV6, addrs: []string{"2001:db8::53"}, expire: now.Add(time.Hour)},
	}, now, nil)
	if _, addrs, ok, stale := tr.get(dotTarget, now); !ok || stale || len(addrs) != 1 {
		t.Fatalf("after the lookup: %v known %v stale %v, want the AAAA, the A not due yet", addrs, ok, stale)
	}
	retry := now.Add(endpointAddrRetry)
	if _, _, _, stale := tr.get(dotTarget, retry); !stale {
		t.Error("the A that failed is not due after endpointAddrRetry")
	}
	if !began(tr.begin(dotTarget, retry)) {
		t.Fatal("the A's lookup could not be claimed")
	}
	tr.finishLookup(dotTarget, []familyLookup{
		{family: cache.FamilyV4, addrs: []string{"192.0.2.53"}, expire: retry.Add(time.Hour)},
		{family: cache.FamilyV6, addrs: []string{"2001:db8::53"}, expire: retry.Add(time.Hour)},
	}, retry, nil)
	if _, addrs, ok, stale := tr.get(dotTarget, retry); !ok || stale || len(addrs) != 2 {
		t.Errorf("after the retry: %v known %v stale %v, want both families", addrs, ok, stale)
	}
}

// A selection that starts a target's lookup itself, as when the target's
// retry mark ran out after the pass's first selection, has that lookup
// waited for (CodeRabbit on #1147): the collection made before it found
// nothing running.
func TestAnotherPassWaitsForALookupItsSelectionStarted(t *testing.T) {
	imr, server, _, _, _ := endpointTestRig(t)
	server.SetAddrs([]string{"192.0.2.1"})
	imr.Tuning.Discovery.StrictWait = 3 * time.Second
	// A lookup failed a moment ago: the first selection cannot start one.
	if !began(imr.endpointAddrs.begin(dotTarget, time.Now())) {
		t.Fatal("setup: the lookup could not be claimed")
	}
	imr.endpointAddrs.finish(dotTarget, nil, time.Now(), nil)
	release := make(chan struct{})
	saved := endpointAddrLookupHook
	endpointAddrLookupHook = func(*Imr, string) ([]string, time.Time) {
		<-release
		return []string{"192.0.2.53"}, time.Now().Add(time.Hour)
	}
	t.Cleanup(func() { endpointAddrLookupHook = saved })
	releaseOnWait(t, release)
	savedSel := anotherPassSelectedHook
	anotherPassSelectedHook = func() {
		// The retry mark runs out.
		imr.endpointAddrs.mu.Lock()
		delete(imr.endpointAddrs.retry, core.CanonicalizeName(dotTarget))
		imr.endpointAddrs.mu.Unlock()
	}
	t.Cleanup(func() { anotherPassSelectedHook = savedSel })
	server.RecordEndpointAddrFailure("192.0.2.1", 0, core.TransportDoT, errors.New("read: connection refused"))
	serverMap := map[string]*cache.AuthServer{pathNS: server}
	tried := map[passTuple]bool{{server, "192.0.2.1", 0, core.TransportDoT}: true}

	sel := imr.anotherPassAfter(context.Background(), &signalWaitBudget{}, "example.", dns.TypeA, serverMap, edns0.PrivacyStrict, tried)
	if sel == nil || len(sel.tuples) != 1 || sel.tuples[0].Transport != core.TransportDoT {
		t.Fatalf("next pass %+v, want the DoT tuple to the target", sel)
	}
	if d, _ := imr.attemptKey(context.Background(), server, sel.zone, "192.0.2.1", core.TransportDoT, false); !d.redirect || d.addr != "192.0.2.53" {
		t.Errorf("the next pass dials %+v, want the target", d)
	}
}

// A query held to the default endpoints, as a target's own address lookup
// is, does not wait for a running target lookup (CodeRabbit on #1147): it
// never dials a target, so the lookup cannot give it a tuple.
func TestADefaultEndpointsQueryDoesNotWaitForTargets(t *testing.T) {
	imr, server, _, _, _ := endpointTestRig(t)
	server.SetAddrs([]string{"192.0.2.1"})
	imr.Tuning.Discovery.StrictWait = 2 * time.Second
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	saved := endpointAddrLookupHook
	endpointAddrLookupHook = func(*Imr, string) ([]string, time.Time) {
		<-release
		return []string{"192.0.2.53"}, time.Now().Add(time.Hour)
	}
	t.Cleanup(func() { endpointAddrLookupHook = saved })
	imr.startEndpointLookup(dotTarget)
	serverMap := map[string]*cache.AuthServer{pathNS: server}
	tried := map[passTuple]bool{{server, "192.0.2.1", 0, core.TransportDoT}: true}

	waited := watchForWait(t)
	sel := imr.anotherPassAfter(withDefaultEndpoints(context.Background()), &signalWaitBudget{}, "example.", dns.TypeA, serverMap, edns0.PrivacyStrict, tried)
	if sel != nil {
		t.Errorf("next pass %+v, want none", sel.tuples)
	}
	if waited.Load() {
		t.Error("the pass waited for a target lookup the query cannot use")
	}
}

// watchForWait reports whether anotherPassAfter's wait began
// (anotherPassWaitHook).
func watchForWait(t *testing.T) *atomic.Bool {
	t.Helper()
	var waited atomic.Bool
	saved := anotherPassWaitHook
	anotherPassWaitHook = func() { waited.Store(true) }
	t.Cleanup(func() { anotherPassWaitHook = saved })
	return &waited
}

// A strict pass does not wait for the lookup of a target that only a udp
// endpoint is sent to (CodeRabbit on #1147): a strict query never dials udp,
// so the lookup cannot give it a tuple, and the wait would spend the query's
// budget for nothing.
func TestAStrictPassDoesNotWaitForAUdpTarget(t *testing.T) {
	imr, _, _, _, _ := endpointTestRig(t)
	imr.Tuning.Discovery.StrictWait = 300 * time.Millisecond
	const udpTarget = "udp.target.example."
	server := cache.NewAuthServer(pathNS)
	server.SetAddrs([]string{"192.0.2.1"})
	installTransportMap(server, map[string]uint8{"dot": 30, "udp": 10}, map[core.Transport]uint16{core.TransportDo53: 1234},
		map[core.Transport]string{core.TransportDo53: udpTarget}, cache.SignalViaLookup,
		[]cache.SignalHop{{Owner: pathOwner, State: cache.ValidationStateSecure}})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	saved := endpointAddrLookupHook
	endpointAddrLookupHook = func(*Imr, string) ([]string, time.Time) {
		<-release
		return []string{"192.0.2.53"}, time.Now().Add(time.Hour)
	}
	t.Cleanup(func() { endpointAddrLookupHook = saved })
	imr.startEndpointLookup(udpTarget)
	if imr.endpointAddrs.inflight(udpTarget) == nil {
		t.Fatal("setup: the udp target's lookup is not running")
	}
	serverMap := map[string]*cache.AuthServer{pathNS: server}
	tried := map[passTuple]bool{{server, "192.0.2.1", 0, core.TransportDoT}: true}

	waited := watchForWait(t)
	sel := imr.anotherPassAfter(context.Background(), &signalWaitBudget{}, "example.", dns.TypeA, serverMap, edns0.PrivacyStrict, tried)
	if sel != nil {
		t.Errorf("next pass %+v, want none", sel.tuples)
	}
	if waited.Load() {
		t.Error("the strict pass waited for the lookup of a udp endpoint's target")
	}
}

// The wait takes on a lookup that its own readiness check started
// (CodeRabbit on #1147): target A's lookup is running and B's retry mark runs
// out while the pass waits. A's lookup ends without an address, and the
// selection made then starts B's lookup but finds no tuple yet; the pass
// waits for B rather than giving up, and the next pass goes to B.
func TestTheWaitTakesOnALookupItsReadinessCheckStarted(t *testing.T) {
	imr, _, _, _, _ := endpointTestRig(t)
	imr.Tuning.Discovery.StrictWait = 2 * time.Second
	const targetA, targetB = "a.target.example.", "b.target.example."
	ns1 := redirectedServerTo("ns1.example.", "192.0.2.1", core.TransportDoT, targetA)
	ns2 := redirectedServerTo("ns2.example.", "192.0.2.2", core.TransportDoT, targetB)
	releaseA := make(chan struct{})
	saved := endpointAddrLookupHook
	endpointAddrLookupHook = func(_ *Imr, target string) ([]string, time.Time) {
		if target == targetA {
			<-releaseA
			return nil, time.Time{}
		}
		return []string{"192.0.2.54"}, time.Now().Add(time.Hour)
	}
	t.Cleanup(func() { endpointAddrLookupHook = saved })
	imr.endpointAddrs.finish(targetB, nil, time.Now(), nil) // B failed a moment ago
	imr.startEndpointLookup(targetA)
	var once sync.Once
	savedWait := anotherPassWaitHook
	anotherPassWaitHook = func() {
		once.Do(func() {
			// B's retry mark runs out, and A's lookup ends.
			imr.endpointAddrs.mu.Lock()
			delete(imr.endpointAddrs.retry, core.CanonicalizeName(targetB))
			imr.endpointAddrs.mu.Unlock()
			close(releaseA)
		})
	}
	t.Cleanup(func() {
		anotherPassWaitHook = savedWait
		once.Do(func() { close(releaseA) })
	})
	serverMap := map[string]*cache.AuthServer{"ns1.example.": ns1, "ns2.example.": ns2}
	tried := map[passTuple]bool{
		{ns1, "192.0.2.1", 0, core.TransportDoT}: true,
		{ns2, "192.0.2.2", 0, core.TransportDoT}: true,
	}

	sel := imr.anotherPassAfter(context.Background(), &signalWaitBudget{}, "example.", dns.TypeA, serverMap, edns0.PrivacyStrict, tried)
	if sel == nil || len(sel.tuples) != 1 || sel.tuples[0].Server != ns2 {
		t.Fatalf("next pass %+v, want ns2's DoT tuple to target B", sel)
	}
	if d, _ := imr.attemptKey(context.Background(), ns2, sel.zone, "192.0.2.2", core.TransportDoT, false); !d.redirect || d.addr != "192.0.2.54" {
		t.Errorf("the next pass dials %+v, want target B", d)
	}
}

// A selector that read a target stale claims no lookup once another lookup
// has refreshed it meanwhile (CodeRabbit on #1147): here the refresh failed
// the A that had run out and renewed the AAAA, so no family is due until the
// A's retry time.
func TestAnOutdatedStaleReadingClaimsNoLookup(t *testing.T) {
	var tr endpointAddrTracker
	now := time.Now()
	tr.finishLookup(dotTarget, []familyLookup{
		{family: cache.FamilyV4, addrs: []string{"192.0.2.53"}, expire: now.Add(time.Minute)},
		{family: cache.FamilyV6, addrs: []string{"2001:db8::53"}, expire: now.Add(time.Hour)},
	}, now, nil)
	later := now.Add(2 * time.Minute)
	if _, _, _, stale := tr.get(dotTarget, later); !stale {
		t.Fatal("setup: the target is not stale once its A has run out")
	}
	// Another selector's refresh runs first.
	if !began(tr.begin(dotTarget, later)) {
		t.Fatal("setup: the other refresh could not be claimed")
	}
	tr.finishLookup(dotTarget, []familyLookup{
		{family: cache.FamilyV4, failed: true},
		{family: cache.FamilyV6, addrs: []string{"2001:db8::54"}, expire: later.Add(time.Hour)},
	}, later, nil)
	if fams, ok := tr.begin(dotTarget, later); ok {
		t.Errorf("a lookup of %v was claimed on the outdated stale reading, before the A's retry time", fams)
	}
	if !began(tr.begin(dotTarget, later.Add(endpointAddrRetry))) {
		t.Error("the A's lookup could not be claimed at its retry time")
	}
}

// The refresh of a family that ran out leaves a failed family out until its
// retry time (CodeRabbit on #1147): here the A failed, and the AAAA runs out
// before the A's retry time; the refresh queries the AAAA alone, and the A
// keeps its retry time.
func TestARefreshOfOneFamilyLeavesAFailedOneToItsRetry(t *testing.T) {
	imr, _, _, _, _ := endpointTestRig(t)
	now := time.Now()
	failedAt := now.Add(-10 * time.Second)
	first := []familyLookup{
		{family: cache.FamilyV4, failed: true},
		{family: cache.FamilyV6, addrs: []string{"2001:db8::53"}, expire: now.Add(-time.Second)},
	}
	var tr endpointAddrTracker
	tr.finishLookup(dotTarget, first, failedAt, nil)
	if fams, ok := tr.begin(dotTarget, now); !ok || !slices.Equal(fams, []cache.AddressFamily{cache.FamilyV6}) {
		t.Fatalf("the refresh queries %v (claimed %v), want the AAAA alone", fams, ok)
	}

	imr.endpointAddrs.finishLookup(dotTarget, first, failedAt, nil)

	// The lookup is held until the test has its completion channel: one
	// that ended first would leave no channel to take.
	looked := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	saved := endpointAddrLookupHook
	endpointAddrLookupHook = func(*Imr, string) ([]string, time.Time) {
		looked <- struct{}{}
		<-release
		return []string{"192.0.2.53", "2001:db8::54"}, time.Now().Add(time.Hour)
	}
	t.Cleanup(func() { endpointAddrLookupHook = saved })
	imr.startEndpointLookup(dotTarget)
	running := imr.endpointAddrs.inflight(dotTarget)
	if running == nil {
		t.Fatal("the refresh was not started")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-looked:
	case <-time.After(5 * time.Second):
		t.Fatal("the refresh never queried")
	}
	select {
	case <-running:
	case <-time.After(5 * time.Second):
		t.Fatal("the refresh never ended")
	}
	imr.endpointAddrs.mu.Lock()
	v4 := *imr.endpointAddrs.entries[core.CanonicalizeName(dotTarget)].fams[cache.FamilyV4]
	imr.endpointAddrs.mu.Unlock()
	if len(v4.addrs) != 0 || !v4.retryAt.Equal(failedAt.Add(endpointAddrRetry)) {
		t.Errorf("the A after the AAAA's refresh: %+v, want no address and its retry time kept", v4)
	}
	if _, addrs, ok, _ := imr.endpointAddrs.get(dotTarget, time.Now()); !ok || len(addrs) != 1 || addrs[0] != "2001:db8::54" {
		t.Errorf("after the refresh: %v known %v, want the new AAAA", addrs, ok)
	}

	// The lookup itself queries only the families it is given.
	put := func(rr dns.RR) {
		name := rr.Header().Name
		imr.Cache.Set(name, rr.Header().Rrtype, &cache.CachedRRset{Name: name, RRtype: rr.Header().Rrtype,
			Context: cache.ContextAnswer, State: cache.ValidationStateSecure, Ttl: 3600,
			Expiration: time.Now().Add(time.Hour), RRset: &core.RRset{Name: name, Class: dns.ClassINET,
				RRtype: rr.Header().Rrtype, RRs: []dns.RR{rr}}})
	}
	put(mustRR(t, dotTarget+` 3600 IN A 192.0.2.53`))
	put(mustRR(t, dotTarget+` 3600 IN AAAA 2001:db8::54`))
	if results := imr.lookupEndpointAddrs(dotTarget, []cache.AddressFamily{cache.FamilyV6}); len(results) != 1 || results[0].family != cache.FamilyV6 {
		t.Errorf("a lookup of the AAAA alone gave %v", results)
	}
}

// An attempt whose endpoint has changed to an address of a suspect family
// since selection is not made (CodeRabbit on #1147): selection admitted the
// udp tuple for the target's IPv4 address, which then went into backoff, so
// udp gives way to the server's own IPv6 address, and IPv6 is suspect with no
// probe reserved for it. A tuple selection admitted as an IPv6 probe is
// still sent there.
func TestAnAttemptWhoseFamilyTurnedSuspectIsNotMade(t *testing.T) {
	imr, _, _, do53, q := endpointTestRig(t)
	reply := new(dns.Msg)
	reply.SetReply(q)
	do53.Set("example.", "2001:db8::1", core.FakeResponse{Msg: reply})
	server := redirectedServerTo("ns6.example.", "2001:db8::1", core.TransportDo53, dotTarget)
	imr.FamilyTracker = cache.NewFamilyTracker(10*time.Minute, 10*time.Minute, time.Hour, 1)
	imr.FamilyTracker.RecordResult("2001:db8::99", false)
	if !imr.FamilyTracker.IsSuspect(cache.FamilyV6) {
		t.Fatal("setup: IPv6 is not suspect")
	}
	imr.endpointAddrs.set(dotTarget, []string{"192.0.2.53"}, time.Now().Add(time.Hour))
	_, _, tuples := imr.prioritizeServers("example.", dns.TypeA, map[string]*cache.AuthServer{"ns6.example.": server}, edns0.PrivacyNone)
	if len(tuples) != 1 || tuples[0].Transport != core.TransportDo53 || tuples[0].Family != cache.FamilyV4 {
		t.Fatalf("selection %+v, want the udp tuple, decided for IPv4", tuples)
	}
	targetServer(t, imr, dotTarget).RecordEndpointAddrFailure("192.0.2.53", 1234, core.TransportDo53, errors.New("read: connection refused"))

	ctx := context.Background()
	if _, _, _, _, err := imr.tryServer(ctx, server, nil, "2001:db8::1", core.TransportDo53, q, "example.", dns.TypeA, false, cache.ClassNone, attemptSelection{family: tuples[0].Family}); err == nil {
		t.Error("the attempt was made")
	}
	if got := lastDial(do53); got != "" {
		t.Errorf("dialed %s, an address of the suspect family", got)
	}
	_, _, _, ep, err := imr.tryServer(ctx, server, nil, "2001:db8::1", core.TransportDo53, q, "example.", dns.TypeA, false, cache.ClassNone, attemptSelection{family: cache.FamilyV6, probe: true})
	if err != nil || ep.addr != "2001:db8::1" {
		t.Errorf("the IPv6 probe: %+v %v, want it sent to the server's own address", ep, err)
	}
}

// releaseOnWait has anotherPassAfter close release when its wait begins
// (anotherPassWaitHook), so that a lookup held on release ends only once the
// pass has collected it and found no tuple usable. release is closed at the
// end of the test if the wait never began.
func releaseOnWait(t *testing.T, release chan struct{}) {
	t.Helper()
	var once sync.Once
	saved := anotherPassWaitHook
	anotherPassWaitHook = func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() {
		anotherPassWaitHook = saved
		once.Do(func() { close(release) })
	})
}

// A target whose only address is of a suspect family is not dropped
// (CodeRabbit on #1147): selection lets its tuple through as that family's
// recovery probe, as it does a nameserver's own address, and the attempt
// dials it. A tuple selection decided on another family does not.
func TestASuspectTargetAddressIsProbed(t *testing.T) {
	imr, server, dot, _, q := endpointTestRig(t)
	server.SetAddrs([]string{"192.0.2.1"})
	imr.FamilyTracker = cache.NewFamilyTracker(10*time.Minute, 10*time.Minute, time.Hour, 1)
	imr.FamilyTracker.RecordResult("192.0.2.99", false)
	if !imr.FamilyTracker.IsSuspect(cache.FamilyV4) {
		t.Fatal("setup: IPv4 is not suspect")
	}
	imr.endpointAddrs.set(dotTarget, []string{"192.0.2.53"}, time.Now().Add(time.Hour))
	serverMap := map[string]*cache.AuthServer{pathNS: server}

	_, _, tuples := imr.prioritizeServers("example.", dns.TypeA, serverMap, edns0.PrivacyStrict)
	if len(tuples) != 1 || tuples[0].Transport != core.TransportDoT || tuples[0].Family != cache.FamilyV4 {
		t.Fatalf("selection %+v, want the DoT tuple to the target as the IPv4 probe", tuples)
	}
	if imr.FamilyTracker.ShouldProbe(cache.FamilyV4) {
		t.Error("selection did not reserve the IPv4 probe")
	}
	ctx := context.Background()
	if _, _, _, _, err := imr.tryServer(ctx, server, nil, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone, attemptSelection{family: cache.FamilyV6}); err == nil {
		t.Error("a tuple decided for IPv6 dialed the target's suspect IPv4 address")
	}
	_, _, _, ep, err := imr.tryServer(ctx, server, nil, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone, attemptSelection{family: tuples[0].Family, probe: tuples[0].Probe})
	if err != nil || ep.addr != "192.0.2.53" || lastDial(dot) != "192.0.2.53:1234" {
		t.Errorf("the probe: %+v %v, dialed %q; want the target's address", ep, err, lastDial(dot))
	}
}

// A signal wait keeps its time beside a target lookup (CodeRabbit on #1147):
// with a redirected nameserver whose target's lookup runs past the budget,
// and a nameserver with no signal yet, the two waits run side by side. The
// signal lookup the wait starts comes in within the budget and is used,
// rather than being started only once the target wait has spent it.
func TestASignalWaitKeepsItsTimeBesideATargetLookup(t *testing.T) {
	imr, server, serverMap := newStrictTestImr(t, time.Second)
	ns1 := redirectedServerTo("ns1."+strictChildZone, "192.0.2.1", core.TransportDoT, dotTarget)
	ns1.RecordEndpointAddrFailure("192.0.2.1", 0, core.TransportDoT, errors.New("read: connection refused"))
	serverMap[cache.ServerKey(ns1.Name)] = ns1
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	saved := endpointAddrLookupHook
	endpointAddrLookupHook = func(*Imr, string) ([]string, time.Time) {
		<-release
		return nil, time.Time{}
	}
	t.Cleanup(func() { endpointAddrLookupHook = saved })
	imr.startEndpointLookup(dotTarget)
	// The signal comes in a moment after the wait starts its lookup.
	end := startSignalLookup(t, imr, server)
	var once sync.Once
	testHookSignalLookupStarted = func(owner string) {
		if owner == strictChildOwner {
			once.Do(func() { end(100*time.Millisecond, map[core.Transport]uint8{core.TransportDoT: 50}) })
		}
	}
	t.Cleanup(func() { testHookSignalLookupStarted = nil })

	sel := imr.anotherPassAfter(context.Background(), &signalWaitBudget{}, "www."+strictChildZone, dns.TypeA, serverMap, edns0.PrivacyStrict, map[passTuple]bool{})
	if sel == nil || len(sel.tuples) != 1 || sel.tuples[0].Server != server || sel.tuples[0].Transport != core.TransportDoT {
		t.Fatalf("next pass %+v, want DoT to the nameserver whose signal came in", sel)
	}
}

// An extra pass does not dial an endpoint the pass before tried (CodeRabbit on
// #1147): its selection left that endpoint out, but the signal changed back
// before the attempt, and the tuple would dial it again.
func TestAnExtraPassDoesNotRedialAnEndpointTriedBefore(t *testing.T) {
	imr, server, dot, _, q := endpointTestRig(t)
	server.SetAddrs([]string{"192.0.2.1"})
	serverMap := map[string]*cache.AuthServer{pathNS: server}
	// The pass before tried the default endpoint; the target's address has
	// come in since.
	tried := map[passTuple]bool{{server, "192.0.2.1", 0, core.TransportDoT}: true}
	imr.endpointAddrs.set(dotTarget, []string{"192.0.2.53"}, time.Now().Add(time.Hour))
	ctx := context.Background()
	sel := imr.anotherPassAfter(ctx, &signalWaitBudget{}, "example.", dns.TypeA, serverMap, edns0.PrivacyStrict, tried)
	if sel == nil || len(sel.tuples) != 1 || len(sel.tried) != 1 || !sel.tried[passTuple{server, "192.0.2.1", 0, core.TransportDoT}] {
		t.Fatalf("next pass %+v, want the DoT tuple to the target, with the endpoints the pass before tried", sel)
	}
	// The signal now sends DoT to the nameserver's own address again.
	installTransportMap(server, map[string]uint8{"dot": 30}, nil, nil, cache.SignalViaLookup,
		[]cache.SignalHop{{Owner: pathOwner, State: cache.ValidationStateSecure}})

	_, _, _, _, err := imr.tryServer(ctx, server, sel.zone, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone, attemptSelection{family: sel.tuples[0].Family, tried: sel.tried})
	var triedErr errEndpointTried
	if !errors.As(err, &triedErr) {
		t.Errorf("got %v, want the attempt refused as tried in the pass before", err)
	}
	if got := lastDial(dot); got != "" {
		t.Errorf("dialed %s again", got)
	}
}

// A family that failed is looked up at its retry time although a later
// refresh of the other family was denied and left the target without a live
// address (CodeRabbit on #1147): the target-wide retry that denial set holds
// back only a target with no family due.
func TestADueFamilyIsNotHeldBackByItsSiblingsDenial(t *testing.T) {
	var tr endpointAddrTracker
	t0 := time.Now()
	tr.finishLookup(dotTarget, []familyLookup{
		{family: cache.FamilyV4, failed: true},
		{family: cache.FamilyV6, addrs: []string{"2001:db8::53"}, expire: t0.Add(5 * time.Second)},
	}, t0, nil)
	refresh := t0.Add(6 * time.Second)
	if fams, ok := tr.begin(dotTarget, refresh); !ok || !slices.Equal(fams, []cache.AddressFamily{cache.FamilyV6}) {
		t.Fatalf("setup: the AAAA's refresh claimed %v %v, want the AAAA alone", fams, ok)
	}
	tr.finishLookup(dotTarget, []familyLookup{{family: cache.FamilyV6}}, refresh, nil)
	if began(tr.begin(dotTarget, t0.Add(20*time.Second))) {
		t.Error("a lookup was claimed with no family due")
	}
	fams, ok := tr.begin(dotTarget, t0.Add(endpointAddrRetry))
	if !ok || !slices.Contains(fams, cache.FamilyV4) {
		t.Errorf("at the A's retry time: %v %v, want the A looked up", fams, ok)
	}
}

// A pass does not wait for a target that only a nameserver selection may not
// query sends a transport to (CodeRabbit on #1147): here one on this host,
// with allow-loopback-nameservers not set.
func TestAPassDoesNotWaitForATargetOnlyAnExcludedNameserverReaches(t *testing.T) {
	imr, _, _, _, _ := endpointTestRig(t)
	imr.Options[ImrOptAllowLoopbackNameservers] = "false"
	imr.Tuning.Discovery.StrictWait = 300 * time.Millisecond
	loop := redirectedServerTo("ns9.example.", "127.0.0.9", core.TransportDoT, dotTarget)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	saved := endpointAddrLookupHook
	endpointAddrLookupHook = func(*Imr, string) ([]string, time.Time) {
		<-release
		return []string{"192.0.2.53"}, time.Now().Add(time.Hour)
	}
	t.Cleanup(func() { endpointAddrLookupHook = saved })
	imr.startEndpointLookup(dotTarget)
	serverMap := map[string]*cache.AuthServer{"ns9.example.": loop}

	waited := watchForWait(t)
	if sel := imr.anotherPassAfter(context.Background(), &signalWaitBudget{}, "example.", dns.TypeA, serverMap, edns0.PrivacyStrict, map[passTuple]bool{}); sel != nil {
		t.Errorf("next pass %+v, want none", sel.tuples)
	}
	if waited.Load() {
		t.Error("the pass waited for a target only a nameserver it may not query reaches")
	}
}

// A tuple selection decided on a family while it was healthy is not sent
// once that family has turned suspect (CodeRabbit on #1147): no probe was
// reserved for it. A tuple that holds the family's probe is.
func TestAFamilyThatTurnedSuspectIsDialedOnlyAsAProbe(t *testing.T) {
	imr, server, dot, _, q := endpointTestRig(t)
	server.SetAddrs([]string{"192.0.2.1"})
	imr.FamilyTracker = cache.NewFamilyTracker(10*time.Minute, 10*time.Minute, time.Hour, 1)
	imr.endpointAddrs.set(dotTarget, []string{"192.0.2.53"}, time.Now().Add(time.Hour))
	_, _, tuples := imr.prioritizeServers("example.", dns.TypeA, map[string]*cache.AuthServer{pathNS: server}, edns0.PrivacyStrict)
	if len(tuples) != 1 || tuples[0].Family != cache.FamilyV4 || tuples[0].Probe {
		t.Fatalf("selection %+v, want the DoT tuple decided for a healthy IPv4", tuples)
	}
	// Another query's failures make IPv4 suspect before the attempt.
	imr.FamilyTracker.RecordResult("192.0.2.99", false)
	if !imr.FamilyTracker.IsSuspect(cache.FamilyV4) {
		t.Fatal("setup: IPv4 is not suspect")
	}

	ctx := context.Background()
	_, _, _, _, err := imr.tryServer(ctx, server, nil, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone, attemptSelection{family: tuples[0].Family, probe: tuples[0].Probe})
	var suspect errEndpointSuspectFamily
	if !errors.As(err, &suspect) {
		t.Errorf("got %v, want the attempt refused for its suspect family", err)
	}
	if got := lastDial(dot); got != "" {
		t.Errorf("dialed %s with no probe reserved", got)
	}
	if _, _, _, ep, err := imr.tryServer(ctx, server, nil, "192.0.2.1", core.TransportDoT, q, "example.", dns.TypeA, false, cache.ClassNone, attemptSelection{family: cache.FamilyV4, probe: true}); err != nil || ep.addr != "192.0.2.53" {
		t.Errorf("the IPv4 probe: %+v %v, want it sent to the target", ep, err)
	}
}

// An attempt refused for its suspect family does not count as tried
// (CodeRabbit on #1147): nothing was sent, and the extra pass's selection
// decides on that family afresh, here letting the tuple through as its probe.
// Other attempts not made still count, under the server's own address.
func TestARefusalForASuspectFamilyIsNotCountedAsTried(t *testing.T) {
	imr, _, _, do53, q := endpointTestRig(t)
	reply := new(dns.Msg)
	reply.SetReply(q)
	do53.Set("example.", "2001:db8::1", core.FakeResponse{Msg: reply})
	server := redirectedServerTo("ns6.example.", "2001:db8::1", core.TransportDo53, dotTarget)
	serverMap := map[string]*cache.AuthServer{"ns6.example.": server}
	imr.FamilyTracker = cache.NewFamilyTracker(10*time.Minute, 10*time.Minute, time.Hour, 1)
	imr.FamilyTracker.RecordResult("2001:db8::99", false)
	imr.endpointAddrs.set(dotTarget, []string{"192.0.2.53"}, time.Now().Add(time.Hour))
	_, _, tuples := imr.prioritizeServers("example.", dns.TypeA, serverMap, edns0.PrivacyNone)
	if len(tuples) != 1 || tuples[0].Family != cache.FamilyV4 {
		t.Fatalf("selection %+v, want the udp tuple decided for IPv4", tuples)
	}
	// The target's address goes into backoff: udp gives way to the server's
	// own IPv6 address, whose family is suspect.
	targetServer(t, imr, dotTarget).RecordEndpointAddrFailure("192.0.2.53", 1234, core.TransportDo53, errors.New("read: connection refused"))
	ctx := context.Background()
	_, _, _, ep, err := imr.tryServer(ctx, server, nil, "2001:db8::1", core.TransportDo53, q, "example.", dns.TypeA, false, cache.ClassNone, attemptSelection{family: tuples[0].Family, probe: tuples[0].Probe})
	if key, ok := passTried(server, "2001:db8::1", core.TransportDo53, ep, err); ok {
		t.Fatalf("the refusal (%v) counts as tried: %+v", err, key)
	}
	if key, ok := passTried(server, "2001:db8::1", core.TransportDo53, endpointDial{}, errEndpointUnavailable{}); !ok || key != (passTuple{server, "2001:db8::1", 0, core.TransportDo53}) {
		t.Errorf("an endpoint not usable counts as %+v %v, want the server's own address tried", key, ok)
	}

	sel := imr.anotherPassAfter(ctx, &signalWaitBudget{}, "example.", dns.TypeA, serverMap, edns0.PrivacyNone, map[passTuple]bool{})
	if sel == nil || len(sel.tuples) != 1 || !sel.tuples[0].Probe || sel.tuples[0].Family != cache.FamilyV6 {
		t.Fatalf("next pass %+v, want the udp tuple as the IPv6 probe", sel)
	}
	if _, _, _, ep, err := imr.tryServer(ctx, server, sel.zone, "2001:db8::1", core.TransportDo53, q, "example.", dns.TypeA, false, cache.ClassNone, attemptSelection{family: sel.tuples[0].Family, probe: sel.tuples[0].Probe}); err != nil || ep.addr != "2001:db8::1" {
		t.Errorf("the IPv6 probe: %+v %v, want it sent to the server's own address", ep, err)
	}
}

// A udp endpoint whose target has only addresses of a suspect family gives
// way to the nameserver's own healthy address on port 53 (CodeRabbit on
// #1147): here IPv6 is suspect and its probe already spent, so the target
// cannot be let through, and the tuple used to be dropped instead.
func TestAUdpTargetThatCannotBeProbedGivesWayToPort53(t *testing.T) {
	imr, _, _, do53, q := endpointTestRig(t)
	server := redirectedServerTo("ns4.example.", "192.0.2.1", core.TransportDo53, dotTarget)
	imr.FamilyTracker = cache.NewFamilyTracker(10*time.Minute, 10*time.Minute, time.Hour, 1)
	imr.FamilyTracker.RecordResult("2001:db8::99", false)
	if !imr.FamilyTracker.IsSuspect(cache.FamilyV6) || !imr.FamilyTracker.ShouldProbe(cache.FamilyV6) {
		t.Fatal("setup: IPv6 is not suspect with its probe to spend")
	}
	imr.endpointAddrs.set(dotTarget, []string{"2001:db8::53"}, time.Now().Add(time.Hour))

	_, _, tuples := imr.prioritizeServers("example.", dns.TypeA, map[string]*cache.AuthServer{"ns4.example.": server}, edns0.PrivacyNone)
	if len(tuples) != 1 || tuples[0].Transport != core.TransportDo53 || tuples[0].Family != cache.FamilyV4 || tuples[0].Probe {
		t.Fatalf("selection %+v, want the udp tuple to the nameserver's healthy IPv4", tuples)
	}
	_, _, _, ep, err := imr.tryServer(context.Background(), server, nil, "192.0.2.1", core.TransportDo53, q, "example.", dns.TypeA, false, cache.ClassNone, attemptSelection{family: tuples[0].Family, probe: tuples[0].Probe})
	if err != nil || ep.redirect || ep.addr != "192.0.2.1" || lastDial(do53) != "192.0.2.1" {
		t.Errorf("the attempt: %+v %v, dialed %q; want the nameserver's own address on port 53", ep, err, lastDial(do53))
	}
}
