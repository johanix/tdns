/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// Zone lameness in the endpoint model (CodeRabbit on #1118). A lame answer is
// booked at the address and port the attempt dialed, and holds back only that
// endpoint: a target address that refuses does not hold back the target's
// other addresses or the nameserver's own address, and a lame udp endpoint on
// 5353 does not hold back port 53 (design 2026-11-14, section 3). Port 53 is
// still held back by a lameness of its own.

const (
	epLameZone   = "lame.example."
	epLameNS     = "ns." + epLameZone
	epLameOwner  = "_dns." + epLameNS
	epLameTarget = "dot." + epLameZone
	epLameNSAddr = "192.0.2.1"
)

// epLameZoneImr is a resolver that knows epLameZone, served by epLameNS at
// epLameNSAddr, and a cache zone for it whose lameness the tests read.
func epLameZoneImr(t *testing.T) (*Imr, *cache.AuthServer, *cache.Zone, map[string]*cache.AuthServer) {
	t.Helper()
	imr := newTestImr(t)
	server := imr.Cache.GetOrCreateAuthServer(epLameNS)
	server.AddAddr(epLameNSAddr)
	serverMap := map[string]*cache.AuthServer{cache.ServerKey(epLameNS): server}
	if err := imr.Cache.AddServers(epLameZone, serverMap); err != nil {
		t.Fatalf("setup: AddServers: %v", err)
	}
	zone := &cache.Zone{ZoneName: epLameZone}
	imr.Cache.ZoneMap.Set(epLameZone, zone)
	return imr, server, zone, serverMap
}

// redirectTo installs a signal, validated Secure, that sends t to epLameTarget
// at port, with weights.
func redirectTo(server *cache.AuthServer, weights map[string]uint8, t core.Transport, port uint16) {
	installTransportMap(server, weights, map[core.Transport]uint16{t: port},
		map[core.Transport]string{t: epLameTarget}, cache.SignalViaLookup,
		[]cache.SignalHop{{Owner: epLameOwner, State: cache.ValidationStateSecure}})
}

func refusedReply(qname string, qtype uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(qname, qtype)
	r := new(dns.Msg)
	r.SetRcode(q, dns.RcodeRefused)
	return r
}

func dialedAddrs(f *core.FakeDNSClient) map[string]bool {
	out := map[string]bool{}
	for _, c := range f.Calls() {
		out[c.Addr] = true
	}
	return out
}

// A query whose DoT goes to a target with two addresses, both refusing. The
// first refusal is booked at that target address and port, so the query's
// next pass goes to the target's other address. Booked at the nameserver's
// own tuple, as before, it held back every target address, and the query
// ended after one attempt.
func TestATargetThatRefusesHoldsBackOnlyItself(t *testing.T) {
	imr, server, zone, serverMap := epLameZoneImr(t)
	qname := "www." + epLameZone
	dot := core.NewFakeDNSClient(core.TransportDoT)
	for _, a := range []string{"192.0.2.53:1234", "[2001:db8::53]:1234"} {
		dot.Set(qname, a, core.FakeResponse{Msg: refusedReply(qname, dns.TypeA)})
	}
	imr.Cache.DNSClient = map[core.Transport]core.DNSClienter{core.TransportDoT: dot}
	redirectTo(server, map[string]uint8{"dot": 50}, core.TransportDoT, 1234)
	imr.endpointAddrs.set(epLameTarget, []string{"192.0.2.53", "2001:db8::53"}, time.Now().Add(time.Hour))

	_, _, _, _, _ = imr.IterativeDNSQuery(context.Background(), qname, dns.TypeA, serverMap, true, edns0.PrivacyStrict)

	dialed := dialedAddrs(dot)
	if !dialed["192.0.2.53:1234"] || !dialed["[2001:db8::53]:1234"] {
		t.Errorf("dialed %v, want both target addresses in one query", dialed)
	}
	for _, a := range []string{"192.0.2.53", "2001:db8::53"} {
		if zone.IsZoneEndpointAvailable(a, 1234, core.TransportDoT) {
			t.Errorf("the refusal from %s is not booked at its address and port", a)
		}
	}
	if !zone.IsZoneEndpointAvailable(epLameNSAddr, 0, core.TransportDoT) {
		t.Error("a target's refusal was booked at the nameserver's own address")
	}
}

// udp sent to a target whose one address is lame for the zone falls back to
// the nameserver's own address on port 53, and selection offers it. Lame on
// port 53 as well, udp is not offered.
func TestALameUDPTargetFallsBackToPort53(t *testing.T) {
	imr, server, zone, serverMap := epLameZoneImr(t)
	redirectTo(server, map[string]uint8{"udp": 100}, core.TransportDo53, 5353)
	imr.endpointAddrs.set(epLameTarget, []string{"192.0.2.53"}, time.Now().Add(time.Hour))
	ctx := context.Background()

	if d, err := imr.endpointFor(ctx, server, zone, epLameNSAddr, core.TransportDo53); err != nil || !d.redirect || d.addr != "192.0.2.53" || d.keyPort != 5353 {
		t.Fatalf("before the refusal: %+v %v, want the target on 5353", d, err)
	}
	zone.RecordZoneEndpointFailureForRcode("192.0.2.53", 5353, core.TransportDo53, dns.RcodeRefused, false)
	d, err := imr.endpointFor(ctx, server, zone, epLameNSAddr, core.TransportDo53)
	if err != nil || d.redirect || d.addr != epLameNSAddr || d.port != 0 || d.keyPort != 0 {
		t.Errorf("the target lame: %+v %v, want the nameserver on port 53", d, err)
	}
	if d, _ := imr.endpointFor(ctx, server, nil, epLameNSAddr, core.TransportDo53); !d.redirect {
		t.Errorf("without the zone: %+v, want the target (the lameness is the zone's)", d)
	}
	if !hasTuple(imr, serverMap, epLameNSAddr, core.TransportDo53) {
		t.Error("selection does not offer udp on port 53 while the target is lame")
	}
	zone.RecordZoneEndpointFailureForRcode(epLameNSAddr, 0, core.TransportDo53, dns.RcodeRefused, false)
	if hasTuple(imr, serverMap, epLameNSAddr, core.TransportDo53) {
		t.Error("selection offers udp on port 53 while port 53 is lame too")
	}
}

// A udp endpoint at the nameserver's own name, on 5353, lame for the zone:
// the attempt goes to port 53, which selection offers while it is not lame
// itself. Before, the lameness on 5353 removed the tuple, and with one
// nameserver the zone had none until the backoff ran out.
func TestALameSignalledUDPPortFallsBackToPort53(t *testing.T) {
	imr, server, zone, serverMap := epLameZoneImr(t)
	applyTransportMapWithPorts(server, map[string]uint8{"udp": 100}, map[core.Transport]uint16{core.TransportDo53: 5353})
	ctx := context.Background()

	zone.RecordZoneEndpointFailureForRcode(epLameNSAddr, 5353, core.TransportDo53, dns.RcodeRefused, false)
	if d, ok := imr.attemptKey(ctx, server, zone, epLameNSAddr, core.TransportDo53, false); !ok || d.addr != epLameNSAddr || d.keyPort != 0 {
		t.Errorf("the attempt goes to %s port %d (%v), want %s on port 53", d.addr, d.keyPort, ok, epLameNSAddr)
	}
	if !hasTuple(imr, serverMap, epLameNSAddr, core.TransportDo53) {
		t.Error("selection does not offer port 53 while 5353 is lame")
	}
	zone.RecordZoneEndpointFailureForRcode(epLameNSAddr, 0, core.TransportDo53, dns.RcodeRefused, false)
	if hasTuple(imr, serverMap, epLameNSAddr, core.TransportDo53) {
		t.Error("selection offers port 53 while port 53 is lame too")
	}
}

func hasTuple(imr *Imr, serverMap map[string]*cache.AuthServer, addr string, t core.Transport) bool {
	_, _, tuples := imr.prioritizeServers("www."+epLameZone, dns.TypeA, serverMap, edns0.PrivacyNone)
	for _, tup := range tuples {
		if tup.Addr == addr && tup.Transport == t {
			return true
		}
	}
	return false
}

// A pass whose udp attempt on 5353 failed: the next attempt goes to port 53,
// an endpoint the pass did not try, so there is another pass. The tried set
// used to hold the tuple without its port, and the query ended without
// trying port 53.
func TestAnotherPassAfterAFailedSignalledPortTriesPort53(t *testing.T) {
	imr, server, _, serverMap := epLameZoneImr(t)
	applyTransportMapWithPorts(server, map[string]uint8{"udp": 100}, map[core.Transport]uint16{core.TransportDo53: 5353})
	server.RecordEndpointAddrFailure(epLameNSAddr, 5353, core.TransportDo53, errors.New("read: connection refused"))
	tried := map[passTuple]bool{{server, epLameNSAddr, 5353, core.TransportDo53}: true}

	sel := imr.anotherPassAfter(context.Background(), &signalWaitBudget{}, "www."+epLameZone, dns.TypeA, serverMap, edns0.PrivacyNone, tried)
	if sel == nil {
		t.Fatal("no further pass, although port 53 was never tried")
	}
	for _, tup := range sel.tuples {
		if d, _ := imr.attemptKey(context.Background(), tup.Server, sel.zone, tup.Addr, tup.Transport, false); tried[passTuple{d.server, d.addr, d.keyPort, tup.Transport}] {
			t.Errorf("the next pass holds a tried endpoint: %s port %d", d.addr, d.keyPort)
		}
	}
}

// Only tried endpoints left, on a suspect address family: no further pass,
// and the family's recovery probe is left for another query. The selection
// used to reserve the probe for the tried tuple and then drop it, which
// used it up for a probe interval.
func TestAnotherPassAfterLeavesTheProbeOfATriedTuple(t *testing.T) {
	imr, server, _, serverMap := epLameZoneImr(t)
	imr.FamilyTracker = cache.NewFamilyTracker(10*time.Minute, 10*time.Minute, time.Hour, 1)
	imr.FamilyTracker.RecordResult("192.0.2.99", false)
	if !imr.FamilyTracker.IsSuspect(cache.FamilyV4) {
		t.Fatal("setup: IPv4 is not suspect")
	}
	applyTransportMapToServer(server, map[string]uint8{"udp": 100})
	tried := map[passTuple]bool{{server, epLameNSAddr, 0, core.TransportDo53}: true}

	if sel := imr.anotherPassAfter(context.Background(), &signalWaitBudget{}, "www."+epLameZone, dns.TypeA, serverMap, edns0.PrivacyNone, tried); sel != nil {
		t.Fatalf("a further pass with only the tried tuple left: %+v", sel.tuples)
	}
	if !imr.FamilyTracker.ShouldProbe(cache.FamilyV4) {
		t.Error("the IPv4 probe was used up on a tuple the pass had tried")
	}
}

// A signal that names a transport's default port explicitly is the default
// endpoint's socket: its backoff and RTT are kept under port 0 with the
// default endpoint's. A client on another port keeps the named port apart.
func TestAnExplicitDefaultPortIsTheDefaultEndpoint(t *testing.T) {
	imr, server, _, serverMap := epLameZoneImr(t)
	ctx := context.Background()
	applyTransportMapWithPorts(server, map[string]uint8{"udp": 100, "dot": 50},
		map[core.Transport]uint16{core.TransportDo53: 53, core.TransportDoT: 853})
	for _, tr := range []core.Transport{core.TransportDo53, core.TransportDoT} {
		if d, ok := imr.attemptKey(ctx, server, nil, epLameNSAddr, tr, false); !ok || d.addr != epLameNSAddr || d.keyPort != 0 {
			t.Errorf("%s: kept under %s port %d (%v), want port 0", core.TransportToString[tr], d.addr, d.keyPort, ok)
		}
	}
	server.RecordEndpointAddrFailure(epLameNSAddr, 0, core.TransportDoT, nil)
	if hasTuple(imr, serverMap, epLameNSAddr, core.TransportDoT) {
		t.Error("a backoff on the default DoT endpoint does not hold back the same socket named as port 853")
	}

	imr.Cache.DNSClient[core.TransportDoT] = core.NewDNSClient(core.TransportDoT, "8853", nil)
	if d, _ := imr.attemptKey(ctx, server, nil, epLameNSAddr, core.TransportDoT, false); d.keyPort != 853 {
		t.Errorf("a client on 8853: port 853 kept under %d, want 853", d.keyPort)
	}
	applyTransportMapWithPorts(server, map[string]uint8{"dot": 50}, map[core.Transport]uint16{core.TransportDoT: 8853})
	if d, _ := imr.attemptKey(ctx, server, nil, epLameNSAddr, core.TransportDoT, false); d.keyPort != 0 {
		t.Errorf("a client on 8853: port 8853 kept under %d, want 0", d.keyPort)
	}
}

// Selection starts the lookup of a target whose addresses are not known,
// although the default endpoint is in backoff and the tuple is not offered:
// once the addresses are in, the transport goes to the target. Only
// tryServer used to start it, and it never ran for a tuple that was not
// offered. A default-endpoint lookup starts nothing.
func TestSelectionStartsTheTargetLookupBehindABackedOffDefault(t *testing.T) {
	imr, server, _, _, _ := endpointTestRig(t)
	server.SetAddrs([]string{"192.0.2.1"})
	server.RecordEndpointAddrFailure("192.0.2.1", 0, core.TransportDoT, nil)
	serverMap := map[string]*cache.AuthServer{pathNS: server}
	looked := make(chan string, 4)
	saved := endpointAddrLookupHook
	endpointAddrLookupHook = func(_ *Imr, target string) ([]string, time.Time) {
		looked <- target
		return []string{"192.0.2.53"}, time.Now().Add(time.Hour)
	}
	t.Cleanup(func() { endpointAddrLookupHook = saved })
	hasDoT := func(ctx context.Context) bool {
		_, _, tuples := imr.prioritizeServersFor(ctx, "example.", dns.TypeA, serverMap, edns0.PrivacyNone)
		for _, tup := range tuples {
			if tup.Transport == core.TransportDoT {
				return true
			}
		}
		return false
	}

	if hasDoT(withDefaultEndpoints(context.Background())) {
		t.Fatal("a default-endpoint lookup: DoT offered at the backed-off own address")
	}
	select {
	case target := <-looked:
		t.Fatalf("a default-endpoint lookup started the lookup of %s", target)
	case <-time.After(50 * time.Millisecond):
	}

	if hasDoT(context.Background()) {
		t.Fatal("the target's addresses unknown: DoT offered at the backed-off own address")
	}
	select {
	case target := <-looked:
		if target != dotTarget {
			t.Fatalf("looked up %s, want %s", target, dotTarget)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("selection did not start the target's lookup")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !hasDoT(context.Background()) {
		if time.Now().After(deadline) {
			t.Fatal("DoT not offered once the target's addresses were in")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A DNSKEY bypass attempt is recorded under the endpoint tryServer dialed,
// not the key it was checked against beforehand: the two differ when a
// target's addresses come in between, and recording the first would skip a
// later attempt at an endpoint never dialed. With no endpoint chosen, the
// key checked is recorded, unless tryServer refused the attempt for its
// suspect family (CodeRabbit on #1147): nothing was sent, and a later tuple
// that holds the family's probe must not find the key taken.
func TestDNSKEYTriedIsTheEndpointDialed(t *testing.T) {
	pre := cache.AddrXport{Addr: epLameNSAddr, Port: 0, Transport: core.TransportDoT}
	dialed := endpointDial{addr: "192.0.2.53", port: 1234, redirect: true, keyPort: 1234}
	if got, ok := dnskeyTried(pre, dialed, core.TransportDoT, errors.New("i/o timeout")); !ok || got != (cache.AddrXport{Addr: "192.0.2.53", Port: 1234, Transport: core.TransportDoT}) {
		t.Errorf("an attempt that dialed the target is recorded as %+v %v", got, ok)
	}
	if got, ok := dnskeyTried(pre, endpointDial{}, core.TransportDoT, errEndpointUnavailable{}); !ok || got != pre {
		t.Errorf("an attempt with no endpoint is recorded as %+v %v, want %+v", got, ok, pre)
	}
	if got, ok := dnskeyTried(pre, endpointDial{}, core.TransportDoT, errEndpointSuspectFamily{}); ok {
		t.Errorf("an attempt refused for its suspect family is recorded as %+v", got)
	}
}

// tryServer checks the endpoint it ends up with. udp went to a target that
// has since refused, so the attempt gives way to the nameserver's own
// address on port 53; at an address whose port 53 is backed off it makes no
// dial, and at one whose port 53 is usable it dials there.
func TestTryServerRechecksTheFinalEndpoint(t *testing.T) {
	imr, server, zone, _ := epLameZoneImr(t)
	server.AddAddr("192.0.2.2")
	redirectTo(server, map[string]uint8{"udp": 100}, core.TransportDo53, 5353)
	imr.endpointAddrs.set(epLameTarget, []string{"192.0.2.53"}, time.Now().Add(time.Hour))
	q := new(dns.Msg)
	q.SetQuestion("www."+epLameZone, dns.TypeA)
	reply := new(dns.Msg)
	reply.SetReply(q)
	do53 := core.NewFakeDNSClient(core.TransportDo53)
	for _, a := range []string{epLameNSAddr, "192.0.2.2"} {
		do53.Set("www."+epLameZone, a, core.FakeResponse{Msg: reply})
	}
	imr.Cache.DNSClient[core.TransportDo53] = do53
	zone.RecordZoneEndpointFailureForRcode("192.0.2.53", 5353, core.TransportDo53, dns.RcodeRefused, false)
	server.RecordEndpointAddrFailure(epLameNSAddr, 0, core.TransportDo53, errors.New("i/o timeout"))
	ctx := context.Background()

	_, _, _, _, err := imr.tryServer(ctx, server, zone, epLameNSAddr, core.TransportDo53, q, "www."+epLameZone, dns.TypeA, false, cache.ClassNone, attemptSelection{})
	if _, ok := err.(errEndpointUnavailable); !ok {
		t.Errorf("port 53 backed off: err %v, want errEndpointUnavailable", err)
	}
	if n := len(do53.Calls()); n != 0 {
		t.Fatalf("%d dial(s) to an endpoint that is backed off", n)
	}
	_, _, _, ep, err := imr.tryServer(ctx, server, zone, "192.0.2.2", core.TransportDo53, q, "www."+epLameZone, dns.TypeA, false, cache.ClassNone, attemptSelection{})
	if err != nil || ep.addr != "192.0.2.2" || ep.port != 0 || lastDial(do53) != "192.0.2.2" {
		t.Errorf("port 53 usable: %+v %v, dialed %q, want 192.0.2.2 on port 53", ep, err, lastDial(do53))
	}
}

// A DNSKEY bypass attempt is recorded under the transport tryServer dialed,
// which reads the preference again: a change between the query loop's reading
// and tryServer's must not leave the attempt recorded under a transport never
// dialed, so that the next tuple, which reads the new preference, dials the
// same endpoint again.
func TestDNSKEYAttemptIsRecordedUnderTheTransportDialed(t *testing.T) {
	const ns = "ns.dnskey.example."
	const addr = "192.0.2.53"
	imr := newTestImr(t)
	imr.dnskeyTransport = DNSKEYTransportTryEncrypted
	server := imr.Cache.GetOrCreateAuthServer(ns)
	server.AddAddr(addr)
	applyTransportMapToServer(server, map[string]uint8{"dot": 50, "doq": 50})
	serverMap := map[string]*cache.AuthServer{cache.ServerKey(ns): server}
	clients := map[core.Transport]*core.FakeDNSClient{}
	imr.Cache.DNSClient = map[core.Transport]core.DNSClienter{}
	for _, tr := range []core.Transport{core.TransportDo53, core.TransportDo53TCP, core.TransportDoT, core.TransportDoQ} {
		f := core.NewFakeDNSClient(tr)
		f.Set("dnskey.example.", addr, core.FakeResponse{Err: errors.New("i/o timeout")})
		clients[tr] = f
		imr.Cache.DNSClient[tr] = f
	}
	reads := 0
	saved := preferredDNSKEYTransportHook
	preferredDNSKEYTransportHook = func(*Imr, *cache.AuthServer) core.Transport {
		reads++
		if reads == 1 {
			return core.TransportDoT
		}
		return core.TransportDoQ
	}
	t.Cleanup(func() { preferredDNSKEYTransportHook = saved })

	_, _, _, _, _ = imr.IterativeDNSQuery(context.Background(), "dnskey.example.", dns.TypeDNSKEY, serverMap, true, edns0.PrivacyNone)

	if n := len(clients[core.TransportDoQ].Calls()); n != 1 {
		t.Errorf("DoQ dialed %d times, want 1: the attempt was recorded under a transport never dialed", n)
	}
	if n := len(clients[core.TransportDoT].Calls()); n != 0 {
		t.Errorf("DoT dialed %d times, want 0", n)
	}
}
