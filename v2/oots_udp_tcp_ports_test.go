/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * udp and tcp take a port (step S5 of the alternative-endpoint plan): a
 * record's port applies to udp and tcp as to every transport it names; the
 * do53 shorthand never takes one; forced TCP goes to the tcp endpoint, or to
 * port 53, never to the udp port; backoff and RTT are keyed by address, port
 * and transport. Design: the alternative-endpoint note, sections 2 and 3.
 */
package tdns

import (
	"context"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// A record's port applies to udp and tcp, on every path and in both RR orders.
func TestUDPAndTCPTakeAPort(t *testing.T) {
	checkEveryPathBothOrders(t, []string{
		pathOwner + ` 3600 IN SVCB 1 . oots="dot:10"`,
		pathOwner + ` 3600 IN SVCB 1 . port=5353 oots="udp:100"`,
		pathOwner + ` 3600 IN SVCB 1 . port=5354 oots="tcp:30"`,
	}, "oots w=dot:10,tcp:30,udp:100 p=tcp:5354,udp:5353")
	// One record for both, the natural case.
	checkEveryPathBothOrders(t, []string{
		pathOwner + ` 3600 IN SVCB 1 . port=5353 oots="tcp:100,udp:100"`,
	}, "oots w=tcp:100,udp:100 p=tcp:5353,udp:5353")
}

// The do53 shorthand carries no port: in a record with one it is ignored, and
// a record left with nothing is ignored whole. The ALPN path does the same.
func TestDo53IgnoredInARecordWithAPort(t *testing.T) {
	checkEveryPathBothOrders(t, []string{
		pathOwner + ` 3600 IN SVCB 1 . port=5353 oots="do53:40,dot:10"`,
	}, "oots w=dot:10 p=dot:5353")
	checkEveryPathBothOrders(t, []string{
		pathOwner + ` 3600 IN SVCB 1 . port=5353 oots="do53:40"`,
	}, "none")
	// Beside a record without a port, which keeps its do53.
	checkEveryPathBothOrders(t, []string{
		pathOwner + ` 3600 IN SVCB 1 . oots="do53:40"`,
		pathOwner + ` 3600 IN SVCB 1 . port=5353 oots="do53:0,doq:5"`,
	}, "oots w=doq:5,tcp:40,udp:40 p=doq:5353")
	checkEveryPathBothOrders(t, []string{
		pathOwner + ` 3600 IN SVCB 1 . alpn=do53,dot port=5353`,
	}, "alpn w=dot:100 p=dot:5353")
}

// Each transport dials its own port: udp's for Do53, and for forced TCP
// (Do53TCP, the large-KSK DNSKEY fetch) tcp's, or the default port 53 when no
// tcp endpoint is signalled, never udp's.
func TestForcedTCPNeverDialsTheUDPPort(t *testing.T) {
	const addr = "192.0.2.1"
	imr := &Imr{}
	// A server that offers cleartext only, its udp on port 5353, installed
	// the production way: the absence defaults put dot, doh and doq in
	// Transports at weight 0, which preferredDNSKEYTransport must not take
	// for offered.
	s := cache.NewAuthServer(ootsTestNS)
	applyTransportMapWithPorts(s, map[string]uint8{"udp": 100}, map[core.Transport]uint16{core.TransportDo53: 5353})
	if !slices.Contains(s.GetTransports(), core.TransportDoQ) {
		t.Fatalf("setup: DoQ at weight 0 is not in Transports (%v); the test no longer reaches the case", s.GetTransports())
	}
	if got := imr.preferredDNSKEYTransport(s); got != core.TransportDo53TCP {
		t.Fatalf("preferredDNSKEYTransport = %v, want Do53TCP for a server with no encrypted transport", got)
	}
	if got := s.DialAddr(addr, core.TransportDo53); got != addr+":5353" {
		t.Errorf("udp dials %q, want %s:5353", got, addr)
	}
	if got := s.DialAddr(addr, core.TransportDo53TCP); got != addr {
		t.Errorf("forced TCP dials %q with only a udp port signalled, want %s (the client's port 53)", got, addr)
	}
	applyTransportMapWithPorts(s, map[string]uint8{"udp": 100, "tcp": 0},
		map[core.Transport]uint16{core.TransportDo53: 5353, core.TransportDo53TCP: 5354})
	if got := s.DialAddr(addr, core.TransportDo53TCP); got != addr+":5354" {
		t.Errorf("forced TCP dials %q, want the tcp endpoint %s:5354, tcp:0 notwithstanding", got, addr)
	}
}

// Backoff and RTT are booked under the endpoint tried, its address and port: a
// udp endpoint on another port that fails does not back off the fallback on
// port 53, which then takes the attempts, and a changed port starts clean.
// Driven through tryServer and prioritizeServers.
func TestBackoffAndRTTKeyedByEndpoint(t *testing.T) {
	const addr = "127.0.0.1"
	pc, err := net.ListenPacket("udp", addr+":0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	_, ps, _ := net.SplitHostPort(pc.LocalAddr().String())
	pc.Close() // nothing listens there now
	closed, _ := strconv.Atoi(ps)

	imr := newTestImr(t)
	imr.Quiet = true
	c := core.NewDNSClient(core.TransportDo53, "53", nil)
	c.Timeout, c.DNSClientUDP.Timeout, c.DNSClientTCP.Timeout = time.Second, time.Second, time.Second
	imr.Cache.DNSClient[core.TransportDo53] = c

	s := cache.NewAuthServer(ootsTestNS)
	s.SetAddrs([]string{addr})
	applyTransportMapWithPorts(s, map[string]uint8{"udp": 100}, map[core.Transport]uint16{core.TransportDo53: uint16(closed)})
	m := new(dns.Msg)
	m.SetQuestion("www.example.", dns.TypeA)
	_, _, _, dial, err := imr.tryServer(context.Background(), s, nil, addr, core.TransportDo53, m, "www.example.", dns.TypeA, false, cache.ClassNone, attemptSelection{})
	if err == nil {
		t.Fatalf("tryServer to the closed port %d succeeded", closed)
	}
	endpoint := net.JoinHostPort(addr, ps)
	// The caller books the rcode outcome by the endpoint tryServer returns,
	// the one it tried.
	if got := dial.dialAddr(); got != endpoint || dial.keyPort != uint16(closed) {
		t.Errorf("tryServer returned %+v (dial %q), want %s", dial, got, endpoint)
	}
	if s.IsEndpointAddrAvailable(addr, uint16(closed), core.TransportDo53) {
		t.Errorf("%s is not backed off after it failed", endpoint)
	}
	if _, ok := s.GetEndpointAddrRTT(addr, uint16(closed), core.TransportDo53); !ok {
		t.Errorf("no RTT booked for %s", endpoint)
	}
	if !s.IsEndpointAddrAvailable(addr, 0, core.TransportDo53) {
		t.Error("the failure on the signalled port backed off the fallback on port 53")
	}
	if _, ok := s.GetEndpointAddrRTT(addr, 0, core.TransportDo53); ok {
		t.Error("the failure on the signalled port booked an RTT for port 53")
	}

	serverMap := map[string]*cache.AuthServer{ootsTestNS: s}
	hasDo53 := func() bool {
		_, _, tuples := imr.prioritizeServers("www.example.", dns.TypeA, serverMap, edns0.PrivacyNone)
		for _, tup := range tuples {
			if tup.Transport == core.TransportDo53 && tup.Addr == addr {
				return true
			}
		}
		return false
	}
	// The signalled endpoint is backed off: Do53 falls back to port 53.
	if !hasDo53() {
		t.Error("prioritizeServers does not offer the fallback on port 53 while the signalled endpoint is backed off")
	}
	if d, ok := imr.attemptKey(context.Background(), s, nil, addr, core.TransportDo53, false); !ok || d.addr != addr || d.keyPort != 0 {
		t.Errorf("the attempt goes to %s port %d (%v), want %s on port 53", d.addr, d.keyPort, ok, addr)
	}
	// The signal drops the port: the fallback on 53 is offered.
	applyTransportMapWithPorts(s, map[string]uint8{"udp": 100}, nil)
	if !hasDo53() {
		t.Error("prioritizeServers does not offer Do53 on port 53 once the signal drops the port")
	}
	// Another port starts clean.
	applyTransportMapWithPorts(s, map[string]uint8{"udp": 100}, map[core.Transport]uint16{core.TransportDo53: uint16(closed) ^ 1})
	if d, _ := imr.attemptKey(context.Background(), s, nil, addr, core.TransportDo53, false); d.keyPort != uint16(closed)^1 {
		t.Errorf("the attempt goes to port %d, want the changed port %d", d.keyPort, uint16(closed)^1)
	}
	if !hasDo53() {
		t.Error("prioritizeServers does not offer Do53 on a changed port")
	}
}

// The ports map takes udp and tcp, with the socket rules: udp takes its port
// on TCP too, for the retry, so dot or doh there is refused; udp and doq
// cannot share a UDP port; udp and tcp share one naturally. A published udp
// or tcp port is warned about when listeners.addresses does not listen on it.
func TestTransportSignalChecksUDPAndTCP(t *testing.T) {
	listen := ListenerPortsConf{DoT: []uint16{853}, DoQ: []uint16{853}, DoH: []uint16{443}}
	addrs := []string{"127.0.0.1:5353", "[::1]:5353"}
	for _, tc := range []struct {
		name    string
		conf    TransportConf
		wantErr string
		warns   int
	}{
		{"udp and tcp on one port", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"udp": 5353, "tcp": 5353}}, "", 0},
		{"udp and tcp need no weight in the signal", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"tcp": 5353}}, "", 0},
		{"tcp:0 with a port: forced TCP goes there", TransportConf{Type: "svcb", Signal: "tcp:0", Ports: map[string]uint16{"tcp": 5353}}, "", 0},
		{"udp:0 with a port: the last resort goes there", TransportConf{Type: "svcb", Signal: "udp:0", Ports: map[string]uint16{"udp": 5353}}, "", 0},
		{"standard port 53 counts as absent", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"udp": 53}}, "", 0},
		{"a udp port nothing listens on warns", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"udp": 5300}}, "", 1},
		{"dot on udp's port", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"udp": 5353, "dot": 5353}}, "both are TCP", 0},
		{"doh on tcp's port", TransportConf{Type: "svcb", Signal: "doh:10", Ports: map[string]uint16{"tcp": 8443, "doh": 8443}}, "both are TCP", 0},
		{"dot on 53 clashes with tcp", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"dot": 53}}, "both are TCP", 0},
		{"udp and doq on one port", TransportConf{Type: "svcb", Signal: "doq:10", Ports: map[string]uint16{"udp": 853}}, "both are UDP", 0},
		{"udp on doq's port, doq without weight", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"udp": 5353, "doq": 5353}}, "no weight", 0},
		{"do53 is still not a key", TransportConf{Type: "svcb", Signal: "dot:10", Ports: map[string]uint16{"do53": 5353}}, "ports.do53", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			warns, err := validateTransportSignal(tc.conf, listen, addrs)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("error %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("accepted, want an error with %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q, want %q in it", err, tc.wantErr)
			}
			if len(warns) != tc.warns {
				t.Errorf("warnings %q, want %d", warns, tc.warns)
			}
		})
	}
	if got := listenerAddressPorts([]string{"127.0.0.1:5354", "[::1]:53", "bare", "x:notaport"}); len(got) != 2 || got[0] != 5354 || got[1] != 53 {
		t.Errorf("listenerAddressPorts = %v, want [5354 53]", got)
	}
}

// config -> buildServerSVCB -> the resolver: udp and tcp on a port reach the
// resolver's dial addresses.
func TestUDPPortConfigReachesTheDial(t *testing.T) {
	rrs := buildSignalRRs(t, TransportConf{Type: "svcb", Signal: "do53:50,dot:10", Ports: map[string]uint16{"udp": 5353, "tcp": 5354}})
	imr := &Imr{Quiet: true}
	s := cache.NewAuthServer(pathNS)
	sm := map[string]*cache.AuthServer{cache.ServerKey(pathNS): s}
	pending := map[string]*svcbSignalSet{}
	for _, rr := range rrs {
		svcb, ok := rr.(*dns.SVCB)
		if !ok {
			t.Fatalf("published %T, want SVCB", rr)
		}
		imr.collectSVCBSignal(pending, pathNS, svcb)
	}
	if installed, _ := imr.installSVCBSignal(sm[cache.ServerKey(pathNS)], pending[cache.ServerKey(pathNS)], notConfigured); !installed {
		t.Fatalf("the published signal %v was not installed", rrs)
	}
	for tr, want := range map[core.Transport]string{
		core.TransportDo53:    "192.0.2.1:5353",
		core.TransportDo53TCP: "192.0.2.1:5354",
		core.TransportDoT:     "192.0.2.1",
	} {
		if got := s.DialAddr("192.0.2.1", tr); got != want {
			t.Errorf("%s dials %q, want %q", core.TransportToSignalToken[tr], got, want)
		}
	}
	if w := s.GetTransportWeights(); w[core.TransportDo53] != 50 || w[core.TransportDo53TCP] != 50 {
		t.Errorf("weights %v, want udp and tcp at do53's 50", w)
	}
}

// A DNSKEY bypass attempt is deduplicated by endpoint and transport: two
// servers on one address that signal different tcp ports are two attempts.
func TestDNSKEYAttemptKeyIsTheEndpoint(t *testing.T) {
	const addr = "192.0.2.1"
	imr := newTestImr(t)
	imr.dnskeyTransport = DNSKEYTransportTryEncrypted
	ctx := context.Background()
	a := cache.NewAuthServer("ns1.example.")
	applyTransportMapWithPorts(a, map[string]uint8{"udp": 100}, map[core.Transport]uint16{core.TransportDo53TCP: 5354})
	b := cache.NewAuthServer("ns2.example.")
	applyTransportMapWithPorts(b, map[string]uint8{"udp": 100}, map[core.Transport]uint16{core.TransportDo53TCP: 5355})
	c := cache.NewAuthServer("ns3.example.")
	applyTransportMapWithPorts(c, map[string]uint8{"udp": 100}, map[core.Transport]uint16{core.TransportDo53TCP: 5354})
	key := func(s *cache.AuthServer) cache.AddrXport {
		t.Helper()
		k, ok := imr.resolveDNSKEYAttempt(ctx, s, nil, addr).key()
		if !ok || k.Transport != core.TransportDo53TCP {
			t.Fatalf("%s: key %+v %v, want one over tcp", s.Name, k, ok)
		}
		return k
	}
	ka := key(a)
	if ka == key(b) {
		t.Errorf("one key for two tcp endpoints: %v", ka)
	}
	if kc := key(c); ka != kc {
		t.Errorf("two keys for one endpoint: %v and %v", ka, kc)
	}
}
