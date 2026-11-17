/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"log"
	"os"
	"sync"
	"testing"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// A nameserver's AuthServer is one instance shared by every zone that names
// it. Its transport state (Transports, Alpn, TransportWeights) is written when
// a transport signal arrives and when AddServers merges another instance of
// the same name into it, while every query that selects among its transports
// reads it. The signal writers and the readers used to touch those fields
// without the server's lock: -race reported them, and a weight merge during
// candidateTransports' range over the map could abort the process with
// "concurrent map iteration and map write" (#714).
func TestTransportSignalWhileServersArePrioritized(t *testing.T) {
	imr := newTestImr(t)
	const (
		zone   = "shared.test."
		nsname = "ns1.shared.test."
		rounds = 300
	)
	server := imr.Cache.GetOrCreateAuthServer(nsname)
	server.SetAddrs([]string{"192.0.2.1"})
	// Every signal below advertises an encrypted transport with a weight above
	// 1, so from here on a consistent view always has a strict candidate.
	applyAlpnSignalToServer(server, "dot")
	if err := imr.Cache.AddServers(zone, map[string]*cache.AuthServer{nsname: server}); err != nil {
		t.Fatalf("AddServers: %v", err)
	}
	serverMap := map[string]*cache.AuthServer{nsname: server}

	// The writers run until the readers are done, so the two always overlap:
	// writers that finish first leave nothing for -race to see.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		// Transport signals for the server: SVCB/TSYNC weights and ALPN lists.
		defer wg.Done()
		for i := 0; !stopped(stop); i++ {
			if i%2 == 0 {
				applyTransportMapToServer(server, map[string]uint8{"dot": 60, "doq": 30, "do53": 10})
			} else {
				applyAlpnSignalToServer(server, "doq,dot")
			}
		}
	}()
	go func() {
		// Another zone's referral names the same server and brings weights of
		// its own, which AddServers merges into the shared instance.
		defer wg.Done()
		for i := 0; !stopped(stop); i++ {
			other := cache.NewAuthServer(nsname)
			other.SetAlpn([]string{"dot"})
			other.SetTransportWeights(map[core.Transport]uint8{core.TransportDoT: uint8(20 + i%50)})
			if err := imr.Cache.AddServers(zone, map[string]*cache.AuthServer{nsname: other}); err != nil {
				t.Errorf("AddServers: %v", err)
				return
			}
		}
	}()
	// What queries do meanwhile.
	func() {
		defer close(stop)
		for i := 0; i < rounds; i++ {
			if _, _, tuples := imr.prioritizeServers("www."+zone, dns.TypeA, serverMap, edns0.PrivacyNone); len(tuples) == 0 {
				t.Errorf("round %d: no tuples at privacy none", i)
				return
			}
			if _, _, tuples := imr.prioritizeServers("www."+zone, dns.TypeA, serverMap, edns0.PrivacyStrict); len(tuples) == 0 {
				t.Errorf("round %d: no strict tuples, though every signal advertises an encrypted transport", i)
				return
			}
			if owners := tlsaOwnersForServer(zone, server); len(owners) == 0 {
				t.Errorf("round %d: no TLSA owners", i)
				return
			}
			if tr := imr.preferredDNSKEYTransport(server); tr != core.TransportDoQ && tr != core.TransportDoT {
				t.Errorf("round %d: DNSKEY transport %v, want DoQ or DoT", i, tr)
				return
			}
		}
	}()
	wg.Wait()
}

// A stub zone's servers are private instances, but they are live: queries
// to the stub apply transport signals and addresses to them while the stub
// list and status API read them.
func TestTransportSignalWhileStubStatusIsRead(t *testing.T) {
	const (
		zone   = "stubrace.test."
		nsname = "ns.stubrace.test."
		rounds = 300
	)
	c := cache.NewRRsetCache(log.New(os.Stderr, "test", log.LstdFlags), false, false)
	if err := c.AddStub(zone, []cache.AuthServer{
		{Name: nsname, Addrs: []string{"192.0.2.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	imr := &Imr{Cache: c, Quiet: true}
	imr.setZoneTable(nil, []string{zone}, nil)
	servers := imr.stubServers(zone)
	if len(servers) != 1 {
		t.Fatalf("stubServers(%s) = %d servers, want 1", zone, len(servers))
	}
	server := servers[0]

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stopped(stop); i++ {
			if i%2 == 0 {
				applyTransportMapToServer(server, map[string]uint8{"dot": 60, "do53": 40})
			} else {
				applyAlpnSignalToServer(server, "do53,doq")
			}
			server.AddAddr(fmt.Sprintf("198.51.100.%d", i%250+1))
		}
	}()
	func() {
		defer close(stop)
		for i := 0; i < rounds; i++ {
			if list := imr.StubZoneList(); len(list) != 1 || len(list[0].Servers) != 1 {
				t.Errorf("round %d: StubZoneList = %+v", i, list)
				return
			}
			if st := imr.StubZoneStatus(); len(st) != 1 || len(st[0].Servers) != 1 || len(st[0].Servers[0].Transports) == 0 {
				t.Errorf("round %d: StubZoneStatus = %+v", i, st)
				return
			}
		}
	}()
	wg.Wait()
}

// stopped reports whether stop has been closed.
func stopped(stop <-chan struct{}) bool {
	select {
	case <-stop:
		return true
	default:
		return false
	}
}
