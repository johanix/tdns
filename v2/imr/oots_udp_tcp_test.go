/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The token split, receiving side (step S4 of the alternative-endpoint plan):
 * cleartext is udp and tcp, both 100 when absent; do53:N reads as udp:N and
 * tcp:N, and an explicit udp or tcp wins over it. udp maps to TransportDo53
 * and tcp to TransportDo53TCP. A tcp weight caps only the TCP the resolver
 * chooses on its own, and tdns chooses none. Design: the alternative-endpoint
 * note, sections 2 and 3.
 */
package imr

import (
	"fmt"
	"reflect"
	"slices"
	"testing"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
)

var allPrivacyLevels = []edns0.PrivacyLevel{edns0.PrivacyNone, edns0.PrivacyOpportunistic, edns0.PrivacyStrict}

// No weight makes the resolver choose TCP on its own: not tcp:100, not
// tcp:100 beside udp:0. Without PRIVACY, Do53 (UDP, retried over TCP after
// truncation) stays the last resort, udp:0 included: neither weight is a hard
// gate.
func TestTCPWeightNeverChoosesTCP(t *testing.T) {
	imr := &Imr{}
	for _, sig := range []string{"tcp:100", "tcp:100,udp:0", "udp:0,tcp:100,dot:30", "do53:0,tcp:100,doq:20", "tcp:0", "udp:0,tcp:0"} {
		s := cache.NewAuthServer(ootsTestNS)
		if !imr.applyTransportSignalToServer(s, sig) {
			t.Fatalf("%s: not applied", sig)
		}
		assertTCPNotChosen(t, sig, stateOf(s))
		ts, ws := s.GetTransportSignal()
		for _, level := range allPrivacyLevels {
			for i := 0; i < 200; i++ {
				if got := candidateTransports(s, fmt.Sprintf("q%d.example.", i), level); slices.Contains(got, core.TransportDo53TCP) {
					t.Fatalf("%s, privacy %v: candidates %v hold Do53TCP", sig, level, got)
				}
			}
			if _, ok := ExpectedShares(ts, ws, level)[core.TransportDo53TCP]; ok {
				t.Errorf("%s, privacy %v: expected shares give Do53TCP a share", sig, level)
			}
		}
		if got := candidateTransports(s, "www.example.", edns0.PrivacyNone); !slices.Contains(got, core.TransportDo53) {
			t.Errorf("%s: candidates %v, want Do53 as the last resort", sig, got)
		}
	}
}

// The weights a signal installs: do53 read as udp and tcp, an explicit entry
// winning over it, both defaulting to 100, and tcp held as Do53TCP's weight.
func TestUDPAndTCPWeightsInstalled(t *testing.T) {
	imr := &Imr{}
	for _, tc := range []struct {
		sig       string
		udp, tcp  uint8
		received  map[core.Transport]uint8
		chosenLen int
	}{
		{"dot:10", 100, 100, map[core.Transport]uint8{core.TransportDoT: 10}, 4},
		{"tcp:30", 100, 30, map[core.Transport]uint8{core.TransportDo53TCP: 30}, 4},
		{"do53:0", 0, 0, map[core.Transport]uint8{core.TransportDo53: 0, core.TransportDo53TCP: 0}, 4},
		{"do53:40,tcp:5", 40, 5, map[core.Transport]uint8{core.TransportDo53: 40, core.TransportDo53TCP: 5}, 4},
		{"do53:40,udp:90", 90, 40, map[core.Transport]uint8{core.TransportDo53: 90, core.TransportDo53TCP: 40}, 4},
	} {
		s := cache.NewAuthServer(ootsTestNS)
		if !imr.applyTransportSignalToServer(s, tc.sig) {
			t.Fatalf("%s: not applied", tc.sig)
		}
		st := stateOf(s)
		if st.Weights[core.TransportDo53] != tc.udp || st.Weights[core.TransportDo53TCP] != tc.tcp {
			t.Errorf("%s: weights %v, want udp %d tcp %d", tc.sig, st.Weights, tc.udp, tc.tcp)
		}
		if !reflect.DeepEqual(st.Received, tc.received) {
			t.Errorf("%s: received %v, want %v", tc.sig, st.Received, tc.received)
		}
		if len(st.Transports) != tc.chosenLen || st.Transports[0] != core.TransportDo53 {
			t.Errorf("%s: transports %v, want Do53 and the encrypted ones, not Do53TCP", tc.sig, st.Transports)
		}
	}
}

// The shorthand works across the records of one RRset: do53 in one record and
// an explicit tcp or udp in another combine, the explicit entry winning,
// whatever order the records arrive in and on every path.
func TestDo53ShorthandAcrossRecords(t *testing.T) {
	checkEveryPathBothOrders(t, []string{
		pathOwner + ` 3600 IN SVCB 1 . oots="do53:40,dot:10"`,
		pathOwner + ` 3600 IN SVCB 1 . oots="tcp:5"`,
	}, "oots w=dot:10,tcp:5,udp:40 p=")
	// The port applies to udp as to dot (S5); the do53 record has none.
	checkEveryPathBothOrders(t, []string{
		pathOwner + ` 3600 IN SVCB 1 . oots="do53:40"`,
		pathOwner + ` 3600 IN SVCB 1 . port=1234 oots="dot:10,udp:90"`,
	}, "oots w=dot:10,tcp:40,udp:90 p=dot:1234,udp:1234")
}

// A stub's configured signal is read the same way, and its tcp weight is not a
// transport the stub is queried over.
func TestStubSignalSplitsUDPAndTCP(t *testing.T) {
	const zone = "stub.example."
	imr := newTestImr(t)
	if err := imr.Cache.AddStub(zone, []cache.AuthServer{
		{Name: "ns." + zone, Addrs: []string{"127.0.0.1"}, TransportSignal: "do53:40,tcp:5,dot:10"},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	servers := imr.stubServers(zone)
	if len(servers) != 1 {
		t.Fatalf("stub servers %v, want one", servers)
	}
	st := stateOf(servers[0])
	assertTCPNotChosen(t, "stub", st)
	if st.Weights[core.TransportDo53] != 40 || st.Weights[core.TransportDo53TCP] != 5 || st.Weights[core.TransportDoT] != 10 {
		t.Errorf("stub weights %v, want udp 40 tcp 5 dot 10", st.Weights)
	}
	want := map[core.Transport]uint8{core.TransportDo53: 40, core.TransportDo53TCP: 5, core.TransportDoT: 10}
	if st.Source != "config" || !reflect.DeepEqual(st.Received, want) {
		t.Errorf("stub signal %v (%s), want %v (config)", st.Received, st.Source, want)
	}
}
