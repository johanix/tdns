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
	"strings"
	"testing"

	imrcore "github.com/johanix/tdns/v2/imr"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

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
	imr := &Imr{Imr: &imrcore.Imr{Quiet: true}}
	s := cache.NewAuthServer(pathNS)
	var svcbs []*dns.SVCB
	for _, rr := range rrs {
		svcb, ok := rr.(*dns.SVCB)
		if !ok {
			t.Fatalf("published %T, want SVCB", rr)
		}
		svcbs = append(svcbs, svcb)
	}
	if !imr.InstallSVCBSignal(s, svcbs) {
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
