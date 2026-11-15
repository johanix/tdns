/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"testing"

	core "github.com/johanix/tdns/v2/core"
)

// A signal's ports and targets become one endpoint per transport. Do53 gets
// none, and a target of "." is the nameserver itself. A redirected transport
// is dialed through its endpoint, so DialAddr leaves the server's own address
// at the usual port for it.
func TestEndpointsFromReceived(t *testing.T) {
	as := NewAuthServer("ns.example.")
	as.SetTransportSignal(nil, nil, nil, &ReceivedSignal{
		Source: "oots",
		Ports:  map[core.Transport]uint16{core.TransportDoT: 1234, core.TransportDoQ: 1235, core.TransportDo53: 553},
		Targets: map[core.Transport]string{
			core.TransportDoT: "dot-ns.example", core.TransportDoH: "doh-ns.example.",
			core.TransportDoQ: ".", core.TransportDo53: "udp-ns.example.",
		},
	})
	want := map[core.Transport]Endpoint{
		core.TransportDoT: {Target: "dot-ns.example.", Port: 1234},
		core.TransportDoH: {Target: "doh-ns.example."},
		core.TransportDoQ: {Port: 1235},
	}
	got := as.GetTransportEndpoints()
	if len(got) != len(want) {
		t.Fatalf("endpoints %v, want %v", got, want)
	}
	for tr, ep := range want {
		if got[tr] != ep {
			t.Errorf("%s: %v, want %v", core.TransportToString[tr], got[tr], ep)
		}
	}
	if ep := as.GetTransportEndpoint(core.TransportDo53); !ep.IsDefault() {
		t.Errorf("Do53 endpoint %v", ep)
	}
	if got := as.DialAddr("192.0.2.1", core.TransportDoT); got != "192.0.2.1" {
		t.Errorf("DialAddr for a redirected DoT: %q, want the bare address", got)
	}
	if got := as.DialAddr("192.0.2.1", core.TransportDoQ); got != "192.0.2.1:1235" {
		t.Errorf("DialAddr for DoQ on a port: %q", got)
	}
	if got := (Endpoint{Target: "dot-ns.example.", Port: 1234}).String(); got != "dot-ns.example.:1234" {
		t.Errorf("String %q", got)
	}
	if got := (Endpoint{Port: 853}).String(); got != ".:853" {
		t.Errorf("String %q", got)
	}

	// The next signal assigns no endpoint and clears them.
	as.SetTransportSignal(nil, nil, nil, &ReceivedSignal{Source: "oots"})
	if got := as.GetTransportEndpoints(); got != nil {
		t.Errorf("endpoints after a signal with none: %v", got)
	}
}

// The redirect counters are snapshotted and taken with the others.
func TestRedirectCounters(t *testing.T) {
	as := NewAuthServer("ns.example.")
	as.IncrementRedirectedCounter(core.TransportDoT)
	as.AddIgnoredRedirects(2)
	as.AddIgnoredRedirects(0)
	if st := as.SnapshotTransportStats(); st.Redirected[core.TransportDoT] != 1 || st.IgnoredRedirects != 2 {
		t.Errorf("snapshot %v %d", st.Redirected, st.IgnoredRedirects)
	}
	if st := as.TakeTransportStats(); st.Redirected[core.TransportDoT] != 1 || st.IgnoredRedirects != 2 {
		t.Errorf("take %v %d", st.Redirected, st.IgnoredRedirects)
	}
	if st := as.SnapshotTransportStats(); st.Redirected != nil || st.IgnoredRedirects != 0 {
		t.Errorf("after take %v %d", st.Redirected, st.IgnoredRedirects)
	}
}

// Backoff and RTT at a port are kept apart from the same address at port 0.
func TestEndpointAddrKeys(t *testing.T) {
	as := NewAuthServer("ns.example.")
	as.RecordEndpointAddrFailure("192.0.2.1", 1234, core.TransportDoT, nil)
	if as.IsEndpointAddrAvailable("192.0.2.1", 1234, core.TransportDoT) {
		t.Error("not backed off at its port")
	}
	if !as.IsAddrXportAvailable("192.0.2.1", core.TransportDoT) {
		t.Error("port 0 backed off by a failure at 1234")
	}
	as.RecordEndpointAddrSuccess("192.0.2.1", 1234, core.TransportDoT)
	if !as.IsEndpointAddrAvailable("192.0.2.1", 1234, core.TransportDoT) {
		t.Error("success did not clear the backoff")
	}
}
