/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"testing"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
)

// The dump shows where a server's signal arrived and the state of each RRset
// it was read from, and nothing for a signal that did not come from an SVCB
// RRset.
func TestFormatSignalValidation(t *testing.T) {
	as := cache.NewAuthServer("ns.example.")
	if got := formatSignalValidation(as); got != "" {
		t.Errorf("no signal: %q", got)
	}
	weights := map[core.Transport]uint8{core.TransportDoT: 30}
	as.SetTransportSignal([]core.Transport{core.TransportDoT}, []string{"dot"}, weights,
		&cache.ReceivedSignal{Source: "oots", Weights: weights})
	if got := formatSignalValidation(as); got != "" {
		t.Errorf("signal with no path: %q", got)
	}
	as.SetTransportSignal([]core.Transport{core.TransportDoT}, []string{"dot"}, weights,
		&cache.ReceivedSignal{Source: "oots", Weights: weights, Via: cache.SignalViaReferral, Path: []cache.SignalHop{
			{Owner: "_dns.ns.example.", State: cache.ValidationStateSecure},
		}})
	if got, want := formatSignalValidation(as), "secure (via referral: _dns.ns.example. secure)"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
