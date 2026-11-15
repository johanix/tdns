/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cli

import (
	"testing"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
)

// A server's weights are shown with cleartext as udp and tcp, apart, by
// their oots tokens; without weights, as the absence defaults.
func TestSignalRenderingSplitsUDPAndTCP(t *testing.T) {
	w := map[core.Transport]uint8{core.TransportDoT: 30, core.TransportDo53: 100, core.TransportDo53TCP: 20, core.TransportDoH: 0}
	if got, want := renderSignalFromWeights(w), "dot=30,udp=100,tcp=20"; got != want {
		t.Errorf("renderSignalFromWeights = %q, want %q", got, want)
	}
	if got := renderSignalFromWeights(nil); got != "udp=100,tcp=100" {
		t.Errorf("renderSignalFromWeights(nil) = %q, want the absence defaults", got)
	}
	// A recorded udp or tcp 0 is a signal: it is shown, never replaced by
	// the absence defaults. An encrypted 0 is left out.
	zero := map[core.Transport]uint8{core.TransportDo53: 0, core.TransportDo53TCP: 0, core.TransportDoT: 0, core.TransportDoH: 0, core.TransportDoQ: 0}
	if got, want := renderSignalFromWeights(zero), "udp=0,tcp=0"; got != want {
		t.Errorf("renderSignalFromWeights(all zero) = %q, want %q", got, want)
	}
	capped := map[core.Transport]uint8{core.TransportDoQ: 40, core.TransportDo53: 100, core.TransportDo53TCP: 0, core.TransportDoT: 0}
	if got, want := renderSignalFromWeights(capped), "doq=40,udp=100,tcp=0"; got != want {
		t.Errorf("renderSignalFromWeights(tcp capped) = %q, want %q", got, want)
	}
	s := cache.NewAuthServer("ns.example.")
	s.SetTransportWeights(w)
	if got, want := formatTransportWeights(s), "[dot:30 udp:100 tcp:20]"; got != want {
		t.Errorf("formatTransportWeights = %q, want %q", got, want)
	}
}
