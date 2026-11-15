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
	s := cache.NewAuthServer("ns.example.")
	s.SetTransportWeights(w)
	if got, want := formatTransportWeights(s), "[dot:30 udp:100 tcp:20]"; got != want {
		t.Errorf("formatTransportWeights = %q, want %q", got, want)
	}
}
