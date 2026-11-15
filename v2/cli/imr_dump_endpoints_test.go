/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"testing"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
)

// The dump shows a transport sent to another host with that host, and a port
// at the server's own name on the ports line.
func TestFormatSignalTargets(t *testing.T) {
	as := cache.NewAuthServer("ns.example.")
	as.SetTransportSignal(nil, nil, nil, &cache.ReceivedSignal{
		Source:  "oots",
		Ports:   map[core.Transport]uint16{core.TransportDoT: 1234, core.TransportDoQ: 1235},
		Targets: map[core.Transport]string{core.TransportDoT: "dot-ns.example."},
	})
	if got, want := formatSignalTargets(as), "dot=dot-ns.example.:1234"; got != want {
		t.Errorf("targets %q, want %q", got, want)
	}
	if got, want := formatAuthServerPorts(as), "doq:1235"; got != want {
		t.Errorf("ports %q, want %q", got, want)
	}
}
