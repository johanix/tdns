/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// stats auth-transports shows where a validated signal sent each transport,
// the answers a target carried, and the redirects ignored.
func TestAuthTransportsReportRedirects(t *testing.T) {
	imr := newTestImr(t)
	server := imr.Cache.GetOrCreateAuthServer(pathNS)
	installTransportMap(server, map[string]uint8{"dot": 30}, nil, map[core.Transport]string{core.TransportDoT: dotTarget},
		cache.SignalViaLookup, []cache.SignalHop{{Owner: pathOwner, State: cache.ValidationStateSecure}})
	server.CountAnswer(core.TransportDoT, cache.ClassNone, true)
	server.CountAnswer(core.TransportDoT, cache.ClassNone, false)
	server.AddIgnoredRedirects(3)
	report := ImrAuthTransportsSnapshot(imr.Cache, []string{pathNS}, "", false)
	if len(report.Rows) != 1 {
		t.Fatalf("rows %d, want 1", len(report.Rows))
	}
	row := report.Rows[0]
	if row.SignalTargets["dot"] != dotTarget || row.Redirected["dot"] != 1 || row.IgnoredRedirects != 3 {
		t.Errorf("targets %v, redirected %v, ignored %d", row.SignalTargets, row.Redirected, row.IgnoredRedirects)
	}
	if got := server.SnapshotTransportStats().Used[core.TransportDoT]; got != 2 {
		t.Errorf("DoT answers %d, want 2", got)
	}
}
