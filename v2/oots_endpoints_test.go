/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"testing"

	imrcore "github.com/johanix/tdns/v2/imr"

	"github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
)

// stats auth-transports shows where a validated signal sent each transport,
// the answers a target carried, and the redirects ignored.
func TestAuthTransportsReportRedirects(t *testing.T) {
	imr := newTestImr(t)
	server := imr.Cache.GetOrCreateAuthServer(pathNS)
	imrcore.InstallTransportSignal(server, map[string]uint8{"dot": 30}, nil, map[core.Transport]string{core.TransportDoT: dotTarget},
		cache.SignalViaLookup, []cache.SignalHop{{Owner: pathOwner, State: cache.ValidationStateSecure}})
	server.IncrementRedirectedCounter(core.TransportDoT)
	server.IncrementUsedCounter(core.TransportDoT, cache.ClassNone)
	server.AddIgnoredRedirects(3)
	report := ImrAuthTransportsSnapshot(imr.Cache, []string{pathNS}, "", false)
	if len(report.Rows) != 1 {
		t.Fatalf("rows %d, want 1", len(report.Rows))
	}
	row := report.Rows[0]
	if row.SignalTargets["dot"] != dotTarget || row.Redirected["dot"] != 1 || row.IgnoredRedirects != 3 {
		t.Errorf("targets %v, redirected %v, ignored %d", row.SignalTargets, row.Redirected, row.IgnoredRedirects)
	}
	if got := server.SnapshotTransportStats().Used[core.TransportDoT]; got != 1 {
		t.Errorf("DoT answers %d, want 1: the target's are counted on its own instance", got)
	}
}

// stats auth-transports lists each target's instance on a row of its own,
// marked as a target; a selection by zone leaves it out, and a reset clears
// its counters. The resolver half of this test is imr's
// TestAuthTransportsListsTargetsResolverHalf.
func TestAuthTransportsListsTargets(t *testing.T) {
	imr := newTestImr(t)
	target := cache.NewAuthServer(dotTarget)
	target.ForceSetSrc("target")
	target.IncrementUsedCounter(core.TransportDoT, cache.ClassNone)
	targets := []*cache.AuthServer{target}
	rep := authTransportsSnapshot(imr.Cache, targets, nil, "", false)
	var row *ImrAuthTransportsRow
	for i := range rep.Rows {
		if rep.Rows[i].Server == dotTarget {
			row = &rep.Rows[i]
		}
	}
	if row == nil {
		t.Fatalf("no row for the target in %+v", rep.Rows)
	}
	if !row.Target || row.Shared || row.Src != "target" || row.Counts["dot"] != 1 || row.Signal != nil {
		t.Errorf("target row %+v: want a target, not shared, one DoT answer, no signal", *row)
	}
	if rep := authTransportsSnapshot(imr.Cache, targets, nil, "example.", false); len(rep.Rows) != 0 {
		t.Errorf("a selection by zone listed %+v", rep.Rows)
	}
	authTransportsSnapshot(imr.Cache, targets, nil, "", true)
	if got := target.SnapshotTransportStats().Used[core.TransportDoT]; got != 0 {
		t.Errorf("after a reset the target still counts %d answers", got)
	}
}
