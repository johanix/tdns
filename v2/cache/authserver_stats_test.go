/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"io"
	"log"
	"sync"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
)

// TestTransportStatsCounters exercises the four per-server transport counters
// and the consolidated snapshot, including the attempted/used/failed/truncated
// independence and that the snapshot is an isolated copy.
func TestTransportStatsCounters(t *testing.T) {
	s := NewAuthServer("ns.example.")

	// One query attempted DoT (failed), fell back to Do53 (carried the answer);
	// plus one Do53/UDP query that was TC=1 truncated and answered over Do53TCP.
	s.IncrementTransportCounter(core.TransportDoT)           // attempted DoT
	s.IncrementFailedCounter(core.TransportDoT)              // DoT failed (capability)
	s.IncrementTransportCounter(core.TransportDo53)          // attempted Do53
	s.IncrementUsedCounter(core.TransportDo53, ClassNone)    // Do53 carried it
	s.IncrementTransportCounter(core.TransportDo53)          // attempted Do53 (the truncated one)
	s.IncrementUsedCounter(core.TransportDo53TCP, ClassNone) // truncation-upgraded answer
	s.IncrementTruncated()

	ts := s.SnapshotTransportStats()
	if got := ts.Attempted[core.TransportDoT]; got != 1 {
		t.Fatalf("attempted DoT = %d, want 1", got)
	}
	if got := ts.Attempted[core.TransportDo53]; got != 2 {
		t.Fatalf("attempted Do53 = %d, want 2", got)
	}
	if got := ts.Failed[core.TransportDoT]; got != 1 {
		t.Fatalf("failed DoT = %d, want 1", got)
	}
	if got := ts.Used[core.TransportDo53]; got != 1 {
		t.Fatalf("used Do53 = %d, want 1", got)
	}
	if got := ts.Used[core.TransportDo53TCP]; got != 1 {
		t.Fatalf("used Do53TCP = %d, want 1 (truncation upgrade must be visible)", got)
	}
	if ts.Truncated != 1 {
		t.Fatalf("truncated = %d, want 1", ts.Truncated)
	}

	// The snapshot must be an isolated copy: mutating the server afterwards
	// must not change the returned snapshot.
	s.IncrementUsedCounter(core.TransportDo53, ClassNone)
	if ts.Used[core.TransportDo53] != 1 {
		t.Fatalf("snapshot not isolated: used Do53 changed to %d", ts.Used[core.TransportDo53])
	}
}

// TestAuthServerStatsOneRowPerInstance: a server shared by two zones is one
// entry listing both zones, not two entries; a stub zone's server of the same
// name is its own instance and its own entry; a shared server no zone lists
// any more is still reported, because its counters are.
func TestAuthServerStatsOneRowPerInstance(t *testing.T) {
	rc := NewRRsetCache(log.New(io.Discard, "", 0), false, false)
	shared := rc.GetOrCreateAuthServer("ns1.example.")
	for _, zone := range []string{"example.net.", "example."} {
		if err := rc.AddServers(zone, map[string]*AuthServer{"ns1.example.": shared}); err != nil {
			t.Fatalf("AddServers(%s): %v", zone, err)
		}
	}
	if err := rc.AddStub("stub.test.", []AuthServer{
		{Name: "ns1.example.", Addrs: []string{"192.0.2.1"}, Alpn: []string{"do53"}},
	}); err != nil {
		t.Fatalf("AddStub: %v", err)
	}
	rc.GetOrCreateAuthServer("orphan.example.").IncrementUsedCounter(core.TransportDoT, ClassNone)
	shared.IncrementUsedCounter(core.TransportDo53, ClassNone)
	shared.IncrementUsedCounter(core.TransportDo53, ClassNone)

	_, stats := rc.AuthServerStats(false)
	if len(stats) != 3 {
		t.Fatalf("got %d entries, want 3 (shared ns1, stub ns1, orphan): %+v", len(stats), stats)
	}
	ns1, stub, orphan := stats[0], stats[1], stats[2]
	if ns1.Name != "ns1.example." || !ns1.Shared || len(ns1.Zones) != 2 || ns1.Zones[0] != "example." || ns1.Zones[1] != "example.net." {
		t.Errorf("shared entry %+v, want ns1.example. shared, zones [example. example.net.]", ns1)
	}
	if ns1.Used[core.TransportDo53] != 2 {
		t.Errorf("shared ns1 used do53 = %d, want 2 (counted once, not once per zone)", ns1.Used[core.TransportDo53])
	}
	if stub.Name != "ns1.example." || stub.Shared || stub.Src != "stub" || len(stub.Zones) != 1 || stub.Zones[0] != "stub.test." {
		t.Errorf("stub entry %+v, want a private ns1.example. with Src stub, zones [stub.test.]", stub)
	}
	if len(stub.Used) != 0 {
		t.Errorf("stub entry has the shared instance's counts: %v", stub.Used)
	}
	if orphan.Name != "orphan.example." || len(orphan.Zones) != 0 || orphan.Used[core.TransportDoT] != 1 {
		t.Errorf("orphan entry %+v, want orphan.example., no zones, one DoT answer", orphan)
	}
	if ns1.Weights != nil {
		t.Errorf("shared ns1 has weights %v, but it was given no signal", ns1.Weights)
	}
}

// TestAuthServerStatsReset: the reset snapshot carries the counts, the next
// one starts from zero, and the period starts again.
func TestAuthServerStatsReset(t *testing.T) {
	rc := NewRRsetCache(log.New(io.Discard, "", 0), false, false)
	s := rc.GetOrCreateAuthServer("ns.example.")
	s.IncrementTransportCounter(core.TransportDoQ)
	s.IncrementUsedCounter(core.TransportDoQ, ClassNone)
	s.IncrementFailedCounter(core.TransportDoT)
	s.IncrementTruncated()

	since1, stats := rc.AuthServerStats(true)
	if got := stats[0]; got.Used[core.TransportDoQ] != 1 || got.Failed[core.TransportDoT] != 1 || got.Truncated != 1 || got.LastUsed[core.TransportDoQ].IsZero() {
		t.Fatalf("reset snapshot %+v lacks the counts it cleared", got)
	}
	since2, stats := rc.AuthServerStats(false)
	if got := stats[0].TransportStats; len(got.Attempted)+len(got.Used)+len(got.LastUsed)+len(got.Failed) != 0 || got.Truncated != 0 {
		t.Errorf("after reset: %+v, want nothing", got)
	}
	if !since2.After(since1) {
		t.Errorf("since %v after the reset, want later than %v", since2, since1)
	}
	s.IncrementUsedCounter(core.TransportDo53, ClassNone)
	if _, stats := rc.AuthServerStats(false); stats[0].Used[core.TransportDo53] != 1 {
		t.Errorf("counting after a reset: used do53 = %d, want 1", stats[0].Used[core.TransportDo53])
	}
}

// TestAuthServerStatsResetLosesNothing: under concurrent counting, every answer
// lands in exactly one of the reset snapshots or the final one.
func TestAuthServerStatsResetLosesNothing(t *testing.T) {
	rc := NewRRsetCache(log.New(io.Discard, "", 0), false, false)
	s := rc.GetOrCreateAuthServer("ns.example.")
	const writers, per = 8, 2000
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				s.IncrementUsedCounter(core.TransportDo53, ClassNone)
			}
		}()
	}
	var seen uint64
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	for running := true; running; {
		select {
		case <-done:
			running = false
		default:
			time.Sleep(50 * time.Microsecond)
		}
		_, stats := rc.AuthServerStats(true)
		seen += stats[0].Used[core.TransportDo53]
	}
	if seen != writers*per {
		t.Errorf("counted %d answers across the resets, want %d", seen, writers*per)
	}
}
