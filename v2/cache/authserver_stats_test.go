/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"testing"

	core "github.com/johanix/tdns/v2/core"
)

// TestTransportStatsCounters exercises the four per-server transport counters
// and the consolidated snapshot, including the attempted/used/failed/truncated
// independence and that the snapshot is an isolated copy.
func TestTransportStatsCounters(t *testing.T) {
	s := NewAuthServer("ns.example.")

	// One query attempted DoT (failed), fell back to Do53 (carried the answer);
	// plus one Do53/UDP query that was TC=1 truncated and answered over Do53TCP.
	s.IncrementTransportCounter(core.TransportDoT)  // attempted DoT
	s.IncrementFailedCounter(core.TransportDoT)     // DoT failed (capability)
	s.IncrementTransportCounter(core.TransportDo53) // attempted Do53
	s.IncrementUsedCounter(core.TransportDo53)      // Do53 carried it
	s.IncrementTransportCounter(core.TransportDo53) // attempted Do53 (the truncated one)
	s.IncrementUsedCounter(core.TransportDo53TCP)   // truncation-upgraded answer
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
	s.IncrementUsedCounter(core.TransportDo53)
	if ts.Used[core.TransportDo53] != 1 {
		t.Fatalf("snapshot not isolated: used Do53 changed to %d", ts.Used[core.TransportDo53])
	}
}
