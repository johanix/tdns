package tdns

import (
	core "github.com/johanix/tdns/v2/core"
	"testing"
)

// The counter is unsigned and zero means DUE, so decrementing at zero wraps to
// 4294967295 and the zone stops being due for the life of the process.
//
// Zero is not an edge case here, it is a normal resting state: a zone
// dispatched and still in flight (the reset happens when the outcome comes
// back), a job the pool refused as busy or saturated, and a zone skipped for a
// service-impacting error all leave it there deliberately, each meaning "still
// due, try again next tick". The wrap turned every one of those into "never
// again".
func TestTheRefreshCounterDoesNotWrapPastDue(t *testing.T) {
	// The PRODUCTION guard, not a copy of it. This test used to carry its own
	// reimplementation of the decrement, which meant an unguarded one in the
	// ticker passed every test in the package -- the test pinned its own
	// behaviour and nothing else.
	tick := refreshCounterTick

	rc := &RefreshCounter{Name: "z.example.", SOARefresh: 3, SOARetry: 2, CurRefresh: 2}

	if tick(rc) {
		t.Fatalf("due at CurRefresh=%d, too early", rc.CurRefresh)
	}
	if !tick(rc) {
		t.Fatalf("not due at CurRefresh=%d, want due at 0", rc.CurRefresh)
	}

	// The zone is dispatched and the counter is deliberately left at zero until
	// the outcome returns. Every tick in between must keep it due.
	for i := 0; i < 5; i++ {
		if !tick(rc) {
			t.Fatalf("tick %d after dispatch: CurRefresh=%d, want it to stay due at 0."+
				" Wrapping here is what stops a zone refreshing for 136 years", i, rc.CurRefresh)
		}
	}
	if rc.CurRefresh != 0 {
		t.Errorf("CurRefresh=%d, want 0", rc.CurRefresh)
	}
}

// And the resting state that was pinning a broken zone at "due" on every tick:
// a service-impacting error now reschedules on the retry interval.
func TestAnErroredZoneReschedulesRatherThanStayingDue(t *testing.T) {
	rc := &RefreshCounter{Name: "z.example.", SOARefresh: 3600, SOARetry: 900, CurRefresh: 0}

	rc.CurRefresh = refreshCounterRetry(rc)

	if rc.CurRefresh != 900 {
		t.Errorf("CurRefresh=%d, want the SOA RETRY (900): a zone left at zero is walked,"+
			" logged and skipped on every single tick until its error clears", rc.CurRefresh)
	}

	// Falling back to REFRESH when the zone has no RETRY.
	noRetry := &RefreshCounter{Name: "z.example.", SOARefresh: 3600, CurRefresh: 0}
	if got := refreshCounterRetry(noRetry); got != 3600 {
		t.Errorf("with no SOA RETRY: %d, want the REFRESH interval 3600", got)
	}
}

// TestRetryIntervalReachesTheCounterTheMapHolds.
//
// The ticker collects counters under IterCb and then does work that can REPLACE
// them: a successful initialLoadZone calls refreshCounters.Set for the very
// zone being processed, so the pointer collected before that call no longer
// reaches the map. Writing the retry interval through it went nowhere, and a
// zone whose policy sync had just failed waited out a full jittered SOA REFRESH
// instead of retrying in thirty seconds.
func TestRetryIntervalReachesTheCounterTheMapHolds(t *testing.T) {
	const zone = "z.example."
	counters := core.NewCmap[*RefreshCounter]()

	stale := &RefreshCounter{Name: zone, SOARefresh: 3600, CurRefresh: 0}
	counters.Set(zone, stale)

	// What initialLoadZone does on success: a brand-new counter for this zone.
	fresh := &RefreshCounter{Name: zone, SOARefresh: 7200, CurRefresh: 0}
	counters.Set(zone, fresh)

	// The ticker still holds `stale`.
	setRefreshRetry(counters, zone, stale, 30)

	if got, _ := counters.Get(zone); got.CurRefresh != 30 {
		t.Errorf("the live counter has CurRefresh=%d, want 30; the retry was written to a"+
			" counter that is no longer in the map, so the zone waits out a full SOA"+
			" REFRESH before retrying", got.CurRefresh)
	}

	// 0 means "reset to whatever the LIVE counter's SOA REFRESH is" -- not the
	// stale one's, which is a different zone's worth of seconds.
	setRefreshRetry(counters, zone, stale, 0)
	if got, _ := counters.Get(zone); got.CurRefresh != 7200 {
		t.Errorf("reset to %d, want the live counter's SOARefresh 7200 (the stale one says %d)",
			got.CurRefresh, stale.SOARefresh)
	}
}
