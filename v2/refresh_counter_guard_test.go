package tdns

import (
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
	tick := func(rc *RefreshCounter) bool {
		// The guarded decrement the ticker performs.
		if rc.CurRefresh > 0 {
			rc.CurRefresh--
		}
		return rc.CurRefresh == 0
	}

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
