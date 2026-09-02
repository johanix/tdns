package tdns

import (
	"context"
	"testing"
	"time"
)

// Carry-over 9 on the zone-load path (review T2): a DELEGATION-SYNC-SETUP
// whose bootstrap failed only because the parent's SVCB advertisement could
// not be looked up is re-enqueued with the delegation-sync backoff and an
// advanced attempt count, instead of being dropped until the next reload.

func TestSetupRetryDelaySchedule(t *testing.T) {
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second}
	for attempt, d := range want {
		if got := setupRetryDelay(attempt); got != d {
			t.Errorf("attempt %d: delay %s, want %s", attempt, got, d)
		}
	}
}

func TestDeferSetupRetryDeliversWithAdvancedAttempt(t *testing.T) {
	q := make(chan DelegationSyncRequest, 1)
	ds := DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: "child.example.", Attempt: 1}
	done := deferSetupRetryAfter(context.Background(), q, ds, time.Millisecond)
	select {
	case got := <-q:
		if got.Attempt != 2 || got.ZoneName != ds.ZoneName || got.Command != ds.Command {
			t.Fatalf("re-enqueued %+v, want the same request with Attempt=2", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("setup was not re-enqueued")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("deferred worker did not exit after delivering")
	}
}

func TestDeferSetupRetryHonoursCancellation(t *testing.T) {
	q := make(chan DelegationSyncRequest, 1)
	ctx, cancel := context.WithCancel(context.Background())
	ds := DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: "child.example."}
	done := deferSetupRetryAfter(ctx, q, ds, time.Hour)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("deferred worker did not exit on cancellation")
	}
	if len(q) != 0 {
		t.Fatal("a cancelled worker must not re-enqueue")
	}
}
