package tdns

import (
	"context"
	"testing"
	"time"
)

// Proxy work cannot start without an IMR: the parent's DSYNC records are
// discovered, not configured. At startup the zone's first transfer routinely
// beats InitImrEngine, and before this the plan skipped every scheme with "no
// IMR available" and nothing retried -- so a restarted proxy forwarded nothing
// until the child zone happened to change again.
func TestDeferForImrRequeuesTheRequest(t *testing.T) {
	q := make(chan DelegationSyncRequest, 1)
	ds := DelegationSyncRequest{Command: "PROXY-SYNC", ZoneName: "child.example."}

	if !deferForImr(context.Background(), q, ds, time.Millisecond) {
		t.Fatal("first deferral was refused")
	}
	select {
	case got := <-q:
		if got.Command != "PROXY-SYNC" || got.ZoneName != "child.example." {
			t.Errorf("requeued the wrong request: %+v", got)
		}
		if got.ImrWaits != 1 {
			t.Errorf("ImrWaits = %d, want 1; without a counter this retries forever",
				got.ImrWaits)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request was never put back on the queue")
	}
}

// The budget has to be finite, or a permanently absent IMR is retried forever
// instead of being reported.
func TestDeferForImrGivesUpEventually(t *testing.T) {
	q := make(chan DelegationSyncRequest, 1)
	ds := DelegationSyncRequest{
		Command: "PROXY-UPDATE-SETUP", ZoneName: "child.example.", ImrWaits: maxImrWaits,
	}

	if deferForImr(context.Background(), q, ds, time.Millisecond) {
		t.Fatal("deferral was accepted past the retry budget")
	}
	select {
	case got := <-q:
		t.Fatalf("a request past the budget was still requeued: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
}

// A cancelled context must not leave the re-enqueue goroutine parked forever.
func TestDeferForImrHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	q := make(chan DelegationSyncRequest, 1)

	if !deferForImr(ctx, q, DelegationSyncRequest{Command: "PROXY-SYNC", ZoneName: "child.example."}, time.Hour) {
		t.Fatal("deferral refused")
	}
	cancel()
	select {
	case got := <-q:
		t.Fatalf("request was requeued after cancellation: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
}
