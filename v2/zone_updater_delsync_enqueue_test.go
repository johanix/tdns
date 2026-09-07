package tdns

import (
	"context"
	"testing"
	"time"
)

// The delegation-sync enqueue in ZoneUpdaterEngine used to be a plain send.
// The only reader of that queue is DelegationSyncher, which exits on the same
// cancellation, so a full queue at shutdown left the updater blocked forever on
// a request nobody would ever take — and ZoneUpdaterEngine never returned.
//
// Giving up is safe there: ur.respond has already released the waiter and the
// change is durable by that point, so the sync is follow-up work. See #559 for
// the other unguarded sends on this queue.

func TestEnqueueDelegationSyncQueues(t *testing.T) {
	q := make(chan DelegationSyncRequest, 1)
	req := DelegationSyncRequest{Command: "SYNC-DELEGATION", ZoneName: "example."}

	if !enqueueDelegationSync(context.Background(), q, req) {
		t.Fatal("a live context and a queue with room must enqueue")
	}
	select {
	case got := <-q:
		if got.ZoneName != "example." {
			t.Errorf("queued %q, want example.", got.ZoneName)
		}
	default:
		t.Error("reported queued, but nothing is on the queue")
	}
}

// The regression: a FULL queue and a cancelled context must return, not block.
// Run in a goroutine so a reintroduced plain send fails the test instead of
// hanging the suite.
func TestEnqueueDelegationSyncGivesUpOnCancel(t *testing.T) {
	q := make(chan DelegationSyncRequest, 1)
	q <- DelegationSyncRequest{Command: "SYNC-DELEGATION", ZoneName: "filler."}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan bool, 1)
	go func() {
		done <- enqueueDelegationSync(ctx, q, DelegationSyncRequest{ZoneName: "example."})
	}()

	select {
	case queued := <-done:
		if queued {
			t.Error("reported queued, but the queue was full")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked on a full queue with a cancelled context: the send is not cancellable")
	}

	// The filler is untouched: giving up must not consume or displace anything.
	if len(q) != 1 {
		t.Errorf("queue holds %d entries, want the untouched filler", len(q))
	}
}

// Cancelled context, room in the queue: select picks at random among ready
// cases, so EITHER outcome is correct. The contract is only that it returns.
func TestEnqueueDelegationSyncCancelledWithRoomStillReturns(t *testing.T) {
	q := make(chan DelegationSyncRequest, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan bool, 1)
	go func() {
		done <- enqueueDelegationSync(ctx, q, DelegationSyncRequest{ZoneName: "example."})
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("did not return with room in the queue and a cancelled context")
	}
}
