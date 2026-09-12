package tdns

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// #575: the child-authoritative bootstrap needs the IMR, because the parent
// zone is discovered rather than configured. At startup DELEGATION-SYNC-SETUP
// routinely arrives before InitImrEngine has published the engine, and the
// failure was logged and the request DROPPED -- "ignoring sync request".
// Nothing retried it, so a child never bootstrapped unaided: every key had to
// be presented to the parent by hand after the daemon settled.
//
// The proxy arm of the same loop already deferred for this. This is the same
// signal, for the setup arm.
func TestBootstrapSetupComesBackOnceTheImrIsReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	q := make(chan DelegationSyncRequest, 1)
	ready := NewImrReadiness()
	ds := DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: "child.example."}

	done := deferForImr(ctx, q, ready, ds)
	defer awaitExit(t, cancel, done)

	select {
	case got := <-q:
		t.Fatalf("the setup request came back before the IMR was ready: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}

	ready.Publish()

	select {
	case got := <-q:
		if got.Command != "DELEGATION-SYNC-SETUP" || got.ZoneName != "child.example." {
			t.Errorf("re-enqueued the wrong request: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the setup request never came back; this is the one chance the child gets" +
			" to bootstrap, and losing it means the key is never presented to the parent")
	}
}

// The failure is matched on the condition, not on its prose, so a caller cannot
// stop recognising it by someone rewording the message.
func TestMissingImrIsAMatchableCondition(t *testing.T) {
	zd := &ZoneData{ZoneName: "child.example."}

	// No IMR anywhere: exactly the state the first seconds of a process are in.
	prev := Globals.ImrEngine
	Globals.ImrEngine = nil
	t.Cleanup(func() { Globals.ImrEngine = prev })
	prevConf := Conf.Internal.ImrEngine
	Conf.Internal.ImrEngine = nil
	t.Cleanup(func() { Conf.Internal.ImrEngine = prevConf })

	err := zd.resolveParentZone()
	if err == nil {
		// Not a build to skip over: this fixture is a bare ZoneData with every
		// IMR pointer nil, so resolving a parent is impossible. Succeeding
		// means the fixture stopped being what the test says it is, and
		// skipping would turn that into a pass.
		t.Fatal("resolveParentZone succeeded with no IMR anywhere; the fixture no longer" +
			" reproduces the startup state this test is about")
	}
	if !errors.Is(err, ErrNoImrEngine) {
		t.Errorf("resolveParentZone reported %v, which does not match ErrNoImrEngine."+
			" The syncher then cannot tell 'the IMR is not up yet' from a real failure,"+
			" and drops a request that should have been deferred", err)
	}
}

// setupRig stands up what handleDelegationSyncSetup needs: a queue, a
// readiness signal, and a Config wired to it.
// awaitExit cancels a deferred-request worker's context and waits for it to
// finish, with a deadline.
//
// Every test here that starts one of these workers used to leave it to
// `defer cancel()`: the worker was told to stop, and nothing checked that it
// did. A regression that made deferForImr or deferSetupRetry ignore
// cancellation -- sleeping out a backoff, or blocking on a queue nobody reads
// any more -- would have passed all of them.
//
// Two seconds, against a retry backoff that starts at five: a worker that
// honours cancellation is gone at once, and one that does not is still asleep.
// nil means no worker was started, and there is nothing to wait for.
func awaitExit(t *testing.T, cancel context.CancelFunc, done <-chan struct{}) {
	t.Helper()
	if done == nil {
		return
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the deferred worker did not exit within 2s of its context being cancelled;" +
			" it would outlive shutdown")
	}
}

func setupRig(t *testing.T, published bool) (*Config, chan DelegationSyncRequest) {
	t.Helper()
	conf := &Config{}
	conf.Internal.ImrReady = NewImrReadiness()
	if published {
		conf.Internal.ImrReady.Publish()
	}
	return conf, make(chan DelegationSyncRequest, 4)
}

// TestSetupWaitsForTheImrRatherThanRunningWithoutOne drives the syncher's own
// SETUP arm, not the helper underneath it. Reverting the Published() check
// inside that arm used to leave every #575 test green.
func TestSetupWaitsForTheImrRatherThanRunningWithoutOne(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conf, q := setupRig(t, false) // IMR not published
	zd := &ZoneData{ZoneName: "child.example."}
	ds := DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: "child.example.", ZoneData: zd}

	done := handleDelegationSyncSetupWith(ctx, conf, q, ds, func() error {
		t.Error("setup ran with no IMR published; that is what the pre-check exists to prevent")
		return nil
	})
	defer awaitExit(t, cancel, done)

	select {
	case <-q:
		t.Fatal("the request came back before the IMR was published")
	case <-time.After(50 * time.Millisecond):
	}

	conf.Internal.ImrReady.Publish()

	select {
	case got := <-q:
		if got.Command != "DELEGATION-SYNC-SETUP" {
			t.Errorf("re-enqueued the wrong request: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the setup request was dropped rather than deferred; this is the one chance" +
			" the child gets to bootstrap unaided")
	}
}

// TestSetupDoesNotSpinWhenTheImrIsPublishedButUnusable.
//
// After Published() is true the readiness signal is CLOSED, so deferring on it
// re-enqueues immediately. The single DelegationSyncher goroutine would then
// spin on one zone and starve every other. This arm has to back off instead.
func TestSetupDoesNotSpinWhenTheImrIsPublishedButUnusable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conf, q := setupRig(t, true) // published...
	ds := DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: "child.example."}

	// ...and still no usable IMR from here, which is the whole point of the
	// post-readiness branch.
	done := handleDelegationSyncSetupWith(ctx, conf, q, ds, func() error {
		return fmt.Errorf("setting up %s: %w", ds.ZoneName, ErrNoImrEngine)
	})
	// The worker is asleep in its backoff when the test ends. It has to wake
	// on cancellation rather than sleep it out.
	defer awaitExit(t, cancel, done)

	// The backoff is seconds; an immediate re-enqueue is the bug.
	select {
	case got := <-q:
		t.Fatalf("the request came straight back (attempt %d); on a closed readiness signal"+
			" that is a tight loop in the one goroutine that serves every zone", got.Attempt)
	case <-time.After(200 * time.Millisecond):
	}
}

// Backing off is not dropping: the request must still come back, once.
func TestSetupRetriesAnUnusableImrAfterABackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conf, q := setupRig(t, true)
	ds := DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: "child.example."}

	done := handleDelegationSyncSetupWith(ctx, conf, q, ds, func() error {
		return fmt.Errorf("setting up %s: %w", ds.ZoneName, ErrNoImrEngine)
	})
	defer awaitExit(t, cancel, done)

	select {
	case got := <-q:
		if got.Attempt != ds.Attempt+1 {
			t.Errorf("re-enqueued at attempt %d, want %d; without the increment the backoff"+
				" never reaches its limit and the zone retries forever", got.Attempt, ds.Attempt+1)
		}
	case <-time.After(setupRetryDelay(ds.Attempt) + 5*time.Second):
		t.Error("the request never came back; a published-but-unusable IMR is a condition to" +
			" wait out, not a verdict on the zone")
	}
}

// The backoff is bounded: a zone that can never be set up must stop asking.
func TestSetupGivesUpAfterRepeatedUnusableImr(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conf, q := setupRig(t, true)
	ds := DelegationSyncRequest{
		Command:  "DELEGATION-SYNC-SETUP",
		ZoneName: "child.example.",
		Attempt:  delegationSyncMaxRetries - 1, // the last one
	}

	scheduled := handleDelegationSyncSetupWith(ctx, conf, q, ds, func() error {
		return fmt.Errorf("setting up %s: %w", ds.ZoneName, ErrNoImrEngine)
	})
	// None should have started; if one did, the test fails below and this
	// still stops it rather than leaking it into the rest of the run.
	defer awaitExit(t, cancel, scheduled)

	if scheduled != nil {
		t.Error("another attempt was scheduled past the retry limit; a zone that can never" +
			" be set up would keep asking for the life of the process")
	}
	select {
	case got := <-q:
		t.Fatalf("still retrying past the limit (attempt %d of %d)", got.Attempt, delegationSyncMaxRetries)
	case <-time.After(200 * time.Millisecond):
	}
}

// A failure that is neither "no IMR" nor an advertisement lookup is final:
// retrying it would just repeat the same answer.
func TestSetupDoesNotRetryAFinalFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conf, q := setupRig(t, true)
	ds := DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: "child.example."}

	scheduled := handleDelegationSyncSetupWith(ctx, conf, q, ds, func() error {
		return errors.New("the zone has no parent and never will")
	})
	defer awaitExit(t, cancel, scheduled)
	if scheduled != nil {
		t.Error("a final failure scheduled a retry; it would just get the same answer")
	}

	select {
	case got := <-q:
		t.Fatalf("a final failure was re-enqueued: %+v", got)
	case <-time.After(200 * time.Millisecond):
	}
}
