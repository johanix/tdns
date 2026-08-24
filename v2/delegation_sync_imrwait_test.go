package tdns

import (
	"context"
	"testing"
	"time"
)

// A proxy request that arrives before the IMR is up must come back once it is,
// rather than running against a nil IMR or being dropped.
//
// This is the startup race the change exists for: a proxy zone's first transfer
// routinely beats InitImrEngine, BuildParentSyncPlan then skips every scheme
// with "no IMR available", and before this nothing retried -- so a restarted
// proxy forwarded nothing at all until the child zone next changed.
func TestDeferForImrRequeuesOnceTheImrIsReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	q := make(chan DelegationSyncRequest, 1)
	ready := NewImrReadiness()
	ds := DelegationSyncRequest{Command: "PROXY-SYNC", ZoneName: "child.example."}

	deferForImr(ctx, q, ready, ds)

	// Nothing yet: the IMR has not been announced.
	select {
	case got := <-q:
		t.Fatalf("the request came back before the IMR was ready: %+v", got)
	case <-time.After(50 * time.Millisecond):
	}

	ready.Publish()

	select {
	case got := <-q:
		if got.Command != "PROXY-SYNC" || got.ZoneName != "child.example." {
			t.Errorf("re-enqueued the wrong request: %+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the request never came back after the IMR was announced")
	}
}

// An IMR that is already up must not make the request wait at all.
func TestDeferForImrRequeuesImmediatelyWhenAlreadyReady(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	q := make(chan DelegationSyncRequest, 1)
	ready := NewImrReadiness()
	ready.Publish()

	deferForImr(ctx, q, ready, DelegationSyncRequest{Command: "PROXY-UPDATE-SETUP", ZoneName: "child.example."})

	select {
	case <-q:
	case <-time.After(2 * time.Second):
		t.Fatal("an already-ready IMR still made the request wait")
	}
}

// Shutdown must not be held up by a request waiting on an IMR that will never
// arrive.
//
// Deliberately does NOT publish after cancelling. Both cases would then be
// ready at once and Go picks among ready select cases at random, so asserting
// either outcome would be a coin flip -- which is how the first version of this
// test passed alone and failed in the full suite. The code does not promise
// anything about that race, and it does not need to: a send onto a buffered
// queue nobody will read again is harmless during shutdown.
func TestDeferForImrHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	q := make(chan DelegationSyncRequest, 1)
	ready := NewImrReadiness()

	deferForImr(ctx, q, ready, DelegationSyncRequest{Command: "PROXY-SYNC", ZoneName: "child.example."})
	cancel()

	// The IMR never arrives, so nothing should ever be re-enqueued.
	select {
	case got := <-q:
		t.Fatalf("a cancelled request was re-enqueued without the IMR ever being ready: %+v", got)
	case <-time.After(200 * time.Millisecond):
	}
}

// The readiness signal is the synchronisation point, so its own contract has to
// hold: idempotent publication, and a nil receiver that is inert rather than a
// panic (the CLI builds an IMR without the daemon's channel setup).
func TestImrReadinessContract(t *testing.T) {
	r := NewImrReadiness()
	if r.Published() {
		t.Error("a fresh readiness reported published")
	}
	r.Publish()
	if !r.Published() {
		t.Error("Publish did not mark it published")
	}
	r.Publish() // must not panic on a double close

	var nilr *ImrReadiness
	nilr.Publish() // must not panic
	if nilr.Published() {
		t.Error("a nil readiness reported published")
	}
	if nilr.Ready() != nil {
		t.Error("a nil readiness returned a non-nil channel")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if nilr.Wait(ctx) {
		t.Error("Wait on a nil readiness reported the IMR ready")
	}
}

// The wiring, not just the primitive.
//
// The tests above build an ImrReadiness and publish it by hand, so they pass
// whether or not anything in production ever calls Publish -- which is exactly
// what happened while this change was being written: the call was reverted by
// accident and the whole suite stayed green. This asserts that the function
// which stores the Imr is also the one that announces it.
func TestPublishImrStoresAndAnnounces(t *testing.T) {
	conf := &Config{}
	conf.Internal.ImrReady = NewImrReadiness()

	if conf.Internal.ImrReady.Published() {
		t.Fatal("readiness was published before publishImr ran")
	}

	imr := &Imr{}
	prevGlobal := Globals.ImrEngine
	t.Cleanup(func() { Globals.ImrEngine = prevGlobal })

	conf.publishImr(imr)

	if conf.Internal.ImrEngine != imr {
		t.Error("publishImr did not store the Imr on the config")
	}
	if !conf.Internal.ImrReady.Published() {
		t.Fatal("publishImr stored the Imr without announcing it;" +
			" every waiter would block forever")
	}
	// The ordering that makes the announcement mean anything: anyone who has
	// received from Ready must see the stored pointer.
	<-conf.Internal.ImrReady.Ready()
	if conf.Internal.ImrEngine == nil {
		t.Error("the Imr was not visible after the readiness signal fired")
	}
}
