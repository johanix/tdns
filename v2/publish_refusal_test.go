package tdns

import (
	"context"
	"errors"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A signing failure must reach the caller, because the caller is what refuses
// the publish.
//
// MaybeSignRRset used to log the error and drop it, so signWorkingSetLocked
// returned nil, signStagedScopeLocked returned nil, and publishWorkingSetLocked
// swapped in a snapshot whose RRsets had not been signed. A signing zone
// published its content UNSIGNED -- the exact outcome
// refuseUnsignableWorkingSetLocked exists to prevent, which until now only
// fired when key RESOLUTION failed and never when signing itself did.
func TestASigningFailureRefusesThePass(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := signingTestZone(t, kdb)

	dak, err := zd.EnsureActiveDnssecKeys(kdb, false)
	if err != nil {
		t.Fatalf("resolving keys: %v", err)
	}

	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.ensureWorkingSet()

	// An RRset with no records. SignRRset refuses it -- it is a caller error --
	// and that refusal is what has to travel back out of the walk.
	zd.stageRRsetLocked("alpha.inv.example.", core.RRset{
		Name: "alpha.inv.example.", RRtype: dns.TypeTXT, Class: dns.ClassINET,
	})

	_, _, err = zd.signWorkingSetLocked(context.Background(), dak, nil, true, false, nil)
	if err == nil {
		t.Fatal("an RRset that could not be signed was reported as a clean pass;" +
			" the publish path then swaps in unsigned content for a zone that signs")
	}
}

// The refusal helpers leave the change staged on purpose -- it is not lost, and
// a later publish retries it. What they must not leave is the publish QUEUED:
// runPublisher republishes whenever the flag is set and the cadence has
// elapsed, and lastPublish never moved, so a zone that cannot sign re-attempted
// the same doomed publish as fast as the publisher could take zd.mu.
func TestARefusedPublishDoesNotSpinThePublisher(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := signingTestZone(t, kdb)

	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.ensureWorkingSet()
	zd.publishQueued = true
	zd.publishUrgent = true
	zd.lastPublish = time.Time{} // never published: the cadence check passes at once

	before := zd.CurrentSerial
	zd.refuseUnsignableWorkingSetLocked(before, errTestSigning)

	if zd.publishQueued {
		t.Error("the publish is still queued after being refused; runPublisher retries it" +
			" immediately, fails the same way, and loops")
	}
	if zd.publishUrgent {
		t.Error("still marked urgent, which skips the cadence entirely")
	}
	if zd.lastPublish.IsZero() {
		t.Error("lastPublish did not move, so the next request sees the cadence as elapsed")
	}
	if zd.workingSet == nil {
		t.Error("the staged change was discarded; a refusal keeps it for the next publish")
	}
	if zd.CurrentSerial != before {
		t.Errorf("serial %d, want the previous %d restored", zd.CurrentSerial, before)
	}
}

var errTestSigning = &testSigningError{}

type testSigningError struct{}

func (e *testSigningError) Error() string { return "test: could not sign" }

// TestACancelledSigningWalkRefusesRatherThanPublishesHalfOfIt.
//
// signWorkingSetLocked holds zd.mu and, on a full pass, visits every owner in
// the zone -- unbounded work on a large one, with no way to stop it. Making it
// cancellable is only safe if abandoning it is an ERROR: a short walk that
// reported success would let publishWorkingSetLocked swap in a snapshot whose
// remaining RRsets were never signed, which is the outcome
// refuseUnsignableWorkingSetLocked exists to prevent. Cancelled means refused,
// and the zone goes on serving what it already had.
func TestACancelledSigningWalkRefusesRatherThanPublishesHalfOfIt(t *testing.T) {
	zd, kdb, _ := rolledZone(t)

	before := zd.publishedSnapshot()
	if before == nil {
		t.Fatal("fixture: nothing published to keep serving")
	}

	dak, err := zd.EnsureActiveDnssecKeys(kdb, false)
	if err != nil {
		t.Fatalf("EnsureActiveDnssecKeys: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	zd.mu.Lock()
	zd.ensureWorkingSet()
	_, _, err = zd.signWorkingSetLocked(ctx, dak, nil, true, false, nil)
	zd.mu.Unlock()

	if err == nil {
		t.Fatal("a cancelled signing walk reported success; the caller would then publish a" +
			" snapshot whose RRsets were never signed")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v does not match context.Canceled, so a caller cannot tell a shutdown"+
			" from a genuine signing failure", err)
	}
	if after := zd.publishedSnapshot(); after != before {
		t.Error("the published snapshot changed despite the walk being abandoned")
	}
}

// TestAFailedPostBindSigningIsNotReportedAsASuccessfulLoad.
//
// signOnceAfterPolicyBind used to log its SignZone error and return nothing.
// Both callers then carried on: completeFirstZonePolicyAndLoad replayed deltas
// and drained OnFirstLoad, finishFirstLoadPolicy drained them. The load
// reported success while a signing zone sat unsigned and not Ready -- and
// nothing retried it, because the callbacks a retry needs had already been
// spent and the refresh flow considered the first load done.
func TestAFailedPostBindSigningIsNotReportedAsASuccessfulLoad(t *testing.T) {
	zd, kdb, _ := rolledZone(t)
	zd.KeyDB = kdb

	// Unservable content forces SignZone to fail: the policy is bound, the
	// zone signs its own content, but signing is refused.
	zd.SetError(DnssecError, "injected: signing is broken for this zone")

	// Not already signed, or the function returns before it tries.
	zd.snapshot.Store(nil)

	if err := signOnceAfterPolicyBind(context.Background(), zd); err == nil {
		t.Fatal("a failed post-bind signing reported success; the caller then replays deltas" +
			" and drains OnFirstLoad on a zone that cannot be served, and nothing retries it")
	}
}

// The other half: a zone that signs cleanly must not be reported as a failure,
// or every first load of a healthy signing zone would be retried forever.
func TestASuccessfulPostBindSigningReportsSuccess(t *testing.T) {
	zd, kdb, _ := rolledZone(t)
	zd.KeyDB = kdb
	zd.snapshot.Store(nil)

	if err := signOnceAfterPolicyBind(context.Background(), zd); err != nil {
		t.Fatalf("a zone that signs cleanly was reported as failed: %v", err)
	}
}
