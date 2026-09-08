package tdns

import (
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

	_, _, err = zd.signWorkingSetLocked(dak, nil, true, false, nil)
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
