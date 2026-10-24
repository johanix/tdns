package tdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// #944: BADKEY re-bootstrap must never generate a key, and must wait for the
// key to be served the way the key poll does (#917).

func TestBADKEYReBootstrapDoesNotGenerateWhenNoActiveKey(t *testing.T) {
	zd := testZone(t, "child.example.", rolloverZone)
	zd.SetParent("example.")
	zd.KeyDB = newTestKeyDB(t)

	// A real algorithm: the old path relied on algorithm 0 being rejected.
	// allowGenerate=false must refuse before any generate attempt.
	_, _, err := zd.bootstrapSig0KeyWithParent(context.Background(), dns.ED25519, []string{"at-apex"}, false)
	if !errors.Is(err, errBootstrapNoActiveKey) {
		t.Fatalf("err = %v, want errBootstrapNoActiveKey", err)
	}
	sak, gerr := zd.KeyDB.GetSig0Keys(zd.ZoneName, Sig0StateActive)
	if gerr != nil {
		t.Fatalf("GetSig0Keys: %v", gerr)
	}
	if sak != nil && len(sak.Keys) != 0 {
		t.Fatalf("generated %d active SIG(0) keys; BADKEY re-bootstrap must not generate", len(sak.Keys))
	}

	err = zd.reBootstrapSig0KeyAfterBADKEYWith(context.Background(), nil, waitOrDone, keyServedWait)
	if !errors.Is(err, errBootstrapNoActiveKey) {
		t.Fatalf("reBootstrap err = %v, want errBootstrapNoActiveKey", err)
	}
}

// The BADKEY path waits with the same look/wait seams as the key poll
// (parentsync_key_served_test.go) before it uploads.
func TestBADKEYReBootstrapWaitsForKeyServed(t *testing.T) {
	looks := 0
	look := func(context.Context) (keyServedState, string) {
		looks++
		if looks < 3 {
			return keyNotServedYet, "ns2 still serves the previous KEY"
		}
		return keyServed, "both nameservers serve the key"
	}
	var waited []time.Duration
	bootstraps := 0
	err := waitThenBootstrapSig0(context.Background(), "child.example.", 4711, look,
		func(ctx context.Context, d time.Duration) bool { waited = append(waited, d); return true },
		keyServedWait,
		func(context.Context) error { bootstraps++; return nil })
	if err != nil {
		t.Fatalf("waitThenBootstrapSig0: %v", err)
	}
	if bootstraps != 1 {
		t.Errorf("bootstrap called %d times, want 1", bootstraps)
	}
	if looks != 3 {
		t.Errorf("looked %d times, want 3 (two not-yet, then served)", looks)
	}
	want := []time.Duration{keyServedWait.first, 2 * keyServedWait.first}
	if len(waited) != len(want) || waited[0] != want[0] || waited[1] != want[1] {
		t.Errorf("waited %v between looks, want %v", waited, want)
	}
}

func TestBADKEYReBootstrapShutdownDuringWaitSendsNothing(t *testing.T) {
	look := func(context.Context) (keyServedState, string) {
		return keyNotServedYet, "not served yet"
	}
	bootstraps := 0
	err := waitThenBootstrapSig0(context.Background(), "child.example.", 4711, look,
		func(context.Context, time.Duration) bool { return false },
		keyServedWait,
		func(context.Context) error { bootstraps++; return nil })
	if err == nil {
		t.Fatal("a shutdown during the wait was reported as success")
	}
	if bootstraps != 0 {
		t.Errorf("%d bootstraps after the wait was cut short", bootstraps)
	}
}

func TestBADKEYReBootstrapDefersWhenKeyPollIsRunning(t *testing.T) {
	zd := testZone(t, "child.example.", rolloverZone)
	zd.SetParent("example.")
	kdb := newTestKeyDB(t)
	zd.KeyDB = kdb
	keyid := generateSig0Key(t, kdb, zd.ZoneName, Sig0StateActive)

	id := childKeyVerificationID(zd.ZoneName, keyid)
	childKeyStatePolls.Store(id, struct{}{})
	t.Cleanup(func() { childKeyStatePolls.Delete(id) })

	// Injected wait is unused when the poll owns the bootstrap; still pass
	// one that fails the test if a regression skips the poll check.
	err := zd.reBootstrapSig0KeyAfterBADKEYWith(context.Background(), nil,
		func(context.Context, time.Duration) bool {
			t.Error("waited for served while a key poll is running")
			return true
		}, keyServedWait)
	if !errors.Is(err, errBootstrapDeferredToPoll) {
		t.Fatalf("err = %v, want errBootstrapDeferredToPoll", err)
	}
}

// A deferred-to-poll error leaves the one re-bootstrap unspent, like an
// advertisement lookup failure.
func TestSendUpdateWithRetryDefersReBootstrapWhenKeyPollIsRunning(t *testing.T) {
	fast := time.Millisecond
	sends, reboots := 0, 0
	rcode, _, err := sendUpdateWithRetry(context.Background(), 5, fast,
		func() (int, UpdateResult, error) {
			sends++
			if sends <= 2 {
				return dns.RcodeBadKey, UpdateResult{}, nil
			}
			return dns.RcodeSuccess, UpdateResult{}, nil
		},
		func() error {
			reboots++
			if reboots == 1 {
				return errBootstrapDeferredToPoll
			}
			return nil
		})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %d, want NOERROR", rcode)
	}
	if reboots != 2 || sends != 3 {
		t.Errorf("reboots=%d sends=%d, want 2 and 3", reboots, sends)
	}
}
