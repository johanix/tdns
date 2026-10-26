package tdns

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// #944: a BADKEY re-bootstrap never generates a key. It uploads only once the
// zone's nameservers serve the key (#917), without holding the delegation-sync
// loop to wait for that, and it leaves the upload to a key poll that is about
// to send the key, but not to one that already has.

// badkeyChild plays the zone's nameservers and the upload for a BADKEY
// re-bootstrap, and records what happens, in order.
type badkeyChild struct {
	served []keyServedState // one per look; the last repeats
	looks  int
	events []string
}

func (c *badkeyChild) look(string, uint16) func(context.Context) (keyServedState, string) {
	return func(context.Context) (keyServedState, string) {
		s := c.served[min(c.looks, len(c.served)-1)]
		c.looks++
		c.events = append(c.events, "look")
		return s, "ns2 still serves the previous KEY"
	}
}

func (c *badkeyChild) upload(context.Context) error {
	c.events = append(c.events, "upload")
	return nil
}

func (c *badkeyChild) uploaded() bool {
	return strings.Contains(strings.Join(c.events, " "), "upload")
}

// badkeyZone is a child zone with an active SIG(0) key.
func badkeyZone(t *testing.T) (*ZoneData, uint16) {
	t.Helper()
	zd := testZone(t, "child.example.", rolloverZone)
	zd.SetParent("example.")
	zd.KeyDB = newTestKeyDB(t)
	keyid := generateSig0Key(t, zd.KeyDB, zd.ZoneName, Sig0StateActive)
	t.Cleanup(func() { badkeyNotServedSince.Delete(childKeyVerificationID(zd.ZoneName, keyid)) })
	return zd, keyid
}

// sendUntilUploaded sends a delegation UPDATE through sendUpdateWithRetry,
// with the zone's BADKEY re-bootstrap: the parent answers BADKEY until c has
// uploaded, then NOERROR.
func sendUntilUploaded(zd *ZoneData, c *badkeyChild, attempts int) (int, error) {
	ctx := context.Background()
	rcode, _, err := sendUpdateWithRetry(ctx, attempts, time.Millisecond,
		func() (int, UpdateResult, error) {
			c.events = append(c.events, "send")
			if !c.uploaded() {
				return dns.RcodeBadKey, UpdateResult{}, nil
			}
			return dns.RcodeSuccess, UpdateResult{}, nil
		},
		func() error { return zd.reBootstrapSig0KeyAfterBADKEYWith(ctx, c.look, c.upload) })
	return rcode, err
}

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

	if err := zd.reBootstrapSig0KeyAfterBADKEY(context.Background()); !errors.Is(err, errBootstrapNoActiveKey) {
		t.Fatalf("reBootstrapSig0KeyAfterBADKEY err = %v, want errBootstrapNoActiveKey", err)
	}
	c := &badkeyChild{served: []keyServedState{keyServed}}
	if err := zd.reBootstrapSig0KeyAfterBADKEYWith(context.Background(), c.look, c.upload); !errors.Is(err, errBootstrapNoActiveKey) {
		t.Fatalf("err = %v, want errBootstrapNoActiveKey", err)
	}
	if len(c.events) != 0 {
		t.Errorf("%v with no active key", c.events)
	}
}

// One look per UPDATE attempt, and the upload only once the zone's nameservers
// serve the key. The attempts' backoff is the wait (#917).
func TestBADKEYReBootstrapUploadsOnlyOnceTheKeyIsServed(t *testing.T) {
	zd, _ := badkeyZone(t)
	c := &badkeyChild{served: []keyServedState{keyNotServedYet, keyNotServedYet, keyServed}}
	rcode, err := sendUntilUploaded(zd, c, 5)
	if err != nil || rcode != dns.RcodeSuccess {
		t.Fatalf("rcode %s, err %v; want NOERROR", dns.RcodeToString[rcode], err)
	}
	want := "send look send look send look upload send"
	if got := strings.Join(c.events, " "); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// A key still not served when the attempts run out is not uploaded, and the
// UPDATE says why.
func TestBADKEYReBootstrapNotServedWithinTheAttemptsUploadsNothing(t *testing.T) {
	zd, _ := badkeyZone(t)
	c := &badkeyChild{served: []keyServedState{keyNotServedYet}}
	_, err := sendUntilUploaded(zd, c, 3)
	if !errors.Is(err, errBootstrapKeyNotServed) {
		t.Fatalf("err = %v, want errBootstrapKeyNotServed", err)
	}
	if c.uploaded() {
		t.Errorf("uploaded a key no nameserver set serves yet: %v", c.events)
	}
}

// A nameserver that never takes the key delays the upload, as it delays the
// poll's, and does not stop it: once keyServedWait.limit has passed since a
// look first found the key not served, the BADKEY path uploads all the same.
func TestBADKEYReBootstrapUploadsAllTheSameAfterTheLimit(t *testing.T) {
	zd, keyid := badkeyZone(t)
	badkeyNotServedSince.Store(childKeyVerificationID(zd.ZoneName, keyid), time.Now().Add(-keyServedWait.limit))
	c := &badkeyChild{served: []keyServedState{keyNotServedYet}}
	rcode, err := sendUntilUploaded(zd, c, 2)
	if err != nil || rcode != dns.RcodeSuccess {
		t.Fatalf("rcode %s, err %v; want NOERROR", dns.RcodeToString[rcode], err)
	}
	if got, want := strings.Join(c.events, " "), "send look upload send"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBADKEYReBootstrapShutdownDuringTheLookSendsNothing(t *testing.T) {
	zd, _ := badkeyZone(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &badkeyChild{served: []keyServedState{keyServed}}
	look := func(zone string, keyid uint16) func(context.Context) (keyServedState, string) {
		inner := c.look(zone, keyid)
		return func(ctx context.Context) (keyServedState, string) {
			cancel()
			return inner(ctx)
		}
	}
	err := zd.reBootstrapSig0KeyAfterBADKEYWith(ctx, look, c.upload)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want a shutdown", err)
	}
	if c.uploaded() {
		t.Error("uploaded after the shutdown")
	}
}

// heldKeyPoll runs a real KeyState poll for zd's key, registered the way
// startChildKeyStatePoll registers every poll. The parent answers "unknown"
// until inquiry heldAt, which it holds until the test ends. It returns once
// the poll is held, with how many bootstraps the poll had sent by then.
func heldKeyPoll(t *testing.T, zd *ZoneData, keyid uint16, bootstrapped bool, heldAt int) int {
	t.Helper()
	held, release := make(chan struct{}), make(chan struct{})
	asked, sent := 0, 0
	poll := parentKeyStatePoll{
		zone:         ZoneName(zd.ZoneName),
		keyid:        keyid,
		bootstrapped: bootstrapped,
		query: func(ctx context.Context) (*edns0.KeyStateOption, bool, error) {
			asked++
			if asked == heldAt {
				close(held)
				<-release
				return &edns0.KeyStateOption{KeyState: edns0.KeyStateTrusted}, true, nil
			}
			return &edns0.KeyStateOption{KeyState: edns0.KeyStateUnknown}, true, nil
		},
		record:           func(uint8) {},
		bootstrap:        func(context.Context) error { sent++; return nil },
		pollDelay:        time.Millisecond,
		wait:             waitOrDone,
		reBootstrapDelay: childReBootstrapDelay,
	}
	done := startChildKeyStatePoll(zd.ZoneName, keyid, func(st *childKeyPoll) {
		poll.state = st
		_ = (&Config{}).pollParentKeyState(context.Background(), poll)
	})
	if done == nil {
		t.Fatal("no poll started")
	}
	t.Cleanup(func() { close(release); <-done })
	select {
	case <-held:
	case <-time.After(2 * time.Second):
		t.Fatal("the poll never reached the held inquiry")
	}
	return sent
}

// A running poll for the key takes the upload only while it is still about to
// send the key. Once it has sent it, a parent that does not know the key is
// polled again by it, not sent the key again, so BADKEY's upload is this
// path's (onParentKeyState).
func TestBADKEYReBootstrapLeavesTheUploadOnlyToAPollAboutToSendTheKey(t *testing.T) {
	for _, tc := range []struct {
		name         string
		bootstrapped bool // the poll starts after an accepted bootstrap
		heldAt       int
		wantSent     int
		wantDefer    bool
	}{
		{"agent poll before its bootstrap", false, 1, 0, true},
		{"agent poll after its bootstrap", false, 2, 1, false},
		{"poll after an accepted bootstrap", true, 1, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zd, keyid := badkeyZone(t)
			if sent := heldKeyPoll(t, zd, keyid, tc.bootstrapped, tc.heldAt); sent != tc.wantSent {
				t.Fatalf("fixture: the poll sent %d bootstraps, want %d", sent, tc.wantSent)
			}
			c := &badkeyChild{served: []keyServedState{keyServed}}
			err := zd.reBootstrapSig0KeyAfterBADKEYWith(context.Background(), c.look, c.upload)
			if tc.wantDefer {
				if !errors.Is(err, errBootstrapDeferredToPoll) {
					t.Fatalf("err = %v, want errBootstrapDeferredToPoll", err)
				}
				if len(c.events) != 0 {
					t.Errorf("%v while the poll was about to send the key", c.events)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if got := strings.Join(c.events, " "); got != "look upload" {
				t.Errorf("got %q, want the key looked for and uploaded", got)
			}
		})
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
