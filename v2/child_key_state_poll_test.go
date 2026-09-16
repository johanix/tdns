package tdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// #677, the tdns-auth child: a bootstrap the parent accepted is followed by a
// KeyState poll, so a verification that fails afterwards leads to a
// re-bootstrap rather than silence.

// Only a ceremony the parent answered NOERROR counts as accepted, driven
// through the real SendUpdate so the result carries what the sender fills in.
func TestBootstrapAcceptedOnlyForACeremonyAnsweredNOERROR(t *testing.T) {
	send := func(rcode int, ede uint16) (UpdateResult, error) {
		t.Helper()
		var addr string
		if ede != 0 {
			addr = startRcodeEDEResponder(t, rcode, ede)
		} else {
			addr = startRcodeResponder(t, rcode)
		}
		_, ur, err := SendUpdate(context.Background(), testUpdateMsg(t), "child.parent.example.", []string{addr})
		return ur, err
	}

	for _, tc := range []struct {
		name  string
		rcode int
		ede   uint16
		want  bool
	}{
		{"NOERROR", dns.RcodeSuccess, 0, true},
		{"REFUSED, validation failed", dns.RcodeRefused, edns0.EDESig0KeyValidationFailed, false},
		{"REFUSED, still verifying", dns.RcodeRefused, edns0.EDESig0KeyKnownButNotTrusted, false},
		{"SERVFAIL", dns.RcodeServerFailure, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ur, err := send(tc.rcode, tc.ede)
			if got := bootstrapAccepted(ur, err); got != tc.want {
				t.Errorf("accepted=%v, want %v (rcode %s, err %v)", got, tc.want, dns.RcodeToString[ur.Rcode], err)
			}
		})
	}

	t.Run("unreachable parent", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		dead := ln.Addr().String()
		ln.Close()
		_, ur, sendErr := SendUpdate(context.Background(), testUpdateMsg(t), "child.parent.example.", []string{dead})
		if bootstrapAccepted(ur, sendErr) {
			t.Error("a ceremony that never reached the parent counted as accepted")
		}
	})

	// Never sent: the ceremony returns an empty result, whose zero Rcode is
	// NOERROR.
	if bootstrapAccepted(UpdateResult{}, fmt.Errorf("%w for child.example.", errBootstrapManual)) {
		t.Error("a ceremony not sent to a manual parent counted as accepted")
	}
}

func TestSetupThenPollStartsThePollOnlyWhenAccepted(t *testing.T) {
	for _, tc := range []struct {
		name     string
		accepted bool
		err      error
		wantPoll bool
	}{
		{"accepted", true, nil, true},
		{"not accepted", false, nil, false},
		{"failed", false, errors.New("DSYNC lookup failed"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			polled := -1
			run := setupThenPoll(
				func() (bool, uint8, error) { return tc.accepted, dns.ED25519, tc.err },
				func(alg uint8) { polled = int(alg) },
			)
			if err := run(); !errors.Is(err, tc.err) {
				t.Errorf("setup error %v, want %v", err, tc.err)
			}
			if gotPoll := polled >= 0; gotPoll != tc.wantPoll {
				t.Errorf("poll started=%v, want %v", gotPoll, tc.wantPoll)
			}
			if tc.wantPoll && polled != int(dns.ED25519) {
				t.Errorf("poll got algorithm %d, want the setup's %d", polled, dns.ED25519)
			}
		})
	}
}

// Every zone load sends the ceremony again. One poll per key, however often.
func TestOneKeyStatePollPerChildKey(t *testing.T) {
	const zone, keyid = "poll.example.", 4711
	release := make(chan struct{})

	first := startChildKeyStatePoll(zone, keyid, func() { <-release })
	if first == nil {
		t.Fatal("no poll started")
	}
	if second := startChildKeyStatePoll(zone, keyid, func() {}); second != nil {
		<-second
		t.Error("a second poll started for a key already being polled")
	}
	close(release)
	select {
	case <-first:
	case <-time.After(2 * time.Second):
		t.Fatal("the poll did not exit")
	}
	third := startChildKeyStatePoll(zone, keyid, func() {})
	if third == nil {
		t.Fatal("the key stayed marked as polled after its poll exited")
	}
	<-third
}

// The ceremony has been sent. A parent that has not processed it yet is polled
// again, not sent another ceremony.
func TestAPollAfterAnAcceptedBootstrapDoesNotBootstrapAgain(t *testing.T) {
	for _, tc := range []struct {
		name           string
		bootstrapped   bool
		wantBootstraps int
	}{
		{"after an accepted bootstrap", true, 0},
		{"agent, key not yet bootstrapped", false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kp := &keyStateParent{t: t, waitOK: true, answers: [][]uint8{
				{edns0.KeyStateUnknown, edns0.KeyStateTrusted},
			}}
			poll := kp.poll()
			poll.bootstrapped = tc.bootstrapped
			if err := (&Config{}).pollParentKeyState(context.Background(), poll); err != nil {
				t.Fatalf("poll ended with %v", err)
			}
			if kp.bootstraps != tc.wantBootstraps {
				t.Errorf("%d bootstraps, want %d", kp.bootstraps, tc.wantBootstraps)
			}
		})
	}
}

// The agent syncs the delegation once its key is trusted. The post-bootstrap
// poll runs at every zone load, and does not.
func TestOnlyTheAgentsPollSyncsTheDelegationWhenTrusted(t *testing.T) {
	registerZones(t, &ZoneData{ZoneName: "child.example."})
	for _, tc := range []struct {
		name     string
		sync     bool
		wantSync int
	}{
		{"agent", true, 1},
		{"after an accepted bootstrap", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := &Config{}
			conf.Internal.DelegationSyncQ = make(chan DelegationSyncRequest, 1)
			kp := &keyStateParent{t: t, waitOK: true, answers: [][]uint8{{edns0.KeyStateTrusted}}}
			poll := kp.poll()
			poll.syncDelegationWhenTrusted = tc.sync
			if err := conf.pollParentKeyState(context.Background(), poll); err != nil {
				t.Fatalf("poll ended with %v", err)
			}
			if got := len(conf.Internal.DelegationSyncQ); got != tc.wantSync {
				t.Errorf("%d delegation syncs enqueued, want %d", got, tc.wantSync)
			}
		})
	}
}

// Without an IMR there is no parent to ask, and nothing is started.
func TestPollAfterAcceptedBootstrapNeedsAnImr(t *testing.T) {
	conf := &Config{}
	if done := conf.pollAfterAcceptedBootstrap(context.Background(), &KeyDB{}, &ZoneData{ZoneName: "child.example."}, dns.ED25519); done != nil {
		<-done
		t.Error("a poll started with no IMR to reach the parent through")
	}
}
