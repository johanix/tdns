package tdns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/edns0"
)

// #677, fix 2, the child's side: a parent that reports the key's validation
// failed has the child re-bootstrap later, a few times, rather than stop.

func TestTheChildsReBootstrapWaitOutlastsTheParentsCooldown(t *testing.T) {
	if childReBootstrapDelay(0) <= childKeyReBootstrapCooldown {
		t.Errorf("the first re-bootstrap comes after %v, within the parent's cooldown of %v;"+
			" the parent would refuse it and the round is wasted",
			childReBootstrapDelay(0), childKeyReBootstrapCooldown)
	}
	for round := 1; round < childReBootstrapRounds; round++ {
		if childReBootstrapDelay(round) <= childReBootstrapDelay(round-1) {
			t.Errorf("round %d waits %v, no longer than round %d", round, childReBootstrapDelay(round), round-1)
		}
	}
}

// keyStateParent plays the parent for pollParentKeyState: it answers with
// states in turn, taking the next set of answers each time the child
// bootstraps.
type keyStateParent struct {
	t          *testing.T
	answers    [][]uint8 // per bootstrap round; the last answer repeats
	bootstraps int
	asked      int
	recorded   []uint8
	waits      []time.Duration
	waitOK     bool
}

func (kp *keyStateParent) poll() parentKeyStatePoll {
	return parentKeyStatePoll{
		zone:  "child.example.",
		keyid: 4711,
		query: func(ctx context.Context) (*edns0.KeyStateOption, bool, error) {
			round := kp.answers[min(kp.bootstraps, len(kp.answers)-1)]
			state := round[min(kp.asked, len(round)-1)]
			kp.asked++
			return &edns0.KeyStateOption{KeyState: state, ExtraText: "no KEY at _sig0key.child.example._signal.ns.provider.net."}, true, nil
		},
		record: func(state uint8) { kp.recorded = append(kp.recorded, state) },
		bootstrap: func(ctx context.Context) error {
			kp.bootstraps++
			kp.asked = 0
			return nil
		},
		pollDelay: time.Millisecond,
		wait: func(ctx context.Context, d time.Duration) bool {
			kp.waits = append(kp.waits, d)
			return kp.waitOK
		},
		reBootstrapDelay: childReBootstrapDelay,
	}
}

// The lab sequence after fix 2: the parent's verification ran out before the
// provider published. The child is told validation failed, waits, re-bootstraps,
// the parent verifies again, and trusts the key.
func TestTheChildReBootstrapsWhenTheParentReportsValidationFailed(t *testing.T) {
	kp := &keyStateParent{t: t, waitOK: true, answers: [][]uint8{
		{edns0.KeyStateValidationFail},
		{edns0.KeyStateBootstrapAutoOngoing, edns0.KeyStateTrusted},
	}}

	err := (&Config{}).pollParentKeyState(context.Background(), kp.poll())
	if err != nil {
		t.Fatalf("poll ended with %v, want the key trusted", err)
	}
	if kp.bootstraps != 1 {
		t.Errorf("%d re-bootstraps, want 1", kp.bootstraps)
	}
	if len(kp.waits) != 1 || kp.waits[0] != childReBootstrapDelay(0) {
		t.Errorf("waited %v before re-bootstrapping, want [%v]", kp.waits, childReBootstrapDelay(0))
	}
	if last := kp.recorded[len(kp.recorded)-1]; last != edns0.KeyStateTrusted {
		t.Errorf("recorded states %v; the last is not trusted", kp.recorded)
	}
}

// A parent that keeps failing the key gets childReBootstrapRounds re-bootstraps,
// on the schedule, and then the child gives up with the parent's reason.
func TestTheChildStopsReBootstrappingAfterItsRounds(t *testing.T) {
	kp := &keyStateParent{t: t, waitOK: true, answers: [][]uint8{{edns0.KeyStateValidationFail}}}

	err := (&Config{}).pollParentKeyState(context.Background(), kp.poll())
	if err == nil || !strings.Contains(err.Error(), "KEY_VALIDATION_FAILED") ||
		!strings.Contains(err.Error(), "no KEY at") {
		t.Errorf("poll ended with %v, want KEY_VALIDATION_FAILED with the parent's reason", err)
	}
	if kp.bootstraps != childReBootstrapRounds {
		t.Errorf("%d re-bootstraps, want %d", kp.bootstraps, childReBootstrapRounds)
	}
	var want []time.Duration
	for round := 0; round < childReBootstrapRounds; round++ {
		want = append(want, childReBootstrapDelay(round))
	}
	if fmt.Sprint(kp.waits) != fmt.Sprint(want) {
		t.Errorf("waited %v, want %v", kp.waits, want)
	}
}

// A shutdown while waiting to re-bootstrap sends nothing.
func TestAShutdownWhileWaitingToReBootstrapSendsNothing(t *testing.T) {
	kp := &keyStateParent{t: t, waitOK: false, answers: [][]uint8{{edns0.KeyStateValidationFail}}}

	if err := (&Config{}).pollParentKeyState(context.Background(), kp.poll()); err == nil {
		t.Error("a shutdown during the wait was reported as success")
	}
	if kp.bootstraps != 0 {
		t.Errorf("%d re-bootstraps after the wait was cut short", kp.bootstraps)
	}
}

// The tdns-auth child's setup arm: EDE KEY-VALIDATION-FAILED on the bootstrap
// schedules a re-bootstrap, until the rounds run out.
func TestTheSetupArmReBootstrapsAfterAFailedValidationWithinItsRounds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conf, q := setupRig(t, true)

	failed := func() error {
		return fmt.Errorf("%w (EDE 541)", errBootstrapValidationFailed)
	}

	ds := DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: "child.example.", Attempt: 2}
	done := handleDelegationSyncSetupWith(ctx, conf, q, ds, failed)
	if done == nil {
		t.Error("a failed validation scheduled no re-bootstrap; the child stopped where the parent" +
			" keeps no state waiting for it")
	}
	defer awaitExit(t, cancel, done)

	next, delay, ok := nextReBootstrap(ds)
	if !ok || next.ReBootstrapRound != 1 || next.Attempt != 0 || delay != childReBootstrapDelay(0) {
		t.Errorf("next re-bootstrap %+v after %v (ok=%v), want round 1, attempt 0, after %v",
			next, delay, ok, childReBootstrapDelay(0))
	}

	last := ds
	last.ReBootstrapRound = childReBootstrapRounds
	if handleDelegationSyncSetupWith(ctx, conf, q, last, failed) != nil {
		t.Error("still re-bootstrapping past the rounds; a key the parent will never accept" +
			" would be re-sent for the life of the process")
	}
	if !errors.Is(failed(), errBootstrapValidationFailed) {
		t.Fatal("fixture: the setup error is not errBootstrapValidationFailed")
	}
}
