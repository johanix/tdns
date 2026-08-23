package tdns

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The retry budget applies defaults to anything non-positive. Zero means
// "unset", but a NEGATIVE max-attempts used to skip the retry loop entirely and
// abandon key verification without saying so, and a negative interval turned the
// exponential backoff into a busy loop. Neither value could reach the code
// before, because the setting was read through viper and viper is never
// populated here — modelling the block is what makes them possible.
func TestKeyVerificationRetrySettingsRejectsNonPositive(t *testing.T) {
	neg := -1
	cases := []struct {
		name         string
		in           DsyncKeyVerificationConf
		wantAttempts int
		wantInterval time.Duration
	}{
		{"unset", DsyncKeyVerificationConf{}, 5, 10 * time.Second},
		{"negative attempts", DsyncKeyVerificationConf{MaxAttempts: neg}, 5, 10 * time.Second},
		{"negative interval", DsyncKeyVerificationConf{RetryInterval: -time.Second}, 5, 10 * time.Second},
		{"both negative", DsyncKeyVerificationConf{MaxAttempts: neg, RetryInterval: -time.Second}, 5, 10 * time.Second},
		{"configured", DsyncKeyVerificationConf{MaxAttempts: 3, RetryInterval: 2 * time.Second}, 3, 2 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, i := keyVerificationRetrySettings(tc.in)
			if a != tc.wantAttempts || i != tc.wantInterval {
				t.Errorf("got (%d, %v), want (%d, %v)", a, i, tc.wantAttempts, tc.wantInterval)
			}
		})
	}
}

// The retry goroutine must observe shutdown. It used to time.Sleep through the
// backoff, so it outlived cancellation by however long the backoff had left —
// and the backoff doubles each attempt.
func TestWaitOrDoneObservesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	start := time.Now()
	if waitOrDone(ctx, time.Hour) {
		t.Error("waitOrDone reported the timer fired on a cancelled context")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("waitOrDone took %v on a cancelled context; it slept instead of returning", elapsed)
	}
}

// And it still waits when nothing cancels it, or the retry loop would spin.
func TestWaitOrDoneWaitsWhenNotCancelled(t *testing.T) {
	start := time.Now()
	if !waitOrDone(context.Background(), 20*time.Millisecond) {
		t.Error("waitOrDone reported cancellation on a live context")
	}
	if elapsed := time.Since(start); elapsed < 15*time.Millisecond {
		t.Errorf("waitOrDone returned after %v, expected to wait ~20ms", elapsed)
	}
}

// parseKeygenAlgorithm takes the configured VALUE, not a config key. Passing a
// key meant the value was fetched through viper, which is never populated in
// tdns-auth or tdns-agent, so the setting was silently ignored whatever an
// operator wrote.
func TestParseKeygenAlgorithmTakesAValue(t *testing.T) {
	cases := []struct {
		in   string
		want uint8
	}{
		{"ED25519", dns.ED25519},
		{"ed25519", dns.ED25519},
		{"ECDSAP256SHA256", dns.ECDSAP256SHA256},
		{"", dns.ED25519},          // unset -> default
		{"NOSUCHALG", dns.ED25519}, // unknown -> default
		// A config KEY must not resolve; that was the bug.
		{"delegationsync.child.update.keygen.algorithm", dns.ED25519},
	}
	for _, tc := range cases {
		got, err := parseKeygenAlgorithm(tc.in, dns.ED25519)
		if err != nil {
			t.Fatalf("parseKeygenAlgorithm(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("parseKeygenAlgorithm(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// The unit tests above prove waitOrDone behaves; this one proves the goroutine
// actually uses it. Start the real verification goroutine with an
// already-cancelled context and assert it is gone within a bounded time.
//
// Whichever branch it takes, the goroutine reaches a wait: with no IMR it is the
// "IMR not yet available" retry, and with one it is the post-attempt backoff.
// Both are where the old time.Sleep stranded it past shutdown -- 10s on the
// first attempt, doubling from there. Under the old code this test still sees it
// running at the deadline.
func TestTriggerChildKeyVerificationExitsOnCancellation(t *testing.T) {
	// Deliberately does NOT touch Globals.ImrEngine. Setting and restoring it
	// races the goroutine that reads it, and the restore in a t.Cleanup can run
	// while the goroutine is still live -- the goroutine-count check below is a
	// heuristic, not a completion signal, so there is nothing to order against.
	//
	// It is not needed either: every wait in the retry loop goes through
	// waitOrDone(ctx), so a cancelled context makes the goroutine exit promptly
	// whichever branch it takes, IMR or no IMR.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Let anything already in flight settle, so the baseline is meaningful.
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	kdb := &KeyDB{}
	kdb.TriggerChildKeyVerification(ctx, "child.example.", 12345,
		"child.example. 3600 IN KEY 256 3 15 x")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before {
			return // it exited
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the verification goroutine was still running 5s after a cancelled"+
		" context (goroutines %d -> %d); it is sleeping through shutdown instead"+
		" of selecting on ctx.Done()", before, runtime.NumGoroutine())
}
