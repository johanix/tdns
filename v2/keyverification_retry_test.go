package tdns

import (
	"context"
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
