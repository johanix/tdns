/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"errors"
	"testing"
	"time"
)

// TestDiscoveryTracker_BeginFirstCallSucceeds: an unseen owner is allowed.
func TestDiscoveryTracker_BeginFirstCallSucceeds(t *testing.T) {
	d := NewDiscoveryTracker(time.Second, 3)
	if !d.Begin("a.example.") {
		t.Error("Begin on a fresh owner should return true")
	}
}

// TestDiscoveryTracker_BeginBlocksWhileInProgress: a second Begin without
// a Succeed/Fail returns false.
func TestDiscoveryTracker_BeginBlocksWhileInProgress(t *testing.T) {
	d := NewDiscoveryTracker(time.Second, 3)
	d.Begin("a.example.")
	if d.Begin("a.example.") {
		t.Error("Begin while another attempt is in progress should return false")
	}
}

// TestDiscoveryTracker_BeginAfterSucceedIsTerminal: once Succeed has been
// called, Begin keeps returning false until Reset.
func TestDiscoveryTracker_BeginAfterSucceedIsTerminal(t *testing.T) {
	d := NewDiscoveryTracker(time.Second, 3)
	d.Begin("a.example.")
	d.Succeed("a.example.")
	if d.Begin("a.example.") {
		t.Error("Begin after Succeed should return false (terminal)")
	}
	d.Reset("a.example.")
	if !d.Begin("a.example.") {
		t.Error("Begin after Reset should return true again")
	}
}

// TestDiscoveryTracker_FailScheduleCooldown: a failed owner cannot retry
// before NextAttemptAt, then can.
func TestDiscoveryTracker_FailScheduleCooldown(t *testing.T) {
	d := NewDiscoveryTracker(50*time.Millisecond, 3)
	d.Begin("a.example.")
	d.Fail("a.example.", errors.New("boom"))
	if d.Begin("a.example.") {
		t.Error("Begin immediately after Fail should return false (cooldown)")
	}
	// Backdate NextAttemptAt to simulate cooldown elapsed.
	d.mu.Lock()
	d.states["a.example."].NextAttemptAt = time.Now().Add(-time.Second)
	d.mu.Unlock()
	if !d.Begin("a.example.") {
		t.Error("Begin after cooldown should return true")
	}
}

// TestDiscoveryTracker_ExponentialBackoff: successive Fail calls grow the
// cooldown geometrically (base * 2^(n-1)) up to maxFailures.
func TestDiscoveryTracker_ExponentialBackoff(t *testing.T) {
	base := 100 * time.Millisecond
	d := NewDiscoveryTracker(base, 3)
	owner := "a.example."

	expectedShift := []uint{0, 1, 2, 3, 3, 3}
	for i, want := range expectedShift {
		d.Begin(owner)
		before := time.Now()
		d.Fail(owner, errors.New("err"))
		d.mu.Lock()
		next := d.states[owner].NextAttemptAt
		d.mu.Unlock()
		gotCooldown := next.Sub(before)
		expectedCooldown := base << want
		// Allow slack for scheduling jitter; verify within +/- 20%
		lo := expectedCooldown - expectedCooldown/5
		hi := expectedCooldown + expectedCooldown/5
		if gotCooldown < lo || gotCooldown > hi {
			t.Errorf("attempt %d: expected cooldown ~%s (base<<%d), got %s", i+1, expectedCooldown, want, gotCooldown)
		}
		// Reset NextAttemptAt to permit the next Begin in this loop.
		d.mu.Lock()
		d.states[owner].NextAttemptAt = time.Now().Add(-time.Second)
		d.mu.Unlock()
	}
}

// TestDiscoveryTracker_SuccessAfterFailClears: a Succeed after Fail clears
// the cooldown — but subsequent Begins still return false (terminal).
func TestDiscoveryTracker_SuccessAfterFailClears(t *testing.T) {
	d := NewDiscoveryTracker(time.Hour, 3)
	d.Begin("a.example.")
	d.Fail("a.example.", errors.New("err"))
	d.Begin("a.example.") // still in cooldown (returns false)

	// Now simulate the in-progress goroutine somehow succeeding.
	d.Succeed("a.example.")
	snap := d.Snapshot()
	if snap["a.example."].Status != DiscoverySucceeded {
		t.Errorf("expected DiscoverySucceeded, got %v", snap["a.example."].Status)
	}
	if snap["a.example."].LastError != "" {
		t.Errorf("Succeed should clear LastError, got %q", snap["a.example."].LastError)
	}
}

// TestDiscoveryTracker_Snapshot: returns a copy with the right keys.
func TestDiscoveryTracker_Snapshot(t *testing.T) {
	d := NewDiscoveryTracker(time.Second, 3)
	d.Begin("a.example.")
	d.Begin("b.example.")
	d.Succeed("a.example.")
	d.Fail("b.example.", errors.New("nope"))

	snap := d.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(snap))
	}
	if snap["a.example."].Status != DiscoverySucceeded {
		t.Errorf("a.example. should be Succeeded, got %v", snap["a.example."].Status)
	}
	if snap["b.example."].Status != DiscoveryFailed {
		t.Errorf("b.example. should be Failed, got %v", snap["b.example."].Status)
	}
	if snap["b.example."].LastError != "nope" {
		t.Errorf("b.example. LastError = %q, want %q", snap["b.example."].LastError, "nope")
	}
	// Confirm copy semantics: mutating the snapshot doesn't affect tracker.
	s := snap["b.example."]
	s.Status = DiscoverySucceeded
	if d.Snapshot()["b.example."].Status != DiscoveryFailed {
		t.Error("snapshot should be a copy; tracker state was mutated")
	}
}

// TestDiscoveryTracker_NilSafe: nil receiver / empty owner are no-ops.
func TestDiscoveryTracker_NilSafe(t *testing.T) {
	var d *DiscoveryTracker
	if d.Begin("x") {
		t.Error("nil.Begin should return false")
	}
	d.Succeed("x")           // must not panic
	d.Fail("x", nil)         // must not panic
	d.Reset("x")             // must not panic
	if d.Snapshot() != nil { // must not panic
		t.Error("nil.Snapshot should return nil")
	}

	d2 := NewDiscoveryTracker(time.Second, 3)
	if d2.Begin("") {
		t.Error("Begin with empty owner should return false")
	}
}

// Pending hands out a channel only while an attempt is in progress, and
// every way the attempt can end closes it: a caller waiting on it must never
// be left waiting on an attempt that is already over.
func TestDiscoveryTracker_PendingClosesWhenTheAttemptEnds(t *testing.T) {
	owner := "a.example."
	for name, end := range map[string]func(d *DiscoveryTracker){
		"succeed": func(d *DiscoveryTracker) { d.Succeed(owner) },
		"fail":    func(d *DiscoveryTracker) { d.Fail(owner, errors.New("boom")) },
		"reset":   func(d *DiscoveryTracker) { d.Reset(owner) },
	} {
		d := NewDiscoveryTracker(time.Second, 3)
		if ch := d.Pending(owner); ch != nil {
			t.Errorf("%s: Pending before any Begin returned a channel", name)
		}
		d.Begin(owner)
		ch := d.Pending(owner)
		if ch == nil {
			t.Fatalf("%s: Pending during an attempt returned nil", name)
		}
		select {
		case <-ch:
			t.Fatalf("%s: channel closed before the attempt ended", name)
		default:
		}
		end(d)
		select {
		case <-ch:
		default:
			t.Errorf("%s: channel still open after the attempt ended", name)
		}
		if ch := d.Pending(owner); ch != nil {
			t.Errorf("%s: Pending after the attempt ended returned a channel", name)
		}
	}
}

// A retry after a failure is a new attempt with a channel of its own; the
// one closed by the failure stays closed.
func TestDiscoveryTracker_PendingIsPerAttempt(t *testing.T) {
	owner := "a.example."
	d := NewDiscoveryTracker(time.Millisecond, 3)
	d.Begin(owner)
	first := d.Pending(owner)
	d.Fail(owner, errors.New("boom"))
	d.mu.Lock()
	d.states[owner].NextAttemptAt = time.Now().Add(-time.Second)
	d.mu.Unlock()
	if !d.Begin(owner) {
		t.Fatal("Begin after the cooldown should return true")
	}
	second := d.Pending(owner)
	if second == nil {
		t.Fatal("Pending during the retry returned nil")
	}
	select {
	case <-second:
		t.Error("the retry's channel is already closed")
	default:
	}
	select {
	case <-first:
	default:
		t.Error("the failed attempt's channel is open again")
	}
}
