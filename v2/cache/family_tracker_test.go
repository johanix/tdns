/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"testing"
	"time"
)

const (
	v4Addr = "192.0.2.1:53"
	v6Addr = "[2001:db8::1]:53"
)

func newTrackerForTest() *FamilyTracker {
	return NewFamilyTracker(
		10*time.Minute, // window
		10*time.Minute, // suspect duration
		30*time.Second, // probe interval
		5,              // failure threshold
	)
}

// TestFamilyOf covers v4, v6 (with/without brackets), missing-port, and
// junk inputs.
func TestFamilyOf(t *testing.T) {
	cases := []struct {
		in   string
		want AddressFamily
	}{
		{"192.0.2.1:53", FamilyV4},
		{"192.0.2.1", FamilyV4},
		{"[2001:db8::1]:53", FamilyV6},
		{"2001:db8::1", FamilyV6},
		{"not-an-ip", FamilyUnknown},
		{"", FamilyUnknown},
	}
	for _, c := range cases {
		if got := FamilyOf(c.in); got != c.want {
			t.Errorf("FamilyOf(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestFamilyTracker_ThresholdMarksSuspect verifies that N failures with zero
// successes flip the family to suspect.
func TestFamilyTracker_ThresholdMarksSuspect(t *testing.T) {
	ft := newTrackerForTest()
	for i := 0; i < 4; i++ {
		ft.RecordResult(v6Addr, false)
		if ft.IsSuspect(FamilyV6) {
			t.Fatalf("v6 marked suspect after %d failures, threshold is 5", i+1)
		}
	}
	ft.RecordResult(v6Addr, false) // 5th
	if !ft.IsSuspect(FamilyV6) {
		t.Error("v6 should be suspect after reaching threshold")
	}
	if ft.IsSuspect(FamilyV4) {
		t.Error("v4 must not be suspect from v6 failures")
	}
}

// TestFamilyTracker_SuccessClearsSuspect verifies that a single success
// immediately drops the suspect mark.
func TestFamilyTracker_SuccessClearsSuspect(t *testing.T) {
	ft := newTrackerForTest()
	for i := 0; i < 5; i++ {
		ft.RecordResult(v6Addr, false)
	}
	if !ft.IsSuspect(FamilyV6) {
		t.Fatal("setup: v6 should be suspect")
	}
	ft.RecordResult(v6Addr, true)
	if ft.IsSuspect(FamilyV6) {
		t.Error("a single v6 success should clear the suspect mark")
	}
}

// TestFamilyTracker_FailuresWithSuccessDontMarkSuspect verifies the
// "zero successes" precondition — if some successes are present in the
// window, failures don't flip suspect.
func TestFamilyTracker_FailuresWithSuccessDontMarkSuspect(t *testing.T) {
	ft := newTrackerForTest()
	ft.RecordResult(v6Addr, true)
	for i := 0; i < 10; i++ {
		ft.RecordResult(v6Addr, false)
	}
	if ft.IsSuspect(FamilyV6) {
		t.Error("with at least one success in the window, suspect should not trigger")
	}
}

// TestFamilyTracker_SuspectExpires verifies that IsSuspect returns false
// once SuspectDuration elapses (we backdate the internal mark).
func TestFamilyTracker_SuspectExpires(t *testing.T) {
	ft := newTrackerForTest()
	for i := 0; i < 5; i++ {
		ft.RecordResult(v6Addr, false)
	}
	if !ft.IsSuspect(FamilyV6) {
		t.Fatal("setup: v6 should be suspect")
	}
	ft.mu.Lock()
	ft.v6.suspectUntil = time.Now().Add(-1 * time.Second)
	ft.mu.Unlock()
	if ft.IsSuspect(FamilyV6) {
		t.Error("suspect must lift once SuspectDuration has elapsed")
	}
}

// TestFamilyTracker_ShouldProbeOncePerInterval verifies the probe throttle.
func TestFamilyTracker_ShouldProbeOncePerInterval(t *testing.T) {
	ft := newTrackerForTest()
	// Not suspect: ShouldProbe returns false.
	if ft.ShouldProbe(FamilyV6) {
		t.Error("ShouldProbe must return false when family not suspect")
	}

	for i := 0; i < 5; i++ {
		ft.RecordResult(v6Addr, false)
	}
	// First call: should probe.
	if !ft.ShouldProbe(FamilyV6) {
		t.Error("first ShouldProbe in suspect period should return true")
	}
	// Many subsequent calls within ProbeInterval: all false.
	for i := 0; i < 10; i++ {
		if ft.ShouldProbe(FamilyV6) {
			t.Errorf("ShouldProbe returned true within ProbeInterval (call %d)", i+1)
		}
	}
	// Backdate lastProbeAt to simulate ProbeInterval elapsed.
	ft.mu.Lock()
	ft.v6.lastProbeAt = time.Now().Add(-1 * time.Hour)
	ft.mu.Unlock()
	if !ft.ShouldProbe(FamilyV6) {
		t.Error("after ProbeInterval elapsed, ShouldProbe should permit one more probe")
	}
}

// TestFamilyTracker_SlidingWindowExpires verifies that failures older than
// WindowDuration drop out of the count, so a brief outage doesn't keep the
// family suspect forever once the failures age out.
func TestFamilyTracker_SlidingWindowExpires(t *testing.T) {
	ft := NewFamilyTracker(
		100*time.Millisecond, // window
		10*time.Minute,       // suspect duration
		30*time.Second,       // probe interval
		5,                    // threshold
	)
	for i := 0; i < 4; i++ {
		ft.RecordResult(v6Addr, false)
	}
	// Wait for window to expire.
	time.Sleep(150 * time.Millisecond)
	// One more failure: window now has just this one, below threshold.
	ft.RecordResult(v6Addr, false)
	if ft.IsSuspect(FamilyV6) {
		t.Error("aged-out failures should not contribute to threshold")
	}
}

// TestFamilyTracker_UnknownFamilyIgnored verifies non-IP addresses are
// silently ignored (no panic, no state change).
func TestFamilyTracker_UnknownFamilyIgnored(t *testing.T) {
	ft := newTrackerForTest()
	for i := 0; i < 10; i++ {
		ft.RecordResult("not-an-ip", false)
	}
	if ft.IsSuspect(FamilyV4) || ft.IsSuspect(FamilyV6) {
		t.Error("unknown-family failures must not flip any family to suspect")
	}
}

// TestFamilyTracker_NewClampsBadInputs verifies that NewFamilyTracker
// silently replaces non-positive values with safe minima rather than
// returning a tracker that misbehaves at runtime (probe always allowed,
// divide-by-zero in window math, etc.).
func TestFamilyTracker_NewClampsBadInputs(t *testing.T) {
	ft := NewFamilyTracker(0, -1*time.Second, 0, 0)
	if ft.window <= 0 {
		t.Errorf("window not clamped: got %v", ft.window)
	}
	if ft.suspectDuration <= 0 {
		t.Errorf("suspectDuration not clamped: got %v", ft.suspectDuration)
	}
	if ft.probeInterval <= 0 {
		t.Errorf("probeInterval not clamped: got %v", ft.probeInterval)
	}
	if ft.threshold <= 0 {
		t.Errorf("threshold not clamped: got %d", ft.threshold)
	}
	// Sanity: a tracker built with clamped defaults still functions —
	// one failure with threshold=1 should immediately mark suspect.
	ft.RecordResult(v6Addr, false)
	if !ft.IsSuspect(FamilyV6) {
		t.Error("clamped threshold=1 should trip on first failure")
	}
}

// TestFamilyTracker_NilSafe verifies the nil receiver is safe — callers may
// pass a nil tracker (e.g. in tests / boot paths) without panicking.
func TestFamilyTracker_NilSafe(t *testing.T) {
	var ft *FamilyTracker
	ft.RecordResult(v4Addr, false) // must not panic
	if ft.IsSuspect(FamilyV4) {
		t.Error("nil tracker should never report suspect")
	}
	if ft.ShouldProbe(FamilyV4) {
		t.Error("nil tracker should never grant a probe")
	}
}
