/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"sync"
	"time"
)

// DiscoveryStatus is the state a single owner sits in inside a
// DiscoveryTracker. The transitions are:
//
//	NotAttempted (the empty initial state, never stored)
//	 -> InProgress    via Begin
//	      -> Succeeded via Succeed (terminal until external reset)
//	      -> Failed    via Fail (with cooldown; Begin permits a retry
//	                   once NextAttemptAt has passed)
type DiscoveryStatus int

const (
	DiscoveryNotAttempted DiscoveryStatus = iota
	DiscoveryInProgress
	DiscoverySucceeded
	DiscoveryFailed
)

var DiscoveryStatusToString = map[DiscoveryStatus]string{
	DiscoveryNotAttempted: "not-attempted",
	DiscoveryInProgress:   "in-progress",
	DiscoverySucceeded:    "succeeded",
	DiscoveryFailed:       "failed",
}

// DiscoveryState is the per-owner state stored in a DiscoveryTracker.
type DiscoveryState struct {
	Status        DiscoveryStatus
	AttemptCount  int       // total Begin calls that ran a real attempt
	LastAttemptAt time.Time // wall-clock of the most recent Begin
	NextAttemptAt time.Time // earliest time Begin will return true again after Fail
	LastError     string    // populated by Fail (empty string allowed)
}

// DiscoveryTracker replaces the prior "in-flight mutex" pattern with a
// stateful tracker per (kind, owner). Each kind of discovery (transport
// signal, TLSA, etc.) should have its own tracker so a TLSA failure
// doesn't suppress transport-signal discovery and vice versa.
//
// Compared to the in-flight bool it replaces, this tracker:
//   - remembers permanent failures so we don't keep silently re-trying
//     a broken endpoint each time a caller wanders past;
//   - remembers successes so we don't pointlessly re-discover an owner
//     whose data is already cached;
//   - throttles failure retries with exponential backoff.
type DiscoveryTracker struct {
	mu          sync.Mutex
	states      map[string]*DiscoveryState
	retryAfter  time.Duration
	maxFailures int
}

// NewDiscoveryTracker constructs a tracker. retryAfter is the base cooldown
// after the first failure; subsequent failures grow exponentially up to
// retryAfter * 2^maxFailures.
func NewDiscoveryTracker(retryAfter time.Duration, maxFailures int) *DiscoveryTracker {
	if retryAfter <= 0 {
		retryAfter = 30 * time.Second
	}
	if maxFailures <= 0 {
		maxFailures = 3
	}
	return &DiscoveryTracker{
		states:      make(map[string]*DiscoveryState),
		retryAfter:  retryAfter,
		maxFailures: maxFailures,
	}
}

// Begin reports whether the caller should attempt discovery for owner now.
// Returns true on first attempt, on retry past NextAttemptAt after a Fail,
// or never again after Succeed (until external reset). Returns false when
// another goroutine already has an attempt in progress or the cooldown is
// still active. Marks the owner InProgress as a side effect when it
// returns true.
func (d *DiscoveryTracker) Begin(owner string) bool {
	if d == nil || owner == "" {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	s, ok := d.states[owner]
	if !ok {
		d.states[owner] = &DiscoveryState{
			Status:        DiscoveryInProgress,
			AttemptCount:  1,
			LastAttemptAt: now,
		}
		return true
	}
	switch s.Status {
	case DiscoveryInProgress:
		return false
	case DiscoverySucceeded:
		return false
	case DiscoveryFailed:
		if now.Before(s.NextAttemptAt) {
			return false
		}
	}
	s.Status = DiscoveryInProgress
	s.AttemptCount++
	s.LastAttemptAt = now
	return true
}

// Succeed records a successful attempt for owner. Subsequent Begin calls
// for the same owner will return false until Reset is called explicitly.
func (d *DiscoveryTracker) Succeed(owner string) {
	if d == nil || owner == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.states[owner]
	if !ok {
		// Defensive: a Succeed without a prior Begin shouldn't happen, but
		// record it anyway to keep the state machine consistent.
		d.states[owner] = &DiscoveryState{
			Status:        DiscoverySucceeded,
			AttemptCount:  1,
			LastAttemptAt: time.Now(),
		}
		return
	}
	s.Status = DiscoverySucceeded
	s.LastError = ""
}

// Fail records a failed attempt. Subsequent Begin calls return false until
// NextAttemptAt (cooldown = retryAfter * 2^min(AttemptCount-1, maxFailures))
// has passed.
func (d *DiscoveryTracker) Fail(owner string, err error) {
	if d == nil || owner == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.states[owner]
	if !ok {
		// Same defensive insertion as Succeed.
		s = &DiscoveryState{
			Status:        DiscoveryFailed,
			AttemptCount:  1,
			LastAttemptAt: time.Now(),
		}
		d.states[owner] = s
	} else {
		s.Status = DiscoveryFailed
	}
	if err != nil {
		s.LastError = err.Error()
	}
	exp := s.AttemptCount - 1
	if exp < 0 {
		exp = 0
	}
	if exp > d.maxFailures {
		exp = d.maxFailures
	}
	s.NextAttemptAt = time.Now().Add(d.retryAfter << uint(exp))
}

// Reset removes the recorded state for owner so the next Begin starts
// fresh. Useful when external information says we should re-try a
// previously-succeeded owner (e.g., the cached signal data expired).
func (d *DiscoveryTracker) Reset(owner string) {
	if d == nil || owner == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.states, owner)
}

// Snapshot returns a copy of the per-owner state for observability dumps.
// Map keys are owners.
func (d *DiscoveryTracker) Snapshot() map[string]DiscoveryState {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.states) == 0 {
		return nil
	}
	out := make(map[string]DiscoveryState, len(d.states))
	for k, v := range d.states {
		out[k] = *v
	}
	return out
}
