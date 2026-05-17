/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"net"
	"sync"
	"time"
)

// AddressFamily is v4 or v6. Other values (e.g. zero) mean "unknown".
type AddressFamily int

const (
	FamilyUnknown AddressFamily = 0
	FamilyV4      AddressFamily = 4
	FamilyV6      AddressFamily = 6
)

// FamilyTracker accumulates per-family reachability evidence from query
// outcomes and reports a "suspect" verdict for a family when the local host
// appears to have no working connectivity over it. Used by
// prioritizeServers to silence v6 tuples (or v4 tuples) on hosts where
// that family is broken — with periodic probes so the situation is noticed
// when it recovers.
type FamilyTracker struct {
	mu              sync.Mutex
	window          time.Duration
	threshold       int
	suspectDuration time.Duration
	probeInterval   time.Duration

	v4 familyStats
	v6 familyStats
}

type familyStats struct {
	recentFailures  []time.Time // sliding window of failure timestamps
	recentSuccesses []time.Time // sliding window of success timestamps
	suspectUntil    time.Time   // zero if not suspect; otherwise the time the suspect mark lifts
	lastProbeAt     time.Time   // most recent time ShouldProbe returned true
}

// FamilyStatsSnapshot is the read-only view returned by Snapshot for
// observability dumps.
type FamilyStatsSnapshot struct {
	RecentFailures  int
	RecentSuccesses int
	SuspectUntil    time.Time
	LastProbeAt     time.Time
}

// NewFamilyTracker constructs a tracker with the given knobs. All durations
// must be > 0; threshold must be > 0. Caller is responsible for sourcing
// these from ImrTuningConf.AddressFamily.
func NewFamilyTracker(window, suspect, probe time.Duration, threshold int) *FamilyTracker {
	return &FamilyTracker{
		window:          window,
		threshold:       threshold,
		suspectDuration: suspect,
		probeInterval:   probe,
	}
}

// RecordResult folds a single query outcome into the tracker. A successful
// outcome immediately clears the suspect mark for that family (the path
// works again). A failure may mark the family suspect if enough failures
// accumulate within the sliding window with zero successes.
func (f *FamilyTracker) RecordResult(addr string, success bool) {
	if f == nil {
		return
	}
	fam := familyOf(addr)
	if fam == FamilyUnknown {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	stats := f.statsFor(fam)
	now := time.Now()
	f.expire(stats, now)
	if success {
		stats.recentSuccesses = append(stats.recentSuccesses, now)
		stats.suspectUntil = time.Time{}
		return
	}
	stats.recentFailures = append(stats.recentFailures, now)
	if len(stats.recentFailures) >= f.threshold && len(stats.recentSuccesses) == 0 {
		stats.suspectUntil = now.Add(f.suspectDuration)
	}
}

// IsSuspect reports whether a family is currently in the suspect state.
// Returns false once the suspect window expires (even with no fresh
// evidence) — that's the recovery handshake: at the end of SuspectDuration
// the family is given the benefit of the doubt and re-considered.
func (f *FamilyTracker) IsSuspect(fam AddressFamily) bool {
	if f == nil || fam == FamilyUnknown {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	stats := f.statsFor(fam)
	return !stats.suspectUntil.IsZero() && time.Now().Before(stats.suspectUntil)
}

// ShouldProbe is the throttle for sneaking one suspect-family tuple into the
// prioritized list per ProbeInterval. Returns true at most once per
// ProbeInterval while suspect, and advances LastProbeAt as a side effect.
// Returns false when not suspect (the regular sort already includes that
// family) or when called too soon after a previous probe.
func (f *FamilyTracker) ShouldProbe(fam AddressFamily) bool {
	if f == nil || fam == FamilyUnknown {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	stats := f.statsFor(fam)
	if stats.suspectUntil.IsZero() {
		return false
	}
	now := time.Now()
	if !now.Before(stats.suspectUntil) {
		// suspect period expired; nothing to probe
		return false
	}
	if !stats.lastProbeAt.IsZero() && now.Sub(stats.lastProbeAt) < f.probeInterval {
		return false
	}
	stats.lastProbeAt = now
	return true
}

// Snapshot returns a thread-safe summary of the tracker state for dumps.
func (f *FamilyTracker) Snapshot() (v4, v6 FamilyStatsSnapshot) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	f.expire(&f.v4, now)
	f.expire(&f.v6, now)
	v4 = FamilyStatsSnapshot{
		RecentFailures:  len(f.v4.recentFailures),
		RecentSuccesses: len(f.v4.recentSuccesses),
		SuspectUntil:    f.v4.suspectUntil,
		LastProbeAt:     f.v4.lastProbeAt,
	}
	v6 = FamilyStatsSnapshot{
		RecentFailures:  len(f.v6.recentFailures),
		RecentSuccesses: len(f.v6.recentSuccesses),
		SuspectUntil:    f.v6.suspectUntil,
		LastProbeAt:     f.v6.lastProbeAt,
	}
	return
}

// FamilyOf parses an address (with or without port) and returns its address
// family. Exported so the IMR can avoid duplicating the parsing logic.
func FamilyOf(addr string) AddressFamily {
	return familyOf(addr)
}

func (f *FamilyTracker) statsFor(fam AddressFamily) *familyStats {
	if fam == FamilyV4 {
		return &f.v4
	}
	return &f.v6
}

// expire trims failure / success slices to the sliding window. Caller holds
// f.mu.
func (f *FamilyTracker) expire(s *familyStats, now time.Time) {
	cutoff := now.Add(-f.window)
	s.recentFailures = trimBefore(s.recentFailures, cutoff)
	s.recentSuccesses = trimBefore(s.recentSuccesses, cutoff)
}

// trimBefore returns ts with all entries strictly before cutoff dropped.
// Allocates only when something is trimmed.
func trimBefore(ts []time.Time, cutoff time.Time) []time.Time {
	if len(ts) == 0 {
		return ts
	}
	keep := 0
	for _, t := range ts {
		if !t.Before(cutoff) {
			break
		}
		keep++
	}
	if keep == 0 {
		return ts
	}
	return append([]time.Time(nil), ts[keep:]...)
}

func familyOf(addr string) AddressFamily {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return FamilyUnknown
	}
	if ip.To4() != nil {
		return FamilyV4
	}
	return FamilyV6
}
