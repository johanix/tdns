/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"math"
	"math/rand"
	"sync"
	"time"
)

// BackoffPolicy is a plain-data snapshot of the tunable values that
// drive address-backoff durations. The cache package cannot import
// the parent tdns package (which owns the YAML/mapstructure conf
// type), so the parent calls SetBackoffPolicy at IMR init time to
// inject the resolved values.
//
// All fields use sensible defaults until SetBackoffPolicy is called.
// Defaults mirror the historical hardcoded constants so behaviour
// matches the pre-W2 baseline if nothing is wired up.
type BackoffPolicy struct {
	FirstFailure   time.Duration // first failure base backoff
	MaxFailure     time.Duration // upper bound for exponential growth
	Multiplier     float64       // exponential growth factor per consecutive failure
	JitterFraction float64       // ±fraction applied to the chosen duration
	RoutingFailure time.Duration // immediate backoff on routing errors
	LameDelegation time.Duration // backoff on REFUSED / NOTAUTH / SERVFAIL (lame delegation)
}

var (
	backoffMu     sync.RWMutex
	backoffPolicy = BackoffPolicy{
		// Pre-W2 defaults — overridden by SetBackoffPolicy at IMR init.
		FirstFailure:   2 * time.Minute,
		MaxFailure:     1 * time.Hour,
		Multiplier:     3.0,
		JitterFraction: 0.0,
		RoutingFailure: 1 * time.Hour,
		LameDelegation: 1 * time.Hour,
	}
)

// SetBackoffPolicy replaces the active policy. Safe for concurrent
// calls. Typically invoked once at IMR init.
func SetBackoffPolicy(p BackoffPolicy) {
	backoffMu.Lock()
	defer backoffMu.Unlock()
	backoffPolicy = p
}

// GetBackoffPolicy returns a copy of the active policy. Used by
// dump commands so operators can see what's in effect.
func GetBackoffPolicy() BackoffPolicy {
	backoffMu.RLock()
	defer backoffMu.RUnlock()
	return backoffPolicy
}

// exponentialBackoff returns the base duration for the given
// consecutive-failure count using the current policy. count=0 means
// "first failure ever" and returns FirstFailure. Higher counts grow
// geometrically and are capped at MaxFailure.
func exponentialBackoff(count uint8) time.Duration {
	p := GetBackoffPolicy()
	if count == 0 {
		return p.FirstFailure
	}
	d := time.Duration(float64(p.FirstFailure) * math.Pow(p.Multiplier, float64(count)))
	if d <= 0 || d > p.MaxFailure {
		return p.MaxFailure
	}
	return d
}

// applyJitter returns d ± a random fraction of d as configured by
// JitterFraction. Fraction <= 0 returns d unchanged. The randomness
// uses math/rand (default-seeded in modern Go); this is not security
// sensitive.
func applyJitter(d time.Duration) time.Duration {
	frac := GetBackoffPolicy().JitterFraction
	if frac <= 0 || d <= 0 {
		return d
	}
	delta := float64(d) * frac * (2*rand.Float64() - 1) // ±frac
	out := d + time.Duration(delta)
	if out <= 0 {
		return d
	}
	return out
}
