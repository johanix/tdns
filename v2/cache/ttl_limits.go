/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Bounding how long the resolver keeps what it learned from the network:
 * Unbound's cache-min-ttl and cache-max-ttl.
 */
package cache

import (
	"math"
	"sync/atomic"
	"time"
)

// TTLLimits bounds the lifetime, in seconds, of data cached from the network.
// Min is Unbound's cache-min-ttl, Max its cache-max-ttl; zero means no bound on
// that side. When Min > Max, Max wins, as in Unbound, which applies the floor
// first and the ceiling second.
//
// The limits are applied where an entry's lifetime is decided -- RRsetCacheT.Set,
// DnskeyCacheT.Set and StoreTLSAForServer -- and nowhere else. The TTL a client
// sees is always the entry's remaining lifetime (RemainingTTL), so bounding the
// lifetime bounds the TTL on the wire too: Unbound's "downstream clients also
// see the lower TTL", with no second path to keep in step.
//
// Like the backoff policy, the limits are process-wide: the IMR is a process
// singleton, DnskeyCache is a package global, and SetTTLLimits is called once
// at IMR init. Until then there are no limits, which is the cache's behaviour
// for every other user of this package.
type TTLLimits struct {
	Min uint32
	Max uint32
}

var ttlLimits atomic.Pointer[TTLLimits]

// SetTTLLimits installs the limits for every cache in the process.
func SetTTLLimits(l TTLLimits) {
	ttlLimits.Store(&l)
}

// GetTTLLimits returns the limits in force; the zero value if none were set.
func GetTTLLimits() TTLLimits {
	if l := ttlLimits.Load(); l != nil {
		return *l
	}
	return TTLLimits{}
}

// Clamp bounds a TTL in seconds.
func (l TTLLimits) Clamp(ttl uint32) uint32 {
	if l.Min > 0 && ttl < l.Min {
		ttl = l.Min
	}
	if l.Max > 0 && ttl > l.Max {
		ttl = l.Max
	}
	return ttl
}

// bound applies the limits to an entry expiring at exp, measured from now. It
// returns the bounded expiration and lifetime, and whether either changed. An
// entry within the limits keeps its exact expiration; a zero or past expiration
// is a lifetime of zero, which the floor raises like any other.
func (l TTLLimits) bound(exp, now time.Time) (time.Time, uint32, bool) {
	var left uint32
	if d := exp.Sub(now); !exp.IsZero() && d > 0 {
		left = uint32(min(d/time.Second, math.MaxUint32))
	}
	b := l.Clamp(left)
	if b == left {
		return exp, left, false
	}
	return now.Add(time.Duration(b) * time.Second), b, true
}

// ttlBounded reports whether entries of this context are subject to the
// limits: exactly the ones learned from the network. Hints and the entries
// seeded from trust anchors (ContextPriming) are configuration and keep the
// lifetime they were configured with -- Unbound keeps them outside its cache
// altogether. A failure marker's lifetime is the resolver's own choice, and a
// floor would pin it.
func ttlBounded(c CacheContext) bool {
	switch c {
	case ContextAnswer, ContextReferral, ContextGlue, ContextNXDOMAIN, ContextNoErrNoAns:
		return true
	}
	return false
}
