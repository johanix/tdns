/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"time"

	"github.com/miekg/dns"
)

// How long a cache entry that holds records lives (entryLifetime).
//
// An entry lives for the smallest TTL among the records it holds and serves:
// its RRset, and the proof kept with an answer synthesized from a wildcard.
// A denial is cached for its negative TTL (RFC 2308 section 5): the SOA's TTL
// and its MINIMUM field, whichever is smaller, and no longer than any record
// of the proof served with it. cache-min-ttl and cache-max-ttl bound the
// result for data learned from the network (ttlBounded). An entry held
// Secure lives no longer than its signatures allow (signature_lifetime.go).
//
// The lifetime is computed from the records each time an entry is stored,
// whatever its caller computed: a caller's own Expiration is not used for an
// entry with records.

// negativeContext reports whether c is the context of a denial.
func negativeContext(c CacheContext) bool {
	return c == ContextNXDOMAIN || c == ContextNoErrNoAns
}

// entryLifetime returns the lifetime of c, an entry with records stored for
// qtype at storedAt: its TTL in seconds, and its expiration. limits are applied
// when bounded.
func entryLifetime(c *CachedRRset, qtype uint16, storedAt time.Time, limits TTLLimits, bounded bool) (uint32, time.Time) {
	ttl := c.RRset.RRs[0].Header().Ttl
	lower := func(t uint32) {
		if t < ttl {
			ttl = t
		}
	}
	for _, rr := range c.RRset.RRs[1:] {
		lower(rr.Header().Ttl)
	}
	// An answer synthesized from a wildcard lives no longer than the proof
	// kept with it, which is served beside it.
	for _, set := range c.WildcardProof {
		if set == nil {
			continue
		}
		for _, rr := range set.RRs {
			lower(rr.Header().Ttl)
		}
	}
	// A denial: its RRset is the SOA, and its proof is served beside it.
	if negativeContext(c.Context) {
		for _, rr := range c.RRset.RRs {
			if soa, ok := rr.(*dns.SOA); ok {
				lower(soa.Minttl)
			}
		}
		for _, set := range c.NegAuthority {
			if set == nil {
				continue
			}
			for _, rr := range set.RRs {
				lower(rr.Header().Ttl)
				if soa, ok := rr.(*dns.SOA); ok {
					lower(soa.Minttl)
				}
			}
		}
	}
	// An entry held Secure is bounded by the RRSIGs that can have
	// authenticated it (signature_lifetime.go): their TTL and Original TTL
	// here, as TTLs, and the time left to their expiration below.
	var sigExpires time.Time
	signed := false
	if c.State == ValidationStateSecure {
		var sigTTL uint32
		if sigTTL, sigExpires, signed = signatureBounds(entrySignedSets(c), storedAt); signed {
			lower(sigTTL)
		}
	}
	// A small floor for an NS RRset learned from a referral, so that a TTL
	// of 0 does not drop it at once.
	if qtype == dns.TypeNS && c.Context == ContextReferral && ttl == 0 {
		ttl = 10
	}
	if bounded {
		ttl = limits.Clamp(ttl)
	}
	expires := storedAt.Add(time.Duration(ttl) * time.Second)
	// After cache-min-ttl: nothing serves an authenticated entry past its
	// signatures.
	if signed && sigExpires.Before(expires) {
		expires = sigExpires
		ttl = uint32(max(expires.Sub(storedAt), 0) / time.Second)
	}
	return ttl, expires
}
