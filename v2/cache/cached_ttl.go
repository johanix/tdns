/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Handing a cached RRset to a client: the TTL on the wire is what is LEFT of
 * the entry's lifetime, not what it was given when it was cached.
 */
package cache

import (
	"time"

	"github.com/miekg/dns"
)

// RemainingTTL is the entry's remaining lifetime in whole seconds, floored at
// zero.
//
// Set() records an absolute Expiration and leaves the stored RRs carrying the
// TTL they arrived with, so this is the only honest source for what to put on
// the wire. Rounded DOWN: a TTL rounded up outlives the entry that justifies
// it, and the last fractional second is worth less than a downstream cache
// holding data this resolver has already dropped.
//
// Zero is a legitimate answer -- RFC 2181 §8 -- and says "usable now, do not
// cache". An entry that reaches zero here is within a second of eviction, so
// that is exactly right.
func (c *CachedRRset) RemainingTTL(now time.Time) uint32 {
	if c == nil || c.Expiration.IsZero() {
		return 0
	}
	left := c.Expiration.Sub(now)
	if left <= 0 {
		return 0
	}
	return uint32(left / time.Second)
}

// ServeRRs returns the records with their TTL set to the entry's remaining
// lifetime.
//
// COPIES, always. The cached RRs are shared: the caller puts the result
// straight into a dns.Msg section, and rewriting the TTL in place would edit
// the cache itself -- every later reader would see the remaining lifetime as
// computed for one earlier client, decreasing on every hit until the record
// was served with a TTL of zero while the entry itself was still fresh. It
// would also be a data race, since nothing holds a lock across the serve.
//
// Aliasing was already a hazard here without the TTL rewrite: assigning the
// cached slice into m.Answer hands the cache's own backing array to the
// message layer.
func (c *CachedRRset) ServeRRs(rrs []dns.RR, now time.Time) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	ttl := c.RemainingTTL(now)
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		cp := dns.Copy(rr)
		cp.Header().Ttl = ttl
		out = append(out, cp)
	}
	return out
}

// ServeAnswer is ServeRRs over the entry's own RRset, with the RRSIGs appended
// when the client asked for them. The signatures carry the same remaining
// lifetime as the records they cover, which is what an authoritative server
// would have served and what a validator expects.
func (c *CachedRRset) ServeAnswer(now time.Time, withSigs bool) []dns.RR {
	if c == nil || c.RRset == nil {
		return nil
	}
	out := c.ServeRRs(c.RRset.RRs, now)
	if withSigs {
		out = append(out, c.ServeRRs(c.RRset.RRSIGs, now)...)
	}
	return out
}
