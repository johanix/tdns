/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// How long an authenticated entry may live (RFC 4035 section 5.3.3): no
// longer than the TTL of its records, the TTL of the RRSIGs over them, their
// Original TTL field, and the time left to their Signature Expiration.
//
// The bound is read from the RRSIGs the entry holds, for the RRset, a kept
// wildcard proof and a denial's proof alike, each time the entry is stored or
// its verdict changes: not from TTLs that validation lowered in place, which
// a verdict reached earlier, or later, does not do. It applies to entries held
// Secure only. Section 5.3.3 is about RRsets that have been authenticated, and
// a validator caps their TTL when a signature verifies. An entry that is not
// Secure is not served as authenticated, and capping it by signatures nothing
// verified would only shorten the life of data from zones that are not
// validated -- to nothing, for a zone that serves expired signatures beside
// an insecure delegation.
//
// Only an RRSIG within its validity period counts: one that is not cannot
// have authenticated anything. Of those, the smallest bound is taken, over
// every RRSIG of every RRset the entry holds. That is conservative when an
// RRset carries more than one: the one that verified may expire later than
// another one. A signature that has not verified can only shorten the
// lifetime this way, never extend it.
//
// The RRSIG's TTL and Original TTL bound the lifetime as TTLs do, so
// cache-min-ttl can raise them. The time left to the Signature Expiration
// bounds it after cache-min-ttl and cache-max-ttl: no setting serves an
// authenticated entry past the signatures that authenticated it.

// entrySignedSets returns the RRsets c holds whose RRSIGs bound its lifetime:
// its RRset, a kept wildcard proof, and a denial's proof.
func entrySignedSets(c *CachedRRset) []*core.RRset {
	sets := append([]*core.RRset{c.RRset}, c.WildcardProof...)
	if negativeContext(c.Context) {
		sets = append(sets, c.NegAuthority...)
	}
	return sets
}

// signatureBounds reads the RRSIGs over sets that are within their validity
// period at now. It returns the smallest of their TTLs and Original TTL
// fields, and the earliest of their Signature Expirations. ok is false when
// there is no such RRSIG.
func signatureBounds(sets []*core.RRset, now time.Time) (ttl uint32, expires time.Time, ok bool) {
	for _, set := range sets {
		if set == nil {
			continue
		}
		for _, rr := range set.RRSIGs {
			sig, isSig := rr.(*dns.RRSIG)
			if !isSig || !WithinValidityPeriod(sig.Inception, sig.Expiration, now) {
				continue
			}
			t := min(sig.Hdr.Ttl, sig.OrigTtl)
			exp := now.Add(signatureTTLCap(sig.Expiration, now))
			if !ok || t < ttl {
				ttl = t
			}
			if !ok || exp.Before(expires) {
				expires = exp
			}
			ok = true
		}
	}
	return ttl, expires, ok
}
