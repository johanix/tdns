/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	cache "github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
)

// Which records in a referral's additional section the resolver uses.
//
// A referral names the delegated zone's nameservers, and its additional section
// may carry their addresses (glue) and transport signals (_dns.<nameserver>).
// The server that sent the referral speaks for the names in its own zone, the
// referring zone, and for no others. So an address record, or a transport
// signal, is used only when its owner lies at or below the referring zone. In
// the terms of RFC 9471 that is in-domain glue, for a nameserver at or below
// the delegated zone, and sibling glue, for one elsewhere in the referring
// zone. For a nameserver outside the referring zone the record is not used, and
// the nameserver's addresses are looked up, as for a referral without glue.
//
// When the referring zone is not known, only in-domain glue is used.
//
// The addresses are stored on the nameserver's AuthServer, which is one
// instance shared by every zone the nameserver serves, and in the cache under
// the nameserver's name: what a referral says about a name outside its zone
// would otherwise reach every zone that name serves.

// referralGlueZone returns the zone whose names a referral's additional section
// may give records for: referringZone, the zone of the servers that sent the
// referral, or, when that is not known, the delegated zone itself.
func referralGlueZone(referringZone, delegatedZone string) string {
	if referringZone != "" {
		return referringZone
	}
	return delegatedZone
}

// withinGlueZone reports whether a record owned by owner, in the additional
// section of a referral, lies within glueZone (referralGlueZone) and so may be
// used. With no glueZone nothing may.
func withinGlueZone(owner, glueZone string) bool {
	if owner == "" || glueZone == "" {
		return false
	}
	return dns.IsSubDomain(dns.CanonicalName(glueZone), dns.CanonicalName(owner))
}

// glueMayReplace reports whether glue for a name may be cached over existing,
// the entry the cache holds for the name and type. It may not replace a live
// authoritative answer, positive or negative: glue ranks below an answer
// (RFC 2181 section 5.4.1). An expired entry, or one that is itself referral
// data, may be replaced.
func glueMayReplace(existing *cache.CachedRRset) bool {
	if existing == nil || !existing.Expiration.After(cache.Now()) {
		return true
	}
	switch existing.Context {
	case cache.ContextAnswer, cache.ContextNoErrNoAns, cache.ContextNXDOMAIN:
		return false
	}
	return true
}
