/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// One TTL per RRset, the largest (#996, part 1).
//
// The records of an RRset share one TTL (RFC 2181 §5.2). Content this server
// adopts -- a zone file, an AXFR, an applied IXFR delta -- can arrive with an
// RRset whose TTLs differ, and each such RRset is brought to the largest of
// them. An UPDATE does the same (setRRsetTTL). The largest rather than the
// smallest because a resolver may hold the RRset for that long anyway, from
// another server of the zone, and every server of a multi-provider zone then
// serves the same TTL (johanix/tdns-mp#369).
//
// A zone that signs its own content signs the unified RRset afresh, so the
// signature's original TTL is the unified one, and the signer's TTL clamp
// (applyClampToRRset) lowers it from there: unify first, then clamp. A
// relayed copy that is already signed keeps the signatures it came with, so
// its RRsets are never raised above the original TTL those signatures carry.
//
// Not touched: the SOA, a single record; NSEC, whose TTL follows the SOA's
// negative TTL (RFC 9077) and which lives outside RRtypes; and, in a zone
// that signs its own content, DNSKEY, which the signer rebuilds from its
// keystore (part 2 of #996).

// unifyAdoptedTTLs brings each RRset in data whose TTLs differ to one TTL, and
// returns how many it rewrote. owners, when not nil, limits the walk to those
// owners: an applied IXFR delta shares every other owner with the published
// snapshot, which was unified when it arrived and must not be written. The
// stores walked are the adopted content's own, not yet published; the records
// in them may be shared, so a record whose TTL changes is replaced by a copy.
func unifyAdoptedTTLs(data *core.NameMap[OwnerData], owners map[string]bool, signsHere bool) int {
	if data == nil {
		return 0
	}
	rewritten := 0
	visit := func(name string, od OwnerData) {
		if od.RRtypes == nil {
			return
		}
		for _, t := range od.RRtypes.Keys() {
			if t == dns.TypeSOA || (signsHere && t == dns.TypeDNSKEY) {
				continue
			}
			rs := od.RRtypes.GetOnlyRRSet(t)
			ttl, mixed := unifiedTTL(rs, signsHere)
			if !mixed {
				continue
			}
			lg.Debug("unified the TTLs of an RRset to the largest", "owner", name,
				"rrtype", dns.TypeToString[t], "ttl", ttl)
			od.RRtypes.Set(t, rrsetWithTTL(rs, ttl, signsHere)) // mutator-ok: the adopted content's own store, not yet published or shared
			rewritten++
		}
	}
	if owners == nil {
		for name, od := range data.Items() {
			visit(name, od)
		}
		return rewritten
	}
	for name := range owners {
		if od, ok := data.Get(name); ok {
			visit(name, od)
		}
	}
	return rewritten
}

// unifiedTTL returns the TTL an RRset is to have and whether its TTLs differ.
// That is the largest of them, except in a relayed signed copy (signsHere
// false), where it is never above the smallest original TTL of the RRSIGs
// covering the RRset: the signature stays as it came, and a TTL above its
// original one would be served for longer than its signer said.
func unifiedTTL(rs core.RRset, signsHere bool) (uint32, bool) {
	if len(rs.RRs) < 2 {
		return 0, false
	}
	lo, hi := rs.RRs[0].Header().Ttl, rs.RRs[0].Header().Ttl
	for _, rr := range rs.RRs[1:] {
		lo, hi = min(lo, rr.Header().Ttl), max(hi, rr.Header().Ttl)
	}
	if lo == hi {
		return 0, false
	}
	if !signsHere {
		for _, rr := range rs.RRSIGs {
			if sig, ok := rr.(*dns.RRSIG); ok {
				hi = min(hi, sig.OrigTtl)
			}
		}
	}
	return hi, true
}

// rrsetWithTTL returns rs with every record at ttl. Records already at ttl keep
// their pointers; the others are copies. In a zone that signs its own content
// the RRSIGs are dropped, so the publish signs the RRset afresh at its new TTL
// rather than keep a signature whose original TTL is not the one served. In a
// relayed copy they are kept, at the TTL of the RRset they cover (RFC 4034
// §3); a signature does not cover its own TTL.
//
// An RRset the signer has clamped (a touched owner of an applied IXFR delta)
// is served below its own TTL, which UnclampedTTL holds, so its records are
// at the clamp and only a record the delta added can be above it. Its own TTL
// is then the larger of the two, and signing clamps the records again.
func rrsetWithTTL(rs core.RRset, ttl uint32, signsHere bool) core.RRset {
	out := rs
	if rs.UnclampedTTL != 0 {
		out.UnclampedTTL = max(rs.UnclampedTTL, ttl)
	}
	out.RRs = recordsWithTTL(rs.RRs, ttl)
	if signsHere {
		out.RRSIGs = nil
	} else {
		out.RRSIGs = recordsWithTTL(rs.RRSIGs, ttl)
	}
	return out
}

func recordsWithTTL(rrs []dns.RR, ttl uint32) []dns.RR {
	if len(rrs) == 0 {
		return rrs
	}
	out := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		if rr.Header().Ttl == ttl {
			out[i] = rr
			continue
		}
		c := dns.Copy(rr)
		c.Header().Ttl = ttl
		out[i] = c
	}
	return out
}
