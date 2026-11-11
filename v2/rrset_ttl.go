/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"sort"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// One TTL per RRset, the largest (#996, part 1).
//
// The records of an RRset share one TTL (RFC 2181 §5.2). Content a zone
// adopts -- a zone file, an AXFR, an applied IXFR delta -- can arrive with an
// RRset whose TTLs differ, and in a zone this server is told to modify
// (toldToModify) each such RRset is brought to the largest of them. An UPDATE
// does the same (setRRsetTTL). The largest rather than the smallest because a
// resolver may hold the RRset for that long anyway, from another server of the
// zone, and every server of a multi-provider zone then serves the same TTL
// (johanix/tdns-mp#369).
//
// A secondary that is told nothing of the kind is a copy of its upstream and
// is served as received, mixed TTLs included, with a warning. So is any zone
// that carries a ZONEMD this server does not compute: the digest covers every
// TTL (adoptedTTLsUnify).
//
// A zone that signs its own content signs the unified RRset afresh, so the
// signature's original TTL is the unified one, and the signer's TTL clamp
// (applyClampToRRset) lowers it from there: unify first, then clamp. A zone
// that does not sign here but holds signatures -- a zone file signed
// elsewhere -- keeps the signatures it came with, so its RRsets are never
// raised above the original TTL those signatures carry.
//
// Not touched: the SOA, a single record; NSEC, whose TTL follows the SOA's
// negative TTL (RFC 9077) and which lives outside RRtypes; and, in a zone
// that signs its own content, DNSKEY, which the signer rebuilds from its
// keystore (part 2 of #996).

// modifyingOptions are the zone options that tell this server to write into a
// zone: UPDATE from clients and from children, RR changes over the API, and
// the combiner's edits. On tdns-auth a secondary that may not originate
// content has the first three stripped when its configuration is parsed
// (normalizeOptionsForRole).
var modifyingOptions = []ZoneOption{OptAllowUpdates, OptAllowChildUpdates, OptAllowApiUpdates, OptAllowEdits}

// toldToModify reports whether this server is told to change the zone's
// content, and so may unify the TTLs of what it adopts: the zone is a primary,
// whose content is this server's own; it signs the zone here; or it accepts
// changes (modifyingOptions). A secondary told none of these is a copy of its
// upstream, and a secondary is immutable (#996, ruling of 2026-11-09). Never
// in a zone that may not originate content (zoneMayOriginateContent),
// whatever its options say.
func (zd *ZoneData) toldToModify() bool {
	if !zoneMayOriginateContent(zd) {
		return false
	}
	if zd.ZoneType == Primary || zd.signsItsOwnContent() {
		return true
	}
	for _, opt := range modifyingOptions {
		if zd.Options[opt] {
			return true
		}
	}
	return false
}

// adoptedTTLsUnify reports whether the RRsets of content this zone adopts are
// brought to one TTL, and when they are not, why. They are in a zone told to
// modify its content, unless the content carries a ZONEMD this server does not
// compute: that digest covers every TTL, and unifying would leave it not
// describing the zone. One the zone computes itself (publish-zonemd) is
// computed again at the publish, after the unification.
func (zd *ZoneData) adoptedTTLsUnify(data *core.NameMap[OwnerData]) (bool, string) {
	if !zd.toldToModify() {
		return false, "a secondary is served as it was received"
	}
	if hasApexZonemd(data, zd.ZoneName) && !zd.zoneManagesZonemd() {
		return false, "the zone carries a ZONEMD this server does not compute, which unifying would break"
	}
	return true, ""
}

func hasApexZonemd(data *core.NameMap[OwnerData], apex string) bool {
	if data == nil {
		return false
	}
	od, ok := data.Get(apex)
	return ok && od.RRtypes != nil && len(od.RRtypes.GetOnlyRRSet(dns.TypeZONEMD).RRs) > 0
}

// walkAdoptedRRsets calls fn for each RRset in data that the TTL rule covers:
// all but the SOA and, in a zone that signs here, DNSKEY. owners, when not
// nil, limits the walk to those owners: an applied IXFR delta shares every
// other owner with the published snapshot, which was dealt with when it
// arrived and must not be written.
func walkAdoptedRRsets(data *core.NameMap[OwnerData], owners map[string]bool, signsHere bool,
	fn func(name string, od OwnerData, t uint16, rs core.RRset)) {
	if data == nil {
		return
	}
	visit := func(name string, od OwnerData) {
		if od.RRtypes == nil {
			return
		}
		for _, t := range od.RRtypes.Keys() {
			if t == dns.TypeSOA || (signsHere && t == dns.TypeDNSKEY) {
				continue
			}
			fn(name, od, t, od.RRtypes.GetOnlyRRSet(t))
		}
	}
	if owners == nil {
		for name, od := range data.Items() {
			visit(name, od)
		}
		return
	}
	for name := range owners {
		if od, ok := data.Get(name); ok {
			visit(name, od)
		}
	}
}

// unifyAdoptedTTLs brings each RRset in data whose TTLs differ to one TTL, and
// returns how many it rewrote. The stores walked are the adopted content's
// own, not yet published; the records in them may be shared, so a record whose
// TTL changes is replaced by a copy.
func unifyAdoptedTTLs(data *core.NameMap[OwnerData], owners map[string]bool, signsHere bool) int {
	rewritten := 0
	walkAdoptedRRsets(data, owners, signsHere, func(name string, od OwnerData, t uint16, rs core.RRset) {
		ttl, mixed := unifiedTTL(rs, signsHere)
		if !mixed {
			return
		}
		lg.Debug("unified the TTLs of an RRset to the largest", "owner", name,
			"rrtype", dns.TypeToString[t], "ttl", ttl)
		od.RRtypes.Set(t, rrsetWithTTL(rs, ttl, signsHere)) // mutator-ok: the adopted content's own store, not yet published or shared
		rewritten++
	})
	return rewritten
}

// mixedTTLRRsets names the RRsets in data whose TTLs differ, as "owner TYPE",
// sorted, walking what unifyAdoptedTTLs would.
func mixedTTLRRsets(data *core.NameMap[OwnerData], owners map[string]bool, signsHere bool) []string {
	var out []string
	walkAdoptedRRsets(data, owners, signsHere, func(name string, _ OwnerData, t uint16, rs core.RRset) {
		if _, mixed := unifiedTTL(rs, true); mixed { // true: whether they differ, not the cap
			out = append(out, name+" "+dns.TypeToString[t])
		}
	})
	sort.Strings(out)
	return out
}

// unifiedTTL returns the TTL an RRset is to have and whether its TTLs differ.
// That is the largest of them, except in a copy signed elsewhere (signsHere
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
// copy signed elsewhere they are kept, at the TTL of the RRset they cover
// (RFC 4034 §3); a signature does not cover its own TTL.
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
