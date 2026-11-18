/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr

import (
	"context"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// Questions about a zone this server is authoritative for (#842).
//
// The resolver sent them where it sends any other question: to a forward's
// upstream, to a stub, or down the tree from the root. A parent forwarding "."
// fetched its own zone's DNSKEY RRset from the upstream to initialise its trust
// anchor, and a child's DS, with the DNSKEY RRset that signs it, to validate
// the child's keys for a DS UPDATE. That put a third party's cache, TTLs and
// validation between the server and its own data, and a child was refused for
// what the upstream held at that moment.
//
// Such a question is answered in process now, from the zone's published data,
// by the QueryResponder that answers it on the wire (localResponse), and the
// answer is processed as any authoritative answer is. Only an authoritative
// answer is taken: data, NXDOMAIN or NODATA. Whatever is at or below one of
// the zone's cuts, the DS at the cut excepted, is the child's data, and its
// question goes where it always went.
//
// The zone's own DNSKEY RRset is the trust point for its data. The resolver
// holds it Secure when the zone's own keys sign it (holdOwnZoneKeys), and the
// rest of the zone validates against it, locally, as data validates against
// any validated DNSKEY RRset. Nobody above the zone is asked to vouch for it.
//
// The resolver reaches the zones through OwnZones (Options.OwnZones). The
// daemon's is hostedZones, over the Zones map; an Imr without one answers
// nothing locally.

// OwnZones is how a resolver reaches the zones of the server it runs in. Nil
// is a server with no zones of its own.
type OwnZones interface {
	// ZoneFor returns the zone the server answers <qname, qtype> from, or
	// nil when there is none: the zone that holds the answer, answering
	// queries, not modified downstream, and qname not at or below one of its
	// cuts (a DS at the cut excepted).
	ZoneFor(qname string, qtype uint16) OwnZone
}

// OwnZone is one zone a resolver answers from (OwnZones.ZoneFor).
type OwnZone interface {
	// Apex is the zone's name.
	Apex() string
	// Response is the zone's response to <qname, qtype> asked with DO set,
	// as the server would send it, or nil when it gives none. A copy: the
	// resolver caches what it is given and caps TTLs in place.
	Response(ctx context.Context, qname string, qtype uint16) *dns.Msg
}

// ownZoneFor returns the zone the server answers <qname, qtype> from, or nil
// (OwnZones.ZoneFor).
func (imr *Imr) ownZoneFor(qname string, qtype uint16) OwnZone {
	if imr.ownZones == nil {
		return nil
	}
	return imr.ownZones.ZoneFor(qname, qtype)
}

// ownZoneTransport is what an answer from the server's own zone is reported,
// and cached, as having arrived over. It crossed no wire; Do53 claims no
// encryption, the safe side of the privacy status a client is given.
const ownZoneTransport = core.TransportDo53

// answeredLocally reports whether the question <qname, qtype> is answered from
// a zone this server is authoritative for. The cache's validator asks, through
// RRsetCacheT.AnsweredLocally.
func (imr *Imr) answeredLocally(qname string, qtype uint16) bool {
	return imr.ownZoneFor(qname, qtype) != nil
}

// holdOwnZoneKeys makes zone's own DNSKEY RRset the resolver's trust point
// for it, and returns zone's response to the DNSKEY question at its apex. The
// RRset is Secure when one of its own keys signs it: its keys go into the
// DNSKEY cache as a validated RRset's do, and the zone is held Secure. A zone
// with no DNSKEY RRset, or with one that none of its keys signs, is held
// Insecure: no validator could follow a chain of trust into it.
//
// Nothing above the zone is asked. Validating the zone's keys against a DS in
// the zone above would take the word of whoever answers for that zone about
// the server's own data, which is the dependency this removes.
//
// Done before every answer from the zone, so a key rollover is followed as soon
// as it is published.
func (imr *Imr) holdOwnZoneKeys(ctx context.Context, zone OwnZone) *dns.Msg {
	apex := zone.Apex()
	r := zone.Response(ctx, apex, dns.TypeDNSKEY)
	keys := &core.RRset{Name: apex, Class: dns.ClassINET, RRtype: dns.TypeDNSKEY}
	if r != nil {
		for _, rr := range r.Answer {
			if !core.EqualNames(rr.Header().Name, apex) {
				continue
			}
			switch v := rr.(type) {
			case *dns.DNSKEY:
				keys.RRs = append(keys.RRs, v)
			case *dns.RRSIG:
				if v.TypeCovered == dns.TypeDNSKEY {
					keys.RRSIGs = append(keys.RRSIGs, v)
				}
			}
		}
	}

	state := cache.ValidationStateInsecure
	for _, rr := range keys.RRs {
		dk := rr.(*dns.DNSKEY)
		if dk.Flags&dns.ZONE == 0 {
			continue
		}
		if ok, _ := cache.ValidateDNSKEYRRsetSignature(keys, dk.KeyTag(), apex, dk, imr.Verbose); ok {
			state = cache.ValidationStateSecure
			break
		}
	}

	if len(keys.RRs) > 0 {
		exp := cache.Now().Add(cache.GetMinTTL(keys.RRs))
		imr.Cache.Set(apex, dns.TypeDNSKEY, &cache.CachedRRset{
			Name:       apex,
			RRtype:     dns.TypeDNSKEY,
			Rcode:      uint8(dns.RcodeSuccess),
			RRset:      keys,
			Context:    cache.ContextAnswer,
			State:      state,
			Expiration: exp,
			Transport:  ownZoneTransport,
		})
		if state == cache.ValidationStateSecure {
			dkc := imr.Cache.DnskeyCache
			for _, rr := range keys.RRs {
				dk := rr.(*dns.DNSKEY)
				keyid := dk.KeyTag()
				// A configured trust anchor for the zone stays one.
				trustAnchor := false
				if existing := dkc.Get(apex, keyid); existing != nil {
					trustAnchor = existing.TrustAnchor
				}
				dkc.Set(apex, keyid, &cache.CachedDnskeyRRset{
					Name:        apex,
					Keyid:       keyid,
					State:       cache.ValidationStateSecure,
					TrustAnchor: trustAnchor,
					Dnskey:      *dk,
					Expiration:  exp,
				})
			}
		}
	}

	z, exists := imr.Cache.ZoneMap.Get(apex)
	if !exists {
		z = &cache.Zone{ZoneName: apex}
	}
	z.SetState(state)
	imr.Cache.ZoneMap.Set(apex, z)
	return r
}

// answerFromOwnZone answers <qname, qtype> from the zone this server is
// authoritative for that holds the answer, if there is one
// (OwnZones.ZoneFor). The response is processed as an authoritative server's
// is -- validated, cached, a CNAME followed -- once holdOwnZoneKeys has made
// the zone's own keys the ones it validates against. ok is false when the zone
// has no authoritative answer to give; the question then goes where it would
// have gone without the zone.
func (imr *Imr) answerFromOwnZone(ctx context.Context, qname string, qtype uint16, force bool, privacy edns0.PrivacyLevel) (*core.RRset, int, cache.CacheContext, core.Transport, error, bool) {
	z := imr.ownZoneFor(qname, qtype)
	if z == nil {
		return nil, 0, cache.ContextFailure, ownZoneTransport, nil, false
	}
	r := imr.holdOwnZoneKeys(ctx, z)
	if qtype != dns.TypeDNSKEY || !core.EqualNames(qname, z.Apex()) {
		r = z.Response(ctx, qname, qtype)
	}
	if r == nil || !r.Authoritative || (r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError) {
		imr.lgImr().Debug("own zone has no authoritative answer; asking elsewhere",
			"zone", z.Apex(), "qname", qname, "qtype", dns.TypeToString[qtype])
		return nil, 0, cache.ContextFailure, ownZoneTransport, nil, false
	}
	if len(r.Answer) > 0 {
		rrset, rcode, cctx, transport, err, done := imr.handleAnswer(ctx, qname, qtype, r, force, ownZoneTransport, privacy)
		if err != nil || done {
			return rrset, rcode, cctx, transport, err, true
		}
		return nil, 0, cache.ContextFailure, ownZoneTransport, nil, false
	}
	switch classifyResponse(qname, qtype, r) {
	case responseKindNegativeNoData, responseKindNegativeNXDOMAIN:
		if cctx, rcode, handled := imr.handleNegative(qname, qtype, r, ownZoneTransport, z.Apex()); handled {
			return nil, rcode, cctx, ownZoneTransport, nil, true
		}
	}
	return nil, 0, cache.ContextFailure, ownZoneTransport, nil, false
}
