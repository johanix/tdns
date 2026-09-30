/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"net"
	"slices"
	"strings"

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

// ownZoneTransport is what an answer from the server's own zone is reported,
// and cached, as having arrived over. It crossed no wire; Do53 claims no
// encryption, the safe side of the privacy status a client is given.
const ownZoneTransport = core.TransportDo53

// ownZoneForQuestion returns the zone this server serves the answer to <qname,
// qtype> from, or nil when there is none. A DS is the parent side's data, in
// the closest hosted zone above qname (FindParentZone, as the DS query path
// finds it); anything else is in the closest hosted zone that holds qname
// (FindZoneOrRoot, as the query handler finds it). The zone must be answering
// queries (servesQueries), and qname must not be at or below one of its cuts:
// there the zone holds only the delegation, and answers with a referral.
//
// Own data comes before any forward or stub: the server does not ask anyone
// about a zone it is authoritative for.
func (imr *Imr) ownZoneForQuestion(qname string, qtype uint16) *ZoneData {
	// The standalone resolver, and every other daemon without zones.
	if Zones.IsEmpty() {
		return nil
	}
	// Not data: the responder refuses them, or they are not asked of it.
	if core.IsMetaType(qtype) || core.IsReservedType(qtype) {
		return nil
	}
	qname = dns.Fqdn(qname)
	var zd *ZoneData
	if qtype == dns.TypeDS {
		if qname == "." {
			return nil
		}
		zd = FindParentZone(qname)
	} else {
		zd = FindZoneOrRoot(qname)
	}
	if zd == nil || !zd.servesQueries() || zd.modifiedDownstream() {
		return nil
	}
	snap := zd.publishedSnapshot()
	if snap == nil {
		return nil
	}
	if cdd := zd.findDelegationFrom(snap, qname, false); cdd != nil &&
		!(qtype == dns.TypeDS && core.EqualNames(cdd.ChildName, qname)) {
		return nil
	}
	return zd
}

// answeredLocally reports whether the question <qname, qtype> is answered from
// a zone this server is authoritative for. The cache's validator asks, through
// RRsetCacheT.AnsweredLocally.
func (imr *Imr) answeredLocally(qname string, qtype uint16) bool {
	return imr.ownZoneForQuestion(qname, qtype) != nil
}

// ownZonePending reports whether zone is one this server is to answer from
// but does not yet: it is registered, or listed in the configuration, and not
// answering queries. Every configured zone is in that state while the daemon
// starts, as the resolver starts before the zones load.
func (imr *Imr) ownZonePending(conf *Config, zone string) bool {
	if Globals.App.Type == AppTypeAgent || imr.ownZoneForQuestion(zone, dns.TypeDNSKEY) != nil {
		return false
	}
	// A zone modified downstream is never answered from, loaded or not.
	if zd, ok := Zones.Get(zone); ok {
		return !zd.modifiedDownstream()
	}
	if conf == nil || !slices.ContainsFunc(conf.Internal.AllZones, func(z string) bool { return core.EqualNames(z, zone) }) {
		return false
	}
	for i := range conf.Zones {
		if core.EqualNames(conf.Zones[i].Name, zone) && slices.ContainsFunc(conf.Zones[i].OptionsStrs, func(o string) bool {
			return strings.EqualFold(strings.TrimSpace(o), ZoneOptionToString[OptModifiedDownstream])
		}) {
			return false
		}
	}
	return true
}

// modifiedDownstream reports whether zd carries the zone option
// modified-downstream: the copy held here is not the zone the world sees,
// because downstream of this server it is signed or changed in ways this
// server does not know of -- the source of a multi-provider zone, whose
// providers add the keys and signatures, or a primary behind a signer. The
// resolver never answers a question about such a zone from it: the question
// goes where any other goes, and the answer is the published zone's, through
// the parent's delegation and validated through the parent's DS (#863).
func (zd *ZoneData) modifiedDownstream() bool {
	return zd != nil && zd.Options[OptModifiedDownstream]
}

// forgetResolverSource drops what the running resolver holds about zone, after
// a reload turned modified-downstream on or off for it: it came from the source
// the resolver no longer uses. Turned on, that is what the copy answered --
// NODATA for the keys it lacks, its data, the zone held Insecure, which never
// lapses -- and until it expired the parent went on refusing the child's
// updates. Turned off, it is the published zone's answers, which the copy gives
// now. The next question goes to the new source, as a changed delegation's does
// (invalidateImrDelegations).
func forgetResolverSource(zone string) {
	imr := Globals.ImrEngine
	if imr == nil || imr.Cache == nil {
		return
	}
	if n, err := imr.Cache.FlushDomain(zone, false); err == nil {
		lgImr.Info("modified-downstream changed; dropped what the resolver held about the zone",
			"zone", zone, "entries", n)
	}
}

// servesQueries reports whether zd answers queries now, by the tests
// DefaultQueryHandler applies before it hands one to QueryResponder: the zone
// has published data, no service-impacting error, and has not passed SOA
// EXPIRE. A zone held only for transfer answers nothing, and nor does an agent,
// which answers no ordinary query.
func (zd *ZoneData) servesQueries() bool {
	if Globals.App.Type == AppTypeAgent || zd.ZoneStore == XfrZone {
		return false
	}
	return zd.HasPublishedData() && !zd.HasServiceImpactingError() && !zd.HasExpired()
}

// localResponse is zd's response to <qname, qtype> asked with DO set, as a
// validating resolver asks it: the message QueryResponder would send. A copy,
// because the responder hands out the published snapshot's own records, and the
// resolver caches what it is given and caps TTLs in place.
func (zd *ZoneData) localResponse(ctx context.Context, qname string, qtype uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(qname, qtype)
	q.SetEdns0(dns.DefaultMsgSize, true)
	msgoptions, err := edns0.ExtractFlagsAndEDNS0Options(q)
	if err != nil {
		return nil
	}
	kdb := zd.KeyDB
	if kdb == nil {
		kdb = Conf.Internal.KeyDB
	}
	w := &localResponseWriter{}
	if err := zd.QueryResponder(ctx, w, q, qname, qtype, msgoptions, kdb, nil); err != nil || w.msg == nil {
		return nil
	}
	return w.msg.Copy()
}

// localResponseWriter keeps the response QueryResponder writes. Nothing is sent
// anywhere.
type localResponseWriter struct{ msg *dns.Msg }

var localResponseAddr = &net.UDPAddr{IP: net.IPv6loopback, Port: 53}

func (w *localResponseWriter) LocalAddr() net.Addr       { return localResponseAddr }
func (w *localResponseWriter) RemoteAddr() net.Addr      { return localResponseAddr }
func (w *localResponseWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *localResponseWriter) Write(b []byte) (int, error) {
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return 0, err
	}
	w.msg = m
	return len(b), nil
}
func (w *localResponseWriter) Close() error        { return nil }
func (w *localResponseWriter) TsigStatus() error   { return nil }
func (w *localResponseWriter) TsigTimersOnly(bool) {}
func (w *localResponseWriter) Hijack()             {}

// holdOwnZoneKeys makes zd's own DNSKEY RRset the resolver's trust point for
// the zone, and returns zd's response to the DNSKEY question at its apex. The
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
func (imr *Imr) holdOwnZoneKeys(ctx context.Context, zd *ZoneData) *dns.Msg {
	apex := zd.ZoneName
	r := zd.localResponse(ctx, apex, dns.TypeDNSKEY)
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
// (ownZoneForQuestion). The response is processed as an authoritative server's
// is -- validated, cached, a CNAME followed -- once holdOwnZoneKeys has made
// the zone's own keys the ones it validates against. ok is false when the zone
// has no authoritative answer to give; the question then goes where it would
// have gone without the zone.
func (imr *Imr) answerFromOwnZone(ctx context.Context, qname string, qtype uint16, force bool, privacy edns0.PrivacyLevel) (*core.RRset, int, cache.CacheContext, core.Transport, error, bool) {
	zd := imr.ownZoneForQuestion(qname, qtype)
	if zd == nil {
		return nil, 0, cache.ContextFailure, ownZoneTransport, nil, false
	}
	r := imr.holdOwnZoneKeys(ctx, zd)
	if qtype != dns.TypeDNSKEY || !core.EqualNames(qname, zd.ZoneName) {
		r = zd.localResponse(ctx, qname, qtype)
	}
	if r == nil || !r.Authoritative || (r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError) {
		lgImr.Debug("own zone has no authoritative answer; asking elsewhere",
			"zone", zd.ZoneName, "qname", qname, "qtype", dns.TypeToString[qtype])
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
		if cctx, rcode, handled := imr.handleNegative(qname, qtype, r, ownZoneTransport, zd.ZoneName); handled {
			return nil, rcode, cctx, ownZoneTransport, nil, true
		}
	}
	return nil, 0, cache.ContextFailure, ownZoneTransport, nil, false
}
