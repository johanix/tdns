/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"net"
	"slices"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// hostedZones is the daemon's OwnZones: the zones in Zones.
type hostedZones struct{}

func (hostedZones) ZoneFor(qname string, qtype uint16) OwnZone {
	if zd := ownZoneForQuestion(qname, qtype); zd != nil {
		return hostedZone{zd}
	}
	return nil
}

// hostedZone is a zone in Zones as an OwnZone.
type hostedZone struct{ zd *ZoneData }

func (z hostedZone) Apex() string { return z.zd.ZoneName }

func (z hostedZone) Response(ctx context.Context, qname string, qtype uint16) *dns.Msg {
	return z.zd.localResponse(ctx, qname, qtype)
}

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
func ownZoneForQuestion(qname string, qtype uint16) *ZoneData {
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

// ownZonePending reports whether zone is one this server is to answer from
// but does not yet: it is registered, or listed in the configuration, and not
// answering queries. Every configured zone is in that state while the daemon
// starts, as the resolver starts before the zones load.
func ownZonePending(conf *Config, zone string) bool {
	if Globals.App.Type == AppTypeAgent || ownZoneForQuestion(zone, dns.TypeDNSKEY) != nil {
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
		lgResolver.Info("modified-downstream changed; dropped what the resolver held about the zone",
			"zone", zone, "entries", n)
	}
}

// servesQueries reports whether zd answers queries now, by the tests
// DefaultQueryHandler applies before it hands one to QueryResponder: the zone
// has published data, no service-impacting error, is not withheld, and has not
// passed SOA EXPIRE. A zone held only for transfer answers nothing, and nor does
// an agent, which answers no ordinary query.
func (zd *ZoneData) servesQueries() bool {
	if Globals.App.Type == AppTypeAgent || zd.ZoneStore == XfrZone {
		return false
	}
	return zd.HasPublishedData() && !zd.HasServiceImpactingError() && !zd.Withheld() && !zd.HasExpired()
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

func (w *localResponseWriter) LocalAddr() net.Addr { return localResponseAddr }

func (w *localResponseWriter) RemoteAddr() net.Addr { return localResponseAddr }

func (w *localResponseWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }

func (w *localResponseWriter) Write(b []byte) (int, error) {
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return 0, err
	}
	w.msg = m
	return len(b), nil
}

func (w *localResponseWriter) Close() error { return nil }

func (w *localResponseWriter) TsigStatus() error { return nil }

func (w *localResponseWriter) TsigTimersOnly(bool) {}

func (w *localResponseWriter) Hijack() {}
