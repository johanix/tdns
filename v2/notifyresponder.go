/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"strings"
	"sync"

	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// advertisesDsyncNotify reports whether the parent zone's local DSYNC
// RRset advertises NOTIFY for the given RRtype. ANY-typed DSYNC RRs
// match every qtype. The DSYNC owner is "_dsync.<zone>" — same lookup
// that ops_dsync.go uses. In-memory zone read; no DNS round-trip.
//
// Returns false if the zone has no DSYNC RRset, no NOTIFY-scheme RR,
// or no RR matching the qtype. The NOTIFY responder uses this to gate
// incoming NOTIFY(CDS)/NOTIFY(CSYNC) before kicking off the async
// scan: a child mis-configured to send NOTIFY at a parent that
// advertises only UPDATE (or only NOTIFY for the other RRtype) gets
// REFUSED + EDENotifyDsyncSchemeNotAdvertised on the first attempt
// instead of a generic parent-publish-failure after attempt-timeout.
func (zd *ZoneData) advertisesDsyncNotify(qtype uint16) bool {
	owner, err := zd.GetOwner("_dsync." + zd.ZoneName)
	if err != nil || owner == nil {
		return false
	}
	rrset := owner.RRtypes.GetOnlyRRSet(core.TypeDSYNC)
	if rrset.RRs == nil {
		return false
	}
	for _, rr := range rrset.RRs {
		prr, ok := rr.(*dns.PrivateRR)
		if !ok {
			continue
		}
		ds, ok := prr.Data.(*core.DSYNC)
		if !ok {
			continue
		}
		if ds.Scheme != core.SchemeNotify {
			continue
		}
		if ds.Type == qtype || ds.Type == dns.TypeANY {
			return true
		}
	}
	return false
}

// NotifyHandlerWithCallback consumes DnsNotifyRequest messages from the DnsNotifyQ channel
// and calls the provided handler function. This allows custom NOTIFY handlers
// (like KDC for confirmation NOTIFYs) to process NOTIFYs via channels.
// handlerFunc: Function that processes a DnsNotifyRequest
func NotifyHandlerWithCallback(ctx context.Context, conf *Config, handlerFunc func(context.Context, *DnsNotifyRequest) error) error {
	dnsnotifyq := conf.Internal.DnsNotifyQ

	lgHandler.Info("DnsNotifyHandler starting (with callback)")
	lgHandler.Debug("DnsNotifyHandler channel info", "capacity", cap(dnsnotifyq))

	for {
		select {
		case <-ctx.Done():
			lgHandler.Info("DnsNotifyHandler: context cancelled")
			return nil
		case dnr, ok := <-dnsnotifyq:
			if !ok {
				lgHandler.Info("DnsNotifyHandler: dnsnotifyq closed")
				return nil
			}
			lgHandler.Debug("received NOTIFY from channel", "qname", dnr.Qname, "from", dnr.ResponseWriter.RemoteAddr())
			if err := handlerFunc(ctx, &dnr); err != nil {
				lgHandler.Error("error in NOTIFY handler", "err", err)
			} else {
				lgHandler.Debug("NOTIFY handler completed successfully")
			}
		}
	}
}

func NotifyHandler(ctx context.Context, conf *Config) error {
	zonech := conf.Internal.RefreshZoneCh
	dnsnotifyq := conf.Internal.DnsNotifyQ
	scannerq := conf.Internal.ScannerQ
	lgHandler.Info("DnsNotifyResponderEngine starting")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				lgHandler.Info("DnsNotifyResponderEngine: context cancelled")
				return
			case dhr, ok := <-dnsnotifyq:
				if !ok {
					lgHandler.Info("DnsNotifyResponderEngine: dnsnotifyq closed")
					return
				}
				NotifyResponder(ctx, &dhr, zonech, scannerq)
			}

		}
	}()
	wg.Wait()

	lgHandler.Info("DnsNotifyResponderEngine: terminating")
	return nil
}

// TODO: Add per-source rate limiting for NOTIFY messages. An attacker could flood
// the server with NOTIFY messages to trigger excessive zone refreshes and scanner
// scans. Consider a token bucket or sliding window rate limiter keyed by source IP.
func NotifyResponder(ctx context.Context, dnr *DnsNotifyRequest, zonech chan ZoneRefresher, scannerq chan ScanRequest) error {

	qname := dnr.Qname
	// ntype := dnr.Msg.Question[0].Qtype
	if dnr.Msg == nil || len(dnr.Msg.Question) == 0 {
		lgHandler.Warn("received NOTIFY with no question", "zone", qname)
		m := new(dns.Msg)
		m.MsgHdr.Rcode = dns.RcodeFormatError
		m.MsgHdr.Response = true
		m.MsgHdr.Authoritative = true
		if dnr.Msg != nil {
			m.MsgHdr.Id = dnr.Msg.MsgHdr.Id
		}
		if err := dnr.ResponseWriter.WriteMsg(m); err != nil {
			lgHandler.Error("WriteMsg error on FormatError", "err", err)
		}
		return nil
	}
	ntype := dnr.Msg.Question[0].Qtype

	lgHandler.Info("received NOTIFY", "type", dns.TypeToString[ntype], "zone", qname, "from", dnr.ResponseWriter.RemoteAddr())

	m := new(dns.Msg)
	m.SetReply(dnr.Msg)
	m.SetRcode(dnr.Msg, dns.RcodeSuccess)
	m.MsgHdr.Authoritative = true

	// Determine which zone this NOTIFY should target based on the NOTIFY type
	// - NOTIFY(SOA): targets the zone itself (qname)
	// - NOTIFY(CDS/CSYNC): targets the parent zone of qname
	// - NOTIFY(DNSKEY): targets the zone itself (qname) for multi-signer communication
	var zd *ZoneData
	var targetZoneName string

	switch ntype {
	case dns.TypeSOA, dns.TypeDNSKEY:
		// For SOA and DNSKEY, target the zone for qname itself.
		// FindZone walks up from qname so it can return a containing
		// zone for an interior name (e.g. host.example.com. resolves
		// to example.com.). NOTIFY(SOA)/NOTIFY(DNSKEY) for an
		// interior name is not a valid request — refuse it rather
		// than silently refreshing the containing zone.
		zd, _ = FindZone(qname)
		if zd == nil {
			lgHandler.Warn("received NOTIFY for unknown zone, ignoring", "type", dns.TypeToString[ntype], "zone", qname)
			m.SetRcode(dnr.Msg, dns.RcodeRefused)
			edns0.AttachEDEToResponseWithText(m, edns0.EDENotifyParentNotAuthoritative,
				fmt.Sprintf("server is not authoritative for %s", qname), false)
			dnr.ResponseWriter.WriteMsg(m)
			return nil
		}
		if !strings.EqualFold(dns.Fqdn(zd.ZoneName), dns.Fqdn(qname)) {
			// FindZone returned a containing zone, not an exact
			// zone match. Could be a child delegation point or a
			// plain interior name; either way we don't accept the
			// NOTIFY against the containing zone.
			if zd.IsChildDelegation(qname) {
				lgHandler.Warn("received NOTIFY for child delegation, ignoring", "type", dns.TypeToString[ntype], "qname", qname)
				m.SetRcode(dnr.Msg, dns.RcodeRefused)
				edns0.AttachEDEToResponseWithText(m, edns0.EDENotifyTargetNotChildDelegation,
					fmt.Sprintf("%s is a child delegation, not authoritative on this server", qname), false)
				dnr.ResponseWriter.WriteMsg(m)
				return nil
			}
			lgHandler.Warn("received NOTIFY for interior name in zone, ignoring", "type", dns.TypeToString[ntype], "qname", qname, "zone", zd.ZoneName)
			m.SetRcode(dnr.Msg, dns.RcodeRefused)
			edns0.AttachEDEToResponseWithText(m, edns0.EDENotifyParentNotAuthoritative,
				fmt.Sprintf("%s is not a zone apex on this server (containing zone %s)", qname, zd.ZoneName), false)
			dnr.ResponseWriter.WriteMsg(m)
			return nil
		}
		targetZoneName = zd.ZoneName

	case dns.TypeCDS, dns.TypeCSYNC:
		// For CDS and CSYNC, find the parent zone locally.
		// Strip first label and use FindZone to walk up.
		labels := strings.SplitN(qname, ".", 2)
		if len(labels) < 2 || labels[1] == "" {
			lgHandler.Warn("NOTIFY(CDS/CSYNC) qname has no parent", "qname", qname)
			m.SetRcode(dnr.Msg, dns.RcodeRefused)
			edns0.AttachEDEToResponseWithText(m, edns0.EDENotifyTargetNotChildDelegation,
				fmt.Sprintf("%s has no parent label", qname), false)
			dnr.ResponseWriter.WriteMsg(m)
			return nil
		}
		zd, _ = FindZone(labels[1])
		if zd == nil {
			lgHandler.Warn("parent zone not authoritative, refusing NOTIFY", "type", dns.TypeToString[ntype], "qname", qname)
			m.SetRcode(dnr.Msg, dns.RcodeNotAuth)
			edns0.AttachEDEToResponseWithText(m, edns0.EDENotifyParentNotAuthoritative,
				fmt.Sprintf("server is not authoritative for parent of %s", qname), false)
			dnr.ResponseWriter.WriteMsg(m)
			return nil
		}
		if !zd.IsChildDelegation(qname) {
			lgHandler.Warn("qname is not a child delegation in parent zone", "type", dns.TypeToString[ntype], "qname", qname, "parent", zd.ZoneName)
			m.SetRcode(dnr.Msg, dns.RcodeRefused)
			edns0.AttachEDEToResponseWithText(m, edns0.EDENotifyTargetNotChildDelegation,
				fmt.Sprintf("%s is not a child delegation of %s", qname, zd.ZoneName), false)
			dnr.ResponseWriter.WriteMsg(m)
			return nil
		}
		// DSYNC scheme gate: refuse NOTIFY for an RRtype the parent
		// does not advertise NOTIFY for. Catches misconfigured
		// children on the very first push instead of after
		// attempt-timeout. In-memory zone read; no DNS round-trip.
		if !zd.advertisesDsyncNotify(ntype) {
			lgHandler.Warn("parent does not advertise NOTIFY for type, refusing",
				"type", dns.TypeToString[ntype], "parent", zd.ZoneName, "qname", qname)
			m.SetRcode(dnr.Msg, dns.RcodeRefused)
			edns0.AttachEDEToResponseWithText(m, edns0.EDENotifyDsyncSchemeNotAdvertised,
				fmt.Sprintf("parent zone %s does not advertise NOTIFY for type %s; ignoring",
					zd.ZoneName, dns.TypeToString[ntype]), false)
			dnr.ResponseWriter.WriteMsg(m)
			return nil
		}
		targetZoneName = zd.ZoneName

	default:
		lgHandler.Warn("unknown NOTIFY type", "type", dns.TypeToString[ntype])
		m.SetRcode(dnr.Msg, dns.RcodeRefused)
		edns0.AttachEDEToResponseWithText(m, edns0.EDENotifyUnknownType,
			fmt.Sprintf("NOTIFY for type %s not supported", dns.TypeToString[ntype]), false)
		dnr.ResponseWriter.WriteMsg(m)
		return nil
	}

	// Validate that the target zone is not in an error state
	if zd.Error && zd.ErrorType != RefreshError {
		lgHandler.Error("zone in error state, refusing NOTIFY", "type", dns.TypeToString[ntype], "qname", qname, "zone", targetZoneName, "errorMsg", zd.ErrorMsg)
		m.SetRcode(dnr.Msg, dns.RcodeServerFailure)
		edns0.AttachEDEToResponseWithText(m, edns0.EDENotifyZoneInErrorState,
			fmt.Sprintf("zone %s in error state: %s", targetZoneName, zd.ErrorMsg), false)
		dnr.ResponseWriter.WriteMsg(m)
		return nil
	}

	lgHandler.Info("NOTIFY will be handled", "type", dns.TypeToString[ntype], "qname", qname, "zone", targetZoneName)

	switch ntype {
	case dns.TypeSOA:
		select {
		case <-ctx.Done():
			// Send immediate failure so NOTIFY sender doesn't block on cancellation
			m.SetRcode(dnr.Msg, dns.RcodeServerFailure)
			if err := dnr.ResponseWriter.WriteMsg(m); err != nil {
				lgHandler.Error("WriteMsg error on cancellation", "notifyType", "SOA", "err", err)
			}
			return nil
		case zonech <- ZoneRefresher{
			Name:         targetZoneName, // send zone name into RefreshEngine
			ZoneStore:    zd.ZoneStore,
			Edns0Options: dnr.Options,
		}:
		}
		lgHandler.Info("refreshing zone on NOTIFY", "type", dns.TypeToString[ntype], "qname", qname, "zone", targetZoneName)

	case dns.TypeCDS, dns.TypeCSYNC:
		// NOTIFY(CDS/CSYNC) targets the parent zone, which should scan the child zone's CDS/CSYNC RRset
		lgHandler.Info("scanning child zone on NOTIFY", "type", dns.TypeToString[ntype], "child", qname, "parentZone", targetZoneName)
		select {
		case <-ctx.Done():
			// Send immediate failure so NOTIFY sender doesn't block on cancellation
			m.SetRcode(dnr.Msg, dns.RcodeServerFailure)
			if err := dnr.ResponseWriter.WriteMsg(m); err != nil {
				lgHandler.Error("WriteMsg error on cancellation", "notifyType", "CDS/CSYNC", "err", err)
			}
			return nil
		case scannerq <- ScanRequest{
			Cmd:          "SCAN",
			ChildZone:    qname, // The child zone name (where CDS/CSYNC RRset is)
			ZoneData:     zd,    // The parent zone data (which will perform the scan)
			RRtype:       ntype,
			Edns0Options: dnr.Options,
		}:
		}

	case dns.TypeDNSKEY:
		// NOTIFY(DNSKEY) targets the zone itself for multi-signer communication
		lgHandler.Info("scanning zone on DNSKEY NOTIFY", "type", dns.TypeToString[ntype], "qname", qname, "zone", targetZoneName)
		select {
		case <-ctx.Done():
			// Send immediate failure so NOTIFY sender doesn't block on cancellation
			m.SetRcode(dnr.Msg, dns.RcodeServerFailure)
			if err := dnr.ResponseWriter.WriteMsg(m); err != nil {
				lgHandler.Error("WriteMsg error on cancellation", "notifyType", "DNSKEY", "err", err)
			}
			return nil
		case scannerq <- ScanRequest{
			Cmd:          "SCAN",
			ChildZone:    qname, // The zone name (where DNSKEY RRset is)
			ZoneData:     zd,    // The zone data (which will perform the scan)
			RRtype:       ntype,
			Edns0Options: dnr.Options,
		}:
		}
	}

	dnr.ResponseWriter.WriteMsg(m)
	return nil
}
