/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

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
	imr := conf.Internal.ImrEngine

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
				NotifyResponder(ctx, &dhr, zonech, scannerq, imr)
			}

		}
	}()
	wg.Wait()

	lgHandler.Info("DnsNotifyResponderEngine: terminating")
	return nil
}

func NotifyResponder(ctx context.Context, dnr *DnsNotifyRequest, zonech chan ZoneRefresher, scannerq chan ScanRequest, imr *Imr) error {

	qname := dnr.Qname
	// ntype := dnr.Msg.Question[0].Qtype
	if dnr.Msg == nil || len(dnr.Msg.Question) == 0 {
		lgHandler.Warn("received NOTIFY with no question", "zone", qname)
		m := new(dns.Msg)
		m.MsgHdr.Rcode = dns.RcodeFormatError
		m.MsgHdr.Response = true
		m.MsgHdr.Authoritative = true
		if dnr.Msg != nil && len(dnr.Msg.Question) > 0 {
			m.Question = dnr.Msg.Question
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
		// For SOA and DNSKEY, target the zone for qname itself
		var found bool
		zd, found = FindZone(qname)
		if zd == nil {
			lgHandler.Warn("received NOTIFY for unknown zone, ignoring", "type", dns.TypeToString[ntype], "zone", qname)
			m.SetRcode(dnr.Msg, dns.RcodeRefused)
			dnr.ResponseWriter.WriteMsg(m)
			return nil
		}
		if !found && zd.IsChildDelegation(qname) {
			lgHandler.Warn("received NOTIFY for child delegation, ignoring", "type", dns.TypeToString[ntype], "qname", qname)
			m.SetRcode(dnr.Msg, dns.RcodeRefused)
			dnr.ResponseWriter.WriteMsg(m)
			return nil
		}
		targetZoneName = zd.ZoneName

	case dns.TypeCDS, dns.TypeCSYNC:
		// For CDS and CSYNC, target the parent zone of qname
		// Use ParentZone() to find the parent zone name via DNS lookup

		parentZoneName, err := imr.ParentZone(qname)
		if err != nil {
			lgHandler.Error("error finding parent zone", "qname", qname, "err", err)
			m.SetRcode(dnr.Msg, dns.RcodeServerFailure)
			dnr.ResponseWriter.WriteMsg(m)
			return nil
		}

		// Look up the parent zone in our authoritative zones
		var ok bool
		zd, ok = Zones.Get(parentZoneName)
		if !ok {
			// Try case-insensitive lookup
			parentZoneNameLower := strings.ToLower(parentZoneName)
			zd, ok = Zones.Get(parentZoneNameLower)
			if !ok {
				lgHandler.Warn("parent zone not authoritative, refusing NOTIFY", "type", dns.TypeToString[ntype], "qname", qname, "parent", parentZoneName)
				m.SetRcode(dnr.Msg, dns.RcodeNotAuth)
				dnr.ResponseWriter.WriteMsg(m)
				return nil
			}
			// Use the correct case from the Zones map (parentZoneName already used for logging above)
		}
		targetZoneName = zd.ZoneName

	default:
		lgHandler.Warn("unknown NOTIFY type", "type", dns.TypeToString[ntype])
		m.SetRcode(dnr.Msg, dns.RcodeRefused)
		dnr.ResponseWriter.WriteMsg(m)
		return nil
	}

	// Validate that the target zone is not in an error state
	if zd.Error && zd.ErrorType != RefreshError {
		lgHandler.Error("zone in error state, refusing NOTIFY", "type", dns.TypeToString[ntype], "qname", qname, "zone", targetZoneName, "errorMsg", zd.ErrorMsg)
		m.SetRcode(dnr.Msg, dns.RcodeServerFailure)
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
