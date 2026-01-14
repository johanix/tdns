/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"log"
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

	log.Printf("*** DnsNotifyHandler: starting (with callback)")
	if Globals.Debug {
		log.Printf("DnsNotifyHandler: Channel capacity: %d", cap(dnsnotifyq))
		log.Printf("DnsNotifyHandler: Waiting for NOTIFYs on dnsnotifyq channel")
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("DnsNotifyHandler: context cancelled")
			return nil
		case dnr, ok := <-dnsnotifyq:
			if !ok {
				log.Println("DnsNotifyHandler: dnsnotifyq closed")
				return nil
			}
			if Globals.Debug {
				log.Printf("DnsNotifyHandler: Received NOTIFY from channel (qname=%s, from=%s)", dnr.Qname, dnr.ResponseWriter.RemoteAddr())
			}
			if err := handlerFunc(ctx, &dnr); err != nil {
				log.Printf("Error in NOTIFY handler: %v", err)
			} else {
				if Globals.Debug {
					log.Printf("DnsNotifyHandler: NOTIFY handler completed successfully")
				}
			}
		}
	}
}

func NotifyHandler(ctx context.Context, conf *Config) error {
	zonech := conf.Internal.RefreshZoneCh
	dnsnotifyq := conf.Internal.DnsNotifyQ
	scannerq := conf.Internal.ScannerQ
	imr := conf.Internal.ImrEngine

	log.Printf("*** DnsNotifyResponderEngine: starting")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				log.Println("DnsNotifyResponderEngine: context cancelled")
				return
			case dhr, ok := <-dnsnotifyq:
				if !ok {
					log.Println("DnsNotifyResponderEngine: dnsnotifyq closed")
					return
				}
				NotifyResponder(ctx, &dhr, zonech, scannerq, imr)
			}

		}
	}()
	wg.Wait()

	log.Println("DnsNotifyResponderEngine: terminating")
	return nil
}

func NotifyResponder(ctx context.Context, dnr *DnsNotifyRequest, zonech chan ZoneRefresher, scannerq chan ScanRequest, imr *Imr) error {

	qname := dnr.Qname
	// ntype := dnr.Msg.Question[0].Qtype
	if dns.Msg == nil || len(dnr.Msg.Question) == 0 {
		log.Printf("NotifyResponder: Received NOTIFY for zone %q, but no question in message", qname)
		m := new(dns.Msg)
		m.SetReply(dnr.Msg)
		m.SetRcode(dnr.Msg, dns.RcodeFormatError)
		m.MsgHdr.Authoritative = true
		if err := dnr.ResponseWriter.WriteMsg(m); err != nil {
			log.Printf("NotifyResponder: WriteMsg error on FormatError: %v", err)
		}
		return nil
	}
	ntype := dnr.Msg.Question[0].Qtype	

	log.Printf("NotifyResponder: Received NOTIFY(%s) for zone %q", dns.TypeToString[ntype], qname)

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
			log.Printf("NotifyResponder: Received NOTIFY(%s) for unknown zone %q. Ignoring.", dns.TypeToString[ntype], qname)
			m.SetRcode(dnr.Msg, dns.RcodeRefused)
			dnr.ResponseWriter.WriteMsg(m)
			return nil
		}
		if !found && zd.IsChildDelegation(qname) {
			log.Printf("NotifyResponder: Received NOTIFY(%s) for %q, but it's a child delegation. Ignoring.", dns.TypeToString[ntype], qname)
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
			log.Printf("NotifyResponder: Error finding parent zone for %q: %v", qname, err)
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
				log.Printf("NotifyResponder: Received NOTIFY(%s) for %q, but parent zone %q is not authoritative. Refusing.",
					dns.TypeToString[ntype], qname, parentZoneName)
				m.SetRcode(dnr.Msg, dns.RcodeNotAuth)
				dnr.ResponseWriter.WriteMsg(m)
				return nil
			}
			// Use the correct case from the Zones map (parentZoneName already used for logging above)
		}
		targetZoneName = zd.ZoneName

	default:
		log.Printf("NotifyResponder: Unknown type of notification: NOTIFY(%s)", dns.TypeToString[ntype])
		m.SetRcode(dnr.Msg, dns.RcodeRefused)
		dnr.ResponseWriter.WriteMsg(m)
		return nil
	}

	// Validate that the target zone is not in an error state
	if zd.Error && zd.ErrorType != RefreshError {
		log.Printf("NotifyResponder: Received NOTIFY(%s) for %q targeting zone %q, but it is in error state: %s",
			dns.TypeToString[ntype], qname, targetZoneName, zd.ErrorMsg)
		m.SetRcode(dnr.Msg, dns.RcodeServerFailure)
		dnr.ResponseWriter.WriteMsg(m)
		return nil
	}

	log.Printf("NotifyResponder: NOTIFY(%s) for %q will be handled by zone %q",
		dns.TypeToString[ntype], qname, targetZoneName)

	switch ntype {
	case dns.TypeSOA:
		select {
		case <-ctx.Done():
			// Send immediate failure so NOTIFY sender doesn't block on cancellation
			m.SetRcode(dnr.Msg, dns.RcodeServerFailure)
			if err := dnr.ResponseWriter.WriteMsg(m); err != nil {
				log.Printf("NotifyResponder: WriteMsg error on cancellation (SOA): %v", err)
			}
			return nil
		case zonech <- ZoneRefresher{
			Name:         targetZoneName, // send zone name into RefreshEngine
			ZoneStore:    zd.ZoneStore,
			Edns0Options: dnr.Options,
		}:
		}
		log.Printf("NotifyResponder: Received NOTIFY(%s) for %q. Refreshing zone %q.",
			dns.TypeToString[ntype], qname, targetZoneName)

	case dns.TypeCDS, dns.TypeCSYNC:
		// NOTIFY(CDS/CSYNC) targets the parent zone, which should scan the child zone's CDS/CSYNC RRset
		log.Printf("NotifyResponder: Received NOTIFY(%s) for child %q. Parent zone %q will scan the %s %s RRset",
			dns.TypeToString[ntype], qname, targetZoneName, qname, dns.TypeToString[ntype])
		select {
		case <-ctx.Done():
			// Send immediate failure so NOTIFY sender doesn't block on cancellation
			m.SetRcode(dnr.Msg, dns.RcodeServerFailure)
			if err := dnr.ResponseWriter.WriteMsg(m); err != nil {
				log.Printf("NotifyResponder: WriteMsg error on cancellation (CDS/CSYNC): %v", err)
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
		log.Printf("NotifyResponder: Received NOTIFY(%s) for %q. Zone %q will scan the %s %s RRset",
			dns.TypeToString[ntype], qname, targetZoneName, qname, dns.TypeToString[ntype])
		select {
		case <-ctx.Done():
			// Send immediate failure so NOTIFY sender doesn't block on cancellation
			m.SetRcode(dnr.Msg, dns.RcodeServerFailure)
			if err := dnr.ResponseWriter.WriteMsg(m); err != nil {
				log.Printf("NotifyResponder: WriteMsg error on cancellation (DNSKEY): %v", err)
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
