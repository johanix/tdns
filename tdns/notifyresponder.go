/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"log"
	"sync"

	"github.com/miekg/dns"
)

func NotifyHandler(ctx context.Context, conf *Config) error {
	zonech := conf.Internal.RefreshZoneCh
	dnsnotifyq := conf.Internal.DnsNotifyQ
	scannerq := conf.Internal.ScannerQ

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
				NotifyResponder(ctx, &dhr, zonech, scannerq)
			}

		}
	}()
	wg.Wait()

	log.Println("DnsNotifyResponderEngine: terminating")
	return nil
}

func NotifyResponder(ctx context.Context, dnr *DnsNotifyRequest, zonech chan ZoneRefresher, scannerq chan ScanRequest) error {

	qname := dnr.Qname
	ntype := dnr.Msg.Question[0].Qtype

	log.Printf("NotifyResponder: Received NOTIFY(%s) for zone %q", dns.TypeToString[ntype], qname)

	m := new(dns.Msg)
	m.SetReply(dnr.Msg)
	m.SetRcode(dnr.Msg, dns.RcodeSuccess)

	// Let's see if we can find the zone
	zd, _ := FindZone(qname)
	if zd == nil || (zd != nil && zd.IsChildDelegation(qname)) {
		log.Printf("NotifyResponder: Received Notify for unknown zone %q. Ignoring.", qname)
		m := new(dns.Msg)
		m.SetRcode(dnr.Msg, dns.RcodeRefused)
		dnr.ResponseWriter.WriteMsg(m)
		return nil // didn't find any zone for that qname
	}

	if zd.Error && zd.ErrorType != RefreshError {
		log.Printf("NotifyResponder: Received Notify for zone %q, but it is in error state: %s", qname, zd.ErrorMsg)
		m := new(dns.Msg)
		m.SetRcode(dnr.Msg, dns.RcodeServerFailure)
		dnr.ResponseWriter.WriteMsg(m)
		return nil // didn't find any zone for that qname
	}

	// log.Printf("NotifyResponder: The qname %s seems to belong to the known zone %s", qname, zd.ZoneName)
	m.MsgHdr.Authoritative = true

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
			Name:      qname, // send zone name into RefreshEngine
			ZoneStore: zd.ZoneStore,
			Edns0Options: dnr.Options,
		}:
		}
		log.Printf("NotifyResponder: Received NOTIFY(%s) for %q Refreshing.",
			dns.TypeToString[ntype], qname)

	case dns.TypeCDS, dns.TypeCSYNC:
		log.Printf("NotifyResponder: Received a NOTIFY(%s) for %q. This should trigger a scan for the %s %s RRset",
			dns.TypeToString[ntype], qname, qname, dns.TypeToString[ntype])
		select {
		case <-ctx.Done():
			// Send immediate failure so NOTIFY sender doesn't block on cancellation
			m.SetRcode(dnr.Msg, dns.RcodeServerFailure)
			if err := dnr.ResponseWriter.WriteMsg(m); err != nil {
				log.Printf("NotifyResponder: WriteMsg error on cancellation (CDS/CSYNC): %v", err)
			}
			return nil
		case scannerq <- ScanRequest{
			Cmd:       "SCAN",
			ChildZone: qname,
			ZoneData:  zd,
			RRtype:    ntype,
			Edns0Options: dnr.Options,
		}:
		}

	case dns.TypeDNSKEY:
		log.Printf("NotifyResponder: Received a NOTIFY(%s) for %q. This should trigger a scan for the %s %s RRset",
			dns.TypeToString[ntype], qname, qname, dns.TypeToString[ntype])
		select {
		case <-ctx.Done():
			// Send immediate failure so NOTIFY sender doesn't block on cancellation
			m.SetRcode(dnr.Msg, dns.RcodeServerFailure)
			if err := dnr.ResponseWriter.WriteMsg(m); err != nil {
				log.Printf("NotifyResponder: WriteMsg error on cancellation (DNSKEY): %v", err)
			}
			return nil
		case scannerq <- ScanRequest{
			Cmd:       "SCAN",
			ChildZone: qname,
			ZoneData:  zd,
			RRtype:    ntype,
			Edns0Options: dnr.Options,
		}:
		}

	default:
		log.Printf("NotifyResponder: Unknown type of notification: NOTIFY(%s)",
			dns.TypeToString[ntype])
	}

	dnr.ResponseWriter.WriteMsg(m)
	return nil
}
