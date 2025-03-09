/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"log"
	"sync"

	"github.com/miekg/dns"
)

func NotifyHandler(conf *Config) error {
	zonech := conf.Internal.RefreshZoneCh
	dnsnotifyq := conf.Internal.DnsNotifyQ
	scannerq := conf.Internal.ScannerQ

	log.Printf("*** DnsNotifyResponderEngine: starting")

	var dhr DnsNotifyRequest

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for dhr = range dnsnotifyq {
			NotifyResponder(&dhr, zonech, scannerq)
		}
	}()
	wg.Wait()

	log.Println("DnsNotifyResponderEngine: terminating")
	return nil
}

func NotifyResponder(dhr *DnsNotifyRequest, zonech chan ZoneRefresher, scannerq chan ScanRequest) error {

	qname := dhr.Qname
	ntype := dhr.Msg.Question[0].Qtype

	log.Printf("NotifyResponder: Received NOTIFY(%s) for zone %q", dns.TypeToString[ntype], qname)

	m := new(dns.Msg)
	m.SetReply(dhr.Msg)

	// Let's see if we can find the zone
	zd, _ := FindZone(qname)
	if zd == nil || (zd != nil && zd.IsChildDelegation(qname)) {
		log.Printf("NotifyResponder: Received Notify for unknown zone %q. Ignoring.", qname)
		m := new(dns.Msg)
		m.SetRcode(dhr.Msg, dns.RcodeRefused)
		dhr.ResponseWriter.WriteMsg(m)
		return nil // didn't find any zone for that qname
	}

	if zd.Error {
		log.Printf("NotifyResponder: Received Notify for zone %q, but it is in error state: %s", qname, zd.ErrorMsg)
		m := new(dns.Msg)
		m.SetRcode(dhr.Msg, dns.RcodeServerFailure)
		dhr.ResponseWriter.WriteMsg(m)
		return nil // didn't find any zone for that qname
	}

	// log.Printf("NotifyResponder: The qname %s seems to belong to the known zone %s", qname, zd.ZoneName)

	switch ntype {
	case dns.TypeSOA:
		zonech <- ZoneRefresher{
			Name:      qname, // send zone name into RefreshEngine
			ZoneStore: zd.ZoneStore,
		}
		log.Printf("NotifyResponder: Received NOTIFY(%s) for %q Refreshing.",
			dns.TypeToString[ntype], qname)

	case dns.TypeCDS, dns.TypeCSYNC:
		log.Printf("NotifyResponder: Received a NOTIFY(%s) for %q. This should trigger a scan for the %s %s RRset",
			dns.TypeToString[ntype], qname, qname, dns.TypeToString[ntype])
		scannerq <- ScanRequest{
			Cmd:       "SCAN",
			ChildZone: qname,
			ZoneData:  zd,
			RRtype:    ntype,
		}

	case dns.TypeDNSKEY:
		log.Printf("NotifyResponder: Received a NOTIFY(%s) for %q. This should trigger a scan for the %s %s RRset",
			dns.TypeToString[ntype], qname, qname, dns.TypeToString[ntype])
		scannerq <- ScanRequest{
			Cmd:       "SCAN",
			ChildZone: qname,
			ZoneData:  zd,
			RRtype:    ntype,
		}

	default:
		log.Printf("NotifyResponder: Unknown type of notification: NOTIFY(%s)",
			dns.TypeToString[ntype])
	}

	m.SetRcode(dhr.Msg, dns.RcodeSuccess)
	m.MsgHdr.Authoritative = true
	dhr.ResponseWriter.WriteMsg(m)
	return nil
}
