/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	"log"
	"sync"

	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
)

func NotifyHandler(conf *Config) error {
	zonech := conf.Internal.RefreshZoneCh
	dnsnotifyq := conf.Internal.DnsNotifyQ
	scannerq := conf.Internal.ScannerQ

	log.Printf("*** DnsNotifyResponderEngine: starting")

	var dhr tdns.DnsHandlerRequest

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for {
			select {
			case dhr = <-dnsnotifyq:
				NotifyResponder(&dhr, zonech, scannerq)
			}
		}
	}()
	wg.Wait()

	log.Println("DnsNotifyResponderEngine: terminating")
	return nil
}

// func NotifyResponder(w dns.ResponseWriter, r *dns.Msg, qname string, ntype uint16,
//
//	zonech chan tdns.ZoneRefresher) error {
func NotifyResponder(dhr *tdns.DnsHandlerRequest, zonech chan tdns.ZoneRefresher, scannerq chan tdns.ScanRequest) error {

	qname := dhr.Qname
	ntype := dhr.Msg.Question[0].Qtype

	log.Printf("NotifyResponder: Received NOTIFY(%s) for zone '%s'", dns.TypeToString[ntype], qname)

	m := new(dns.Msg)
	m.SetReply(dhr.Msg)

	// Let's see if we can find the zone
	zd, _ := tdns.FindZone(qname)
	if zd == nil && !zd.IsChildDelegation(qname) {
		log.Printf("NotifyResponder: Received Notify for unknown zone %s. Ignoring.", qname)
		m := new(dns.Msg)
		m.SetRcode(dhr.Msg, dns.RcodeRefused)
		dhr.ResponseWriter.WriteMsg(m)
		return nil // didn't find any zone for that qname
	}

	// log.Printf("NotifyResponder: The qname %s seems to belong to the known zone %s", qname, zd.ZoneName)

	switch ntype {
	case dns.TypeSOA:
		zonech <- tdns.ZoneRefresher{
			Name:      qname, // send zone name into RefreshEngine
			ZoneStore: zd.ZoneStore,
		}
		log.Printf("NotifyResponder: Received NOTIFY(%s) for %s Refreshing.",
			dns.TypeToString[ntype], qname)

	case dns.TypeCDS, dns.TypeCSYNC:
		log.Printf("NotifyResponder: Received a NOTIFY(%s) for %s This should trigger a scan for the %s %s RRset",
			dns.TypeToString[ntype], qname, qname, dns.TypeToString[ntype])
		scannerq <- tdns.ScanRequest{
			Cmd:       "SCAN",
			ChildZone: qname,
			ZoneData:  zd,
			RRtype:    ntype,
		}

	case dns.TypeDNSKEY:
		log.Printf("NotifyResponder: Received a NOTIFY(%s) for %s This should trigger a scan for the %s %s RRset",
			dns.TypeToString[ntype], qname, qname, dns.TypeToString[ntype])
		scannerq <- tdns.ScanRequest{
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
