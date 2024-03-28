/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
        "log"
	"sync"

        "github.com/miekg/dns"
	"github.com/johanix/tdns/tdns"
)

func DnsNotifyResponderEngine(conf *Config) error {
	zonech := conf.Internal.RefreshZoneCh
        dnsnotifyq := conf.Internal.DnsNotifyQ

	log.Printf("DnsNotifyResponderEngine: starting")

	var dhr DnsHandlerRequest

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for {
			select {
			case dhr = <-dnsnotifyq:
				NotifyResponder(&dhr, zonech)
			}
		}
	}()
	wg.Wait()

	log.Println("DnsNotifyResponderEngine: terminating")
	return nil
}


//func NotifyResponder(w dns.ResponseWriter, r *dns.Msg, qname string, ntype uint16,
//					   zonech chan tdns.ZoneRefresher) error {
func NotifyResponder(dhr *DnsHandlerRequest, zonech chan tdns.ZoneRefresher) error {

        qname := dhr.Qname
	ntype := dhr.Msg.Question[0].Qtype
	
	log.Printf("Received NOTIFY(%s) for zone '%s'", dns.TypeToString[ntype], qname)
//	err := NotifyResponder(w, r, qname, ntype, zonech)
//	if err != nil {
//	   log.Printf("Error from NotifyResponder: %v", err)
//	}

	m := new(dns.Msg)
	m.SetReply(dhr.Msg)

	// Let's see if we can find the zone
	zd := tdns.FindZone(qname)
	if zd == nil || zd.ZoneName != qname {
		log.Printf("Received Notify for unknown zone %s. Ignoring.", qname)
		m := new(dns.Msg)
		m.SetRcode(dhr.Msg, dns.RcodeRefused)
		dhr.ResponseWriter.WriteMsg(m)
		return nil // didn't find any zone for that qname
	}

	log.Printf("NotifyResponder: The qname %s seems to belong to the known zone %s",
				     qname, zd.ZoneName)

	switch ntype {
	case dns.TypeSOA:
	     zonech <- tdns.ZoneRefresher{
			Name:      qname, // send zone name into RefreshEngine
			ZoneStore: zd.ZoneStore,
		}
		log.Printf("NotifyResponder: Received NOTIFY(%s) for %s. Refreshing.",
					     dns.TypeToString[ntype], qname)
	case dns.TypeCDS, dns.TypeCSYNC, dns.TypeDNSKEY:
		log.Printf("NotifyResponder: Received a NOTIFY(%s) for %s",
					     dns.TypeToString[ntype], qname)
	default:
		log.Printf("NotifyResponder: Unknown type of notification: NOTIFY(%s)",
					     dns.TypeToString[ntype])
	}

	m.SetRcode(dhr.Msg, dns.RcodeSuccess)
        m.MsgHdr.Authoritative = true
	dhr.ResponseWriter.WriteMsg(m)
	return nil
}
