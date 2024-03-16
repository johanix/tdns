/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
        "log"
        "github.com/miekg/dns"
	"github.com/johanix/tdns/tdns"
)

func NotifyResponder(w dns.ResponseWriter, r *dns.Msg, qname string, ntype uint16,
					   zonech chan tdns.ZoneRefresher) error {

	m := new(dns.Msg)
	m.SetReply(r)

	// Let's see if we can find the zone
	zd := tdns.FindZone(qname)
	if zd == nil {
		log.Printf("Received Notify for unknown zone %s. Ignoring.", qname)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return nil // didn't find any zone for that qname
	}

	switch ntype {
	case dns.TypeSOA:
	     zonech <- tdns.ZoneRefresher{
			Name:      qname, // send zone name into RefreshEngine
			ZoneStore: zd.ZoneStore,
		}
		log.Printf("NotifyResponder: Received NOTIFY(%s) for %s. Refreshing.",
					     dns.TypeToString[ntype])
	case dns.TypeCDS, dns.TypeCSYNC, dns.TypeDNSKEY:
		log.Printf("NotifyResponder: Received a NOTIFY(%S) for %s",
					     dns.TypeToString[ntype], qname)
	default:
		log.Printf("NotifyResponder: Unknown type of notification: NOTIFY(%S)",
					     dns.TypeToString[ntype])
	}

	m.SetRcode(r, dns.RcodeSuccess)
        m.MsgHdr.Authoritative = true
	w.WriteMsg(m)
	return nil
}
