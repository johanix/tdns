/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	// "fmt"
	"log"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/spf13/viper"

	"github.com/johanix/tdns/tdns"
	"github.com/orcaman/concurrent-map/v2"
)

var Zones = cmap.New[*tdns.ZoneData]()

func DnsEngine(conf *Config) error {
	addresses := viper.GetStringSlice("dnsengine.addresses")

	// verbose := viper.GetBool("dnsengine.verbose")
	// debug := viper.GetBool("dnsengine.debug")
	dns.HandleFunc(".", createHandler(conf))

	log.Printf("DnsEngine: addresses: %v", addresses)
	for _, addr := range addresses {
		for _, net := range []string{"udp", "tcp"} {
			go func(addr, net string) {
				log.Printf("DnsEngine: serving on %s (%s)\n", addr, net)
				server := &dns.Server{Addr: addr, Net: net}

				// Must bump the buffer size of incoming UDP msgs, as updates
				// may be much larger then queries
				server.UDPSize = dns.DefaultMsgSize // 4096
				if err := server.ListenAndServe(); err != nil {
					log.Printf("Failed to setup the %s server: %s\n", net, err.Error())
				} else {
					log.Printf("DnsEngine: listening on %s/%s\n", addr, net)
				}
			}(addr, net)
		}
	}
	return nil
}

func createHandler(conf *Config) func(w dns.ResponseWriter, r *dns.Msg) {

	zonech := conf.Internal.RefreshZoneCh

	return func(w dns.ResponseWriter, r *dns.Msg) {
		qname := r.Question[0].Name
		var dnssec_ok bool
		opt := r.IsEdns0()
		if opt != nil {
			dnssec_ok = opt.Do()
		}
		// log.Printf("DNSSEC OK: %v", dnssec_ok)

		switch r.Opcode {
		case dns.OpcodeNotify:
			ntype := r.Question[0].Qtype
			log.Printf("Received NOTIFY(%s) for zone '%s'", dns.TypeToString[ntype], qname)
			// send NOERROR response
			m := new(dns.Msg)
			m.SetReply(r)

			if zd, ok := Zones.Get(qname); ok {
				log.Printf("Received Notify for known zone %s. Fetching from upstream", qname)
				zonech <- tdns.ZoneRefresher{
					Name:      qname, // send zone name into RefreshEngine
					ZoneStore: zd.ZoneStore,
				}
			} else {
				log.Printf("Received Notify for unknown zone %s. Ignoring.", qname)
				m.SetRcode(r, dns.RcodeRefused)
			}
			w.WriteMsg(m)
			// fmt.Printf("Notify message: %v\n", m.String())
			return

		case dns.OpcodeQuery:
			qtype := r.Question[0].Qtype
			log.Printf("Zone %s %s request from %s", qname, dns.TypeToString[qtype], w.RemoteAddr())
			if zd, ok := Zones.Get(qname); ok {
				// The qname is equal to the name of a zone we have
				ApexResponder(w, r, zd, qname, qtype, dnssec_ok)
				return
			}

			if qtype == dns.TypeAXFR || qtype == dns.TypeIXFR {
			   // We are not auth for this zone, so no xfrs possible
			   m := new(dns.Msg)
			   m.SetReply(r)
			   m.MsgHdr.Rcode = dns.RcodeNotAuth
			   w.WriteMsg(m)
			   return
			}
			
			log.Printf("DnsHandler: Qname is '%s', which is not a known zone.", qname)
			known_zones := []string{}
			for _, zname := range Zones.Keys() {
				known_zones = append(known_zones, zname)
			}
			log.Printf("DnsHandler: Known zones are: %v", known_zones)

			// Let's see if we can find the zone
			zd := FindZone(qname)
			if zd == nil {
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeRefused)
				w.WriteMsg(m)
				return // didn't find any zone for that qname or found zone, but it is an XFR zone only
			}
			// log.Printf("After FindZone zd.ZoneStore: %v (%s)", zd.ZoneStore,
			//	tdns.ZoneStoreToString[zd.ZoneStore])
			if zd.ZoneStore == tdns.XfrZone {
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeRefused)
				w.WriteMsg(m)
				return // didn't find any zone for that qname or found zone, but it is an XFR zone only
			}
			// log.Printf("Found matching %s (%d) zone for qname %s: %s",
			// 	tdns.ZoneStoreToString[zd.ZoneStore], zd.ZoneStore,
			//	qname, zd.ZoneName)
			QueryResponder(w, r, zd, qname, qtype, dnssec_ok)
			return

		default:
			log.Printf("Error: unable to handle msgs of type %s", dns.OpcodeToString[r.Opcode])
		}
	}
}

func ApexResponder(w dns.ResponseWriter, r *dns.Msg, zd *tdns.ZoneData, qname string, qtype uint16, dnssec_ok bool) error {
	m := new(dns.Msg)
	m.SetReply(r)
	m.MsgHdr.Authoritative = true

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		log.Fatalf("ApexResponder: failed to get apex data for zone %s", zd.ZoneName)
	}

	var v4glue, v6glue *tdns.RRset

	switch qtype {
	case dns.TypeAXFR, dns.TypeIXFR:
		log.Printf("We have the %s %s, so let's try to serve it", tdns.ZoneStoreToString[zd.ZoneStore], qname)
		zd.ZoneTransferOut(w, r)
		return nil
	case dns.TypeSOA:
		zd.Logger.Printf("apex: %v", apex)
		zd.Logger.Printf("There are %d SOA RRs in %s. rrset: %v", len(apex.RRtypes[dns.TypeSOA].RRs),
			zd.ZoneName, apex.RRtypes[dns.TypeSOA])
		apex.RRtypes[dns.TypeSOA].RRs[0].(*dns.SOA).Serial = zd.CurrentSerial
		m.Answer = append(m.Answer, apex.RRtypes[dns.TypeSOA].RRs[0])
		m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRs...)
		v4glue, v6glue = zd.FindGlue(apex.RRtypes[dns.TypeNS], dnssec_ok)
		m.Extra = append(m.Extra, v4glue.RRs...)
		m.Extra = append(m.Extra, v6glue.RRs...)
		if dnssec_ok {
			m.Answer = append(m.Answer, apex.RRtypes[dns.TypeSOA].RRSIGs...)
			m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRSIGs...)
			//			m.Extra = append(m.Extra, glue.RRSIGs...)
		}
	case dns.TypeMX, dns.TypeTLSA, dns.TypeSRV, dns.TypeA, dns.TypeAAAA,
		dns.TypeNS, dns.TypeTXT, dns.TypeZONEMD,
		dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeRRSIG, dns.TypeDNSKEY,
		dns.TypeCSYNC, dns.TypeCDS, dns.TypeCDNSKEY:
		if rrset, ok := apex.RRtypes[qtype]; ok {
			if len(rrset.RRs) > 0 {
				m.Answer = append(m.Answer, rrset.RRs...)
				m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRs...)
				v4glue, v6glue = zd.FindGlue(apex.RRtypes[dns.TypeNS], dnssec_ok)
				m.Extra = append(m.Extra, v4glue.RRs...)
				m.Extra = append(m.Extra, v6glue.RRs...)
				if dnssec_ok {
					m.Answer = append(m.Answer, rrset.RRSIGs...)
					m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRSIGs...)
					m.Extra = append(m.Extra, v4glue.RRSIGs...)
					m.Extra = append(m.Extra, v6glue.RRSIGs...)
				}
			} else {
				m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRs...)
				if dnssec_ok {
					m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRSIGs...)
				}
			}
		} else {
			m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRs...)
			if dnssec_ok {
				m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRSIGs...)
			}
		}
		// Anything special?
		switch qtype {
		case dns.TypeNS:
		     m.Ns = []dns.RR{}	// authority not needed when querying for zone NS
		}

	default:
		// every apex query we don't want to deal with
		m.MsgHdr.Rcode = dns.RcodeRefused
		m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRs...)
		m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRSIGs...)
	}
	w.WriteMsg(m)
	return nil
}

// 0. Check for *any* existence of qname
// 1. [OK] For a qname below zone, first check if there is a delegation. If so--> send referral
// 2. If no delegation, check for exact match
// 3. [OK] If no exact match, check for CNAME match
// 4. If no CNAME match, check for wild card match
// 5. Give up.

func QueryResponder(w dns.ResponseWriter, r *dns.Msg, zd *tdns.ZoneData, qname string,
	qtype uint16, dnssec_ok bool) error {

	// log.Printf("QueryResponder: qname: %s qtype: %s", qname, dns.TypeToString[qtype])
	m := new(dns.Msg)
	m.SetReply(r)
	m.MsgHdr.Authoritative = true

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		log.Fatalf("QueryResponder: failed to get apex data for zone %s", zd.ZoneName)
	}

	var v4glue, v6glue *tdns.RRset
	var wildqname string
	origqname := qname

	// log.Printf("---> Checking for existence of qname %s", qname)
	if !zd.NameExists(qname) {

		wildqname = "*." + strings.Join(strings.Split(qname, ".")[1:], ".")
		// log.Printf("---> Checking for existence of wildcard %s", wildqname)

		if !zd.NameExists(wildqname) {
			// return NXDOMAIN
			m.MsgHdr.Rcode = dns.RcodeNameError
			// ensure correct serial
			apex.RRtypes[dns.TypeSOA].RRs[0].(*dns.SOA).Serial = zd.CurrentSerial
			m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRs...)
			if dnssec_ok {
				m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRSIGs...)
				// XXX: Here we need to also add the proof of non-existence via NSEC+RRSIG(NSEC) or NSEC3+RRSIG(NSEC3)... at some point
				// covering NSEC+RRSIG(that NSEC) + // apex NSEC + RRSIG(apex NSEC)
			}
			// log.Printf("QR: qname %s does not exist in zone %s. Returning NXDOMAIN", qname, zd.ZoneName)
			w.WriteMsg(m)
			return nil
		} else {
			origqname = qname
			qname = wildqname
		}
	}

	owner, err := zd.GetOwner(qname)

	// 0. Check for *any* existence of qname in zone
	// log.Printf("---> Checking for any existence of qname %s", qname)
	if len(owner.RRtypes) == 0 {
		m.MsgHdr.Rcode = dns.RcodeNameError
		// ensure correct serial
		apex.RRtypes[dns.TypeSOA].RRs[0].(*dns.SOA).Serial = zd.CurrentSerial
		m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRs...)
		if dnssec_ok {
			m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRSIGs...)
			// XXX: Here we need to also add the proof of non-existence via NSEC+RRSIG(NSEC) or NSEC3+RRSIG(NSEC3)... at some point
			// covering NSEC+RRSIG(that NSEC) + // apex NSEC + RRSIG(apex NSEC)
		}
		w.WriteMsg(m)
		return nil
	}

	// 2. Check for qname + CNAME
	// log.Printf("---> Checking for qname + CNAME %s", qname)
	if len(owner.RRtypes) == 1 {
		for k, v := range owner.RRtypes {
			if k == dns.TypeCNAME {
				if len(v.RRs) > 1 {
					// XXX: NSD will not even load a zone with multiple CNAMEs. Better to check during load...
					log.Printf("QueryResponder: Zone %s: Illegal content: multiple CNAME RRs: %v", zd.ZoneName, v)
				}
				m.Answer = append(m.Answer, v.RRs...)
				if dnssec_ok {
					m.Answer = append(m.Answer, v.RRSIGs...)
				}
				tgt := v.RRs[0].(*dns.CNAME).Target
				if strings.HasSuffix(tgt, zd.ZoneName) {
					tgtowner, _ := zd.GetOwner(tgt)
					if tgtrrset, ok := tgtowner.RRtypes[qtype]; ok {
						m.Answer = append(m.Answer, tgtrrset.RRs...)
						m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRs...)
						v4glue, v6glue = zd.FindGlue(apex.RRtypes[dns.TypeNS], dnssec_ok)
						m.Extra = append(m.Extra, v4glue.RRs...)
						m.Extra = append(m.Extra, v6glue.RRs...)
						if dnssec_ok {
							m.Answer = append(m.Answer, tgtrrset.RRSIGs...)
							m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRSIGs...)
							m.Extra = append(m.Extra, v4glue.RRSIGs...)
							m.Extra = append(m.Extra, v6glue.RRSIGs...)
						}
					}
					w.WriteMsg(m)
					return nil
				}
			}
		}
	}

	// 1. Check for child delegation
	// log.Printf("---> Checking for child delegation for %s", qname)
	childns, v4glue, v6glue := zd.FindDelegation(qname, dnssec_ok)
	if childns != nil {
		m.MsgHdr.Authoritative = false
		m.Ns = append(m.Ns, childns.RRs...)
		m.Extra = append(m.Extra, v4glue.RRs...)
		m.Extra = append(m.Extra, v6glue.RRs...)
		w.WriteMsg(m)
		return nil
	}

	// 2. Check for exact match qname+qtype
	// log.Printf("---> Checking for exact match qname+qtype %s %s", qname, dns.TypeToString[qtype])
	switch qtype {
	case dns.TypeTXT, dns.TypeMX, dns.TypeA, dns.TypeAAAA, dns.TypeSRV, tdns.TypeNOTIFY, tdns.TypeDSYNC,
		dns.TypeDS, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeRRSIG:
		if _, ok := owner.RRtypes[qtype]; ok && len(owner.RRtypes[qtype].RRs) > 0 {
			if qname == origqname {
				// zd.Logger.Printf("Exact match qname %s %s", qname, dns.TypeToString[qtype])
				m.Answer = append(m.Answer, owner.RRtypes[qtype].RRs...)
			} else {
				// zd.Logger.Printf("Wildcard match qname %s %s", qname, origqname)
				tmp := tdns.WildcardReplace(owner.RRtypes[qtype].RRs, qname, origqname)
				m.Answer = append(m.Answer, tmp...)
			}
			m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRs...)
			v4glue, v6glue = zd.FindGlue(apex.RRtypes[dns.TypeNS], dnssec_ok)
			m.Extra = append(m.Extra, v4glue.RRs...)
			m.Extra = append(m.Extra, v6glue.RRs...)
			if dnssec_ok {
				if qname == origqname {
					m.Answer = append(m.Answer, owner.RRtypes[qtype].RRSIGs...)
				} else {
					tmp := tdns.WildcardReplace(owner.RRtypes[qtype].RRSIGs, qname, origqname)
					m.Answer = append(m.Answer, tmp...)
				}
				m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRSIGs...)
				m.Extra = append(m.Extra, v4glue.RRSIGs...)
				m.Extra = append(m.Extra, v6glue.RRSIGs...)
			}
		} else {
			// ensure correct serial
			apex.RRtypes[dns.TypeSOA].RRs[0].(*dns.SOA).Serial = zd.CurrentSerial
			m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRs[0])
			if dnssec_ok {
				m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRSIGs...)
			}
		}
		w.WriteMsg(m)
		return nil

	default:
		// everything we don't want to deal with
		m.MsgHdr.Rcode = dns.RcodeRefused
		m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRs...)
		v4glue, v6glue = zd.FindGlue(apex.RRtypes[dns.TypeNS], dnssec_ok)
		m.Extra = append(m.Extra, v4glue.RRs...)
		m.Extra = append(m.Extra, v6glue.RRs...)
		if dnssec_ok {
			m.Extra = append(m.Extra, v4glue.RRSIGs...)
			m.Extra = append(m.Extra, v6glue.RRSIGs...)
		}
		w.WriteMsg(m)
	}

	_ = origqname

	return nil
}

func FindZone(qname string) *tdns.ZoneData {
	var tzone string
	labels := strings.Split(qname, ".")
	for i := 1; i < len(labels)-1; i++ {
		tzone = strings.Join(labels[i:], ".")
		if zd, ok := Zones.Get(tzone); ok {
			return zd
		}
	}
	log.Printf("FindZone: no zone for qname=%s found", qname)
	return nil
}

func FindZoneNG(qname string) *tdns.ZoneData {
	i := strings.Index(qname, ".")
	for {
		if i == -1 {
			break // done
		}
		if zd, ok := Zones.Get(qname[i:]); ok {
			return zd
		}
		i = strings.Index(qname[i:], ".")
	}
	return nil
}
