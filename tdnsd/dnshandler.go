/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	"fmt"
	"log"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/spf13/viper"

	"github.com/johanix/tdns/tdns"
)

func DnsEngine(conf *tdns.Config) error {
	addresses := viper.GetStringSlice("dnsengine.addresses")

	// verbose := viper.GetBool("dnsengine.verbose")
	// debug := viper.GetBool("dnsengine.debug")
	dns.HandleFunc(".", createHandler(conf))

	log.Printf("DnsEngine: addresses: %v", addresses)
	for _, addr := range addresses {
		for _, net := range []string{"udp", "tcp"} {
			go func(addr, net string) {
				log.Printf("DnsEngine: serving on %s (%s)\n", addr, net)
				server := &dns.Server{
					Addr:          addr,
					Net:           net,
					MsgAcceptFunc: tdns.MsgAcceptFunc, // We need a tweaked version for DNS UPDATE
				}

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

func createHandler(conf *tdns.Config) func(w dns.ResponseWriter, r *dns.Msg) {
	dnsupdateq := conf.Internal.DnsUpdateQ
	dnsnotifyq := conf.Internal.DnsNotifyQ
	kdb := conf.Internal.KeyDB

	return func(w dns.ResponseWriter, r *dns.Msg) {
		qname := r.Question[0].Name
		var dnssec_ok bool
		opt := r.IsEdns0()
		if opt != nil {
			dnssec_ok = opt.Do()
		}
		// log.Printf("DNSSEC OK: %v", dnssec_ok)
		log.Printf("DnsHandler: qname: %s opcode: %s (%d) dnssec_ok: %v", qname, dns.OpcodeToString[r.Opcode], r.Opcode, dnssec_ok)

		switch r.Opcode {
		case dns.OpcodeNotify:
			// A DNS NOTIFY may trigger time consuming outbound queries
			dnsnotifyq <- tdns.DnsNotifyRequest{ResponseWriter: w, Msg: r, Qname: qname}
			// Not waiting for a result
			return

		case dns.OpcodeUpdate:
			// A DNS Update may trigger time consuming outbound queries
			dnsupdateq <- tdns.DnsUpdateRequest{
				ResponseWriter: w,
				Msg:            r,
				Qname:          qname,
				Status:         &tdns.UpdateStatus{},
			}
			// Not waiting for a result
			return

		case dns.OpcodeQuery:
			qtype := r.Question[0].Qtype
			log.Printf("Zone %s %s request from %s", qname, dns.TypeToString[qtype], w.RemoteAddr())

			if zd, ok := tdns.Zones.Get(qname); ok {
				// The qname is equal to the name of a zone we are authoritative for
				err := ApexResponder(w, r, zd, qname, qtype, dnssec_ok, kdb)
				if err != nil {
					log.Printf("Error in ApexResponder: %v", err)
				}
				return
			}

			// Let's try case folded
			lcqname := strings.ToLower(qname)
			if zd, ok := tdns.Zones.Get(lcqname); ok {
				// The qname is equal to the name of a zone we are authoritative for
				err := ApexResponder(w, r, zd, lcqname, qtype, dnssec_ok, kdb)
				if err != nil {
					log.Printf("Error in ApexResponder: %v", err)
				}
				return
			}

			if qtype == dns.TypeAXFR || qtype == dns.TypeIXFR {
				// We are not authoritative for this zone, so no xfrs possible
				m := new(dns.Msg)
				m.SetReply(r)
				m.MsgHdr.Rcode = dns.RcodeNotAuth
				w.WriteMsg(m)
				return
			}

			log.Printf("DnsHandler: Qname is '%s', which is not a known zone.", qname)
			// known_zones := append([]string{}, tdns.Zones.Keys()...)
			// log.Printf("DnsHandler: Known zones are: %v", known_zones)

			// Let's see if we can find the zone
			zd, folded := tdns.FindZone(qname)
			if zd == nil {
				// No zone found, but perhaps this is a query for the .server CH tld?
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeRefused)
				qname = strings.ToLower(qname)
				if strings.HasSuffix(qname, ".server.") && r.Question[0].Qclass == dns.ClassCHAOS {
					log.Printf("DnsHandler: Qname is '%s', which is not a known zone, but likely a query for the .server CH tld", qname)
					switch qname {
					case "id.server.":
						m.SetRcode(r, dns.RcodeSuccess)
						v := viper.GetString("server.id")
						if v == "" {
							v = "tdnsd - an authoritative name server for experiments and POCs"
						}
						m.Answer = append(m.Answer, &dns.TXT{
							Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}, Txt: []string{v},
						})
					case "version.server.":
						m.SetRcode(r, dns.RcodeSuccess)
						v := viper.GetString("server.version")
						if v == "" {
							v = fmt.Sprintf("tdnsd version %s", appVersion)
						}
						m.Answer = append(m.Answer, &dns.TXT{
							Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}, Txt: []string{v},
						})
					case "authors.server.":
						m.SetRcode(r, dns.RcodeSuccess)
						m.Answer = append(m.Answer, &dns.TXT{
							Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
							Txt: []string{"Johan Stenstam <johani@johani.org>"},
						})

					case "hostname.server.":
						m.SetRcode(r, dns.RcodeSuccess)
						v := viper.GetString("server.hostname")
						if v == "" {
							v = "a.random.internet.host."
						}
						m.Answer = append(m.Answer, &dns.TXT{
							Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600}, Txt: []string{v},
						})
					default:
					}
					w.WriteMsg(m)
					return
				}
				w.WriteMsg(m)
				return // didn't find any zone for that qname or found zone, but it is an XFR zone only
			}

			if zd.ZoneStore == tdns.XfrZone {
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeRefused)
				w.WriteMsg(m)
				return // didn't find any zone for that qname or found zone, but it is an XFR zone only
			}

			if folded {
				qname = strings.ToLower(qname)
			}

			// log.Printf("Found matching %s (%d) zone for qname %s: %s", tdns.ZoneStoreToString[zd.ZoneStore], zd.ZoneStore, qname, zd.ZoneName)
			err := QueryResponder(w, r, zd, qname, qtype, dnssec_ok, kdb)
			if err != nil {
				log.Printf("Error in QueryResponder: %v", err)
			}
			return

		default:
			log.Printf("Error: unable to handle msgs of type %s", dns.OpcodeToString[r.Opcode])
		}
	}
}

func ApexResponder(w dns.ResponseWriter, r *dns.Msg, zd *tdns.ZoneData, qname string, qtype uint16, dnssec_ok bool, kdb *tdns.KeyDB) error {
	dak, err := kdb.GetDnssecKeys(zd.ZoneName, tdns.DnskeyStateActive)
	if err != nil {
		log.Printf("ApexResponder: failed to get dnssec key for zone %s", zd.ZoneName)
	}

	MaybeSignRRset := func(rrset tdns.RRset, qname string) tdns.RRset {
		if dak == nil {
			log.Printf("ApexResponder: MaybeSignRRset: Warning: dak is nil")
			return rrset
		}
		if zd.Options["online-signing"] && dak != nil && len(dak.ZSKs) > 0 && len(rrset.RRSIGs) == 0 {
			_, err := zd.SignRRset(&rrset, qname, dak, false)
			if err != nil {
				log.Printf("Error signing %s: %v", qname, err)
			} else {
				log.Printf("Signed %s: %v", qname, err)
			}
		}
		return rrset
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil || apex == nil {
		log.Fatalf("ApexResponder: failed to get apex data for zone %s", zd.ZoneName)
	}

	if dnssec_ok {
		apex.RRtypes[dns.TypeSOA] = MaybeSignRRset(apex.RRtypes[dns.TypeSOA], zd.ZoneName)
		apex.RRtypes[dns.TypeNS] = MaybeSignRRset(apex.RRtypes[dns.TypeNS], zd.ZoneName)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.MsgHdr.Authoritative = true

	var v4glue, v6glue *tdns.RRset

	switch qtype {
	case dns.TypeAXFR, dns.TypeIXFR:
		log.Printf("We have the %s %s, so let's try to serve it", tdns.ZoneStoreToString[zd.ZoneStore], qname)
		zd.ZoneTransferOut(w, r)
		return nil

	case dns.TypeSOA:
		// zd.Logger.Printf("apex: %v", apex)
		zd.Logger.Printf("There are %d SOA RRs in %s. rrset: %v", len(apex.RRtypes[dns.TypeSOA].RRs),
			zd.ZoneName, apex.RRtypes[dns.TypeSOA])
		apex.RRtypes[dns.TypeSOA].RRs[0].(*dns.SOA).Serial = zd.CurrentSerial
		m.Answer = append(m.Answer, apex.RRtypes[dns.TypeSOA].RRs[0])
		m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRs...)
		v4glue, v6glue = zd.FindGlue(apex.RRtypes[dns.TypeNS], dnssec_ok)
		m.Extra = append(m.Extra, v4glue.RRs...)
		m.Extra = append(m.Extra, v6glue.RRs...)
		if dnssec_ok {
			log.Printf("ApexResponder: dnssec_ok is true, adding RRSIGs")
			m.Answer = append(m.Answer, apex.RRtypes[dns.TypeSOA].RRSIGs...)
			m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRSIGs...)
			m.Extra = append(m.Extra, v4glue.RRSIGs...)
			m.Extra = append(m.Extra, v6glue.RRSIGs...)
		}

	case tdns.TypeDSYNC, tdns.TypeNOTIFY, dns.TypeMX, dns.TypeTLSA, dns.TypeSRV,
		dns.TypeA, dns.TypeAAAA, dns.TypeNS, dns.TypeTXT, dns.TypeZONEMD, dns.TypeKEY,
		dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeRRSIG,
		dns.TypeDNSKEY, dns.TypeCSYNC, dns.TypeCDS, dns.TypeCDNSKEY:
		if rrset, ok := apex.RRtypes[qtype]; ok {
			if len(rrset.RRs) > 0 {
				m.Answer = append(m.Answer, rrset.RRs...)
				m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRs...)
				v4glue, v6glue = zd.FindGlue(apex.RRtypes[dns.TypeNS], dnssec_ok)
				m.Extra = append(m.Extra, v4glue.RRs...)
				m.Extra = append(m.Extra, v6glue.RRs...)
				if dnssec_ok {
					apex.RRtypes[qtype] = MaybeSignRRset(apex.RRtypes[qtype], zd.ZoneName)
					apex.RRtypes[dns.TypeNS] = MaybeSignRRset(apex.RRtypes[dns.TypeNS], zd.ZoneName)

					m.Answer = append(m.Answer, apex.RRtypes[qtype].RRSIGs...)
					m.Ns = append(m.Ns, apex.RRtypes[dns.TypeNS].RRSIGs...)
					m.Extra = append(m.Extra, v4glue.RRSIGs...)
					m.Extra = append(m.Extra, v6glue.RRSIGs...)
				}
			} else {
				m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRs...)
				if dnssec_ok {
					apex.RRtypes[dns.TypeSOA] = MaybeSignRRset(apex.RRtypes[dns.TypeSOA], zd.ZoneName)
					m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRSIGs...)
				}
			}
		} else {
			m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRs...)
			if dnssec_ok {
				apex.RRtypes[dns.TypeSOA] = MaybeSignRRset(apex.RRtypes[dns.TypeSOA], zd.ZoneName)
				m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRSIGs...)
			}
		}
		// Anything special?
		switch qtype {
		case dns.TypeNS:
			m.Ns = []dns.RR{} // authority not needed when querying for zone NS
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

func QueryResponder(w dns.ResponseWriter, r *dns.Msg, zd *tdns.ZoneData, qname string, qtype uint16, dnssec_ok bool, kdb *tdns.KeyDB) error {

	dak, err := kdb.GetDnssecKeys(zd.ZoneName, tdns.DnskeyStateActive)
	if err != nil {
		log.Printf("QueryResponder: failed to get dnssec key for zone %s", zd.ZoneName)
	}

	MaybeSignRRset := func(rrset tdns.RRset, qname string) tdns.RRset {
		if dak == nil {
			log.Printf("QueryResponder: MaybeSignRRset: Warning: dak is nil")
			return rrset
		}
		if zd.Options["online-signing"] && dak != nil && len(dak.ZSKs) > 0 && len(rrset.RRSIGs) == 0 {
			_, err := zd.SignRRset(&rrset, qname, dak, false)
			if err != nil {
				log.Printf("Error signing %s: %v", qname, err)
			} else {
				log.Printf("Signed %s: %v", qname, err)
			}
		}
		return rrset
	}

	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		log.Fatalf("QueryResponder: failed to get apex data for zone %s", zd.ZoneName)
	}

	if dnssec_ok {
		apex.RRtypes[dns.TypeSOA] = MaybeSignRRset(apex.RRtypes[dns.TypeSOA], zd.ZoneName)
		apex.RRtypes[dns.TypeNS] = MaybeSignRRset(apex.RRtypes[dns.TypeNS], zd.ZoneName)
	}

	// log.Printf("QueryResponder: qname: %s qtype: %s", qname, dns.TypeToString[qtype])
	m := new(dns.Msg)
	m.SetReply(r)
	m.MsgHdr.Authoritative = true

	var v4glue, v6glue *tdns.RRset
	var wildqname string
	origqname := qname

	// log.Printf("---> Checking for existence of qname %s", qname)
	if !zd.NameExists(qname) {
		log.Printf("---> No exact match for %s in zone %s", qname, zd.ZoneName)

		// 1. Check for child delegation
		log.Printf("---> Checking for child delegation for %s", qname)
		cdd := zd.FindDelegation(qname, dnssec_ok)

		// If there is delegation data and an NS RRset is present, return a referral
		if cdd != nil && cdd.NS_rrset != nil && qtype != dns.TypeDS && qtype != tdns.TypeDELEG {
			log.Printf("---> Sending referral for %s", qname)
			m.MsgHdr.Authoritative = false
			m.Ns = append(m.Ns, cdd.NS_rrset.RRs...)
			m.Extra = append(m.Extra, cdd.A_glue...)
			m.Extra = append(m.Extra, cdd.AAAA_glue...)
			w.WriteMsg(m)
			return nil
		}

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
		}
		log.Printf("---> Wildcard match for %s (matches %s) in zone %s", qname, wildqname, zd.ZoneName)
		origqname = qname
		qname = wildqname
	}

	owner, err := zd.GetOwner(qname)
	if err != nil {
		log.Printf("QueryResponder: failed to get owner for qname %s", qname)
	}

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
	log.Printf("---> Checking for qname + CNAME %s in zone %s", qname, zd.ZoneName)
	if len(owner.RRtypes) == 1 {
		for k, v := range owner.RRtypes {
			if k == dns.TypeCNAME {
				if len(v.RRs) > 1 {
					// XXX: NSD will not even load a zone with multiple CNAMEs. Better to check during load...
					log.Printf("QueryResponder: Zone %s: Illegal content: multiple CNAME RRs: %v", zd.ZoneName, v)
				}
				m.Answer = append(m.Answer, v.RRs...)
				if dnssec_ok {
					owner.RRtypes[k] = MaybeSignRRset(owner.RRtypes[k], qname)
					m.Answer = append(m.Answer, owner.RRtypes[k].RRSIGs...)
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
							tgtowner.RRtypes[qtype] = MaybeSignRRset(tgtowner.RRtypes[qtype], qname)
							m.Answer = append(m.Answer, tgtowner.RRtypes[qtype].RRSIGs...)

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
	cdd := zd.FindDelegation(qname, dnssec_ok)

	// dump.P(cdd)

	// If there is delegation data and an NS RRset is present, return a referral
	if cdd != nil && cdd.NS_rrset != nil && qtype != dns.TypeDS && qtype != tdns.TypeDELEG {
		log.Printf("---> Sending referral for %s", qname)
		m.MsgHdr.Authoritative = false
		m.Ns = append(m.Ns, cdd.NS_rrset.RRs...)
		m.Extra = append(m.Extra, cdd.A_glue...)
		m.Extra = append(m.Extra, cdd.AAAA_glue...)
		w.WriteMsg(m)
		return nil
	}

	// 2. Check for exact match qname+qtype
	log.Printf("---> Checking for exact match qname+qtype %s %s in zone %s", qname, dns.TypeToString[qtype], zd.ZoneName)
	switch qtype {
	case dns.TypeTXT, dns.TypeMX, dns.TypeA, dns.TypeAAAA, dns.TypeSRV, tdns.TypeNOTIFY, tdns.TypeDSYNC,
		tdns.TypeDELEG, dns.TypeDS, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeRRSIG:
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

				log.Printf("Should we sign qname %s %s (origqname: %s)?", qname, dns.TypeToString[qtype], origqname)
				// if zd.OnlineSigning && cs != nil {
				if zd.Options["online-signing"] && dak != nil && len(dak.ZSKs) > 0 {
					if qname == origqname {
						owner.RRtypes[qtype] = MaybeSignRRset(owner.RRtypes[qtype], qname)
					}
				}

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
			log.Printf("---> No exact match qname+qtype %s %s in zone %s", qname, dns.TypeToString[qtype], zd.ZoneName)
			// ensure correct serial
			apex.RRtypes[dns.TypeSOA].RRs[0].(*dns.SOA).Serial = zd.CurrentSerial
			m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRs[0])
			if dnssec_ok {
				m.Ns = append(m.Ns, apex.RRtypes[dns.TypeSOA].RRSIGs...)
			}
		}
		w.WriteMsg(m)
		return nil
	}

	// Final catcheverything we don't want to deal with
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

	_ = origqname

	return nil
}
