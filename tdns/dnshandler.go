/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"log"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

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
				server := &dns.Server{
					Addr:          addr,
					Net:           net,
					MsgAcceptFunc: MsgAcceptFunc, // We need a tweaked version for DNS UPDATE
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

func createHandler(conf *Config) func(w dns.ResponseWriter, r *dns.Msg) {
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
			dnsnotifyq <- DnsNotifyRequest{ResponseWriter: w, Msg: r, Qname: qname}
			// Not waiting for a result
			return

		case dns.OpcodeUpdate:
			// A DNS Update may trigger time consuming outbound queries
			dnsupdateq <- DnsUpdateRequest{
				ResponseWriter: w,
				Msg:            r,
				Qname:          qname,
				Status:         &UpdateStatus{},
			}
			// Not waiting for a result
			return

		case dns.OpcodeQuery:
			qtype := r.Question[0].Qtype
			log.Printf("Zone %s %s request from %s", qname, dns.TypeToString[qtype], w.RemoteAddr())

			if zd, ok := Zones.Get(qname); ok {
				// The qname is equal to the name of a zone we are authoritative for
				err := zd.ApexResponder(w, r, qname, qtype, dnssec_ok, kdb)
				if err != nil {
					log.Printf("Error in ApexResponder: %v", err)
				}
				return
			}

			// Let's try case folded
			lcqname := strings.ToLower(qname)
			if zd, ok := Zones.Get(lcqname); ok {
				// The qname is equal to the name of a zone we are authoritative for
				err := zd.ApexResponder(w, r, lcqname, qtype, dnssec_ok, kdb)
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
			zd, folded := FindZone(qname)
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
							v = fmt.Sprintf("tdnsd version %s", conf.AppVersion)
						} else if strings.Contains(v, "{version}") {
							v = strings.Replace(v, "{version}", conf.AppVersion, -1)
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

			log.Printf("DnsHandler: AppMode: \"%s\"", conf.AppMode)
			if conf.AppMode == "agent" {
				log.Printf("DnsHandler: Agent mode, not handling ordinary queries for zone %s", qname)
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeRefused)
				w.WriteMsg(m)
				return
			}

			if zd.ZoneStore == XfrZone {
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeRefused)
				w.WriteMsg(m)
				return // didn't find any zone for that qname or found zone, but it is an XFR zone only
			}

			if folded {
				qname = strings.ToLower(qname)
			}

			// log.Printf("Found matching %s (%d) zone for qname %s: %s", tdns.ZoneStoreToString[zd.ZoneStore], zd.ZoneStore, qname, zd.ZoneName)
			err := zd.QueryResponder(w, r, qname, qtype, dnssec_ok, kdb)
			if err != nil {
				log.Printf("Error in QueryResponder: %v", err)
			}
			return

		default:
			log.Printf("Error: unable to handle msgs of type %s", dns.OpcodeToString[r.Opcode])
		}
	}
}