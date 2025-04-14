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

	// verbose := viper.GetBool("dnsengine.verbose")
	// debug := viper.GetBool("dnsengine.debug")
	ourDNSHandler := createDnsHandler(conf)
	dns.HandleFunc(".", ourDNSHandler)

	addresses := viper.GetStringSlice("dnsengine.do53.addresses")
	log.Printf("DnsEngine: UDP/TCP addresses: %v", addresses)
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
					log.Printf("Failed to setup the %s server: %s", net, err.Error())
				} else {
					log.Printf("DnsEngine: listening on %s/%s", addr, net)
				}
			}(addr, net)
		}
	}

	dotaddrs := viper.GetStringSlice("dnsengine.dot.addresses")
	if len(dotaddrs) > 0 {
		err := DnsDoTEngine(conf, dotaddrs, ourDNSHandler)
		if err != nil {
			log.Printf("Failed to setup the DoT server: %s\n", err.Error())
		}
	}

	dohaddrs := viper.GetStringSlice("dnsengine.doh.addresses")
	if len(dohaddrs) > 0 {
		err := DnsDoHEngine(conf, dohaddrs, ourDNSHandler)
		if err != nil {
			log.Printf("Failed to setup the DoH server: %s\n", err.Error())
		}
	}

	doqaddrs := viper.GetStringSlice("dnsengine.doq.addresses")
	if len(doqaddrs) > 0 {
		err := DnsDoQEngine(conf, doqaddrs, ourDNSHandler)
		if err != nil {
			log.Printf("Failed to setup the DoQ server: %s\n", err.Error())
		}
	}
	return nil
}

func createDnsHandler(conf *Config) func(w dns.ResponseWriter, r *dns.Msg) {
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

		switch r.Opcode {
		case dns.OpcodeNotify:
			log.Printf("DnsHandler: qname: %s opcode: %s (%d) dnssec_ok: %v. len(dnsnotifyq): %d", qname, dns.OpcodeToString[r.Opcode], r.Opcode, dnssec_ok, len(dnsnotifyq))
			// A DNS NOTIFY may trigger time consuming outbound queries
			dnsnotifyq <- DnsNotifyRequest{ResponseWriter: w, Msg: r, Qname: qname}
			// Not waiting for a result
			return

		case dns.OpcodeUpdate:
			log.Printf("DnsHandler: qname: %s opcode: %s (%d) dnssec_ok: %v. len(dnsupdateq): %d", qname, dns.OpcodeToString[r.Opcode], r.Opcode, dnssec_ok, len(dnsupdateq))
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
			log.Printf("DnsHandler: qname: %s opcode: %s (%d) dnssec_ok: %v", qname, dns.OpcodeToString[r.Opcode], r.Opcode, dnssec_ok)
			qtype := r.Question[0].Qtype
			log.Printf("Zone %s %s request from %s", qname, dns.TypeToString[qtype], w.RemoteAddr())

			if zd, ok := Zones.Get(qname); ok {
				if zd.Error {
					if zd.ErrorType != RefreshError || zd.RefreshCount == 0 {
						log.Printf("DnsHandler: Qname is %q, which is a known zone, but it is in %s error state: %s",
							qname, ErrorTypeToString[zd.ErrorType], zd.ErrorMsg)
						m := new(dns.Msg)
						m.SetRcode(r, dns.RcodeServerFailure)
						w.WriteMsg(m)
						return
					}
				}

				log.Printf("DnsHandler: Qname is %q, which is a known zone.", qname)
				err := zd.QueryResponder(w, r, qname, qtype, dnssec_ok, kdb)
				if err != nil {
					log.Printf("Error in QueryResponder: %v", err)
				}
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(m)
				return
			}

			// Let's try case folded
			// lcqname := strings.ToLower(qname)
			// if zd, ok := Zones.Get(lcqname); ok {
			// The qname is equal to the name of a zone we are authoritative for
			// err := zd.ApexResponder(w, r, lcqname, qtype, dnssec_ok, kdb)
			// if err != nil {
			// 	log.Printf("Error in ApexResponder: %v", err)
			// }
			// return
			// }

			log.Printf("DnsHandler: Qname is %q, which is not a known zone.", qname)
			log.Printf("DnsHandler: known zones are: %v", Zones.Keys())

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
							v = fmt.Sprintf("%s version %s", Globals.App.Name, Globals.App.Version)
						} else if strings.Contains(v, "{version}") {
							v = strings.Replace(v, "{version}", Globals.App.Version, -1)
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

			log.Printf("DnsHandler: AppMode: \"%s\"", AppTypeToString[Globals.App.Type])
			if Globals.App.Type == AppTypeAgent {
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

			if zd.Error && zd.ErrorType != RefreshError {
				log.Printf("DnsHandler: Qname is %q, which is a known zone, but it is in %s error state: %s",
					qname, ErrorTypeToString[zd.ErrorType], zd.ErrorMsg)
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(m)
				return
			}

			if zd.RefreshCount == 0 {
				log.Printf("DnsHandler: Qname is %q, which is a known zone, but it has not been refreshed at least once yet", qname)
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(m)
				return
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
