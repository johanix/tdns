/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"crypto/tls"
	"log"
	"net"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

type MsgOptions struct {
	DnssecOK bool
	OtsOptIn bool
	OtsOptOut bool
}

func CaseFoldContains(slice []string, str string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, str) {
			return true
		}
	}
	return false
}

func DnsEngine(conf *Config) error {

	// verbose := viper.GetBool("dnsengine.verbose")
	// debug := viper.GetBool("dnsengine.debug")
	authDNSHandler := createAuthDnsHandler(conf)
	dns.HandleFunc(".", authDNSHandler)

	addresses := viper.GetStringSlice("dnsengine.addresses")
	if !CaseFoldContains(conf.DnsEngine.Transports, "do53") {
		log.Printf("DnsEngine: Do53 transport (UDP/TCP) NOT specified but mandatory. Still configuring: %v", addresses)
	}
	log.Printf("DnsEngine: UDP/TCP addresses: %v", addresses)
	for _, addr := range addresses {
		for _, transport := range []string{"udp", "tcp"} {
			go func(addr, transport string) {
				log.Printf("DnsEngine: serving on %s (%s)\n", addr, transport)
				server := &dns.Server{
					Addr:          addr,
					Net:           transport,
					MsgAcceptFunc: MsgAcceptFunc, // We need a tweaked version for DNS UPDATE
				}

				// Must bump the buffer size of incoming UDP msgs, as updates
				// may be much larger then queries
				server.UDPSize = dns.DefaultMsgSize // 4096
				if err := server.ListenAndServe(); err != nil {
					log.Printf("Failed to setup the %s server: %s", transport, err.Error())
				} else {
					log.Printf("DnsEngine: listening on %s/%s", addr, transport)
				}
			}(addr, transport)
		}
	}

	certFile := viper.GetString("dnsengine.certfile")
	keyFile := viper.GetString("dnsengine.keyfile")
	certKey := true

	if certFile == "" || keyFile == "" {
		log.Println("DnsEngine: no certificate file or key file provided. Not starting DoT, DoH or DoQ service.")
		certKey = false
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Printf("DnsEngine: certificate file %q does not exist. Not starting DoT, DoH or DoQ service.", certFile)
		certKey = false
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Printf("DnsEngine: key file %q does not exist. Not starting DoT, DoH or DoQ service.", keyFile)
		certKey = false
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Printf("DnsEngine: failed to load certificate: %v. Not starting DoT, DoH or DoQ service.", err)
		certKey = false
	}

	if certKey {
		// Strip port numbers from addresses before proceeding to modern transports
		tmp := make([]string, len(addresses))
		for i, addr := range addresses {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				log.Printf("Failed to parse address %s: %v", addr, err)
				tmp[i] = addr // Keep original if parsing fails
			} else {
				tmp[i] = host
			}
		}
		addresses = tmp

		if CaseFoldContains(conf.DnsEngine.Transports, "dot") {
			err := DnsDoTEngine(conf, addresses, &cert, authDNSHandler)
			if err != nil {
				log.Printf("Failed to setup the DoT server: %s\n", err.Error())
			}
		}

		if CaseFoldContains(conf.DnsEngine.Transports, "doh") {
			err := DnsDoHEngine(conf, addresses, certFile, keyFile, authDNSHandler)
			if err != nil {
				log.Printf("Failed to setup the DoH server: %s\n", err.Error())
			}
		}

		if CaseFoldContains(conf.DnsEngine.Transports, "doq") {
			err := DnsDoQEngine(conf, addresses, &cert, authDNSHandler)
			if err != nil {
				log.Printf("Failed to setup the DoQ server: %s\n", err.Error())
			}
		}
	}
	return nil
}

func createAuthDnsHandler(conf *Config) func(w dns.ResponseWriter, r *dns.Msg) {
	dnsupdateq := conf.Internal.DnsUpdateQ
	dnsnotifyq := conf.Internal.DnsNotifyQ
	kdb := conf.Internal.KeyDB

	return func(w dns.ResponseWriter, r *dns.Msg) {
		qname := r.Question[0].Name
		// var dnssec_ok, ots_opt_in, ots_opt_out bool
		var msgoptions MsgOptions
		opt := r.IsEdns0()
		if opt != nil {
			msgoptions.DnssecOK = opt.Do()
			ots_val, ots_ok := ExtractOTSOption(opt)
			if ots_ok {
				msgoptions.OtsOptIn = ots_val == OTS_OPT_IN
				msgoptions.OtsOptOut = ots_val == OTS_OPT_OUT
			}
			if msgoptions.OtsOptIn {
				log.Printf("OTS OPT_IN: %v", msgoptions.OtsOptIn)
			}
			if msgoptions.OtsOptOut {
				log.Printf("OTS OPT_OUT: %v", msgoptions.OtsOptOut)
			}
		}
		// log.Printf("DNSSEC OK: %v", dnssec_ok)

		switch r.Opcode {
		case dns.OpcodeNotify:
			log.Printf("DnsHandler: qname: %s opcode: %s (%d) dnssec_ok: %v. len(dnsnotifyq): %d", qname, dns.OpcodeToString[r.Opcode], r.Opcode, msgoptions.DnssecOK, len(dnsnotifyq))
			// A DNS NOTIFY may trigger time consuming outbound queries
			dnsnotifyq <- DnsNotifyRequest{ResponseWriter: w, Msg: r, Qname: qname}
			// Not waiting for a result
			return

		case dns.OpcodeUpdate:
			log.Printf("DnsHandler: qname: %s opcode: %s (%d) dnssec_ok: %v. len(dnsupdateq): %d", qname, dns.OpcodeToString[r.Opcode], r.Opcode, msgoptions.DnssecOK, len(dnsupdateq))
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
			log.Printf("DnsHandler: qname: %s opcode: %s (%d) dnssec_ok: %v", qname, dns.OpcodeToString[r.Opcode], r.Opcode, msgoptions.DnssecOK)
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
				err := zd.QueryResponder(w, r, qname, qtype, msgoptions, kdb)
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
					DotServerQnameResponse(qname, w, r)
					return
				}

				// We don't have the zone, and it's not a .server CH tld query, so we return a REFUSED
				w.WriteMsg(m)
				return // didn't find any zone for that qname or found zone, but it is an XFR zone only
			}

			log.Printf("DnsHandler: query %q refers to zone %q", qname, zd.ZoneName)

			log.Printf("DnsHandler: AppMode: \"%s\"", AppTypeToString[Globals.App.Type])
			if Globals.App.Type == AppTypeAgent {
				log.Printf("DnsHandler: Agent mode, not handling ordinary queries for zone %q", qname)
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
				log.Printf("DnsHandler: Qname is %q, which is belongs to a known zone (%q), but it is in %s error state: %s",
					qname, zd.ZoneName, ErrorTypeToString[zd.ErrorType], zd.ErrorMsg)
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(m)
				return
			}

			if zd.RefreshCount == 0 {
				log.Printf("DnsHandler: Qname is %q, which belongs to a known zone (%q), but it has not been refreshed at least once yet", qname, zd.ZoneName)
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(m)
				return
			}

			// log.Printf("Found matching %s (%d) zone for qname %s: %s", tdns.ZoneStoreToString[zd.ZoneStore], zd.ZoneStore, qname, zd.ZoneName)
			err := zd.QueryResponder(w, r, qname, qtype, msgoptions, kdb)
			if err != nil {
				log.Printf("Error in QueryResponder: %v", err)
			}
			return

		default:
			log.Printf("Error: unable to handle msgs of type %s", dns.OpcodeToString[r.Opcode])
		}
	}
}
