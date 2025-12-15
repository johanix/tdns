/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	edns0 "github.com/johanix/tdns/tdns/edns0"
	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func CaseFoldContains(slice []string, str string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, str) {
			return true
		}
	}
	return false
}

func DnsEngine(ctx context.Context, conf *Config) error {
	log.Printf("DnsEngine: starting with addresses: %v", conf.DnsEngine.Addresses)

	// verbose := viper.GetBool("dnsengine.verbose")
	// debug := viper.GetBool("dnsengine.debug")
	authDNSHandler := createAuthDnsHandler(ctx, conf)

	// Create a local ServeMux for DnsEngine to avoid conflicts with other engines
	dnsMux := dns.NewServeMux()
	dnsMux.HandleFunc(".", authDNSHandler)

	addresses := conf.DnsEngine.Addresses
	if !CaseFoldContains(conf.DnsEngine.Transports, "do53") {
		log.Printf("DnsEngine: Do53 transport (UDP/TCP) NOT specified but mandatory. Still configuring: %v", addresses)
	}
	log.Printf("DnsEngine: UDP/TCP addresses: %v", addresses)
	var servers []*dns.Server
	for _, addr := range addresses {
		for _, transport := range []string{"udp", "tcp"} {
			srv := &dns.Server{
				Addr:          addr,
				Net:           transport,
				Handler:       dnsMux,        // Use local mux instead of global handler
				MsgAcceptFunc: MsgAcceptFunc, // We need a tweaked version for DNS UPDATE
			}
			// Must bump the buffer size of incoming UDP msgs, as updates
			// may be much larger then queries
			srv.UDPSize = dns.DefaultMsgSize // 4096
			servers = append(servers, srv)

			go func(s *dns.Server, addr, transport string) {
				log.Printf("DnsEngine: serving on %s (%s)\n", addr, transport)
				if err := s.ListenAndServe(); err != nil {
					log.Printf("Failed to setup the %s server: %s", transport, err.Error())
				} else {
					log.Printf("DnsEngine: listening on %s/%s", addr, transport)
				}
			}(srv, addr, transport)
		}
	}

	// Graceful shutdown on context cancellation
	go func() {
		<-ctx.Done()
		log.Printf("DnsEngine: shutting down Do53 servers...")
		for _, s := range servers {
			done := make(chan struct{})
			go func(srv *dns.Server) {
				_ = srv.Shutdown()
				close(done)
			}(s)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				log.Printf("DnsEngine: timeout shutting down %s/%s; continuing", s.Addr, s.Net)
			}
		}
	}()

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

	var certPEM []byte
	var keyPEM []byte
	var err error

	if certKey {
		certPEM, err = os.ReadFile(certFile)
		if err != nil {
			return fmt.Errorf("DnsEngine: error reading cert file: %v", err)
		}

		keyPEM, err = os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("DnsEngine: error reading key file: %v", err)
		}

		conf.Internal.CertData = string(certPEM)
		conf.Internal.KeyData = string(keyPEM)

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Printf("DnsEngine: failed to load certificate: %v. Not starting DoT, DoH or DoQ service.", err)
			certKey = false
		}

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
			err := DnsDoTEngine(ctx, conf, addresses, &cert, authDNSHandler)
			if err != nil {
				log.Printf("Failed to setup the DoT server: %s\n", err.Error())
			}
		}

		if CaseFoldContains(conf.DnsEngine.Transports, "doh") {
			err := DnsDoHEngine(ctx, conf, addresses, certFile, keyFile, authDNSHandler)
			if err != nil {
				log.Printf("Failed to setup the DoH server: %s\n", err.Error())
			}
		}

		if CaseFoldContains(conf.DnsEngine.Transports, "doq") {
			err := DnsDoQEngine(ctx, conf, addresses, &cert, authDNSHandler)
			if err != nil {
				log.Printf("Failed to setup the DoQ server: %s\n", err.Error())
			}
		}
	}
	return nil
}

func createAuthDnsHandler(ctx context.Context, conf *Config) func(w dns.ResponseWriter, r *dns.Msg) {
	dnsupdateq := conf.Internal.DnsUpdateQ
	dnsnotifyq := conf.Internal.DnsNotifyQ
	kdb := conf.Internal.KeyDB

	return func(w dns.ResponseWriter, r *dns.Msg) {
		qname := r.Question[0].Name
		// var dnssec_ok, ots_opt_in, ots_opt_out bool
		msgoptions, err := edns0.ExtractFlagsAndEDNS0Options(r)
		if err != nil {
			log.Printf("Error extracting EDNS0 options: %v", err)
		}

		switch r.Opcode {
		case dns.OpcodeNotify:
			log.Printf("DnsHandler: qname: %s opcode: %s (%d) DO: %v. len(dnsnotifyq): %d", qname, dns.OpcodeToString[r.Opcode], r.Opcode, msgoptions.DO, len(dnsnotifyq))
			// A DNS NOTIFY may trigger time consuming outbound queries
			dnsnotifyq <- DnsNotifyRequest{ResponseWriter: w, Msg: r, Qname: qname, Options: msgoptions}
			// Not waiting for a result
			return

		case dns.OpcodeUpdate:
			log.Printf("DnsHandler: qname: %s opcode: %s (%d) DO: %v. len(dnsupdateq): %d", qname, dns.OpcodeToString[r.Opcode], r.Opcode, msgoptions.DO, len(dnsupdateq))
			// A DNS Update may trigger time consuming outbound queries
			dnsupdateq <- DnsUpdateRequest{
				ResponseWriter: w,
				Msg:            r,
				Qname:          qname,
				Options:        msgoptions,
				Status:         &UpdateStatus{},
			}
			// Not waiting for a result
			return

		case dns.OpcodeQuery:
			log.Printf("DnsHandler: qname: %s opcode: %s (%d) DO: %v", qname, dns.OpcodeToString[r.Opcode], r.Opcode, msgoptions.DO)
			qtype := r.Question[0].Qtype
			log.Printf("Zone %s %s request from %s", qname, dns.TypeToString[qtype], w.RemoteAddr())

			// Check if this is a reporter app handling error channel queries (RFC9567)
			if Globals.App.Type == AppTypeReporter {
				if strings.HasPrefix(qname, "_er.") {
					edns0.ErrorChannelReporter(qname, qtype, w, r)
					return
				}
				log.Printf("DnsHandler: Qname is %q, which is not the correct format for error channel reports (expected to start with '_er.').", qname)
				m := new(dns.Msg)
				m.SetRcode(r, dns.RcodeRefused)
				w.WriteMsg(m)
				return
			}

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
				err := zd.QueryResponder(ctx, w, r, qname, qtype, msgoptions, kdb, conf.Internal.ImrEngine)
				if err != nil {
					log.Printf("Error in QueryResponder: %v", err)
					m := new(dns.Msg)
					m.SetRcode(r, dns.RcodeServerFailure)
					w.WriteMsg(m)
				}
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
			err := zd.QueryResponder(ctx, w, r, qname, qtype, msgoptions, kdb, conf.Internal.ImrEngine)
			if err != nil {
				log.Printf("Error in QueryResponder: %v", err)
			}
			return

		default:
			log.Printf("Error: unable to handle msgs of type %s", dns.OpcodeToString[r.Opcode])
		}
	}
}
