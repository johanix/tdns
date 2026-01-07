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

	edns0 "github.com/johanix/tdns/v0.x/tdns/edns0"
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
	if Globals.Debug {
		log.Printf("DnsEngine: Debug mode enabled")
		log.Printf("DnsEngine: DnsQueryQ channel: %v (nil=%v)", conf.Internal.DnsQueryQ, conf.Internal.DnsQueryQ == nil)
		log.Printf("DnsEngine: DnsNotifyQ channel: %v (nil=%v)", conf.Internal.DnsNotifyQ, conf.Internal.DnsNotifyQ == nil)
		log.Printf("DnsEngine: DnsUpdateQ channel: %v (nil=%v)", conf.Internal.DnsUpdateQ, conf.Internal.DnsUpdateQ == nil)
	}

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
				if Globals.Debug {
					log.Printf("DnsEngine: Attempting to bind to %s (%s)", addr, transport)
				}
				log.Printf("DnsEngine: serving on %s (%s)\n", addr, transport)
				if err := s.ListenAndServe(); err != nil {
					log.Printf("Failed to setup the %s server: %s", transport, err.Error())
				} else {
					if Globals.Debug {
						log.Printf("DnsEngine: Successfully listening on %s/%s", addr, transport)
					}
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
	dnsqueryq := conf.Internal.DnsQueryQ    // This should be non-nil only for customer handlers like KDC queries
	kdb := conf.Internal.KeyDB

	return func(w dns.ResponseWriter, r *dns.Msg) {
		if Globals.Debug {
			log.Printf("DnsHandler: Received DNS message from %s", w.RemoteAddr())
			log.Printf("DnsHandler: Message ID: %d, Opcode: %s (%d)", r.MsgHdr.Id, dns.OpcodeToString[r.Opcode], r.Opcode)
			log.Printf("DnsHandler: Question count: %d", len(r.Question))
			if len(r.Question) > 0 {
				log.Printf("DnsHandler: Question: %s %s", r.Question[0].Name, dns.TypeToString[r.Question[0].Qtype])
			}
			log.Printf("DnsHandler: Additional count: %d", len(r.Extra))
		}
		qname := r.Question[0].Name
		// var dnssec_ok, ots_opt_in, ots_opt_out bool
		msgoptions, err := edns0.ExtractFlagsAndEDNS0Options(r)
		if err != nil {
			log.Printf("Error extracting EDNS0 options: %v", err)
		}
		if Globals.Debug {
			log.Printf("DnsHandler: EDNS0 DO bit: %v", msgoptions.DO)
		}

		switch r.Opcode {
		case dns.OpcodeNotify:
			// Extract qtype from NOTIFY question (if present)
			var qtype uint16
			if len(r.Question) > 0 {
				qtype = r.Question[0].Qtype
			}
			
			// Check for registered NOTIFY handlers (new registration API)
			handlers := getNotifyHandlers(conf, qtype)
			if len(handlers) > 0 {
				// Try registered handlers
				handled := false
				for _, handler := range handlers {
					dnr := DnsNotifyRequest{
						ResponseWriter: w,
						Msg:            r,
						Qname:          qname,
						Options:        msgoptions,
					}
					
					err := handler(ctx, &dnr)
					if err == nil {
						// Handler successfully handled the NOTIFY
						handled = true
						if Globals.Debug {
							log.Printf("DnsHandler: NOTIFY handled by registered handler (qname=%s, qtype=%s)", qname, dns.TypeToString[qtype])
						}
						return
					} else if err == ErrNotHandled {
						// Handler doesn't handle this NOTIFY, try next handler
						if Globals.Debug {
							log.Printf("DnsHandler: NOTIFY handler returned ErrNotHandled, trying next handler")
						}
						continue
					} else {
						// Handler attempted to handle but failed
						log.Printf("DnsHandler: NOTIFY handler error: %v", err)
						// Continue to next handler or fall back to default
						continue
					}
				}
				
				if handled {
					return // NOTIFY was handled by a registered handler
				}
				// All handlers returned ErrNotHandled, fall through to default handler
				if Globals.Debug {
					log.Printf("DnsHandler: All registered NOTIFY handlers returned ErrNotHandled, falling back to channel-based handler")
				}
			}
			
			// Backward compatibility: If DnsNotifyQ channel is provided, route NOTIFYs there
			// (This is the old way, kept for backward compatibility)
			if dnsnotifyq != nil {
				log.Printf("DnsHandler: qname: %s opcode: %s (%d) DO: %v. len(dnsnotifyq): %d", qname, dns.OpcodeToString[r.Opcode], r.Opcode, msgoptions.DO, len(dnsnotifyq))
				// A DNS NOTIFY may trigger time consuming outbound queries
				dnsnotifyq <- DnsNotifyRequest{ResponseWriter: w, Msg: r, Qname: qname, Options: msgoptions}
				// Not waiting for a result
				return
			}
			
			// No handlers and no channel - send error response
			m := new(dns.Msg)
			m.SetReply(r)
			m.SetRcode(r, dns.RcodeNotImplemented)
			w.WriteMsg(m)
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
			qtype := r.Question[0].Qtype
			
			// Check for registered query handlers (new registration API)
			handlers := getQueryHandlers(conf, qtype)
			if len(handlers) > 0 {
				// Try registered handlers
				handled := false
				for _, handler := range handlers {
					dqr := DnsQueryRequest{
						ResponseWriter: w,
						Msg:            r,
						Qname:          qname,
						Qtype:          qtype,
						Options:        msgoptions,
					}
					
					err := handler(ctx, &dqr)
					if err == nil {
						// Handler successfully handled the query
						handled = true
						if Globals.Debug {
							log.Printf("DnsHandler: Query handled by registered handler (qname=%s, qtype=%s)", qname, dns.TypeToString[qtype])
						}
						return
					} else if err == ErrNotHandled {
						// Handler doesn't handle this query, try next handler
						if Globals.Debug {
							log.Printf("DnsHandler: Handler returned ErrNotHandled, trying next handler")
						}
						continue
					} else {
						// Handler attempted to handle but failed
						log.Printf("DnsHandler: Query handler error: %v", err)
						// Continue to next handler or fall back to default
						continue
					}
				}
				
				if handled {
					return // Query was handled by a registered handler
				}
				// All handlers returned ErrNotHandled, fall through to default handler
				if Globals.Debug {
					log.Printf("DnsHandler: All registered handlers returned ErrNotHandled, falling back to default handler")
				}
			}
			
			// Backward compatibility: If DnsQueryQ channel is provided, route queries there
			// (This is the old way, kept for backward compatibility)
			if dnsqueryq != nil {
				if Globals.Debug {
					log.Printf("DnsHandler: Routing QUERY to dnsqueryq channel (qname=%s, qtype=%s, channel_len=%d)", qname, dns.TypeToString[qtype], len(dnsqueryq))
				}
				log.Printf("DnsHandler: qname: %s opcode: %s (%d) DO: %v. Routing to dnsqueryq channel", qname, dns.OpcodeToString[r.Opcode], r.Opcode, msgoptions.DO)
				// A DNS Query may trigger time consuming processing
				select {
				case dnsqueryq <- DnsQueryRequest{
					ResponseWriter: w,
					Msg:            r,
					Qname:          qname,
					Qtype:          qtype,
					Options:        msgoptions,
				}:
					if Globals.Debug {
						log.Printf("DnsHandler: Successfully sent query to dnsqueryq channel")
					}
				default:
					log.Printf("DnsHandler: ERROR: dnsqueryq channel is full! Dropping query")
				}
				// Not waiting for a result
				return
			}
			
			// Fall through to existing direct QueryResponder call (default zone-based handler)
			log.Printf("DnsHandler: qname: %s opcode: %s (%d) DO: %v", qname, dns.OpcodeToString[r.Opcode], r.Opcode, msgoptions.DO)
			// qtype already declared above
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
