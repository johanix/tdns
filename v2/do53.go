/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/johanix/tdns/v2/notifyerrors"
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
	lgDns.Info("DnsEngine: starting", "addresses", conf.DnsEngine.Addresses)
	lgDns.Debug("DnsEngine: channel status",
		"DnsQueryQ_nil", conf.Internal.DnsQueryQ == nil,
		"DnsNotifyQ_nil", conf.Internal.DnsNotifyQ == nil,
		"DnsUpdateQ_nil", conf.Internal.DnsUpdateQ == nil)

	// verbose := viper.GetBool("dnsengine.verbose")
	// debug := viper.GetBool("dnsengine.debug")
	authDNSHandler := createAuthDnsHandler(ctx, conf)

	// Create a local ServeMux for DnsEngine to avoid conflicts with other engines
	dnsMux := dns.NewServeMux()
	dnsMux.HandleFunc(".", authDNSHandler)

	addresses := conf.DnsEngine.Addresses
	if !CaseFoldContains(conf.DnsEngine.Transports, "do53") {
		lgDns.Warn("DnsEngine: Do53 transport (UDP/TCP) NOT specified but mandatory, still configuring", "addresses", addresses)
	}
	lgDns.Info("DnsEngine: UDP/TCP addresses configured", "addresses", addresses)
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
				lgDns.Debug("DnsEngine: attempting to bind", "addr", addr, "transport", transport)
				// Announce we're attempting to listen. This does not mean we're listening yet.
				lgDns.Info("DnsEngine: launching server", "addr", addr, "transport", transport)
				if err := s.ListenAndServe(); err != nil {
					// ListenAndServe only returns on error or shutdown.
					lgDns.Error("DnsEngine: server failed to start or stopped unexpectedly", "addr", addr, "transport", transport, "err", err)
				} else {
					// This case is basically never reached unless shutdown is very clean.
					lgDns.Debug("DnsEngine: server exited normally", "addr", addr, "transport", transport)
				}
			}(srv, addr, transport)
		}
	}

	// Graceful shutdown on context cancellation
	go func() {
		<-ctx.Done()
		lgDns.Info("DnsEngine: shutting down Do53 servers...")
		for _, s := range servers {
			done := make(chan struct{})
			go func(srv *dns.Server) {
				if err := srv.Shutdown(); err != nil {
					lgDns.Warn("DnsEngine: error shutting down Do53 server", "addr", srv.Addr, "net", srv.Net, "err", err)
				}
				close(done)
			}(s)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				lgDns.Warn("DnsEngine: timeout shutting down server, continuing", "addr", s.Addr, "net", s.Net)
			}
		}
	}()

	certFile := viper.GetString("dnsengine.certfile")
	keyFile := viper.GetString("dnsengine.keyfile")
	certKey := true

	if certFile == "" || keyFile == "" {
		lgDns.Info("DnsEngine: no certificate file or key file provided. Not starting DoT, DoH or DoQ service.")
		certKey = false
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		lgDns.Info("DnsEngine: certificate file does not exist. Not starting DoT, DoH or DoQ service.", "file", certFile)
		certKey = false
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		lgDns.Info("DnsEngine: key file does not exist. Not starting DoT, DoH or DoQ service.", "file", keyFile)
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
			lgDns.Error("DnsEngine: failed to load certificate, not starting DoT/DoH/DoQ service", "err", err)
			certKey = false
		}

		// Check certificate expiry at startup
		if certKey && len(cert.Certificate) > 0 {
			x509Cert, parseErr := x509.ParseCertificate(cert.Certificate[0])
			if parseErr != nil {
				lgDns.Warn("DnsEngine: failed to parse certificate for expiry check", "err", parseErr)
			} else {
				now := time.Now()
				if now.After(x509Cert.NotAfter) {
					lgDns.Error("DnsEngine: TLS certificate has EXPIRED", "expiry", x509Cert.NotAfter, "file", certFile)
				} else if x509Cert.NotAfter.Sub(now) < 30*24*time.Hour {
					lgDns.Warn("DnsEngine: TLS certificate expires within 30 days", "expiry", x509Cert.NotAfter, "remaining", x509Cert.NotAfter.Sub(now).Round(time.Hour), "file", certFile)
				} else {
					lgDns.Info("DnsEngine: TLS certificate expiry check passed", "expiry", x509Cert.NotAfter, "file", certFile)
				}
			}
		}

		// Strip port numbers from addresses before proceeding to modern transports
		tmp := make([]string, len(addresses))
		for i, addr := range addresses {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				lgDns.Error("Failed to parse address", "addr", addr, "err", err)
				tmp[i] = addr // Keep original if parsing fails
			} else {
				tmp[i] = host
			}
		}
		addresses = tmp

		if CaseFoldContains(conf.DnsEngine.Transports, "dot") {
			err := DnsDoTEngine(ctx, conf, addresses, &cert, authDNSHandler)
			if err != nil {
				lgDns.Error("Failed to setup the DoT server", "err", err)
			}
		}

		if CaseFoldContains(conf.DnsEngine.Transports, "doh") {
			err := DnsDoHEngine(ctx, conf, addresses, certFile, keyFile, authDNSHandler)
			if err != nil {
				lgDns.Error("Failed to setup the DoH server", "err", err)
			}
		}

		if CaseFoldContains(conf.DnsEngine.Transports, "doq") {
			err := DnsDoQEngine(ctx, conf, addresses, &cert, authDNSHandler)
			if err != nil {
				lgDns.Error("Failed to setup the DoQ server", "err", err)
			}
		}
	}
	return nil
}

func createAuthDnsHandler(ctx context.Context, conf *Config) func(w dns.ResponseWriter, r *dns.Msg) {
	dnsupdateq := conf.Internal.DnsUpdateQ
	dnsnotifyq := conf.Internal.DnsNotifyQ
	dnsqueryq := conf.Internal.DnsQueryQ // NOTE: Only used by original tdns-kdc (before repo split). New dzm/tdns-kdc uses RegisterQueryHandler.

	return func(w dns.ResponseWriter, r *dns.Msg) {
		lgDns.Debug("DnsHandler: received DNS message", "remoteaddr", w.RemoteAddr(),
			"id", r.MsgHdr.Id, "opcode", dns.OpcodeToString[r.Opcode],
			"questions", len(r.Question), "additional", len(r.Extra))

		if len(r.Question) == 0 {
			lgDns.Warn("DnsHandler: received message with no question section", "remoteaddr", w.RemoteAddr())
			resp := new(dns.Msg)
			resp.SetRcode(r, dns.RcodeFormatError)
			w.WriteMsg(resp)
			return
		}

		qname := r.Question[0].Name
		// var dnssec_ok, ots_opt_in, ots_opt_out bool
		msgoptions, err := edns0.ExtractFlagsAndEDNS0Options(r)
		if err != nil {
			lgDns.Error("Error extracting EDNS0 options", "err", err)
		}
		lgDns.Debug("DnsHandler: EDNS0 DO bit", "do", msgoptions.DO)

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
						lgDns.Debug("DnsHandler: NOTIFY handled by registered handler", "qname", qname, "qtype", dns.TypeToString[qtype])
						return
					}
					if errors.Is(err, notifyerrors.ErrNotifyHandlerErrorResponse) {
						// Handler sent an error response (e.g. decryption failed); do not try next handler
						handled = true
						lgDns.Warn("DnsHandler: NOTIFY handler responded with error", "qname", qname, "qtype", dns.TypeToString[qtype])
						return
					}
					if err == ErrNotHandled {
						// Handler doesn't handle this NOTIFY, try next handler
						lgDns.Debug("DnsHandler: NOTIFY handler returned ErrNotHandled, trying next handler")
						continue
					} else {
						// Handler attempted to handle but failed
						lgDns.Error("DnsHandler: NOTIFY handler error", "err", err)
						// Continue to next handler or fall back to default
						continue
					}
				}

				if handled {
					return // NOTIFY was handled by a registered handler
				}
				// All handlers returned ErrNotHandled, fall through to default handler
				lgDns.Debug("DnsHandler: all registered NOTIFY handlers returned ErrNotHandled, falling back to channel-based handler")
			}

			// Backward compatibility: If DnsNotifyQ channel is provided, route NOTIFYs there
			// (This is the old way, kept for backward compatibility)
			if dnsnotifyq != nil {
				lgDns.Debug("DnsHandler: routing NOTIFY to dnsnotifyq channel",
					"qname", qname, "opcode", dns.OpcodeToString[r.Opcode],
					"do", msgoptions.DO, "channellen", len(dnsnotifyq))
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
			lgDns.Debug("DnsHandler: received UPDATE",
				"qname", qname, "opcode", dns.OpcodeToString[r.Opcode],
				"do", msgoptions.DO, "channellen", len(dnsupdateq))

			// Create DnsUpdateRequest for handler matching
			dur := DnsUpdateRequest{
				ResponseWriter: w,
				Msg:            r,
				Qname:          qname,
				Options:        msgoptions,
				Status:         &UpdateStatus{},
			}

			// Check for registered UPDATE handlers (new registration API)
			handlers := getUpdateHandlers(conf, &dur)
			if len(handlers) > 0 {
				// Try registered handlers
				handled := false
				for _, handler := range handlers {
					err := handler(ctx, &dur)
					if err == nil {
						// Handler successfully handled the UPDATE
						handled = true
						lgDns.Debug("DnsHandler: UPDATE handled by registered handler", "qname", qname)
						return
					} else if err == ErrNotHandled {
						// Handler doesn't handle this UPDATE, try next handler
						lgDns.Debug("DnsHandler: UPDATE handler returned ErrNotHandled, trying next handler")
						continue
					} else {
						// Handler attempted to handle but encountered an error
						lgDns.Error("DnsHandler: UPDATE handler error", "err", err)
						// Continue to next handler or fall through to default
						continue
					}
				}

				if handled {
					return // UPDATE was handled by a registered handler
				}
				// All handlers returned ErrNotHandled, fall through to default handler
				lgDns.Debug("DnsHandler: all registered UPDATE handlers returned ErrNotHandled, falling back to channel-based handler")
			}

			// Backward compatibility: If DnsUpdateQ channel is provided, route UPDATEs there
			// (This is the old way, kept for backward compatibility)
			if dnsupdateq != nil {
				// A DNS Update may trigger time consuming outbound queries
				dnsupdateq <- dur
				// Not waiting for a result
				return
			}

			// No handlers and no channel - send error response
			m := new(dns.Msg)
			m.SetReply(r)
			m.SetRcode(r, dns.RcodeNotImplemented)
			w.WriteMsg(m)
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
						lgDns.Debug("DnsHandler: query handled by registered handler", "qname", qname, "qtype", dns.TypeToString[qtype])
						return
					} else if err == ErrNotHandled {
						// Handler doesn't handle this query, try next handler
						lgDns.Debug("DnsHandler: handler returned ErrNotHandled, trying next handler")
						continue
					} else {
						// Handler attempted to handle but failed
						lgDns.Error("DnsHandler: Query handler error", "err", err)
						// Continue to next handler or fall back to default
						continue
					}
				}

				if handled {
					return // Query was handled by a registered handler
				}
				// All handlers returned ErrNotHandled, fall through to default handler
				lgDns.Debug("DnsHandler: all registered handlers returned ErrNotHandled, falling back to default handler")
			}

			// Backward compatibility: If DnsQueryQ channel is provided, route queries there
			// NOTE: This is only used by the original tdns-kdc (before repo split to dzm).
			// The new dzm/tdns-kdc uses RegisterQueryHandler instead.
			// (This is the old way, kept for backward compatibility with tdns/tdns/kdc_init.go)
			if dnsqueryq != nil {
				lgDns.Debug("DnsHandler: routing QUERY to dnsqueryq channel", "qname", qname, "qtype", dns.TypeToString[qtype], "channellen", len(dnsqueryq))
				lgDns.Debug("DnsHandler: routing to dnsqueryq channel",
					"qname", qname, "opcode", dns.OpcodeToString[r.Opcode], "do", msgoptions.DO)
				// A DNS Query may trigger time consuming processing
				select {
				case dnsqueryq <- DnsQueryRequest{
					ResponseWriter: w,
					Msg:            r,
					Qname:          qname,
					Qtype:          qtype,
					Options:        msgoptions,
				}:
					lgDns.Debug("DnsHandler: successfully sent query to dnsqueryq channel")
				default:
					lgDns.Error("DnsHandler: ERROR: dnsqueryq channel is full! Dropping query")
				}
				// Not waiting for a result
				return
			}

			// All registered handlers (including default handlers) returned ErrNotHandled
			// Before returning REFUSED, check for .server. queries (standard DNS server identification)
			qnameLower := strings.ToLower(qname)
			if strings.HasSuffix(qnameLower, ".server.") && r.Question[0].Qclass == dns.ClassCHAOS {
				lgDns.Debug("DnsHandler: likely a .server CH query", "qname", qnameLower)
				DotServerQnameResponse(qnameLower, w, r)
				return
			}

			// No handler processed the query, return REFUSED
			lgDns.Info("DnsHandler: no handler processed query, returning REFUSED",
				"qname", qname, "qtype", dns.TypeToString[qtype])
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeRefused)
			w.WriteMsg(m)
			return

		default:
			lgDns.Error("Error: unable to handle msgs of type", "type", dns.OpcodeToString[r.Opcode])
		}
	}
}
