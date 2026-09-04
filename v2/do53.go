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
	lgDns.Info("DnsEngine: starting", "addresses", conf.Listeners.Addresses)
	lgDns.Debug("DnsEngine: channel status",
		"DnsQueryQ_nil", conf.Internal.DnsQueryQ == nil,
		"DnsNotifyQ_nil", conf.Internal.DnsNotifyQ == nil,
		"DnsUpdateQ_nil", conf.Internal.DnsUpdateQ == nil)

	authDNSHandler := createAuthDnsHandler(ctx, conf)

	// Create a local ServeMux for DnsEngine to avoid conflicts with other engines
	dnsMux := dns.NewServeMux()
	// TsigSigningHandler is installed here, on the Do53 mux, because the Do53
	// servers below carry a TsigProvider (needed to MAC the response). DoH/DoQ
	// receive the unwrapped authDNSHandler; DoT installs the wrapper itself in
	// DnsDoTEngine, since it also carries a TsigProvider.
	// udpTruncate sits inside TsigSigningHandler so TSIG MACs the truncated wire.
	dnsMux.HandleFunc(".", TsigSigningHandler(udpTruncate(authDNSHandler)))

	addresses := conf.Listeners.Addresses
	if !CaseFoldContains(conf.Listeners.Transports, "do53") {
		lgDns.Warn("DnsEngine: Do53 transport (UDP/TCP) NOT specified but mandatory, still configuring", "addresses", addresses)
	}
	lgDns.Info("DnsEngine: UDP/TCP addresses configured", "addresses", addresses)
	var servers []*dns.Server

	// How many UDP sockets to open per listen address.
	//
	// miekg/dns serves each socket from a single goroutine: serveUDP() does one
	// ReadUDP() at a time and only hands the *handling* off to new goroutines.
	// Reception is therefore serialised per socket, and that socket becomes the
	// ceiling long before the CPU does -- the kernel drops arriving datagrams
	// into the socket buffer while cores sit idle.
	//
	// Several sockets in one kernel load-balance group give the kernel that
	// many receive queues to spread arriving datagrams over, each with its own
	// buffer and wakeup, and each sender pinned to one reader. Which socket
	// option provides this differs per platform; see reuseport.go.
	//
	// Platforms without such an option serve from a single socket regardless
	// of this setting: listenUDPSockets falls back and reports why. There, use
	// several listen addresses instead, which gives one socket each.
	udpSockets := conf.Listeners.UDPSockets
	if udpSockets < 1 {
		udpSockets = 1
	}

	for _, addr := range addresses {
		// Cancelled between addresses: stop, rather than launching listeners
		// for the rest of the list. Checked at the TOP because TCP starts
		// before UDP below, so a check further down would still have launched
		// a TCP server for this address on the way past.
		if ctx.Err() != nil {
			lgDns.Debug("DnsEngine: shutting down, not binding further addresses", "remaining_from", addr)
			break
		}

		// ---- TCP: one server per address.
		tcpSrv := &dns.Server{
			Addr:          addr,
			Net:           "tcp",
			Handler:       dnsMux,
			MsgAcceptFunc: MsgAcceptFunc,
			TsigProvider:  conf.tsigProvider(),
		}
		tcpSrv.UDPSize = dns.DefaultMsgSize
		servers = append(servers, tcpSrv)
		go func(s *dns.Server, addr string) {
			lgDns.Info("DnsEngine: launching server", "addr", addr, "transport", "tcp")
			if err := s.ListenAndServe(); err != nil {
				lgDns.Error("DnsEngine: server failed to start or stopped unexpectedly", "addr", addr, "transport", "tcp", "err", err)
				if ctx.Err() == nil {
					conf.Internal.ServerErrors.SetTransportPortError(addr+"/tcp", err)
				}
			}
		}(tcpSrv, addr)

		// ---- UDP: one or more sockets, load-balanced by the kernel where
		// the platform supports it.
		lst, err := listenUDPSockets(ctx, addr, udpSockets)
		if err != nil {
			// Cancellation is not a bind failure: it is the daemon going down
			// while we were opening sockets. Reporting it as a transport error
			// would put a lie in the server-error table on the way out, and
			// carrying on to the next address would start listeners nobody
			// will serve from.
			if ctx.Err() != nil {
				lgDns.Debug("DnsEngine: UDP bind cancelled by shutdown", "addr", addr)
				break
			}
			lgDns.Error("DnsEngine: failed to bind UDP socket", "addr", addr, "err", err)
			conf.Internal.ServerErrors.SetTransportPortError(addr+"/udp", err)
			continue
		}
		if lst.Degraded != nil {
			lgDns.Warn("DnsEngine: serving UDP from fewer sockets than configured",
				"addr", addr, "requested", udpSockets, "opened", len(lst.Conns),
				"reason", lst.Degraded)
		}
		for i, pc := range lst.Conns {
			srv := &dns.Server{
				PacketConn:    pc,
				Handler:       dnsMux,
				MsgAcceptFunc: MsgAcceptFunc,
				TsigProvider:  conf.tsigProvider(),
			}
			srv.UDPSize = dns.DefaultMsgSize
			servers = append(servers, srv)
			go func(s *dns.Server, addr string, idx int) {
				if err := s.ActivateAndServe(); err != nil {
					if ctx.Err() == nil {
						lgDns.Error("DnsEngine: udp socket stopped unexpectedly", "addr", addr, "socket", idx, "err", err)
						conf.Internal.ServerErrors.SetTransportPortError(addr+"/udp", err)
					}
				}
			}(srv, addr, i)
		}
		lgDns.Info("DnsEngine: launching server", "addr", addr, "transport", "udp",
			"sockets", len(lst.Conns), "kernel-balanced", lst.Balanced)
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

	certFile := conf.Listeners.CertFile
	keyFile := conf.Listeners.KeyFile
	certKey := true
	certReason := ""

	// Mutually exclusive: an empty certFile/keyFile makes os.Stat("") return
	// ENOENT (satisfies os.IsNotExist), so without the else-if the later
	// blocks would run too and overwrite the accurate "not configured"
	// reason with a misleading "keyfile  does not exist" (empty filename),
	// besides the redundant stats/logs.
	if certFile == "" || keyFile == "" {
		lgDns.Info("DnsEngine: no certificate file or key file provided. Not starting DoT, DoH or DoQ service.")
		certKey = false
		certReason = "certfile/keyfile not configured"
	} else if _, err := os.Stat(certFile); err != nil {
		// Any stat failure (missing, permission, not-a-directory, …) disables
		// encrypted transports AND is recorded, so `config status` sees it —
		// not only os.IsNotExist.
		lgDns.Info("DnsEngine: certificate file not accessible. Not starting DoT, DoH or DoQ service.", "file", certFile, "err", err)
		certKey = false
		if os.IsNotExist(err) {
			certReason = fmt.Sprintf("certfile %s does not exist", certFile)
		} else {
			certReason = fmt.Sprintf("certfile %s not accessible: %v", certFile, err)
		}
	} else if _, err := os.Stat(keyFile); err != nil {
		lgDns.Info("DnsEngine: key file not accessible. Not starting DoT, DoH or DoQ service.", "file", keyFile, "err", err)
		certKey = false
		if os.IsNotExist(err) {
			certReason = fmt.Sprintf("keyfile %s does not exist", keyFile)
		} else {
			certReason = fmt.Sprintf("keyfile %s not accessible: %v", keyFile, err)
		}
	}

	var certPEM []byte
	var keyPEM []byte
	var cert tls.Certificate
	var err error

	if certKey {
		// A cert/key access failure (unreadable file, a directory, a race
		// after the stat above, …) is non-fatal, exactly like a missing file:
		// disable encrypted transports and record certReason so `config status`
		// reports it (via SetTransportCertError below), rather than aborting the
		// whole DnsEngine and taking Do53 down with it.
		if certPEM, err = os.ReadFile(certFile); err != nil {
			lgDns.Error("DnsEngine: error reading cert file, not starting DoT/DoH/DoQ service", "file", certFile, "err", err)
			certKey = false
			certReason = fmt.Sprintf("reading certfile %s: %v", certFile, err)
		} else if keyPEM, err = os.ReadFile(keyFile); err != nil {
			lgDns.Error("DnsEngine: error reading key file, not starting DoT/DoH/DoQ service", "file", keyFile, "err", err)
			certKey = false
			certReason = fmt.Sprintf("reading keyfile %s: %v", keyFile, err)
		} else {
			conf.Internal.CertData = string(certPEM)
			conf.Internal.KeyData = string(keyPEM)

			// Parse from the bytes already read, not LoadX509KeyPair(file,file):
			// re-reading the files could parse a cert that no longer matches the
			// CertData/KeyData captured above if the files changed in between.
			if cert, err = tls.X509KeyPair(certPEM, keyPEM); err != nil {
				lgDns.Error("DnsEngine: failed to load certificate, not starting DoT/DoH/DoQ service", "err", err)
				certKey = false
				certReason = fmt.Sprintf("loading certfile/keyfile: %v", err)
			}
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
				// XoT chain-presentation note: LoadX509KeyPair presents every
				// CERTIFICATE block in certfile. The condition below fires for a
				// single certificate that is NOT a self-signed CA — i.e. a leaf,
				// whether CA-signed (cert init, two-tier PKI) or self-signed. A
				// self-signed CA root (the mwe default) is exempt: CheckSignature-
				// From(self) succeeds for it, so no note. Info, not Warn: presenting
				// a single leaf is fine when peers trust it (or its issuing CA)
				// directly; it only breaks if the leaf was issued via CA
				// intermediates that were not bundled. Rewording avoids calling a
				// self-signed leaf "CA-signed".
				if parseErr == nil && len(cert.Certificate) == 1 && x509Cert.CheckSignatureFrom(x509Cert) != nil {
					lgDns.Info("DnsEngine: certfile holds a single leaf certificate (no chain bundled) — fine when peers trust it, or its issuing CA, directly; but if it was issued via CA intermediates, bundle them into certfile (leaf first) or secondaries will fail chain building", "file", certFile)
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

		if CaseFoldContains(conf.Listeners.Transports, "dot") {
			err := DnsDoTEngine(ctx, conf, addresses, portStrings(conf.Listeners.Ports.DoT), &cert, authDNSHandler, true)
			if err != nil {
				lgDns.Error("Failed to setup the DoT server", "err", err)
			}
		}

		if CaseFoldContains(conf.Listeners.Transports, "doh") {
			err := DnsDoHEngine(ctx, conf, addresses, portStrings(conf.Listeners.Ports.DoH), certFile, keyFile, authDNSHandler)
			if err != nil {
				lgDns.Error("Failed to setup the DoH server", "err", err)
			}
		}

		if CaseFoldContains(conf.Listeners.Transports, "doq") {
			err := DnsDoQEngine(ctx, conf, addresses, portStrings(conf.Listeners.Ports.DoQ), &cert, authDNSHandler)
			if err != nil {
				lgDns.Error("Failed to setup the DoQ server", "err", err)
			}
		}
	}
	// Transport/Cert: encrypted transports are configured but the cert/key
	// could not be loaded, so those listeners did not start (owned here,
	// boot-scoped — clears on a fresh start with a working cert).
	if !certKey && anyEncryptedTransport(conf.Listeners.Transports) {
		conf.Internal.ServerErrors.SetTransportCertError(certReason)
	}
	return nil
}

func createAuthDnsHandler(ctx context.Context, conf *Config) func(w dns.ResponseWriter, r *dns.Msg) {
	dnsupdateq := conf.Internal.DnsUpdateQ
	dnsnotifyq := conf.Internal.DnsNotifyQ
	dnsqueryq := conf.Internal.DnsQueryQ // NOTE: Only used by original tdns-kdc (before repo split). New dzm/tdns-kdc uses RegisterQueryHandler.

	return func(w dns.ResponseWriter, r *dns.Msg) {
		// Defensive: catch any panic in the auth-side DNS handler chain so
		// a bug in zone lookup, signing, IMR delegation, etc. returns
		// SERVFAIL to the client instead of crashing the process. tdns-auth
		// + tdns-mp both reach this handler from a per-connection
		// goroutine, and an unrecovered panic in any handler chain takes
		// down the entire server. ns1.p.axfr.net crashed exactly this way
		// when the IMR's nil-resp deref propagated up.
		defer func() {
			if rec := recover(); rec != nil {
				qname := ""
				if r != nil && len(r.Question) > 0 {
					qname = r.Question[0].Name
				}
				lgDns.Error("DnsHandler: PANIC recovered — returning SERVFAIL",
					"qname", qname, "remoteaddr", w.RemoteAddr(),
					"panic", fmt.Sprintf("%v", rec))
				// Best-effort SERVFAIL. If w is already broken / written, ignore.
				defer func() { _ = recover() }()
				resp := new(dns.Msg)
				resp.SetRcode(r, dns.RcodeServerFailure)
				_ = w.WriteMsg(resp)
			}
		}()

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
