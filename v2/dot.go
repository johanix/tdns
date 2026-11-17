/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

// DnsDoTEngine starts the DoT listeners. requestClientCert is true for the
// auth listener — it REQUESTS (never requires) a client certificate so the
// per-zone downstream-auth check at transfer time can see one when the
// downstream has it; cert-less clients are unaffected. The IMR's DoT front
// end passes false and never requests certificates.
func DnsDoTEngine(ctx context.Context, conf *Config, dotaddrs, ports []string, cert *tls.Certificate,
	ourDNSHandler func(w dns.ResponseWriter, r *dns.Msg), requestClientCert bool) error {

	if cert == nil {
		return fmt.Errorf("DnsDoTEngine:DoT certificate is not set")
	}

	lgDns.Info("DnsEngine: DoT addresses", "addrs", dotaddrs)

	tlsConfig, err := ServerTLSConfigForDoT(conf, cert, requestClientCert)
	if err != nil {
		return fmt.Errorf("DnsDoTEngine: %v", err)
	}

	// Wrap the DNS handler to add logging
	loggingHandler := func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 0 {
			lgDns.Warn("DoT: received message with no question section", "remote", w.RemoteAddr())
			resp := new(dns.Msg)
			resp.SetRcode(r, dns.RcodeFormatError)
			w.WriteMsg(resp)
			return
		}
		lgDns.Debug("DoT: received message", "opcode", dns.OpcodeToString[r.Opcode], "qname", r.Question[0].Name, "rrtype", dns.TypeToString[r.Question[0].Qtype])
		ourDNSHandler(w, r)
	}

	// ports comes from the caller's listeners: block — the engine is shared
	// between apps and must not reach into any app's config (#444/#446).
	if len(ports) == 0 {
		ports = []string{"853"}
	}
	// Each listener binds here, before the engine returns, so a caller
	// knows whether DoT came up: one that bound in its goroutine could fail
	// after the engine had reported success (debug-do53-queries-refused
	// stops the server when no encrypted transport came up).
	var servers []*dns.Server
	for _, addr := range dotaddrs {
		for _, port := range ports {
			hostport := net.JoinHostPort(addr, port)
			ln, err := tls.Listen("tcp", hostport, tlsConfig)
			if err != nil {
				lgDns.Error("failed to setup DoT listener", "hostport", hostport, "err", err)
				if ctx.Err() == nil {
					conf.Internal.ServerErrors.SetTransportPortError("dot "+hostport, err)
				}
				continue
			}
			server := &dns.Server{
				Addr:          hostport,
				Listener:      ln,
				Net:           "tcp-tls",
				TLSConfig:     tlsConfig,
				MsgAcceptFunc: MsgAcceptFunc, // We need a tweaked version for DNS UPDATE
				// TSIG parity with Do53: verify inbound TSIG and sign responses
				// to validated TSIG-signed requests (RFC 8945). Safe here because
				// this is a real miekg dns.Server (unlike the DoH/DoQ custom
				// writers); TsigSigningHandler needs the provider to MAC the reply.
				TsigProvider: conf.tsigProvider(),
				Handler:      dns.HandlerFunc(TsigSigningHandler(loggingHandler)),
			}
			servers = append(servers, server)
			go func(srv *dns.Server, hp string) {
				lgDns.Info("DnsEngine: serving on DoT", "hostport", hp)
				if err := srv.ActivateAndServe(); err != nil && ctx.Err() == nil {
					lgDns.Error("DoT server stopped unexpectedly", "hostport", hp, "err", err)
					conf.Internal.ServerErrors.SetTransportPortError("dot "+hp, err)
				}
			}(server, hostport)
		}
	}
	// Every listener failed, each with its own error recorded above.
	if len(servers) == 0 {
		return fmt.Errorf("DnsDoTEngine: no DoT listener could be set up on %v, ports %v", dotaddrs, ports)
	}
	go func() {
		<-ctx.Done()
		lgDns.Info("DnsDoTEngine: shutting down DoT servers")
		for _, s := range servers {
			done := make(chan struct{})
			go func(srv *dns.Server) {
				if err := srv.Shutdown(); err != nil {
					lgDns.Warn("DnsDoTEngine: error shutting down DoT server", "addr", srv.Addr, "err", err)
				}
				close(done)
			}(s)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				lgDns.Warn("DnsDoTEngine: timeout shutting down server, continuing", "addr", s.Addr)
			}
		}
	}()
	return nil
}
