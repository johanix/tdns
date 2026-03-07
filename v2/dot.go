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
	"github.com/spf13/viper"
)

func DnsDoTEngine(ctx context.Context, conf *Config, dotaddrs []string, cert *tls.Certificate,
	ourDNSHandler func(w dns.ResponseWriter, r *dns.Msg)) error {

	if cert == nil {
		return fmt.Errorf("DnsDoTEngine:DoT certificate is not set")
	}

	lgDns.Info("DnsEngine: DoT addresses", "addrs", dotaddrs)
	// tlsConfig := DoTTLSConfig(certFile, keyFile)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS13, // or TLS12 if you need broader support
		// ClientAuth: tls.NoClientCert, // optional: change if you want client certs
		NextProtos: []string{"dot"}, // important for DoT
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

	ports := viper.GetStringSlice("dnsengine.ports.dot")
	if len(ports) == 0 {
		ports = []string{"853"}
	}
	var servers []*dns.Server
	for _, addr := range dotaddrs {
		for _, port := range ports {
			hostport := net.JoinHostPort(addr, port)
			server := &dns.Server{
				Addr:          hostport,
				Net:           "tcp-tls",
				TLSConfig:     tlsConfig,
				MsgAcceptFunc: MsgAcceptFunc, // We need a tweaked version for DNS UPDATE
				Handler:       dns.HandlerFunc(loggingHandler),
			}
			servers = append(servers, server)
			go func(srv *dns.Server, hp string) {
				lgDns.Info("DnsEngine: serving on DoT", "hostport", hp)
				if err := srv.ListenAndServe(); err != nil {
					lgDns.Error("failed to setup DoT server", "hostport", hp, "err", err)
				} else {
					lgDns.Info("DnsEngine: listening on DoT", "hostport", hp)
				}
			}(server, hostport)
		}
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
