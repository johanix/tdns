/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func DnsDoTEngine(conf *Config, dotaddrs []string, cert *tls.Certificate,
	ourDNSHandler func(w dns.ResponseWriter, r *dns.Msg)) error {

	if cert == nil {
		return fmt.Errorf("DnsDoTEngine:DoT certificate is not set")
	}

	log.Printf("DnsEngine: DoT addresses: %v", dotaddrs)
	// tlsConfig := DoTTLSConfig(certFile, keyFile)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS13, // or TLS12 if you need broader support
		// ClientAuth: tls.NoClientCert, // optional: change if you want client certs
		NextProtos: []string{"dot"}, // important for DoT
	}

	ports := viper.GetStringSlice("dnsengine.ports.dot")
	if len(ports) == 0 {
		ports = []string{"853"}
	}
	for _, addr := range dotaddrs {
		for _, port := range ports {
			hostport := net.JoinHostPort(addr, port)
			server := &dns.Server{
				Addr:          hostport,
				Net:           "tcp-tls",
				TLSConfig:     tlsConfig,
				MsgAcceptFunc: MsgAcceptFunc, // We need a tweaked version for DNS UPDATE
				Handler:       dns.HandlerFunc(ourDNSHandler),
			}
			go func() {
				log.Printf("DnsEngine: serving on %s (DoT)\n", hostport)
				if err := server.ListenAndServe(); err != nil {
					log.Printf("Failed to setup the DoT server on %s: %s", hostport, err.Error())
				} else {
					log.Printf("DnsEngine: listening on %s/DoT", hostport)
				}
			}()
		}
	}
	return nil
}
