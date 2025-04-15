/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"crypto/tls"
	"log"
	"net"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

func DnsDoTEngine(conf *Config, dotaddrs []string, cert *tls.Certificate,
	ourDNSHandler func(w dns.ResponseWriter, r *dns.Msg)) error {

	log.Printf("DnsEngine: DoT addresses: %v", dotaddrs)
	// tlsConfig := DoTTLSConfig(certFile, keyFile)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS13, // or TLS12 if you need broader support
		// ClientAuth: tls.NoClientCert, // optional: change if you want client certs
		NextProtos: []string{"dot"}, // important for DoT
	}

	for _, addr := range dotaddrs {
		hostport := net.JoinHostPort(addr, "853") // At the moment, we only support port 853
		server := &dns.Server{
			Addr:          hostport,
			Net:           "tcp-tls",
			TLSConfig:     tlsConfig,
			MsgAcceptFunc: MsgAcceptFunc, // We need a tweaked version for DNS UPDATE
			Handler:       dns.HandlerFunc(ourDNSHandler),
		}
		go func(addr string) {
			log.Printf("DnsEngine: serving on %s (DoT)\n", hostport)
			if err := server.ListenAndServe(); err != nil {
				log.Printf("Failed to setup the DoT server on %s: %s", hostport, err.Error())
			} else {
				log.Printf("DnsEngine: listening on %s/DoT", hostport)
			}
		}(addr)
	}
	return nil
}

func xxxDoTTLSConfig(certFile, keyFile string) *tls.Config {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("failed to load TLS cert/key: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13, // or TLS12 if you need broader support
		// ClientAuth: tls.NoClientCert, // optional: change if you want client certs
		NextProtos: []string{"dot"}, // important for DoT
	}
}
