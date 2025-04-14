/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func DnsDoTEngine(conf *Config, dotaddrs []string,
	ourDNSHandler func(w dns.ResponseWriter, r *dns.Msg)) error {
	certFile := viper.GetString("dnsengine.dot.certfile")
	keyFile := viper.GetString("dnsengine.dot.keyfile")

	if certFile == "" || keyFile == "" {
		log.Println("DnSDoTEngine: no certificate file or key file provided. Not starting.")
		return fmt.Errorf("no certificate file or key file provided")
	}

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Printf("DnSDoTEngine: certificate file %q does not exist. Not starting.", certFile)
		return fmt.Errorf("certificate file %q does not exist", certFile)
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Printf("DnSDoTEngine: key file %q does not exist. Not starting.", keyFile)
		return fmt.Errorf("key file %q does not exist", keyFile)
	}

	log.Printf("DnsEngine: DoT addresses: %v", dotaddrs)
	tlsConfig := DoTTLSConfig(certFile, keyFile)
	for _, addr := range dotaddrs {
		server := &dns.Server{
			Addr:          addr,
			Net:           "tcp-tls",
			TLSConfig:     tlsConfig,
			MsgAcceptFunc: MsgAcceptFunc, // We need a tweaked version for DNS UPDATE
			Handler:       dns.HandlerFunc(ourDNSHandler),
		}
		go func(addr string) {
			log.Printf("DnsEngine: serving on %s (DoT)\n", addr)
			if err := server.ListenAndServe(); err != nil {
				log.Printf("Failed to setup the DoT server: %s", err.Error())
			} else {
				log.Printf("DnsEngine: listening on %s/DoT", addr)
			}
		}(addr)
	}
	return nil
}

func DoTTLSConfig(certFile, keyFile string) *tls.Config {
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
