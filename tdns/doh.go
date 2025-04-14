/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func DnsDoHEngine(conf *Config, dohaddrs []string,
	ourDNSHandler func(w dns.ResponseWriter, r *dns.Msg)) error {
	certFile := viper.GetString("dnsengine.doh.certfile")
	keyFile := viper.GetString("dnsengine.doh.keyfile")

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

	log.Printf("DnsEngine: DoH addresses: %v", dohaddrs)
	http.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		var dnsQuery []byte
		var err error
		msg := new(dns.Msg)
		if r.Method == http.MethodPost {
			dnsQuery, err = io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Failed to read request body", http.StatusInternalServerError)
				return
			}
		} else if r.Method == http.MethodGet {
			base64msg := r.URL.Query().Get("dns")
			dnsQuery, err = base64.RawURLEncoding.DecodeString(base64msg)
			if err != nil {
				http.Error(w, "Failed to decode base64 message", http.StatusBadRequest)
				return
			}
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		err = msg.Unpack(dnsQuery)
		if err != nil {
			http.Error(w, "Failed to unpack DNS message", http.StatusBadRequest)
			return
		}

		// Create a response writer abstraction for DoH
		var buf bytes.Buffer
		rw := &dohResponseWriter{&buf}

		// Call your internal handler to process DNS query
		ourDNSHandler(rw, msg)

		// raw, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(buf.Bytes())
	})

	for _, addr := range dohaddrs {
		go func(addr string) {
			log.Printf("DnsEngine: setting up DoH server on %s", addr)
			if err := http.ListenAndServeTLS(addr, certFile, keyFile, nil); err != nil {
				log.Printf("Failed to setup the DoH server: %s", err.Error())
			} else {
				log.Printf("DnsEngine: listening on %s/DoH", addr)
			}
			log.Printf("DnsEngine: done setting up DoH server on %s", addr)
		}(addr)
	}
	return nil
}

type dohResponseWriter struct {
	buf *bytes.Buffer
}

func (w *dohResponseWriter) WriteMsg(m *dns.Msg) error {
	raw, err := m.Pack()
	if err != nil {
		return err
	}
	_, err = w.buf.Write(raw)
	return err
}

func (w *dohResponseWriter) Close() error              { return nil }
func (w *dohResponseWriter) TsigStatus() error         { return nil }
func (w *dohResponseWriter) TsigTimersOnly(bool)       {}
func (w *dohResponseWriter) Hijack()                   {}
func (w *dohResponseWriter) LocalAddr() net.Addr       { return dummyAddr{} }
func (w *dohResponseWriter) RemoteAddr() net.Addr      { return dummyAddr{} }
func (w *dohResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (w *dohResponseWriter) WriteMsgWithTsig(*dns.Msg, string, bool) error {
	return errors.New("not implemented")
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "doh" }
func (dummyAddr) String() string  { return "127.0.0.1:443" }
