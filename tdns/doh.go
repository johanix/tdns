/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

func DnsDoHEngine(conf *Config, dohaddrs []string, certFile, keyFile string,
	ourDNSHandler func(w dns.ResponseWriter, r *dns.Msg)) error {

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

		if Globals.Debug {
			log.Printf("*** DoH received message opcode: %s qname: %s rrtype: %s", dns.OpcodeToString[msg.Opcode], msg.Question[0].Name, dns.TypeToString[msg.Question[0].Qtype])
		}

		// Call your internal handler to process DNS query
		ourDNSHandler(rw, msg)

		// raw, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(buf.Bytes())
	})

	for _, addr := range dohaddrs {
		go func(addr string) {
			hostport := net.JoinHostPort(addr, "443") // At the moment, we only support port 443
			log.Printf("DnsEngine: setting up DoH server on %s", hostport)
			if err := http.ListenAndServeTLS(hostport, certFile, keyFile, nil); err != nil {
				log.Printf("Failed to setup the DoH server on %s: %s", hostport, err.Error())
			} else {
				log.Printf("DnsEngine: listening on %s/DoH", hostport)
			}
			log.Printf("DnsEngine: done setting up DoH server on %s", hostport)
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
