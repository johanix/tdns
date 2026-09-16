/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/miekg/dns"
)

// DefaultDoHPath is the path the DoH listeners answer on when
// listeners.doh-path is unset: the one RFC 8484 uses in its examples, and the
// one clients assume when given only a host.
const DefaultDoHPath = "/dns-query"

// validateDoHPath checks listeners.doh-path (#666). Empty means
// DefaultDoHPath. The listener compares the request path byte for byte, so
// the rules keep out what a client would rewrite before sending, which could
// then never match, and what would read as something else in a URI template:
//   - it starts with "/";
//   - no empty, "." or ".." segments, which clients normalise away (a
//     trailing "/" is kept by clients and is allowed);
//   - RFC 3986 path characters only, without percent-encoding: no query,
//     fragment, space or braces.
func validateDoHPath(path string) error {
	if path == "" {
		return nil
	}
	if path[0] != '/' {
		return fmt.Errorf("listeners.doh-path %q must start with \"/\"", path)
	}
	for i := 0; i < len(path); i++ {
		if !isDoHPathByte(path[i]) {
			return fmt.Errorf("listeners.doh-path %q: %q is not allowed; use letters, digits, \"/\" and -._~!$&'()*+,;=:@ (no query, fragment or percent-encoding)",
				path, string(path[i]))
		}
	}
	segments := strings.Split(path[1:], "/")
	for i, seg := range segments {
		switch {
		case seg == "" && i < len(segments)-1:
			return fmt.Errorf("listeners.doh-path %q has an empty segment (\"//\"), which clients collapse", path)
		case seg == "." || seg == "..":
			return fmt.Errorf("listeners.doh-path %q has a %q segment, which clients resolve away", path, seg)
		}
	}
	return nil
}

// isDoHPathByte is RFC 3986 pchar without pct-encoded, plus "/".
func isDoHPathByte(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	return strings.IndexByte("-._~!$&'()*+,;=:@/", c) >= 0
}

func DnsDoHEngine(ctx context.Context, conf *Config, dohaddrs, ports []string, path, certFile, keyFile string,
	ourDNSHandler func(w dns.ResponseWriter, r *dns.Msg)) error {

	// path comes from the caller's listeners: block, like ports. The config
	// loader has already refused a bad one; this is for any other caller.
	if err := validateDoHPath(path); err != nil {
		return err
	}
	if path == "" {
		path = DefaultDoHPath
	}
	lgDns.Info("DnsEngine: DoH addresses", "addrs", dohaddrs, "path", path)
	// The closure captures ourDNSHandler (a function parameter) and conf (a pointer).
	// Both are set once at startup before any HTTP requests are served, so there is
	// no data race despite the closure being invoked concurrently by the HTTP server.
	serveQuery := func(w http.ResponseWriter, r *http.Request) {
		var dnsQuery []byte
		var err error
		msg := new(dns.Msg)
		if r.Method == http.MethodPost {
			// ReadHeaderTimeout covers only the headers and IdleTimeout only
			// parked connections: without a deadline here, a client sending
			// its (at most 65535-byte) body one byte at a time holds the
			// handler and its HTTP/2 stream open indefinitely. Ten seconds
			// is generous for 64KB from any legitimate client. The error is
			// ignored deliberately: a transport that does not support
			// per-request deadlines just keeps the pre-deadline behaviour.
			rc := http.NewResponseController(w)
			_ = rc.SetReadDeadline(time.Now().Add(10 * time.Second))
			dnsQuery, err = io.ReadAll(io.LimitReader(r.Body, 65535))
			_ = rc.SetReadDeadline(time.Time{})
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

		if len(msg.Question) == 0 {
			lgDns.Warn("DoH: received message with no question section", "remote", r.RemoteAddr)
			http.Error(w, "DNS message has no question section", http.StatusBadRequest)
			return
		}

		// Create a response writer abstraction for DoH
		var buf bytes.Buffer
		rw := &dohResponseWriter{&buf}

		lgDns.Debug("DoH: received message", "opcode", dns.OpcodeToString[msg.Opcode], "qname", msg.Question[0].Name, "rrtype", dns.TypeToString[msg.Question[0].Qtype])

		// Call your internal handler to process DNS query
		ourDNSHandler(rw, msg)

		// raw, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		if _, err := w.Write(buf.Bytes()); err != nil {
			lgDns.Warn("DoH: error writing response", "err", err)
		}
	}

	// The servers get this handler, never http.DefaultServeMux. The default
	// mux is process-wide: whatever registers on it is served by every server
	// that leaves Handler nil. net/http/pprof registers /debug/pprof/ there
	// from its init(), and this package imports it for service.pprof-address,
	// so a nil Handler put the profiler on the public DoH port,
	// unauthenticated, whether or not pprof-address was set.
	//
	// One path, compared exactly, and not a ServeMux either: a mux pattern
	// ending in "/" matches everything below it, and the mux answers paths it
	// would clean with a redirect, so a configured path would not mean only
	// itself.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		serveQuery(w, r)
	})

	// ports comes from the caller's listeners: block (#444/#446).
	if len(ports) == 0 {
		ports = []string{"443"}
	}
	var servers []*http.Server
	for _, addr := range dohaddrs {
		for _, port := range ports {
			hostport := net.JoinHostPort(addr, port)
			srv := &http.Server{
				Addr:    hostport,
				Handler: handler,
				TLSConfig: &tls.Config{
					MinVersion: tls.VersionTLS13,
				},
				// DoH clients speak HTTP/2 or HTTP/1.1 keep-alive and hold
				// their TCP connections open as long as we let them; every
				// held connection is a file descriptor that never comes
				// back. Without these bounds an hour of ordinary DoH
				// traffic can exhaust the process fd limit, at which point
				// every OUTBOUND dial fails and a forwarding resolver
				// serves SERVFAIL for everything uncached, silently, until
				// restarted (#443). IdleTimeout reaps parked connections
				// and ReadHeaderTimeout bounds half-open handshakes.
				// Deliberately NO ReadTimeout/WriteTimeout: on HTTP/2 those
				// have historically acted as connection lifetimes rather
				// than per-request caps, which would force well-behaved
				// long-lived DoH clients to reconnect on a timer — and this
				// server is shared with the tdns-auth DoH listener.
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       120 * time.Second,
			}
			servers = append(servers, srv)
			go func(s *http.Server, hp string) {
				lgDns.Info("DnsEngine: setting up DoH server", "hostport", hp, "path", path)
				if err := s.ListenAndServeTLS(certFile, keyFile); err != http.ErrServerClosed {
					lgDns.Error("failed to setup DoH server", "hostport", hp, "err", err)
					if ctx.Err() == nil {
						conf.Internal.ServerErrors.SetTransportPortError("doh "+hp, err)
					}
				} else {
					lgDns.Info("DnsEngine: listening on DoH", "hostport", hp)
				}
				lgDns.Info("DnsEngine: done setting up DoH server", "hostport", hp)
			}(srv, hostport)
		}
	}
	go func() {
		<-ctx.Done()
		lgDns.Info("DnsDoHEngine: shutting down DoH servers")
		// Use bounded shutdown context to avoid hanging forever
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, s := range servers {
			if err := s.Shutdown(shutdownCtx); err != nil {
				lgDns.Error("DnsDoHEngine: error during shutdown", "addr", s.Addr, "err", err)
			}
		}
	}()
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

func (w *dohResponseWriter) Close() error { return nil }

// TODO(tsig): DoH is served by this buffer-backed writer, not a miekg
// dns.Server, so miekg's conn-level TSIG (verify-on-read, MAC-on-write) does not
// apply and TsigStatus is a stub. Supporting TSIG over DoH would mean manually
// dns.TsigVerify'ing the inbound message and dns.TsigGenerate'ing the reply
// (request-MAC prefixed) in this path. Deferred: encrypted transports usually
// authenticate peers via TLS/mTLS, and tdns replication (AXFR/NOTIFY) is Do53.
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
