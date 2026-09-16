/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// dohTestEngine is a running DnsDoHEngine on 127.0.0.1 and a client that
// trusts its certificate.
type dohTestEngine struct {
	base   string // https://127.0.0.1:<port>
	client *http.Client
}

// dohEngineGoroutines counts the goroutines DnsDoHEngine started and that are
// still running: one per listener serving, and the one waiting to shut them
// down. They are found in a full goroutine dump by their creator, so the count
// covers this engine code only. A process-wide count would not do: an
// unrelated goroutine exiting could satisfy it while an engine's stayed up.
func dohEngineGoroutines() int {
	creator := "created by " + runtime.FuncForPC(reflect.ValueOf(DnsDoHEngine).Pointer()).Name() + " in goroutine "
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Count(string(buf[:n]), creator)
		}
		buf = make([]byte, 2*len(buf))
	}
}

// startTestDoHEngine runs the real DnsDoHEngine, not a copy of its handler:
// what is under test is what the engine puts behind its listener. The engine
// binds in a goroutine and reports nothing back, so this picks a free port,
// hands it over and waits until TLS connects. path is listeners.doh-path: ""
// is the default.
//
// When the test ends the engine is cancelled, and the test fails unless every
// goroutine the engine started has exited within 3s. A closed port is not
// enough: http.Server.Shutdown closes its listeners first and only then waits
// for connections, so the port closes while the engine is still running. The
// shutdown goroutine exits only after Shutdown returns, by which time every
// connection is closed. The wait compares against the count from before this
// engine started, which is exact because these tests do not run in parallel
// and cleanups run in reverse order: the last engine started stops first.
func startTestDoHEngine(t *testing.T, path string) *dohTestEngine {
	t.Helper()
	cert, pool := newUpstreamTestCert(t)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick a port: %v", err)
	}
	hostport := l.Addr().String()
	_, port, _ := net.SplitHostPort(hostport)
	l.Close()

	handler := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	}
	tlsConf := &tls.Config{RootCAs: pool, ServerName: "dns.test.example"}
	e := &dohTestEngine{
		base:   "https://" + hostport,
		client: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConf}},
	}

	before := dohEngineGoroutines()
	ctx, cancel := context.WithCancel(context.Background())
	if err := DnsDoHEngine(ctx, &Config{}, []string{"127.0.0.1"}, []string{port}, path, certFile, keyFile, handler); err != nil {
		cancel()
		t.Fatalf("DnsDoHEngine: %v", err)
	}
	t.Cleanup(func() {
		// Shutdown closes idle connections on its own; closing the client's
		// kept-alive ones too keeps the client's connection goroutines from
		// outliving the test.
		e.client.CloseIdleConnections()
		cancel()
		deadline := time.Now().Add(3 * time.Second)
		for dohEngineGoroutines() > before {
			if time.Now().After(deadline) {
				t.Errorf("DoH engine on %s: %d of its goroutines still running 3s after cancel",
					hostport, dohEngineGoroutines()-before)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 200 * time.Millisecond}, "tcp", hostport, tlsConf)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("DoH engine on %s never accepted TLS: %v", hostport, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Without this the shutdown wait proves nothing: if the dump stopped
	// naming DnsDoHEngine as the creator, the count would stay at before.
	if dohEngineGoroutines() <= before {
		t.Fatalf("the goroutine dump shows no goroutines created by DnsDoHEngine; the shutdown check would pass vacuously")
	}
	return e
}

func (e *dohTestEngine) get(t *testing.T, path string) (int, []byte) {
	t.Helper()
	resp, err := e.client.Get(e.base + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func dohTestQuery(t *testing.T) *dns.Msg {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("www.example.", dns.TypeA)
	return q
}

func checkDoHReply(t *testing.T, how string, q *dns.Msg, status int, body []byte) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("%s: status %d, body %q", how, status, body)
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		t.Fatalf("%s: reply does not unpack: %v", how, err)
	}
	if r.Id != q.Id || !r.Response || len(r.Question) != 1 || r.Question[0].Name != "www.example." {
		t.Fatalf("%s: reply does not answer the query: %v", how, r)
	}
}

// checkDoHAnswers sends the query in both RFC 8484 forms to path.
func (e *dohTestEngine) checkDoHAnswers(t *testing.T, path string) {
	t.Helper()
	q := dohTestQuery(t)
	packed, err := q.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	resp, err := e.client.Post(e.base+path, "application/dns-message", bytes.NewReader(packed))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	checkDoHReply(t, "POST "+path, q, resp.StatusCode, body)

	status, body := e.get(t, path+"?dns="+base64.RawURLEncoding.EncodeToString(packed))
	checkDoHReply(t, "GET "+path, q, status, body)
}

// With no doh-path the DoH endpoint is /dns-query, in both RFC 8484 forms.
func TestDoHEngineAnswersDnsQuery(t *testing.T) {
	e := startTestDoHEngine(t, "")
	e.checkDoHAnswers(t, DefaultDoHPath)
}

// A configured doh-path is the only path answered, matched exactly: not
// /dns-query, not the path with a trailing "/", nothing above or below it.
func TestDoHEngineConfiguredPath(t *testing.T) {
	e := startTestDoHEngine(t, "/resolve/v1")
	e.checkDoHAnswers(t, "/resolve/v1")

	q := dohTestQuery(t)
	packed, err := q.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	query := "?dns=" + base64.RawURLEncoding.EncodeToString(packed)
	for _, path := range []string{"/dns-query", "/resolve/v1/", "/resolve", "/resolve/", "/resolve/v1/x", "/RESOLVE/v1", "/", "/debug/pprof/"} {
		if status, body := e.get(t, path+query); status != http.StatusNotFound {
			t.Errorf("GET %s with doh-path /resolve/v1: status %d, want 404; body %.80q", path, status, body)
		}
	}
}

// A path the config loader would refuse is refused by the engine too, before
// anything binds.
func TestDoHEngineRefusesInvalidPath(t *testing.T) {
	handler := func(w dns.ResponseWriter, r *dns.Msg) {}
	err := DnsDoHEngine(context.Background(), &Config{}, []string{"127.0.0.1"}, []string{"0"}, "dns-query", "nocert", "nokey", handler)
	if err == nil || !strings.Contains(err.Error(), "doh-path") {
		t.Fatalf("DnsDoHEngine with doh-path \"dns-query\": err = %v, want a doh-path error", err)
	}
}

func TestValidateDoHPath(t *testing.T) {
	for _, ok := range []string{"", "/", "/dns-query", "/resolve/v1", "/dns/", "/a-b_c.d~e", "/x;v=1", "/@home:8443", "/$!&'()*+,="} {
		if err := validateDoHPath(ok); err != nil {
			t.Errorf("validateDoHPath(%q) = %v, want accepted", ok, err)
		}
	}
	for _, bad := range []string{
		"dns-query",        // relative
		" /dns-query",      // leading space
		"/dns query",       // space
		"/dns-query?dns=x", // query
		"/dns-query#x",     // fragment
		"/dns%2Dquery",     // percent-encoding
		"/dns-query{?dns}", // a URI template, not a path
		"GET /dns-query",   // a ServeMux method pattern
		"//dns-query",      // empty segment
		"/a//b",            // empty segment
		"/a/./b",           // dot segment
		"/a/../dns-query",  // dot-dot segment
		"/..",              // dot-dot segment
		"/dns-q\u00fcery",  // non-ASCII
		"/dns\\query",      // backslash
	} {
		if err := validateDoHPath(bad); err == nil {
			t.Errorf("validateDoHPath(%q) accepted, want refused", bad)
		}
	}
}

// The key is listeners.doh-path, it reaches ListenersConf through the
// daemon's decoder, and both the daemon loader and `config check` refuse a
// bad value.
func TestDoHPathConfig(t *testing.T) {
	var conf Config
	if _, _, _, err := decodeConfigFile(writeCfg(t, "listeners:\n   doh-path: /resolve/v1\n"), &conf); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if conf.Listeners.DoHPath != "/resolve/v1" {
		t.Fatalf("listeners.doh-path decoded as %q, want /resolve/v1", conf.Listeners.DoHPath)
	}

	const bad = "listeners:\n   doh-path: resolve/v1\n"
	loader := &Config{}
	loader.Internal.CfgFile = writeCfg(t, bad)
	if err := loader.ParseConfig(false); err == nil || !strings.Contains(err.Error(), "doh-path") {
		t.Errorf("ParseConfig with doh-path \"resolve/v1\": err = %v, want a doh-path error", err)
	}
	if err := ValidateConfig(nil, writeCfg(t, bad)); err == nil || !strings.Contains(err.Error(), "doh-path") {
		t.Errorf("ValidateConfig with doh-path \"resolve/v1\": err = %v, want a doh-path error", err)
	}
}

// The DoH listener serves /dns-query and nothing else. In particular not the
// profiler that net/http/pprof puts on http.DefaultServeMux, which a nil
// Handler used to serve on the public DoH port.
func TestDoHEngineServesNothingFromDefaultServeMux(t *testing.T) {
	// The precondition that makes this test mean something: the profiler IS
	// on the default mux in this binary, as it is in every daemon.
	if _, pattern := http.DefaultServeMux.Handler(httptest.NewRequest(http.MethodGet, "/debug/pprof/cmdline", nil)); pattern == "" {
		t.Fatal("precondition: net/http/pprof is not registered on http.DefaultServeMux, so this test proves nothing")
	}

	e := startTestDoHEngine(t, "")
	for _, path := range []string{"/debug/pprof/", "/debug/pprof/cmdline", "/debug/pprof/goroutine?debug=2"} {
		if status, body := e.get(t, path); status != http.StatusNotFound {
			t.Errorf("GET %s on the DoH listener: status %d, want 404; body %.80q", path, status, body)
		}
	}
}

// Two DoH engines in one process on the same path. On the default mux the
// second registration of /dns-query panicked.
func TestDoHEngineTwoInOneProcess(t *testing.T) {
	a := startTestDoHEngine(t, "")
	b := startTestDoHEngine(t, "")
	a.checkDoHAnswers(t, DefaultDoHPath)
	b.checkDoHAnswers(t, DefaultDoHPath)
}
