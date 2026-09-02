/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The all-upstreams-failed SERVFAIL must be logged, but throttled: one line
// per interval per zone, however hot the query load.
func TestForwardServfailLogThrottle(t *testing.T) {
	fz := &ForwardZone{Zone: "fwd.example."}
	if !fz.noteAllUpstreamsFailed("www.fwd.example.", dns.TypeA, 1, 1, fmt.Errorf("timeout")) {
		t.Error("first SERVFAIL not logged")
	}
	for i := 0; i < 5; i++ {
		if fz.noteAllUpstreamsFailed("www.fwd.example.", dns.TypeA, 1, 1, fmt.Errorf("timeout")) {
			t.Fatal("throttle did not suppress an immediate repeat")
		}
	}
	// A different zone throttles independently.
	fz2 := &ForwardZone{Zone: "other.example."}
	if !fz2.noteAllUpstreamsFailed("x.other.example.", dns.TypeA, 1, 1, fmt.Errorf("timeout")) {
		t.Error("second zone's first SERVFAIL suppressed by the first zone's throttle")
	}
}

// InitImrEngine must CHOOSE hints-only priming when a forward zone covers
// the root — this pins the dispatch itself, not just the helper: with the
// condition inverted, init would run the live priming fetch through the
// forward (PrimedVia "hints+fetch", a '. NS' at the upstream) and both
// assertions below fail.
func TestInitImrEngineHintsOnlyDispatch(t *testing.T) {
	addr, port, logr, stop := startTestUpstream(t)
	defer stop()

	savedImr := Globals.ImrEngine
	defer func() { Globals.ImrEngine = savedImr }()

	conf := &Config{}
	conf.Imr.Forward = []ImrForwardConf{
		{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}},
	}
	if err := conf.InitImrEngine(context.Background(), true); err != nil {
		t.Fatalf("InitImrEngine: %v", err)
	}
	imr := conf.Internal.ImrEngine
	if imr == nil || !imr.Cache.IsPrimed() {
		t.Fatalf("engine not initialized/primed: %+v", imr)
	}
	if imr.PrimedVia != "hints-only (root forwarded)" {
		t.Errorf("dispatch took the wrong priming path: PrimedVia = %q", imr.PrimedVia)
	}
	logr.mu.Lock()
	n := len(logr.queries)
	logr.mu.Unlock()
	if n != 0 {
		t.Errorf("init sent %d query(ies) to the upstream; hints-only priming must be offline: %+v", n, logr.queries)
	}
}

// A failure whose exchange STARTED before a later success must be discarded:
// an uncancellable probe racing a recovery must not re-mark a healthy
// upstream failing (stale DEGRADED).
func TestRecordFailureSuperseded(t *testing.T) {
	up := &ForwardUpstream{Label: "192.0.2.1:53/do53"}
	start := time.Now()
	up.recordSuccess()
	if up.recordFailure(start, fmt.Errorf("stale timeout")) {
		t.Error("superseded failure reported a transition")
	}
	if up.failing || up.failures != 0 {
		t.Errorf("superseded failure recorded: failing=%v failures=%d", up.failing, up.failures)
	}
	if up.queries != 2 {
		t.Errorf("superseded failure not counted as an attempt: queries=%d, want 2", up.queries)
	}
	// A failure that started after the success records normally.
	if !up.recordFailure(time.Now(), fmt.Errorf("real timeout")) {
		t.Error("current failure did not report the ok->failing transition")
	}
	if !up.failing || up.failures != 1 {
		t.Errorf("current failure not recorded: failing=%v failures=%d", up.failing, up.failures)
	}
}

// loadImrListenerCert: mutually exclusive checks, one accurate reason each.
func TestLoadImrListenerCert(t *testing.T) {
	dir := t.TempDir()

	// Valid pair, from the shared test-cert generator.
	cert, _ := newUpstreamTestCert(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	garbageFile := filepath.Join(dir, "garbage.pem")
	for file, data := range map[string][]byte{
		certFile:    certPEM,
		keyFile:     keyPEM,
		garbageFile: []byte("not a pem file"),
	} {
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatalf("write %s: %v", file, err)
		}
	}

	cases := []struct {
		name       string
		cert, key  string
		ok         bool
		reasonPart string
	}{
		{"valid pair", certFile, keyFile, true, ""},
		{"unconfigured", "", "", false, "not configured"},
		{"half configured", certFile, "", false, "not configured"},
		{"missing certfile", filepath.Join(dir, "nope.crt"), keyFile, false, "certfile"},
		{"missing keyfile", certFile, filepath.Join(dir, "nope.key"), false, "keyfile"},
		{"unparseable pair", garbageFile, keyFile, false, "loading"},
	}
	for _, c := range cases {
		loaded, reason, ok := loadImrListenerCert(c.cert, c.key)
		if ok != c.ok {
			t.Errorf("%s: ok=%v, want %v (reason=%q)", c.name, ok, c.ok, reason)
			continue
		}
		if c.ok {
			if len(loaded.Certificate) == 0 {
				t.Errorf("%s: no certificate loaded", c.name)
			}
			continue
		}
		if !strings.Contains(reason, c.reasonPart) {
			t.Errorf("%s: reason %q does not mention %q", c.name, reason, c.reasonPart)
		}
	}
}
