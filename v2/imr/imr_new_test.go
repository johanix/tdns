/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package imr

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// recordingSink is an ErrorSink that is not the daemon's registry.
type recordingSink struct {
	mu    sync.Mutex
	calls []string
}

func (s *recordingSink) note(c string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, c)
}

func (s *recordingSink) SetImrPrimingError(msg string) { s.note("set-priming " + msg) }

func (s *recordingSink) ClearImrPrimingError() { s.note("clear-priming") }

func (s *recordingSink) SetImrForwardZoneError(msg string) { s.note("set-zone " + msg) }

func (s *recordingSink) ClearImrForwardZoneError() { s.note("clear-zone") }

func (s *recordingSink) SetImrForwardUpstreamError(msg string) { s.note("set-upstream " + msg) }

func (s *recordingSink) ClearImrForwardUpstreamError() { s.note("clear-upstream") }

func (s *recordingSink) SetImrForwardUpstreamConfigError(msg string) { s.note("set-config " + msg) }

func (s *recordingSink) ClearImrForwardUpstreamConfigError() { s.note("clear-config") }

func (s *recordingSink) List() []ServerError { return nil }

// The forward table's quarantine goes to the sink New was given, whatever it
// is; a nil sink, a typed nil registry and the daemon's registry are all fine.
func TestNewReportsToTheErrorSink(t *testing.T) {
	restoreProcessWideTuning(t)
	addr, port, _, stop := startTestUpstream(t)
	defer stop()
	ic := Config{Forward: append(rootForward(addr, port),
		// trust-ad over plaintext: quarantined, not fatal.
		ForwardConf{Zone: "bad.example.", TrustAD: true, Upstreams: []UpstreamConf{{Addr: "192.0.2.9"}}})}

	rec, reg := &recordingSink{}, newTestErrorSink()
	for _, tc := range []struct {
		name string
		sink ErrorSink
	}{{"recording sink", rec}, {"registry", reg}, {"nil sink", nil}, {"typed nil registry", (*testErrorSink)(nil)}} {
		imr, err := New(context.Background(), ic, Options{Errors: tc.sink})
		if err != nil {
			t.Fatalf("%s: New: %v", tc.name, err)
		}
		if imr.errorRegistry == nil {
			t.Errorf("%s: the Imr has no sink", tc.name)
		}
	}

	if !slices.ContainsFunc(rec.calls, func(c string) bool { return strings.HasPrefix(c, "set-zone ") && strings.Contains(c, "bad.example.") }) {
		t.Errorf("the recording sink was told %q; want the quarantined zone", rec.calls)
	}
	var found bool
	for _, e := range reg.List() {
		found = found || (e.Subtype == ErrSubImrForwardZone && strings.Contains(e.Message, "bad.example."))
	}
	if !found {
		t.Errorf("the registry holds %+v; want the quarantined zone", reg.List())
	}
}

// Options.PendingOwnZone keeps trust-anchor set-up from asking the network
// for the keys of a zone this server hosts and has not loaded yet; without it,
// the keys are fetched.
func TestNewPendingOwnZoneKeepsTrustAnchorSetupOffTheNetwork(t *testing.T) {
	restoreProcessWideTuning(t)
	addr, port, logr, stop := startTestUpstream(t)
	defer stop()
	const zone = "anchor.fwd.example."
	ic := Config{
		Forward:       rootForward(addr, port),
		TrustAnchorDS: zone + " 3600 IN DS 12345 13 2 " + strings.Repeat("ab", 32),
	}

	pending := Options{PendingOwnZone: func(z string) bool { return z == zone }}
	imr, err := New(context.Background(), ic, pending)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := imr.initializeImrTrustAnchors(context.Background(), imr.bootConf); err != nil {
		t.Errorf("trust-anchor set-up with %s pending: %v", zone, err)
	}
	if n := len(logr.find(zone, dns.TypeDNSKEY)); n != 0 {
		t.Errorf("trust-anchor set-up asked the upstream for %s DNSKEY %d time(s) though the zone is pending", zone, n)
	}

	imr, err = New(context.Background(), ic, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = imr.initializeImrTrustAnchors(context.Background(), imr.bootConf) // the upstream has no such key
	if len(logr.find(zone, dns.TypeDNSKEY)) == 0 {
		t.Errorf("trust-anchor set-up did not ask for %s DNSKEY with nothing pending", zone)
	}
}

// Two resolvers in one process register one set of debug hooks between them,
// not one each (which would log every query once per resolver).
func TestNewRegistersItsDebugHooksOnce(t *testing.T) {
	restoreProcessWideTuning(t)
	addr, port, _, stop := startTestUpstream(t)
	defer stop()
	hooks := func() int {
		globalImrOutboundQueryHooksMutex.RLock()
		defer globalImrOutboundQueryHooksMutex.RUnlock()
		return len(globalImrOutboundQueryHooks)
	}

	ic := Config{Forward: rootForward(addr, port)}
	ic.Logging.Enabled = true
	ic.Logging.File = filepath.Join(t.TempDir(), "imr-debug.log")
	before := hooks()
	for i := 0; i < 2; i++ {
		if _, err := New(context.Background(), ic, Options{}); err != nil {
			t.Fatalf("New %d: %v", i+1, err)
		}
	}
	if got := hooks() - before; got > 1 {
		t.Errorf("%d debug hooks registered by two resolvers, want at most one", got)
	}
}
