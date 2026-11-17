/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"path/filepath"
	"runtime/pprof"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
)

// restoreProcessWideTuning puts back what NewImr sets for the whole process.
func restoreProcessWideTuning(t *testing.T) {
	t.Helper()
	policy, limits := cache.GetBackoffPolicy(), cache.GetTTLLimits()
	t.Cleanup(func() {
		cache.SetBackoffPolicy(policy)
		cache.SetTTLLimits(limits)
	})
}

// goroutinesIn counts the goroutines that have fn on their stack.
func goroutinesIn(fn string) int {
	var b strings.Builder
	_ = pprof.Lookup("goroutine").WriteTo(&b, 2)
	return strings.Count(b.String(), fn)
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// An application builds a resolver from the imrengine: configuration alone. No
// Config, nothing published, no listeners; Start runs what keeps it going and
// ends with its context.
func TestNewImrFromImrEngineConfAlone(t *testing.T) {
	restoreProcessWideTuning(t)
	addr, port, _, stop := startTestUpstream(t)
	defer stop()

	published := Globals.ImrEngine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	imr, err := NewImr(ctx, ImrEngineConf{Forward: rootForward(addr, port)}, ImrOptions{Quiet: true})
	if err != nil {
		t.Fatalf("NewImr: %v", err)
	}
	if Globals.ImrEngine != published {
		t.Error("NewImr published the Imr in Globals.ImrEngine")
	}

	refreshing, listening := goroutinesIn("(*Imr).refreshRootLoop("), goroutinesIn("StartImrEngineListeners(")
	imr.Start(ctx)
	waitUntil(t, "Start to run the root refresh", func() bool { return goroutinesIn("(*Imr).refreshRootLoop(") > refreshing })

	resp, err := imr.ImrQuery(ctx, "www.fwd.example.", dns.TypeA, dns.ClassINET, nil)
	if err != nil || resp == nil || resp.RRset == nil || len(resp.RRset.RRs) != 1 {
		t.Fatalf("www.fwd.example. A: %+v (err %v), want the upstream's answer", resp, err)
	}
	if a, ok := resp.RRset.RRs[0].(*dns.A); !ok || a.A.String() != "192.0.2.77" {
		t.Errorf("www.fwd.example. A = %v, want 192.0.2.77", resp.RRset.RRs[0])
	}
	if got := goroutinesIn("StartImrEngineListeners("); got != listening {
		t.Error("Start started listeners")
	}

	cancel()
	waitUntil(t, "Start's goroutines to end with its context", func() bool { return goroutinesIn("(*Imr).refreshRootLoop(") <= refreshing })
}

// A priming that fails is NewImr's error, and it has published nothing.
func TestNewImrReturnsThePrimingError(t *testing.T) {
	restoreProcessWideTuning(t)
	published := Globals.ImrEngine
	ic := ImrEngineConf{RootHints: filepath.Join(t.TempDir(), "no-such-hints")}
	if imr, err := NewImr(context.Background(), ic, ImrOptions{Quiet: true}); err == nil || imr != nil {
		t.Fatalf("NewImr with no root hints to read: %v, %v; want no Imr and an error", imr, err)
	}
	if Globals.ImrEngine != published {
		t.Error("a failed NewImr published an Imr")
	}
}

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
func (s *recordingSink) SetImrForwardZoneError(msg string)           { s.note("set-zone " + msg) }
func (s *recordingSink) ClearImrForwardZoneError()                   { s.note("clear-zone") }
func (s *recordingSink) SetImrForwardUpstreamError(msg string)       { s.note("set-upstream " + msg) }
func (s *recordingSink) ClearImrForwardUpstreamError()               { s.note("clear-upstream") }
func (s *recordingSink) SetImrForwardUpstreamConfigError(msg string) { s.note("set-config " + msg) }
func (s *recordingSink) ClearImrForwardUpstreamConfigError()         { s.note("clear-config") }
func (s *recordingSink) List() []ServerError                         { return nil }

// The forward table's quarantine goes to the sink NewImr was given, whatever it
// is; a nil sink, a typed nil registry and the daemon's registry are all fine.
func TestNewImrReportsToTheErrorSink(t *testing.T) {
	restoreProcessWideTuning(t)
	addr, port, _, stop := startTestUpstream(t)
	defer stop()
	ic := ImrEngineConf{Forward: append(rootForward(addr, port),
		// trust-ad over plaintext: quarantined, not fatal.
		ImrForwardConf{Zone: "bad.example.", TrustAD: true, Upstreams: []ImrUpstreamConf{{Addr: "192.0.2.9"}}})}

	rec, reg := &recordingSink{}, NewServerErrorRegistry()
	for _, tc := range []struct {
		name string
		sink ErrorSink
	}{{"recording sink", rec}, {"registry", reg}, {"nil sink", nil}, {"typed nil registry", (*ServerErrorRegistry)(nil)}} {
		imr, err := NewImr(context.Background(), ic, ImrOptions{Errors: tc.sink, Quiet: true})
		if err != nil {
			t.Fatalf("%s: NewImr: %v", tc.name, err)
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

// ImrOptions.PendingOwnZone keeps trust-anchor set-up from asking the network
// for the keys of a zone this server hosts and has not loaded yet; without it,
// the keys are fetched.
func TestNewImrPendingOwnZoneKeepsTrustAnchorSetupOffTheNetwork(t *testing.T) {
	restoreProcessWideTuning(t)
	addr, port, logr, stop := startTestUpstream(t)
	defer stop()
	const zone = "anchor.fwd.example."
	ic := ImrEngineConf{
		Forward:       rootForward(addr, port),
		TrustAnchorDS: zone + " 3600 IN DS 12345 13 2 " + strings.Repeat("ab", 32),
	}

	pending := ImrOptions{Quiet: true, PendingOwnZone: func(z string) bool { return z == zone }}
	imr, err := NewImr(context.Background(), ic, pending)
	if err != nil {
		t.Fatalf("NewImr: %v", err)
	}
	if err := imr.initializeImrTrustAnchors(context.Background(), imr.bootConf); err != nil {
		t.Errorf("trust-anchor set-up with %s pending: %v", zone, err)
	}
	if n := len(logr.find(zone, dns.TypeDNSKEY)); n != 0 {
		t.Errorf("trust-anchor set-up asked the upstream for %s DNSKEY %d time(s) though the zone is pending", zone, n)
	}

	imr, err = NewImr(context.Background(), ic, ImrOptions{Quiet: true})
	if err != nil {
		t.Fatalf("NewImr: %v", err)
	}
	_ = imr.initializeImrTrustAnchors(context.Background(), imr.bootConf) // the upstream has no such key
	if len(logr.find(zone, dns.TypeDNSKEY)) == 0 {
		t.Errorf("trust-anchor set-up did not ask for %s DNSKEY with nothing pending", zone)
	}
}
