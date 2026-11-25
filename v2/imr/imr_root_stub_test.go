/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package imr

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/cache"
	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// rootServerNames is the names of the servers under "." in the cache, sorted.
func rootServerNames(imr *Imr) []string {
	servers, _ := imr.Cache.ServerMapCopy(".")
	var names []string
	for _, s := range servers {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	return names
}

var rootStubNames = []string{"ns.private-root.test."}

func checkRootStub(t *testing.T, got []string, when string) {
	t.Helper()
	if !slices.Equal(got, rootStubNames) {
		t.Errorf("%s the root's servers are %v, want the stub's %v", when, got, rootStubNames)
	}
}

// rootStubRig is a resolver with a "." stub, and root hints that name one
// server: a fake root on loopback that answers through handler. It returns the
// resolver, its stub and the hints file.
func rootStubRig(t *testing.T, handler dns.HandlerFunc) (*Imr, StubConf, string) {
	t.Helper()
	restoreProcessWideTuning(t)
	port := startRefDouble(t, net.IPv4(127, 0, 0, 1), 0, handler)
	hints := filepath.Join(t.TempDir(), "root.hints")
	if err := os.WriteFile(hints, []byte(". 3600000 IN NS hints-root.test.\nhints-root.test. 3600000 IN A 127.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stub := StubConf{Zone: ".", Servers: []cache.AuthServer{{Name: rootStubNames[0], Addrs: []string{"192.0.2.53"}}}}
	ic := Config{RootHints: hints, Stubs: []StubConf{stub}, Options: map[Option]string{OptAllowLoopbackNameservers: "true"}}
	imr, err := New(context.Background(), ic, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	qminClients(imr, port)
	checkRootStub(t, rootServerNames(imr), "after New")
	return imr, stub, hints
}

// A configured "." stub is the root's servers. New installs it, and priming
// from the root hints at Start must not replace it with the hints' servers,
// nor may a reload that leaves the stub as it is. (When the stubs were
// installed after priming, the stub was the last word.)
func TestRootStubSurvivesPriming(t *testing.T) {
	imr, stub, _ := rootStubRig(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if r.Question[0].Qtype == dns.TypeNS && r.Question[0].Name == "." {
			m.Answer = []dns.RR{mustRR(t, ". 518400 IN NS hints-root.test.")}
			m.Extra = []dns.RR{mustRR(t, "hints-root.test. 518400 IN A 127.0.0.1")}
		}
		_ = w.WriteMsg(m)
	})

	if err := imr.primeFromHints(context.Background()); err != nil {
		t.Fatalf("priming: %v", err)
	}
	checkRootStub(t, rootServerNames(imr), "after priming")

	if _, err := imr.ReloadZones([]StubConf{stub}, nil); err != nil {
		t.Fatalf("ReloadZones: %v", err)
	}
	checkRootStub(t, rootServerNames(imr), "after an unchanged reload")
}

// failingRoot is a fake root that answers SERVFAIL. Before it answers, it
// records the root's servers as the resolver holds them at that moment, and,
// when hold is set, says on entered that it has a query and waits for hold to
// close.
type failingRoot struct {
	imr     atomic.Pointer[Imr]
	hold    chan struct{}
	entered chan struct{}
	mu      sync.Mutex
	seen    [][]string
}

func (f *failingRoot) serve(w dns.ResponseWriter, r *dns.Msg) {
	if imr := f.imr.Load(); imr != nil {
		names := rootServerNames(imr)
		f.mu.Lock()
		f.seen = append(f.seen, names)
		f.mu.Unlock()
	}
	if f.hold != nil {
		select {
		case f.entered <- struct{}{}:
		default:
		}
		<-f.hold
	}
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	_ = w.WriteMsg(m)
}

func (f *failingRoot) seenWhileAsked() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.seen)
}

// Priming that fails leaves a "." stub as the root's servers, and so does
// every moment of it: when the live ". NS" fetch fails after the hints are
// seeded, when the context ends before the fetch, and when a reload comes
// while the fetch waits. Start retries priming for as long as it fails, and
// lookups other than Query read the root's servers meanwhile.
func TestRootStubThroughFailedPriming(t *testing.T) {
	t.Run("the NS fetch fails", func(t *testing.T) {
		f := &failingRoot{}
		imr, _, _ := rootStubRig(t, f.serve)
		f.imr.Store(imr)
		if err := imr.primeFromHints(context.Background()); err == nil {
			t.Fatal("priming succeeded against a root that fails")
		}
		seen := f.seenWhileAsked()
		if len(seen) == 0 {
			t.Fatal("the fake root got no query")
		}
		for _, names := range seen {
			checkRootStub(t, names, "while the root was asked")
		}
		checkRootStub(t, rootServerNames(imr), "after priming failed")
	})

	t.Run("the context ends before the fetch", func(t *testing.T) {
		f := &failingRoot{}
		imr, _, _ := rootStubRig(t, f.serve)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := imr.primeFromHints(ctx); err == nil {
			t.Fatal("priming succeeded on a cancelled context")
		}
		checkRootStub(t, rootServerNames(imr), "after priming on a cancelled context")
	})

	t.Run("an unchanged reload while the fetch waits", func(t *testing.T) {
		f := &failingRoot{hold: make(chan struct{}), entered: make(chan struct{}, 1)}
		imr, stub, _ := rootStubRig(t, f.serve)
		f.imr.Store(imr)
		errc := make(chan error, 1)
		go func() { errc <- imr.primeFromHints(context.Background()) }()
		select {
		case <-f.entered:
		case <-time.After(5 * time.Second):
			close(f.hold)
			t.Fatal("the fake root got no query")
		}
		if _, err := imr.ReloadZones([]StubConf{stub}, nil); err != nil {
			t.Errorf("ReloadZones: %v", err)
		}
		checkRootStub(t, rootServerNames(imr), "after a reload while the priming fetch waited")
		close(f.hold)
		select {
		case err := <-errc:
			if err == nil {
				t.Fatal("priming succeeded against a root that fails")
			}
		case <-time.After(30 * time.Second):
			t.Fatal("priming did not return")
		}
		checkRootStub(t, rootServerNames(imr), "after priming failed")
	})
}

// RefreshRoot's re-primes from the hints leave a "." stub as the root's
// servers, whether the live ". NS" fetch that follows works or not: the
// re-prime once the root NS is gone, and priming once a reload removes a "."
// forward.
func TestRootStubThroughRootRefreshReprimes(t *testing.T) {
	f := &failingRoot{}
	imr, _, hints := rootStubRig(t, f.serve)
	failing := func(context.Context, map[string]*cache.AuthServer) (*core.RRset, error) {
		return nil, errors.New("no root server answered")
	}
	// New does not prime, so the cache holds no root NS.
	if imr.Cache.Get(".", dns.TypeNS) != nil {
		t.Fatal("the cache holds a root NS before priming")
	}
	imr.rootRefreshPass(context.Background(), hints, failing)
	checkRootStub(t, rootServerNames(imr), "after the re-prime once the root NS was gone")
	imr.primeRoot(context.Background(), hints, failing)
	checkRootStub(t, rootServerNames(imr), "after priming once the root forward was removed, its fetch failing")
}
