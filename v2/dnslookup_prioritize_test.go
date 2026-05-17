/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"log"
	"os"
	"slices"
	"testing"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
)

// TestCandidateTransports_SinglePreferred: when only one transport is
// configured (and no weights), it is returned alone.
func TestCandidateTransports_SinglePreferred_Encrypted(t *testing.T) {
	s := cache.NewAuthServer("ns.example.")
	s.SetTransports([]core.Transport{core.TransportDoT})
	s.SetTransportWeight(core.TransportDoT, 100)

	got := candidateTransports(s, "example.", true /*requireEncrypted*/)
	want := []core.Transport{core.TransportDoT}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestCandidateTransports_Do53RemainderAdded: when configured weights don't
// sum to 100, the remainder is added as Do53 unless requireEncrypted.
func TestCandidateTransports_Do53RemainderAdded(t *testing.T) {
	s := cache.NewAuthServer("ns.example.")
	s.SetTransports([]core.Transport{core.TransportDoT})
	s.SetTransportWeight(core.TransportDoT, 30)

	got := candidateTransports(s, "example.", false)
	if !slices.Contains(got, core.TransportDo53) {
		t.Errorf("expected Do53 in candidates (weight remainder), got %v", got)
	}
	if !slices.Contains(got, core.TransportDoT) {
		t.Errorf("expected DoT in candidates, got %v", got)
	}
	if len(got) != 2 {
		t.Errorf("expected exactly 2 candidates, got %d (%v)", len(got), got)
	}
}

// TestCandidateTransports_EncryptedFiltersDo53: requireEncrypted excludes
// Do53 even when it would otherwise be in the candidates.
func TestCandidateTransports_EncryptedFiltersDo53(t *testing.T) {
	s := cache.NewAuthServer("ns.example.")
	s.SetTransports([]core.Transport{core.TransportDoT, core.TransportDo53})
	s.SetTransportWeight(core.TransportDoT, 50)
	s.SetTransportWeight(core.TransportDo53, 50)

	got := candidateTransports(s, "example.", true)
	for _, tr := range got {
		if !core.IsEncryptedTransport(tr) {
			t.Errorf("requireEncrypted=true but got unencrypted transport %v in %v", tr, got)
		}
	}
	if !slices.Contains(got, core.TransportDoT) {
		t.Errorf("expected DoT in candidates, got %v", got)
	}
}

// TestCandidateTransports_NoEncryptedReturnsNil: requireEncrypted=true on a
// server with no encrypted transports returns nil.
func TestCandidateTransports_NoEncryptedReturnsNil(t *testing.T) {
	s := cache.NewAuthServer("ns.example.")
	s.SetTransports([]core.Transport{core.TransportDo53})
	s.SetTransportWeight(core.TransportDo53, 100)

	got := candidateTransports(s, "example.", true)
	if len(got) != 0 {
		t.Errorf("expected nil/empty, got %v", got)
	}
}

// TestCandidateTransports_DeterministicHashFirst: the bucket-winning
// transport is returned first; the same (qname, server.Name) pair must
// produce the same first transport across calls.
func TestCandidateTransports_DeterministicHashFirst(t *testing.T) {
	s := cache.NewAuthServer("ns.example.")
	s.SetTransports([]core.Transport{core.TransportDoT, core.TransportDoH})
	s.SetTransportWeight(core.TransportDoT, 50)
	s.SetTransportWeight(core.TransportDoH, 50)

	first := candidateTransports(s, "alpha.example.", false)
	for i := 0; i < 5; i++ {
		again := candidateTransports(s, "alpha.example.", false)
		if !slices.Equal(first, again) {
			t.Fatalf("non-deterministic: first=%v again=%v", first, again)
		}
	}

	// Ensure both transports appear in the result somewhere — winner first
	// plus the loser in the fallback positions.
	if !slices.Contains(first, core.TransportDoT) || !slices.Contains(first, core.TransportDoH) {
		t.Errorf("expected both DoT and DoH in candidates, got %v", first)
	}
}

// TestPrioritizeServers_PerTransportBackoffFiltering: a failure on
// (addr, DoT) removes only that tuple from the prioritized list, not the
// (addr, Do53) tuple for the same address.
func TestPrioritizeServers_PerTransportBackoffFiltering(t *testing.T) {
	imr := newTestImr(t)

	const ns = "ns.example."
	const addr = "10.0.0.5:53"
	s := cache.NewAuthServer(ns)
	s.SetAddrs([]string{addr})
	s.SetTransports([]core.Transport{core.TransportDoT})
	s.SetTransportWeight(core.TransportDoT, 30) // Do53 remainder = 70

	// Baseline: both (addr, DoT) and (addr, Do53) should be in the list.
	serverMap := map[string]*cache.AuthServer{ns: s}
	_, _, tuples := imr.prioritizeServers("foo.example.", serverMap, false)
	if len(tuples) != 2 {
		t.Fatalf("baseline: expected 2 tuples (DoT + Do53), got %d (%+v)", len(tuples), tuples)
	}

	// Poison (addr, DoT). (addr, Do53) must remain.
	s.RecordAddressFailure(addr, core.TransportDoT, fmt.Errorf("dot handshake"))
	_, _, tuples = imr.prioritizeServers("foo.example.", serverMap, false)
	if len(tuples) != 1 {
		t.Fatalf("after DoT failure: expected 1 tuple (Do53 only), got %d (%+v)", len(tuples), tuples)
	}
	if tuples[0].Transport != core.TransportDo53 {
		t.Errorf("after DoT failure: surviving tuple should be Do53, got %v", tuples[0].Transport)
	}
}

// TestPrioritizeServers_RequireEncryptedFilters: with requireEncrypted, no
// Do53 tuple should be emitted.
func TestPrioritizeServers_RequireEncryptedFilters(t *testing.T) {
	imr := newTestImr(t)

	const ns = "ns.example."
	const addr = "10.0.0.6:53"
	s := cache.NewAuthServer(ns)
	s.SetAddrs([]string{addr})
	s.SetTransports([]core.Transport{core.TransportDoT, core.TransportDo53})
	s.SetTransportWeight(core.TransportDoT, 50)
	s.SetTransportWeight(core.TransportDo53, 50)

	serverMap := map[string]*cache.AuthServer{ns: s}
	_, _, tuples := imr.prioritizeServers("foo.example.", serverMap, true)
	for _, tup := range tuples {
		if tup.Transport == core.TransportDo53 {
			t.Errorf("requireEncrypted=true but Do53 tuple emitted: %+v", tup)
		}
	}
	if len(tuples) == 0 {
		t.Error("expected at least one encrypted tuple, got none")
	}
}

// newTestImr returns a minimal Imr suitable for prioritizeServers tests.
// The cache is populated but no network clients are exercised.
func newTestImr(t *testing.T) *Imr {
	t.Helper()
	lg := log.New(os.Stderr, "test", log.LstdFlags)
	c := cache.NewRRsetCache(lg, false, false)
	return &Imr{Cache: c}
}
