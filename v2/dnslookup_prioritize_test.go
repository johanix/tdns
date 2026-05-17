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
	"time"

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

// TestPrioritizeServers_RTTSortAcrossServers: when two servers are configured
// and one has a low recorded RTT while the other has a high recorded RTT, the
// fast server's tuples should be listed first.
func TestPrioritizeServers_RTTSortAcrossServers(t *testing.T) {
	imr := newTestImr(t)

	fast := cache.NewAuthServer("fast.example.")
	fast.SetAddrs([]string{"10.0.0.10:53"})
	fast.SetTransports([]core.Transport{core.TransportDo53})
	fast.SetTransportWeight(core.TransportDo53, 100)
	fast.RecordRTT("10.0.0.10:53", core.TransportDo53, 20*time.Millisecond)

	slow := cache.NewAuthServer("slow.example.")
	slow.SetAddrs([]string{"10.0.0.20:53"})
	slow.SetTransports([]core.Transport{core.TransportDo53})
	slow.SetTransportWeight(core.TransportDo53, 100)
	slow.RecordRTT("10.0.0.20:53", core.TransportDo53, 800*time.Millisecond)

	serverMap := map[string]*cache.AuthServer{
		"fast.example.": fast,
		"slow.example.": slow,
	}
	_, _, tuples := imr.prioritizeServers("q.example.", serverMap, false)
	if len(tuples) < 2 {
		t.Fatalf("expected at least 2 tuples, got %d", len(tuples))
	}
	if tuples[0].NSName != "fast.example." {
		t.Errorf("expected fast.example. first, got %q (tuples=%+v)", tuples[0].NSName, tuples)
	}
}

// TestPrioritizeServers_UnprobedSentinelOrdering: an unprobed tuple should
// land between a known-fast (<200ms) and a known-slow (>200ms) tuple.
func TestPrioritizeServers_UnprobedSentinelOrdering(t *testing.T) {
	imr := newTestImr(t)

	makeServer := func(nsname, addr string, rtt time.Duration, record bool) *cache.AuthServer {
		s := cache.NewAuthServer(nsname)
		s.SetAddrs([]string{addr})
		s.SetTransports([]core.Transport{core.TransportDo53})
		s.SetTransportWeight(core.TransportDo53, 100)
		if record {
			s.RecordRTT(addr, core.TransportDo53, rtt)
		}
		return s
	}
	fast := makeServer("fast.example.", "10.0.0.30:53", 20*time.Millisecond, true)
	slow := makeServer("slow.example.", "10.0.0.40:53", 800*time.Millisecond, true)
	unprobed := makeServer("new.example.", "10.0.0.50:53", 0, false)

	serverMap := map[string]*cache.AuthServer{
		"fast.example.": fast,
		"slow.example.": slow,
		"new.example.":  unprobed,
	}
	_, _, tuples := imr.prioritizeServers("q.example.", serverMap, false)
	if len(tuples) != 3 {
		t.Fatalf("expected 3 tuples, got %d (%+v)", len(tuples), tuples)
	}
	order := []string{tuples[0].NSName, tuples[1].NSName, tuples[2].NSName}
	want := []string{"fast.example.", "new.example.", "slow.example."}
	for i := range order {
		if order[i] != want[i] {
			t.Errorf("ordering: got %v, want %v", order, want)
			break
		}
	}
}

// TestPrioritizeServers_SuspectFamilyDeprioritized: when v6 is suspect,
// v4 tuples come first; v6 tuples appear only as the single probe at the
// back. Repeat: the probe quota is one per ProbeInterval.
func TestPrioritizeServers_SuspectFamilyDeprioritized(t *testing.T) {
	imr := newTestImr(t)
	// Mark v6 suspect right now.
	for i := 0; i < 5; i++ {
		imr.FamilyTracker.RecordResult("[2001:db8::1]:53", false)
	}
	if !imr.FamilyTracker.IsSuspect(cache.FamilyV6) {
		t.Fatal("setup: v6 should be suspect")
	}

	ns := "ns.example."
	s := cache.NewAuthServer(ns)
	s.SetAddrs([]string{"10.0.0.1:53", "[2001:db8::1]:53"})
	s.SetTransports([]core.Transport{core.TransportDo53})
	s.SetTransportWeight(core.TransportDo53, 100)
	serverMap := map[string]*cache.AuthServer{ns: s}

	_, _, tuples := imr.prioritizeServers("q.example.", serverMap, false)
	if len(tuples) < 1 {
		t.Fatal("expected at least the v4 tuple")
	}
	if tuples[0].Addr != "10.0.0.1:53" {
		t.Errorf("expected v4 first, got %q", tuples[0].Addr)
	}
	// First prioritizeServers call may have included one v6 probe at back.
	// A second call with no time elapsed must NOT include another v6 probe.
	_, _, tuples2 := imr.prioritizeServers("q.example.", serverMap, false)
	for _, tup := range tuples2 {
		if cache.FamilyOf(tup.Addr) == cache.FamilyV6 {
			t.Errorf("second call within ProbeInterval should not include any v6 tuple, got %+v", tup)
			break
		}
	}
}

// newTestImr returns a minimal Imr suitable for prioritizeServers tests.
// The cache is populated but no network clients are exercised. FamilyTracker
// uses sensible defaults; tests that need to drive specific suspect/probe
// behaviour replace the field after construction.
func newTestImr(t *testing.T) *Imr {
	t.Helper()
	lg := log.New(os.Stderr, "test", log.LstdFlags)
	c := cache.NewRRsetCache(lg, false, false)
	ft := cache.NewFamilyTracker(
		10*time.Minute, // window
		10*time.Minute, // suspect duration
		30*time.Second, // probe interval
		5,              // failure threshold
	)
	return &Imr{Cache: c, FamilyTracker: ft}
}
