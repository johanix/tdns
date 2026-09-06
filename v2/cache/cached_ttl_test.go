/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cache

import (
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return rr
}

// THE REGRESSION. An entry cached with a 900-second TTL and 300 seconds
// already elapsed must be served with 600, not 900. Serving the original TTL
// re-arms every downstream cache on every fetch, so the record's effective
// lifetime never ends.
func TestServeAnswerDecrementsTTL(t *testing.T) {
	now := time.Now()
	soa := mustRR(t, "example. 900 IN SOA ns1.example. hostmaster.example. 1 7200 1800 604800 900")
	c := &CachedRRset{
		Name:       "example.",
		RRtype:     dns.TypeSOA,
		RRset:      &core.RRset{Name: "example.", RRtype: dns.TypeSOA, RRs: []dns.RR{soa}},
		Expiration: now.Add(600 * time.Second),
	}

	out := c.ServeAnswer(now, false)
	if len(out) != 1 {
		t.Fatalf("got %d records, want 1", len(out))
	}
	if got := out[0].Header().Ttl; got != 600 {
		t.Errorf("served TTL = %d, want 600 -- the entry has 600s left of its 900s lifetime", got)
	}
}

// Serving must not edit the cache. The records are shared with every later
// reader, so rewriting the TTL in place would make the entry decay by one
// serve's elapsed time on each hit, and race with concurrent readers besides.
func TestServeAnswerDoesNotMutateTheCachedRecords(t *testing.T) {
	now := time.Now()
	a := mustRR(t, "host.example. 300 IN A 192.0.2.1")
	c := &CachedRRset{
		Name:       "host.example.",
		RRtype:     dns.TypeA,
		RRset:      &core.RRset{Name: "host.example.", RRtype: dns.TypeA, RRs: []dns.RR{a}},
		Expiration: now.Add(120 * time.Second),
	}

	out := c.ServeAnswer(now, false)
	if got := out[0].Header().Ttl; got != 120 {
		t.Fatalf("served TTL = %d, want 120", got)
	}
	if got := c.RRset.RRs[0].Header().Ttl; got != 300 {
		t.Errorf("cached record's TTL is now %d, want the stored 300 -- serving rewrote the cache", got)
	}
	// And the returned slice must not share backing storage with the cache.
	out[0].Header().Ttl = 7
	if got := c.RRset.RRs[0].Header().Ttl; got != 300 {
		t.Errorf("editing the served record changed the cached one (TTL %d); the caller was handed the cache's own records", got)
	}
}

// Signatures travel with the records they cover, at the same remaining TTL.
func TestServeAnswerCarriesSignaturesAtTheSameTTL(t *testing.T) {
	now := time.Now()
	a := mustRR(t, "host.example. 300 IN A 192.0.2.1")
	sig := mustRR(t, "host.example. 300 IN RRSIG A 15 2 300 20260101000000 20250101000000 12345 example. AAAA")
	c := &CachedRRset{
		Name:       "host.example.",
		RRtype:     dns.TypeA,
		RRset:      &core.RRset{Name: "host.example.", RRtype: dns.TypeA, RRs: []dns.RR{a}, RRSIGs: []dns.RR{sig}},
		Expiration: now.Add(60 * time.Second),
	}

	out := c.ServeAnswer(now, true)
	if len(out) != 2 {
		t.Fatalf("got %d records, want the A and its RRSIG", len(out))
	}
	for _, rr := range out {
		if rr.Header().Ttl != 60 {
			t.Errorf("%s served with TTL %d, want 60", dns.TypeToString[rr.Header().Rrtype], rr.Header().Ttl)
		}
	}
}

// An entry within a second of eviction is served with TTL 0: usable now, do
// not cache. Rounding up would hand out a lifetime the entry itself no longer
// has.
func TestRemainingTTLFloorsAtZeroAndRoundsDown(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name string
		left time.Duration
		want uint32
	}{
		{"whole seconds", 45 * time.Second, 45},
		{"rounds down", 45900 * time.Millisecond, 45},
		{"under a second", 400 * time.Millisecond, 0},
		{"already expired", -5 * time.Second, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &CachedRRset{Expiration: now.Add(tc.left)}
			if got := c.RemainingTTL(now); got != tc.want {
				t.Errorf("RemainingTTL = %d, want %d", got, tc.want)
			}
		})
	}
}

// A negative entry carries no RRset of its own to serve; the proof lives in
// NegAuthority and is appended by the caller.
func TestServeAnswerOnAnEntryWithNoRRset(t *testing.T) {
	c := &CachedRRset{Expiration: time.Now().Add(time.Minute)}
	if out := c.ServeAnswer(time.Now(), true); out != nil {
		t.Errorf("got %d records from an entry with no RRset, want none", len(out))
	}
}
