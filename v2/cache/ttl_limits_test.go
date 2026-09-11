/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cache

import (
	"log"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// withTTLLimits installs limits for one test and restores the previous ones:
// they are process-wide, and every other test in the package runs without.
func withTTLLimits(t *testing.T, l TTLLimits) {
	t.Helper()
	prev := GetTTLLimits()
	SetTTLLimits(l)
	t.Cleanup(func() { SetTTLLimits(prev) })
}

// nearTTL allows for RemainingTTL rounding a sub-second remainder down.
func nearTTL(got, want uint32) bool { return got == want || got+1 == want }

func TestTTLLimitsClamp(t *testing.T) {
	cases := []struct {
		name     string
		l        TTLLimits
		ttl, out uint32
	}{
		{"no limits", TTLLimits{}, 604800, 604800},
		{"no limits, zero", TTLLimits{}, 0, 0},
		{"capped", TTLLimits{Max: 86400}, 604800, 86400},
		{"under the cap", TTLLimits{Max: 86400}, 300, 300},
		{"floored", TTLLimits{Min: 60}, 5, 60},
		{"floor raises zero", TTLLimits{Min: 60}, 0, 60},
		{"between", TTLLimits{Min: 60, Max: 86400}, 300, 300},
		{"max wins over min", TTLLimits{Min: 7200, Max: 3600}, 5, 3600},
	}
	for _, c := range cases {
		if got := c.l.Clamp(c.ttl); got != c.out {
			t.Errorf("%s: Clamp(%d) with %+v = %d, want %d", c.name, c.ttl, c.l, got, c.out)
		}
	}
}

// Every network-learned context is bounded, positive and negative, whether the
// lifetime comes from the records or from the caller; hints and trust-anchor
// seeds are not.
func TestSetBoundsNetworkLearnedEntries(t *testing.T) {
	withTTLLimits(t, TTLLimits{Min: 60, Max: 3600})
	rrcache := NewRRsetCache(log.Default(), false, false)

	withRecord := func(name string, ttl uint32, ctx CacheContext) *CachedRRset {
		t.Helper()
		rr := &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: []byte{192, 0, 2, 1}}
		rrcache.Set(name, dns.TypeA, &CachedRRset{
			Name:    name,
			RRtype:  dns.TypeA,
			RRset:   &core.RRset{Name: name, Class: dns.ClassINET, RRtype: dns.TypeA, RRs: []dns.RR{rr}},
			Context: ctx,
		})
		c := rrcache.Get(name, dns.TypeA)
		if c == nil {
			t.Fatalf("%s: entry not cached", name)
		}
		return c
	}

	cases := []struct {
		name string
		ttl  uint32
		ctx  CacheContext
		want uint32
	}{
		{"long.example.", 604800, ContextAnswer, 3600},
		{"short.example.", 5, ContextAnswer, 60},
		{"within.example.", 300, ContextAnswer, 300},
		{"referral.example.", 604800, ContextReferral, 3600},
		{"glue.example.", 604800, ContextGlue, 3600},
		{"hint.example.", 3600000, ContextHint, 3600000},
		{"seed.example.", 5, ContextPriming, 5},
	}
	for _, c := range cases {
		e := withRecord(c.name, c.ttl, c.ctx)
		if got := e.RemainingTTL(time.Now()); !nearTTL(got, c.want) {
			t.Errorf("%s (%s, TTL %d): remaining lifetime %d, want %d", c.name, CacheContextToString[c.ctx], c.ttl, got, c.want)
		}
		// What a client is handed follows the entry, not the stored record.
		if got := e.ServeAnswer(time.Now(), false)[0].Header().Ttl; !nearTTL(got, c.want) {
			t.Errorf("%s: served TTL %d, want %d", c.name, got, c.want)
		}
		if got := e.RRset.RRs[0].Header().Ttl; got != c.ttl {
			t.Errorf("%s: stored record's TTL rewritten to %d, want the original %d", c.name, got, c.ttl)
		}
	}

	// Negative entries without an RRset carry the lifetime their caller chose.
	neg := func(name string, e *CachedRRset) uint32 {
		t.Helper()
		e.Name, e.RRtype, e.Rcode, e.Context = name, dns.TypeA, uint8(dns.RcodeNameError), ContextNXDOMAIN
		rrcache.Set(name, dns.TypeA, e)
		c := rrcache.Get(name, dns.TypeA)
		if c == nil {
			t.Fatalf("%s: negative entry not cached", name)
		}
		return c.RemainingTTL(time.Now())
	}
	if got := neg("nx-long.example.", &CachedRRset{Expiration: time.Now().Add(48 * time.Hour)}); !nearTTL(got, 3600) {
		t.Errorf("negative entry with a 48h expiration: remaining %d, want 3600", got)
	}
	if got := neg("nx-short.example.", &CachedRRset{Ttl: 10}); !nearTTL(got, 60) {
		t.Errorf("negative entry with Ttl 10: remaining %d, want 60", got)
	}
}

func TestSetWithoutLimitsKeepsTheRecordTTL(t *testing.T) {
	withTTLLimits(t, TTLLimits{})
	rrcache := NewRRsetCache(log.Default(), false, false)
	rr := &dns.A{Hdr: dns.RR_Header{Name: "week.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 604800}, A: []byte{192, 0, 2, 1}}
	rrcache.Set("week.example.", dns.TypeA, &CachedRRset{
		RRset:   &core.RRset{Name: "week.example.", RRtype: dns.TypeA, RRs: []dns.RR{rr}},
		Context: ContextAnswer,
	})
	if got := rrcache.Get("week.example.", dns.TypeA).RemainingTTL(time.Now()); !nearTTL(got, 604800) {
		t.Errorf("remaining %d, want 604800: no limits were set", got)
	}
}

// A validated key must not outlive the capped DNSKEY RRset it came from; a
// trust anchor is configuration and keeps its lifetime.
func TestDnskeyCacheBoundsLearnedKeysNotTrustAnchors(t *testing.T) {
	withTTLLimits(t, TTLLimits{Max: 3600})
	dkc := NewDnskeyCache()
	now := time.Now()
	dkc.Set("example.", 1, &CachedDnskeyRRset{Name: "example.", Keyid: 1, Expiration: now.Add(7 * 24 * time.Hour)})
	dkc.Set("example.", 2, &CachedDnskeyRRset{Name: "example.", Keyid: 2, TrustAnchor: true, Expiration: now.Add(365 * 24 * time.Hour)})

	if k := dkc.Get("example.", 1); k == nil || k.Expiration.Sub(now) > 3601*time.Second {
		t.Errorf("learned key: %+v, want an expiry within 3600s", k)
	}
	if k := dkc.Get("example.", 2); k == nil || k.Expiration.Sub(now) < 364*24*time.Hour {
		t.Errorf("trust anchor: %+v, want its configured one-year expiry", k)
	}
}

func TestStoreTLSAForServerIsBounded(t *testing.T) {
	withTTLLimits(t, TTLLimits{Max: 3600})
	rrcache := NewRRsetCache(log.Default(), false, false)
	rr, err := dns.NewRR("_853._tcp.ns1.example. 604800 IN TLSA 3 1 1 " +
		"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	if err != nil {
		t.Fatal(err)
	}
	rrcache.StoreTLSAForServer("ns1.example.", "_853._tcp.ns1.example.",
		&core.RRset{Name: "_853._tcp.ns1.example.", RRtype: dns.TypeTLSA, RRs: []dns.RR{rr}}, ValidationStateSecure)
	c := rrcache.LookupTLSAForServer("ns1.example.", "_853._tcp.ns1.example.")
	if c == nil {
		t.Fatal("TLSA not stored")
	}
	if got := c.RemainingTTL(time.Now()); !nearTTL(got, 3600) {
		t.Errorf("TLSA pin remaining %d, want 3600", got)
	}
}
