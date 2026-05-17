/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// TestValidator_ZeroStateNotReusedAsCachedVerdict is a regression test for
// the apex-NS-unset bug. The ValidationState enum starts at iota+1, so the
// Go zero value (0) is NOT ValidationStateNone (=1). A cache entry written
// without an explicit State field has State==0, which historically slipped
// past the validator's cache-reuse check (`cached.State != ValidationStateNone`)
// because 0 != 1, and the validator returned the garbage zero as if it were
// a real verdict.
//
// Concrete symptom from production: a signed NS RRset cached via the
// answer path with no State set up showed "[unset]" in dumps forever,
// because the next re-validation pass would Get() the entry, see State!=None
// (it was 0), and reuse the zero — never actually validating.
//
// After the fix the check is `cached.State > ValidationStateNone`, so any
// State value below "real validated verdict" forces a re-validate pass.
func TestValidator_ZeroStateNotReusedAsCachedVerdict(t *testing.T) {
	rrcache := NewRRsetCache(log.New(os.Stderr, "test ", 0), false, false)

	// Build a CachedRRset with the State field omitted (Go zero value = 0).
	// This mirrors what AuthDNSQuery did before the fix.
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: "zero.example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:      "ns.zero.example.",
		Mbox:    "hostmaster.zero.example.",
		Serial:  1, Refresh: 7200, Retry: 1800, Expire: 604800, Minttl: 60,
	}
	rrset := &core.RRset{
		Name:   "zero.example.",
		Class:  dns.ClassINET,
		RRtype: dns.TypeSOA,
		RRs:    []dns.RR{soa},
	}
	rrcache.Set("zero.example.", dns.TypeSOA, &CachedRRset{
		Name:       "zero.example.",
		RRtype:     dns.TypeSOA,
		RRset:      rrset,
		Context:    ContextAnswer,
		Expiration: time.Now().Add(time.Hour),
		// State NOT set — Go zero value (0) on purpose.
	})

	// Pre-fix: validator would return (0, nil) — reusing the garbage.
	// Post-fix: validator does NOT reuse a zero State; it falls through.
	// We can't fully drive validation here (no DNSKEYs, no fetcher), so we
	// rely on the indirect signal: the function must NOT return (0, nil)
	// from the cache-reuse fast path.
	got, err := rrcache.ValidateRRsetWithParentZone(context.Background(), rrset, nil, nil)
	if err == nil && got == 0 {
		t.Fatalf("validator returned (0, nil) from cache-reuse fast path on a State=0 entry — this is the bug")
	}
	// The post-fix path falls through; without a fetcher / DNSKEYs the
	// validator should reach a sensible terminal (Indeterminate / Insecure
	// / error) but specifically NOT the Go zero value (0).
	if got == 0 && err == nil {
		t.Errorf("validator should never return (0, nil); got state=%d err=%v", got, err)
	}
}

// TestValidator_ExplicitValidVerdictIsReused verifies the positive case:
// a cache entry with a real validated verdict (Secure / Insecure / Bogus /
// Indeterminate, all > ValidationStateNone) is reused by the validator on
// subsequent calls.
func TestValidator_ExplicitValidVerdictIsReused(t *testing.T) {
	rrcache := NewRRsetCache(log.New(os.Stderr, "test ", 0), false, false)

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: "secure.example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:      "ns.secure.example.",
		Mbox:    "hostmaster.secure.example.",
		Serial:  1, Refresh: 7200, Retry: 1800, Expire: 604800, Minttl: 60,
	}
	rrset := &core.RRset{
		Name:   "secure.example.",
		Class:  dns.ClassINET,
		RRtype: dns.TypeSOA,
		RRs:    []dns.RR{soa},
	}
	rrcache.Set("secure.example.", dns.TypeSOA, &CachedRRset{
		Name:       "secure.example.",
		RRtype:     dns.TypeSOA,
		RRset:      rrset,
		Context:    ContextAnswer,
		State:      ValidationStateSecure,
		Expiration: time.Now().Add(time.Hour),
	})

	got, err := rrcache.ValidateRRsetWithParentZone(context.Background(), rrset, nil, nil)
	if err != nil {
		t.Fatalf("expected reuse with nil error, got err=%v", err)
	}
	if got != ValidationStateSecure {
		t.Errorf("expected ValidationStateSecure reused from cache, got %v", got)
	}
}
