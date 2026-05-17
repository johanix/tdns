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
		Hdr:    dns.RR_Header{Name: "zero.example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:     "ns.zero.example.",
		Mbox:   "hostmaster.zero.example.",
		Serial: 1, Refresh: 7200, Retry: 1800, Expire: 604800, Minttl: 60,
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

// TestValidator_ChainUnavailableReturnsIndeterminate verifies the
// bogus-vs-indeterminate semantic split. An RRset with an RRSIG whose
// signer DNSKEY is not in cache (and cannot be fetched — ctx == nil)
// must yield Indeterminate (chain unavailable, no verify was attempted),
// NOT Bogus (which means "we had the keys and the sig failed").
//
// Regression: pre-fix, this case fell through both inner validation
// returns as ValidationStateNone and the outer loop's terminal branch
// reported Bogus regardless of why each sig failed, slandering legit
// data whenever the chain was momentarily unreachable (e.g. async
// revalidation racing the foreground W2 budget).
func TestValidator_ChainUnavailableReturnsIndeterminate(t *testing.T) {
	rrcache := NewRRsetCache(log.New(os.Stderr, "test ", 0), false, false)

	a := &dns.A{
		Hdr: dns.RR_Header{Name: "data.chain.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
	}
	// Real-looking RRSIG with a signer we have no DNSKEY for. ctx=nil
	// below prevents the validator from attempting to fetch the missing
	// DNSKEY, so we deterministically land on the "chain unavailable"
	// path.
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "data.chain.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60},
		TypeCovered: dns.TypeA,
		Algorithm:   dns.RSASHA256,
		Labels:      3,
		OrigTtl:     60,
		Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()),
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()),
		KeyTag:      9999,
		SignerName:  "unknown.example.",
		Signature:   "AAAA", // irrelevant for this test path
	}
	rrset := &core.RRset{
		Name:   "data.chain.example.",
		Class:  dns.ClassINET,
		RRtype: dns.TypeA,
		RRs:    []dns.RR{a},
		RRSIGs: []dns.RR{sig},
	}

	got, err := rrcache.ValidateRRsetWithParentZone(context.TODO(), rrset, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != ValidationStateIndeterminate {
		t.Errorf("chain-unavailable case: got %s, want %s — chain failures must not be reported as Bogus",
			ValidationStateToString[got], ValidationStateToString[ValidationStateIndeterminate])
	}
}

// TestValidator_VerifyFailedReturnsBogus verifies the other side of the
// split: when the signer DNSKEY IS available and sig.Verify() fails,
// the outer loop must report Bogus (a real verification failure).
func TestValidator_VerifyFailedReturnsBogus(t *testing.T) {
	rrcache := NewRRsetCache(log.New(os.Stderr, "test ", 0), false, false)

	a := &dns.A{
		Hdr: dns.RR_Header{Name: "data.verify.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
	}
	// Stash a Secure DNSKEY in DnskeyCache for the signer. The RRSIG's
	// signature bytes won't match this key, so sig.Verify() will return
	// an error — the "actually failed" path.
	const signer = "verify.example."
	const keyTag uint16 = 1234
	dnskey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: signer, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 60},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: "AwEAAaXfPp1qvNNgPlxOmZc6sN+nrJaP7p1Z3iY5C8w1lLPZbAuc1bC7s4FW", // arbitrary
	}
	dkc := rrcache.DnskeyCache
	dkc.Set(signer, keyTag, &CachedDnskeyRRset{
		Name:       signer,
		Keyid:      keyTag,
		State:      ValidationStateSecure,
		Dnskey:     *dnskey,
		Expiration: time.Now().Add(time.Hour),
	})

	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "data.verify.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60},
		TypeCovered: dns.TypeA,
		Algorithm:   dns.RSASHA256,
		Labels:      3,
		OrigTtl:     60,
		Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()),
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()),
		KeyTag:      keyTag,
		SignerName:  signer,
		Signature:   "AAAA",
	}
	rrset := &core.RRset{
		Name:   "data.verify.example.",
		Class:  dns.ClassINET,
		RRtype: dns.TypeA,
		RRs:    []dns.RR{a},
		RRSIGs: []dns.RR{sig},
	}

	got, err := rrcache.ValidateRRsetWithParentZone(context.TODO(), rrset, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != ValidationStateBogus {
		t.Errorf("verify-failed case: got %s, want %s — real sig.Verify() failure must report Bogus",
			ValidationStateToString[got], ValidationStateToString[ValidationStateBogus])
	}
}

// TestValidator_ExplicitValidVerdictIsReused verifies the positive case:
// a cache entry with a real validated verdict (Secure / Insecure / Bogus /
// Indeterminate, all > ValidationStateNone) is reused by the validator on
// subsequent calls.
func TestValidator_ExplicitValidVerdictIsReused(t *testing.T) {
	rrcache := NewRRsetCache(log.New(os.Stderr, "test ", 0), false, false)

	soa := &dns.SOA{
		Hdr:    dns.RR_Header{Name: "secure.example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:     "ns.secure.example.",
		Mbox:   "hostmaster.secure.example.",
		Serial: 1, Refresh: 7200, Retry: 1800, Expire: 604800, Minttl: 60,
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
