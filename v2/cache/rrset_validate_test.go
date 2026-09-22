/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"context"
	"crypto"
	"errors"
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
	// path. The signer is the owner's zone: one that could not hold the
	// owner is rejected as Bogus before any key is looked for.
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "data.chain.example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60},
		TypeCovered: dns.TypeA,
		Algorithm:   dns.RSASHA256,
		Labels:      3,
		OrigTtl:     60,
		Inception:   uint32(time.Now().Add(-1 * time.Hour).Unix()),
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()),
		KeyTag:      9999,
		SignerName:  "chain.example.",
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

// TestValidateDNSKEYs_BackfillsMissingDS is the regression test for the
// DS-backfill fix. To anchor a zone's DNSKEY the validator needs the zone's
// DS; pre-fix it only ever looked in the cache and, on a miss, returned
// Indeterminate without fetching — so a cold resolution of a signed child
// (whose DS was never cached, e.g. because the same server is authoritative
// for both parent and child, so no DS-bearing referral is ever emitted) could
// never validate. The fix fetches the missing DS on demand via the fetcher.
//
// This asserts the load-bearing behaviour: on a DS cache miss, ValidateDNSKEYs
// ASKS the fetcher for the DS at all. (The mock returns no DS, so the verdict
// stays Indeterminate — the point is purely that the fetch is attempted, which
// pre-fix it never was.)
func TestValidateDNSKEYs_BackfillsMissingDS(t *testing.T) {
	rrcache := NewRRsetCache(log.New(os.Stderr, "test ", 0), false, false)

	// Seed root servers so backfillDS can reach the fetcher (same
	// FindClosestKnownZone + ServerMap["."] path the DNSKEY fetch uses).
	rrcache.ServerMap.Set(".", map[string]*AuthServer{"a.root.": {}})

	const child = "falcon512-mayo2.pq.axfr.net."
	ksk := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: child, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=",
	}
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: child, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: dns.TypeDNSKEY,
		Algorithm:   dns.ED25519,
		Labels:      4,
		OrigTtl:     3600,
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()),
		KeyTag:      ksk.KeyTag(),
		SignerName:  child,
		Signature:   "AAAA",
	}
	dnskeyRRset := &core.RRset{
		Name:   child,
		Class:  dns.ClassINET,
		RRtype: dns.TypeDNSKEY,
		RRs:    []dns.RR{ksk},
		RRSIGs: []dns.RR{sig},
	}

	var askedDS bool
	fetcher := func(ctx context.Context, qname string, qtype uint16, servers map[string]*AuthServer) (*core.RRset, error) {
		if dns.Fqdn(qname) == child && qtype == dns.TypeDS {
			askedDS = true
		}
		return nil, nil // no DS returned; verdict stays Indeterminate
	}

	if _, err := rrcache.ValidateDNSKEYs(context.Background(), dnskeyRRset, fetcher); err != nil {
		t.Fatalf("ValidateDNSKEYs error: %v", err)
	}
	if !askedDS {
		t.Fatalf("ValidateDNSKEYs did not fetch the missing DS for %s on a cache miss — DS-backfill regression", child)
	}
}

// kidZone is a signed child, kid.sec.example., with one key that signs everything
// in it. The resolver does not hold the key: only a DS in sec.example. could make
// it trusted.
type kidZone struct {
	dnskey *core.RRset
	www    *core.RRset // www.kid.sec.example. A, signed
}

func newKidZone(t *testing.T) kidZone {
	t.Helper()
	ksk := &dns.DNSKEY{Hdr: dns.RR_Header{Name: secKid, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 257, Protocol: 3, Algorithm: dns.ED25519}
	priv, err := ksk.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	k := &zoneKey{zone: secKid, key: ksk, priv: priv.(crypto.Signer)}
	return kidZone{dnskey: k.sign(t, ksk), www: k.sign(t, rrFrom(t, kidWWW+" 300 IN A 192.0.2.7"))}
}

// kidInsecureNSEC is sec.example.'s NSEC at kid: a delegation with no DS.
func kidInsecureNSEC(t *testing.T, k *zoneKey) *core.RRset {
	return k.sign(t, rrFrom(t, secKid+" 300 IN NSEC "+secWWW+" NS RRSIG NSEC"))
}

// forwardedDSFetcher answers the DS question at kid as a forwarding IMR does
// (#702): forwardQuery hands the denial to handleNegative, which caches it with
// its verdict, and returns no RRset. The DNSKEY question gets kid's keys,
// unvalidated. It counts the DS questions.
func forwardedDSFetcher(t *testing.T, rrcache *RRsetCacheT, kid kidZone, denial []*core.RRset, dsQuestions *int) RRsetFetcher {
	return func(_ context.Context, qname string, qtype uint16, _ map[string]*AuthServer) (*core.RRset, error) {
		switch {
		case core.EqualNames(qname, secKid) && qtype == dns.TypeDS:
			*dsQuestions++
			seedDSDenial(t, rrcache, secKid, denial...)
			return nil, nil
		case core.EqualNames(qname, secKid) && qtype == dns.TypeDNSKEY:
			return kid.dnskey, nil
		}
		return nil, errors.New("no answer")
	}
}

// TestValidateDNSKEYs_SecureDSDenialIsInsecureCut is the regression for a
// forwarding IMR that SERVFAILs a signed child whose parent has no DS (#702).
// The parent's NSEC denial of DS validates Secure; ValidateDNSKEYs treated that
// cache entry as a DS RRset, found no matching DS, and marked the DNSKEYs Bogus
// (EDE 9). A denial of DS that proves an insecure delegation makes the zone
// Insecure, answered without AD.
func TestValidateDNSKEYs_SecureDSDenialIsInsecureCut(t *testing.T) {
	rrcache, k := secCache(t)
	seedDSDenial(t, rrcache, secKid, k.sign(t, soaFor(t, secZone)), kidInsecureNSEC(t, k))

	got, err := rrcache.ValidateDNSKEYs(context.Background(), newKidZone(t).dnskey, nil)
	if err != nil {
		t.Fatalf("ValidateDNSKEYs: %v", err)
	}
	if got != ValidationStateInsecure {
		t.Fatalf("got %s, want insecure: a secure denial of DS is a proven insecure cut, not EDE 9 bogus", ValidationStateToString[got])
	}
	if z, ok := rrcache.ZoneMap.Get(secKid); !ok || z.GetState() != ValidationStateInsecure {
		t.Fatalf("zone %s is not in ZoneMap as insecure", secKid)
	}
}

// The same denial, not yet cached: in forward mode no referral arrives, and the
// DS question is asked by backfillDS. Its fetch caches the denial and returns
// no RRset, and backfillDS used to return nil for it, so the first pass came out
// Indeterminate and only a second validation of the same keys found the proof.
func TestValidateDNSKEYs_FetchedDSDenialIsInsecureCut(t *testing.T) {
	rrcache, k := secCache(t)
	kid := newKidZone(t)
	var n int
	fetch := forwardedDSFetcher(t, rrcache, kid, []*core.RRset{k.sign(t, soaFor(t, secZone)), kidInsecureNSEC(t, k)}, &n)

	got, err := rrcache.ValidateDNSKEYs(context.Background(), kid.dnskey, fetch)
	if err != nil {
		t.Fatalf("ValidateDNSKEYs: %v", err)
	}
	if got != ValidationStateInsecure {
		t.Fatalf("got %s on the first pass, want insecure", ValidationStateToString[got])
	}
	if n != 1 {
		t.Errorf("%d DS question(s), want 1", n)
	}
	if z, ok := rrcache.ZoneMap.Get(secKid); !ok || z.GetState() != ValidationStateInsecure {
		t.Fatalf("zone %s is not in ZoneMap as insecure", secKid)
	}
}

// And from the data, validated once: the keys are fetched and judged in
// validateRRsetWithRRSIG with nothing validated before them.
func TestValidateRRset_SignedDataBelowAFetchedDSDenialIsInsecure(t *testing.T) {
	rrcache, k := secCache(t)
	kid := newKidZone(t)
	var n int
	fetch := forwardedDSFetcher(t, rrcache, kid, []*core.RRset{k.sign(t, soaFor(t, secZone)), kidInsecureNSEC(t, k)}, &n)

	got, err := rrcache.ValidateRRset(context.Background(), kid.www, fetch)
	if err != nil {
		t.Fatalf("ValidateRRset: %v", err)
	}
	if got != ValidationStateInsecure {
		t.Fatalf("got %s, want insecure", ValidationStateToString[got])
	}
}

// The parent side's denial of the DS at kid decides the zone, NSEC or NSEC3.
// Every NSEC3 denial validates Indeterminate, and ValidateDNSKEYs used to give
// the zone that state before looking at the proof: a signed child of an
// NSEC3-signed parent with no DS was SERVFAIL (EDE 5) through a forwarding IMR.
// A proof that does not show an insecure delegation, or does not validate,
// must leave the zone anything but Insecure.
func TestValidateDNSKEYs_DSDenialProofs(t *testing.T) {
	const optOut = 1
	cases := []struct {
		name     string
		denial   func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) []*core.RRset
		insecure bool
	}{
		{"NSEC3 at kid, NS and no DS", func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, nsec3In(secZone, secKid, false, 0, 0, dns.TypeNS))}
		}, true},
		{"NSEC3 Opt-Out span covering kid", func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, apexNSEC3(secZone)), k.sign(t, nsec3In(secZone, secKid, true, optOut, 0, dns.TypeA, dns.TypeRRSIG))}
		}, true},
		{"NSEC3 at kid, no NS", func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, nsec3In(secZone, secKid, false, 0, 0, dns.TypeA, dns.TypeRRSIG))}
		}, false},
		{"NSEC3 at kid, signed with a stray key", func(t *testing.T, _ *RRsetCacheT, _ *zoneKey) []*core.RRset {
			return []*core.RRset{strayKey(t, secZone).sign(t, nsec3In(secZone, secKid, false, 0, 0, dns.TypeNS))}
		}, false},
		{"NSEC3 at kid, signed by kid", func(t *testing.T, rrcache *RRsetCacheT, _ *zoneKey) []*core.RRset {
			return []*core.RRset{newZoneKey(t, rrcache, secKid, false).sign(t, nsec3In(secZone, secKid, false, 0, 0, dns.TypeNS))}
		}, false},
		{"NSEC at kid, no NS", func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, rrFrom(t, secKid+" 300 IN NSEC "+secWWW+" A RRSIG NSEC"))}
		}, false},
		{"NSEC at kid, signed with a stray key", func(t *testing.T, _ *RRsetCacheT, _ *zoneKey) []*core.RRset {
			return []*core.RRset{strayKey(t, secZone).sign(t, rrFrom(t, secKid+" 300 IN NSEC "+secWWW+" NS RRSIG NSEC"))}
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache, k := secCache(t)
			seedDSDenial(t, rrcache, secKid, append([]*core.RRset{k.sign(t, soaFor(t, secZone))}, c.denial(t, rrcache, k)...)...)

			got, err := rrcache.ValidateDNSKEYs(context.Background(), newKidZone(t).dnskey, nil)
			if err != nil {
				t.Fatalf("ValidateDNSKEYs: %v", err)
			}
			z, _ := rrcache.ZoneMap.Get(secKid)
			switch {
			case c.insecure && got != ValidationStateInsecure:
				t.Fatalf("got %s, want insecure", ValidationStateToString[got])
			case c.insecure && z.GetState() != ValidationStateInsecure:
				t.Fatalf("zone %s is not in ZoneMap as insecure", secKid)
			case !c.insecure && (got == ValidationStateInsecure || z.GetState() == ValidationStateInsecure):
				t.Fatalf("got %s (zone %s): the denial proves no insecure delegation", ValidationStateToString[got],
					ValidationStateToString[z.GetState()])
			}
		})
	}
}
