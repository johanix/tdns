/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"crypto"
	"log"
	"os"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A cached Indeterminate verdict is not an answer. It records that the chain
// could not be followed when the entry was made; once the key is available the
// same RRset must validate, not come back Indeterminate from the cache for the
// rest of its TTL.
func TestValidator_IndeterminateVerdictIsNotReused(t *testing.T) {
	rrcache := NewRRsetCache(log.New(os.Stderr, "test ", 0), false, false)
	rrcache.DnskeyCache = NewDnskeyCache()
	const zone = "reuse.example."

	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 256, Protocol: 3, Algorithm: dns.ED25519}
	priv, err := k.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	a := &dns.A{Hdr: dns.RR_Header{Name: "www." + zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}}
	sig := &dns.RRSIG{Algorithm: dns.ED25519, KeyTag: k.KeyTag(), SignerName: zone,
		Inception: uint32(time.Now().Add(-time.Hour).Unix()), Expiration: uint32(time.Now().Add(time.Hour).Unix())}
	if err := sig.Sign(priv.(crypto.Signer), []dns.RR{a}); err != nil {
		t.Fatal(err)
	}
	rrset := &core.RRset{Name: "www." + zone, Class: dns.ClassINET, RRtype: dns.TypeA, RRs: []dns.RR{a}, RRSIGs: []dns.RR{sig}}

	// Cached while the key was not available.
	rrcache.Set(rrset.Name, dns.TypeA, &CachedRRset{Name: rrset.Name, RRtype: dns.TypeA, RRset: rrset,
		Context: ContextAnswer, State: ValidationStateIndeterminate, Expiration: time.Now().Add(time.Hour)})

	// The key arrives.
	rrcache.DnskeyCache.Set(zone, k.KeyTag(), &CachedDnskeyRRset{Name: zone, Keyid: k.KeyTag(),
		State: ValidationStateSecure, Dnskey: *k, Expiration: time.Now().Add(time.Hour)})

	got, err := rrcache.ValidateRRsetWithParentZone(context.Background(), rrset, nil, nil)
	if err != nil {
		t.Fatalf("ValidateRRsetWithParentZone: %v", err)
	}
	if got != ValidationStateSecure {
		t.Fatalf("got %s, want secure: the cached Indeterminate verdict was reused instead of validating again",
			ValidationStateToString[got])
	}
}
