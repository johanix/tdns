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

// An Indeterminate zone state is a moment's verdict and must lapse; Secure and
// Insecure are not touched by this.
func TestZoneIndeterminateStateLapses(t *testing.T) {
	z := &Zone{ZoneName: "lapse.example.", State: ValidationStateIndeterminate}
	if got := z.GetState(); got != ValidationStateIndeterminate {
		t.Fatalf("fresh Indeterminate reads %s", ValidationStateToString[got])
	}
	z.stateSince = time.Now().Add(-ZoneIndeterminateRetry - time.Second)
	if got := z.GetState(); got != ValidationStateNone {
		t.Fatalf("Indeterminate older than %s reads %s, want none", ZoneIndeterminateRetry, ValidationStateToString[got])
	}

	for _, st := range []ValidationState{ValidationStateSecure, ValidationStateInsecure} {
		z := &Zone{ZoneName: "keep.example."}
		z.SetState(st)
		z.stateSince = time.Now().Add(-time.Hour)
		if got := z.GetState(); got != st {
			t.Errorf("%s lapsed to %s", ValidationStateToString[st], ValidationStateToString[got])
		}
	}
}

// THE DEFECT, through the validator. A zone marked Indeterminate while its key
// was unavailable stayed Indeterminate for good: validateRRsetWithRRSIG returns
// on that state before looking for a key, so the key arriving changed nothing.
func TestAZoneMarkedIndeterminateValidatesOnceTheStateLapses(t *testing.T) {
	rrcache := NewRRsetCache(log.New(os.Stderr, "test ", 0), false, false)
	rrcache.DnskeyCache = NewDnskeyCache()
	const zone = "gap.example."

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

	// The chain was unavailable, and the validator said so.
	z := &Zone{ZoneName: zone}
	z.SetState(ValidationStateIndeterminate)
	rrcache.ZoneMap.Set(zone, z)

	// The key becomes available.
	rrcache.DnskeyCache.Set(zone, k.KeyTag(), &CachedDnskeyRRset{Name: zone, Keyid: k.KeyTag(),
		State: ValidationStateSecure, Dnskey: *k, Expiration: time.Now().Add(time.Hour)})

	// While the state stands, the validator does not look (that is the point
	// of recording it).
	if got, _ := rrcache.ValidateRRsetWithParentZone(context.Background(), rrset, nil, nil); got != ValidationStateIndeterminate {
		t.Fatalf("within the retry interval: got %s, want indeterminate", ValidationStateToString[got])
	}

	// Once it lapses, it does.
	z.mu.Lock()
	z.stateSince = time.Now().Add(-ZoneIndeterminateRetry - time.Second)
	z.mu.Unlock()
	got, err := rrcache.ValidateRRsetWithParentZone(context.Background(), rrset, nil, nil)
	if err != nil {
		t.Fatalf("ValidateRRsetWithParentZone: %v", err)
	}
	if got != ValidationStateSecure {
		t.Fatalf("after the retry interval: got %s, want secure -- the zone stayed Indeterminate for good",
			ValidationStateToString[got])
	}
}
