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

// A trust anchor's key is also a key in the zone's DNSKEY RRset, and every
// fetch of that RRset stores the key again with the RRset's TTL. Storing it
// again must refresh the key, not end the anchor.
func TestDnskeyCacheTrustAnchorSurvivesRecaching(t *testing.T) {
	withTTLLimits(t, TTLLimits{})
	dkc := NewDnskeyCache()
	now := time.Now()
	dkc.Set(".", 7, &CachedDnskeyRRset{Name: ".", Keyid: 7, State: ValidationStateSecure,
		TrustAnchor: true, Expiration: now.Add(365 * 24 * time.Hour)})

	// What a DNSKEY RRset refresh writes: the RRset's TTL, and no flag.
	dkc.Set(".", 7, &CachedDnskeyRRset{Name: ".", Keyid: 7, State: ValidationStateSecure,
		Expiration: now.Add(900 * time.Second)})

	k := dkc.Get(".", 7)
	if k == nil || !k.TrustAnchor {
		t.Fatalf("after re-caching: %+v, want the key still flagged as a trust anchor", k)
	}
	if k.Expiration.Sub(now) < 364*24*time.Hour {
		t.Errorf("after re-caching: anchor expires %v, want its configured one-year lifetime", k.Expiration)
	}
}

// A trust anchor is configuration: Get must return it whatever its
// Expiration says. The truststore loader stores anchors with no Expiration at
// all, which a Get that honoured it would discard on first use.
func TestDnskeyCacheTrustAnchorDoesNotExpire(t *testing.T) {
	dkc := NewDnskeyCache()
	dkc.Set("zero.example.", 1, &CachedDnskeyRRset{Name: "zero.example.", Keyid: 1, State: ValidationStateSecure, TrustAnchor: true})
	dkc.Set("past.example.", 2, &CachedDnskeyRRset{Name: "past.example.", Keyid: 2, State: ValidationStateSecure, TrustAnchor: true,
		Expiration: time.Now().Add(-time.Hour)})
	dkc.Set("learned.example.", 3, &CachedDnskeyRRset{Name: "learned.example.", Keyid: 3, State: ValidationStateSecure,
		Expiration: time.Now().Add(-time.Hour)})

	if dkc.Get("zero.example.", 1) == nil {
		t.Error("trust anchor with no Expiration was discarded")
	}
	if dkc.Get("past.example.", 2) == nil {
		t.Error("trust anchor past its Expiration was discarded")
	}
	if dkc.Get("learned.example.", 3) != nil {
		t.Error("an expired learned key is still returned")
	}
}

// The resolver-level failure: a root anchored only by a configured DNSKEY
// validates its DNSKEY RRset once, and on every later fetch after the RRset's
// TTL has run out. TTL 0 makes "later" the very next call.
//
// Before the fix the second fetch found the key expired, read it back through
// Get (which deleted it), stored it again without the TrustAnchor flag, and the
// third fetch had no anchor left: Indeterminate, which the caller then writes
// into ZoneMap for good.
func TestValidateDNSKEYs_TrustAnchorSurvivesDNSKEYRefresh(t *testing.T) {
	withTTLLimits(t, TTLLimits{})
	rrcache := NewRRsetCache(log.New(os.Stderr, "test ", 0), false, false)
	rrcache.DnskeyCache = NewDnskeyCache() // not the process-wide one
	rrcache.ZoneMap.Set(".", &Zone{ZoneName: ".", State: ValidationStateSecure})

	ksk := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 0},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ED25519,
	}
	priv, err := ksk.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	zsk := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 0},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.ED25519,
	}
	if _, err := zsk.Generate(256); err != nil {
		t.Fatal(err)
	}

	rrcache.DnskeyCache.Set(".", ksk.KeyTag(), &CachedDnskeyRRset{
		Name: ".", Keyid: ksk.KeyTag(), State: ValidationStateSecure, TrustAnchor: true,
		Dnskey: *ksk, Expiration: time.Now().Add(365 * 24 * time.Hour),
	})

	// A fresh RRset per fetch, as off the wire: validation caps TTLs in place.
	fetch := func() *core.RRset {
		k, z := *ksk, *zsk
		rrs := []dns.RR{&k, &z}
		sig := &dns.RRSIG{
			Algorithm:  dns.ED25519,
			KeyTag:     ksk.KeyTag(),
			SignerName: ".",
			Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
			Expiration: uint32(time.Now().Add(24 * time.Hour).Unix()),
		}
		if err := sig.Sign(priv.(crypto.Signer), rrs); err != nil {
			t.Fatal(err)
		}
		return &core.RRset{Name: ".", Class: dns.ClassINET, RRtype: dns.TypeDNSKEY, RRs: rrs, RRSIGs: []dns.RR{sig}}
	}

	for i := 1; i <= 3; i++ {
		got, err := rrcache.ValidateDNSKEYs(context.Background(), fetch(), nil)
		if err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
		if got != ValidationStateSecure {
			t.Fatalf("fetch %d: %s, want %s: the trust anchor did not survive the DNSKEY RRset expiring",
				i, ValidationStateToString[got], ValidationStateToString[ValidationStateSecure])
		}
		time.Sleep(time.Millisecond) // past the TTL-0 expiry of what was just cached
	}
	if k := rrcache.DnskeyCache.Get(".", ksk.KeyTag()); k == nil || !k.TrustAnchor {
		t.Errorf("root KSK after three fetches: %+v, want it still a trust anchor", k)
	}
}
