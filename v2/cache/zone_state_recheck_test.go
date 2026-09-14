/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"crypto"
	"io"
	"log"
	"net"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// chain636 is a signed parent and a signed child below it, in the shape of
// #636: the resolver holds the child Insecure, from a delegation it saw without
// a DS, and the parent may since have published one.
type chain636 struct {
	rrcache       *RRsetCacheT
	parent, child string
	dsRRset       *core.RRset // the child's DS, signed by the parent
	dnskeyRRset   *core.RRset // the child's DNSKEY RRset, signed by the child
	www           *core.RRset // data in the child, signed by the child
	publishDS     bool        // whether the parent answers a DS query with dsRRset
	dsQueries     int
}

func sign636(t *testing.T, key *dns.DNSKEY, priv crypto.PrivateKey, rrs ...dns.RR) *core.RRset {
	t.Helper()
	sig := &dns.RRSIG{Algorithm: key.Algorithm, KeyTag: key.KeyTag(), SignerName: key.Hdr.Name,
		Inception: uint32(time.Now().Add(-time.Hour).Unix()), Expiration: uint32(time.Now().Add(time.Hour).Unix())}
	if err := sig.Sign(priv.(crypto.Signer), rrs); err != nil {
		t.Fatal(err)
	}
	h := rrs[0].Header()
	return &core.RRset{Name: h.Name, Class: dns.ClassINET, RRtype: h.Rrtype, RRs: rrs, RRSIGs: []dns.RR{sig}}
}

func newChain636(t *testing.T) *chain636 {
	t.Helper()
	c := &chain636{
		rrcache: NewRRsetCache(log.New(io.Discard, "", 0), false, false),
		parent:  "p636.example.",
		child:   "c.p636.example.",
	}
	c.rrcache.DnskeyCache = NewDnskeyCache()
	// Somewhere to send queries to; the fetcher answers them.
	c.rrcache.ServerMap.Set(".", map[string]*AuthServer{"a.root.": {}})

	newKey := func(zone string, flags uint16) (*dns.DNSKEY, crypto.PrivateKey) {
		k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
			Flags: flags, Protocol: 3, Algorithm: dns.ED25519}
		priv, err := k.Generate(256)
		if err != nil {
			t.Fatal(err)
		}
		return k, priv
	}

	// The parent is Secure, with its key validated.
	pk, ppriv := newKey(c.parent, 256)
	c.rrcache.DnskeyCache.Set(c.parent, pk.KeyTag(), &CachedDnskeyRRset{Name: c.parent, Keyid: pk.KeyTag(),
		State: ValidationStateSecure, Dnskey: *pk, Expiration: time.Now().Add(time.Hour)})
	pz := &Zone{ZoneName: c.parent}
	pz.SetState(ValidationStateSecure)
	c.rrcache.ZoneMap.Set(c.parent, pz)

	// The child signs its DNSKEY RRset and its data with one KSK.
	ck, cpriv := newKey(c.child, 257)
	c.dnskeyRRset = sign636(t, ck, cpriv, ck)
	c.www = sign636(t, ck, cpriv, &dns.A{
		Hdr: dns.RR_Header{Name: "www." + c.child, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.36"),
	})
	c.dsRRset = sign636(t, pk, ppriv, ck.ToDS(dns.SHA256))
	return c
}

func (c *chain636) fetcher() RRsetFetcher {
	return func(ctx context.Context, qname string, qtype uint16, servers map[string]*AuthServer) (*core.RRset, error) {
		if !core.EqualNames(qname, c.child) {
			return nil, nil
		}
		switch qtype {
		case dns.TypeDS:
			c.dsQueries++
			if c.publishDS {
				return c.dsRRset, nil
			}
		case dns.TypeDNSKEY:
			return c.dnskeyRRset, nil
		}
		return nil, nil
	}
}

// holdChildInsecure records the child as Insecure, a state that has stood for age.
func (c *chain636) holdChildInsecure(age time.Duration) *Zone {
	z := &Zone{ZoneName: c.child}
	z.SetState(ValidationStateInsecure)
	z.stateSince = time.Now().Add(-age)
	c.rrcache.ZoneMap.Set(c.child, z)
	return z
}

// THE DEFECT (#636), at the DS. A DS for a child held Insecure was checked
// against the child's state rather than its parent's, so the parent's signature
// was never looked at and the DS came back Insecure however valid it was.
func TestADSForAnInsecureChildValidatesAgainstItsParent(t *testing.T) {
	c := newChain636(t)
	z := c.holdChildInsecure(0)

	got, err := c.rrcache.ValidateRRset(context.Background(), c.dsRRset, nil)
	if err != nil {
		t.Fatalf("ValidateRRset: %v", err)
	}
	if got != ValidationStateSecure {
		t.Fatalf("a DS signed by the secure parent validated %s, want secure", ValidationStateToString[got])
	}
	if st := z.GetState(); st != ValidationStateSecure {
		t.Errorf("the child is %s after its DS validated, want secure", ValidationStateToString[st])
	}
}

// THE DEFECT (#636), through the validator. A signed child held Insecure stays
// Insecure while the state stands. Once it has stood for ZoneStateRecheck, the
// next signature checked from the child has the parent asked for a DS; the
// parent now publishes one, so the child's data validates.
func TestAnInsecureZoneBecomesSecureOnceItsParentPublishesADS(t *testing.T) {
	c := newChain636(t)
	z := c.holdChildInsecure(0)
	c.publishDS = true

	got, err := c.rrcache.ValidateRRset(context.Background(), c.www, c.fetcher())
	if err != nil {
		t.Fatalf("ValidateRRset: %v", err)
	}
	if got != ValidationStateInsecure || c.dsQueries != 0 {
		t.Fatalf("within the interval: got %s after %d DS queries, want insecure after none",
			ValidationStateToString[got], c.dsQueries)
	}

	z.stateSince = time.Now().Add(-ZoneStateRecheck() - time.Second)
	got, err = c.rrcache.ValidateRRset(context.Background(), c.www, c.fetcher())
	if err != nil {
		t.Fatalf("ValidateRRset: %v", err)
	}
	if got != ValidationStateSecure {
		t.Fatalf("after the interval: got %s, want secure -- the zone stayed Insecure for good",
			ValidationStateToString[got])
	}
	if c.dsQueries != 1 {
		t.Errorf("%d DS queries, want 1", c.dsQueries)
	}
	if st := z.GetState(); st != ValidationStateSecure {
		t.Errorf("the child is %s, want secure", ValidationStateToString[st])
	}
}

// A child still delegated without a DS stays Insecure through a recheck -- not
// Indeterminate or Bogus, which is what following its chain afresh would say --
// and is not asked about again until the interval has passed once more.
func TestAnInsecureZoneWithoutADSStaysInsecureAcrossARecheck(t *testing.T) {
	c := newChain636(t)
	z := c.holdChildInsecure(ZoneStateRecheck() + time.Second)

	for i := range 2 {
		got, err := c.rrcache.ValidateRRset(context.Background(), c.www, c.fetcher())
		if err != nil {
			t.Fatalf("validation %d: %v", i+1, err)
		}
		if got != ValidationStateInsecure {
			t.Fatalf("validation %d: got %s, want insecure", i+1, ValidationStateToString[got])
		}
	}
	if c.dsQueries != 1 {
		t.Errorf("%d DS queries, want 1: a recheck restarts the clock", c.dsQueries)
	}
	if st := z.GetState(); st != ValidationStateInsecure {
		t.Errorf("the child is %s, want insecure", ValidationStateToString[st])
	}
}

// Insecure does not lapse to "not known" the way Indeterminate does, and a
// recheck is claimed by one caller per interval.
func TestAnInsecureZoneStateIsClaimedNotLapsed(t *testing.T) {
	z := &Zone{ZoneName: "claim.example."}
	z.SetState(ValidationStateInsecure)
	if z.claimInsecureRecheck() {
		t.Fatal("a fresh Insecure state was claimed for a recheck")
	}
	z.stateSince = time.Now().Add(-ZoneStateRecheck() - time.Second)
	if got := z.GetState(); got != ValidationStateInsecure {
		t.Fatalf("an old Insecure state reads %s, want insecure", ValidationStateToString[got])
	}
	if !z.claimInsecureRecheck() {
		t.Fatal("an Insecure state older than the interval was not claimed")
	}
	if z.claimInsecureRecheck() {
		t.Error("a second caller claimed the same recheck")
	}

	for _, st := range []ValidationState{ValidationStateSecure, ValidationStateIndeterminate} {
		z.SetState(st)
		z.stateSince = time.Now().Add(-time.Hour)
		if z.claimInsecureRecheck() {
			t.Errorf("a %s state was claimed for an Insecure recheck", ValidationStateToString[st])
		}
	}
}

// The interval is the configured one, for both states, and a non-positive
// setting restores the default.
func TestZoneStateRecheckIsConfigurable(t *testing.T) {
	t.Cleanup(func() { SetZoneStateRecheck(0) })
	if got := ZoneStateRecheck(); got != DefaultZoneStateRecheck {
		t.Fatalf("unset interval is %s, want %s", got, DefaultZoneStateRecheck)
	}

	SetZoneStateRecheck(5 * time.Minute)
	z := &Zone{ZoneName: "knob.example."}
	z.SetState(ValidationStateIndeterminate)
	z.stateSince = time.Now().Add(-time.Minute) // past the default, within the setting
	if got := z.GetState(); got != ValidationStateIndeterminate {
		t.Errorf("Indeterminate lapsed to %s within a 5m interval", ValidationStateToString[got])
	}
	z.SetState(ValidationStateInsecure)
	z.stateSince = time.Now().Add(-time.Minute)
	if z.claimInsecureRecheck() {
		t.Error("Insecure was claimed for a recheck within a 5m interval")
	}

	SetZoneStateRecheck(-time.Second)
	if got := ZoneStateRecheck(); got != DefaultZoneStateRecheck {
		t.Errorf("a negative setting gives %s, want the default %s", got, DefaultZoneStateRecheck)
	}
}

// A flush drops what the resolver concluded about the zones it flushes, and a
// reset about every zone, keeping only the zones with a trust anchor. Before,
// neither changed anything about a zone held Insecure (#636).
func TestFlushForgetsZoneStates(t *testing.T) {
	mk := func() *RRsetCacheT {
		c := NewRRsetCache(log.New(io.Discard, "", 0), false, false)
		c.DnskeyCache = NewDnskeyCache()
		for zone, st := range map[string]ValidationState{
			".":                     ValidationStateSecure,
			"anchored.example.":     ValidationStateSecure,
			"c.anchored.example.":   ValidationStateInsecure,
			"d.c.anchored.example.": ValidationStateIndeterminate,
			"other.example.":        ValidationStateInsecure,
		} {
			z := &Zone{ZoneName: zone}
			z.SetState(st)
			c.ZoneMap.Set(zone, z)
		}
		for _, zone := range []string{".", "anchored.example."} {
			c.DnskeyCache.Set(zone, 1, &CachedDnskeyRRset{Name: zone, Keyid: 1, State: ValidationStateSecure,
				TrustAnchor: true, Expiration: time.Now().Add(time.Hour)})
		}
		return c
	}
	check := func(t *testing.T, c *RRsetCacheT, want map[string]bool) {
		t.Helper()
		for zone, kept := range want {
			if _, ok := c.ZoneMap.Get(zone); ok != kept {
				t.Errorf("%s: state kept = %v, want %v", zone, ok, kept)
			}
		}
	}

	t.Run("flush all drops the zones at and below the domain", func(t *testing.T) {
		c := mk()
		if _, err := c.FlushDomain("anchored.example.", false); err != nil {
			t.Fatal(err)
		}
		check(t, c, map[string]bool{".": true, "anchored.example.": true, "c.anchored.example.": false,
			"d.c.anchored.example.": false, "other.example.": true})
	})

	t.Run("flush keeping structural records keeps the zone states", func(t *testing.T) {
		c := mk()
		if _, err := c.FlushDomain("c.anchored.example.", true); err != nil {
			t.Fatal(err)
		}
		check(t, c, map[string]bool{"c.anchored.example.": true, "d.c.anchored.example.": true})
	})

	t.Run("reset drops every zone without a trust anchor", func(t *testing.T) {
		c := mk()
		c.FlushAll()
		check(t, c, map[string]bool{".": true, "anchored.example.": true, "c.anchored.example.": false,
			"d.c.anchored.example.": false, "other.example.": false})
	})
}
