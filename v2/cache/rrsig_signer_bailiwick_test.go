/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"crypto"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const bailiwickDS = " 300 IN DS 12345 15 2 E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CFC41A5766"

// zoneSigner is an ED25519 key for zone.
type zoneSigner struct {
	zone string
	key  *dns.DNSKEY
	priv crypto.Signer
}

func newZoneSigner(t *testing.T, zone string) *zoneSigner {
	t.Helper()
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 256, Protocol: 3, Algorithm: dns.ED25519}
	p, err := k.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	return &zoneSigner{zone: zone, key: k, priv: p.(crypto.Signer)}
}

// trust holds the key Secure in rrcache, as a validated DNSKEY RRset would.
func (s *zoneSigner) trust(rrcache *RRsetCacheT) {
	rrcache.DnskeyCache.Set(s.zone, s.key.KeyTag(), &CachedDnskeyRRset{Name: s.zone, Keyid: s.key.KeyTag(),
		State: ValidationStateSecure, Dnskey: *s.key, Expiration: time.Now().Add(time.Hour)})
}

// signAs signs the RR in text, then serves it and its RRSIG under the owner
// served, in an RRset named name. A wildcard source served below itself is a
// wildcard expansion; anything else served under another name is a forgery.
func (s *zoneSigner) signAs(t *testing.T, text, served, name string) *core.RRset {
	t.Helper()
	rr, err := dns.NewRR(text)
	if err != nil {
		t.Fatal(err)
	}
	sig := &dns.RRSIG{Algorithm: dns.ED25519, KeyTag: s.key.KeyTag(), SignerName: s.zone,
		Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
		Expiration: uint32(time.Now().Add(time.Hour).Unix())}
	if err := sig.Sign(s.priv, []dns.RR{rr}); err != nil {
		t.Fatal(err)
	}
	rr.Header().Name = served
	sig.Hdr.Name = served
	return &core.RRset{Name: name, Class: dns.ClassINET, RRtype: rr.Header().Rrtype, RRs: []dns.RR{rr}, RRSIGs: []dns.RR{sig}}
}

// RFC 4035 section 5.3.1: the Signer's Name MUST be the zone that holds the
// RRset. RRSIG.Verify only checks that the owner ends with the signer's name as
// a string, and the validator checked nothing, so a key held Secure for one
// zone made data for names outside it Secure -- and a signer the resolver
// holds Insecure made any RRset carrying its name Insecure, unverified.
func TestRRSIGSignerMustHoldTheOwner(t *testing.T) {
	const victim = "www.victim.example."
	cases := []struct {
		name   string
		signer string
		held   bool   // the signer's key is Secure; otherwise its zone is Insecure
		text   string // the RR as signed
		served string // its owner as served
		rrset  string // the RRset's name, when not the served owner
		want   ValidationState
	}{
		// Forgeries.
		{"signer is a string suffix of the owner", "ictim.example.", true, victim + " 300 IN A 192.0.2.66", victim, "", ValidationStateBogus},
		{"RRset named outside the signer", "attacker.example.", true, "www.attacker.example. 300 IN A 192.0.2.66", "www.attacker.example.", victim, ValidationStateBogus},
		{"wildcard source outside the signer", "victim.example.", true, "*.example. 300 IN A 192.0.2.66", victim, "", ValidationStateBogus},
		{"DS signed by its own zone", "victim.example.", true, "victim.example." + bailiwickDS, "victim.example.", "", ValidationStateBogus},
		{"unrelated signer held Insecure", "insecure.example.", false, victim + " 300 IN A 192.0.2.66", victim, "", ValidationStateBogus},
		// Legitimate signers.
		{"owner's zone", "victim.example.", true, victim + " 300 IN A 192.0.2.66", victim, "", ValidationStateSecure},
		{"deeper in the zone", "victim.example.", true, "a.b.victim.example. 300 IN A 192.0.2.66", "a.b.victim.example.", "", ValidationStateSecure},
		{"zone apex", "victim.example.", true, "victim.example. 300 IN TXT \"apex\"", "victim.example.", "", ValidationStateSecure},
		{"DS signed by the parent", "example.", true, "victim.example." + bailiwickDS, "victim.example.", "", ValidationStateSecure},
		{"DS signed by the root", ".", true, "example." + bailiwickDS, "example.", "", ValidationStateSecure},
		{"wildcard expansion", "victim.example.", true, "*.victim.example. 300 IN A 192.0.2.66", "a.b.victim.example.", "", ValidationStateSecure},
		{"owner in another case", "victim.example.", true, victim + " 300 IN A 192.0.2.66", "WWW.Victim.EXAMPLE.", "", ValidationStateSecure},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache := testCache(t)
			rrcache.DnskeyCache = NewDnskeyCache() // not the process-wide one
			s := newZoneSigner(t, c.signer)
			if c.held {
				s.trust(rrcache)
			} else {
				rrcache.ZoneMap.Set("victim.example.", &Zone{ZoneName: "victim.example.", State: ValidationStateSecure})
				rrcache.ZoneMap.Set(c.signer, &Zone{ZoneName: c.signer, State: ValidationStateInsecure})
			}
			name := c.rrset
			if name == "" {
				name = c.served
			}
			rrset := s.signAs(t, c.text, c.served, name)

			got, err := rrcache.ValidateRRset(context.Background(), rrset, nil)
			if err != nil {
				t.Fatalf("ValidateRRset: %v", err)
			}
			if got != c.want {
				t.Errorf("%s %s signed by %s: got %s, want %s", name, dns.TypeToString[rrset.RRtype], c.signer,
					ValidationStateToString[got], ValidationStateToString[c.want])
			}
			// A DS that validates marks its zone Secure; one that does not must not.
			if rrset.RRtype == dns.TypeDS && c.want != ValidationStateSecure {
				if z, ok := rrcache.ZoneMap.Get(name); ok && z.GetState() == ValidationStateSecure {
					t.Errorf("zone %s marked Secure by a DS its own zone signed", name)
				}
			}
		})
	}
}
