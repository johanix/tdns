/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"crypto"
	"io"
	"log"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// ZoneData.ValidateRRset used whatever key it held for an RRSIG's Signer's
// Name. RRSIG.Verify only checks that the owner ends with that name as a
// string, so a key for ictim.example. authenticated data at
// www.victim.example.

// signerTestDnskeyCache gives one test its own DnskeyCache. ZoneData.FindDnskey
// reads the process-wide cache.DnskeyCache, which other tests fill.
func signerTestDnskeyCache(t *testing.T) *cache.DnskeyCacheT {
	t.Helper()
	saved := cache.DnskeyCache
	cache.DnskeyCache = cache.NewDnskeyCache()
	t.Cleanup(func() { cache.DnskeyCache = saved })
	return cache.DnskeyCache
}

type signerTestKey struct {
	dnskey *dns.DNSKEY
	priv   crypto.Signer
}

// newSignerTestKey makes an ED25519 key for zone.
func newSignerTestKey(t *testing.T, zone string, flags uint16) *signerTestKey {
	t.Helper()
	dk := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ED25519,
	}
	priv, err := dk.Generate(256)
	if err != nil {
		t.Fatalf("Generate(%s): %v", zone, err)
	}
	return &signerTestKey{dnskey: dk, priv: priv.(crypto.Signer)}
}

// holdSecure puts k in dkc as a validated delegation would.
func (k *signerTestKey) holdSecure(dkc *cache.DnskeyCacheT) {
	zone := k.dnskey.Header().Name
	dkc.Set(zone, k.dnskey.KeyTag(), &cache.CachedDnskeyRRset{
		Name: zone, Keyid: k.dnskey.KeyTag(), State: cache.ValidationStateSecure,
		Dnskey: *k.dnskey, Expiration: time.Now().Add(time.Hour),
	})
}

// sign returns rrs as an RRset carrying k's signature over them.
func (k *signerTestKey) sign(t *testing.T, rrs ...dns.RR) *core.RRset {
	t.Helper()
	sig := &dns.RRSIG{
		Algorithm:  k.dnskey.Algorithm,
		Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
		Expiration: uint32(time.Now().Add(time.Hour).Unix()),
		KeyTag:     k.dnskey.KeyTag(),
		SignerName: k.dnskey.Header().Name,
	}
	if err := sig.Sign(k.priv, rrs); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	h := rrs[0].Header()
	return &core.RRset{Name: h.Name, Class: h.Class, RRtype: h.Rrtype, RRs: rrs, RRSIGs: []dns.RR{sig}}
}

// newSignerTestSig0Key makes an ED25519 KEY RR at owner.
func newSignerTestSig0Key(t *testing.T, owner string) *dns.KEY {
	t.Helper()
	k := &dns.KEY{DNSKEY: dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: owner, Rrtype: dns.TypeKEY, Class: dns.ClassINET, Ttl: 3600},
		Protocol:  3,
		Algorithm: dns.ED25519,
	}}
	if _, err := k.Generate(256); err != nil {
		t.Fatalf("Generate(%s): %v", owner, err)
	}
	return k
}

// signerTestExpand renames a signed wildcard RRset to owner, as a wildcard
// expansion does. The RRSIG keeps the wildcard's Labels.
func signerTestExpand(rrset *core.RRset, owner string) *core.RRset {
	out := &core.RRset{Name: owner, Class: rrset.Class, RRtype: rrset.RRtype}
	for _, rr := range rrset.RRs {
		c := dns.Copy(rr)
		c.Header().Name = owner
		out.RRs = append(out.RRs, c)
	}
	for _, rr := range rrset.RRSIGs {
		c := dns.Copy(rr)
		c.Header().Name = owner
		out.RRSIGs = append(out.RRSIGs, c)
	}
	return out
}

func TestZoneDataValidateRRsetSignerHoldsOwner(t *testing.T) {
	dkc := signerTestDnskeyCache(t)
	zd := &ZoneData{ZoneName: "example.", Logger: log.New(io.Discard, "", 0)}

	parent := newSignerTestKey(t, "example.", 257)
	victim := newSignerTestKey(t, "victim.example.", 257)
	ictim := newSignerTestKey(t, "ictim.example.", 257)
	for _, k := range []*signerTestKey{parent, victim, ictim} {
		k.holdSecure(dkc)
	}

	const owner = "www.victim.example."
	www := mustRR(t, owner+" 3600 IN A 192.0.2.1")
	ds := victim.dnskey.ToDS(dns.SHA256)
	wild := mustRR(t, `*.example. 3600 IN TXT "wild"`)

	for _, tc := range []struct {
		what  string
		rrset *core.RRset
		want  bool
	}{
		{"signed by the owner's zone", victim.sign(t, www), true},
		{"signed by an ancestor of the owner's zone", parent.sign(t, www), true},
		{"signed by a zone whose name only ends the owner's", ictim.sign(t, www), false},
		{"a DS signed by the parent", parent.sign(t, ds), true},
		{"a DS signed by the child it names", victim.sign(t, ds), false},
		{"a wildcard expansion signed at the wildcard's zone", signerTestExpand(parent.sign(t, wild), owner), true},
		{"a wildcard expansion signed below its wildcard", signerTestExpand(victim.sign(t, wild), owner), false},
	} {
		t.Run(tc.what, func(t *testing.T) {
			valid, err := zd.ValidateRRset(tc.rrset, true)
			if valid != tc.want {
				t.Errorf("ValidateRRset(%s %s signed by %s) = %v (err %v), want %v",
					tc.rrset.Name, dns.TypeToString[tc.rrset.RRtype],
					tc.rrset.RRSIGs[0].(*dns.RRSIG).SignerName, valid, err, tc.want)
			}
		})
	}
}

// The in-zone arm of LookupAndValidateRRset and SIG(0) key discovery hand
// zone data to ValidateRRset, in an RRset that carries no name.
func TestZoneDataSignerHoldsOwnerInZoneCallers(t *testing.T) {
	dkc := signerTestDnskeyCache(t)
	victim := newSignerTestKey(t, "victim.example.", 257)
	ictim := newSignerTestKey(t, "ictim.example.", 257)
	victim.holdSecure(dkc)
	ictim.holdSecure(dkc)

	forged := newSignerTestSig0Key(t, "www.victim.example.")
	genuine := newSignerTestSig0Key(t, "ok.victim.example.")
	forgedSet := ictim.sign(t, forged)
	genuineSet := victim.sign(t, genuine)

	zone := "victim.example. 3600 IN SOA ns.victim.example. hostmaster.victim.example. 1 7200 1800 604800 7200\n" +
		"victim.example. 3600 IN NS ns.victim.example.\n" +
		"ns.victim.example. 3600 IN A 192.0.2.1\n" +
		forgedSet.RRs[0].String() + "\n" + forgedSet.RRSIGs[0].String() + "\n" +
		genuineSet.RRs[0].String() + "\n" + genuineSet.RRSIGs[0].String() + "\n"
	zd := testZone(t, "victim.example.", zone)

	for _, tc := range []struct {
		owner string
		keyid uint16
		want  bool
	}{
		{"ok.victim.example.", genuine.KeyTag(), true},
		{"www.victim.example.", forged.KeyTag(), false},
	} {
		t.Run(tc.owner, func(t *testing.T) {
			rrset, valid, err := zd.LookupAndValidateRRset(tc.owner, dns.TypeKEY, false)
			if err != nil || rrset == nil || len(rrset.RRSIGs) == 0 {
				t.Fatalf("LookupAndValidateRRset(%s KEY) = (%v, %v, %v), want the signed KEY RRset", tc.owner, rrset, valid, err)
			}
			if valid != tc.want {
				t.Errorf("LookupAndValidateRRset(%s KEY) validated = %v, want %v", tc.owner, valid, tc.want)
			}

			k, err := zd.FindSig0KeyViaDNS(tc.owner, tc.keyid)
			if err != nil || k == nil {
				t.Fatalf("FindSig0KeyViaDNS(%s, %d) = (%v, %v), want the key", tc.owner, tc.keyid, k, err)
			}
			if k.Validated != tc.want {
				t.Errorf("FindSig0KeyViaDNS(%s) Validated = %v, want %v", tc.owner, k.Validated, tc.want)
			}
		})
	}
}

// A parent learns a child's keys from the child's nameservers. ValidateChildDnskeys
// accepted the child's DNSKEY RRset once one KSK in it matched the parent's DS
// and ValidateRRset passed the RRset's signature, and then held its ZSKs
// Secure in the process-wide DnskeyCache, which the in-process IMR validates
// with too. A nameserver for the child, or anyone on the path to one, can put
// the child's real KSK next to a ZSK of its own.
//
// SIG(0) key discovery gets there from an UPDATE: the signer's KEY is fetched
// from the child, and its RRSIG names a ZSK that is not yet held.
func TestChildDnskeysSignerHoldsOwner(t *testing.T) {
	const child = "victim.example."
	ksk := newSignerTestKey(t, child, 257)
	zsk := newSignerTestKey(t, child, 256)
	ictim := newSignerTestKey(t, "ictim.example.", 257)

	parentZone := "example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200\n" +
		"example. 3600 IN NS ns.example.\n" +
		"ns.example. 3600 IN A 192.0.2.1\n" +
		child + " 3600 IN NS ns." + child + "\n" +
		"ns." + child + " 3600 IN A 192.0.2.53\n" +
		ksk.dnskey.ToDS(dns.SHA256).String() + "\n"
	zd := testZone(t, "example.", parentZone)
	cdd := zd.FindDelegation(child, true)
	if cdd == nil || len(cdd.A_glue) == 0 || cdd.DS_rrset == nil || len(cdd.DS_rrset.RRs) == 0 {
		t.Fatalf("FindDelegation(%s) = %+v, want NS, glue and DS", child, cdd)
	}

	sig0 := newSignerTestSig0Key(t, child)
	keys := zsk.sign(t, sig0)
	var dnskeys *core.RRset
	saved := lookupChildRRset
	lookupChildRRset = func(_ *ZoneData, qname string, qtype uint16, _ []string, _ bool) (*core.RRset, error) {
		var rrset *core.RRset
		switch {
		case !core.EqualNames(qname, child):
		case qtype == dns.TypeDNSKEY:
			rrset = dnskeys
		case qtype == dns.TypeKEY:
			rrset = keys
		}
		if rrset == nil {
			return &core.RRset{}, nil
		}
		// As AuthDNSQuery builds it: records and signatures, no name or type.
		return &core.RRset{RRs: rrset.RRs, RRSIGs: rrset.RRSIGs}, nil
	}
	t.Cleanup(func() { lookupChildRRset = saved })

	for _, tc := range []struct {
		what   string
		signer *signerTestKey
		want   bool
	}{
		{"DNSKEY RRset signed by the child's KSK", ksk, true},
		{"DNSKEY RRset signed by a zone whose name only ends the child's", ictim, false},
	} {
		t.Run(tc.what, func(t *testing.T) {
			dnskeys = tc.signer.sign(t, ksk.dnskey, zsk.dnskey)
			zskHeld := func(t *testing.T, dkc *cache.DnskeyCacheT) {
				t.Helper()
				if held := dkc.Get(child, zsk.dnskey.KeyTag()) != nil; held != tc.want {
					t.Errorf("ZSK %d held for %s: %v, want %v", zsk.dnskey.KeyTag(), child, held, tc.want)
				}
			}

			t.Run("ValidateChildDnskeys", func(t *testing.T) {
				dkc := signerTestDnskeyCache(t)
				ictim.holdSecure(dkc)
				valid, err := zd.ValidateChildDnskeys(cdd, false)
				if valid != tc.want {
					t.Errorf("ValidateChildDnskeys(%s) = %v (err %v), want %v", child, valid, err, tc.want)
				}
				zskHeld(t, dkc)
			})

			t.Run("FindSig0KeyViaDNS", func(t *testing.T) {
				dkc := signerTestDnskeyCache(t)
				ictim.holdSecure(dkc)
				k, err := zd.FindSig0KeyViaDNS(child, sig0.KeyTag())
				if validated := err == nil && k != nil && k.Validated; validated != tc.want {
					t.Errorf("FindSig0KeyViaDNS(%s, %d) = (%+v, %v), validated %v, want %v",
						child, sig0.KeyTag(), k, err, validated, tc.want)
				}
				zskHeld(t, dkc)
			})
		})
	}
}
