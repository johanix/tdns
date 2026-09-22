/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// RFC 4035 section 5.2: a child's DNSKEY RRset is authenticated by a signature
// made with a key that matches the parent's DS. ValidateChildDnskeys handed the
// RRset to ValidateRRset instead, which verifies with whatever key FindDnskey
// returns for the signature's signer: an ancestor's key, a ZSK held from an
// earlier fetch, or, for a key it does not hold, whatever fetching and
// validating the child's DNSKEYs again yields -- ValidateChildDnskeys once
// more, with nothing to end it.

const childKskChild = "victim.example."

// childKskFetchCap ends a recursing validation, so that it fails the test
// instead of hanging it.
const childKskFetchCap = 50

var errChildKskFetchCap = errors.New("DNSKEY fetch cap reached")

type childKskFixture struct {
	zd       *ZoneData
	cdd      *ChildDelegationData
	ksk, zsk *signerTestKey
	sig0     *dns.KEY
	dnskeys  *core.RRset // what the child's nameservers answer for DNSKEY
	fetches  int         // DNSKEY queries sent to them
}

// newChildKskFixture delegates victim.example. from example. with a DS for its
// KSK. The child's nameservers answer DNSKEY with f.dnskeys, and KEY with a
// SIG(0) key signed by the child's ZSK.
func newChildKskFixture(t *testing.T) *childKskFixture {
	t.Helper()
	const child = childKskChild
	f := &childKskFixture{
		ksk: newSignerTestKey(t, child, 257),
		zsk: newSignerTestKey(t, child, 256),
	}

	f.zd, f.cdd = childKskParent(t, f.ksk.dnskey.ToDS(dns.SHA256))

	f.sig0 = newSignerTestSig0Key(t, child)
	keys := f.zsk.sign(t, f.sig0)
	saved := lookupChildRRset
	lookupChildRRset = func(_ *ZoneData, qname string, qtype uint16, _ []string, _ bool) (*core.RRset, error) {
		var rrset *core.RRset
		switch {
		case !core.EqualNames(qname, child):
		case qtype == dns.TypeDNSKEY:
			f.fetches++
			if f.fetches > childKskFetchCap {
				return nil, errChildKskFetchCap
			}
			rrset = f.dnskeys
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
	return f
}

// signedDnskeys returns the DNSKEY RRset of members with a signature by each
// of signers, valid from inception to expiration.
func signedDnskeys(t *testing.T, members, signers []*signerTestKey, inception, expiration time.Time) *core.RRset {
	t.Helper()
	rrset := &core.RRset{Name: members[0].dnskey.Header().Name, Class: dns.ClassINET, RRtype: dns.TypeDNSKEY}
	for _, k := range members {
		rrset.RRs = append(rrset.RRs, k.dnskey)
	}
	for _, k := range signers {
		sig := &dns.RRSIG{
			Algorithm:  k.dnskey.Algorithm,
			Inception:  uint32(inception.Unix()),
			Expiration: uint32(expiration.Unix()),
			KeyTag:     k.dnskey.KeyTag(),
			SignerName: k.dnskey.Header().Name,
		}
		if err := sig.Sign(k.priv, rrset.RRs); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		rrset.RRSIGs = append(rrset.RRSIGs, sig)
	}
	return rrset
}

func TestChildDnskeysValidatedByDSMatchedKSK(t *testing.T) {
	f := newChildKskFixture(t)
	parent := newSignerTestKey(t, "example.", 257)
	newKsk := newSignerTestKey(t, childKskChild, 257) // in the RRset, not yet in the DS
	rogue := newSignerTestKey(t, childKskChild, 257)  // in neither
	now := time.Now()

	for _, tc := range []struct {
		what    string
		members []*signerTestKey // default: the KSK and the ZSK
		signers []*signerTestKey
		held    []*signerTestKey // held Secure before the fetch
		expired bool
		want    bool
	}{
		{what: "signed by the DS-matched KSK", signers: []*signerTestKey{f.ksk}, want: true},
		{what: "signed by a KSK without a DS, then by the DS-matched KSK",
			members: []*signerTestKey{f.ksk, f.zsk, newKsk}, signers: []*signerTestKey{newKsk, f.ksk}, want: true},
		{what: "signed only by the ZSK in the set", signers: []*signerTestKey{f.zsk}},
		{what: "signed only by the ZSK in the set, held from an earlier fetch",
			signers: []*signerTestKey{f.zsk}, held: []*signerTestKey{f.zsk}},
		{what: "signed by an ancestor's key held Secure",
			signers: []*signerTestKey{parent}, held: []*signerTestKey{parent}},
		{what: "signed with a key tag that is not in the set", signers: []*signerTestKey{rogue}},
		{what: "signed by the DS-matched KSK, expired", signers: []*signerTestKey{f.ksk}, expired: true},
	} {
		t.Run(tc.what, func(t *testing.T) {
			members := tc.members
			if members == nil {
				members = []*signerTestKey{f.ksk, f.zsk}
			}
			inception, expiration := now.Add(-time.Hour), now.Add(time.Hour)
			if tc.expired {
				inception, expiration = now.Add(-2*time.Hour), now.Add(-time.Hour)
			}
			f.dnskeys = signedDnskeys(t, members, tc.signers, inception, expiration)

			zskHeldBefore := false
			hold := func(dkc *cache.DnskeyCacheT) {
				for _, k := range tc.held {
					k.holdSecure(dkc)
					zskHeldBefore = zskHeldBefore || k == f.zsk
				}
			}
			checkFetches := func(t *testing.T) {
				t.Helper()
				if f.fetches != 1 {
					t.Errorf("child DNSKEY RRset fetched %d times, want 1", f.fetches)
				}
			}
			checkHeld := func(t *testing.T, dkc *cache.DnskeyCacheT) {
				t.Helper()
				if held := dkc.Get(childKskChild, f.ksk.dnskey.KeyTag()) != nil; held != tc.want {
					t.Errorf("KSK %d held: %v, want %v", f.ksk.dnskey.KeyTag(), held, tc.want)
				}
				if zskHeldBefore {
					return
				}
				if held := dkc.Get(childKskChild, f.zsk.dnskey.KeyTag()) != nil; held != tc.want {
					t.Errorf("ZSK %d held: %v, want %v", f.zsk.dnskey.KeyTag(), held, tc.want)
				}
			}

			t.Run("ValidateChildDnskeys", func(t *testing.T) {
				dkc := signerTestDnskeyCache(t)
				hold(dkc)
				f.fetches = 0
				valid, err := f.zd.ValidateChildDnskeys(f.cdd, false)
				if valid != tc.want {
					t.Errorf("ValidateChildDnskeys(%s) = %v (err %v), want %v", childKskChild, valid, err, tc.want)
				}
				checkFetches(t)
				checkHeld(t, dkc)
			})

			// With the ZSK held, the KEY's signature is checked against it
			// and the child's DNSKEYs are never fetched.
			if zskHeldBefore {
				return
			}
			t.Run("FindSig0KeyViaDNS", func(t *testing.T) {
				dkc := signerTestDnskeyCache(t)
				hold(dkc)
				f.fetches = 0
				k, err := f.zd.FindSig0KeyViaDNS(childKskChild, f.sig0.KeyTag())
				if validated := err == nil && k != nil && k.Validated; validated != tc.want {
					t.Errorf("FindSig0KeyViaDNS(%s, %d) = (%+v, %v), validated %v, want %v",
						childKskChild, f.sig0.KeyTag(), k, err, validated, tc.want)
				}
				checkFetches(t)
				checkHeld(t, dkc)
			})
		})
	}
}

// An UPDATE is enough to set it off. ValidateUpdate looks up the key of a
// signer it does not hold before it checks the signature, so the SIG's bytes
// do not matter; the signer only has to sit below a signed delegation whose
// nameservers answer for it.
func TestValidateUpdateChildDnskeysUnknownKeyTag(t *testing.T) {
	f := newChildKskFixture(t)
	signerTestDnskeyCache(t)
	f.zd.KeyDB = newTestKeyDB(t)
	rogue := newSignerTestKey(t, childKskChild, 257)
	now := time.Now()
	f.dnskeys = signedDnskeys(t, []*signerTestKey{f.ksk, f.zsk}, []*signerTestKey{rogue},
		now.Add(-time.Hour), now.Add(time.Hour))

	us := &UpdateStatus{}
	err := f.zd.ValidateUpdate(context.Background(),
		signedUpdateFrom(t, f.zd.ZoneName, childKskChild, f.sig0.KeyTag()), us)
	if f.fetches != 1 {
		t.Errorf("ValidateUpdate (err %v) fetched the child DNSKEY RRset %d times, want 1", err, f.fetches)
	}
	for _, s := range us.Signers {
		if s.Validated {
			t.Errorf("signer %s::%d validated", s.Name, s.KeyId)
		}
	}
}

// childKskParent is example., delegating victim.example. with glue and ds.
func childKskParent(t *testing.T, ds ...*dns.DS) (*ZoneData, *ChildDelegationData) {
	t.Helper()
	const child = childKskChild
	parentZone := "example. 3600 IN SOA ns.example. hostmaster.example. 1 7200 1800 604800 7200\n" +
		"example. 3600 IN NS ns.example.\n" +
		"ns.example. 3600 IN A 192.0.2.1\n" +
		child + " 3600 IN NS ns." + child + "\n" +
		"ns." + child + " 3600 IN A 192.0.2.53\n"
	for _, d := range ds {
		parentZone += d.String() + "\n"
	}
	zd := testZone(t, "example.", parentZone)
	cdd := zd.FindDelegation(child, true)
	if cdd == nil || len(cdd.A_glue) == 0 || cdd.DS_rrset == nil || len(cdd.DS_rrset.RRs) != len(ds) {
		t.Fatalf("FindDelegation(%s) = %+v, want NS, glue and %d DS", child, cdd, len(ds))
	}
	return zd, cdd
}

// RFC 4035 section 5.2 also asks that the DS's algorithm match the DNSKEY's.
// The digest covers the key's algorithm field but not the DS's, so a DS
// naming another algorithm still matched the key by key tag and digest.
func TestChildDnskeysDSAlgorithmMatchesKSK(t *testing.T) {
	f := newChildKskFixture(t)
	now := time.Now()
	f.dnskeys = signedDnskeys(t, []*signerTestKey{f.ksk, f.zsk}, []*signerTestKey{f.ksk},
		now.Add(-time.Hour), now.Add(time.Hour))

	ds := f.ksk.dnskey.ToDS(dns.SHA256)
	otherAlg := f.ksk.dnskey.ToDS(dns.SHA256)
	otherAlg.Algorithm = dns.ECDSAP256SHA256

	for _, tc := range []struct {
		what string
		ds   []*dns.DS
		want bool
	}{
		{"a DS naming the KSK's algorithm", []*dns.DS{ds}, true},
		{"a DS naming another algorithm", []*dns.DS{otherAlg}, false},
		{"a DS naming another algorithm, and one naming the KSK's", []*dns.DS{otherAlg, ds}, true},
	} {
		t.Run(tc.what, func(t *testing.T) {
			zd, cdd := childKskParent(t, tc.ds...)

			t.Run("ValidateChildDnskeys", func(t *testing.T) {
				dkc := signerTestDnskeyCache(t)
				valid, err := zd.ValidateChildDnskeys(cdd, false)
				if valid != tc.want {
					t.Errorf("ValidateChildDnskeys(%s) = %v (err %v), want %v", childKskChild, valid, err, tc.want)
				}
				if held := dkc.Get(childKskChild, f.ksk.dnskey.KeyTag()) != nil; held != tc.want {
					t.Errorf("KSK %d held: %v, want %v", f.ksk.dnskey.KeyTag(), held, tc.want)
				}
			})

			t.Run("FindSig0KeyViaDNS", func(t *testing.T) {
				signerTestDnskeyCache(t)
				k, err := zd.FindSig0KeyViaDNS(childKskChild, f.sig0.KeyTag())
				if validated := err == nil && k != nil && k.Validated; validated != tc.want {
					t.Errorf("FindSig0KeyViaDNS(%s, %d) = (%+v, %v), validated %v, want %v",
						childKskChild, f.sig0.KeyTag(), k, err, validated, tc.want)
				}
			})
		})
	}
}
