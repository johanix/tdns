/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"strconv"
	"testing"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// RFC 4035 section 5.2: a DS authenticates a DNSKEY when its key tag and
// algorithm match the key's, and its digest is the key's. The digest covers
// the key's algorithm field but not the DS's, so the resolver, which compared
// the key tag and the digest only, took a DS naming another algorithm as a
// match (Deckard: val_minimal_baddsalgorithm, val_unalgo_ds).

// withAlgorithm is ds naming another algorithm, with the same key tag and
// digest.
func withAlgorithm(ds *dns.DS, alg uint8) *dns.DS {
	c := dns.Copy(ds).(*dns.DS)
	c.Algorithm = alg
	return c
}

// A trust anchor DS whose algorithm is not the root key's matches no key: the
// root's data is SERVFAIL, whether or not its keys were fetched at start-up,
// and whether or not the resolver can verify the algorithm it names. A trust
// anchor is the operator's, and one that matches nothing is an error, not an
// insecure delegation. With the right algorithm it is Secure.
func TestTrustAnchorDSOfAnotherAlgorithmMatchesNoKey(t *testing.T) {
	for _, startup := range []bool{true, false} {
		t.Run("startup="+strconv.FormatBool(startup), func(t *testing.T) {
			root := newRefKey(t, ".")
			serve := rootServing(t, root, true, true)
			ds := root.key.ToDS(dns.SHA256)

			imr := anchorImrDS(t, ds, serve, startup)
			if got := askType(t, imr, ".", dns.TypeNS); got.Rcode != dns.RcodeSuccess || !got.AuthenticatedData {
				t.Fatalf("anchor of the key's own algorithm: %s, AD=%v; want NOERROR with AD",
					dns.RcodeToString[got.Rcode], got.AuthenticatedData)
			}

			for _, alg := range []uint8{dns.ECDSAP256SHA256, 208} {
				imr = anchorImrDS(t, withAlgorithm(ds, alg), serve, startup)
				wantServfail(t, imr, askType(t, imr, ".", dns.TypeNS))
				wantServfail(t, imr, askType(t, imr, taUnsigned, dns.TypeA))
			}
		})
	}
}

// dsRig is a resolver forwarding "." to a double serving sec.example., signed,
// and kid.sec.example., signed, delegated with the DS records ds. www.kid is
// signed, unsigned.kid is not. sec.example. is anchored by its DNSKEY, or by
// the DS records anchor if there are any. Each call is a fresh resolver.
func dsRig(t *testing.T, ds func(kid *fwdSecKey) []dns.RR, anchor func(parent *fwdSecKey) []*dns.DS) *Imr {
	t.Helper()
	parent, kid := newFwdSecKey(t, fwdSecParent), newFwdSecKey(t, fwdSecKid)
	addr, port := startSignedForwardUpstream(t, map[string]*dns.Msg{
		fwdSecWWW + " A":               {Answer: kid.sign(t, fwdSecRR(t, fwdSecWWW+" 300 IN A 192.0.2.7"))},
		"unsigned." + fwdSecKid + " A": {Answer: []dns.RR{fwdSecRR(t, "unsigned."+fwdSecKid+" 300 IN A 192.0.2.8")}},
		fwdSecKid + " DNSKEY":          {Answer: kid.sign(t, dns.Copy(kid.dnskey))},
		fwdSecKid + " DS":              {Answer: parent.sign(t, ds(kid)...)},
		fwdSecParent + " DNSKEY":       {Answer: parent.sign(t, dns.Copy(parent.dnskey))},
	})
	imr := newForwardTestImr(t, []ImrForwardConf{{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}}})
	imr.Cache.DnskeyCache = cache.NewDnskeyCache() // not the process-wide one
	imr.DnskeyCache = imr.Cache.DnskeyCache
	if err := imr.Cache.PrimeFromHintsOnly(""); err != nil {
		t.Fatalf("PrimeFromHintsOnly: %v", err)
	}
	if anchor != nil {
		imr.seedDSRRsetFromTrustAnchors(fwdSecParent, anchor(parent))
		return imr
	}
	imr.Cache.DnskeyCache.Set(fwdSecParent, parent.dnskey.KeyTag(), &cache.CachedDnskeyRRset{
		Name: fwdSecParent, Keyid: parent.dnskey.KeyTag(), TrustAnchor: true, State: cache.ValidationStateSecure,
		Dnskey: *parent.dnskey, Expiration: time.Now().Add(time.Hour)})
	imr.Cache.ZoneMap.Set(fwdSecParent, &cache.Zone{ZoneName: fwdSecParent, State: cache.ValidationStateSecure})
	return imr
}

const (
	outcomeSecure   = "secure"
	outcomeInsecure = "insecure"
	outcomeServfail = "servfail"
)

// outcome asks imr for qname's A RRset, with DO, and says how it was answered.
func outcome(t *testing.T, imr *Imr, qname string, qtype uint16) string {
	t.Helper()
	r := new(dns.Msg)
	r.SetQuestion(qname, qtype)
	r.SetEdns0(4096, true)
	cw := &captureWriter{}
	imr.ImrResponder(context.Background(), cw, r, qname, qtype, &edns0.MsgOptions{RD: true, DO: true})
	if cw.got == nil {
		t.Fatalf("%s %s: nothing written", qname, dns.TypeToString[qtype])
	}
	m := cw.got
	switch {
	case m.Rcode == dns.RcodeServerFailure:
		return outcomeServfail
	case m.Rcode == dns.RcodeSuccess && len(m.Answer) > 0 && m.AuthenticatedData:
		return outcomeSecure
	case m.Rcode == dns.RcodeSuccess && len(m.Answer) > 0:
		return outcomeInsecure
	}
	return dns.RcodeToString[m.Rcode] + " without an answer"
}

// A delegation's DS RRset decides how the child's data validates:
//
//   - A DS naming the key's algorithm, with its digest: Secure.
//   - A DS naming another algorithm the resolver supports, even with the key's
//     tag and digest: no DS matches the key, and the child is Bogus (SERVFAIL).
//     RSASHA1 is supported: tdns does not sign with it, but validates it.
//   - Only DS records the resolver cannot use -- an algorithm it cannot verify,
//     or a digest type it cannot compute: no supported authentication path
//     (RFC 4035 section 5.2), and the child is Insecure, as if the parent had
//     proven it has no DS. That is Deckard's val_unalgo_ds.
//   - One usable DS beside unusable ones: validated as usual.
//
// Signed and unsigned data in the child go the same way, except that unsigned
// data under a Secure delegation is Bogus. Unsigned data is also asked for
// after the DS alone, before anything has looked at the child's keys.
func TestDelegationDSAlgorithmsAndDigests(t *testing.T) {
	unsigned := "unsigned." + fwdSecKid
	for _, c := range []struct {
		name             string
		ds               func(kid *fwdSecKey) []dns.RR
		signed, unsigned string
	}{
		{"the key's algorithm", func(kid *fwdSecKey) []dns.RR {
			return []dns.RR{kid.dnskey.ToDS(dns.SHA256)}
		}, outcomeSecure, outcomeServfail},
		{"another supported algorithm", func(kid *fwdSecKey) []dns.RR {
			return []dns.RR{withAlgorithm(kid.dnskey.ToDS(dns.SHA256), dns.ECDSAP256SHA256)}
		}, outcomeServfail, outcomeServfail},
		{"RSASHA1", func(kid *fwdSecKey) []dns.RR {
			return []dns.RR{withAlgorithm(kid.dnskey.ToDS(dns.SHA256), dns.RSASHA1)}
		}, outcomeServfail, outcomeServfail},
		{"an unknown algorithm", func(kid *fwdSecKey) []dns.RR {
			return []dns.RR{withAlgorithm(kid.dnskey.ToDS(dns.SHA256), 208)}
		}, outcomeInsecure, outcomeInsecure},
		{"an unknown digest type", func(kid *fwdSecKey) []dns.RR {
			ds := kid.dnskey.ToDS(dns.SHA256)
			ds.DigestType = 99
			return []dns.RR{ds}
		}, outcomeInsecure, outcomeInsecure},
		{"an unknown algorithm beside another supported one", func(kid *fwdSecKey) []dns.RR {
			return []dns.RR{withAlgorithm(kid.dnskey.ToDS(dns.SHA256), 208),
				withAlgorithm(kid.dnskey.ToDS(dns.SHA384), dns.ECDSAP256SHA256)}
		}, outcomeServfail, outcomeServfail},
		{"an unknown algorithm beside the key's", func(kid *fwdSecKey) []dns.RR {
			return []dns.RR{withAlgorithm(kid.dnskey.ToDS(dns.SHA256), 208), kid.dnskey.ToDS(dns.SHA384)}
		}, outcomeSecure, outcomeServfail},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := outcome(t, dsRig(t, c.ds, nil), fwdSecWWW, dns.TypeA); got != c.signed {
				t.Errorf("signed data: %s, want %s", got, c.signed)
			}
			if got := outcome(t, dsRig(t, c.ds, nil), unsigned, dns.TypeA); got != c.unsigned {
				t.Errorf("unsigned data: %s, want %s", got, c.unsigned)
			}
			imr := dsRig(t, c.ds, nil)
			_ = outcome(t, imr, fwdSecKid, dns.TypeDS)
			if got := outcome(t, imr, unsigned, dns.TypeA); got != c.unsigned {
				t.Errorf("unsigned data after the DS: %s, want %s", got, c.unsigned)
			}
		})
	}
}

// A trust anchor below the root that matches no key is an error whatever
// algorithm it names: the anchored zone and its children are SERVFAIL, never
// Insecure. The DS RRset the rule for unusable DS records applies to is the
// parent's, not the operator's anchor.
func TestTrustAnchorDSBelowTheRoot(t *testing.T) {
	keyDS := func(kid *fwdSecKey) []dns.RR { return []dns.RR{kid.dnskey.ToDS(dns.SHA256)} }
	for _, c := range []struct {
		name string
		alg  func(parent *fwdSecKey) uint8
		want string
	}{
		{"the key's algorithm", func(p *fwdSecKey) uint8 { return p.dnskey.Algorithm }, outcomeSecure},
		{"another supported algorithm", func(*fwdSecKey) uint8 { return dns.ECDSAP256SHA256 }, outcomeServfail},
		{"an unknown algorithm", func(*fwdSecKey) uint8 { return 208 }, outcomeServfail},
	} {
		t.Run(c.name, func(t *testing.T) {
			anchor := func(parent *fwdSecKey) []*dns.DS {
				return []*dns.DS{withAlgorithm(parent.dnskey.ToDS(dns.SHA256), c.alg(parent))}
			}
			if got := outcome(t, dsRig(t, keyDS, anchor), fwdSecWWW, dns.TypeA); got != c.want {
				t.Errorf("data under the anchor: %s, want %s", got, c.want)
			}
		})
	}
}

// The algorithms the resolver can verify: those with a real implementation in
// the registry, and RSASHA1 and RSASHA1-NSEC3-SHA1, which it validates
// although tdns does not sign with them. Not RSAMD5, DSA or ECC-GOST, nor an
// unassigned codepoint.
func TestDNSSECAlgorithmVerifiable(t *testing.T) {
	for _, alg := range []uint8{dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512,
		dns.ECDSAP256SHA256, dns.ECDSAP384SHA384, dns.ED25519, dns.ED448, 18} {
		if !cache.AlgorithmSupported(alg) {
			t.Errorf("algorithm %d: not supported, want supported", alg)
		}
	}
	for _, alg := range []uint8{dns.RSAMD5, dns.DSA, dns.DSANSEC3SHA1, dns.ECCGOST, 208} {
		if cache.AlgorithmSupported(alg) {
			t.Errorf("algorithm %d: supported, want not", alg)
		}
	}
}
