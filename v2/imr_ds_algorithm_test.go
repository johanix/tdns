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
// root's data is SERVFAIL, whether or not its keys were fetched at start-up.
// With the right algorithm it is Secure.
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

			imr = anchorImrDS(t, withAlgorithm(ds, dns.ECDSAP256SHA256), serve, startup)
			wantServfail(t, imr, askType(t, imr, ".", dns.TypeNS))
			wantServfail(t, imr, askType(t, imr, taUnsigned, dns.TypeA))
		})
	}
}

// A delegation whose DS names another algorithm than the child's key has no
// DS that matches the key: the child's data is SERVFAIL. With the right
// algorithm it is Secure.
func TestDelegationDSOfAnotherAlgorithmMatchesNoKey(t *testing.T) {
	for _, c := range []struct {
		name   string
		alg    func(kid *fwdSecKey) uint8
		secure bool
	}{
		{"the key's algorithm", func(kid *fwdSecKey) uint8 { return kid.dnskey.Algorithm }, true},
		{"another algorithm", func(*fwdSecKey) uint8 { return dns.ECDSAP256SHA256 }, false},
		{"an unknown algorithm", func(*fwdSecKey) uint8 { return 208 }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			parent, kid := newFwdSecKey(t, fwdSecParent), newFwdSecKey(t, fwdSecKid)
			ds := withAlgorithm(kid.dnskey.ToDS(dns.SHA256), c.alg(kid))
			addr, port := startSignedForwardUpstream(t, map[string]*dns.Msg{
				fwdSecWWW + " A":         {Answer: kid.sign(t, fwdSecRR(t, fwdSecWWW+" 300 IN A 192.0.2.7"))},
				fwdSecKid + " DNSKEY":    {Answer: kid.sign(t, dns.Copy(kid.dnskey))},
				fwdSecKid + " DS":        {Answer: parent.sign(t, ds)},
				fwdSecParent + " DNSKEY": {Answer: parent.sign(t, dns.Copy(parent.dnskey))},
			})
			imr := newForwardTestImr(t, []ImrForwardConf{{Zone: ".", Upstreams: []ImrUpstreamConf{{Addr: addr, Port: port}}}})
			imr.Cache.DnskeyCache = cache.NewDnskeyCache() // not the process-wide one
			if err := imr.Cache.PrimeFromHintsOnly(""); err != nil {
				t.Fatalf("PrimeFromHintsOnly: %v", err)
			}
			imr.Cache.DnskeyCache.Set(fwdSecParent, parent.dnskey.KeyTag(), &cache.CachedDnskeyRRset{
				Name: fwdSecParent, Keyid: parent.dnskey.KeyTag(), TrustAnchor: true, State: cache.ValidationStateSecure,
				Dnskey: *parent.dnskey, Expiration: time.Now().Add(time.Hour)})
			imr.Cache.ZoneMap.Set(fwdSecParent, &cache.Zone{ZoneName: fwdSecParent, State: cache.ValidationStateSecure})

			r := new(dns.Msg)
			r.SetQuestion(fwdSecWWW, dns.TypeA)
			r.SetEdns0(4096, true)
			cw := &captureWriter{}
			imr.ImrResponder(context.Background(), cw, r, fwdSecWWW, dns.TypeA, &edns0.MsgOptions{RD: true, DO: true})
			if cw.got == nil {
				t.Fatal("nothing written")
			}
			switch {
			case c.secure && (cw.got.Rcode != dns.RcodeSuccess || !cw.got.AuthenticatedData):
				t.Errorf("rcode %s, AD=%v; want NOERROR with AD", dns.RcodeToString[cw.got.Rcode], cw.got.AuthenticatedData)
			case !c.secure && cw.got.Rcode != dns.RcodeServerFailure:
				t.Errorf("rcode %s, AD=%v, %d answer RRs; want SERVFAIL",
					dns.RcodeToString[cw.got.Rcode], cw.got.AuthenticatedData, len(cw.got.Answer))
			}
		})
	}
}
