/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A CNAME on the way down from a secure zone answers the DS question there
// (#875). alias owns a CNAME; below it, sub is delegated without a DS, and the
// parent side proves it. The resolver caches the CNAME as a link at
// <alias, CNAME> and nothing under <alias, DS>.
const (
	secAlias    = "alias." + secZone
	secAliasSub = "sub." + secAlias
	aliasSubWWW = "www." + secAliasSub
)

func seedLink(rrcache *RRsetCacheT, link *core.RRset, state ValidationState, synthesizedFrom string) {
	rrcache.Set(link.Name, dns.TypeCNAME, &CachedRRset{Name: link.Name, RRtype: dns.TypeCNAME,
		Rcode: dns.RcodeSuccess, RRset: link, Context: ContextAnswer, State: state,
		Expiration: time.Now().Add(5 * time.Minute), SynthesizedFrom: synthesizedFrom})
}

func TestACNAMEOnTheWayDownAnswersTheDSQuestion(t *testing.T) {
	cname := func(t *testing.T) dns.RR { return rrFrom(t, secAlias+" 300 IN CNAME target.example.") }
	cases := []struct {
		name string
		seed func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey)
		want ValidationState
	}{
		{
			// The parent signs a CNAME at alias: alias is no delegation, and
			// the walk goes on to the proven insecure delegation at sub.
			name: "secure, signed by the zone above",
			seed: func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) {
				seedLink(rrcache, k.sign(t, cname(t)), ValidationStateSecure, "")
			},
			want: ValidationStateInsecure,
		},
		{
			// A CNAME whose signer is alias itself would have a zone apex
			// holding a CNAME, which there cannot be. Whatever its verdict,
			// it proves nothing about a cut.
			name: "secure, signed by its own owner",
			seed: func(t *testing.T, rrcache *RRsetCacheT, _ *zoneKey) {
				kk := newZoneKey(t, rrcache, secAlias, false)
				seedLink(rrcache, kk.sign(t, cname(t)), ValidationStateSecure, "")
			},
			want: ValidationStateBogus,
		},
		{
			name: "bogus",
			seed: func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) {
				seedLink(rrcache, k.sign(t, cname(t)), ValidationStateBogus, "")
			},
			want: ValidationStateBogus,
		},
		{
			// An unsigned CNAME in a zone held Secure was stripped on the way.
			name: "unsigned, held insecure",
			seed: func(t *testing.T, rrcache *RRsetCacheT, _ *zoneKey) {
				seedLink(rrcache, unsigned(cname(t)), ValidationStateInsecure, "")
			},
			want: ValidationStateBogus,
		},
		{
			// A link synthesized from a DNAME is unsigned; the DNAME's
			// signature, from the zone above, is what counts.
			name: "synthesized from a signed DNAME",
			seed: func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) {
				dname := k.sign(t, rrFrom(t, secZone+" 300 IN DNAME other.example."))
				rrcache.Set(secZone, dns.TypeDNAME, &CachedRRset{Name: secZone, RRtype: dns.TypeDNAME,
					RRset: dname, Context: ContextAnswer, State: ValidationStateSecure,
					Expiration: time.Now().Add(5 * time.Minute)})
				seedLink(rrcache, unsigned(cname(t)), ValidationStateSecure, secZone)
			},
			want: ValidationStateInsecure,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache, k := secCache(t)
			seedDSDenial(t, rrcache, secAliasSub, k.sign(t, soaFor(t, secZone)),
				k.sign(t, rrFrom(t, secAliasSub+" 300 IN NSEC "+aliasSubWWW+" NS RRSIG NSEC")))
			c.seed(t, rrcache, k)
			f := &fetchCounter{}
			if state := validateUnsigned(t, rrcache, aliasSubWWW+" 300 IN A 192.0.2.5", f.fetch); state != c.want {
				t.Errorf("state %s, want %s", ValidationStateToString[state], ValidationStateToString[c.want])
			}
			if f.n != 0 {
				t.Errorf("%d DS question(s) asked: the cached link answers the one at alias", f.n)
			}
			if c := rrcache.Get(secAlias, dns.TypeDS); c != nil {
				t.Errorf("an entry appeared under <alias, DS>: %+v", c)
			}
		})
	}
}

// Without a link in the cache, the question at alias is asked, and with no
// answer the data is bogus, as before.
func TestNoLinkOnTheWayDownIsAskedFor(t *testing.T) {
	rrcache, k := secCache(t)
	seedDSDenial(t, rrcache, secAliasSub, k.sign(t, soaFor(t, secZone)),
		k.sign(t, rrFrom(t, secAliasSub+" 300 IN NSEC "+aliasSubWWW+" NS RRSIG NSEC")))
	f := &fetchCounter{}
	if state := validateUnsigned(t, rrcache, aliasSubWWW+" 300 IN A 192.0.2.5", f.fetch); state != ValidationStateBogus {
		t.Errorf("state %s, want bogus", ValidationStateToString[state])
	}
	if f.n != 1 {
		t.Errorf("%d DS question(s) asked, want 1, at alias", f.n)
	}
}
