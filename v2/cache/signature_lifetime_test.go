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

// The entries below are stored on a 2010 data clock, with signatures valid
// from an hour before it until expiring, unless a case says otherwise.
var (
	sigFrom = faketime2010.Add(-time.Hour)
	inAWeek = faketime2010.Add(7 * 24 * time.Hour)
	in60s   = faketime2010.Add(60 * time.Second)
)

// storedTTL stores c under <qname, qtype> and returns the lifetime it was
// given, in seconds.
func storedTTL(t *testing.T, rrcache *RRsetCacheT, qname string, qtype uint16, c *CachedRRset) uint32 {
	t.Helper()
	rrcache.Set(qname, qtype, c)
	got := rrcache.Peek(qname, qtype)
	if got == nil {
		t.Fatalf("%s %s: not cached", qname, dns.TypeToString[qtype])
	}
	return got.Ttl
}

// withServedTTL returns the records of set served with TTL ttl, and its
// RRSIGs as they are: signatures made over the records at their Original TTL.
func withServedTTL(set *core.RRset, ttl uint32) *core.RRset {
	out := &core.RRset{Name: set.Name, Class: set.Class, RRtype: set.RRtype, RRSIGs: set.RRSIGs}
	for _, rr := range set.RRs {
		c := dns.Copy(rr)
		c.Header().Ttl = ttl
		out.RRs = append(out.RRs, c)
	}
	return out
}

// A positive answer held Secure lives no longer than its signature: not past
// its Signature Expiration, and not past its Original TTL or the RRSIG's own
// TTL (RFC 4035 section 5.3.3). The same answer held Insecure is not
// authenticated, and lives for its TTL.
func TestAnAuthenticatedAnswerLivesNoLongerThanItsSignature(t *testing.T) {
	useFaketime(t, faketime2010)
	const www = "www." + secZone
	for _, c := range []struct {
		name  string
		state ValidationState
		set   func(k *zoneKey) *core.RRset
		want  uint32
	}{
		{"Secure, the signature expires in 60 s", ValidationStateSecure, func(k *zoneKey) *core.RRset {
			return k.signAt(t, sigFrom, in60s, rrFrom(t, www+" 3600 IN A 192.0.2.1"))
		}, 60},
		{"Insecure, the signature expires in 60 s", ValidationStateInsecure, func(k *zoneKey) *core.RRset {
			return k.signAt(t, sigFrom, in60s, rrFrom(t, www+" 3600 IN A 192.0.2.1"))
		}, 3600},
		{"Secure, Original TTL 300, served with 3600", ValidationStateSecure, func(k *zoneKey) *core.RRset {
			return withServedTTL(k.signAt(t, sigFrom, inAWeek, rrFrom(t, www+" 300 IN A 192.0.2.1")), 3600)
		}, 300},
		{"Secure, the RRSIG's own TTL 120", ValidationStateSecure, func(k *zoneKey) *core.RRset {
			set := k.signAt(t, sigFrom, inAWeek, rrFrom(t, www+" 3600 IN A 192.0.2.1"))
			set.RRSIGs[0].Header().Ttl = 120
			return set
		}, 120},
		{"Secure, an expired signature beside a current one", ValidationStateSecure, func(k *zoneKey) *core.RRset {
			set := k.signAt(t, sigFrom, inAWeek, rrFrom(t, www+" 3600 IN A 192.0.2.1"))
			old := k.signAt(t, sigFrom.Add(-24*time.Hour), faketime2010.Add(-time.Minute), rrFrom(t, www+" 3600 IN A 192.0.2.1"))
			set.RRSIGs = append(set.RRSIGs, old.RRSIGs...)
			return set
		}, 3600},
	} {
		t.Run(c.name, func(t *testing.T) {
			rrcache := negCache(t)
			k := newZoneKey(t, rrcache, secZone, true)
			got := storedTTL(t, rrcache, www, dns.TypeA, &CachedRRset{Name: www, RRtype: dns.TypeA, RRset: c.set(k),
				Context: ContextAnswer, State: c.state})
			if got != c.want && got+1 != c.want {
				t.Errorf("lifetime %d s, want %d", got, c.want)
			}
		})
	}
}

// A denial held Secure lives no longer than the signatures over its proof:
// with the SOA's TTL and MINIMUM at 3600, and the proof signed until 60 s
// from now, it is gone 61 s on. NSEC NXDOMAIN, NSEC NODATA and NSEC3
// NXDOMAIN alike. An Original TTL below the TTL served bounds it too.
func TestAnAuthenticatedDenialLivesNoLongerThanItsProofsSignatures(t *testing.T) {
	soa := func(t *testing.T) dns.RR {
		return rrFrom(t, secZone+" 3600 IN SOA ns."+secZone+" h."+secZone+" 1 7200 1800 604800 3600")
	}
	n3 := func(r *dns.NSEC3) dns.RR { r.Hdr.Ttl = 3600; return r }
	cases := []struct {
		name  string
		qname string
		ctx   CacheContext
		proof func(t *testing.T, k *zoneKey) []*core.RRset
		want  uint32
	}{
		{"NSEC, NXDOMAIN", "nx." + secZone, ContextNXDOMAIN, func(t *testing.T, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.signAt(t, sigFrom, in60s, rrFrom(t, secZone+" 3600 IN NSEC zzz."+secZone+" SOA NS RRSIG NSEC DNSKEY"))}
		}, 60},
		{"NSEC, NODATA", secWWW, ContextNoErrNoAns, func(t *testing.T, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.signAt(t, sigFrom, in60s, rrFrom(t, secWWW+" 3600 IN NSEC zzz."+secZone+" A RRSIG NSEC"))}
		}, 60},
		{"NSEC3, NXDOMAIN", n3NX, ContextNXDOMAIN, func(t *testing.T, k *zoneKey) []*core.RRset {
			var sets []*core.RRset
			for _, r := range n3NameError(0, 0) {
				sets = append(sets, k.signAt(t, sigFrom, in60s, n3(r)))
			}
			return sets
		}, 60},
		{"NSEC, Original TTL 300, served with 3600", "nx." + secZone, ContextNXDOMAIN, func(t *testing.T, k *zoneKey) []*core.RRset {
			signed := k.signAt(t, sigFrom, inAWeek, rrFrom(t, secZone+" 300 IN NSEC zzz."+secZone+" SOA NS RRSIG NSEC DNSKEY"))
			return []*core.RRset{withServedTTL(signed, 3600)}
		}, 300},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, path := useFaketime(t, faketime2010)
			rrcache := negCache(t)
			k := newZoneKey(t, rrcache, secZone, true)
			soaSet := k.signAt(t, sigFrom, inAWeek, soa(t))
			auth := append([]*core.RRset{soaSet}, c.proof(t, k)...)
			rcode := uint8(dns.RcodeNameError)
			if c.ctx == ContextNoErrNoAns {
				rcode = dns.RcodeSuccess
			}
			got := storedTTL(t, rrcache, c.qname, dns.TypeA, &CachedRRset{Name: c.qname, RRtype: dns.TypeA, Rcode: rcode,
				RRset: soaSet, NegAuthority: auth, Context: c.ctx, State: ValidationStateSecure})
			if got != c.want && got+1 != c.want {
				t.Errorf("lifetime %d s, want %d", got, c.want)
			}
			writeFaketime(t, path, faketime2010.Add(time.Duration(c.want+1)*time.Second))
			if e := rrcache.Get(c.qname, dns.TypeA); e != nil {
				t.Errorf("still cached %d s on, expiring %v", c.want+1, e.Expiration)
			}
		})
	}
}

// cache-min-ttl raises a Secure entry's TTL, its RRSIG's TTL and Original
// TTL included, as any other. It does not keep a Secure entry past its
// signature's expiration: nothing serves AD for data whose signatures have
// expired. cache-max-ttl still lowers it. An entry that is not Secure is not
// bounded by signatures at all.
func TestTheSignatureBoundsASecureEntryWhateverCacheMinTTL(t *testing.T) {
	useFaketime(t, faketime2010)
	const www = "www." + secZone
	for _, c := range []struct {
		name   string
		limits TTLLimits
		state  ValidationState
		until  time.Time
		want   uint32
	}{
		{"cache-min-ttl, a signature valid for a week", TTLLimits{Min: 600}, ValidationStateSecure, inAWeek, 600},
		{"cache-min-ttl, a signature expiring in 60 s", TTLLimits{Min: 600}, ValidationStateSecure, in60s, 60},
		{"cache-min-ttl, Insecure, a signature expiring in 60 s", TTLLimits{Min: 600}, ValidationStateInsecure, in60s, 600},
		{"cache-max-ttl below the signature", TTLLimits{Max: 30}, ValidationStateSecure, in60s, 30},
	} {
		t.Run(c.name, func(t *testing.T) {
			withTTLLimits(t, c.limits)
			rrcache := negCache(t)
			k := newZoneKey(t, rrcache, secZone, true)
			got := storedTTL(t, rrcache, www, dns.TypeA, &CachedRRset{Name: www, RRtype: dns.TypeA,
				RRset: k.signAt(t, sigFrom, c.until, rrFrom(t, www+" 60 IN A 192.0.2.1")), Context: ContextAnswer, State: c.state})
			if got != c.want && got+1 != c.want {
				t.Errorf("lifetime %d s, want %d", got, c.want)
			}
		})
	}
}

// The proof kept with an answer synthesized from a wildcard is served with
// it, and its signatures bound the answer's life as the answer's own do.
func TestAWildcardAnswerLivesNoLongerThanItsProofsSignatures(t *testing.T) {
	useFaketime(t, faketime2010)
	const www = "www." + secZone
	rrcache := negCache(t)
	k := newZoneKey(t, rrcache, secZone, true)
	proof := k.signAt(t, sigFrom, in60s, rrFrom(t, secZone+" 3600 IN NSEC zzz."+secZone+" SOA NS RRSIG NSEC DNSKEY"))
	got := storedTTL(t, rrcache, www, dns.TypeA, &CachedRRset{Name: www, RRtype: dns.TypeA,
		RRset: k.signAt(t, sigFrom, inAWeek, rrFrom(t, www+" 3600 IN A 192.0.2.1")), WildcardProof: []*core.RRset{proof},
		Context: ContextAnswer, State: ValidationStateSecure})
	if got != 60 && got != 59 {
		t.Errorf("lifetime %d s, want 60", got)
	}
}
