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

// The answers below are for wcQname in secZone, synthesized from wcWild
// (Labels 3): the wildcard's closest encloser is w.sec.example, and the next
// closer name z.w.sec.example.
const (
	wcWild  = "*.w." + secZone
	wcQname = "a.z.w." + secZone
	wcNC    = "z.w." + secZone
)

// wcAnswer signs the record in text, owned by a wildcard, with k, then serves
// it and its RRSIG owned by owner: an answer synthesized from the wildcard.
func wcAnswer(t *testing.T, k *zoneKey, text, owner string) *core.RRset {
	t.Helper()
	set := k.sign(t, rrFrom(t, text))
	set.RRs[0].Header().Name = owner
	set.RRSIGs[0].Header().Name = owner
	set.Name = owner
	return set
}

// wcA is wcQname's A, synthesized from wcWild.
func wcA(t *testing.T, k *zoneKey) *core.RRset {
	return wcAnswer(t, k, wcWild+" 300 IN A 192.0.2.7", wcQname)
}

// signedNSEC is the NSEC in text, signed by k.
func signedNSEC(t *testing.T, k *zoneKey, text string) *core.RRset {
	t.Helper()
	return k.sign(t, rrFrom(t, text))
}

// wcCover is the NSEC that proves wcQname absent, and nothing between it and
// w.sec.example: it covers a.z.w.sec.example and shares w.sec.example with it
// at both ends.
const wcCover = "x.w." + secZone + " 300 IN NSEC zz.w." + secZone + " A RRSIG NSEC"

func TestWildcardExpansionSignatures(t *testing.T) {
	_, k := secCache(t)
	cases := []struct {
		name  string
		rrset func() *core.RRset
		want  int
	}{
		{"synthesized from a wildcard", func() *core.RRset { return wcA(t, k) }, 1},
		{"the wildcard asked for by name", func() *core.RRset { return k.sign(t, rrFrom(t, wcWild+" 300 IN A 192.0.2.7")) }, 0},
		{"the owner's own record", func() *core.RRset { return k.sign(t, rrFrom(t, wcQname+" 300 IN A 192.0.2.7")) }, 0},
		{"an RRSIG over another type", func() *core.RRset {
			set := wcA(t, k)
			set.RRSIGs[0].(*dns.RRSIG).TypeCovered = dns.TypeAAAA
			return set
		}, 0},
		{"an RRSIG owned by another name", func() *core.RRset {
			set := wcA(t, k)
			set.RRSIGs[0].Header().Name = "b.z.w." + secZone
			return set
		}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, exp := splitExpansionSignatures(c.rrset()); len(exp) != c.want {
				t.Errorf("%d expansion signatures, want %d", len(exp), c.want)
			}
		})
	}
}

// An NSEC proof for an answer synthesized from a wildcard (RFC 4035 section
// 5.3.4).
func TestValidateAnswerWildcardNSEC(t *testing.T) {
	cases := []struct {
		name      string
		qname     string // wcQname unless set
		authority func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) []*core.RRset
		want      ValidationState
	}{
		{"the proof holds", "", func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, soaFor(t, secZone)), signedNSEC(t, k, wcCover)}
		}, ValidationStateSecure},
		{"no proof", "", func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, soaFor(t, secZone))}
		}, ValidationStateBogus},
		{"the cover proves a longer closest encloser", "", func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			// z.w.sec.example exists: the wildcard does not apply below it.
			return []*core.RRset{signedNSEC(t, k, wcNC+" 300 IN NSEC zz.w."+secZone+" A RRSIG NSEC")}
		}, ValidationStateBogus},
		{"the cover's next name is below qname", wcNC, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			// z.w.sec.example has a descendant: it exists.
			return []*core.RRset{signedNSEC(t, k, "x.w."+secZone+" 300 IN NSEC a."+wcNC+" A RRSIG NSEC")}
		}, ValidationStateBogus},
		{"the cover's owner is an ancestor with DNAME", "", func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{signedNSEC(t, k, "w."+secZone+" 300 IN NSEC zz.w."+secZone+" DNAME RRSIG NSEC")}
		}, ValidationStateBogus},
		{"the cover's owner is an ancestor with NS and no SOA", "", func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{signedNSEC(t, k, "w."+secZone+" 300 IN NSEC zz.w."+secZone+" NS RRSIG NSEC")}
		}, ValidationStateBogus},
		{"an ancestor that is neither: the proof holds", "", func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{signedNSEC(t, k, "w."+secZone+" 300 IN NSEC zz.w."+secZone+" TXT RRSIG NSEC")}
		}, ValidationStateSecure},
		{"an NSEC that does not cover qname", "", func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{signedNSEC(t, k, "b.w."+secZone+" 300 IN NSEC c.w."+secZone+" A RRSIG NSEC")}
		}, ValidationStateBogus},
		{"an NSEC owned by qname", "", func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{signedNSEC(t, k, wcQname+" 300 IN NSEC zz.w."+secZone+" A RRSIG NSEC")}
		}, ValidationStateBogus},
		{"the cover signed by the zone above", "", func(t *testing.T, rrcache *RRsetCacheT, _ *zoneKey) []*core.RRset {
			above := newZoneKey(t, rrcache, "example.", true)
			rrcache.ZoneMap.Set("example.", &Zone{ZoneName: "example.", State: ValidationStateSecure})
			return []*core.RRset{above.sign(t, rrFrom(t, wcCover))}
		}, ValidationStateBogus},
		{"a good cover beside an NSEC whose signature fails", "", func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			broken := signedNSEC(t, k, "b.w."+secZone+" 300 IN NSEC c.w."+secZone+" A RRSIG NSEC")
			broken.RRs[0].(*dns.NSEC).NextDomain = "d.w." + secZone
			return []*core.RRset{signedNSEC(t, k, wcCover), broken}
		}, ValidationStateBogus},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache, k := secCache(t)
			qname := c.qname
			if qname == "" {
				qname = wcQname
			}
			answer := wcAnswer(t, k, wcWild+" 300 IN A 192.0.2.7", qname)
			v, err := rrcache.ValidateAnswer(context.Background(), answer, c.authority(t, rrcache, k), nil)
			if err != nil {
				t.Fatalf("ValidateAnswer: %v", err)
			}
			if v.State != c.want {
				t.Errorf("%s, want %s", ValidationStateToString[v.State], ValidationStateToString[c.want])
			}
			if c.want == ValidationStateSecure && len(v.Proof) == 0 {
				t.Error("Secure, and no proof kept")
			}
		})
	}
}

// An NSEC3 proof for an answer synthesized from a wildcard (RFC 5155 section
// 8.8): a record covers the next closer name.
func TestValidateAnswerWildcardNSEC3(t *testing.T) {
	cases := []struct {
		name      string
		authority func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) []*core.RRset
		want      ValidationState
		ede       uint16
	}{
		{"the next closer name covered", func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, synthNSEC3(secZone, wcNC, true, 0, 0, ""))}
		}, ValidationStateSecure, 0},
		{"covered through Opt-Out", func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, synthNSEC3(secZone, wcNC, true, 1, 0, ""))}
		}, ValidationStateInsecure, 0},
		{"over the iteration limit", func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, synthNSEC3(secZone, wcNC, true, 0, DefaultNSEC3MaxIterations+1, ""))}
		}, ValidationStateInsecure, edeUnsupportedNSEC3Iterations},
		{"not covered", func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, synthNSEC3(secZone, wcQname, true, 0, 0, ""))}
		}, ValidationStateBogus, 0},
		{"covered by a record the zone above signed", func(t *testing.T, rrcache *RRsetCacheT, _ *zoneKey) []*core.RRset {
			above := newZoneKey(t, rrcache, "example.", true)
			rrcache.ZoneMap.Set("example.", &Zone{ZoneName: "example.", State: ValidationStateSecure})
			return []*core.RRset{above.sign(t, synthNSEC3(secZone, wcNC, true, 0, 0, ""))}
		}, ValidationStateBogus, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache, k := secCache(t)
			v, err := rrcache.ValidateAnswer(context.Background(), wcA(t, k), c.authority(t, rrcache, k), nil)
			if err != nil {
				t.Fatalf("ValidateAnswer: %v", err)
			}
			if v.State != c.want || v.EDECode != c.ede {
				t.Errorf("%s EDE %d, want %s EDE %d", ValidationStateToString[v.State], v.EDECode,
					ValidationStateToString[c.want], c.ede)
			}
		})
	}
}

// The signature that validates decides whether the answer was synthesized:
// one made over the owner itself is tried first, and needs no proof.
func TestValidateAnswerTheValidatingSignatureDecides(t *testing.T) {
	both := func(t *testing.T, k *zoneKey, breakOwn bool) *core.RRset {
		set := wcA(t, k)
		own := k.sign(t, rrFrom(t, wcQname+" 300 IN A 192.0.2.7")).RRSIGs[0].(*dns.RRSIG)
		if breakOwn {
			own.Signature = set.RRSIGs[0].(*dns.RRSIG).Signature
		}
		set.RRSIGs = append(set.RRSIGs, own) // the expansion signature first
		return set
	}
	t.Run("the owner's own signature validates", func(t *testing.T) {
		rrcache, k := secCache(t)
		v, _ := rrcache.ValidateAnswer(context.Background(), both(t, k, false), nil, nil)
		if v.State != ValidationStateSecure || len(v.Proof) != 0 {
			t.Errorf("%s with %d proof RRsets; want Secure, no proof", ValidationStateToString[v.State], len(v.Proof))
		}
	})
	t.Run("only the expansion signature validates", func(t *testing.T) {
		rrcache, k := secCache(t)
		if v, _ := rrcache.ValidateAnswer(context.Background(), both(t, k, true), nil, nil); v.State != ValidationStateBogus {
			t.Errorf("without a proof: %s, want Bogus", ValidationStateToString[v.State])
		}
		auth := []*core.RRset{signedNSEC(t, k, wcCover)}
		if v, _ := rrcache.ValidateAnswer(context.Background(), both(t, k, true), auth, nil); v.State != ValidationStateSecure {
			t.Errorf("with the proof: %s, want Secure", ValidationStateToString[v.State])
		}
	})
}

// The wildcard asked for by name is the owner's own record: no proof needed.
func TestValidateAnswerTheWildcardItself(t *testing.T) {
	rrcache, k := secCache(t)
	set := k.sign(t, rrFrom(t, wcWild+" 300 IN A 192.0.2.7"))
	v, err := rrcache.ValidateAnswer(context.Background(), set, nil, nil)
	if err != nil || v.State != ValidationStateSecure {
		t.Errorf("%s (%v), want Secure", ValidationStateToString[v.State], err)
	}
}

// A fresh answer is judged with its own authority section, not by the verdict
// cached for the same RRset.
func TestValidateAnswerDoesNotReuseAVerdictForAWildcard(t *testing.T) {
	rrcache, k := secCache(t)
	answer := wcA(t, k)
	rrcache.Set(wcQname, dns.TypeA, &CachedRRset{Name: wcQname, RRtype: dns.TypeA, RRset: answer,
		Context: ContextAnswer, State: ValidationStateSecure})
	if v, _ := rrcache.ValidateAnswer(context.Background(), answer, nil, nil); v.State != ValidationStateBogus {
		t.Errorf("%s, want Bogus: no proof came with it", ValidationStateToString[v.State])
	}
}

// ValidateRRset validates an answer synthesized from a wildcard with the proof
// kept on its cache entry, also an expired one; with none it is Bogus. A
// reusable verdict is reused.
func TestValidateRRsetUsesTheKeptProof(t *testing.T) {
	entry := func(answer *core.RRset, state ValidationState, proof []*core.RRset, exp time.Time) CachedRRset {
		return CachedRRset{Name: wcQname, RRtype: dns.TypeA, RRset: answer, Context: ContextAnswer,
			State: state, WildcardProof: proof, Expiration: exp}
	}
	cases := []struct {
		name string
		seed func(rrcache *RRsetCacheT, answer *core.RRset, proof []*core.RRset)
		want ValidationState
	}{
		{"the kept proof", func(rrcache *RRsetCacheT, answer *core.RRset, proof []*core.RRset) {
			rrcache.RRsets.Set(rrsetKey(wcQname, dns.TypeA), entry(answer, ValidationStateIndeterminate, proof, time.Now().Add(time.Hour)))
		}, ValidationStateSecure},
		{"the kept proof of an expired entry", func(rrcache *RRsetCacheT, answer *core.RRset, proof []*core.RRset) {
			rrcache.RRsets.Set(rrsetKey(wcQname, dns.TypeA), entry(answer, ValidationStateSecure, proof, time.Now().Add(-time.Second)))
		}, ValidationStateSecure},
		{"no entry", func(*RRsetCacheT, *core.RRset, []*core.RRset) {}, ValidationStateBogus},
		{"a reusable verdict", func(rrcache *RRsetCacheT, answer *core.RRset, _ []*core.RRset) {
			rrcache.RRsets.Set(rrsetKey(wcQname, dns.TypeA), entry(answer, ValidationStateInsecure, nil, time.Now().Add(time.Hour)))
		}, ValidationStateInsecure},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache, k := secCache(t)
			answer := wcA(t, k)
			c.seed(rrcache, answer, []*core.RRset{signedNSEC(t, k, wcCover)})
			if got, _ := rrcache.ValidateRRset(context.Background(), answer, nil); got != c.want {
				t.Errorf("%s, want %s", ValidationStateToString[got], ValidationStateToString[c.want])
			}
		})
	}
}

// The proof kept is the zone's own NSEC and NSEC3 RRsets, with its RRSIGs.
func TestValidateAnswerKeepsOnlyTheZonesProofRecords(t *testing.T) {
	rrcache, k := secCache(t)
	other := newZoneKey(t, rrcache, "other.example.", true)
	zoneNSEC3 := k.sign(t, synthNSEC3(secZone, wcNC, true, 0, 0, ""))
	zoneNSEC3.RRSIGs = append(zoneNSEC3.RRSIGs, other.sign(t, zoneNSEC3.RRs...).RRSIGs...)
	auth := []*core.RRset{
		k.sign(t, soaFor(t, secZone)),
		k.sign(t, rrFrom(t, secZone+" 300 IN NS ns."+secZone)),
		zoneNSEC3,
		other.sign(t, synthNSEC3("other.example.", "x.other.example.", true, 0, 0, "")),
		k.sign(t, synthNSEC3("sub."+secZone, "x.sub."+secZone, true, 0, 0, "")), // not directly below the zone
		unsigned(synthNSEC3(secZone, "q.w."+secZone, true, 0, 0, "")),
	}
	v, err := rrcache.ValidateAnswer(context.Background(), wcA(t, k), auth, nil)
	if err != nil || v.State != ValidationStateSecure {
		t.Fatalf("%s (%v), want Secure", ValidationStateToString[v.State], err)
	}
	if len(v.Proof) != 1 || v.Proof[0].RRtype != dns.TypeNSEC3 || len(v.Proof[0].RRSIGs) != 1 ||
		v.Proof[0].RRSIGs[0].(*dns.RRSIG).SignerName != secZone {
		t.Errorf("proof %v; want the zone's NSEC3 with the zone's RRSIG only", v.Proof)
	}
}

// From a zone held Insecure the answer is Insecure: there is nothing to check a
// proof against, and none is needed. What came is kept.
func TestValidateAnswerZoneHeldInsecure(t *testing.T) {
	rrcache, k := secCache(t)
	rrcache.ZoneMap.Set(secZone, &Zone{ZoneName: secZone, State: ValidationStateInsecure})
	v, _ := rrcache.ValidateAnswer(context.Background(), wcA(t, k), nil, nil)
	if v.State != ValidationStateInsecure {
		t.Errorf("no proof: %s, want Insecure", ValidationStateToString[v.State])
	}
	v, _ = rrcache.ValidateAnswer(context.Background(), wcA(t, k), []*core.RRset{signedNSEC(t, k, wcCover)}, nil)
	if v.State != ValidationStateInsecure || len(v.Proof) != 1 {
		t.Errorf("%s with %d proof RRsets; want Insecure, the proof kept", ValidationStateToString[v.State], len(v.Proof))
	}
}

// When the signer's keys are out of reach the answer is Indeterminate, and the
// proof is kept, to be checked when the answer is validated again.
func TestValidateAnswerIndeterminateKeepsTheProof(t *testing.T) {
	rrcache, k := secCache(t)
	stray := strayKey(t, secZone)
	v, _ := rrcache.ValidateAnswer(context.Background(), wcAnswer(t, stray, wcWild+" 300 IN A 192.0.2.7", wcQname),
		[]*core.RRset{signedNSEC(t, k, wcCover)}, nil)
	if v.State != ValidationStateIndeterminate || len(v.Proof) != 1 {
		t.Errorf("%s with %d proof RRsets; want Indeterminate, the proof kept", ValidationStateToString[v.State], len(v.Proof))
	}
}

// A DNSKEY RRset is validated against its trust anchor or DS, as before,
// whatever RRSIGs come with it: a stray one made over a wildcard does not take
// it off that path.
func TestValidateAnswerDNSKEYIsNotAWildcard(t *testing.T) {
	rrcache := negCache(t)
	const zone = secZone
	ksk := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 257, Protocol: 3, Algorithm: dns.ED25519}
	priv, err := ksk.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	zsk := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 256, Protocol: 3, Algorithm: dns.ED25519}
	if _, err := zsk.Generate(256); err != nil {
		t.Fatal(err)
	}
	rrcache.DnskeyCache.Set(zone, ksk.KeyTag(), &CachedDnskeyRRset{Name: zone, Keyid: ksk.KeyTag(),
		State: ValidationStateSecure, TrustAnchor: true, Dnskey: *ksk, Expiration: time.Now().Add(time.Hour)})
	rrs := []dns.RR{dns.Copy(ksk), dns.Copy(zsk)}
	sig := &dns.RRSIG{Algorithm: dns.ED25519, KeyTag: ksk.KeyTag(), SignerName: zone,
		Inception: uint32(time.Now().Add(-time.Hour).Unix()), Expiration: uint32(time.Now().Add(time.Hour).Unix())}
	if err := sig.Sign(priv.(crypto.Signer), rrs); err != nil {
		t.Fatal(err)
	}
	stray := dns.Copy(sig).(*dns.RRSIG)
	stray.Labels = 1
	stray.KeyTag = ksk.KeyTag() + 1 // another key's
	set := &core.RRset{Name: zone, Class: dns.ClassINET, RRtype: dns.TypeDNSKEY, RRs: rrs, RRSIGs: []dns.RR{stray, sig}}

	v, err := rrcache.ValidateAnswer(context.Background(), set, nil, nil)
	if err != nil || v.State != ValidationStateSecure {
		t.Fatalf("%s (%v), want Secure", ValidationStateToString[v.State], err)
	}
	if got := rrcache.DnskeyCache.Get(zone, zsk.KeyTag()); got == nil || got.State != ValidationStateSecure {
		t.Errorf("the ZSK is not held Secure: the RRset did not go through ValidateDNSKEYs")
	}
}

// An answer synthesized from a wildcard lives no longer than its proof.
func TestSetBoundsAWildcardAnswerByItsProof(t *testing.T) {
	rrcache, k := secCache(t)
	answer := wcA(t, k) // TTL 300
	proof := signedNSEC(t, k, "x.w."+secZone+" 60 IN NSEC zz.w."+secZone+" A RRSIG NSEC")
	for _, c := range []struct {
		name  string
		proof []*core.RRset
		want  time.Duration
	}{
		{"with a proof", []*core.RRset{proof}, 60 * time.Second},
		{"without", nil, 300 * time.Second},
	} {
		t.Run(c.name, func(t *testing.T) {
			rrcache.Set(wcQname, dns.TypeA, &CachedRRset{Name: wcQname, RRtype: dns.TypeA, RRset: answer,
				Context: ContextAnswer, State: ValidationStateSecure, WildcardProof: c.proof})
			got := rrcache.Peek(wcQname, dns.TypeA).Expiration.Sub(Now())
			if got > c.want || got < c.want-5*time.Second {
				t.Errorf("lives %v, want %v", got, c.want)
			}
		})
	}
}
