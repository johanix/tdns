/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Denials from secZone, signed with NSEC3: nx.sec.example does not exist, and
// www.sec.example has an A and nothing else.
const (
	n3NX  = "nx." + secZone
	n3WWW = "www." + secZone
)

// n3Denial is a signed denial from secZone: the SOA and each NSEC3 in its own
// RRset, all signed by k.
func n3Denial(t *testing.T, k *zoneKey, recs ...*dns.NSEC3) []*core.RRset {
	t.Helper()
	sets := []*core.RRset{k.sign(t, soaFor(t, secZone))}
	for _, r := range recs {
		sets = append(sets, k.sign(t, r))
	}
	return sets
}

// n3NameError is the records of a name error proof for nx.sec.example with
// flags and iterations: the apex matched, nx covered, and *.sec.example
// covered.
func n3NameError(flags uint8, iterations uint16) []*dns.NSEC3 {
	return []*dns.NSEC3{
		synthNSEC3(secZone, secZone, false, 0, iterations, "", dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM),
		synthNSEC3(secZone, n3NX, true, flags, iterations, ""),
		synthNSEC3(secZone, "*."+secZone, true, flags, iterations, ""),
	}
}

// ValidateDenial reads NSEC3 denials by RFC 5155 section 8, from the records
// that validate with the zone's own signatures.
func TestValidateDenialNSEC3(t *testing.T) {
	cases := []struct {
		name  string
		qname string
		qtype uint16
		rcode uint8
		sets  func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) []*core.RRset
		want  ValidationState
		ede   uint16
	}{
		{"name error", n3NX, dns.TypeA, dns.RcodeNameError, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return n3Denial(t, k, n3NameError(0, 0)...)
		}, ValidationStateSecure, 0},
		{"name error through Opt-Out", n3NX, dns.TypeA, dns.RcodeNameError, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return n3Denial(t, k, n3NameError(1, 0)...)
		}, ValidationStateInsecure, 0},
		{"name error without the wildcard cover", n3NX, dns.TypeA, dns.RcodeNameError, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return n3Denial(t, k, n3NameError(0, 0)[:2]...)
		}, ValidationStateBogus, 0},
		{"no data", n3WWW, dns.TypeMX, dns.RcodeSuccess, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return n3Denial(t, k, synthNSEC3(secZone, n3WWW, false, 0, 0, "", dns.TypeA, dns.TypeRRSIG))
		}, ValidationStateSecure, 0},
		{"no data, the type exists", n3WWW, dns.TypeA, dns.RcodeSuccess, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return n3Denial(t, k, synthNSEC3(secZone, n3WWW, false, 0, 0, "", dns.TypeA, dns.TypeRRSIG))
		}, ValidationStateBogus, 0},
		{"over the iteration limit", n3NX, dns.TypeA, dns.RcodeNameError, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			return n3Denial(t, k, n3NameError(0, DefaultNSEC3MaxIterations+1)...)
		}, ValidationStateInsecure, edeUnsupportedNSEC3Iterations},
		{"signed with a key the zone does not have", n3NX, dns.TypeA, dns.RcodeNameError, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			recs := n3NameError(0, 0)
			return append(n3Denial(t, k, recs[:2]...), strayKey(t, secZone).sign(t, recs[2]))
		}, ValidationStateIndeterminate, 0},
		// The signature is checked before the iteration count (RFC 9276): a
		// record whose signature cannot be followed does not make the denial
		// Insecure.
		{"over the limit, signed with a key the zone does not have", n3NX, dns.TypeA, dns.RcodeNameError, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			recs := n3NameError(0, DefaultNSEC3MaxIterations+1)
			return append(n3Denial(t, k, recs[:2]...), strayKey(t, secZone).sign(t, recs[2]))
		}, ValidationStateIndeterminate, 0},
		{"the wildcard cover owned in another zone", n3NX, dns.TypeA, dns.RcodeNameError, func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			recs := n3NameError(0, 0)
			recs[2].Hdr.Name = dns.SplitDomainName(recs[2].Hdr.Name)[0] + ".other." + secZone
			return n3Denial(t, k, recs...)
		}, ValidationStateBogus, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache, k := secCache(t)
			v, _ := rrcache.ValidateDenial(context.Background(), c.qname, c.qtype, c.rcode, c.sets(t, rrcache, k), nil)
			if v.State != c.want {
				t.Errorf("state %s, want %s", ValidationStateToString[v.State], ValidationStateToString[c.want])
			}
			if v.EDECode != c.ede {
				t.Errorf("EDE %d, want %d", v.EDECode, c.ede)
			}
			if v.Rcode != c.rcode {
				t.Errorf("rcode %d, want %d", v.Rcode, c.rcode)
			}
		})
	}
}

// NSEC3 records that do not count leave the denial without a proof: the
// answer is not used (an error), and never Secure. Signed by another zone,
// unsigned beside a signed SOA.
func TestValidateDenialNSEC3ThatDoesNotCount(t *testing.T) {
	for name, sets := range map[string]func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) []*core.RRset{
		"signed by the zone above": func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) []*core.RRset {
			above := newZoneKey(t, rrcache, "example.", true)
			var out []*core.RRset
			for _, r := range n3NameError(0, 0) {
				out = append(out, above.sign(t, r))
			}
			return append([]*core.RRset{k.sign(t, soaFor(t, secZone))}, out...)
		},
		"unsigned beside a signed SOA": func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
			out := []*core.RRset{k.sign(t, soaFor(t, secZone))}
			for _, r := range n3NameError(0, 0) {
				out = append(out, unsigned(r))
			}
			return out
		},
	} {
		t.Run(name, func(t *testing.T) {
			rrcache, k := secCache(t)
			v, err := rrcache.ValidateDenial(context.Background(), n3NX, dns.TypeA, dns.RcodeNameError, sets(t, rrcache, k), nil)
			if v.State == ValidationStateSecure || err == nil {
				t.Errorf("state %s, err %v: want an answer that is not used", ValidationStateToString[v.State], err)
			}
		})
	}
}

// The iteration limit is the configured one.
func TestValidateDenialNSEC3ConfiguredLimit(t *testing.T) {
	t.Cleanup(func() { SetNSEC3MaxIterations(DefaultNSEC3MaxIterations) })
	for _, c := range []struct {
		limit uint16
		want  ValidationState
	}{{10, ValidationStateSecure}, {9, ValidationStateInsecure}, {0, ValidationStateInsecure}} {
		SetNSEC3MaxIterations(c.limit)
		rrcache, k := secCache(t)
		v, _ := rrcache.ValidateDenial(context.Background(), n3NX, dns.TypeA, dns.RcodeNameError, n3Denial(t, k, n3NameError(0, 10)...), nil)
		if v.State != c.want {
			t.Errorf("limit %d, 10 iterations: %s, want %s", c.limit, ValidationStateToString[v.State], ValidationStateToString[c.want])
		}
	}
}

// A DS denial through an Opt-Out span is Insecure, and proves kid an
// insecure delegation. One over the iteration limit is Insecure too, but
// proves nothing that can be judged: kid is Indeterminate, as unsigned data
// below it is, not the Insecure the denial itself is. An unsigned denial below
// a Secure zone is Bogus, as it always was.
func TestInsecureNSEC3DSDenials(t *testing.T) {
	const optOut = 1
	cases := []struct {
		name     string
		denial   func(t *testing.T, k *zoneKey) []*core.RRset
		state    ValidationState
		evidence cutEvidence
		zone     ValidationState
	}{
		{"Opt-Out span", func(t *testing.T, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, soaFor(t, secZone)), k.sign(t, apexNSEC3(secZone)),
				k.sign(t, nsec3In(secZone, secKid, true, optOut, 0, dns.TypeA, dns.TypeRRSIG))}
		}, ValidationStateInsecure, evidenceInsecureCut, ValidationStateInsecure},
		{"over the iteration limit", func(t *testing.T, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, soaFor(t, secZone)),
				k.sign(t, nsec3In(secZone, secKid, false, 0, DefaultNSEC3MaxIterations+1, dns.TypeNS))}
		}, ValidationStateInsecure, evidenceUnjudged, ValidationStateIndeterminate},
		{"unsigned", func(t *testing.T, k *zoneKey) []*core.RRset {
			return []*core.RRset{unsigned(soaFor(t, secZone)), unsigned(nsec3In(secZone, secKid, false, 0, 0, dns.TypeNS))}
		}, ValidationStateBogus, evidenceBogus, ValidationStateBogus},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache, k := secCache(t)
			seedDSDenial(t, rrcache, secKid, c.denial(t, k)...)
			crr := rrcache.Get(secKid, dns.TypeDS)
			if crr.State != c.state {
				t.Fatalf("the denial is %s, want %s", ValidationStateToString[crr.State], ValidationStateToString[c.state])
			}
			if ev := rrcache.denialEvidence(context.Background(), secKid, crr, nil); ev != c.evidence {
				t.Errorf("evidence %s, want %s", evidenceToString[ev], evidenceToString[c.evidence])
			}
			if got, _ := rrcache.ValidateDNSKEYs(context.Background(), newKidZone(t).dnskey, nil); got != c.zone {
				t.Errorf("ValidateDNSKEYs: %s, want %s", ValidationStateToString[got], ValidationStateToString[c.zone])
			}
		})
	}
}

// An Insecure DS denial whose records do not validate -- unsigned, as from a
// zone held Insecure -- is bogus evidence below a Secure zone, as every
// Insecure denial was: an Opt-Out span counts only once its records validate.
func TestAnInsecureDSDenialWithoutValidRecordsIsBogusEvidence(t *testing.T) {
	rrcache, _ := secCache(t)
	auth := []*core.RRset{unsigned(soaFor(t, secZone)), unsigned(apexNSEC3(secZone)),
		unsigned(nsec3In(secZone, secKid, true, 1, 0, dns.TypeA, dns.TypeRRSIG))}
	rrcache.Set(secKid, dns.TypeDS, &CachedRRset{Name: secKid, RRtype: dns.TypeDS, Rcode: dns.RcodeSuccess, RRset: auth[0],
		NegAuthority: auth, Context: ContextNoErrNoAns, State: ValidationStateInsecure, Expiration: time.Now().Add(5 * time.Minute)})
	if ev := rrcache.denialEvidence(context.Background(), secKid, rrcache.Get(secKid, dns.TypeDS), nil); ev != evidenceBogus {
		t.Errorf("evidence %s, want %s", evidenceToString[ev], evidenceToString[evidenceBogus])
	}
}
