/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"crypto"
	"errors"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// secZone is signed, and the resolver holds it as Secure under a trust anchor.
// kid is a name below it that may or may not be a delegation.
const (
	secZone = "sec.example."
	secWWW  = "www." + secZone
	secKid  = "kid." + secZone
	kidWWW  = "www." + secKid
)

// zoneKey is a key the cache holds as Secure for its zone.
type zoneKey struct {
	zone string
	key  *dns.DNSKEY
	priv crypto.Signer
}

func newZoneKey(t *testing.T, rrcache *RRsetCacheT, zone string, trustAnchor bool) *zoneKey {
	t.Helper()
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300},
		Flags: 256, Protocol: 3, Algorithm: dns.ED25519}
	p, err := k.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	rrcache.DnskeyCache.Set(zone, k.KeyTag(), &CachedDnskeyRRset{Name: zone, Keyid: k.KeyTag(), TrustAnchor: trustAnchor,
		State: ValidationStateSecure, Dnskey: *k, Expiration: time.Now().Add(time.Hour)})
	return &zoneKey{zone: zone, key: k, priv: p.(crypto.Signer)}
}

func (k *zoneKey) sign(t *testing.T, rrs ...dns.RR) *core.RRset {
	t.Helper()
	sig := &dns.RRSIG{Algorithm: dns.ED25519, KeyTag: k.key.KeyTag(), SignerName: k.zone,
		Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
		Expiration: uint32(time.Now().Add(time.Hour).Unix())}
	if err := sig.Sign(k.priv, rrs); err != nil {
		t.Fatal(err)
	}
	h := rrs[0].Header()
	return &core.RRset{Name: h.Name, Class: dns.ClassINET, RRtype: h.Rrtype, RRs: rrs, RRSIGs: []dns.RR{sig}}
}

func rrFrom(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return rr
}

func soaFor(t *testing.T, zone string) dns.RR {
	return rrFrom(t, zone+" 300 IN SOA ns."+zone+" hostmaster."+zone+" 1 7200 1800 604800 300")
}

// secCache holds secZone as Secure under a trust anchor, with servers for it.
func secCache(t *testing.T) (*RRsetCacheT, *zoneKey) {
	t.Helper()
	rrcache := negCache(t)
	k := newZoneKey(t, rrcache, secZone, true)
	rrcache.ZoneMap.Set(secZone, &Zone{ZoneName: secZone, State: ValidationStateSecure})
	rrcache.ServerMap.Set(secZone, map[string]*AuthServer{"ns." + secZone: NewAuthServer("ns." + secZone)})
	return rrcache, k
}

// seedDSDenial caches the parent side's denial of a DS at name the way
// handleNegative does: validated, with its proof beside it.
func seedDSDenial(t *testing.T, rrcache *RRsetCacheT, name string, auth ...*core.RRset) {
	t.Helper()
	state, rcode, _ := rrcache.ValidateNegativeResponse(context.Background(), name, dns.TypeDS, dns.RcodeSuccess, auth, nil)
	cctx := ContextNoErrNoAns
	if rcode == dns.RcodeNameError {
		cctx = ContextNXDOMAIN
	}
	rrcache.Set(name, dns.TypeDS, &CachedRRset{Name: name, RRtype: dns.TypeDS, Rcode: rcode, RRset: auth[0],
		NegAuthority: auth, Context: cctx, State: state, Expiration: time.Now().Add(5 * time.Minute)})
}

// fetchCounter is a fetcher that gets no answer, and counts the questions.
type fetchCounter struct{ n int }

func (f *fetchCounter) fetch(context.Context, string, uint16, map[string]*AuthServer) (*core.RRset, error) {
	f.n++
	return nil, errors.New("no answer")
}

func validateUnsigned(t *testing.T, rrcache *RRsetCacheT, rr string, fetcher RRsetFetcher) ValidationState {
	t.Helper()
	state, err := rrcache.ValidateRRset(context.Background(), unsigned(rrFrom(t, rr)), fetcher)
	if err != nil {
		t.Fatalf("ValidateRRset(%s): %v", rr, err)
	}
	return state
}

// THE DEFECT. Unsigned data from a zone held Secure validated Insecure, and was
// served. The parent side's NSEC says www is ordinary data, not a delegation.
func TestUnsignedDataInASecureZoneIsBogus(t *testing.T) {
	rrcache, k := secCache(t)
	seedDSDenial(t, rrcache, secWWW, k.sign(t, soaFor(t, secZone)),
		k.sign(t, rrFrom(t, secWWW+" 300 IN NSEC zzz."+secZone+" A RRSIG NSEC")))

	if state := validateUnsigned(t, rrcache, secWWW+" 300 IN A 192.0.2.1", nil); state != ValidationStateBogus {
		t.Fatalf("state %s, want bogus: the zone is signed and www is no delegation", ValidationStateToString[state])
	}
}

// Data at the apex of a secure zone has no delegation above it to look for: it
// is bogus without a question asked.
func TestUnsignedApexDataOfASecureZoneIsBogus(t *testing.T) {
	rrcache, _ := secCache(t)
	f := &fetchCounter{}
	if state := validateUnsigned(t, rrcache, secZone+" 300 IN MX 10 mail."+secZone, f.fetch); state != ValidationStateBogus {
		t.Fatalf("state %s, want bogus", ValidationStateToString[state])
	}
	if f.n != 0 {
		t.Errorf("%d DS question(s) asked for apex data", f.n)
	}
}

// The legitimate case: kid is delegated from the secure zone without a DS, from
// the same servers, so the resolver never saw a referral and has no entry for
// it. The parent's NSEC at kid proves the delegation insecure.
func TestUnsignedDataBelowAProvenInsecureDelegationIsInsecure(t *testing.T) {
	rrcache, k := secCache(t)
	seedDSDenial(t, rrcache, secKid, k.sign(t, soaFor(t, secZone)),
		k.sign(t, rrFrom(t, secKid+" 300 IN NSEC "+secWWW+" NS RRSIG NSEC")))

	for _, rr := range []string{kidWWW + " 300 IN A 192.0.2.2", secKid + " 300 IN SOA ns." + secKid + " h." + secKid + " 1 2 3 4 5"} {
		if state := validateUnsigned(t, rrcache, rr, nil); state != ValidationStateInsecure {
			t.Errorf("%s: state %s, want insecure", rr, ValidationStateToString[state])
		}
	}
	if z, ok := rrcache.ZoneMap.Get(secKid); !ok || z.GetState() != ValidationStateInsecure {
		t.Fatalf("the proven insecure delegation %s is not in ZoneMap as insecure", secKid)
	}
	// Known now, it is not asked about again.
	f := &fetchCounter{}
	if state := validateUnsigned(t, rrcache, "mail."+secKid+" 300 IN A 192.0.2.3", f.fetch); state != ValidationStateInsecure || f.n != 0 {
		t.Errorf("state %s after %d DS question(s), want insecure after none", ValidationStateToString[state], f.n)
	}
}

// The proofs that must not pass for an insecure delegation.
func TestWhatDoesNotProveAnInsecureDelegation(t *testing.T) {
	cases := []struct {
		name  string
		proof func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) []*core.RRset
		want  ValidationState
	}{
		{
			// The attacker strips the proof too.
			name: "stripped denial",
			proof: func(t *testing.T, _ *RRsetCacheT, _ *zoneKey) []*core.RRset {
				return []*core.RRset{unsigned(soaFor(t, secZone)), unsigned(rrFrom(t, secKid+" 300 IN NSEC "+secWWW+" NS RRSIG NSEC"))}
			},
			want: ValidationStateBogus,
		},
		{
			// An unsigned NODATA that names kid as its zone: the child speaking,
			// or a forgery that says so.
			name: "unsigned child-side denial",
			proof: func(t *testing.T, _ *RRsetCacheT, _ *zoneKey) []*core.RRset {
				return []*core.RRset{unsigned(soaFor(t, secKid))}
			},
			want: ValidationStateBogus,
		},
		{
			// An NSEC with NS at kid, signed by a key held for kid itself rather
			// than by the parent.
			name: "delegation NSEC signed by the child",
			proof: func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) []*core.RRset {
				kk := newZoneKey(t, rrcache, secKid, false)
				return []*core.RRset{k.sign(t, soaFor(t, secZone)), kk.sign(t, rrFrom(t, secKid+" 300 IN NSEC "+secWWW+" NS RRSIG NSEC"))}
			},
			want: ValidationStateBogus,
		},
		{
			// A signed NSEC3 denial that neither matches kid nor holds a closest
			// encloser proof for it proves nothing about kid (nsec3CutProof).
			name: "NSEC3 denial proving nothing about kid",
			proof: func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
				return []*core.RRset{k.sign(t, soaFor(t, secZone)),
					k.sign(t, rrFrom(t, "2vptu5timamqttgl4luu9kg21e0aor3s."+secZone+" 300 IN NSEC3 1 0 0 - 2vptu5timamqttgl4luu9kg21e0aor3t NS RRSIG"))}
			},
			want: ValidationStateBogus,
		},
		{
			// A proof of no DS signed with a key secZone does not have validates
			// Indeterminate, which anyone can make.
			name: "denial signed with a stray key",
			proof: func(t *testing.T, _ *RRsetCacheT, k *zoneKey) []*core.RRset {
				return []*core.RRset{k.sign(t, soaFor(t, secZone)),
					strayKey(t, secZone).sign(t, rrFrom(t, secKid+" 300 IN NSEC "+secWWW+" NS RRSIG NSEC"))}
			},
			want: ValidationStateBogus,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache, k := secCache(t)
			seedDSDenial(t, rrcache, secKid, c.proof(t, rrcache, k)...)
			if state := validateUnsigned(t, rrcache, kidWWW+" 300 IN A 192.0.2.2", nil); state != c.want {
				t.Errorf("state %s, want %s", ValidationStateToString[state], ValidationStateToString[c.want])
			}
			if z, ok := rrcache.ZoneMap.Get(secKid); ok && z.GetState() == ValidationStateInsecure {
				t.Errorf("%s was entered in ZoneMap as insecure", secKid)
			}
		})
	}
}

// No answer to the DS question is no proof: an attacker who strips the
// signatures can as easily drop the question.
func TestNoAnswerToTheDSQuestionIsBogus(t *testing.T) {
	rrcache, _ := secCache(t)
	f := &fetchCounter{}
	if state := validateUnsigned(t, rrcache, secWWW+" 300 IN A 192.0.2.1", f.fetch); state != ValidationStateBogus {
		t.Fatalf("state %s, want bogus", ValidationStateToString[state])
	}
	if f.n == 0 {
		t.Error("the parent side was never asked")
	}
}

// A stub or forward zone below a secure zone keeps its unsigned data: its
// servers are the operator's, and the public tree does not speak for it.
func TestAConfiguredZoneBelowASecureZoneIsInsecure(t *testing.T) {
	rrcache, _ := secCache(t)
	rrcache.ConfiguredZone = func(name string) bool { return core.EqualNames(name, secKid) }
	f := &fetchCounter{}
	if state := validateUnsigned(t, rrcache, kidWWW+" 300 IN A 192.0.2.2", f.fetch); state != ValidationStateInsecure {
		t.Fatalf("state %s, want insecure", ValidationStateToString[state])
	}
	if f.n != 0 {
		t.Errorf("%d DS question(s) asked inside a configured zone", f.n)
	}
}

// A zone found Secure through its DS is held to that DS: once the parent proves
// the delegation has none, the zone is insecure, not bogus for ever. While the
// DS stands, its unsigned data is bogus.
func TestASecureZoneWhoseDSIsGoneIsInsecure(t *testing.T) {
	const parent = "example."
	rrcache := negCache(t)
	pk := newZoneKey(t, rrcache, parent, true)
	rrcache.ZoneMap.Set(parent, &Zone{ZoneName: parent, State: ValidationStateSecure})
	rrcache.ZoneMap.Set(secZone, &Zone{ZoneName: secZone, State: ValidationStateSecure})

	t.Run("DS still there", func(t *testing.T) {
		ds := pk.sign(t, rrFrom(t, secZone+" 300 IN DS 4242 15 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"))
		rrcache.Set(secZone, dns.TypeDS, &CachedRRset{Name: secZone, RRtype: dns.TypeDS, RRset: ds,
			Context: ContextReferral, State: ValidationStateSecure, Expiration: time.Now().Add(5 * time.Minute)})
		if state := validateUnsigned(t, rrcache, secZone+" 300 IN MX 10 mail."+secZone, nil); state != ValidationStateBogus {
			t.Fatalf("state %s, want bogus", ValidationStateToString[state])
		}
	})
	t.Run("DS removed", func(t *testing.T) {
		seedDSDenial(t, rrcache, secZone, pk.sign(t, soaFor(t, parent)),
			pk.sign(t, rrFrom(t, secZone+" 300 IN NSEC zzz."+parent+" NS RRSIG NSEC")))
		if state := validateUnsigned(t, rrcache, secZone+" 300 IN MX 10 mail."+secZone, nil); state != ValidationStateInsecure {
			t.Fatalf("state %s, want insecure", ValidationStateToString[state])
		}
		if z, _ := rrcache.ZoneMap.Get(secZone); z.GetState() != ValidationStateInsecure {
			t.Errorf("ZoneMap still holds %s as %s", secZone, ValidationStateToString[z.GetState()])
		}
	})
}

// A DS is the parent's data, signed by the parent: unsigned, from a secure
// parent, it is bogus; below a proven insecure delegation it is insecure.
func TestAnUnsignedDSTakesItsParentsZone(t *testing.T) {
	rrcache, _ := secCache(t)
	if state := validateUnsigned(t, rrcache, secKid+" 300 IN DS 4242 15 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", nil); state != ValidationStateBogus {
		t.Errorf("DS from the secure zone: state %s, want bogus", ValidationStateToString[state])
	}
	rrcache.ZoneMap.Set(secKid, &Zone{ZoneName: secKid, State: ValidationStateInsecure})
	if state := validateUnsigned(t, rrcache, "sub."+secKid+" 300 IN DS 4242 15 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", nil); state != ValidationStateInsecure {
		t.Errorf("DS from the insecure child: state %s, want insecure", ValidationStateToString[state])
	}
}

// Unsigned data from a zone held Insecure or Indeterminate, or from no known
// zone, keeps the verdict it always had.
func TestUnsignedDataOutsideASecureZoneIsUnchanged(t *testing.T) {
	for _, c := range []struct {
		state *ValidationState
		want  ValidationState
	}{
		{nil, ValidationStateIndeterminate},
		{ptr(ValidationStateInsecure), ValidationStateInsecure},
		{ptr(ValidationStateIndeterminate), ValidationStateIndeterminate},
	} {
		rrcache := negCache(t)
		if c.state != nil {
			rrcache.ZoneMap.Set(secZone, &Zone{ZoneName: secZone, State: *c.state})
		}
		if state := validateUnsigned(t, rrcache, secWWW+" 300 IN A 192.0.2.1", nil); state != c.want {
			t.Errorf("zone state %v: got %s, want %s", c.state, ValidationStateToString[state], ValidationStateToString[c.want])
		}
	}
}

// validateDenial validates a denial of qname and qtype whose authority section
// is auth.
func validateDenial(t *testing.T, rrcache *RRsetCacheT, qname string, qtype uint16, fetcher RRsetFetcher, auth ...*core.RRset) ValidationState {
	t.Helper()
	state, _, err := rrcache.ValidateNegativeResponse(context.Background(), qname, qtype, dns.RcodeNameError, auth, fetcher)
	if err != nil {
		t.Fatalf("ValidateNegativeResponse(%s %s): %v", qname, dns.TypeToString[qtype], err)
	}
	return state
}

// THE DEFECT, for denials. kid is signed and delegated from the secure zone with
// a DS, and has no ZoneMap entry of its own: the resolver never saw a referral
// for it, or never had the DS question answered. A denial from kid with its
// RRSIGs stripped validated Insecure, since only a zone with an entry of its own
// held Secure made it Bogus.
func TestAStrippedDenialBelowASecureZoneIsBogus(t *testing.T) {
	dsStates := []struct {
		name  string
		setup func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey)
	}{
		{"no answer to the DS question", func(*testing.T, *RRsetCacheT, *zoneKey) {}},
		{"a secure DS", func(t *testing.T, rrcache *RRsetCacheT, k *zoneKey) {
			ds := k.sign(t, rrFrom(t, secKid+" 300 IN DS 4242 15 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"))
			rrcache.Set(secKid, dns.TypeDS, &CachedRRset{Name: secKid, RRtype: dns.TypeDS, RRset: ds,
				Context: ContextAnswer, State: ValidationStateSecure, Expiration: time.Now().Add(5 * time.Minute)})
		}},
	}
	denials := []struct {
		name  string
		qname string
		qtype uint16
		auth  func(t *testing.T, rrcache *RRsetCacheT) []*core.RRset
	}{
		{"NXDOMAIN", "nope." + secKid, dns.TypeA, func(t *testing.T, _ *RRsetCacheT) []*core.RRset {
			return []*core.RRset{unsigned(soaFor(t, secKid))}
		}},
		{"NODATA, RRSIGs stripped and NSEC left", kidWWW, dns.TypeTXT, func(t *testing.T, _ *RRsetCacheT) []*core.RRset {
			return []*core.RRset{unsigned(soaFor(t, secKid)), unsigned(rrFrom(t, kidWWW+" 300 IN NSEC "+secKid+" A RRSIG NSEC"))}
		}},
		{"signed by a zone held insecure", "nope." + secKid, dns.TypeA, func(t *testing.T, rrcache *RRsetCacheT) []*core.RRset {
			const other = "insecure.example."
			rrcache.ZoneMap.Set(other, &Zone{ZoneName: other, State: ValidationStateInsecure})
			return []*core.RRset{strayKey(t, other).sign(t, soaFor(t, secKid))}
		}},
	}
	for _, ds := range dsStates {
		for _, d := range denials {
			t.Run(ds.name+"/"+d.name, func(t *testing.T) {
				rrcache, k := secCache(t)
				ds.setup(t, rrcache, k)
				f := &dsQuestionCounter{}
				if state := validateDenial(t, rrcache, d.qname, d.qtype, f.fetch, d.auth(t, rrcache)...); state != ValidationStateBogus {
					t.Errorf("state %s, want bogus", ValidationStateToString[state])
				}
				if z, ok := rrcache.ZoneMap.Get(secKid); ok && z.GetState() == ValidationStateInsecure {
					t.Errorf("%s was entered in ZoneMap as insecure", secKid)
				}
			})
		}
	}
}

// What must keep working: the parent side proves kid an insecure delegation --
// an NSEC at the cut, or an NSEC3 Opt-Out span -- and kid's unsigned denials are
// Insecure. kid is entered as such, and the next denial asks nothing.
func TestAnUnsignedDenialBelowAProvenInsecureDelegationIsInsecure(t *testing.T) {
	proofs := []struct {
		name  string
		proof func(t *testing.T, k *zoneKey) []*core.RRset
	}{
		{"NSEC", func(t *testing.T, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, soaFor(t, secZone)), k.sign(t, rrFrom(t, secKid+" 300 IN NSEC "+secWWW+" NS RRSIG NSEC"))}
		}},
		{"NSEC3 Opt-Out span", func(t *testing.T, k *zoneKey) []*core.RRset {
			return []*core.RRset{k.sign(t, soaFor(t, secZone)), k.sign(t, apexNSEC3(secZone)),
				k.sign(t, nsec3In(secZone, secKid, true, 1, 0, dns.TypeA, dns.TypeRRSIG))}
		}},
	}
	for _, p := range proofs {
		t.Run(p.name, func(t *testing.T) {
			rrcache, k := secCache(t)
			seedDSDenial(t, rrcache, secKid, p.proof(t, k)...)
			if state := validateDenial(t, rrcache, "nope."+secKid, dns.TypeA, nil, unsigned(soaFor(t, secKid))); state != ValidationStateInsecure {
				t.Fatalf("state %s, want insecure", ValidationStateToString[state])
			}
			if z, ok := rrcache.ZoneMap.Get(secKid); !ok || z.GetState() != ValidationStateInsecure {
				t.Fatalf("the proven insecure delegation %s is not in ZoneMap as insecure", secKid)
			}
			f := &dsQuestionCounter{}
			if state := validateDenial(t, rrcache, kidWWW, dns.TypeTXT, f.fetch, unsigned(soaFor(t, secKid))); state != ValidationStateInsecure || f.n != 0 {
				t.Errorf("state %s after %d DS question(s), want insecure after none", ValidationStateToString[state], f.n)
			}
		})
	}
}

// Outside a zone held Secure an unsigned denial is Insecure, as it always was,
// and nothing is asked. Nor is anything asked inside a stub or forward zone
// below a secure zone: its servers are the operator's.
func TestAnUnsignedDenialOutsideASecureZoneIsInsecure(t *testing.T) {
	cases := []struct {
		name    string
		rrcache func(t *testing.T) *RRsetCacheT
	}{
		{"no zone known", negCache},
		{"insecure zone above", func(t *testing.T) *RRsetCacheT {
			rrcache := negCache(t)
			rrcache.ZoneMap.Set(secZone, &Zone{ZoneName: secZone, State: ValidationStateInsecure})
			return rrcache
		}},
		{"indeterminate zone above, no trust anchor", func(t *testing.T) *RRsetCacheT {
			rrcache := negCache(t)
			rrcache.ZoneMap.Set(secZone, &Zone{ZoneName: secZone, State: ValidationStateIndeterminate})
			return rrcache
		}},
		{"configured zone below a secure zone", func(t *testing.T) *RRsetCacheT {
			rrcache, _ := secCache(t)
			rrcache.ConfiguredZone = func(name string) bool { return core.EqualNames(name, secKid) }
			return rrcache
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrcache := c.rrcache(t)
			f := &dsQuestionCounter{}
			if state := validateDenial(t, rrcache, "nope."+secKid, dns.TypeA, f.fetch, unsigned(soaFor(t, secKid))); state != ValidationStateInsecure {
				t.Errorf("state %s, want insecure", ValidationStateToString[state])
			}
			if f.n != 0 {
				t.Errorf("%d DS question(s) asked", f.n)
			}
		})
	}
}

// A denial of kid's DS from kid's own apex is the child speaking for its
// parent's data. Below a secure parent it proves nothing, whatever is known
// about kid, and it is judged at the parent without a question about kid.
func TestAnUnsignedDSDenialFromTheChildsApexIsBogus(t *testing.T) {
	for name, entry := range map[string]*Zone{
		"kid unknown":  nil,
		"kid insecure": {ZoneName: secKid, State: ValidationStateInsecure},
	} {
		t.Run(name, func(t *testing.T) {
			rrcache, _ := secCache(t)
			if entry != nil {
				rrcache.ZoneMap.Set(secKid, entry)
			}
			f := &dsQuestionCounter{}
			if state := validateDenial(t, rrcache, secKid, dns.TypeDS, f.fetch, unsigned(soaFor(t, secKid))); state != ValidationStateBogus {
				t.Errorf("state %s, want bogus", ValidationStateToString[state])
			}
			if f.n != 0 {
				t.Errorf("%d DS question(s) asked", f.n)
			}
		})
	}
}

// A zone found Secure through its DS is held to that DS for its denials as for
// its data: while nothing disproves the DS, a stripped denial is bogus; once the
// parent proves it gone, an unsigned denial is insecure.
func TestAnUnsignedDenialFromASecureZoneWhoseDSIsGoneIsInsecure(t *testing.T) {
	const parent = "example."
	rrcache := negCache(t)
	pk := newZoneKey(t, rrcache, parent, true)
	rrcache.ZoneMap.Set(parent, &Zone{ZoneName: parent, State: ValidationStateSecure})
	rrcache.ZoneMap.Set(secZone, &Zone{ZoneName: secZone, State: ValidationStateSecure})
	if state := validateDenial(t, rrcache, secWWW, dns.TypeA, nil, unsigned(soaFor(t, secZone))); state != ValidationStateBogus {
		t.Fatalf("DS not disproved: state %s, want bogus", ValidationStateToString[state])
	}
	seedDSDenial(t, rrcache, secZone, pk.sign(t, soaFor(t, parent)),
		pk.sign(t, rrFrom(t, secZone+" 300 IN NSEC zzz."+parent+" NS RRSIG NSEC")))
	if state := validateDenial(t, rrcache, secWWW, dns.TypeA, nil, unsigned(soaFor(t, secZone))); state != ValidationStateInsecure {
		t.Fatalf("DS disproved: state %s, want insecure", ValidationStateToString[state])
	}
}

func ptr[T any](v T) *T { return &v }
