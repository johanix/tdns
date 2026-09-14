/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"crypto"
	"errors"
	"strconv"
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

// The root is its own parent. Whether a zone held Indeterminate decides for the
// names below it depends on whether its parent side is Secure, and that question
// asked about the root asked about the root again, for ever: a root held
// Indeterminate -- what the validator writes when it cannot anchor the root's
// keys, as on a resolver without a trust anchor -- overflowed the stack.
func TestAnIndeterminateRootIsNotItsOwnParent(t *testing.T) {
	rrcache := negCache(t)
	rrcache.ZoneMap.Set(".", &Zone{ZoneName: ".", State: ValidationStateIndeterminate})
	rrcache.ZoneMap.Set("example.", &Zone{ZoneName: "example.", State: ValidationStateIndeterminate})
	if state := validateUnsigned(t, rrcache, "www.example. 300 IN A 192.0.2.1", nil); state != ValidationStateIndeterminate {
		t.Fatalf("state %s, want indeterminate", ValidationStateToString[state])
	}
}

// Whether the parent side of a name is Secure was worked out again for every
// zone above it, and again for every zone above each of those: the work doubled
// with each label of zones held Indeterminate.
func TestParentSideSecureIsLinearInTheLabels(t *testing.T) {
	rrcache := negCache(t)
	rrcache.ZoneMap.Set(secZone, &Zone{ZoneName: secZone, State: ValidationStateSecure})
	name := secZone
	for i := 0; i < 40; i++ {
		name = "l" + strconv.Itoa(i) + "." + name
		rrcache.ZoneMap.Set(name, &Zone{ZoneName: name, State: ValidationStateIndeterminate})
	}
	done := make(chan bool, 1)
	go func() { done <- rrcache.parentSideSecure("www." + name) }()
	select {
	case secure := <-done:
		if !secure {
			t.Fatalf("the parent side of a name below secure zone %s is not secure", secZone)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("parentSideSecure did not answer within 5s for 40 labels of zones held indeterminate")
	}
}

// The root is looked at too, not only the zones below it. A TLD held Secure
// whose DS now comes back with a chain that cannot be followed -- signed by a
// root key nobody holds -- has a Secure root above it, so that answer is bogus,
// not a reason to serve the TLD's unsigned data.
func TestAChainGapBelowASecureRootIsBogus(t *testing.T) {
	const tld = "tld."
	rrcache := negCache(t)
	rrcache.ZoneMap.Set(".", &Zone{ZoneName: ".", State: ValidationStateSecure})
	rrcache.ZoneMap.Set(tld, &Zone{ZoneName: tld, State: ValidationStateSecure})
	ds := rrFrom(t, tld+" 300 IN DS 4242 15 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
	rrcache.Set(tld, dns.TypeDS, &CachedRRset{Name: tld, RRtype: dns.TypeDS, Context: ContextReferral,
		State: ValidationStateIndeterminate, Expiration: time.Now().Add(5 * time.Minute),
		RRset: &core.RRset{Name: tld, Class: dns.ClassINET, RRtype: dns.TypeDS, RRs: []dns.RR{ds},
			RRSIGs: []dns.RR{&dns.RRSIG{
				Hdr:         dns.RR_Header{Name: tld, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
				TypeCovered: dns.TypeDS, Algorithm: dns.ED25519, Labels: 1, OrigTtl: 300,
				Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
				Expiration: uint32(time.Now().Add(time.Hour).Unix()),
				KeyTag:     4243, SignerName: ".", Signature: "AAAA",
			}}}})

	if state := validateUnsigned(t, rrcache, tld+" 300 IN MX 10 mail."+tld, nil); state != ValidationStateBogus {
		t.Fatalf("state %s, want bogus: the root above the TLD is held secure", ValidationStateToString[state])
	}
}

// A DS that validates Insecure below a zone held Secure is no reason to serve
// unsigned data. An RRSIG earns that verdict unverified by naming a signer the
// resolver holds as Insecure -- here the parent of a zone held Secure under its
// own trust anchor, which is an ancestor of the DS and so a signer it could
// have. The zone above the DS is Secure and signs what it serves: bogus.
func TestADSThatValidatedInsecureBelowASecureZoneIsBogus(t *testing.T) {
	rrcache, _ := secCache(t)
	rrcache.ZoneMap.Set("example.", &Zone{ZoneName: "example.", State: ValidationStateInsecure})
	ds := rrFrom(t, secKid+" 300 IN DS 4242 15 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
	rrcache.Set(secKid, dns.TypeDS, &CachedRRset{Name: secKid, RRtype: dns.TypeDS, Context: ContextAnswer,
		Expiration: time.Now().Add(5 * time.Minute),
		RRset: &core.RRset{Name: secKid, Class: dns.ClassINET, RRtype: dns.TypeDS, RRs: []dns.RR{ds},
			RRSIGs: []dns.RR{&dns.RRSIG{
				Hdr:         dns.RR_Header{Name: secKid, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
				TypeCovered: dns.TypeDS, Algorithm: dns.ED25519, Labels: 3, OrigTtl: 300,
				Inception:  uint32(time.Now().Add(-time.Hour).Unix()),
				Expiration: uint32(time.Now().Add(time.Hour).Unix()),
				KeyTag:     1, SignerName: "example.", Signature: "AAAA",
			}}}})

	if state := validateUnsigned(t, rrcache, kidWWW+" 300 IN A 192.0.2.2", nil); state != ValidationStateBogus {
		t.Fatalf("state %s, want bogus: the DS below secure zone %s validated insecure", ValidationStateToString[state], secZone)
	}
}

func ptr[T any](v T) *T { return &v }
