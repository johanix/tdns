/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// secureTree is the root, example. and sec.example., all signed, with
// www.sec.example. A in sec.example.
func secureTree(t *testing.T) *chaseTree {
	t.Helper()
	tr := newChaseTree(t)
	tr.zone("example.")
	tr.zone("sec.example.").add("www.sec.example. 300 IN A 192.0.2.10")
	return tr
}

// wantStatus fails the test unless got is want.
func wantStatus(t *testing.T, what string, got, want ChainStatus) {
	t.Helper()
	if got != want {
		t.Errorf("%s: %s, want %s", what, got, want)
	}
}

// The chain that has always worked: root, TLD and zone, each anchored in the
// one above, and an answer signed by the zone.
func TestChaseSecureChain(t *testing.T) {
	tr := secureTree(t)
	res := tr.chase("www.sec.example.", dns.TypeA)
	if got, want := zonesOf(res.Links), []string{".", "example.", "sec.example."}; !slices.Equal(got, want) {
		t.Fatalf("links %v, want %v", got, want)
	}
	for _, l := range res.Links {
		wantStatus(t, l.Zone, l.Status, ChainStatusSecure)
	}
	wantStatus(t, "leaf", res.Leaf.Status, ChainStatusSecure)
	wantStatus(t, "result", res.Status, ChainStatusSecure)
	if res.Leaf.RRset == nil || len(res.Leaf.RRset.RRs) != 1 {
		t.Errorf("leaf RRset %v, want the one A", res.Leaf.RRset)
	}
	if got := linkNamed(res.Links, "sec.example.").ParentZone; got != "example." {
		t.Errorf("sec.example. parent zone %q, want example.", got)
	}
	if res.Qname != "www.sec.example." || res.Qtype != dns.TypeA {
		t.Errorf("result for %s %s, want www.sec.example. A", res.Qname, dns.TypeToString[res.Qtype])
	}
	// Every question carries DO, and CD: the walk judges what the server
	// has, not what the server made of it.
	for _, m := range tr.asked {
		if !m.CheckingDisabled {
			t.Errorf("%s %s asked without CD", m.Question[0].Name, dns.TypeToString[m.Question[0].Qtype])
		}
		if opt := m.IsEdns0(); opt == nil || !opt.Do() {
			t.Errorf("%s %s asked without DO", m.Question[0].Name, dns.TypeToString[m.Question[0].Qtype])
		}
	}
}

// The root is anchored by the trust anchor: without one it is Indeterminate,
// with one that matches no key Bogus.
func TestChaseTrustAnchor(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		tr := secureTree(t)
		res, err := NewChaser(tr, "192.0.2.1", nil).Chase("www.sec.example.", dns.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		wantStatus(t, "root", res.Links[0].Status, ChainStatusIndeterminate)
		wantStatus(t, "result", res.Status, ChainStatusIndeterminate)
	})
	t.Run("wrong", func(t *testing.T) {
		tr := secureTree(t)
		other := newFwdSecKey(t, ".").dnskey.ToDS(dns.SHA256)
		res, err := NewChaser(tr, "192.0.2.1", []*dns.DS{other}).Chase("www.sec.example.", dns.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		wantStatus(t, "root", res.Links[0].Status, ChainStatusBogus)
		wantStatus(t, "result", res.Status, ChainStatusBogus)
	})
}

// A DS query is the parent's data: the chain ends at the parent, whose keys
// signed the DS.
func TestChaseDSAsTheLeaf(t *testing.T) {
	tr := secureTree(t)
	res := tr.chase("sec.example.", dns.TypeDS)
	if got, want := zonesOf(res.Links), []string{".", "example."}; !slices.Equal(got, want) {
		t.Fatalf("links %v, want %v", got, want)
	}
	wantStatus(t, "leaf", res.Leaf.Status, ChainStatusSecure)
	wantStatus(t, "result", res.Status, ChainStatusSecure)
	if tr.askedFor("sec.example.", dns.TypeDNSKEY) {
		t.Errorf("the child's DNSKEY was asked for; a DS leaf needs only the parent's")
	}
}

// A DNSKEY query at an apex is answered with the RRset the zone's link
// already validated.
func TestChaseDNSKEYAsTheLeaf(t *testing.T) {
	tr := secureTree(t)
	res := tr.chase("sec.example.", dns.TypeDNSKEY)
	wantStatus(t, "leaf", res.Leaf.Status, ChainStatusSecure)
	wantStatus(t, "result", res.Status, ChainStatusSecure)
}

// Only records owned by the name asked for count: records of the type owned
// by another name are not the answer, and another zone's DS in the answer to
// a DS question does not make the name a zone cut.
func TestChaseTakesOnlyTheNameAskedFor(t *testing.T) {
	t.Run("answer", func(t *testing.T) {
		tr := secureTree(t)
		z := tr.zones["sec.example."]
		z.add("other.sec.example. 300 IN A 192.0.2.20")
		tr.script("www.sec.example.", dns.TypeA, func() *dns.Msg {
			return &dns.Msg{Answer: z.sign(z.get("other.sec.example.", dns.TypeA))}
		})
		res := tr.chase("www.sec.example.", dns.TypeA)
		if res.Leaf.RRset != nil {
			t.Errorf("leaf RRset %v: another name's A taken as the answer", res.Leaf.RRset.RRs)
		}
		if res.Status == ChainStatusSecure {
			t.Errorf("result secure without an answer")
		}
	})
	t.Run("DS", func(t *testing.T) {
		tr := secureTree(t)
		parent := tr.zones["example."]
		tr.script("www.sec.example.", dns.TypeDS, func() *dns.Msg {
			return &dns.Msg{Answer: parent.sign(parent.get("sec.example.", dns.TypeDS))}
		})
		res := tr.chase("www.sec.example.", dns.TypeA)
		if linkNamed(res.Links, "www.sec.example.") != nil {
			t.Errorf("www.sec.example. taken for a zone cut on sec.example.'s DS; links %v", zonesOf(res.Links))
		}
		wantStatus(t, "result", res.Status, ChainStatusSecure)
	})
}

// A query answered with an rcode other than NOERROR or NXDOMAIN failed: it
// says nothing about the name, and the verdict says which query it was.
func TestChaseFailedQueries(t *testing.T) {
	t.Run("answer", func(t *testing.T) {
		tr := secureTree(t)
		tr.edit("www.sec.example.", dns.TypeA, rcodeOnly(dns.RcodeServerFailure))
		res := tr.chase("www.sec.example.", dns.TypeA)
		wantStatus(t, "leaf", res.Leaf.Status, ChainStatusIndeterminate)
		if !hasNote(res.Leaf.Notes, "answer query failed: SERVFAIL") {
			t.Errorf("leaf notes %q", res.Leaf.Notes)
		}
	})
	t.Run("DS", func(t *testing.T) {
		tr := secureTree(t)
		tr.edit("example.", dns.TypeDS, rcodeOnly(dns.RcodeRefused))
		res := tr.chase("www.sec.example.", dns.TypeA)
		l := linkNamed(res.Links, "example.")
		if l == nil {
			t.Fatalf("no link for example.; links %v", zonesOf(res.Links))
		}
		wantStatus(t, "example.", l.Status, ChainStatusIndeterminate)
		if !hasNote(l.Notes, "DS query failed: REFUSED") {
			t.Errorf("example. notes %q", l.Notes)
		}
		wantStatus(t, "result", res.Status, ChainStatusIndeterminate)
	})
	t.Run("DNSKEY", func(t *testing.T) {
		tr := secureTree(t)
		tr.edit("sec.example.", dns.TypeDNSKEY, rcodeOnly(dns.RcodeServerFailure))
		res := tr.chase("www.sec.example.", dns.TypeA)
		l := linkNamed(res.Links, "sec.example.")
		if l == nil || !hasNote(l.Notes, "DNSKEY query failed: SERVFAIL") {
			t.Fatalf("sec.example. link %+v", l)
		}
		wantStatus(t, "result", res.Status, ChainStatusIndeterminate)
	})
}

// The output says where the trust anchors came from (#379): a chase run with
// other anchors than the operator meant otherwise looks like any other.
func TestRenderChainTrustAnchorSource(t *testing.T) {
	tr := secureTree(t)
	c := tr.chaser()
	c.TrustAnchorSource = "file /etc/anchors (1 DS)"
	res, err := c.Chase("www.sec.example.", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	RenderChain(res, &out, false)
	if !strings.HasPrefix(out.String(), "Trust anchor: file /etc/anchors (1 DS)\n") {
		t.Errorf("output does not start with the anchor source:\n%s", out.String())
	}

	res, err = NewChaser(tr, "192.0.2.1", nil).Chase("www.sec.example.", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	RenderChain(res, &out, false)
	if !strings.HasPrefix(out.String(), "Trust anchor: none\n") {
		t.Errorf("output without anchors does not say so:\n%s", out.String())
	}
}

// signedAt is key.sign with a signature valid from inception to expiration.
func signedAt(t *testing.T, key *fwdSecKey, inception, expiration time.Time, rrs ...dns.RR) []dns.RR {
	t.Helper()
	sig := &dns.RRSIG{Algorithm: key.dnskey.Algorithm, KeyTag: key.dnskey.KeyTag(), SignerName: key.dnskey.Hdr.Name,
		Inception: uint32(inception.Unix()), Expiration: uint32(expiration.Unix())}
	if err := sig.Sign(key.priv, rrs); err != nil {
		t.Fatal(err)
	}
	return append(append([]dns.RR{}, rrs...), sig)
}

// A DS RRset is the parent's data, and the parent's keys must have signed
// it (item 2 of #876).
func TestChaseDSRRsetSignature(t *testing.T) {
	t.Run("signed by the parent", func(t *testing.T) {
		tr := secureTree(t)
		res := tr.chase("www.sec.example.", dns.TypeA)
		l := linkNamed(res.Links, "sec.example.")
		wantStatus(t, "sec.example.", l.Status, ChainStatusSecure)
		if !hasNote(l.Notes, "DS RRset signed by example. keytag=") {
			t.Errorf("sec.example. notes %q", l.Notes)
		}
	})
	t.Run("no RRSIG", func(t *testing.T) {
		tr := secureTree(t)
		tr.edit("sec.example.", dns.TypeDS, stripSigs(dns.TypeDS))
		res := tr.chase("www.sec.example.", dns.TypeA)
		l := linkNamed(res.Links, "sec.example.")
		wantStatus(t, "sec.example.", l.Status, ChainStatusBogus)
		if !hasNote(l.Notes, "DS RRset: no RRSIG by example.") {
			t.Errorf("sec.example. notes %q", l.Notes)
		}
		wantStatus(t, "result", res.Status, ChainStatusBogus)
	})
	t.Run("DS changed after signing", func(t *testing.T) {
		tr := secureTree(t)
		// Another key's DS, in place of the one the parent signed: the child
		// would match it, the parent's signature does not.
		other := newFwdSecKey(t, "sec.example.")
		tr.zones["sec.example."].put(other.dnskey)
		tr.edit("sec.example.", dns.TypeDS, changeRR(dns.TypeDS, func(rr dns.RR) {
			*rr.(*dns.DS) = *other.dnskey.ToDS(dns.SHA256)
		}))
		res := tr.chase("www.sec.example.", dns.TypeA)
		l := linkNamed(res.Links, "sec.example.")
		wantStatus(t, "sec.example.", l.Status, ChainStatusBogus)
		if !hasNote(l.Notes, "does not verify") {
			t.Errorf("sec.example. notes %q", l.Notes)
		}
	})
	t.Run("signed with a key the parent does not have", func(t *testing.T) {
		tr := secureTree(t)
		stray := newFwdSecKey(t, "example.")
		parent := tr.zones["example."]
		tr.script("sec.example.", dns.TypeDS, func() *dns.Msg {
			return &dns.Msg{Answer: stray.sign(t, parent.get("sec.example.", dns.TypeDS)...)}
		})
		res := tr.chase("www.sec.example.", dns.TypeA)
		wantStatus(t, "sec.example.", linkNamed(res.Links, "sec.example.").Status, ChainStatusBogus)
	})
	t.Run("signature expired", func(t *testing.T) {
		tr := secureTree(t)
		parent := tr.zones["example."]
		tr.script("sec.example.", dns.TypeDS, func() *dns.Msg {
			return &dns.Msg{Answer: signedAt(t, parent.key, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour),
				parent.get("sec.example.", dns.TypeDS)...)}
		})
		res := tr.chase("www.sec.example.", dns.TypeA)
		l := linkNamed(res.Links, "sec.example.")
		wantStatus(t, "sec.example.", l.Status, ChainStatusBogus)
		if !hasNote(l.Notes, "outside its validity period") {
			t.Errorf("sec.example. notes %q", l.Notes)
		}
	})
}

// A link is no better than the link above it: a child whose own DS and keys
// check out is Indeterminate under an Indeterminate parent and Bogus under a
// Bogus one, and says why.
func TestChaseLinkIsNoBetterThanItsParent(t *testing.T) {
	t.Run("no anchor", func(t *testing.T) {
		tr := secureTree(t)
		res, err := NewChaser(tr, "192.0.2.1", nil).Chase("www.sec.example.", dns.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		for _, zone := range []string{"example.", "sec.example."} {
			l := linkNamed(res.Links, zone)
			wantStatus(t, zone, l.Status, ChainStatusIndeterminate)
			if !hasNote(l.Notes, "DS RRset signed by") || !hasNote(l.Notes, "above is indeterminate; this link can be no better") {
				t.Errorf("%s notes %q", zone, l.Notes)
			}
		}
	})
	t.Run("parent bogus", func(t *testing.T) {
		tr := secureTree(t)
		tr.edit("example.", dns.TypeDNSKEY, stripSigs(dns.TypeDNSKEY))
		res := tr.chase("www.sec.example.", dns.TypeA)
		wantStatus(t, "example.", linkNamed(res.Links, "example.").Status, ChainStatusBogus)
		l := linkNamed(res.Links, "sec.example.")
		wantStatus(t, "sec.example.", l.Status, ChainStatusBogus)
		if !hasNote(l.Notes, "zone example. above is bogus") {
			t.Errorf("sec.example. notes %q", l.Notes)
		}
	})
	t.Run("own trust anchor", func(t *testing.T) {
		// A zone with an anchor of its own is vouched for by it, whatever
		// the zone above it is; no DS is asked for.
		tr := secureTree(t)
		tr.edit("example.", dns.TypeDNSKEY, stripSigs(dns.TypeDNSKEY))
		anchors := append(tr.anchors(), tr.zones["sec.example."].key.dnskey.ToDS(dns.SHA256))
		res, err := NewChaser(tr, "192.0.2.1", anchors).Chase("www.sec.example.", dns.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		wantStatus(t, "sec.example.", linkNamed(res.Links, "sec.example.").Status, ChainStatusSecure)
		if tr.askedFor("sec.example.", dns.TypeDS) {
			t.Errorf("asked for the DS of a zone with its own trust anchor")
		}
	})
	// The anchor is found whatever the case of its owner name: given to
	// NewChaser, or put in Chaser.TrustAnchors by the caller.
	for _, c := range []struct {
		name  string
		chase func(tr *chaseTree, ds *dns.DS) (*ChainResult, error)
	}{
		{"own trust anchor in another case, NewChaser", func(tr *chaseTree, ds *dns.DS) (*ChainResult, error) {
			ds.Hdr.Name = "SEC.Example."
			return NewChaser(tr, "192.0.2.1", append(tr.anchors(), ds)).Chase("www.sec.example.", dns.TypeA)
		}},
		{"own trust anchor in another case, TrustAnchors", func(tr *chaseTree, ds *dns.DS) (*ChainResult, error) {
			c := NewChaser(tr, "192.0.2.1", tr.anchors())
			c.TrustAnchors["SEC.EXAMPLE."] = []*dns.DS{ds}
			return c.Chase("www.sec.example.", dns.TypeA)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr := secureTree(t)
			tr.edit("example.", dns.TypeDNSKEY, stripSigs(dns.TypeDNSKEY))
			res, err := c.chase(tr, tr.zones["sec.example."].key.dnskey.ToDS(dns.SHA256))
			if err != nil {
				t.Fatal(err)
			}
			wantStatus(t, "sec.example.", linkNamed(res.Links, "sec.example.").Status, ChainStatusSecure)
			if tr.askedFor("sec.example.", dns.TypeDS) {
				t.Errorf("asked for the DS of a zone with its own trust anchor")
			}
		})
	}
}

// setDS replaces the DS records the parent of child holds for it.
func setDS(tr *chaseTree, child string, dss ...*dns.DS) {
	parent := tr.zoneAbove(child)
	var rrs []dns.RR
	for _, ds := range dss {
		rrs = append(rrs, ds)
	}
	parent.data[child][dns.TypeDS] = rrs
}

// withDS is the DS of key, with its algorithm and digest type changed as
// given (and the digest kept: it matches nothing once either changes).
func withDS(key *fwdSecKey, alg, digestType uint8) *dns.DS {
	ds := key.dnskey.ToDS(dns.SHA256)
	ds.Algorithm, ds.DigestType = alg, digestType
	return ds
}

// A DS RRset that holds no DS this binary can use, once verified, is an
// insecure delegation (RFC 4035 section 5.2, RFC 6840 section 5.2), not a
// DS that matches no key (item 4 of #876). Below it nothing is checked.
func TestChaseUnusableDS(t *testing.T) {
	const unsupportedAlg = 250
	for _, c := range []struct {
		name string
		ds   func(key *fwdSecKey) []*dns.DS
		edit func(*dns.Msg)
		want ChainStatus
		note string
	}{
		{"digest type not supported", func(k *fwdSecKey) []*dns.DS {
			return []*dns.DS{withDS(k, k.dnskey.Algorithm, 99)}
		}, nil, ChainStatusInsecure, "digest type 99 not supported"},
		{"algorithm not supported", func(k *fwdSecKey) []*dns.DS {
			return []*dns.DS{withDS(k, unsupportedAlg, dns.SHA256)}
		}, nil, ChainStatusInsecure, "algorithm not supported by this binary"},
		{"a usable DS beside them matches", func(k *fwdSecKey) []*dns.DS {
			return []*dns.DS{withDS(k, unsupportedAlg, dns.SHA256), k.dnskey.ToDS(dns.SHA256)}
		}, nil, ChainStatusSecure, "matches KSK"},
		{"a usable DS beside them matches no key", func(k *fwdSecKey) []*dns.DS {
			return []*dns.DS{withDS(k, unsupportedAlg, dns.SHA256), newFwdSecKey(t, "sec.example.").dnskey.ToDS(dns.SHA256)}
		}, nil, ChainStatusBogus, "no matching DNSKEY"},
		{"not verified", func(k *fwdSecKey) []*dns.DS {
			return []*dns.DS{withDS(k, unsupportedAlg, dns.SHA256)}
		}, stripSigs(dns.TypeDS), ChainStatusBogus, "no RRSIG by example."},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr := secureTree(t)
			setDS(tr, "sec.example.", c.ds(tr.zones["sec.example."].key)...)
			if c.edit != nil {
				tr.edit("sec.example.", dns.TypeDS, c.edit)
			}
			res := tr.chase("www.sec.example.", dns.TypeA)
			l := linkNamed(res.Links, "sec.example.")
			if l == nil {
				t.Fatalf("no link for sec.example.; links %v", zonesOf(res.Links))
			}
			wantStatus(t, "sec.example.", l.Status, c.want)
			if !hasNote(l.Notes, c.note) {
				t.Errorf("sec.example. notes %q, want one with %q", l.Notes, c.note)
			}
			if c.want == ChainStatusInsecure {
				if tr.askedFor("www.sec.example.", dns.TypeDS) {
					t.Errorf("a name below the insecure delegation was asked about")
				}
				if res.Status == ChainStatusSecure {
					t.Errorf("result secure below an insecure delegation")
				}
			}
		})
	}
}

// kidTree is secureTree with kid.sec.example., unsigned, delegated from
// sec.example. without a DS, holding www.kid.sec.example. A.
func kidTree(t *testing.T) *chaseTree {
	t.Helper()
	tr := secureTree(t)
	tr.unsignedZone("kid.sec.example.").add("www.kid.sec.example. 300 IN A 192.0.2.30")
	return tr
}

// n3KidDenial scripts the denial of the DS at kid.sec.example. as an NSEC3
// zone gives it: the SOA, and recs, signed by sec.example.
func n3KidDenial(t *testing.T, tr *chaseTree, recs ...*dns.NSEC3) {
	z := tr.zones["sec.example."]
	tr.script("kid.sec.example.", dns.TypeDS, func() *dns.Msg {
		m := &dns.Msg{Ns: z.sign(z.get("sec.example.", dns.TypeSOA))}
		for _, r := range recs {
			m.Ns = append(m.Ns, z.sign([]dns.RR{r})...)
		}
		return m
	})
}

// A delegation without DS is read from the parent's proof in the DS denial
// (item 3 of #876): an NSEC or NSEC3 at the name with NS and neither DS nor
// SOA, or an NSEC3 Opt-Out span over it, makes it an Insecure link, and the
// names below it are not asked about.
func TestChaseUnsignedDelegation(t *testing.T) {
	const optOut = 1
	apex := func() *dns.NSEC3 {
		return n3RR("sec.example.", "sec.example.", false, 0, 0, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM)
	}
	for _, c := range []struct {
		name  string
		setup func(t *testing.T, tr *chaseTree)
		note  string
	}{
		{"NSEC", func(*testing.T, *chaseTree) {}, "NSEC kid.sec.example. -> "},
		{"NSEC3 match", func(t *testing.T, tr *chaseTree) {
			n3KidDenial(t, tr, n3RR("sec.example.", "kid.sec.example.", false, 0, 0, dns.TypeNS))
		}, "NSEC3 proves a delegation without DS"},
		{"NSEC3 Opt-Out", func(t *testing.T, tr *chaseTree) {
			n3KidDenial(t, tr, apex(), n3RR("sec.example.", "kid.sec.example.", true, optOut, 0, dns.TypeA, dns.TypeRRSIG))
		}, "Opt-Out span"},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr := kidTree(t)
			c.setup(t, tr)
			res := tr.chase("www.kid.sec.example.", dns.TypeA)
			l := linkNamed(res.Links, "kid.sec.example.")
			if l == nil {
				t.Fatalf("no link for kid.sec.example.; links %v", zonesOf(res.Links))
			}
			wantStatus(t, "kid.sec.example.", l.Status, ChainStatusInsecure)
			if !hasNote(l.Notes, c.note) {
				t.Errorf("kid.sec.example. notes %q, want one with %q", l.Notes, c.note)
			}
			if tr.askedFor("www.kid.sec.example.", dns.TypeDS) {
				t.Errorf("a name below the insecure delegation was asked about")
			}
			wantStatus(t, "result", res.Status, ChainStatusInsecure)
		})
	}

	t.Run("NSEC3 over the iteration limit", func(t *testing.T) {
		tr := kidTree(t)
		n3KidDenial(t, tr, n3RR("sec.example.", "kid.sec.example.", false, 0, 11, dns.TypeNS))
		res := tr.chase("www.kid.sec.example.", dns.TypeA)
		l := linkNamed(res.Links, "kid.sec.example.")
		if l == nil {
			t.Fatalf("no link for kid.sec.example.; links %v", zonesOf(res.Links))
		}
		wantStatus(t, "kid.sec.example.", l.Status, ChainStatusIndeterminate)
		if !hasNote(l.Notes, "cannot judge") {
			t.Errorf("kid.sec.example. notes %q", l.Notes)
		}
	})

	// Without a proof, or with one that does not verify, the name is taken as
	// part of the zone above, and the note on that zone's link says so.
	for _, c := range []struct {
		name string
		edit func(*dns.Msg)
	}{
		{"proof missing", dropProof},
		{"proof changed", changeRR(dns.TypeNSEC, func(rr dns.RR) {
			rr.(*dns.NSEC).TypeBitMap = []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}
		})},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr := kidTree(t)
			tr.edit("kid.sec.example.", dns.TypeDS, c.edit)
			res := tr.chase("www.kid.sec.example.", dns.TypeA)
			if linkNamed(res.Links, "kid.sec.example.") != nil {
				t.Errorf("kid.sec.example. is a link without a proof; links %v", zonesOf(res.Links))
			}
			if l := linkNamed(res.Links, "sec.example."); !hasNote(l.Notes, "kid.sec.example.: no DS and no proof about a cut; taken as part of sec.example.") {
				t.Errorf("sec.example. notes %q", l.Notes)
			}
		})
	}
}

// A name in a zone is not a zone cut, and the NSEC in the denial of its DS
// says so (#379): no SOA or NS question is asked to find out.
func TestChaseNameInAZoneIsNotACut(t *testing.T) {
	tr := secureTree(t)
	res := tr.chase("www.sec.example.", dns.TypeA)
	if linkNamed(res.Links, "www.sec.example.") != nil {
		t.Errorf("www.sec.example. is a link; links %v", zonesOf(res.Links))
	}
	if l := linkNamed(res.Links, "sec.example."); !hasNote(l.Notes, "www.sec.example.: no DS, and the denial shows no delegation there") {
		t.Errorf("sec.example. notes %q", l.Notes)
	}
	for _, m := range tr.asked {
		if q := m.Question[0]; q.Qtype == dns.TypeSOA || q.Qtype == dns.TypeNS {
			t.Errorf("asked %s %s", q.Name, dns.TypeToString[q.Qtype])
		}
	}
	wantStatus(t, "result", res.Status, ChainStatusSecure)
}

// An answer without RRSIG is Insecure only below an insecure delegation; from
// a signed zone it is Bogus, and it is never better than the zone that holds
// it (item 5 of #876).
func TestChaseAnswerVerdicts(t *testing.T) {
	t.Run("unsigned, zone secure", func(t *testing.T) {
		tr := secureTree(t)
		tr.edit("www.sec.example.", dns.TypeA, stripSigs(dns.TypeA))
		res := tr.chase("www.sec.example.", dns.TypeA)
		wantStatus(t, "leaf", res.Leaf.Status, ChainStatusBogus)
		if !hasNote(res.Leaf.Notes, "no RRSIG, and zone sec.example. is signed") {
			t.Errorf("leaf notes %q", res.Leaf.Notes)
		}
	})
	t.Run("unsigned, zone insecure", func(t *testing.T) {
		tr := kidTree(t)
		res := tr.chase("www.kid.sec.example.", dns.TypeA)
		wantStatus(t, "leaf", res.Leaf.Status, ChainStatusInsecure)
		if !hasNote(res.Leaf.Notes, "zone kid.sec.example. is insecure") {
			t.Errorf("leaf notes %q", res.Leaf.Notes)
		}
		wantStatus(t, "result", res.Status, ChainStatusInsecure)
	})
	t.Run("unsigned, zone indeterminate", func(t *testing.T) {
		tr := secureTree(t)
		tr.edit("www.sec.example.", dns.TypeA, stripSigs(dns.TypeA))
		res, err := NewChaser(tr, "192.0.2.1", nil).Chase("www.sec.example.", dns.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		wantStatus(t, "leaf", res.Leaf.Status, ChainStatusIndeterminate)
	})
	t.Run("signed, zone indeterminate", func(t *testing.T) {
		tr := secureTree(t)
		res, err := NewChaser(tr, "192.0.2.1", nil).Chase("www.sec.example.", dns.TypeA)
		if err != nil {
			t.Fatal(err)
		}
		wantStatus(t, "leaf", res.Leaf.Status, ChainStatusIndeterminate)
		if !hasNote(res.Leaf.Notes, "sig keytag=") || !hasNote(res.Leaf.Notes, "the answer can be no better") {
			t.Errorf("leaf notes %q", res.Leaf.Notes)
		}
	})
	t.Run("changed after signing", func(t *testing.T) {
		tr := secureTree(t)
		tr.edit("www.sec.example.", dns.TypeA, changeRR(dns.TypeA, func(rr dns.RR) {
			rr.(*dns.A).A = rr.(*dns.A).A.To4()
			rr.(*dns.A).A[3]++
		}))
		res := tr.chase("www.sec.example.", dns.TypeA)
		wantStatus(t, "leaf", res.Leaf.Status, ChainStatusBogus)
		if !hasNote(res.Leaf.Notes, "does not verify") {
			t.Errorf("leaf notes %q", res.Leaf.Notes)
		}
	})
	// A delegation whose DS denial carries no proof is taken as part of the
	// zone above, and that cannot make its data Secure: unsigned, it is
	// Bogus; signed by the child, the signature is not the zone above's.
	t.Run("below an unproven delegation, unsigned", func(t *testing.T) {
		tr := kidTree(t)
		tr.edit("kid.sec.example.", dns.TypeDS, dropProof)
		res := tr.chase("www.kid.sec.example.", dns.TypeA)
		wantStatus(t, "result", res.Status, ChainStatusBogus)
		if !hasNote(res.Leaf.Notes, "no RRSIG, and zone sec.example. is signed") {
			t.Errorf("leaf notes %q", res.Leaf.Notes)
		}
	})
	t.Run("below an unproven delegation, signed", func(t *testing.T) {
		tr := secureTree(t)
		tr.zone("kid.sec.example.").add("www.kid.sec.example. 300 IN A 192.0.2.30")
		z := tr.zones["sec.example."]
		tr.script("kid.sec.example.", dns.TypeDS, func() *dns.Msg {
			return &dns.Msg{Ns: z.sign(z.get("sec.example.", dns.TypeSOA))}
		})
		res := tr.chase("www.kid.sec.example.", dns.TypeA)
		wantStatus(t, "result", res.Status, ChainStatusBogus)
		if !hasNote(res.Leaf.Notes, "signed by kid.sec.example., which the chain did not reach") {
			t.Errorf("leaf notes %q", res.Leaf.Notes)
		}
	})
}

// cnameTree is the root, example., sec.example. and other.example., all
// signed: www.sec.example. is a CNAME to sec.example., which has an A, and
// _443._tcp.www.sec.example. a TLSA below the CNAME owner. ext.sec.example.
// is a CNAME to www.other.example.
func cnameTree(t *testing.T) *chaseTree {
	t.Helper()
	tr := newChaseTree(t)
	tr.zone("example.")
	tr.zone("sec.example.").add(
		"sec.example. 300 IN A 192.0.2.50",
		"www.sec.example. 300 IN CNAME sec.example.",
		"_443._tcp.www.sec.example. 300 IN TLSA 3 1 1 "+strings.Repeat("ab", 32),
		"ext.sec.example. 300 IN CNAME www.other.example.",
	)
	tr.zone("other.example.").add("www.other.example. 300 IN A 192.0.2.60")
	return tr
}

// A name that owns a CNAME is no zone cut: its CNAME is verified with the
// keys of the zone that holds it, and its target is walked in turn (item 1
// of #876). The result is the worst of every part.
func TestChaseCNAME(t *testing.T) {
	// A resolver that answers a DS question at a CNAME owner with the CNAME
	// and the target's DS (#875, and 1.1.1.1), and one that answers SERVFAIL
	// (tdns-imr before #875): the walk never asks.
	for _, shape := range []string{"CNAME and the target's DS", "SERVFAIL"} {
		t.Run("in zone, "+shape, func(t *testing.T) {
			tr := cnameTree(t)
			if shape == "SERVFAIL" {
				tr.edit("www.sec.example.", dns.TypeDS, rcodeOnly(dns.RcodeServerFailure))
			}
			res := tr.chase("www.sec.example.", dns.TypeA)
			if len(res.Aliases) != 1 {
				t.Fatalf("%d aliases, want 1", len(res.Aliases))
			}
			alias := res.Aliases[0]
			if alias.Leaf.Qtype != dns.TypeCNAME || alias.Leaf.Qname != "www.sec.example." {
				t.Errorf("alias leaf %s %s", alias.Leaf.Qname, dns.TypeToString[alias.Leaf.Qtype])
			}
			wantStatus(t, "CNAME", alias.Leaf.Status, ChainStatusSecure)
			if linkNamed(alias.Links, "www.sec.example.") != nil {
				t.Errorf("the CNAME owner is a link")
			}
			if l := linkNamed(alias.Links, "sec.example."); !hasNote(l.Notes, "www.sec.example.: owns a CNAME, not a zone cut") {
				t.Errorf("sec.example. notes %q", l.Notes)
			}
			if res.Leaf.Qname != "sec.example." || res.Leaf.RRset == nil {
				t.Fatalf("final leaf %s, RRset %v", res.Leaf.Qname, res.Leaf.RRset)
			}
			wantStatus(t, "A", res.Leaf.Status, ChainStatusSecure)
			wantStatus(t, "result", res.Status, ChainStatusSecure)
			if tr.askedFor("www.sec.example.", dns.TypeDS) || tr.askedFor("www.sec.example.", dns.TypeSOA) {
				t.Errorf("asked about the CNAME owner as a zone cut")
			}
		})
	}
	t.Run("to another zone", func(t *testing.T) {
		tr := cnameTree(t)
		res := tr.chase("ext.sec.example.", dns.TypeA)
		if got, want := zonesOf(res.Links), []string{".", "example.", "other.example."}; !slices.Equal(got, want) {
			t.Errorf("final links %v, want %v", got, want)
		}
		wantStatus(t, "result", res.Status, ChainStatusSecure)
		// Each zone is asked about once for the whole chain.
		n := 0
		for _, m := range tr.asked {
			if q := m.Question[0]; q.Qtype == dns.TypeDNSKEY && q.Name == "example." {
				n++
			}
		}
		if n != 1 {
			t.Errorf("example. DNSKEY asked %d times, want 1", n)
		}
	})
	t.Run("CNAME without RRSIG", func(t *testing.T) {
		tr := cnameTree(t)
		tr.edit("www.sec.example.", dns.TypeA, stripSigs(dns.TypeCNAME))
		res := tr.chase("www.sec.example.", dns.TypeA)
		wantStatus(t, "CNAME", res.Aliases[0].Leaf.Status, ChainStatusBogus)
		wantStatus(t, "result", res.Status, ChainStatusBogus)
	})
	t.Run("CNAME changed after signing", func(t *testing.T) {
		tr := cnameTree(t)
		tr.edit("www.sec.example.", dns.TypeA, changeRR(dns.TypeCNAME, func(rr dns.RR) {
			rr.(*dns.CNAME).Target = "ext.sec.example."
		}))
		res := tr.chase("www.sec.example.", dns.TypeA)
		wantStatus(t, "CNAME", res.Aliases[0].Leaf.Status, ChainStatusBogus)
		wantStatus(t, "result", res.Status, ChainStatusBogus)
	})
	t.Run("loop", func(t *testing.T) {
		tr := cnameTree(t)
		tr.zones["sec.example."].add("a.sec.example. 300 IN CNAME b.sec.example.", "b.sec.example. 300 IN CNAME a.sec.example.")
		res := tr.chase("a.sec.example.", dns.TypeA)
		wantStatus(t, "result", res.Status, ChainStatusIndeterminate)
		if !hasNote(res.Leaf.Notes, "CNAME loop") {
			t.Errorf("final leaf %s, notes %q", res.Leaf.Qname, res.Leaf.Notes)
		}
	})
	t.Run("longer than the limit", func(t *testing.T) {
		tr := cnameTree(t)
		z := tr.zones["sec.example."]
		for i := 0; i <= maxCNAMEChain; i++ {
			z.add(fmt.Sprintf("c%d.sec.example. 300 IN CNAME c%d.sec.example.", i, i+1))
		}
		z.add(fmt.Sprintf("c%d.sec.example. 300 IN A 192.0.2.70", maxCNAMEChain+1))
		res := tr.chase("c0.sec.example.", dns.TypeA)
		wantStatus(t, "result", res.Status, ChainStatusIndeterminate)
		if !hasNote(res.Leaf.Notes, fmt.Sprintf("CNAME chain longer than %d", maxCNAMEChain)) {
			t.Errorf("final leaf %s, notes %q", res.Leaf.Qname, res.Leaf.Notes)
		}

		// One CNAME fewer is followed to the end.
		res = tr.chase("c1.sec.example.", dns.TypeA)
		wantStatus(t, "result, one fewer", res.Status, ChainStatusSecure)
	})
	t.Run("a CNAME query", func(t *testing.T) {
		tr := cnameTree(t)
		res := tr.chase("www.sec.example.", dns.TypeCNAME)
		if len(res.Aliases) != 0 || res.Leaf.RRset == nil {
			t.Fatalf("%d aliases, leaf RRset %v", len(res.Aliases), res.Leaf.RRset)
		}
		wantStatus(t, "result", res.Status, ChainStatusSecure)
	})
}

// A name below a CNAME owner (a TLSA at _443._tcp under it, as DANE has it):
// the DS question at the CNAME owner is answered with the CNAME by a resolver
// that follows it, which shows the owner is no zone cut; one that answers
// SERVFAIL leaves the walk a failed query, which it reports.
func TestChaseBelowACNAMEOwner(t *testing.T) {
	const name = "_443._tcp.www.sec.example."
	t.Run("CNAME and the target's DS", func(t *testing.T) {
		tr := cnameTree(t)
		res := tr.chase(name, dns.TypeTLSA)
		if linkNamed(res.Links, "www.sec.example.") != nil {
			t.Errorf("the CNAME owner is a link")
		}
		if l := linkNamed(res.Links, "sec.example."); !hasNote(l.Notes, "www.sec.example.: owns a CNAME, not a zone cut") {
			t.Errorf("sec.example. notes %q", l.Notes)
		}
		wantStatus(t, "result", res.Status, ChainStatusSecure)
	})
	t.Run("SERVFAIL", func(t *testing.T) {
		tr := cnameTree(t)
		tr.edit("www.sec.example.", dns.TypeDS, rcodeOnly(dns.RcodeServerFailure))
		res := tr.chase(name, dns.TypeTLSA)
		l := linkNamed(res.Links, "www.sec.example.")
		if l == nil || !hasNote(l.Notes, "DS query failed: SERVFAIL") {
			t.Fatalf("www.sec.example. link %+v", l)
		}
		wantStatus(t, "result", res.Status, ChainStatusIndeterminate)
	})
}

// An answer synthesized from a DNAME is reported, not followed.
func TestChaseDNAMEIsNotFollowed(t *testing.T) {
	tr := cnameTree(t)
	z := tr.zones["sec.example."]
	z.add("d.sec.example. 300 IN DNAME other.example.")
	tr.script("www.d.sec.example.", dns.TypeA, func() *dns.Msg {
		answer := z.sign(z.get("d.sec.example.", dns.TypeDNAME))
		answer = append(answer, mustRR(t, "www.d.sec.example. 300 IN CNAME www.other.example."))
		return &dns.Msg{Answer: answer}
	})
	res := tr.chase("www.d.sec.example.", dns.TypeA)
	if len(res.Aliases) != 0 || res.Leaf.Qtype != dns.TypeCNAME {
		t.Fatalf("%d aliases, final leaf %s %s", len(res.Aliases), res.Leaf.Qname, dns.TypeToString[res.Leaf.Qtype])
	}
	wantStatus(t, "leaf", res.Leaf.Status, ChainStatusIndeterminate)
	if !hasNote(res.Leaf.Notes, "synthesized from the DNAME at d.sec.example.; a DNAME is not followed") {
		t.Errorf("leaf notes %q", res.Leaf.Notes)
	}
	if tr.askedFor("www.other.example.", dns.TypeA) {
		t.Errorf("the DNAME's target was followed")
	}
}

// The output of a CNAME chain: a section per target, and links already
// printed are not repeated.
func TestRenderChainCNAME(t *testing.T) {
	tr := cnameTree(t)
	res := tr.chase("www.sec.example.", dns.TypeA)
	var out strings.Builder
	RenderChain(res, &out, false)
	text := out.String()
	for _, want := range []string{
		"Chain validation for www.sec.example. A:",
		"www.sec.example. CNAME    [secure]",
		"\nCNAME target sec.example. A:\n",
		"sec.example.    [secure]    (as above)",
		"sec.example. A    [secure]",
		"Result: secure",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	if n := strings.Count(text, ". (root)"); n != 1 {
		t.Errorf("the root printed %d times, want 1:\n%s", n, text)
	}
}

// dropNSECAt removes the NSEC owned by owner, and its RRSIG, from the
// authority section.
func dropNSECAt(owner string) func(*dns.Msg) {
	return func(m *dns.Msg) {
		m.Ns = slices.DeleteFunc(m.Ns, func(rr dns.RR) bool {
			if !strings.EqualFold(rr.Header().Name, owner) {
				return false
			}
			if sig, ok := rr.(*dns.RRSIG); ok {
				return sig.TypeCovered == dns.TypeNSEC
			}
			return rr.Header().Rrtype == dns.TypeNSEC
		})
	}
}

// denialTree is secureTree with a.sec.example. and b.c.sec.example. (which
// makes c.sec.example. an empty non-terminal), and *.w.sec.example. with an A.
func denialTree(t *testing.T) *chaseTree {
	t.Helper()
	tr := secureTree(t)
	tr.zones["sec.example."].add(
		"a.sec.example. 300 IN A 192.0.2.11",
		"b.c.sec.example. 300 IN A 192.0.2.12",
		"*.w.sec.example. 300 IN A 192.0.2.13",
	)
	return tr
}

// n3SecDenial scripts the answer to qname and qtype as a denial from
// sec.example. signed with NSEC3: rcode, the SOA, and recs.
func n3SecDenial(tr *chaseTree, qname string, qtype uint16, rcode int, recs ...*dns.NSEC3) {
	z := tr.zones["sec.example."]
	tr.script(qname, qtype, func() *dns.Msg {
		m := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: rcode}, Ns: z.sign(z.get("sec.example.", dns.TypeSOA))}
		for _, r := range recs {
			m.Ns = append(m.Ns, z.sign([]dns.RR{r})...)
		}
		return m
	})
}

// A negative answer is proven by the NSEC or NSEC3 records in its authority
// section, verified with the keys of the zone that holds the name, as the
// resolver reads them (item 6 of #876).
func TestChaseDenials(t *testing.T) {
	const optOut = 1
	apex3 := func(iterations uint16) *dns.NSEC3 {
		return n3RR("sec.example.", "sec.example.", false, 0, iterations, dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeDNSKEY, dns.TypeNSEC3PARAM)
	}
	nameError3 := func(flags uint8, iterations uint16) []*dns.NSEC3 {
		return []*dns.NSEC3{apex3(iterations),
			n3RR("sec.example.", "nx.sec.example.", true, flags, iterations),
			n3RR("sec.example.", "*.sec.example.", true, flags, iterations)}
	}
	for _, c := range []struct {
		name  string
		qname string
		qtype uint16
		setup func(tr *chaseTree)
		want  ChainStatus
		note  string
	}{
		{"NSEC name error", "nx.sec.example.", dns.TypeA, nil, ChainStatusSecure, "NXDOMAIN proven by NSEC"},
		{"NSEC no data", "www.sec.example.", dns.TypeMX, nil, ChainStatusSecure, "NODATA proven by NSEC"},
		{"NSEC no data at an empty non-terminal", "c.sec.example.", dns.TypeA, nil, ChainStatusSecure, "NODATA proven by NSEC"},
		{"NSEC no data at a wildcard", "x.w.sec.example.", dns.TypeAAAA, nil, ChainStatusSecure, "NODATA proven by NSEC"},
		{"NSEC no DS, as the leaf", "www.sec.example.", dns.TypeDS, nil, ChainStatusSecure, "NODATA proven by NSEC"},
		{"NSEC compact denial", "nx.sec.example.", dns.TypeA, func(tr *chaseTree) {
			z := tr.zones["sec.example."]
			tr.script("nx.sec.example.", dns.TypeA, func() *dns.Msg {
				nsec := &dns.NSEC{Hdr: dns.RR_Header{Name: "nx.sec.example.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
					NextDomain: "\\000.nx.sec.example.", TypeBitMap: []uint16{dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNXNAME}}
				return &dns.Msg{Ns: append(z.sign(z.get("sec.example.", dns.TypeSOA)), z.sign([]dns.RR{nsec})...)}
			})
		}, ChainStatusSecure, "name error (RFC 9824 compact denial) proven by NSEC"},
		{"NSEC3 name error", "nx.sec.example.", dns.TypeA, func(tr *chaseTree) {
			n3SecDenial(tr, "nx.sec.example.", dns.TypeA, dns.RcodeNameError, nameError3(0, 0)...)
		}, ChainStatusSecure, "NXDOMAIN proven by NSEC3"},
		{"NSEC3 no data", "www.sec.example.", dns.TypeMX, func(tr *chaseTree) {
			n3SecDenial(tr, "www.sec.example.", dns.TypeMX, dns.RcodeSuccess,
				n3RR("sec.example.", "www.sec.example.", false, 0, 0, dns.TypeA, dns.TypeRRSIG))
		}, ChainStatusSecure, "NODATA proven by NSEC3"},
		{"NSEC3 name error through Opt-Out", "nx.sec.example.", dns.TypeA, func(tr *chaseTree) {
			n3SecDenial(tr, "nx.sec.example.", dns.TypeA, dns.RcodeNameError, nameError3(optOut, 0)...)
		}, ChainStatusInsecure, "Opt-Out span"},
		{"NSEC3 over the iteration limit", "nx.sec.example.", dns.TypeA, func(tr *chaseTree) {
			n3SecDenial(tr, "nx.sec.example.", dns.TypeA, dns.RcodeNameError, nameError3(0, 11)...)
		}, ChainStatusInsecure, "iterations above the limit of 10"},
		{"NSEC3 without the wildcard cover", "nx.sec.example.", dns.TypeA, func(tr *chaseTree) {
			n3SecDenial(tr, "nx.sec.example.", dns.TypeA, dns.RcodeNameError, nameError3(0, 0)[:2]...)
		}, ChainStatusBogus, "the NSEC3 proof does not hold"},
		{"proof missing", "nx.sec.example.", dns.TypeA, func(tr *chaseTree) {
			tr.edit("nx.sec.example.", dns.TypeA, dropProof)
		}, ChainStatusBogus, "NXDOMAIN with no NSEC or NSEC3 proof"},
		{"the wildcard cover missing", "nx.sec.example.", dns.TypeA, func(tr *chaseTree) {
			tr.edit("nx.sec.example.", dns.TypeA, dropNSECAt("sec.example."))
		}, ChainStatusBogus, "the NSEC proof does not hold"},
		{"an NSEC changed after signing", "nx.sec.example.", dns.TypeA, func(tr *chaseTree) {
			tr.edit("nx.sec.example.", dns.TypeA, changeRR(dns.TypeNSEC, func(rr dns.RR) {
				rr.(*dns.NSEC).NextDomain = "z.sec.example."
			}))
		}, ChainStatusBogus, "does not verify"},
		{"no RRSIG at all", "nx.sec.example.", dns.TypeA, func(tr *chaseTree) {
			tr.edit("nx.sec.example.", dns.TypeA, func(m *dns.Msg) {
				stripSigs(dns.TypeSOA)(m)
				dropProof(m)
			})
		}, ChainStatusBogus, "NXDOMAIN with no RRSIG, and zone sec.example. is signed"},
		{"the SOA of another zone", "nx.sec.example.", dns.TypeA, func(tr *chaseTree) {
			parent := tr.zones["example."]
			tr.script("nx.sec.example.", dns.TypeA, func() *dns.Msg {
				return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}, Ns: parent.sign(parent.get("example.", dns.TypeSOA))}
			})
		}, ChainStatusBogus, "NXDOMAIN from example., not from sec.example."},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr := denialTree(t)
			if c.setup != nil {
				c.setup(tr)
			}
			res := tr.chase(c.qname, c.qtype)
			wantStatus(t, "leaf", res.Leaf.Status, c.want)
			if !hasNote(res.Leaf.Notes, c.note) {
				t.Errorf("leaf notes %q, want one with %q", res.Leaf.Notes, c.note)
			}
			if c.want == ChainStatusSecure && len(res.Leaf.Proof) == 0 {
				t.Errorf("a proven denial with no proof records kept")
			}
		})
	}

	t.Run("in an insecure zone", func(t *testing.T) {
		tr := kidTree(t)
		res := tr.chase("nx.kid.sec.example.", dns.TypeA)
		wantStatus(t, "leaf", res.Leaf.Status, ChainStatusInsecure)
	})

	// A name proven not to exist has nothing below it (RFC 8020): the walk
	// asks about no name below it.
	t.Run("nothing below a name error", func(t *testing.T) {
		tr := denialTree(t)
		res := tr.chase("y.nx.sec.example.", dns.TypeA)
		if l := linkNamed(res.Links, "sec.example."); !hasNote(l.Notes, "nx.sec.example.: does not exist (NXDOMAIN proven by NSEC)") {
			t.Errorf("sec.example. notes %q", l.Notes)
		}
		if tr.askedFor("y.nx.sec.example.", dns.TypeDS) {
			t.Errorf("asked for the DS of a name below one that does not exist")
		}
		wantStatus(t, "result", res.Status, ChainStatusSecure)
	})
}

// Whether an answer was synthesized from a wildcard is the resolver's call
// (cache.ExpansionSignature): the wildcard asked for by its own name is not
// an expansion, a name it answers for is.
func TestChaseExpansionIsTheResolversCall(t *testing.T) {
	tr := denialTree(t)
	res := tr.chase("*.w.sec.example.", dns.TypeA)
	wantStatus(t, "the wildcard by name", res.Leaf.Status, ChainStatusSecure)
	if hasNote(res.Leaf.Notes, "synthesized") {
		t.Errorf("the wildcard asked for by name taken for an expansion: %q", res.Leaf.Notes)
	}
	res = tr.chase("x.w.sec.example.", dns.TypeA)
	if !hasNote(res.Leaf.Notes, "synthesized from *.w.sec.example.") {
		t.Errorf("an expansion not reported: %q", res.Leaf.Notes)
	}
}

// wcScript answers x.w.sec.example. A with the A synthesized from
// *.w.sec.example., signed, and with the NSEC3 records recs, signed by
// sec.example., as its proof.
func wcScript(tr *chaseTree, recs ...*dns.NSEC3) {
	z := tr.zones["sec.example."]
	tr.script("x.w.sec.example.", dns.TypeA, func() *dns.Msg {
		m := &dns.Msg{Answer: expand(z.sign(z.get("*.w.sec.example.", dns.TypeA)), "x.w.sec.example.")}
		for _, r := range recs {
			m.Ns = append(m.Ns, z.sign([]dns.RR{r})...)
		}
		return m
	})
}

// An answer synthesized from a wildcard is Secure only with the proof that the
// name does not exist, nor any name between it and the wildcard (RFC 4035
// section 5.3.4, RFC 5155 section 8.8; item 7 of #876).
func TestChaseWildcardAnswers(t *testing.T) {
	const optOut = 1
	nc := func(flags uint8, iterations uint16) *dns.NSEC3 {
		return n3RR("sec.example.", "x.w.sec.example.", true, flags, iterations)
	}
	for _, c := range []struct {
		name  string
		setup func(tr *chaseTree)
		want  ChainStatus
		note  string
	}{
		{"NSEC proof", nil, ChainStatusSecure, "synthesized from *.w.sec.example.; the NSEC proof that the name does not exist holds"},
		{"proof missing", func(tr *chaseTree) { tr.edit("x.w.sec.example.", dns.TypeA, dropProof) },
			ChainStatusBogus, "with no NSEC or NSEC3 proof that the name does not exist"},
		{"proof changed after signing", func(tr *chaseTree) {
			tr.edit("x.w.sec.example.", dns.TypeA, changeRR(dns.TypeNSEC, func(rr dns.RR) {
				rr.(*dns.NSEC).NextDomain = "z.sec.example."
			}))
		}, ChainStatusBogus, "does not verify"},
		{"an NSEC that does not cover the name", func(tr *chaseTree) {
			z := tr.zones["sec.example."]
			tr.script("x.w.sec.example.", dns.TypeA, func() *dns.Msg {
				other := &dns.NSEC{Hdr: dns.RR_Header{Name: "a.sec.example.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
					NextDomain: "b.c.sec.example.", TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}}
				return &dns.Msg{Answer: expand(z.sign(z.get("*.w.sec.example.", dns.TypeA)), "x.w.sec.example."),
					Ns: z.sign([]dns.RR{other})}
			})
		}, ChainStatusBogus, "the NSEC proof that the name does not exist does not hold"},
		{"NSEC3 proof", func(tr *chaseTree) { wcScript(tr, nc(0, 0)) }, ChainStatusSecure, "the NSEC3 proof that the name does not exist holds"},
		{"NSEC3 Opt-Out", func(tr *chaseTree) { wcScript(tr, nc(optOut, 0)) }, ChainStatusInsecure, "Opt-Out span"},
		{"NSEC3 over the iteration limit", func(tr *chaseTree) { wcScript(tr, nc(0, 11)) }, ChainStatusInsecure, "iterations above the limit of 10"},
		{"NSEC3 covering another name", func(tr *chaseTree) {
			wcScript(tr, n3RR("sec.example.", "y.w.sec.example.", true, 0, 0))
		}, ChainStatusBogus, "does not hold"},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr := denialTree(t)
			if c.setup != nil {
				c.setup(tr)
			}
			res := tr.chase("x.w.sec.example.", dns.TypeA)
			wantStatus(t, "leaf", res.Leaf.Status, c.want)
			if !hasNote(res.Leaf.Notes, c.note) {
				t.Errorf("leaf notes %q, want one with %q", res.Leaf.Notes, c.note)
			}
		})
	}

	// A CNAME synthesized from a wildcard is a part like any other: its proof
	// is read, and its target walked.
	t.Run("a CNAME from a wildcard", func(t *testing.T) {
		tr := denialTree(t)
		tr.zones["sec.example."].add("*.cn.sec.example. 300 IN CNAME www.sec.example.")
		res := tr.chase("x.cn.sec.example.", dns.TypeA)
		if len(res.Aliases) != 1 {
			t.Fatalf("%d aliases, want 1", len(res.Aliases))
		}
		cn := res.Aliases[0].Leaf
		wantStatus(t, "CNAME", cn.Status, ChainStatusSecure)
		if !hasNote(cn.Notes, "synthesized from *.cn.sec.example.; the NSEC proof that the name does not exist holds") {
			t.Errorf("CNAME notes %q", cn.Notes)
		}
		wantStatus(t, "result", res.Status, ChainStatusSecure)

		tr.edit("x.cn.sec.example.", dns.TypeA, dropProof)
		wantStatus(t, "result without the proof", tr.chase("x.cn.sec.example.", dns.TypeA).Status, ChainStatusBogus)
	})
}

// Below a delegation proven unsigned, the answer takes the link's verdict,
// and the note says that verdict: Insecure under a Secure zone, but no
// better than a zone above that is Bogus or Indeterminate (review of #881).
func TestChaseUnsignedDelegationBelowAZoneNotSecure(t *testing.T) {
	for _, c := range []struct {
		name    string
		anchors func(tr *chaseTree) []*dns.DS
		want    ChainStatus
	}{
		{"wrong anchor", func(*chaseTree) []*dns.DS { return []*dns.DS{newFwdSecKey(t, ".").dnskey.ToDS(dns.SHA256)} }, ChainStatusBogus},
		{"no anchor", func(*chaseTree) []*dns.DS { return nil }, ChainStatusIndeterminate},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr := kidTree(t)
			res, err := NewChaser(tr, "192.0.2.1", c.anchors(tr)).Chase("www.kid.sec.example.", dns.TypeA)
			if err != nil {
				t.Fatal(err)
			}
			wantStatus(t, "kid.sec.example.", linkNamed(res.Links, "kid.sec.example.").Status, c.want)
			wantStatus(t, "leaf", res.Leaf.Status, c.want)
			if hasNote(res.Leaf.Notes, "is insecure") {
				t.Errorf("leaf notes %q say insecure for a %s answer", res.Leaf.Notes, c.want)
			}
			if !hasNote(res.Leaf.Notes, "zone kid.sec.example. is "+c.want.String()+": a delegation with no DS") {
				t.Errorf("leaf notes %q", res.Leaf.Notes)
			}
		})
	}
}
