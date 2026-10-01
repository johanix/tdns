/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
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
