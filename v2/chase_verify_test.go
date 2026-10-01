/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"slices"
	"strings"
	"testing"

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
