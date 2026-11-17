/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"errors"
	"net"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// #1104: a nameserver the update adds together with its in-bailiwick glue is not
// in the parent's resolver yet, so the DS check, which asked the resolver where
// each nameserver is, took it for one that gave no answer, and refused a DS
// withdrawal in that update as unverifiable. The check is given the glue the
// parent will publish, with the update applied, and asks the nameservers there.

const (
	glueChild = twoSignerChild
	glueNS1   = "ns1.child.parent.example."
	glueNS2   = "ns2.child.parent.example."
)

// glueParent is a parent that publishes ds for glueChild, delegated to ns1 with
// its glue at 127.0.0.1.
func glueParent(t *testing.T, ds ...*dns.DS) *ZoneData {
	t.Helper()
	zone := `parent.example.	3600	IN	SOA	ns.parent.example. hostmaster.parent.example. 1 7200 1800 604800 7200
parent.example.	3600	IN	NS	ns.parent.example.
ns.parent.example.	3600	IN	A	192.0.2.53
` + glueChild + `	3600	IN	NS	` + glueNS1 + `
` + glueNS1 + `	3600	IN	A	127.0.0.1
`
	for _, d := range ds {
		zone += d.String() + "\n"
	}
	zd := testSnapshotZone(t, "parent.example.", zone)
	zd.Options = map[ZoneOption]bool{OptAllowChildUpdates: true}
	zd.UpdatePolicy = UpdatePolicy{
		Child: UpdatePolicyDetail{Type: "selfsub",
			RRtypes: map[uint16]bool{dns.TypeDS: true, dns.TypeNS: true, dns.TypeA: true, dns.TypeAAAA: true}, TTL: 120},
	}
	return zd
}

// answerOf is rrset as the records a test DNS server answers with.
func answerOf(rrset *core.RRset) []string {
	var out []string
	for _, rr := range rrset.RRs {
		out = append(out, rr.String())
	}
	for _, rr := range rrset.RRSIGs {
		out = append(out, rr.String())
	}
	return out
}

func mustGlueRR(t *testing.T, class uint16, text string) dns.RR {
	t.Helper()
	rr := mustRR(t, text)
	rr.Header().Class = class
	return rr
}

// What the delegation is once the update is applied: the NS RRset, and the glue
// the parent publishes for it, the update's additions and deletions included.
func TestChildServersAfterCarriesTheGlueTheUpdateLeaves(t *testing.T) {
	zd := glueParent(t)
	glueOf := func(servers childServers) []string {
		var out []string
		for _, rr := range servers.Glue {
			out = append(out, rr.Header().Name+" "+dns.TypeToString[rr.Header().Rrtype]+" "+rdataOf(rr))
		}
		return out
	}
	nsOf := func(servers childServers) []string {
		var out []string
		for _, rr := range servers.NS {
			out = append(out, rr.(*dns.NS).Ns)
		}
		return out
	}
	same := func(t *testing.T, what string, got, want []string) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s: %v, want %v", what, got, want)
		}
		for i := range got {
			if !strings.EqualFold(got[i], want[i]) {
				t.Errorf("%s[%d]: %q, want %q", what, i, got[i], want[i])
			}
		}
	}

	// A DS-only update: the glue the parent holds.
	servers := zd.childServersAfter(glueChild, []dns.RR{addDS(dsForKey(t, newSignerTestKey(t, glueChild, 257)))})
	same(t, "NS", nsOf(servers), []string{glueNS1})
	same(t, "glue", glueOf(servers), []string{glueNS1 + " A 127.0.0.1"})

	// A nameserver added with its glue: both are in the delegation, and ns1's
	// glue stays.
	servers = zd.childServersAfter(glueChild, []dns.RR{
		mustGlueRR(t, dns.ClassINET, glueChild+" 3600 IN NS "+glueNS2),
		mustGlueRR(t, dns.ClassINET, glueNS2+" 3600 IN A 192.0.2.2"),
		mustGlueRR(t, dns.ClassINET, glueNS2+" 3600 IN AAAA 2001:db8::2"),
	})
	same(t, "NS", nsOf(servers), []string{glueNS1, glueNS2})
	same(t, "glue", glueOf(servers), []string{glueNS1 + " A 127.0.0.1", glueNS2 + " A 192.0.2.2", glueNS2 + " AAAA 2001:db8::2"})

	// Glue the update withdraws is not there; a nameserver the update drops
	// takes its glue with it.
	servers = zd.childServersAfter(glueChild, []dns.RR{
		mustGlueRR(t, dns.ClassINET, glueChild+" 3600 IN NS "+glueNS2),
		mustGlueRR(t, dns.ClassNONE, glueChild+" 3600 IN NS "+glueNS1),
		mustGlueRR(t, dns.ClassNONE, glueNS1+" 3600 IN A 127.0.0.1"),
	})
	same(t, "NS", nsOf(servers), []string{glueNS2})
	same(t, "glue", glueOf(servers), nil)

	// A nameserver outside the parent's zone has no glue to give.
	out := twoSignerParent(t).childServersAfter(twoSignerChild, nil)
	if len(out.NS) != 2 || len(out.Glue) != 0 {
		t.Errorf("out-of-bailiwick nameservers: %d NS, %d glue, want 2 and none", len(out.NS), len(out.Glue))
	}
}

// The update adds a nameserver with its glue and withdraws a DS. The new
// nameserver is asked at its glue address, which the resolver knows nothing of:
// accepted when it serves a copy the DS RRset that results validates, refused
// when it serves one it does not, and refused as unverifiable, for a retry,
// when it does not answer.
func TestCoherenceAsksANameserverTheUpdateAddsAtItsGlue(t *testing.T) {
	p := newSignerPair(t, glueChild)
	copyA, copyB := p.signedBy(t, p.a), p.signedBy(t, p.b)

	// ns1, whose glue the parent holds, answers at 127.0.0.1 with B's copy. ns2
	// is added at ::1, on the same port, which a test has to share.
	_, port, err := net.SplitHostPort(testAuthServerAt(t, "127.0.0.1:0", true, answerOf(copyB), nil))
	if err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", net.JoinHostPort("::1", port))
	if err != nil {
		t.Skipf("cannot listen on [::1]:%s: %v", port, err)
	}
	_ = probe.Close()

	sc := NewScanner(startAuthQueryEngine(t), false, false)
	imr := newTestImr(t) // knows no nameserver at all
	sc.conf = &Config{}
	sc.conf.Internal.ImrEngine = imr
	sc.conf.Internal.ImrReady = NewImrReadiness()
	sc.conf.Internal.ImrReady.Publish()
	sc.childPort = port

	addNS2 := func(glue ...string) []dns.RR {
		actions := []dns.RR{mustGlueRR(t, dns.ClassINET, glueChild+" 3600 IN NS "+glueNS2)}
		for _, g := range glue {
			actions = append(actions, mustGlueRR(t, dns.ClassINET, g))
		}
		return actions
	}
	withdrawA := delOneDS(p.dsA)
	ns2Glue := glueNS2 + " 3600 IN AAAA ::1"
	check := func(actions ...dns.RR) error {
		return glueParent(t, p.dsA, p.dsB).CheckDelegationCoherenceForUpdate(actions, nameserversDnskeyFetcher(sc))
	}

	t.Run("it serves a coherent copy", func(t *testing.T) {
		testAuthServerAt(t, net.JoinHostPort("::1", port), true, answerOf(copyB), nil)
		if err := check(append(addNS2(ns2Glue), withdrawA)...); err != nil {
			t.Fatalf("the nameserver added with its glue was not asked there: %v", err)
		}
	})

	t.Run("it serves a copy the DS RRset that results does not validate", func(t *testing.T) {
		testAuthServerAt(t, net.JoinHostPort("::1", port), true, answerOf(copyA), nil)
		err := check(append(addNS2(ns2Glue), withdrawA)...)
		if err == nil {
			t.Fatal("A's DS was withdrawn while the new nameserver serves a copy signed by A only")
		}
		if !strings.Contains(err.Error(), "nameserver "+glueNS2) {
			t.Errorf("the refusal does not name the new nameserver: %v", err)
		}
		if errors.Is(err, ErrDelegationUnverifiable) || delegationCoherenceEDE(err) != edns0.EDEDelegationIncoherent {
			t.Errorf("a decided refusal is marked unverifiable: %v", err)
		}
	})

	// Nothing listens on [::1] at this port in the two that follow: the first
	// server of the subtests above is shut down with its subtest.
	t.Run("its address does not answer", func(t *testing.T) {
		err := check(append(addNS2(ns2Glue), withdrawA)...)
		if err == nil {
			t.Fatal("A's DS was withdrawn with the new nameserver not heard from")
		}
		if !errors.Is(err, ErrDelegationUnverifiable) || !strings.Contains(err.Error(), glueNS2) {
			t.Errorf("got %v, want a refusal that names the new nameserver, marked unverifiable", err)
		}
		if got := delegationCoherenceEDE(err); got != edns0.EDEDelegationUnverifiable {
			t.Errorf("EDE %d, want %d (unverifiable)", got, edns0.EDEDelegationUnverifiable)
		}
	})

	t.Run("no glue, so nothing to ask", func(t *testing.T) {
		err := check(append(addNS2(), withdrawA)...)
		if err == nil || !errors.Is(err, ErrDelegationUnverifiable) || !strings.Contains(err.Error(), glueNS2) {
			t.Fatalf("got %v, want the new nameserver, with no address, to hold the withdrawal as unverifiable", err)
		}
	})

	t.Run("a DS addition does not wait for it", func(t *testing.T) {
		extra := newSignerTestKey(t, glueChild, 257)
		if err := check(append(addNS2(ns2Glue), addDS(dsForKey(t, extra)))...); err != nil {
			t.Fatalf("a DS addition was refused for a nameserver that did not answer: %v", err)
		}
	})
}
