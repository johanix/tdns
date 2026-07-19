package tdns

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/johanix/tdns/v2/core"
)

// scriptedClient is a DNSClienter that answers from a fixed map keyed by
// "qname/qtype", for driving the chaser in tests without a real resolver.
// A missing key returns an empty (NOERROR, no-answer) response.
type scriptedClient struct {
	answers map[string][]dns.RR
}

func (s *scriptedClient) TransportKind() core.Transport { return core.TransportDo53 }

func (s *scriptedClient) ExchangeWithResult(msg *dns.Msg, server string, debug bool) (*dns.Msg, time.Duration, core.ExchangeResult, error) {
	r, rtt, err := s.Exchange(msg, server, debug)
	return r, rtt, core.ExchangeResult{WireTransport: core.TransportDo53}, err
}

func (s *scriptedClient) Exchange(msg *dns.Msg, _ string, _ bool) (*dns.Msg, time.Duration, error) {
	resp := new(dns.Msg)
	resp.SetReply(msg)
	if len(msg.Question) == 1 {
		q := msg.Question[0]
		key := q.Name + "/" + dns.TypeToString[q.Qtype]
		resp.Answer = append(resp.Answer, s.answers[key]...)
	}
	return resp, 0, nil
}

// TestChaseDropsNonApexName is the regression test for the bug where the
// chaser treated every label boundary as a zone cut, so a non-apex name
// (e.g. www.iis.se) became a phantom zone with no DS/DNSKEY and derailed
// validation. The fix: a candidate with no DS AND no NS/SOA of its own is
// not a zone cut and is dropped from the chain. Here iis.se is a real
// (secure) zone and www.iis.se is just a name in it; the chain must NOT
// contain a www.iis.se link.
func TestChaseDropsNonApexName(t *testing.T) {
	// Minimal script: iis.se has a DS (at its parent) and a DNSKEY; the
	// non-apex www.iis.se has neither a DS nor NS/SOA. We are not exercising
	// signature crypto here — only that the phantom cut is excluded — so
	// the deeper links are left unsigned/indeterminate, which is fine: the
	// assertion is purely about which zones appear in the chain.
	ans := map[string][]dns.RR{
		"iis.se./DS":     {mustRR(t, "iis.se. 3600 IN DS 51298 13 2 "+strings.Repeat("aa", 32))},
		"iis.se./DNSKEY": {mustRR(t, "iis.se. 3600 IN DNSKEY 257 3 13 "+strings.Repeat("A", 40))},
		// www.iis.se: no DS, no NS, no SOA -> not a zone cut.
		"www.iis.se./A": {mustRR(t, "www.iis.se. 3600 IN A 159.253.30.207")},
	}
	c := NewChaser(&scriptedClient{answers: ans}, "192.0.2.1:53", nil)
	res, err := c.Chase("www.iis.se.", dns.TypeA)
	if err != nil {
		t.Fatalf("Chase: %v", err)
	}
	var names []string
	for _, l := range res.Links {
		names = append(names, l.Zone)
		if l.Zone == "www.iis.se." {
			t.Errorf("chain must not contain a www.iis.se. link (it is not a zone cut); links: %v", names)
		}
	}
}

// TestAlgField covers the +algchase annotation helper: bare number when
// off, "N (NAME)" when on, and "N (unknown)" for an unregistered
// codepoint.
func TestAlgField(t *testing.T) {
	// ECDSAP256SHA256 (13) is a builtin, always registered.
	if got := algField(dns.ECDSAP256SHA256, false); got != "alg=13" {
		t.Errorf("algField(13, false) = %q, want alg=13", got)
	}
	if got := algField(dns.ECDSAP256SHA256, true); got != "alg=13 (ECDSAP256SHA256)" {
		t.Errorf("algField(13, true) = %q, want alg=13 (ECDSAP256SHA256)", got)
	}
	// A codepoint no binary registers -> unknown.
	if got := algField(251, true); got != "alg=251 (unknown)" {
		t.Errorf("algField(251, true) = %q, want alg=251 (unknown)", got)
	}
}

// TestRenderChainAlgNames verifies RenderChain annotates DS and DNSKEY
// algorithm numbers with names only when algNames is set.
func TestRenderChainAlgNames(t *testing.T) {
	res := &ChainResult{
		Status: ChainStatusSecure,
		Links: []ChainLink{
			{
				Zone:   ".",
				Status: ChainStatusSecure,
				DS: []*dns.DS{
					{Hdr: dns.RR_Header{Name: "."}, KeyTag: 20326, Algorithm: dns.RSASHA256, DigestType: 2, Digest: "ab"},
				},
				DNSKEY: []*dns.DNSKEY{
					{Hdr: dns.RR_Header{Name: "."}, Flags: 257, Protocol: 3, Algorithm: dns.RSASHA256, PublicKey: "AA"},
				},
			},
		},
		Leaf: ChainLeaf{Qname: "example.", Qtype: dns.TypeA, Status: ChainStatusSecure},
	}

	var off, on bytes.Buffer
	RenderChain(res, &off, false)
	RenderChain(res, &on, true)

	if strings.Contains(off.String(), "RSASHA256") {
		t.Errorf("+sigchase (algNames=false) should NOT print algorithm names:\n%s", off.String())
	}
	if !strings.Contains(off.String(), "alg=8") {
		t.Errorf("expected bare alg=8 in non-annotated output:\n%s", off.String())
	}
	if !strings.Contains(on.String(), "alg=8 (RSASHA256)") {
		t.Errorf("+algchase (algNames=true) should annotate alg=8 with the name:\n%s", on.String())
	}
}
