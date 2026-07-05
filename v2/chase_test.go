package tdns

import (
	"bytes"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

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
