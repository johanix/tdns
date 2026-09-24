/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"testing"

	"github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
)

// Only an exact RFC 8078 §4 delete CDS deletes (#755; design
// docs/2026-09-24-cds-publication-and-rfc-conformance.md §2). Any other set
// holding an algorithm-0 record breaks the rules, and RFC 7344 §4.1 says to
// ignore it: no change, and a refusal, with and without a DS.

const deleteCDS = " 3600 IN CDS 0 0 0 00"

func TestClassifyCDS(t *testing.T) {
	update := " 3600 IN CDS 12345 13 2 3f8a1f4c7b0d6c9e8a2b5d4f3e1c0b9a8d7c6e5f4a3b2c1d0e9f8a7b6c5d4e3f"
	cases := []struct {
		name string
		rrs  []string
		want cdsKind
	}{
		{"an update", []string{update}, cdsUpdate},
		{"the exact delete", []string{deleteCDS}, cdsDelete},
		{"a delete alongside a real record", []string{deleteCDS, update}, cdsMalformed},
		{"two delete records", []string{deleteCDS, deleteCDS}, cdsMalformed},
		{"algorithm 0 with a real key tag", []string{" 3600 IN CDS 12345 0 0 00"}, cdsMalformed},
		{"algorithm 0 with a digest type", []string{" 3600 IN CDS 0 0 2 00"}, cdsMalformed},
		{"algorithm 0 with a real digest", []string{" 3600 IN CDS 0 0 0 01"}, cdsMalformed},
		{"algorithm 0 with a real key tag, digest type and digest",
			[]string{" 3600 IN CDS 12345 0 2 3f8a1f4c7b0d6c9e8a2b5d4f3e1c0b9a8d7c6e5f4a3b2c1d0e9f8a7b6c5d4e3f"}, cdsMalformed},
		// Key tag 0 with a real algorithm is an ordinary record: only algorithm
		// 0 is the delete rule's business.
		{"key tag 0, algorithm 13", []string{" 3600 IN CDS 0 13 2 3f8a1f4c7b0d6c9e8a2b5d4f3e1c0b9a8d7c6e5f4a3b2c1d0e9f8a7b6c5d4e3f"}, cdsUpdate},
	}
	for _, tc := range cases {
		var set []dns.RR
		for _, s := range tc.rrs {
			set = append(set, mustRR(t, "child.example."+s))
		}
		if got, reason := classifyCDS(set); got != tc.want {
			t.Errorf("%s: kind %v (%s), want %v", tc.name, got, reason, tc.want)
		}
	}
}

// The scan: the exact delete removes every DS; every other algorithm-0 set is
// refused and changes nothing, with a DS and without one.
func TestScanCDSOnlyAnExactDeleteDeletes(t *testing.T) {
	const oldDigest = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	realCDS := func(child string) string {
		return child + " 3600 IN CDS 12345 13 2 3f8a1f4c7b0d6c9e8a2b5d4f3e1c0b9a8d7c6e5f4a3b2c1d0e9f8a7b6c5d4e3f"
	}
	atNS := DelegationPolicy{Name: "ns-only", Mechanisms: []string{"at-ns"}, RequireDnssec: true}

	for i, tc := range []struct {
		name       string
		pol        DelegationPolicy
		served     func(child string) []string
		hasDS      bool
		wantDelete bool // else refused
	}{
		{name: "the exact delete, with a DS: every DS removed", pol: trustLax(), hasDS: true, wantDelete: true,
			served: func(c string) []string { return []string{c + deleteCDS} }},
		{name: "a delete alongside a real CDS, with a DS", pol: trustLax(), hasDS: true,
			served: func(c string) []string { return []string{c + deleteCDS, realCDS(c)} }},
		{name: "a delete alongside a real CDS, without a DS: no bootstrap", pol: trustLax(),
			served: func(c string) []string { return []string{c + deleteCDS, realCDS(c)} }},
		{name: "algorithm 0 with a real key tag, digest type and digest", pol: trustLax(), hasDS: true,
			served: func(c string) []string {
				return []string{c + " 3600 IN CDS 12345 0 2 3f8a1f4c7b0d6c9e8a2b5d4f3e1c0b9a8d7c6e5f4a3b2c1d0e9f8a7b6c5d4e3f"}
			}},
		{name: "algorithm 0 with digest 01", pol: trustLax(), hasDS: true,
			served: func(c string) []string { return []string{c + " 3600 IN CDS 0 0 0 01"} }},
		{name: "two delete records", pol: trustLax(), hasDS: true,
			served: func(c string) []string { return []string{c + deleteCDS, c + deleteCDS} }},
		{name: "under at-ns (RFC 9615), without a DS: refused before the signaling names", pol: atNS,
			served: func(c string) []string { return []string{c + deleteCDS, realCDS(c)} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := fmt.Sprintf("del%d.example.", i)
			n := &trustNet{served: map[string][]dns.RR{}, verdict: map[string]cache.ValidationState{}}
			n.served[trustKey(child, dns.TypeCDS)] = rrs(t, tc.served(child)...)
			n.set(cache.ValidationStateSecure, trustKey(child, dns.TypeCDS), trustKey(child, dns.TypeDNSKEY))
			var currentDS []dns.RR
			if tc.hasDS {
				currentDS = rrs(t, child+" 3600 IN DS 1111 13 2 "+oldDigest)
			}

			resp := runCDS(t, trustScanner(n), trustParent(t, child, tc.pol), child, currentDS)

			if tc.wantDelete {
				if resp.Error || !resp.DataChanged || len(resp.DSRemoves) != len(currentDS) || len(resp.DSAdds) != 0 {
					t.Fatalf("error %q, changed %v, adds %v, removes %v; want every DS removed",
						resp.ErrorMsg, resp.DataChanged, names(resp.DSAdds), names(resp.DSRemoves))
				}
				return
			}
			assertRefused(t, resp, "RFC 8078")
			if tc.pol.Name == atNS.Name && len(n.validated) != 0 {
				t.Errorf("validated %v for a set refused on its shape", n.validated)
			}
		})
	}
}
