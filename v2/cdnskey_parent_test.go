/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
)

// The parent checks the CDNSKEY against the CDS (#753; design
// docs/2026-09-24-cds-publication-and-rfc-conformance.md §4.3, tests §4.4).
// RFC 9975 §3.1: a key referenced in the CDS but not in the CDNSKEY, or the
// other way round, is inconsistent. A child that serves no CDNSKEY at any
// nameserver is accepted as CDS-only: local policy, not RFC 9975.

func genKSK(t *testing.T, owner string) *dns.DNSKEY {
	t.Helper()
	key := &dns.DNSKEY{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	if _, err := key.Generate(256); err != nil {
		t.Fatalf("generating a key for %s: %v", owner, err)
	}
	return key
}

func cdsRecords(owner string, digest uint8, keys ...*dns.DNSKEY) []dns.RR {
	var out []dns.RR
	for _, k := range keys {
		c := k.ToDS(digest).ToCDS()
		c.Hdr.Name = owner
		out = append(out, c)
	}
	return out
}

func cdnskeyRecords(owner string, keys ...*dns.DNSKEY) []dns.RR {
	var out []dns.RR
	for _, k := range keys {
		out = append(out, cdnskeyOf(owner, k))
	}
	return out
}

func TestCdnskeyAgreesWithCDS(t *testing.T) {
	const zone = "child.example."
	a, b := genKSK(t, zone), genKSK(t, zone)
	cdnskeyDelete := mustRR(t, zone+" 3600 IN CDNSKEY 0 3 0 AA==")
	cdsDelete := mustRR(t, zone+" 3600 IN CDS 0 0 0 00")
	sha384 := cdsRecords(zone, dns.SHA384, a)
	for _, tc := range []struct {
		name    string
		cds     []dns.RR
		cdnskey []dns.RR
		want    bool
		why     string // part of the reason, when it matters
	}{
		{"the same keys", cdsRecords(zone, dns.SHA256, a, b), cdnskeyRecords(zone, a, b), true, ""},
		{"a key in the CDS only", cdsRecords(zone, dns.SHA256, a, b), cdnskeyRecords(zone, a), false, ""},
		{"a key in the CDNSKEY only", cdsRecords(zone, dns.SHA256, a), cdnskeyRecords(zone, a, b), false, ""},
		{"another key", cdsRecords(zone, dns.SHA256, a), cdnskeyRecords(zone, b), false, ""},
		{"SHA-384 records beside SHA-256 ones take no part",
			append(cdsRecords(zone, dns.SHA256, a), cdsRecords(zone, dns.SHA384, b)...), cdnskeyRecords(zone, a), true, ""},
		{"a CDS with no SHA-256 record names no key the check sees", sha384, cdnskeyRecords(zone, a), false, ""},
		{"both the RFC 8078 delete", []dns.RR{cdsDelete}, []dns.RR{cdnskeyDelete}, true, ""},
		{"the delete CDS and a CDNSKEY with keys", []dns.RR{cdsDelete}, cdnskeyRecords(zone, a), false, ""},
		{"a CDS with keys and the delete CDNSKEY", cdsRecords(zone, dns.SHA256, a), []dns.RR{cdnskeyDelete}, false, ""},
		{"an algorithm-0 CDNSKEY beside a key", cdsRecords(zone, dns.SHA256, a),
			append(cdnskeyRecords(zone, a), cdnskeyDelete), false, "algorithm 0"},
	} {
		got, why := cdnskeyAgreesWithCDS(tc.cds, tc.cdnskey)
		if got != tc.want {
			t.Errorf("%s: agrees %v (%s), want %v", tc.name, got, why, tc.want)
		}
		if tc.why != "" && !strings.Contains(why, tc.why) {
			t.Errorf("%s: reason %q does not say %q", tc.name, why, tc.why)
		}
	}
}

func TestScanCDSChecksTheCdnskey(t *testing.T) {
	const oldDigest = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	for i, tc := range []struct {
		name string
		// serve sets what the child serves beyond its DNSKEY RRset {a, b}.
		serve      func(n *trustNet, child string, a, b *dns.DNSKEY)
		hasDS      bool
		wantReason string // empty: applied
		wantAdds   int
		wantLog    string
	}{
		{name: "CDS and CDNSKEY name the same keys", wantAdds: 2,
			serve: func(n *trustNet, c string, a, b *dns.DNSKEY) {
				n.served[trustKey(c, dns.TypeCDS)] = cdsRecords(c, dns.SHA256, a, b)
				n.served[trustKey(c, dns.TypeCDNSKEY)] = cdnskeyRecords(c, a, b)
			}},
		{name: "a key in the CDS only, with a CDNSKEY served", wantReason: "RFC 9975",
			serve: func(n *trustNet, c string, a, b *dns.DNSKEY) {
				n.served[trustKey(c, dns.TypeCDS)] = cdsRecords(c, dns.SHA256, a, b)
				n.served[trustKey(c, dns.TypeCDNSKEY)] = cdnskeyRecords(c, a)
			}},
		{name: "no CDNSKEY at any nameserver: a CDS-only child, by local policy", wantAdds: 1,
			wantLog: "local policy",
			serve: func(n *trustNet, c string, a, b *dns.DNSKEY) {
				n.served[trustKey(c, dns.TypeCDS)] = cdsRecords(c, dns.SHA256, a)
			}},
		{name: "a CDNSKEY served by one nameserver only", wantReason: "CDNSKEY",
			serve: func(n *trustNet, c string, a, b *dns.DNSKEY) {
				n.served[trustKey(c, dns.TypeCDS)] = cdsRecords(c, dns.SHA256, a)
				n.served[trustKey(c, dns.TypeCDNSKEY)] = cdnskeyRecords(c, a)
				n.disagree = map[string]bool{trustKey(c, dns.TypeCDNSKEY): true}
			}},
		{name: "SHA-256 and SHA-384 CDS records, and the CDNSKEY for the key", wantAdds: 2,
			serve: func(n *trustNet, c string, a, b *dns.DNSKEY) {
				n.served[trustKey(c, dns.TypeCDS)] = append(cdsRecords(c, dns.SHA256, a), cdsRecords(c, dns.SHA384, a)...)
				n.served[trustKey(c, dns.TypeCDNSKEY)] = cdnskeyRecords(c, a)
			}},
		{name: "the delete in both, with a DS", hasDS: true,
			serve: func(n *trustNet, c string, a, b *dns.DNSKEY) {
				n.served[trustKey(c, dns.TypeCDS)] = rrs(t, c+deleteCDS)
				n.served[trustKey(c, dns.TypeCDNSKEY)] = rrs(t, c+" 3600 IN CDNSKEY 0 3 0 AA==")
			}},
		{name: "the delete CDS and a CDNSKEY with a key, with a DS", hasDS: true, wantReason: "RFC 9975",
			serve: func(n *trustNet, c string, a, b *dns.DNSKEY) {
				n.served[trustKey(c, dns.TypeCDS)] = rrs(t, c+deleteCDS)
				n.served[trustKey(c, dns.TypeCDNSKEY)] = cdnskeyRecords(c, a)
			}},
		{name: "a CDS with a key and the delete CDNSKEY", wantReason: "RFC 9975",
			serve: func(n *trustNet, c string, a, b *dns.DNSKEY) {
				n.served[trustKey(c, dns.TypeCDS)] = cdsRecords(c, dns.SHA256, a)
				n.served[trustKey(c, dns.TypeCDNSKEY)] = rrs(t, c+" 3600 IN CDNSKEY 0 3 0 AA==")
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := fmt.Sprintf("cdnskey%d.example.", i)
			a, b := genKSK(t, child), genKSK(t, child)
			n := &trustNet{served: map[string][]dns.RR{}, verdict: map[string]cache.ValidationState{}}
			n.served[trustKey(child, dns.TypeDNSKEY)] = []dns.RR{a, b}
			tc.serve(n, child, a, b)
			n.set(cache.ValidationStateSecure, trustKey(child, dns.TypeCDS), trustKey(child, dns.TypeDNSKEY))
			sc := trustScanner(n)
			var logbuf bytes.Buffer
			sc.Log["CDS"] = log.New(&logbuf, "", 0)
			var currentDS []dns.RR
			if tc.hasDS {
				currentDS = rrs(t, child+" 3600 IN DS 1111 13 2 "+oldDigest)
			}

			resp := runCDS(t, sc, trustParent(t, child, trustLax()), child, currentDS)

			if n.queried[trustKey(child, dns.TypeCDNSKEY)] == 0 {
				t.Error("the scan never asked for the CDNSKEY")
			}
			if tc.wantReason != "" {
				assertRefused(t, resp, tc.wantReason)
				return
			}
			if resp.Error || !scanResponseChangesDelegation(resp) {
				t.Fatalf("error %q, applied %v; want the DS change applied", resp.ErrorMsg, scanResponseChangesDelegation(resp))
			}
			if tc.hasDS {
				if len(resp.DSRemoves) != len(currentDS) || len(resp.DSAdds) != 0 {
					t.Errorf("adds %v, removes %v; want every DS removed", names(resp.DSAdds), names(resp.DSRemoves))
				}
			} else if len(resp.DSAdds) != tc.wantAdds {
				t.Errorf("%d DS adds, want %d", len(resp.DSAdds), tc.wantAdds)
			}
			if tc.wantLog != "" && !strings.Contains(logbuf.String(), tc.wantLog) {
				t.Errorf("the log does not say %q:\n%s", tc.wantLog, logbuf.String())
			}
		})
	}
}
