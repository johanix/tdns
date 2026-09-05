/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package peer

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const testDNSKEY = "relay.test. 3600 IN DNSKEY 257 3 15 kRBqRMzUZ6PJyDXkkyOJXHZTRlAvNRTOZUqbXkMDBHo="

func apexKeyTag(t *testing.T) uint16 {
	t.Helper()
	k, ok := mustRR(t, testDNSKEY).(*dns.DNSKEY)
	if !ok {
		t.Fatal("test DNSKEY did not parse as a DNSKEY")
	}
	return k.KeyTag()
}

// sigRR builds a syntactically valid RRSIG. Nothing here verifies
// cryptography — the checks are about presence and about which key an RRSIG
// names — so the signature bytes are a placeholder on purpose.
func sigRR(t *testing.T, owner string, covered uint16, keytag uint16) dns.RR {
	t.Helper()
	labels := dns.CountLabel(dns.Fqdn(owner))
	return mustRR(t, fmt.Sprintf("%s 3600 IN RRSIG %s 15 %d 3600 20260930000000 20260901000000 %d relay.test. c2lnbmF0dXJl",
		dns.Fqdn(owner), dns.TypeToString[covered], labels, keytag))
}

// signedZone is the seed zone as a correct signer would publish it: a DNSKEY,
// an RRSIG over every authoritative RRset, and a closed NSEC chain.
func signedZone(t *testing.T) *Zone {
	t.Helper()
	kt := apexKeyTag(t)
	z := seedZone(t)
	z.Add(mustRR(t, testDNSKEY))
	// Canonical order: apex, then host1, then ns.
	z.Add(mustRR(t, "relay.test. 3600 IN NSEC host1.relay.test. NS SOA RRSIG NSEC DNSKEY"))
	z.Add(mustRR(t, "host1.relay.test. 3600 IN NSEC ns.relay.test. A RRSIG NSEC"))
	z.Add(mustRR(t, "ns.relay.test. 3600 IN NSEC relay.test. A RRSIG NSEC"))
	for _, s := range []struct {
		owner   string
		covered uint16
	}{
		{"relay.test.", dns.TypeSOA},
		{"relay.test.", dns.TypeNS},
		{"relay.test.", dns.TypeDNSKEY},
		{"relay.test.", dns.TypeNSEC},
		{"host1.relay.test.", dns.TypeA},
		{"host1.relay.test.", dns.TypeNSEC},
		{"ns.relay.test.", dns.TypeA},
		{"ns.relay.test.", dns.TypeNSEC},
	} {
		z.Add(sigRR(t, s.owner, s.covered, kt))
	}
	return z
}

func TestCheckSigningAcceptsACorrectlySignedZone(t *testing.T) {
	rep := CheckSigning(signedZone(t))
	if !rep.FullySigned() {
		t.Fatalf("a correctly signed zone was reported defective:\n%s", rep)
	}
	if rep.ChainSkipped != "" {
		t.Fatalf("the NSEC chain was skipped on a zone that has one: %s", rep.ChainSkipped)
	}
	if rep.Checked == 0 {
		t.Fatal("no RRsets were checked; the report would pass vacuously")
	}
}

// The state NOTIFY #1 announces (design §2.3): content as transferred, no
// signatures. N3 rests entirely on this being recognised.
func TestCheckSigningReportsAnUnsignedState(t *testing.T) {
	rep := CheckSigning(seedZone(t))
	if rep.Signed {
		t.Fatal("an unsigned zone was reported signed")
	}
	if rep.FullySigned() {
		t.Fatal("an unsigned zone passed FullySigned")
	}
	// One clear fact, not one issue per RRset.
	if len(rep.Issues) != 0 {
		t.Fatalf("an unsigned zone produced per-RRset issues, burying the finding:\n%s", rep)
	}
}

func TestCheckSigningDetectsPlantedDefects(t *testing.T) {
	kt := apexKeyTag(t)
	tests := []struct {
		name  string
		plant func(t *testing.T, z *Zone)
		want  IssueKind
	}{
		{
			name: "an RRset lost its signature",
			plant: func(t *testing.T, z *Zone) {
				if !z.Remove(sigRR(t, "host1.relay.test.", dns.TypeA, kt)) {
					t.Fatal("setup: the RRSIG to remove was not there")
				}
			},
			want: IssueUnsignedRRset,
		},
		{
			name: "signed by a key the zone does not publish",
			plant: func(t *testing.T, z *Zone) {
				z.Remove(sigRR(t, "host1.relay.test.", dns.TypeA, kt))
				z.Add(sigRR(t, "host1.relay.test.", dns.TypeA, kt+1))
			},
			want: IssueForeignSigner,
		},
		{
			name: "signature left behind by a withdrawn RRset",
			plant: func(t *testing.T, z *Zone) {
				z.Add(sigRR(t, "host1.relay.test.", dns.TypeTXT, kt))
			},
			want: IssueOrphanRRSIG,
		},
		{
			name: "signatures but no keys",
			plant: func(t *testing.T, z *Zone) {
				if !z.Remove(mustRR(t, testDNSKEY)) {
					t.Fatal("setup: no DNSKEY to remove")
				}
			},
			want: IssueNoDNSKEY,
		},
		{
			name: "the chain points at a name that has no NSEC",
			plant: func(t *testing.T, z *Zone) {
				z.Remove(mustRR(t, "host1.relay.test. 3600 IN NSEC ns.relay.test. A RRSIG NSEC"))
				z.Add(mustRR(t, "host1.relay.test. 3600 IN NSEC nowhere.relay.test. A RRSIG NSEC"))
			},
			want: IssueChainBreak,
		},
		{
			name: "an NSEC owner unreachable from the apex",
			plant: func(t *testing.T, z *Zone) {
				// Short-circuit the apex straight to ns, orphaning host1.
				z.Remove(mustRR(t, "relay.test. 3600 IN NSEC host1.relay.test. NS SOA RRSIG NSEC DNSKEY"))
				z.Add(mustRR(t, "relay.test. 3600 IN NSEC ns.relay.test. NS SOA RRSIG NSEC DNSKEY"))
				z.Remove(mustRR(t, "host1.relay.test. 3600 IN NSEC ns.relay.test. A RRSIG NSEC"))
				z.Add(mustRR(t, "host1.relay.test. 3600 IN NSEC relay.test. A RRSIG NSEC"))
			},
			want: IssueChainBreak,
		},
		{
			name: "an authoritative name is not in the chain",
			plant: func(t *testing.T, z *Zone) {
				z.Add(mustRR(t, "host9.relay.test. 3600 IN A 10.0.0.9"))
				z.Add(sigRR(t, "host9.relay.test.", dns.TypeA, kt))
			},
			want: IssueChainMissing,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			z := signedZone(t)
			if base := CheckSigning(z); !base.FullySigned() {
				t.Fatalf("the fixture is not clean before planting:\n%s", base)
			}
			tc.plant(t, z)
			rep := CheckSigning(z)
			if rep.FullySigned() {
				t.Fatalf("a planted %s went unreported:\n%s", tc.want, rep)
			}
			found := false
			for _, i := range rep.Issues {
				if i.Kind == tc.want {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("report does not carry a %s issue:\n%s", tc.want, rep)
			}
		})
	}
}

// A delegation is where a rig most easily reports the correct server as
// broken: the NS RRset and the glue below it are unsigned BY DESIGN, and only
// the DS is signed.
func TestCheckSigningDoesNotDemandSignaturesAtOrBelowADelegation(t *testing.T) {
	kt := apexKeyTag(t)
	z := seedZone(t)
	z.Add(mustRR(t, testDNSKEY))
	z.Add(mustRR(t, "child.relay.test. 3600 IN NS ns1.child.relay.test."))
	z.Add(mustRR(t, "ns1.child.relay.test. 3600 IN A 192.0.2.1"))
	z.Add(mustRR(t, "child.relay.test. 3600 IN DS 12345 15 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"))
	z.Add(sigRR(t, "child.relay.test.", dns.TypeDS, kt))
	for _, s := range []struct {
		owner   string
		covered uint16
	}{
		{"relay.test.", dns.TypeSOA},
		{"relay.test.", dns.TypeNS},
		{"relay.test.", dns.TypeDNSKEY},
		{"host1.relay.test.", dns.TypeA},
		{"ns.relay.test.", dns.TypeA},
	} {
		z.Add(sigRR(t, s.owner, s.covered, kt))
	}

	rep := CheckSigning(z)
	if !strings.Contains(rep.ChainSkipped, "no NSEC records") {
		t.Fatalf("expected the chain check to be skipped and said so, got %q", rep.ChainSkipped)
	}
	if len(rep.Issues) != 0 {
		t.Fatalf("the delegation NS or its glue was demanded signed:\n%s", rep)
	}

	// But the DS at the delegation IS signed, and losing its signature must
	// still be caught — otherwise the exemption above is too wide.
	z.Remove(sigRR(t, "child.relay.test.", dns.TypeDS, kt))
	rep = CheckSigning(z)
	found := false
	for _, i := range rep.Issues {
		if i.Kind == IssueUnsignedRRset && i.Rrtype == dns.TypeDS {
			found = true
		}
	}
	if !found {
		t.Fatalf("an unsigned DS at a delegation went unreported:\n%s", rep)
	}
}

// A skip is reported, never counted as a pass.
func TestCheckSigningSkipsNSEC3Chains(t *testing.T) {
	z := signedZone(t)
	z.Add(mustRR(t, "relay.test. 3600 IN NSEC3PARAM 1 0 0 -"))
	rep := CheckSigning(z)
	if !strings.Contains(rep.ChainSkipped, "NSEC3") {
		t.Fatalf("ChainSkipped = %q, want an NSEC3 explanation", rep.ChainSkipped)
	}
}
