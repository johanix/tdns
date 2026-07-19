/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cli

import (
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// TestDescribeZone_Signed: a signed zone renders the applied-policy triplet and
// the bound policy's KSK/ZSK algorithm + lifetime + sig-validity detail, with
// algorithm numbers rendered as names and lifetimes as durations.
func TestDescribeZone_Signed(t *testing.T) {
	zconf := tdns.ZoneConf{
		Name:                  "signed.example.",
		Type:                  "primary",
		Store:                 "MapZone",
		EffectiveDnssecPolicy: "pol-a",
		AppliedPolicy:         "pol-a",
		AppliedSource:         "command",
		AppliedAt:             "2026-07-18 12:00:00",
		PolicyDetail: &tdns.DnssecPolicyView{
			Name:               "pol-a",
			Mode:               tdns.DnssecPolicyModeKSKZSK,
			KSKAlgorithm:       13, // ECDSAP256SHA256
			ZSKAlgorithm:       13,
			KSKLifetime:        31536000, // 365d
			ZSKLifetime:        2592000,  // 30d
			SigValidityDefault: 1209600,
			SigValidityDNSKEY:  1209600,
			SigValidityDS:      86400,
		},
	}
	out := DescribeZone(zconf)
	for _, want := range []string{
		"zone: signed.example.",
		"Type: primary",
		"DNSSEC policy: pol-a",
		"Applied policy: pol-a",
		"Source: command",
		"Applied at: 2026-07-18 12:00:00",
		"DNSSEC detail: Mode: ksk-zsk",
		"KSK algorithm: ECDSAP256SHA256",
		"ZSK algorithm: ECDSAP256SHA256",
		"KSK lifetime: 8760h0m0s",
		"ZSK lifetime: 720h0m0s",
		"SigValidity: default=336h0m0s DNSKEY=336h0m0s DS=24h0m0s",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("DescribeZone missing %q in output:\n%s", want, out)
		}
	}
	// CSK-only wording must NOT appear for a ksk-zsk policy.
	if strings.Contains(out, "CSK algorithm") {
		t.Fatalf("ksk-zsk policy should not render a CSK line:\n%s", out)
	}
}

// TestDescribeZone_CSK: a csk-mode policy renders a single CSK algorithm/lifetime
// line (from Algorithm / CSKLifetime), not KSK/ZSK.
func TestDescribeZone_CSK(t *testing.T) {
	zconf := tdns.ZoneConf{
		Name:                  "csk.example.",
		EffectiveDnssecPolicy: "csk-pol",
		PolicyDetail: &tdns.DnssecPolicyView{
			Name:        "csk-pol",
			Mode:        tdns.DnssecPolicyModeCSK,
			Algorithm:   15, // ED25519
			CSKLifetime: 5184000,
		},
	}
	out := DescribeZone(zconf)
	if !strings.Contains(out, "CSK algorithm: ED25519") {
		t.Fatalf("csk policy should render CSK algorithm name:\n%s", out)
	}
	if strings.Contains(out, "KSK algorithm") || strings.Contains(out, "ZSK algorithm") {
		t.Fatalf("csk policy should not render KSK/ZSK lines:\n%s", out)
	}
}

// TestDescribeZone_Unsigned: no bound policy and no applied record degrade to
// clear "(not recorded)" / "not signed" lines rather than blanks.
func TestDescribeZone_Unsigned(t *testing.T) {
	out := DescribeZone(tdns.ZoneConf{Name: "plain.example.", Type: "primary"})
	if !strings.Contains(out, "Applied policy: (not recorded)") {
		t.Fatalf("unsigned zone should render (not recorded):\n%s", out)
	}
	if !strings.Contains(out, "DNSSEC detail: not signed") {
		t.Fatalf("unsigned zone should render not signed:\n%s", out)
	}
}

// TestDescribeZone_PolicyUnavailable: a zone bound to a policy the server could
// not resolve (PolicyDetail nil but a policy name is bound) renders a clear
// "policy unavailable" line naming the policy.
func TestDescribeZone_PolicyUnavailable(t *testing.T) {
	out := DescribeZone(tdns.ZoneConf{
		Name:                  "ghost.example.",
		EffectiveDnssecPolicy: "ghost-pol",
	})
	if !strings.Contains(out, "DNSSEC detail: policy unavailable (ghost-pol)") {
		t.Fatalf("bound-but-unresolvable policy should render policy unavailable:\n%s", out)
	}
}
