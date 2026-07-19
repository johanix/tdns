/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import "testing"

// withLiveConfig swaps in a runtime-config snapshot for the duration of a test
// and restores the previous one on cleanup.
func withLiveConfig(t *testing.T, rc *RuntimeConfig) {
	t.Helper()
	prev := liveConfig.Load()
	liveConfig.Store(rc)
	t.Cleanup(func() { liveConfig.Store(prev) })
}

// TestPopulateZoneDescDetail covers the three `zone desc` detail cases: a signed
// zone with an applied record and a resolvable bound policy; an unsigned zone
// (no bound policy → no PolicyDetail, no applied record); and a zone bound to a
// policy name that is not present in the live config snapshot (→ no PolicyDetail
// but the applied record is still surfaced).
func TestPopulateZoneDescDetail(t *testing.T) {
	kdb := newTestKeyDB(t)

	withLiveConfig(t, &RuntimeConfig{
		DnssecPolicies: map[string]DnssecPolicy{
			"pol-a": {
				Name:         "pol-a",
				Mode:         DnssecPolicyModeKSKZSK,
				KSKAlgorithm: 13, // ECDSAP256SHA256
				ZSKAlgorithm: 13,
				KSK:          KeyLifetime{Lifetime: 31536000}, // 365d
				ZSK:          KeyLifetime{Lifetime: 2592000},  // 30d
				SigValidity:  PolicySigValidity{Default: 1209600, DNSKEY: 1209600, DS: 86400},
			},
		},
	})

	// --- signed zone with applied record + resolvable policy ---
	if err := SetZoneAppliedPolicy(kdb, "signed.example.", "pol-a", "command"); err != nil {
		t.Fatalf("SetZoneAppliedPolicy: %v", err)
	}
	zconf := ZoneConf{Name: "signed.example."}
	populateZoneDescDetail(&zconf, &ZoneData{DnssecPolicyName: "pol-a"}, "signed.example.", kdb)

	if zconf.AppliedPolicy != "pol-a" || zconf.AppliedSource != "command" || zconf.AppliedAt == "" {
		t.Fatalf("applied fields: got (%q, %q, at=%q), want (\"pol-a\", \"command\", non-empty)",
			zconf.AppliedPolicy, zconf.AppliedSource, zconf.AppliedAt)
	}
	if zconf.PolicyDetail == nil {
		t.Fatalf("PolicyDetail should be populated for a resolvable bound policy")
	}
	pd := zconf.PolicyDetail
	if pd.Name != "pol-a" || pd.Mode != DnssecPolicyModeKSKZSK || pd.KSKAlgorithm != 13 || pd.ZSKAlgorithm != 13 {
		t.Fatalf("PolicyDetail alg/mode: got %+v", pd)
	}
	if pd.KSKLifetime != 31536000 || pd.ZSKLifetime != 2592000 || pd.SigValidityDS != 86400 {
		t.Fatalf("PolicyDetail lifetimes/sigvalidity: got %+v", pd)
	}

	// --- unsigned zone: no bound policy, no applied record ---
	zUnsigned := ZoneConf{Name: "plain.example."}
	populateZoneDescDetail(&zUnsigned, &ZoneData{DnssecPolicyName: ""}, "plain.example.", kdb)
	if zUnsigned.PolicyDetail != nil {
		t.Fatalf("unsigned zone must have nil PolicyDetail, got %+v", zUnsigned.PolicyDetail)
	}
	if zUnsigned.AppliedPolicy != "" {
		t.Fatalf("unsigned zone without applied record must have empty AppliedPolicy, got %q", zUnsigned.AppliedPolicy)
	}

	// --- bound policy name not in the live snapshot: applied record still shown,
	// PolicyDetail nil (renderer prints "policy unavailable") ---
	if err := SetZoneAppliedPolicy(kdb, "ghost.example.", "ghost-pol", "config"); err != nil {
		t.Fatalf("SetZoneAppliedPolicy: %v", err)
	}
	zGhost := ZoneConf{Name: "ghost.example.", EffectiveDnssecPolicy: "ghost-pol"}
	populateZoneDescDetail(&zGhost, &ZoneData{DnssecPolicyName: "ghost-pol"}, "ghost.example.", kdb)
	if zGhost.PolicyDetail != nil {
		t.Fatalf("unresolvable bound policy must have nil PolicyDetail, got %+v", zGhost.PolicyDetail)
	}
	if zGhost.AppliedPolicy != "ghost-pol" || zGhost.AppliedSource != "config" {
		t.Fatalf("applied record must still be surfaced: got (%q, %q)", zGhost.AppliedPolicy, zGhost.AppliedSource)
	}
}
