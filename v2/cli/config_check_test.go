/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

func algSet(algs ...string) map[string]bool {
	m := map[string]bool{}
	for _, a := range algs {
		m[a] = true
	}
	return m
}

// TestMissingRoleAlgs exercises the pure policy-algorithm vs active-key dry-run
// that predicts a would-break-on-reload algorithm change.
func TestMissingRoleAlgs(t *testing.T) {
	const ksz = tdns.DnssecPolicyModeKSKZSK
	const csk = tdns.DnssecPolicyModeCSK

	cases := []struct {
		name     string
		want     wantAlgs
		active   activeKeyAlgs
		wantMiss []string // roles expected to miss (order-independent)
	}{
		{
			name:   "split: matching algs -> no finding",
			want:   wantAlgs{mode: ksz, ksk: "ed25519", zsk: "ecdsap256sha256"},
			active: activeKeyAlgs{ksk: algSet("ed25519"), zsk: algSet("ecdsap256sha256")},
		},
		{
			name:     "split: KSK algorithm changed -> one KSK WARN",
			want:     wantAlgs{mode: ksz, ksk: "falcon512", zsk: "ed25519"},
			active:   activeKeyAlgs{ksk: algSet("ed25519"), zsk: algSet("ed25519")},
			wantMiss: []string{"KSK"},
		},
		{
			name:     "split: ZSK algorithm changed -> one ZSK WARN",
			want:     wantAlgs{mode: ksz, ksk: "ed25519", zsk: "falcon512"},
			active:   activeKeyAlgs{ksk: algSet("ed25519"), zsk: algSet("ed25519")},
			wantMiss: []string{"ZSK"},
		},
		{
			name:   "split: mid-rollover, both old+new KSK active -> no finding",
			want:   wantAlgs{mode: ksz, ksk: "falcon512", zsk: "ed25519"},
			active: activeKeyAlgs{ksk: algSet("ed25519", "falcon512"), zsk: algSet("ed25519")},
		},
		{
			name:   "split: zero active keys (fresh zone) -> no finding",
			want:   wantAlgs{mode: ksz, ksk: "ed25519", zsk: "ecdsap256sha256"},
			active: activeKeyAlgs{ksk: algSet(), zsk: algSet()},
		},
		{
			name:   "csk: matching alg -> no finding",
			want:   wantAlgs{mode: csk, ksk: "ed25519"},
			active: activeKeyAlgs{ksk: algSet("ed25519"), zsk: algSet()},
		},
		{
			name:     "csk: algorithm changed -> one CSK WARN",
			want:     wantAlgs{mode: csk, ksk: "falcon512"},
			active:   activeKeyAlgs{ksk: algSet("ed25519"), zsk: algSet()},
			wantMiss: []string{"CSK"},
		},
		{
			name:     "split: both roles changed -> two WARNs",
			want:     wantAlgs{mode: ksz, ksk: "falcon512", zsk: "falcon512"},
			active:   activeKeyAlgs{ksk: algSet("ed25519"), zsk: algSet("ecdsap256sha256")},
			wantMiss: []string{"KSK", "ZSK"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			miss := missingRoleAlgs(tc.want, tc.active)
			gotRoles := map[string]bool{}
			for _, m := range miss {
				gotRoles[m.role] = true
			}
			if len(miss) != len(tc.wantMiss) {
				t.Fatalf("got %d misses %v, want %d %v", len(miss), gotRoles, len(tc.wantMiss), tc.wantMiss)
			}
			for _, r := range tc.wantMiss {
				if !gotRoles[r] {
					t.Errorf("expected a miss for role %s, got %v", r, gotRoles)
				}
			}
		})
	}
}

// TestCheckPolicyAlgVsActiveKeys_OfflineInfoSkip verifies the offline path emits
// a single info (no API calls, no FAIL/WARN) when there is a signed zone.
func TestCheckPolicyAlgVsActiveKeys_OfflineInfoSkip(t *testing.T) {
	cfg := &tdns.Config{
		Zones: []tdns.ZoneConf{
			{Name: "signed.example.", OptionsStrs: []string{"online-signing"}, DnssecPolicy: "default"},
		},
	}
	rep := newCCReport()
	// online=false; v is unused on the offline path.
	checkPolicyAlgVsActiveKeys(cfg, nil, rep, false, "auth")

	res := rep.byGroup["Policy vs active keys"]
	if len(res) != 1 {
		t.Fatalf("expected 1 result in offline path, got %d: %+v", len(res), res)
	}
	if res[0].level != ccINFO {
		t.Errorf("expected an INFO result, got level %v (%q)", res[0].level, res[0].msg)
	}
}

// TestCheckPolicyAlgVsActiveKeys_NoSignedZones verifies that a config with no
// signed zones produces no findings at all (not even the offline info).
func TestCheckPolicyAlgVsActiveKeys_NoSignedZones(t *testing.T) {
	cfg := &tdns.Config{
		Zones: []tdns.ZoneConf{
			{Name: "plain.example.", Type: "primary"}, // no signing option
		},
	}
	rep := newCCReport()
	checkPolicyAlgVsActiveKeys(cfg, nil, rep, false, "auth")
	if len(rep.byGroup["Policy vs active keys"]) != 0 {
		t.Errorf("expected no findings for a config with no signed zones, got %+v", rep.byGroup["Policy vs active keys"])
	}
}
