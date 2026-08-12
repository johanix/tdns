package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// TestClassifyPolicyChange_AppliedVsIntentRetarget replaces the old
// applyReloadedPolicyLocked guard tests. Classification is always applied
// (DB) vs intent — never the in-memory binding (blocking ①).
func TestClassifyPolicyChange_AppliedVsIntentRetarget(t *testing.T) {
	applied := &DnssecPolicy{
		Name:         "pq-sqisign",
		Mode:         DnssecPolicyModeKSKZSK,
		Algorithm:    dns.ED25519,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ECDSAP256SHA256,
	}

	tests := []struct {
		name       string
		intentPol  *DnssecPolicy
		intentName string
		want       PolicyChangeClass
	}{
		{
			name: "ksk-algorithm-change-incompatible",
			intentPol: &DnssecPolicy{
				Name:         "pq-mldsa",
				Mode:         DnssecPolicyModeKSKZSK,
				Algorithm:    dns.RSASHA256,
				KSKAlgorithm: dns.RSASHA256,
				ZSKAlgorithm: dns.ECDSAP256SHA256,
			},
			intentName: "pq-mldsa",
			want:       PolicyChangeIncompatibleAlg,
		},
		{
			name: "zsk-algorithm-change-incompatible",
			intentPol: &DnssecPolicy{
				Name:         "pq-mldsa",
				Mode:         DnssecPolicyModeKSKZSK,
				Algorithm:    dns.ED25519,
				KSKAlgorithm: dns.ED25519,
				ZSKAlgorithm: dns.ED25519,
			},
			intentName: "pq-mldsa",
			want:       PolicyChangeIncompatibleAlg,
		},
		{
			name: "compatible-rename-same-algorithms",
			intentPol: &DnssecPolicy{
				Name:         "pq-sqisign-v2",
				Mode:         DnssecPolicyModeKSKZSK,
				Algorithm:    dns.ED25519,
				KSKAlgorithm: dns.ED25519,
				ZSKAlgorithm: dns.ECDSAP256SHA256,
				Rollover:     RolloverPolicy{Method: RolloverMethodMultiDS},
			},
			intentName: "pq-sqisign-v2",
			want:       PolicyChangeCompatibleName,
		},
		{
			name: "identical-none",
			intentPol: &DnssecPolicy{
				Name:         "pq-sqisign",
				Mode:         DnssecPolicyModeKSKZSK,
				Algorithm:    dns.ED25519,
				KSKAlgorithm: dns.ED25519,
				ZSKAlgorithm: dns.ECDSAP256SHA256,
			},
			intentName: "pq-sqisign",
			want:       PolicyChangeNone,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyPolicyChange(applied, applied.Name, tc.intentPol, tc.intentName)
			if got != tc.want {
				t.Fatalf("classify: got %s, want %s", got, tc.want)
			}
		})
	}
}

// TestClassifyPolicyChange_RestartShape is the ① regression in guard-test form:
// on restart the in-memory binding equals intent, but DB applied differs — the
// classifier must still see the change when given applied vs intent.
func TestClassifyPolicyChange_RestartShape(t *testing.T) {
	applied := &DnssecPolicy{
		Name:         "polA",
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
	}
	intent := &DnssecPolicy{
		Name:         "polB",
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
	}
	// Restart trap: binding == intent.
	binding := intent
	if got := classifyPolicyChange(binding, "polB", intent, "polB"); got != PolicyChangeNone {
		t.Fatalf("binding-vs-intent hide: got %s, want none", got)
	}
	if got := classifyPolicyChange(applied, "polA", intent, "polB"); got != PolicyChangeCompatibleName {
		t.Fatalf("applied-vs-intent: got %s, want compatible-name", got)
	}
}

// TestRefuseIncompatiblePolicyChangeRebindsApplied asserts the config-path
// refuse helper keeps the zone on appliedPol (not intent).
func TestRefuseIncompatiblePolicyChangeRebindsApplied(t *testing.T) {
	applied := &DnssecPolicy{
		Name:         "polA",
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
	}
	intent := &DnssecPolicy{
		Name:         "polB",
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.RSASHA256,
		ZSKAlgorithm: dns.ED25519,
	}
	zd := &ZoneData{
		ZoneName:         "example.",
		DnssecPolicy:     intent, // wrongly bound to intent (restart trap shape)
		DnssecPolicyName: "polB",
	}
	refuseIncompatiblePolicyChange(zd, "polB", "polA", applied)
	if zd.DnssecPolicy != applied || zd.DnssecPolicyName != "polA" {
		t.Fatalf("refuse must rebind to applied: name=%q", zd.DnssecPolicyName)
	}
}
