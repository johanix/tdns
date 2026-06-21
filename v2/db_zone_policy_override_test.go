package tdns

import "testing"

func TestZonePolicyOverride(t *testing.T) {
	kdb := newTestKeyDB(t)

	// No override yet: effective = config base, not overridden.
	eff, overridden, err := EffectiveDnssecPolicyName(kdb, "example.", "default")
	if err != nil {
		t.Fatalf("EffectiveDnssecPolicyName: %v", err)
	}
	if eff != "default" || overridden {
		t.Fatalf("no override: got (%q, %v), want (\"default\", false)", eff, overridden)
	}
	if _, ok, err := GetZonePolicyOverride(kdb, "example."); err != nil || ok {
		t.Fatalf("GetZonePolicyOverride should report no override (ok=%v err=%v)", ok, err)
	}

	// Set an override: effective = override, marked overridden. Zone name is
	// FQDN-normalized, so a non-FQDN set must be found by the FQDN lookup.
	if err := SetZonePolicyOverride(kdb, "example", "pq-mayo"); err != nil {
		t.Fatalf("SetZonePolicyOverride: %v", err)
	}
	eff, overridden, err = EffectiveDnssecPolicyName(kdb, "example.", "default")
	if err != nil {
		t.Fatalf("EffectiveDnssecPolicyName: %v", err)
	}
	if eff != "pq-mayo" || !overridden {
		t.Fatalf("with override: got (%q, %v), want (\"pq-mayo\", true)", eff, overridden)
	}

	// Replace the override (upsert).
	if err := SetZonePolicyOverride(kdb, "example.", "fastroll"); err != nil {
		t.Fatalf("SetZonePolicyOverride replace: %v", err)
	}
	if name, ok, err := GetZonePolicyOverride(kdb, "example."); err != nil || !ok || name != "fastroll" {
		t.Fatalf("after replace: got (%q, %v, err=%v), want (\"fastroll\", true, nil)", name, ok, err)
	}

	// Clear: back to config base.
	if err := ClearZonePolicyOverride(kdb, "example."); err != nil {
		t.Fatalf("ClearZonePolicyOverride: %v", err)
	}
	eff, overridden, err = EffectiveDnssecPolicyName(kdb, "example.", "default")
	if err != nil || eff != "default" || overridden {
		t.Fatalf("after clear: got (%q, %v, err=%v), want (\"default\", false, nil)", eff, overridden, err)
	}
	// Clearing a non-existent override is not an error.
	if err := ClearZonePolicyOverride(kdb, "nosuch."); err != nil {
		t.Fatalf("ClearZonePolicyOverride (absent): %v", err)
	}
}
