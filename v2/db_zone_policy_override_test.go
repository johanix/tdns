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
	if _, ok, _ := GetZonePolicyOverride(kdb, "example."); ok {
		t.Fatal("GetZonePolicyOverride should report no override")
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
	if name, ok, _ := GetZonePolicyOverride(kdb, "example."); !ok || name != "fastroll" {
		t.Fatalf("after replace: got (%q, %v), want (\"fastroll\", true)", name, ok)
	}

	// Clear: back to config base.
	if err := ClearZonePolicyOverride(kdb, "example."); err != nil {
		t.Fatalf("ClearZonePolicyOverride: %v", err)
	}
	eff, overridden, _ = EffectiveDnssecPolicyName(kdb, "example.", "default")
	if eff != "default" || overridden {
		t.Fatalf("after clear: got (%q, %v), want (\"default\", false)", eff, overridden)
	}
	// Clearing a non-existent override is not an error.
	if err := ClearZonePolicyOverride(kdb, "nosuch."); err != nil {
		t.Fatalf("ClearZonePolicyOverride (absent): %v", err)
	}
}
