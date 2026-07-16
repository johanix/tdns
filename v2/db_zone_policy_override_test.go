package tdns

import "testing"

// TestZoneAppliedPolicy exercises the last-applied CRUD and, crucially, that it
// is INDEPENDENT of the CLI `policy` override: a config-only zone gets an
// applied record with no override, and setting one never clobbers the other.
func TestZoneAppliedPolicy(t *testing.T) {
	kdb := newTestKeyDB(t)

	// No applied record yet.
	if _, _, ok, err := GetZoneAppliedPolicy(kdb, "example."); err != nil || ok {
		t.Fatalf("no applied yet: got (ok=%v, err=%v), want (false, nil)", ok, err)
	}

	// Record a config-source applied policy for a zone with NO CLI override
	// (the config-only case). FQDN normalization: set non-FQDN, read FQDN.
	if err := SetZoneAppliedPolicy(kdb, "example", "pq-mayo", "config"); err != nil {
		t.Fatalf("SetZoneAppliedPolicy: %v", err)
	}
	name, source, ok, err := GetZoneAppliedPolicy(kdb, "example.")
	if err != nil || !ok || name != "pq-mayo" || source != "config" {
		t.Fatalf("applied round-trip: got (%q, %q, %v, err=%v), want (\"pq-mayo\", \"config\", true, nil)", name, source, ok, err)
	}
	// applied is NOT an override: effective policy still falls back to config,
	// and there is no override row content.
	if eff, overridden, err := EffectiveDnssecPolicyName(kdb, "example.", "default"); err != nil || eff != "default" || overridden {
		t.Fatalf("applied must not act as override: got (%q, %v, err=%v), want (\"default\", false, nil)", eff, overridden, err)
	}
	if _, ovOK, err := GetZonePolicyOverride(kdb, "example."); err != nil || ovOK {
		t.Fatalf("applied write must not create an override (ovOK=%v err=%v)", ovOK, err)
	}

	// Now add a CLI override on the SAME zone: it must not disturb applied.
	if err := SetZonePolicyOverride(kdb, "example.", "fastroll"); err != nil {
		t.Fatalf("SetZonePolicyOverride: %v", err)
	}
	if name, source, ok, err := GetZoneAppliedPolicy(kdb, "example."); err != nil || !ok || name != "pq-mayo" || source != "config" {
		t.Fatalf("applied after override set: got (%q, %q, %v, err=%v), want (\"pq-mayo\", \"config\", true, nil)", name, source, ok, err)
	}
	// And updating applied must not disturb the override.
	if err := SetZoneAppliedPolicy(kdb, "example.", "fastroll", "command"); err != nil {
		t.Fatalf("SetZoneAppliedPolicy update: %v", err)
	}
	if n, ovOK, err := GetZonePolicyOverride(kdb, "example."); err != nil || !ovOK || n != "fastroll" {
		t.Fatalf("override after applied update: got (%q, %v, err=%v), want (\"fastroll\", true, nil)", n, ovOK, err)
	}
	if name, source, _, _ := GetZoneAppliedPolicy(kdb, "example."); name != "fastroll" || source != "command" {
		t.Fatalf("applied after update: got (%q, %q), want (\"fastroll\", \"command\")", name, source)
	}

	// Clear applied: record gone, override retained.
	if err := ClearZoneAppliedPolicy(kdb, "example."); err != nil {
		t.Fatalf("ClearZoneAppliedPolicy: %v", err)
	}
	if _, _, ok, err := GetZoneAppliedPolicy(kdb, "example."); err != nil || ok {
		t.Fatalf("after clear applied: got (ok=%v, err=%v), want (false, nil)", ok, err)
	}
	if n, ovOK, err := GetZonePolicyOverride(kdb, "example."); err != nil || !ovOK || n != "fastroll" {
		t.Fatalf("override survives applied clear: got (%q, %v, err=%v), want (\"fastroll\", true, nil)", n, ovOK, err)
	}
	// Clearing applied on a zone with no row is not an error.
	if err := ClearZoneAppliedPolicy(kdb, "nosuch."); err != nil {
		t.Fatalf("ClearZoneAppliedPolicy (absent): %v", err)
	}

	// Validation: empty policy and bad source are rejected.
	if err := SetZoneAppliedPolicy(kdb, "example.", "", "config"); err == nil {
		t.Fatalf("SetZoneAppliedPolicy with empty policy should fail")
	}
	if err := SetZoneAppliedPolicy(kdb, "example.", "pq-mayo", "bogus"); err == nil {
		t.Fatalf("SetZoneAppliedPolicy with invalid source should fail")
	}
}

// TestZoneAppliedPolicyDataMigration verifies the dbMigrateData backfill that
// seeds applied_* from a pre-existing CLI override row (which was written by
// set-policy AFTER a successful sign), and that the backfill is idempotent.
func TestZoneAppliedPolicyDataMigration(t *testing.T) {
	kdb := newTestKeyDB(t)

	// Simulate a pre-upgrade CLI override row: policy set, applied_* still unset.
	if err := SetZonePolicyOverride(kdb, "legacy.", "pq-mayo"); err != nil {
		t.Fatalf("SetZonePolicyOverride: %v", err)
	}
	if _, _, ok, err := GetZoneAppliedPolicy(kdb, "legacy."); err != nil || ok {
		t.Fatalf("pre-migration applied should be absent (ok=%v err=%v)", ok, err)
	}

	// Run the data migration: applied_* seeded from the override, source command.
	dbMigrateData(kdb.DB)
	name, source, ok, err := GetZoneAppliedPolicy(kdb, "legacy.")
	if err != nil || !ok || name != "pq-mayo" || source != "command" {
		t.Fatalf("post-migration applied: got (%q, %q, %v, err=%v), want (\"pq-mayo\", \"command\", true, nil)", name, source, ok, err)
	}

	// Idempotent: a second run must not change or duplicate anything, and must
	// not overwrite a later applied value that diverged from the override.
	if err := SetZoneAppliedPolicy(kdb, "legacy.", "fastroll", "command"); err != nil {
		t.Fatalf("SetZoneAppliedPolicy diverge: %v", err)
	}
	dbMigrateData(kdb.DB)
	if name, _, _, _ := GetZoneAppliedPolicy(kdb, "legacy."); name != "fastroll" {
		t.Fatalf("migration must not clobber a set applied_policy: got %q, want \"fastroll\"", name)
	}
}

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

// TestClearOverridePreservesApplied is the applied⊥override independence
// regression: ClearZonePolicyOverride must clear only the override (intent) and
// leave the last-applied record intact — it UPDATEs policy=” rather than
// DELETEing the whole row, which previously wiped applied_* too.
func TestClearOverridePreservesApplied(t *testing.T) {
	kdb := newTestKeyDB(t)

	// Zone carries BOTH an override and an applied record.
	if err := SetZonePolicyOverride(kdb, "example.", "override-pol"); err != nil {
		t.Fatalf("SetZonePolicyOverride: %v", err)
	}
	if err := SetZoneAppliedPolicy(kdb, "example.", "applied-pol", "config"); err != nil {
		t.Fatalf("SetZoneAppliedPolicy: %v", err)
	}

	if err := ClearZonePolicyOverride(kdb, "example."); err != nil {
		t.Fatalf("ClearZonePolicyOverride: %v", err)
	}

	// Override gone...
	if _, ok, err := GetZonePolicyOverride(kdb, "example."); err != nil || ok {
		t.Fatalf("override should be cleared after ClearZonePolicyOverride (ok=%v err=%v)", ok, err)
	}
	// ...applied record preserved (the independence guarantee).
	name, source, ok, err := GetZoneAppliedPolicy(kdb, "example.")
	if err != nil || !ok || name != "applied-pol" || source != "config" {
		t.Fatalf("applied must survive an override clear: got (%q,%q,%v,err=%v), want (applied-pol,config,true,nil)", name, source, ok, err)
	}
}
