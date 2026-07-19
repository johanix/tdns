/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import "testing"

// TestGetZoneAppliedPolicyDetail exercises the read-only accessor added for the
// `zone desc` CLI: it returns the applied policy name + source AND the applied_at
// timestamp, and reports ok=false with empty strings when there is no record.
func TestGetZoneAppliedPolicyDetail(t *testing.T) {
	kdb := newTestKeyDB(t)

	// No record yet: ok=false, everything empty.
	if name, source, at, ok, err := GetZoneAppliedPolicyDetail(kdb, "example."); err != nil || ok || name != "" || source != "" || at != "" {
		t.Fatalf("no record: got (%q, %q, %q, ok=%v, err=%v), want (\"\",\"\",\"\", false, nil)", name, source, at, ok, err)
	}

	// Record one (FQDN-normalized): name+source round-trip and applied_at is set.
	if err := SetZoneAppliedPolicy(kdb, "example", "pol-a", "command"); err != nil {
		t.Fatalf("SetZoneAppliedPolicy: %v", err)
	}
	name, source, at, ok, err := GetZoneAppliedPolicyDetail(kdb, "example.")
	if err != nil || !ok || name != "pol-a" || source != "command" {
		t.Fatalf("round-trip: got (%q, %q, ok=%v, err=%v), want (\"pol-a\", \"command\", true, nil)", name, source, ok, err)
	}
	if at == "" {
		t.Fatalf("applied_at should be set by SetZoneAppliedPolicy, got empty")
	}

	// Clearing the applied record makes the accessor report absence again even
	// though the (override) row still exists.
	if err := SetZonePolicyOverride(kdb, "example.", "override-pol"); err != nil {
		t.Fatalf("SetZonePolicyOverride: %v", err)
	}
	if err := ClearZoneAppliedPolicy(kdb, "example."); err != nil {
		t.Fatalf("ClearZoneAppliedPolicy: %v", err)
	}
	if _, _, at, ok, err := GetZoneAppliedPolicyDetail(kdb, "example."); err != nil || ok || at != "" {
		t.Fatalf("after clear: got (at=%q, ok=%v, err=%v), want (\"\", false, nil)", at, ok, err)
	}

	// Nil keystore is a clean error, not a panic.
	if _, _, _, _, err := GetZoneAppliedPolicyDetail(nil, "example."); err == nil {
		t.Fatalf("nil keystore should error")
	}
}
