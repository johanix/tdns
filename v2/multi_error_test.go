package tdns

import (
	"testing"
)

// TestMultiErrorCoexistence verifies that two error categories can
// coexist on a single ZoneData without one displacing the other.
// Critical for W2/W4 sharing the auto-rollover-gating surface.
func TestMultiErrorCoexistence(t *testing.T) {
	// Bypass Zones.Set by constructing a bare ZoneData and exercising
	// the methods that don't require Zones registration. SetError /
	// ClearError call Zones.Set, which is safe on an unregistered
	// zone (no-op against a missing key in the concurrent map).
	zd := &ZoneData{ZoneName: "test.example."}

	zd.SetError(RolloverPolicyViolation, "E10 violation")
	if !zd.HasError(RolloverPolicyViolation) {
		t.Fatal("expected RolloverPolicyViolation present after SetError")
	}
	if zd.HasError(RolloverParentBlocker) {
		t.Fatal("ParentBlocker should not be set yet")
	}

	zd.SetError(RolloverParentBlocker, "no DSYNC scheme")
	if !zd.HasError(RolloverPolicyViolation) {
		t.Fatal("RolloverPolicyViolation must remain set after second SetError")
	}
	if !zd.HasError(RolloverParentBlocker) {
		t.Fatal("RolloverParentBlocker not set")
	}

	if got := len(zd.ErrorList()); got != 2 {
		t.Fatalf("ErrorList: want 2, got %d", got)
	}

	zd.ClearError(RolloverParentBlocker)
	if zd.HasError(RolloverParentBlocker) {
		t.Fatal("ParentBlocker should be cleared")
	}
	if !zd.HasError(RolloverPolicyViolation) {
		t.Fatal("RolloverPolicyViolation must survive single-category clear")
	}

	zd.ClearError(NoError)
	if zd.HasError(RolloverPolicyViolation) {
		t.Fatal("ClearError(NoError) should have cleared everything")
	}
	if zd.Error {
		t.Fatal("derived Error must be false after clear-all")
	}
}

// TestDerivedErrorFieldsBackCompat checks that the legacy
// zd.Error/ErrorType/ErrorMsg readers see something coherent across
// state changes.
func TestDerivedErrorFieldsBackCompat(t *testing.T) {
	zd := &ZoneData{ZoneName: "test.example."}

	if zd.Error {
		t.Fatal("default state must be clean")
	}

	zd.SetError(ConfigError, "bad config")
	if !zd.Error || zd.ErrorType != ConfigError || zd.ErrorMsg != "bad config" {
		t.Errorf("expected derived fields to reflect ConfigError; got %v / %v / %q",
			zd.Error, zd.ErrorType, zd.ErrorMsg)
	}

	// ConfigError outranks RolloverPolicyViolation in errorTypeReportOrder.
	zd.SetError(RolloverPolicyViolation, "E5 violation")
	if zd.ErrorType != ConfigError {
		t.Errorf("expected ConfigError to dominate, got %v", zd.ErrorType)
	}

	zd.ClearError(ConfigError)
	if zd.ErrorType != RolloverPolicyViolation {
		t.Errorf("expected RolloverPolicyViolation after clearing ConfigError, got %v", zd.ErrorType)
	}
	if zd.ErrorMsg != "E5 violation" {
		t.Errorf("expected derived ErrorMsg to track current type, got %q", zd.ErrorMsg)
	}
}

// TestErrorListOrder confirms ErrorList returns categories in
// errorTypeReportOrder so consumers (CLI, status JSON) get a stable
// order.
func TestErrorListOrder(t *testing.T) {
	zd := &ZoneData{ZoneName: "test.example."}
	zd.SetError(RolloverParentBlocker, "B")
	zd.SetError(ConfigError, "C")
	zd.SetError(RolloverPolicyViolation, "P")

	got := zd.ErrorList()
	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(got))
	}
	if got[0].Type != ConfigError {
		t.Errorf("first entry should be ConfigError, got %v", got[0].Type)
	}
	if got[1].Type != RolloverPolicyViolation {
		t.Errorf("second entry should be RolloverPolicyViolation, got %v", got[1].Type)
	}
	if got[2].Type != RolloverParentBlocker {
		t.Errorf("third entry should be RolloverParentBlocker, got %v", got[2].Type)
	}
}
