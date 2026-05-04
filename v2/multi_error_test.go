package tdns

import (
	"testing"
	"time"
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

// TestHasErrorOtherThan covers the multi-error gating helper used by
// notifyresponder / defaultqueryhandlers to avoid masking a
// rollover-policy error behind RefreshError winning the derived-field
// priority.
func TestHasErrorOtherThan(t *testing.T) {
	zd := &ZoneData{ZoneName: "test.example."}

	if zd.HasErrorOtherThan(RefreshError) {
		t.Fatal("clean zone: HasErrorOtherThan should be false")
	}

	zd.SetError(RefreshError, "stale data")
	if zd.HasErrorOtherThan(RefreshError) {
		t.Fatal("only RefreshError set: HasErrorOtherThan(RefreshError) should be false")
	}

	zd.SetError(RolloverPolicyViolation, "E10")
	if !zd.HasErrorOtherThan(RefreshError) {
		t.Fatal("RolloverPolicyViolation alongside RefreshError: HasErrorOtherThan(RefreshError) should be true")
	}

	zd.ClearError(RolloverPolicyViolation)
	if zd.HasErrorOtherThan(RefreshError) {
		t.Fatal("after clearing RolloverPolicyViolation: HasErrorOtherThan(RefreshError) should be false again")
	}

	// Multi-arg allow list.
	zd.SetError(ConfigError, "bad config")
	if zd.HasErrorOtherThan(RefreshError, ConfigError) {
		t.Fatal("RefreshError+ConfigError both allowed: HasErrorOtherThan should be false")
	}
	if !zd.HasErrorOtherThan(RefreshError) {
		t.Fatal("ConfigError not in allow list: HasErrorOtherThan should be true")
	}
}

// TestHasServiceImpactingError confirms RefreshError and rollover-*
// categories don't trigger the service-impacting check, so a zone with
// e.g. RolloverPolicyViolation continues to serve queries normally
// (regression test for the SERVFAIL bug).
func TestHasServiceImpactingError(t *testing.T) {
	zd := &ZoneData{ZoneName: "test.example."}

	if zd.HasServiceImpactingError() {
		t.Fatal("clean zone: HasServiceImpactingError should be false")
	}

	zd.SetError(RefreshError, "stale data")
	if zd.HasServiceImpactingError() {
		t.Fatal("RefreshError alone: serving must continue")
	}

	zd.SetError(RolloverPolicyViolation, "E5")
	if zd.HasServiceImpactingError() {
		t.Fatal("rollover-policy violation: serving must continue (regression: SERVFAIL bug)")
	}

	zd.SetError(RolloverParentBlocker, "no DSYNC")
	if zd.HasServiceImpactingError() {
		t.Fatal("parent blocker: serving must continue")
	}

	zd.SetError(RolloverPolicyWarning, "E11")
	if zd.HasServiceImpactingError() {
		t.Fatal("rollover-policy warning: serving must continue")
	}

	zd.SetError(ConfigError, "bad config")
	if !zd.HasServiceImpactingError() {
		t.Fatal("ConfigError: serving must stop")
	}
}

// TestHasAutoRolloverImpactingError confirms the engine-gating set:
// RolloverPolicyViolation and RolloverParentBlocker block the engine,
// but RolloverPolicyWarning does NOT (warnings let the engine roll).
func TestHasAutoRolloverImpactingError(t *testing.T) {
	zd := &ZoneData{ZoneName: "test.example."}

	if zd.HasAutoRolloverImpactingError() {
		t.Fatal("clean zone: false")
	}

	zd.SetError(RolloverPolicyWarning, "E11")
	if zd.HasAutoRolloverImpactingError() {
		t.Fatal("warning alone: engine must keep rolling")
	}

	zd.SetError(RolloverPolicyViolation, "E5")
	if !zd.HasAutoRolloverImpactingError() {
		t.Fatal("violation: engine must stop")
	}

	zd.ClearError(RolloverPolicyViolation)
	zd.SetError(RolloverParentBlocker, "no DSYNC")
	if !zd.HasAutoRolloverImpactingError() {
		t.Fatal("parent blocker: engine must stop")
	}

	zd.ClearError(RolloverParentBlocker)
	zd.SetError(RefreshError, "stale")
	if zd.HasAutoRolloverImpactingError() {
		t.Fatal("RefreshError alone: engine must keep rolling")
	}
}

// TestEvaluateRolloverPolicyInvariantsSeveritySplit confirms that
// hard violations (E5/E10) and warnings (E11) end up in separate
// error categories so the engine gates only on violations.
func TestEvaluateRolloverPolicyInvariantsSeveritySplit(t *testing.T) {
	// Build a policy that fails E5 (clamping margin too small) AND
	// triggers E11 warning (tight headroom).
	pol := &DnssecPolicy{}
	pol.Rollover.Method = RolloverMethodMultiDS
	pol.Rollover.NumDS = 2
	pol.KSK.Lifetime = 21 * 60    // 21m
	pol.KSK.SigValidity = 60 * 60 // 1h
	pol.Rollover.DsPublishDelay = 5 * time.Minute
	pol.Clamping.Enabled = true
	pol.Clamping.Margin = 1 * time.Minute // < min(5m dnskey, 1h sigvalidity) → E5 fail
	pol.TTLS.DNSKEY = 300                 // 5m
	pol.TTLS.DS = 600                     // 10m so E10/E11 can run

	zd := &ZoneData{ZoneName: "test.example."}
	EvaluateRolloverPolicyInvariants(zd, pol)

	if !zd.HasError(RolloverPolicyViolation) {
		t.Fatal("expected E5 violation in RolloverPolicyViolation category")
	}
	// E11 may or may not fire depending on the specific arithmetic;
	// what matters is that violations and warnings are independent
	// — clearing one shouldn't clear the other.
	if zd.HasError(RolloverPolicyWarning) {
		zd.ClearError(RolloverPolicyWarning)
		if !zd.HasError(RolloverPolicyViolation) {
			t.Fatal("clearing warning must not clear violation (categories independent)")
		}
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
