package tdns

import "testing"

// TestZoneStatus_SetGet verifies the minimal B6 status API: SetStatus persists
// and GetStatus reads it back, independent of the error registry. The
// Provisioning derivation (error precedence) lives in the API handler (B2/B3);
// here we assert the orthogonality the derivation relies on — a zone can be
// ZoneStatusReady AND carry a RefreshError at the same time, and clearing the
// error leaves the status untouched.
func TestZoneStatus_SetGet(t *testing.T) {
	zd := &ZoneData{ZoneName: "status.example."}

	if got := zd.GetStatus(); got != ZoneStatusUnknown {
		t.Errorf("zero-value status = %v, want ZoneStatusUnknown", got)
	}

	zd.SetStatus(ZoneStatusLoading)
	if got := zd.GetStatus(); got != ZoneStatusLoading {
		t.Errorf("after SetStatus(Loading), GetStatus = %v", got)
	}

	zd.SetStatus(ZoneStatusReady)
	if got := zd.GetStatus(); got != ZoneStatusReady {
		t.Errorf("after SetStatus(Ready), GetStatus = %v", got)
	}

	// Orthogonality: a RefreshError coexists with ZoneStatusReady. Status is
	// not touched by the error registry, and vice versa.
	zd.SetError(RefreshError, "upstream timeout")
	if got := zd.GetStatus(); got != ZoneStatusReady {
		t.Errorf("SetError changed status: got %v, want ZoneStatusReady", got)
	}
	if !zd.Error {
		t.Errorf("expected zd.Error true after SetError")
	}

	// The Provisioning derivation used by the API: error wins over status.
	if pp := provisioningString(zd); pp != "error" {
		t.Errorf("Ready + RefreshError should derive Provisioning=error, got %q", pp)
	}

	zd.ClearError(RefreshError)
	if got := zd.GetStatus(); got != ZoneStatusReady {
		t.Errorf("ClearError changed status: got %v, want ZoneStatusReady", got)
	}
	if pp := provisioningString(zd); pp != "ready" {
		t.Errorf("after clearing error, Provisioning should be ready, got %q", pp)
	}
}

// provisioningString mirrors the B2/B3 derivation so the orthogonality contract
// is locked down now, before the API handler consumes it.
func provisioningString(zd *ZoneData) string {
	if zd.Error {
		return "error"
	}
	return ZoneStatusToString[zd.GetStatus()]
}
