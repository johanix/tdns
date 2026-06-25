package tdns

import "testing"

// TestZoneProvisioning verifies the B3 display derivation: error takes
// precedence over the positive lifecycle, otherwise the ZoneStatus string.
func TestZoneProvisioning(t *testing.T) {
	zd := &ZoneData{ZoneName: "p.example."}

	zd.SetStatus(ZoneStatusPending)
	if got := zoneProvisioning(zd); got != "pending" {
		t.Errorf("pending: got %q", got)
	}
	zd.SetStatus(ZoneStatusLoading)
	if got := zoneProvisioning(zd); got != "loading" {
		t.Errorf("loading: got %q", got)
	}
	zd.SetStatus(ZoneStatusReady)
	if got := zoneProvisioning(zd); got != "ready" {
		t.Errorf("ready: got %q", got)
	}

	// Error wins over a ready status.
	zd.SetError(RefreshError, "boom")
	if got := zoneProvisioning(zd); got != "error" {
		t.Errorf("ready+error should derive error, got %q", got)
	}
	zd.ClearError(RefreshError)
	if got := zoneProvisioning(zd); got != "ready" {
		t.Errorf("after clear should revert to ready, got %q", got)
	}
}

// TestZoneOptionsFromStrings verifies the API option-name conversion: known
// names map, unknown names are ignored, empty input yields nil.
func TestZoneOptionsFromStrings(t *testing.T) {
	if zoneOptionsFromStrings(nil) != nil {
		t.Error("empty input should yield nil")
	}
	opts := zoneOptionsFromStrings([]string{"frozen", "not-a-real-option", "allow-updates"})
	if !opts[OptFrozen] {
		t.Error("expected OptFrozen set")
	}
	if !opts[OptAllowUpdates] {
		t.Error("expected OptAllowUpdates set")
	}
	if len(opts) != 2 {
		t.Errorf("unknown option should be ignored; got %d options", len(opts))
	}
}
