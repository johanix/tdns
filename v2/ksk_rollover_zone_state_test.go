package tdns

import "testing"

func TestLoadRolloverZoneRowNilKeyDB(t *testing.T) {
	if _, err := LoadRolloverZoneRow(nil, "example."); err == nil {
		t.Fatal("expected an error for a nil KeyDB, got nil")
	}
	if _, err := LoadRolloverZoneRow(&KeyDB{}, "example."); err == nil {
		t.Fatal("expected an error for a nil DB handle, got nil")
	}
}
