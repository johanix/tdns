package tdns

import "testing"

// TestGetSOANeverReturnsNilNil is the regression test for the RefreshEngine
// nil-pointer crash (found 2026-07-13 via reload-zones racing a refresh):
// GetSOA returned (nil, nil) when the apex owner was transiently missing, and
// RefreshEngine read soa.Refresh in its err==nil branch → nil deref → the
// process crashed. GetSOA must surface a missing apex as an error, never as a
// nil SOA with no error.
func TestGetSOANeverReturnsNilNil(t *testing.T) {
	// A ready primary MapZone with no published snapshot and no apex owner —
	// exactly the transient state a concurrent reload can expose.
	zd := &ZoneData{
		ZoneName:  "empty.example.",
		ZoneType:  Primary,
		ZoneStore: MapZone,
		Ready:     true,
	}

	soa, err := zd.GetSOA()
	if err == nil {
		t.Fatalf("GetSOA must return an error when the apex owner is missing (got soa=%v, err=nil)", soa)
	}
	if soa != nil {
		t.Fatalf("GetSOA must return a nil SOA alongside its error, got %v", soa)
	}
}
