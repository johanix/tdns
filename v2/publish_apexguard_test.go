package tdns

import (
	"testing"

	"github.com/miekg/dns"
)

// TestPublishRefusesApexlessSnapshot is the regression test for the atomic-swap
// invariant break behind the RefreshEngine crash: publishWorkingSetLocked stored
// whatever the working set held, so an apex-less working set (e.g. an empty
// rebuild during reload) overwrote a good snapshot with one having nil Apex/SOA,
// leaving a Ready zone with no servable SOA. The guard must refuse the swap and
// keep the current snapshot.
func TestPublishRefusesApexlessSnapshot(t *testing.T) {
	zd := &ZoneData{ZoneName: "keep.example."}

	// A valid current snapshot with an SOA — what readers are being served.
	good := &zoneSnapshot{Serial: 42, SOA: &dns.SOA{Serial: 42}}
	zd.snapshot.Store(good)

	// Registered with a matching generation so zoneStillLive() passes and we
	// reach the apex guard.
	Zones.Set(zd.ZoneName, zd)
	defer Zones.Remove(zd.ZoneName)

	// A non-nil but apex-less working set: the poison the guard must reject.
	zd.workingSet = map[string]*OwnerData{}

	zd.mu.Lock()
	zd.publishWorkingSetLocked(zd.generation.Load(), false)
	zd.mu.Unlock()

	got := zd.snapshot.Load()
	if got != good {
		t.Fatalf("apex-less publish overwrote the served snapshot (got %+v, want the serial-42 snapshot)", got)
	}
	if got == nil || got.SOA == nil {
		t.Fatal("served snapshot lost its SOA")
	}
	if zd.workingSet != nil {
		t.Errorf("working set should be cleared after a refused publish, got %v", zd.workingSet)
	}
}
