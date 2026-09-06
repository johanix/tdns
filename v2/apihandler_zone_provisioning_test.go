package tdns

import (
	"sync"
	"testing"
	"time"
)

// TestZoneProvisioning pins the display derivation: refusing queries -> error;
// nothing to serve and something wrong -> error; otherwise the lifecycle.
//
// This replaces a version asserting that ANY error outranks the lifecycle. It
// passed, but only because it never set Ready -- so every case it exercised
// fell through the "never loaded" clause and the distinction it claimed to
// test was never reached.
func TestZoneProvisioning(t *testing.T) {
	zd := &ZoneData{ZoneName: "p.example."}

	// The lifecycle, with nothing wrong.
	for _, tc := range []struct {
		status ZoneStatus
		want   string
	}{
		{ZoneStatusPending, "pending"},
		{ZoneStatusLoading, "loading"},
		{ZoneStatusReady, "ready"},
	} {
		zd.SetStatus(tc.status)
		if got := zoneProvisioning(zd); got != tc.want {
			t.Errorf("status %s: got %q, want %q", ZoneStatusToString[tc.status], got, tc.want)
		}
	}

	// A zone that holds data and answers for it is serving, however stale its
	// refresh. Reporting it as an error is the over-reporting half of the bug
	// this derivation fixes.
	zd.SetStatus(ZoneStatusReady)
	zd.Ready = true
	zd.SetError(RefreshError, "SOA probe failed")
	if got := zoneProvisioning(zd); got != "ready" {
		t.Errorf("a loaded zone with a stale refresh: got %q, want ready -- it still answers for the data it holds", got)
	}

	// The same error on a zone that never loaded is the under-reporting half:
	// no data, SERVFAIL to every query, and it used to render as healthy.
	zd.Ready = false
	zd.SetStatus(ZoneStatusPending)
	if got := zoneProvisioning(zd); got != "error" {
		t.Errorf("a secondary that never loaded: got %q, want error", got)
	}
	zd.ClearError(RefreshError)

	// A service-impacting error is an error whatever the zone holds: the query
	// path refuses it with SERVFAIL.
	zd.Ready = true
	zd.SetStatus(ZoneStatusReady)
	zd.SetError(ConfigError, "no such file")
	if got := zoneProvisioning(zd); got != "error" {
		t.Errorf("service-impacting error: got %q, want error", got)
	}
	zd.ClearError(ConfigError)
	if got := zoneProvisioning(zd); got != "ready" {
		t.Errorf("after clear: got %q, want ready", got)
	}
}

// zoneProvisioning takes zd.mu twice -- via HasServiceImpactingError and
// GetStatus -- and zd.mu is not reentrant, so it must acquire the lock itself
// rather than assume a caller holds it. Both call sites are lock-free today;
// this pins the property they depend on.
func TestZoneProvisioningTakesTheLockItself(t *testing.T) {
	zd := &ZoneData{ZoneName: "p.example.", Ready: true}
	zd.SetStatus(ZoneStatusReady)

	done := make(chan string, 1)
	go func() { done <- zoneProvisioning(zd) }()
	select {
	case got := <-done:
		if got != "ready" {
			t.Errorf("got %q, want ready", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("zoneProvisioning did not return; it deadlocked on zd.mu")
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

// zoneProvisioning reads four pieces of zone state -- the error registry,
// Error, Ready and Status -- and every writer of them holds zd.mu. Reading any
// of them outside that lock is a data race, and reading them under separate
// acquisitions lets a concurrent refresh land between two of them and yield a
// state that was never true of the zone at any instant.
//
// Run under -race this fails on the form that took the lock once per piece and
// read Error and Ready outside it altogether.
func TestZoneProvisioningIsRaceFree(t *testing.T) {
	zd := &ZoneData{ZoneName: "p.example."}
	zd.SetStatus(ZoneStatusReady)

	valid := map[string]bool{"unknown": true, "pending": true, "loading": true, "ready": true, "error": true}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// A refresh cycling the zone between loaded-and-well and never-loaded-and-
	// failing, which is exactly the pair the derivation has to tell apart.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				zd.SetError(RefreshError, "SOA probe failed")
				zd.mu.Lock()
				zd.Ready = false
				zd.Status = ZoneStatusPending
				zd.mu.Unlock()
			} else {
				zd.ClearError(RefreshError)
				zd.mu.Lock()
				zd.Ready = true
				zd.Status = ZoneStatusReady
				zd.mu.Unlock()
			}
		}
	}()

	for i := 0; i < 5000; i++ {
		if got := zoneProvisioning(zd); !valid[got] {
			close(stop)
			wg.Wait()
			t.Fatalf("zoneProvisioning returned %q, which is not a state", got)
		}
	}
	close(stop)
	wg.Wait()
}
