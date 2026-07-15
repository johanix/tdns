package tdns

import (
	"testing"
	"time"

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

// TestInstallInitialSnapshotRefusesApexlessData covers the second store site
// (the upstream root cause of the reload crash): InstallInitialSnapshot built a
// snapshot from zd.Data and set Ready=true unconditionally, so an empty/apex-less
// zd.Data produced a Ready zone with a nil-apex snapshot. It must refuse and
// leave the zone not-Ready.
func TestInstallInitialSnapshotRefusesApexlessData(t *testing.T) {
	zd := &ZoneData{ZoneName: "noapex.example."} // zd.Data nil → no apex
	Zones.Set(zd.ZoneName, zd)
	defer Zones.Remove(zd.ZoneName)
	defer zd.stopPublisher()

	zd.InstallInitialSnapshot()

	if zd.Ready {
		t.Fatal("InstallInitialSnapshot marked an apex-less zone Ready")
	}
	if zd.snapshot.Load() != nil {
		t.Fatal("InstallInitialSnapshot stored an apex-less snapshot")
	}
}

// TestInstallInitialSnapshotMarksReadyWhenSnapshotExists covers the first-load
// flow on this branch: the load path publishes the snapshot and leaves zd.Data
// empty, then InstallInitialSnapshot runs only to mark the zone Ready. It must
// flip Ready off the existing valid snapshot rather than refusing (which would
// leave the zone stuck "loading" and unable to serve AXFR) or overwriting it.
func TestInstallInitialSnapshotMarksReadyWhenSnapshotExists(t *testing.T) {
	zd := &ZoneData{ZoneName: "loaded.example."} // zd.Data empty
	good := &zoneSnapshot{Serial: 7, SOA: &dns.SOA{Serial: 7}}
	zd.snapshot.Store(good)
	Zones.Set(zd.ZoneName, zd)
	defer Zones.Remove(zd.ZoneName)
	defer zd.stopPublisher()

	zd.InstallInitialSnapshot()

	if !zd.Ready {
		t.Fatal("InstallInitialSnapshot left a zone with a valid snapshot not Ready (would refuse AXFR)")
	}
	if zd.snapshot.Load() != good {
		t.Fatal("InstallInitialSnapshot overwrote the existing valid snapshot")
	}
}

// TestResignSOAUnderLockNoSelfDeadlock is the regression test for the re-entrant
// zd.mu self-deadlock (instance #2 of the class 6e090a9 fixed). The publish path
// holds zd.mu (publishWorkingSetLocked) and re-signs the working-set SOA via
// resignWorkingSetSOAIfSigned. When the zone has no active keys yet, that reaches
// EnsureActiveDnssecKeys, which generates them and then publishes the DNSKEY
// RRset — and PublishDnskeyRRs takes zd.mu, self-deadlocking (Go mutexes are not
// reentrant). This is the exact production stack:
//
//	applyRefreshReplacementLocked -> publishWorkingSetLocked ->
//	resignWorkingSetSOAIfSigned -> SignRRset -> EnsureActiveDnssecKeys ->
//	PublishDnskeyRRs -> zd.mu.Lock()  (re-entrant, wedges the daemon)
//
// The fix resolves the keys with EnsureActiveDnssecKeys(zdLocked=true), which
// routes the publish through publishDnskeyRRsLocked (no re-lock). The re-sign
// runs in a goroutine holding zd.mu; a re-introduced re-lock blocks it forever,
// so the timeout fails the test instead of hanging the whole run.
func TestResignSOAUnderLockNoSelfDeadlock(t *testing.T) {
	kdb := newTestKeyDB(t)

	zone := `resign.example.	3600	IN	SOA	ns.resign.example. hostmaster.resign.example. 1 7200 1800 604800 7200
resign.example.	3600	IN	NS	ns.resign.example.
`
	zd := testZone(t, "resign.example.", zone)
	zd.KeyDB = kdb
	zd.Options = map[ZoneOption]bool{OptOnlineSigning: true}
	zd.DnssecPolicy = &DnssecPolicy{
		Mode:         DnssecPolicyModeKSKZSK,
		KSKAlgorithm: dns.ED25519,
		ZSKAlgorithm: dns.ED25519,
	}
	// No active keys are pre-generated: the first re-sign must GENERATE them and
	// PUBLISH the DNSKEY RRset — the fresh-key branch that re-locked zd.mu.

	done := make(chan struct{})
	go func() {
		zd.mu.Lock() // the publishWorkingSetLocked context: zd.mu held across the re-sign
		defer zd.mu.Unlock()
		zd.ensureWorkingSet()
		zd.resignWorkingSetSOAIfSigned()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("resignWorkingSetSOAIfSigned deadlocked while zd.mu was held (re-entrant zd.mu via EnsureActiveDnssecKeys -> PublishDnskeyRRs)")
	}

	// The SOA must actually carry an RRSIG now — proves the re-sign ran to
	// completion (generated keys, published DNSKEYs, signed the SOA) rather than
	// bailing out early.
	zd.mu.Lock()
	apex := zd.workingSet[zd.ZoneName]
	zd.mu.Unlock()
	if apex == nil {
		t.Fatal("apex missing from working set after resign")
	}
	soa := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	if len(soa.RRSIGs) == 0 {
		t.Fatal("SOA was not signed under the lock (re-sign did not complete)")
	}
}
