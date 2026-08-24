package tdns

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

func gateTestKeyDB(t *testing.T) *KeyDB {
	t.Helper()
	f := filepath.Join(t.TempDir(), "gate.db")
	if err := os.WriteFile(f, nil, 0664); err != nil {
		t.Fatalf("create db file: %v", err)
	}
	kdb, err := NewKeyDB(f, false, nil)
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	return kdb
}

// seedRolloverRow writes a RolloverZoneState row with rollover_in_progress set
// as given. The engine normally creates this row; the test writes it directly
// so the gate can be exercised without driving a whole rollover.
func seedRolloverRow(t *testing.T, kdb *KeyDB, zone string, inProgress int) {
	t.Helper()
	seedRolloverRowPhase(t, kdb, zone, inProgress, rolloverPhaseIdle)
}

func seedRolloverRowPhase(t *testing.T, kdb *KeyDB, zone string, inProgress int, phase string) {
	t.Helper()
	_, err := kdb.DB.Exec(
		`INSERT INTO RolloverZoneState (zone, rollover_in_progress, rollover_phase) VALUES (?, ?, ?)`,
		zone, inProgress, phase)
	if err != nil {
		t.Fatalf("seed RolloverZoneState(%s, %d, %s): %v", zone, inProgress, phase, err)
	}
}

// While a KSK rollover is in flight the delegation-sync comparison must not
// have an opinion about DS. A double-DS roll places the new DS at the parent
// before the matching DNSKEY is published, so a comparison derived from
// published SEP DNSKEYs would report that DS as surplus and remove it.
func TestRolloverOwnsDS(t *testing.T) {
	const zone = "child.example."

	t.Run("no keystore means not rolling", func(t *testing.T) {
		zd := &ZoneData{ZoneName: zone}
		if zd.rolloverOwnsDS() {
			t.Error("a zone with no keystore was reported as rolling")
		}
	})

	t.Run("nil zone means not rolling", func(t *testing.T) {
		var zd *ZoneData
		if zd.rolloverOwnsDS() {
			t.Error("a nil zone was reported as rolling")
		}
	})

	t.Run("no rollover row means not rolling", func(t *testing.T) {
		zd := &ZoneData{ZoneName: zone, KeyDB: gateTestKeyDB(t)}
		if zd.rolloverOwnsDS() {
			t.Error("a zone with no rollover row was reported as rolling")
		}
	})

	t.Run("cleared flag means not rolling", func(t *testing.T) {
		kdb := gateTestKeyDB(t)
		seedRolloverRow(t, kdb, zone, 0)
		zd := &ZoneData{ZoneName: zone, KeyDB: kdb}
		if zd.rolloverOwnsDS() {
			t.Error("rollover_in_progress=0 was reported as rolling")
		}
	})

	t.Run("set flag means rolling", func(t *testing.T) {
		kdb := gateTestKeyDB(t)
		seedRolloverRow(t, kdb, zone, 1)
		zd := &ZoneData{ZoneName: zone, KeyDB: kdb}
		if !zd.rolloverOwnsDS() {
			t.Fatal("rollover_in_progress=1 was NOT reported as rolling;" +
				" the reconcile would delete the DS the rollover just placed")
		}
	})

	// The window the flag alone did not cover, and the reason this gate reads
	// the phase. Only AtomicRollover sets RolloverInProgress. The engine's idle
	// branch arms pending-parent-push directly for steady-state pipeline
	// maintenance and pushes a DS with the flag still false, so gating on the
	// flag left the reconcile free to delete the DS the engine had just sent --
	// exactly the outage this is here to prevent.
	t.Run("a DS-push phase counts even with the flag clear", func(t *testing.T) {
		for _, phase := range []string{
			rolloverPhasePendingParentPush,
			rolloverPhasePendingParentObserve,
			rolloverPhasePushSoftfail,
			rolloverPhasePendingChildPublish,
			rolloverPhasePendingChildWithdraw,
		} {
			t.Run(phase, func(t *testing.T) {
				kdb := gateTestKeyDB(t)
				seedRolloverRowPhase(t, kdb, zone, 0, phase)
				zd := &ZoneData{ZoneName: zone, KeyDB: kdb}
				if !zd.rolloverOwnsDS() {
					t.Fatalf("phase %q with the flag clear was treated as not rolling;"+
						" the reconcile would delete the DS the engine just pushed", phase)
				}
			})
		}
	})

	t.Run("an explicitly idle phase with the flag clear is not rolling", func(t *testing.T) {
		kdb := gateTestKeyDB(t)
		seedRolloverRowPhase(t, kdb, zone, 0, rolloverPhaseIdle)
		zd := &ZoneData{ZoneName: zone, KeyDB: kdb}
		if zd.rolloverOwnsDS() {
			t.Error("an idle zone was treated as rolling; DS sync would never run")
		}
	})

	t.Run("an empty phase with the flag clear is not rolling", func(t *testing.T) {
		kdb := gateTestKeyDB(t)
		seedRolloverRowPhase(t, kdb, zone, 0, "")
		zd := &ZoneData{ZoneName: zone, KeyDB: kdb}
		if zd.rolloverOwnsDS() {
			t.Error("a zone with no recorded phase was treated as rolling")
		}
	})

	// The flag is per zone. A roll on a sibling must not suppress DS
	// synchronisation for a zone that is not rolling.
	t.Run("another zone rolling does not suppress this one", func(t *testing.T) {
		kdb := gateTestKeyDB(t)
		seedRolloverRow(t, kdb, "sibling.example.", 1)
		zd := &ZoneData{ZoneName: zone, KeyDB: kdb}
		if zd.rolloverOwnsDS() {
			t.Error("a rollover on a sibling zone suppressed this zone's DS sync")
		}
	})
}

// The update path defers to the rollover engine for the same reason the
// analysis path does.
//
// The keystore intent excludes `created` keys, which is right outside a
// rollover and exactly wrong during one: the engine has already sent the DS for
// a key that is still `created`, so an authoritative set computed here omits it
// and replace mode deletes it. AnalyseZoneDelegation was gated; this path was
// the other way in, reached by an ordinary UPDATE that happens to touch a
// DNSKEY while a DS-work phase is in flight.
func TestComputeNewDSDefersWhileTheEngineOwnsTheDS(t *testing.T) {
	const zone = "child.example."

	newDss := func() *DelegationSyncStatus {
		return &DelegationSyncStatus{
			ZoneName:      zone,
			DNSKEYRemoves: []dns.RR{&dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY}}},
		}
	}

	t.Run("during a DS-work phase: no DS opinion", func(t *testing.T) {
		kdb := gateTestKeyDB(t)
		seedRolloverRowPhase(t, kdb, zone, 0, rolloverPhasePendingParentPush)
		// An active key MUST be seeded, or this test proves nothing: with no
		// keystore rows DSIntentForZone reports an unknown intent anyway, and
		// NewDSKnown stays false whether the deferral is there or not. The
		// first version of this test omitted it and passed with the deferral
		// removed.
		seedKey(t, kdb, zone, DnskeyStateActive, 257, pubA)
		zd := &ZoneData{ZoneName: zone, KeyDB: kdb}

		dss := newDss()
		computeNewDS(dss, zd)

		if dss.NewDSKnown {
			t.Fatal("the update path claimed an authoritative DS set while the engine" +
				" owned the DS; replace mode would delete the pre-published record")
		}
		if len(dss.NewDS) != 0 {
			t.Errorf("NewDS carried %d records", len(dss.NewDS))
		}
	})

	t.Run("idle: the update path answers as usual", func(t *testing.T) {
		kdb := gateTestKeyDB(t)
		seedRolloverRowPhase(t, kdb, zone, 0, rolloverPhaseIdle)
		seedKey(t, kdb, zone, DnskeyStateActive, 257, pubA)
		zd := &ZoneData{ZoneName: zone, KeyDB: kdb}

		dss := newDss()
		computeNewDS(dss, zd)

		if !dss.NewDSKnown {
			t.Fatal("an idle zone produced no DS answer; the DS change would be dropped")
		}
	})
}
