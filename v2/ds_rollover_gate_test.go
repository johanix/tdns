package tdns

import (
	"os"
	"path/filepath"
	"testing"
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
	_, err := kdb.DB.Exec(
		`INSERT INTO RolloverZoneState (zone, rollover_in_progress) VALUES (?, ?)`,
		zone, inProgress)
	if err != nil {
		t.Fatalf("seed RolloverZoneState(%s, %d): %v", zone, inProgress, err)
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
