package tdns

import (
	"strings"
	"testing"
	"time"
)

// Removing a dynamic zone and the KeyDB records it leaves (CodeRabbit on
// #1118, issue #1134).

// removalFixture is an API-managed zone with a record of what the signal
// pass stored and a refresh confirmation, both under its canonical name.
func removalFixture(t *testing.T) (*Config, *KeyDB, *ZoneData) {
	t.Helper()
	const z = "remove.sig.example."
	kdb := newTestKeyDB(t)
	zd, _ := signalTestZone(t, z, z+"	3600	IN	NS	ns1."+z+"\nns1."+z+"	3600	IN	A	127.0.0.1\n", "127.0.0.1:53")
	zd.KeyDB = kdb
	zd.Options[OptApiManagedZone] = true
	if err := kdb.SetTransportSignalStored(z, "_dns.ns1."+z, []string{"d1"}); err != nil {
		t.Fatal(err)
	}
	if err := kdb.SetZoneRefreshState(z, 7, time.Now()); err != nil {
		t.Fatal(err)
	}
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	return conf, kdb, zd
}

func storedSignalRows(t *testing.T, kdb *KeyDB, zone string) int {
	t.Helper()
	var n int
	if err := kdb.DB.QueryRow(`SELECT COUNT(*) FROM TransportSignalStored WHERE zone=?`, zone).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A delete given the zone's name in another case drops the records kept
// under its canonical name: the stored-signal record and, as on main, the
// refresh confirmation.
func TestADeleteInAnotherCaseDropsTheZoneRecords(t *testing.T) {
	conf, kdb, zd := removalFixture(t)
	if _, err := conf.RemoveDynamicZone(strings.ToUpper(zd.ZoneName)); err != nil {
		t.Fatalf("RemoveDynamicZone: %v", err)
	}
	if n := storedSignalRows(t, kdb, zd.ZoneName); n != 0 {
		t.Errorf("the stored-signal record outlived the zone (%d rows)", n)
	}
	if _, ok, _ := kdb.GetZoneRefreshState(zd.ZoneName); ok {
		t.Error("the refresh confirmation outlived the zone")
	}
}

// A KeyDB that cannot drop the stored-signal record fails the delete before
// anything is removed: the zone is still served and the delete can be run
// again. Logged and reported as a success, the record outlived the zone and
// a zone added later under the name inherited it.
func TestADeleteWhoseStoredSignalDeleteFailsRemovesNothing(t *testing.T) {
	conf, kdb, zd := removalFixture(t)
	gen := zd.generation.Load()
	if _, err := kdb.DB.Exec(`CREATE TRIGGER refuse_delete BEFORE DELETE ON TransportSignalStored
BEGIN SELECT RAISE(ABORT, 'delete refused by the test'); END`); err != nil {
		t.Fatal(err)
	}
	if msg, err := conf.RemoveDynamicZone(zd.ZoneName); err == nil {
		t.Fatalf("the delete succeeded (%q) with the stored-signal record left in the KeyDB", msg)
	}
	if cur, ok := Zones.Get(zd.ZoneName); !ok || cur != zd {
		t.Fatal("the failed delete removed the zone")
	}
	if zd.generation.Load() != gen {
		t.Error("the failed delete bumped the zone's generation")
	}
	if _, ok, _ := kdb.GetZoneRefreshState(zd.ZoneName); !ok {
		t.Error("the failed delete dropped the refresh confirmation")
	}
	if zd.signalPassRetired {
		t.Error("the failed delete left the zone's signal pass retired")
	}

	if _, err := kdb.DB.Exec(`DROP TRIGGER refuse_delete`); err != nil {
		t.Fatal(err)
	}
	if _, err := conf.RemoveDynamicZone(zd.ZoneName); err != nil {
		t.Fatalf("the delete run again: %v", err)
	}
	if n := storedSignalRows(t, kdb, zd.ZoneName); n != 0 {
		t.Errorf("the stored-signal record outlived the zone (%d rows)", n)
	}
}

// The removed zone's own signal pass, starting after the delete (a first
// load still running, say), records nothing: a record written after the
// delete would outlive the zone.
func TestARemovedZonesSignalPassRecordsNothing(t *testing.T) {
	conf, kdb, zd := removalFixture(t)
	if _, err := conf.RemoveDynamicZone(zd.ZoneName); err != nil {
		t.Fatalf("RemoveDynamicZone: %v", err)
	}
	sconf := &Config{}
	sconf.Service.Transport.Type = "svcb"
	sconf.Service.Transport.Signal = "dot:50"
	sconf.Service.Identities = []string{"ns1." + zd.ZoneName}
	sconf.Listeners.Addresses = []string{"127.0.0.1:53"}
	Zones.Set(zd.ZoneName, zd) // the pass reads Zones to find an identity's home
	if err := zd.CreateTransportSignalRRs(sconf); err != nil {
		t.Fatal(err)
	}
	if n := storedSignalRows(t, kdb, zd.ZoneName); n != 0 {
		t.Errorf("the removed zone's pass recorded a stored signal (%d rows)", n)
	}
}

// An add of the same name waits for the removal (templateApplyMu, which an
// add holds until the zone is in Zones): the removal holds it throughout, so
// it cannot drop the records of the zone that add creates.
func TestADeleteHoldsOffAnAddOfTheSameName(t *testing.T) {
	conf, _, zd := removalFixture(t)
	templateApplyMu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := conf.RemoveDynamicZone(zd.ZoneName)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	_, present := Zones.Get(zd.ZoneName)
	templateApplyMu.Unlock()
	if err := <-done; err != nil {
		t.Fatalf("RemoveDynamicZone: %v", err)
	}
	if !present {
		t.Fatal("the removal ran while an add held templateApplyMu")
	}
	if _, ok := Zones.Get(zd.ZoneName); ok {
		t.Fatal("the zone is still present after the delete")
	}
}
