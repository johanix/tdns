package tdns

import (
	"errors"
	"path/filepath"
	"slices"
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
	if _, err := conf.RemoveDynamicZone(strings.ToUpper(zd.ZoneName), false); err != nil {
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
	if removal, err := conf.RemoveDynamicZone(zd.ZoneName, false); err == nil {
		t.Fatalf("the delete succeeded (%q) with the stored-signal record left in the KeyDB", removal.Msg())
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
	if _, err := conf.RemoveDynamicZone(zd.ZoneName, false); err != nil {
		t.Fatalf("the delete run again: %v", err)
	}
	if n := storedSignalRows(t, kdb, zd.ZoneName); n != 0 {
		t.Errorf("the stored-signal record outlived the zone (%d rows)", n)
	}
}

// A delete whose dynamic config rewrite fails leaves the zone to come back
// on restart, from a zone file that can still hold the signals the pass
// stored. The record of them is put back as it was, every owner and every
// digest: without it the pass would take those signals for the operator's.
func TestADeleteWhoseConfigRewriteFailsKeepsTheSignalRecord(t *testing.T) {
	conf, kdb, zd := removalFixture(t)
	z := zd.ZoneName
	want := map[string][]string{
		"_dns.ns1." + z: {"d3", "d2", "d1"},
		"_dns.ns2." + z: {"e1"},
	}
	for owner, digests := range want {
		if err := kdb.SetTransportSignalStored(z, owner, digests); err != nil {
			t.Fatal(err)
		}
	}
	// A directory that does not exist: the rewrite cannot create its file.
	conf.DynamicZones.ConfigFile = filepath.Join(t.TempDir(), "missing", "dynamic.yaml")

	if _, err := conf.RemoveDynamicZone(z, false); err == nil || !strings.Contains(err.Error(), "will reappear on restart") {
		t.Fatalf("the delete with a failed config rewrite returned %v", err)
	}
	for owner, digests := range want {
		got, ok, err := kdb.GetTransportSignalStored(z, owner)
		if err != nil || !ok || !slices.Equal(got, digests) {
			t.Errorf("after the failed rewrite the record at %s is %v (present %v, error %v), want %v", owner, got, ok, err, digests)
		}
	}
	if n := storedSignalRows(t, kdb, z); n != len(want) {
		t.Errorf("after the failed rewrite the zone has %d stored-signal rows, want %d", n, len(want))
	}
}

// A release in a zone whose removal has started is refused. A removal whose
// config rewrite fails puts the record of what the pass stored back, and a
// release reported done in between would be undone by it: after the
// restart the pass would take the operator's RRset for its own.
func TestAReleaseDuringARemovalIsRefused(t *testing.T) {
	conf, kdb, zd := removalFixture(t)
	z := zd.ZoneName
	owner := "_dns.ns1." + z
	sconf := &Config{}
	sconf.Service.Transport.Type = "svcb"
	sconf.Service.Transport.Signal = "dot:50"
	sconf.Service.Identities = []string{"ns1." + z}
	sconf.Listeners.Addresses = []string{"127.0.0.1:53"}
	if err := zd.CreateTransportSignalRRs(sconf); err != nil {
		t.Fatal(err)
	}
	if len(svcbRecords(zd, owner)) == 0 {
		t.Fatal("the pass stored no signal")
	}
	conf.DynamicZones.ConfigFile = filepath.Join(t.TempDir(), "missing", "dynamic.yaml")

	var released bool
	var releaseErr error
	testHookSignalRecordTaken = func() { released, releaseErr = zd.releaseSignal(owner) }
	t.Cleanup(func() { testHookSignalRecordTaken = nil })
	if _, err := conf.RemoveDynamicZone(z, false); err == nil || !strings.Contains(err.Error(), "will reappear on restart") {
		t.Fatalf("the delete with a failed config rewrite returned %v", err)
	}
	if released || releaseErr == nil {
		t.Errorf("a release during the removal returned released=%v, error %v; the failed removal put the record back", released, releaseErr)
	}
	if _, ok, err := kdb.GetTransportSignalStored(z, owner); err != nil || !ok {
		t.Errorf("the failed removal left no record at %s (error %v)", owner, err)
	}
}

// When the record cannot be put back either, the error says so: after the
// restart the pass takes the zone file's signal for the operator's.
func TestADeleteWhoseRecordCannotBePutBackSaysSo(t *testing.T) {
	conf, kdb, zd := removalFixture(t)
	conf.DynamicZones.ConfigFile = filepath.Join(t.TempDir(), "missing", "dynamic.yaml")
	if _, err := kdb.DB.Exec(`CREATE TRIGGER refuse_insert BEFORE INSERT ON TransportSignalStored
BEGIN SELECT RAISE(ABORT, 'insert refused by the test'); END`); err != nil {
		t.Fatal(err)
	}
	_, err := conf.RemoveDynamicZone(zd.ZoneName, false)
	if err == nil || !strings.Contains(err.Error(), "will reappear on restart") || !strings.Contains(err.Error(), "could not be put back") {
		t.Fatalf("the delete whose record could not be put back returned %v", err)
	}
}

// The removed zone's own signal pass, starting after the delete (a first
// load still running, say), records nothing: a record written after the
// delete would outlive the zone.
func TestARemovedZonesSignalPassRecordsNothing(t *testing.T) {
	conf, kdb, zd := removalFixture(t)
	if _, err := conf.RemoveDynamicZone(zd.ZoneName, false); err != nil {
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
// it cannot drop the records of the zone that add creates. The removal
// starts while the test holds templateApplyMu, as an add would, and reaches
// the lock before the test checks that the zone is still there. Once the
// test lets go, the lock is checked again from inside the removal, where
// its records have been taken: it must be held.
func TestADeleteHoldsOffAnAddOfTheSameName(t *testing.T) {
	conf, _, zd := removalFixture(t)
	reached := make(chan struct{})
	heldInside := false
	t.Cleanup(func() { testHookRemovalLocking, testHookSignalRecordTaken = nil, nil })
	testHookRemovalLocking = func() { close(reached) }
	testHookSignalRecordTaken = func() {
		if templateApplyMu.TryLock() {
			templateApplyMu.Unlock()
			return
		}
		heldInside = true
	}
	templateApplyMu.Lock()
	done := make(chan error, 1)
	go func() {
		_, err := conf.RemoveDynamicZone(zd.ZoneName, false)
		done <- err
	}()
	<-reached
	_, present := Zones.Get(zd.ZoneName)
	templateApplyMu.Unlock()
	if err := <-done; err != nil {
		t.Fatalf("RemoveDynamicZone: %v", err)
	}
	if !present {
		t.Fatal("the removal ran while an add held templateApplyMu")
	}
	if !heldInside {
		t.Fatal("the removal took the zone's records without holding templateApplyMu")
	}
	if _, ok := Zones.Get(zd.ZoneName); ok {
		t.Fatal("the zone is still present after the delete")
	}
}

// A signal pass on an instance that is no longer the zone's live one, one
// a modify replaced or one whose zone has been removed, records nothing:
// only the live instance is retired by a removal, and records written under
// the zone's name would pass to a zone added later under it (CodeRabbit on
// #1146).
func TestASignalPassOnAStaleInstanceRecordsNothing(t *testing.T) {
	const z = "remove.sig.example."
	const owner = "_dns.ns1." + z
	// The instance a modify replaces: the fixture's zone takes its place in
	// Zones.
	stale, sconf := signalTestZone(t, z, z+"	3600	IN	NS	ns1."+z+"\nns1."+z+"	3600	IN	A	127.0.0.1\n", "127.0.0.1:53")
	conf, kdb, zd := removalFixture(t)
	stale.KeyDB = kdb
	sconf.Service.Identities = []string{"ns1." + z}
	sconf.Service.Transport.Signal = "dot:50"

	if err := stale.CreateTransportSignalRRs(sconf); err != nil {
		t.Fatal(err)
	}
	if got, _, err := kdb.GetTransportSignalStored(z, owner); err != nil || !slices.Equal(got, []string{"d1"}) {
		t.Fatalf("the pass on the replaced instance changed the zone's record: %v (error %v)", got, err)
	}

	// And once the zone is gone.
	if _, err := conf.RemoveDynamicZone(zd.ZoneName, false); err != nil {
		t.Fatalf("RemoveDynamicZone: %v", err)
	}
	if err := stale.CreateTransportSignalRRs(sconf); err != nil {
		t.Fatal(err)
	}
	if n := storedSignalRows(t, kdb, z); n != 0 {
		t.Fatalf("the pass on an instance of the removed zone recorded a stored signal (%d rows)", n)
	}
}

// A delete whose rewrite of the dynamic config took effect but could not be
// synced to disk is a removal a crash could still undo. It is reported as
// such, not as a failed rewrite ("will reappear on restart"): the zone is
// out of Zones and out of the file, and a retry would find no zone. The
// keys are kept until the removal is on disk, and the report offers no
// command to delete them before that; so is the record of the signals its
// zone file holds, for the zone a crash would bring back. The configured
// zone set follows the file, which no longer names the zone.
func TestADeleteNotSyncedToDiskIsReportedWithItsKeysKept(t *testing.T) {
	conf, kdb, zd := removalFixture(t)
	z := zd.ZoneName
	fixtureActivePair(t, kdb, z)
	generateSig0Key(t, kdb, z, Sig0StateActive)
	dir := t.TempDir()
	conf.DynamicZones.ConfigFile = filepath.Join(dir, "dynamic.yaml")
	conf.DynamicZones.ZoneDirectory = dir
	prev := syncDynamicConfigDir
	syncDynamicConfigDir = func(string) error { return errors.New("sync refused by the test") }
	t.Cleanup(func() { syncDynamicConfigDir = prev })
	signalConfiguredZones.Store(&map[string]bool{z: true})
	t.Cleanup(func() { signalConfiguredZones.Store(nil) })

	r, err := conf.RemoveDynamicZone(z, false)
	if err != nil {
		t.Fatalf("a delete whose removal is not on disk returned an error, not a report: %v", err)
	}
	if r == nil || r.NotSynced == "" {
		t.Fatalf("the report does not say the removal is not on disk: %+v", r)
	}
	if _, back := Zones.Get(z); back {
		t.Error("the zone is still in Zones")
	}
	if n := countRows(t, kdb, "DnssecKeyStore", "zonename", z); n != 2 {
		t.Errorf("%d DNSSEC keys left, want the 2 kept", n)
	}
	if n := countRows(t, kdb, "Sig0KeyStore", "zonename", z); n != 1 {
		t.Errorf("%d SIG(0) keys left, want the 1 kept", n)
	}
	if n := storedSignalRows(t, kdb, z); n != 1 {
		t.Errorf("the zone has %d stored-signal rows, want its record put back", n)
	}
	msg := r.Msg()
	for _, want := range []string{
		"zone " + z + " deleted, but a crash could bring it back",
		"must stay until the removal is on disk",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the report lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "keystore ") {
		t.Errorf("the report offers to delete the keys before the removal is on disk:\n%s", msg)
	}
	if strings.Contains(msg, "reappear") || len(r.Warnings()) != 0 {
		t.Errorf("the report overstates it: %s %q", msg, r.Warnings())
	}
	if names := signalConfiguredZones.Load(); names == nil || (*names)[z] {
		t.Error("the configured zone set still counts the zone the file no longer names")
	}
}
