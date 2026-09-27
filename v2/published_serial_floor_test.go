/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Tests for the published-serial floor (#655,
// docs/2026-09-27-published-serial-floor.md).

// soaSignatureVerifies reports why the snapshot's apex SOA is not validly
// signed by one of its own DNSKEYs, or nil when it is.
func soaSignatureVerifies(snap *zoneSnapshot) error {
	if snap == nil || snap.Apex == nil {
		return fmt.Errorf("no snapshot or no apex")
	}
	soa := snap.Apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	keys := snap.Apex.RRtypes.GetOnlyRRSet(dns.TypeDNSKEY)
	if len(soa.RRSIGs) == 0 {
		return fmt.Errorf("the apex SOA carries no RRSIG")
	}
	var last error
	for _, rr := range soa.RRSIGs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		for _, krr := range keys.RRs {
			key, ok := krr.(*dns.DNSKEY)
			if !ok || key.KeyTag() != sig.KeyTag || key.Algorithm != sig.Algorithm {
				continue
			}
			if err := sig.Verify(key, soa.RRs); err != nil {
				last = fmt.Errorf("RRSIG by key %d does not verify over SOA serial %d: %v",
					sig.KeyTag, snap.Serial, err)
				continue
			}
			if !sig.ValidityPeriod(time.Now()) {
				last = fmt.Errorf("RRSIG by key %d is outside its validity period", sig.KeyTag)
				continue
			}
			return nil
		}
	}
	if last == nil {
		last = fmt.Errorf("no RRSIG over the SOA matches a served DNSKEY")
	}
	return last
}

// signedZoneFile loads reloadBase as a signing primary, signs it, writes it to
// its file and returns that file's text and serial: the file a signed zone
// leaves behind for its next start.
func signedZoneFile(t *testing.T, kdb *KeyDB) (string, uint32) {
	t.Helper()
	zd, _ := firstLoadFileZone(t, kdb, reloadBase)
	zd.Options[OptOnlineSigning] = true
	zd.DnssecPolicyName = "base"
	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "KSK", nil); err != nil {
		t.Fatalf("KSK: %v", err)
	}
	if _, _, err := kdb.GenerateKeypair(zd.ZoneName, "test", DnskeyStateActive, dns.TypeDNSKEY, dns.ED25519, "ZSK", nil); err != nil {
		t.Fatalf("ZSK: %v", err)
	}
	firstLoadFromFile(t, zd)
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	if err := completeFirstZonePolicyAndLoad(context.Background(), zd, conf, "base"); err != nil {
		t.Fatalf("completeFirstZonePolicyAndLoad: %v", err)
	}
	if !zd.Ready {
		t.Fatal("precondition: the signing zone did not become Ready")
	}
	if _, err := zd.WriteZone(true, true); err != nil {
		t.Fatalf("WriteZone: %v", err)
	}
	text, err := os.ReadFile(zd.Zonefile)
	if err != nil {
		t.Fatalf("reading the written zone file: %v", err)
	}
	zd.mu.Lock()
	serial := zd.CurrentSerial
	zd.mu.Unlock()
	zd.stopPublisher()
	Zones.Remove(zd.ZoneName)
	return string(text), serial
}

// T8: a signed zone whose first-load serial is lifted past the record must not
// serve an apex SOA whose RRSIG covers the file's serial. Once Ready, the SOA
// signature verifies against the SOA actually served.
func TestLiftedFirstLoadServesAValidlySignedSOA(t *testing.T) {
	for _, mode := range []string{OutboundSoaSerialKeep, OutboundSoaSerialPersist} {
		t.Run(mode, func(t *testing.T) { liftedFirstLoadServesAValidlySignedSOA(t, mode) })
	}
}

func liftedFirstLoadServesAValidlySignedSOA(t *testing.T, mode string) {
	kdb := newTestKeyDB(t)
	withLivePolicies(t, map[string]DnssecPolicy{"base": kskzsk(dns.ED25519, dns.ED25519)})
	text, fileSerial := signedZoneFile(t, kdb)

	// After the write the zone went on publishing: re-signs, say, that the
	// journal never saw. The record is ahead of the file.
	recorded := fileSerial + 5
	if err := kdb.SaveOutgoingSerial("example.", recorded); err != nil {
		t.Fatalf("SaveOutgoingSerial: %v", err)
	}

	// The restart.
	zd, _ := firstLoadFileZone(t, kdb, text)
	zd.Options[OptOnlineSigning] = true
	zd.DnssecPolicyName = "base"
	zd.OutboundSoaSerial = mode
	firstLoadFromFile(t, zd)
	if zd.Ready {
		if err := soaSignatureVerifies(zd.publishedSnapshot()); err != nil {
			t.Fatalf("the zone went Ready at its first-load publish with a bad SOA signature: %v", err)
		}
	}
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	if err := completeFirstZonePolicyAndLoad(context.Background(), zd, conf, "base"); err != nil {
		t.Fatalf("completeFirstZonePolicyAndLoad: %v", err)
	}
	if !zd.Ready {
		t.Fatal("the zone did not become Ready at first-load completion")
	}
	snap := zd.publishedSnapshot()
	if !serialNewer(snap.Serial, recorded) {
		t.Fatalf("served serial %d is not newer than the recorded %d", snap.Serial, recorded)
	}
	if err := soaSignatureVerifies(snap); err != nil {
		t.Fatalf("after the lifted first load: %v", err)
	}
}

// --- helpers --------------------------------------------------------------

// restartedPrimary loads zoneText as an unsigned file-backed primary that
// accepts updates, exactly as a start does: first load, then the completion
// that binds the policy and reconciles the journal. mode is the zone's
// outbound-soa-serial ("" for the default).
func restartedPrimary(t *testing.T, kdb *KeyDB, zoneText, mode string) *ZoneData {
	t.Helper()
	zd, _ := firstLoadFileZone(t, kdb, zoneText)
	zd.Options[OptAllowUpdates] = true
	zd.UpdatePolicy = policyAllowing(dns.TypeA, dns.TypeTXT)
	zd.OutboundSoaSerial = mode
	firstLoadFromFile(t, zd)
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	if err := completeFirstZonePolicyAndLoad(context.Background(), zd, conf, ""); err != nil {
		t.Fatalf("completeFirstZonePolicyAndLoad: %v", err)
	}
	return zd
}

// stopped takes zd out of service, as the process ending does.
func stopped(zd *ZoneData) {
	zd.stopPublisher()
	Zones.Remove(zd.ZoneName)
}

// unjournaledPublish publishes with a serial bump and no content change: what
// a re-sign, a DNSKEY publish or `zone bump` does as far as the journal is
// concerned. Returns the serial published.
func unjournaledPublish(t *testing.T, zd *ZoneData) uint32 {
	t.Helper()
	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.ensureWorkingSet()
	zd.publishWorkingSetLocked(zd.generation.Load(), true)
	return zd.CurrentSerial
}

func servedSerial(t *testing.T, zd *ZoneData) uint32 {
	t.Helper()
	snap := zd.publishedSnapshot()
	if snap == nil {
		t.Fatal("no published snapshot")
	}
	return snap.Serial
}

func mustUpdate(t *testing.T, zd *ZoneData, kdb *KeyDB, rr string) uint32 {
	t.Helper()
	if err := apiUpdate(t, zd, kdb, rr); err != nil {
		t.Fatalf("update %q: %v", rr, err)
	}
	return servedSerial(t, zd)
}

func zoneFileText(t *testing.T, zd *ZoneData) string {
	t.Helper()
	b, err := os.ReadFile(zd.Zonefile)
	if err != nil {
		t.Fatalf("reading %s: %v", zd.Zonefile, err)
	}
	return string(b)
}

func hasOwner(zd *ZoneData, name string) bool {
	od, err := zd.GetOwner(name)
	return err == nil && od != nil && ownerHasData(od)
}

// --- the two #655 observations --------------------------------------------

// T1: a journaled change (N), then two publishes the journal never sees (N+1,
// N+2), then a restart. The zone must come back past N+2, not past N.
func TestRestartLandsPastUnjournaledPublishes(t *testing.T) {
	kdb := newTestKeyDB(t)
	live := restartedPrimary(t, kdb, reloadBase, "")
	mustUpdate(t, live, kdb, "journal.example. 3600 IN A 10.1.1.1")
	unjournaledPublish(t, live)
	high := unjournaledPublish(t, live)
	stopped(live)

	again := restartedPrimary(t, kdb, reloadBase, "")
	if got := servedSerial(t, again); !serialNewer(got, high) {
		t.Fatalf("after the restart the zone serves %d, not past %d, the last serial it"+
			" served before it", got, high)
	}
	if !hasOwner(again, "journal.example.") {
		t.Error("the journaled change was not replayed")
	}
}

// T2: the same with an empty journal. The zone was written out after its last
// change, then published twice more; nothing is left in the journal to lift
// the serial.
func TestRestartWithAnEmptyJournalLandsPastUnjournaledPublishes(t *testing.T) {
	kdb := newTestKeyDB(t)
	live := restartedPrimary(t, kdb, reloadBase, "")
	mustUpdate(t, live, kdb, "journal.example. 3600 IN A 10.1.1.1")
	if _, err := live.WriteZone(true, true); err != nil {
		t.Fatalf("WriteZone: %v", err)
	}
	if deltas, _ := kdb.LoadZoneDeltas("example."); len(deltas) != 0 {
		t.Fatalf("precondition: the write left %d deltas in the journal", len(deltas))
	}
	unjournaledPublish(t, live)
	high := unjournaledPublish(t, live)
	text := zoneFileText(t, live)
	stopped(live)

	again := restartedPrimary(t, kdb, text, "")
	if got := servedSerial(t, again); !serialNewer(got, high) {
		t.Fatalf("after the restart the zone serves %d, not past %d", got, high)
	}
}

// T3: after the restart, a change lands on a serial the zone never served
// before it -- so a secondary holding the pre-restart serial transfers it.
// This is the 2026-09-24 observation: the first change after the restart
// landed on a reused serial.
func TestAChangeAfterARestartGetsASerialNeverServed(t *testing.T) {
	kdb := newTestKeyDB(t)
	live := restartedPrimary(t, kdb, reloadBase, "")
	mustUpdate(t, live, kdb, "journal.example. 3600 IN A 10.1.1.1")
	unjournaledPublish(t, live)
	high := unjournaledPublish(t, live)
	stopped(live)

	again := restartedPrimary(t, kdb, reloadBase, "")
	got := mustUpdate(t, again, kdb, "after.example. 3600 IN A 10.1.1.2")
	if !serialNewer(got, high) {
		t.Fatalf("the first change after the restart landed on %d, a serial the zone had"+
			" already served (up to %d)", got, high)
	}
}

// --- the first-load matrix --------------------------------------------------

// T4: the floor applies in every outbound-soa-serial mode, not only persist.
func TestFirstLoadFloorAppliesInEveryMode(t *testing.T) {
	t.Run("keep", func(t *testing.T) {
		zd, _, load := modePrimary(t, OutboundSoaSerialKeep, s2Zone, 1000)
		load()
		waitServing(t, zd, 1001)
	})
	t.Run("persist", func(t *testing.T) {
		zd, _, load := modePrimary(t, OutboundSoaSerialPersist, s2Zone, 1000)
		load()
		waitServing(t, zd, 1001)
	})
	t.Run("unixtime", func(t *testing.T) {
		zd, _, load := modePrimary(t, OutboundSoaSerialUnixtime, s2Zone, 1000)
		load()
		deadline := time.Now().Add(10 * time.Second)
		for {
			zd.mu.Lock()
			ready, cur := zd.Ready, zd.CurrentSerial
			zd.mu.Unlock()
			if ready && serialNewer(cur, 1000) && cur != 1001 {
				return // the clock, which is newer than the floor
			}
			if time.Now().After(deadline) {
				t.Fatalf("Ready=%v CurrentSerial=%d, want the clock, past 1000", ready, cur)
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
}

// T5: a clean restart -- nothing published since the file was written -- lifts
// nothing and burns no serial. For a signed zone, the sign after the policy
// binds still skips a file whose signatures are good.
func TestCleanRestartLiftsNothing(t *testing.T) {
	t.Run("unsigned", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		live := restartedPrimary(t, kdb, reloadBase, "")
		written := mustUpdate(t, live, kdb, "journal.example. 3600 IN A 10.1.1.1")
		if _, err := live.WriteZone(true, true); err != nil {
			t.Fatalf("WriteZone: %v", err)
		}
		text := zoneFileText(t, live)
		stopped(live)

		again := restartedPrimary(t, kdb, text, "")
		if got := servedSerial(t, again); got != written {
			t.Fatalf("a clean restart serves %d, want the written %d", got, written)
		}
	})
	t.Run("signed", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		withLivePolicies(t, map[string]DnssecPolicy{"base": kskzsk(dns.ED25519, dns.ED25519)})
		text, written := signedZoneFile(t, kdb)

		zd, _ := firstLoadFileZone(t, kdb, text)
		zd.Options[OptOnlineSigning] = true
		zd.DnssecPolicyName = "base"
		firstLoadFromFile(t, zd)
		conf := &Config{}
		conf.Internal.KeyDB = kdb
		if err := completeFirstZonePolicyAndLoad(context.Background(), zd, conf, "base"); err != nil {
			t.Fatalf("completeFirstZonePolicyAndLoad: %v", err)
		}
		snap := zd.publishedSnapshot()
		if snap.Serial != written {
			t.Fatalf("a clean restart of a signed zone serves %d, want the written %d", snap.Serial, written)
		}
		if err := soaSignatureVerifies(snap); err != nil {
			t.Fatalf("after a clean restart: %v", err)
		}
	})
}

// T6: RFC 1982 order in the default mode, as in persist: a file serial past
// the wrap is newer than a record just below it and is kept; a record past the
// wrap is newer than a file serial just below it and lifts it.
func TestFirstLoadFloorComparesInRFC1982Order(t *testing.T) {
	t.Run("record past the wrap lifts", func(t *testing.T) {
		zd, _, load := modePrimary(t, OutboundSoaSerialKeep, soaSerial(4294967290), 5)
		load()
		waitServing(t, zd, 6)
	})
	t.Run("file past the wrap is kept", func(t *testing.T) {
		zd, _, load := modePrimary(t, OutboundSoaSerialKeep, soaSerial(5), 4294967290)
		load()
		waitServing(t, zd, 5)
	})
}

// The record never goes backwards, in RFC 1982 order.
func TestRaiseOutgoingSerialNeverLowers(t *testing.T) {
	kdb := newTestKeyDB(t)
	const z = "example."
	steps := []struct {
		raise, want uint32
	}{
		{4294967290, 4294967290},
		{100, 100},               // past the wrap: newer
		{4294967290, 100},        // before the wrap: older
		{99, 100},                // older
		{100, 100},               // equal
		{2147483747, 2147483747}, // 2^31-1 ahead: still newer
	}
	for i, s := range steps {
		if err := kdb.RaiseOutgoingSerial(z, s.raise); err != nil {
			t.Fatalf("step %d: RaiseOutgoingSerial(%d): %v", i, s.raise, err)
		}
		got, err := kdb.LoadOutgoingSerial(z)
		if err != nil {
			t.Fatalf("step %d: LoadOutgoingSerial: %v", i, err)
		}
		if got != s.want {
			t.Fatalf("step %d: after raising to %d the record is %d, want %d", i, s.raise, got, s.want)
		}
	}
}

// The floor is the newer of the record and the journal's tail.
func TestPublishedSerialFloor(t *testing.T) {
	kdb := newTestKeyDB(t)
	const z = "example."
	if _, have, err := kdb.PublishedSerialFloor(z); err != nil || have {
		t.Fatalf("empty database: have=%v err=%v, want nothing known", have, err)
	}
	add := []core.RRset{{Name: "a.example.", RRtype: dns.TypeA,
		RRs: []dns.RR{mustRR(t, "a.example. 3600 IN A 10.0.0.1")}}}
	if err := kdb.PersistZoneDelta(z, 10, 20, nil, add); err != nil {
		t.Fatalf("PersistZoneDelta: %v", err)
	}
	if got, have, _ := kdb.PublishedSerialFloor(z); !have || got != 20 {
		t.Fatalf("tail only: %d/%v, want 20", got, have)
	}
	if err := kdb.RaiseOutgoingSerial(z, 15); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := kdb.PublishedSerialFloor(z); got != 20 {
		t.Fatalf("record 15, tail 20: %d, want 20", got)
	}
	if err := kdb.RaiseOutgoingSerial(z, 30); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := kdb.PublishedSerialFloor(z); got != 30 {
		t.Fatalf("record 30, tail 20: %d, want 30", got)
	}
}

// T7: a mirroring secondary (MUST-NOT-MODIFY) records nothing and gets no
// floor: its serial is upstream's.
func TestMirrorRecordsNoSerialAndGetsNoFloor(t *testing.T) {
	withAppType(t, AppTypeAuth)
	kdb := newTestKeyDB(t)
	zd := loadIxfrTestZone(t, basicZone)
	zd.ZoneType = Secondary
	zd.Options = map[ZoneOption]bool{}
	zd.KeyDB = kdb
	registerZones(t, zd)

	refreshTo(t, zd, "40")
	if _, err := kdb.LoadOutgoingSerial(zd.ZoneName); err == nil {
		t.Fatal("a mirroring secondary recorded a published serial")
	}

	// A row left by an earlier life of the zone does not lift a first load.
	if err := kdb.SaveOutgoingSerial(zd.ZoneName, 5000); err != nil {
		t.Fatal(err)
	}
	newZone := strings.Replace(basicZone, "1 ; serial", "41 ; serial", 1)
	newZd := &ZoneData{ZoneName: zd.ZoneName, ZoneStore: MapZone, ZoneType: zd.ZoneType, Logger: zd.Logger}
	if _, _, err := newZd.ReadZoneData(newZone, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	zd.mu.Lock()
	err := zd.applyRefreshReplacementLocked(newZd, nil, true, false)
	cur := zd.CurrentSerial
	zd.mu.Unlock()
	if err != nil {
		t.Fatalf("applyRefreshReplacementLocked (first load): %v", err)
	}
	if cur != 41 {
		t.Fatalf("a mirroring secondary's first load serves %d, want the upstream's 41", cur)
	}
}

// T9: in unixtime mode, a record ahead of the clock is not undone by the
// clock: the serial never moves backwards.
func TestUnixtimeNeverMovesTheSerialBackwards(t *testing.T) {
	ahead := uint32(time.Now().Unix()) + 100000
	zd, _, load := modePrimary(t, OutboundSoaSerialUnixtime, s2Zone, ahead)
	load()
	waitServing(t, zd, ahead+1)
}

// T10: a restart onto a REPLACED zone file (the merge path), in the default
// mode, lands past everything served before the restart.
func TestMergeAfterRestartLandsPastTheRecord(t *testing.T) {
	kdb := newTestKeyDB(t)
	live := restartedPrimary(t, kdb, reloadBase, "")
	mustUpdate(t, live, kdb, "journal.example. 3600 IN A 10.1.1.1")
	unjournaledPublish(t, live)
	high := unjournaledPublish(t, live)
	stopped(live)

	replaced := strings.Replace(reloadBase, " 100 ", " 50 ", 1) +
		"extra.example.\t3600\tIN\tA\t192.0.2.50\n"
	again := restartedPrimary(t, kdb, replaced, "")
	if got := servedSerial(t, again); !serialNewer(got, high) {
		t.Fatalf("after a restart onto a replaced file the zone serves %d, not past %d", got, high)
	}
	if !hasOwner(again, "extra.example.") || !hasOwner(again, "journal.example.") {
		t.Error("the merge did not keep both the file's record and the journal's")
	}
}

// T12: a failed record write does not stop the publish or take the zone out of
// Ready. It raises a ConfigWarning, and the next publish that records
// successfully clears it and puts back the warning it displaced.
func TestAFailedSerialRecordWarnsAndKeepsServing(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := restartedPrimary(t, kdb, reloadBase, "")
	zd.SetError(ConfigWarning, "an earlier warning")
	before := servedSerial(t, zd)

	if _, err := kdb.DB.Exec(`ALTER TABLE OutgoingSerials RENAME TO OutgoingSerialsAway`); err != nil {
		t.Fatalf("hiding the table: %v", err)
	}
	failed := unjournaledPublish(t, zd)
	if failed != before+1 || servedSerial(t, zd) != failed {
		t.Fatalf("the publish did not go out: served %d, want %d", servedSerial(t, zd), before+1)
	}
	if !zd.Ready {
		t.Fatal("a failed record write took the zone out of Ready")
	}
	if w := ovConfigWarning(zd); !strings.HasPrefix(w, serialRecordWarning) {
		t.Fatalf("no ConfigWarning for the failed record write; the warning is %q", w)
	}

	if _, err := kdb.DB.Exec(`ALTER TABLE OutgoingSerialsAway RENAME TO OutgoingSerials`); err != nil {
		t.Fatalf("restoring the table: %v", err)
	}
	next := unjournaledPublish(t, zd)
	if got, err := kdb.LoadOutgoingSerial("example."); err != nil || got != next {
		t.Fatalf("the next publish recorded %d (err %v), want %d", got, err, next)
	}
	if w := ovConfigWarning(zd); w != "an earlier warning" {
		t.Fatalf("after a successful record the ConfigWarning is %q, want the earlier one back", w)
	}
}

// T13: a database from a build that recorded nothing outside persist mode has
// no record; the journal's tail is the floor.
func TestPreUpgradeDatabaseFloorsOnTheJournalTail(t *testing.T) {
	kdb := newTestKeyDB(t)
	live := restartedPrimary(t, kdb, reloadBase, "")
	tail := mustUpdate(t, live, kdb, "journal.example. 3600 IN A 10.1.1.1")
	stopped(live)
	if err := kdb.DeleteOutgoingSerial("example."); err != nil {
		t.Fatal(err)
	}

	again := restartedPrimary(t, kdb, reloadBase, "")
	if got := servedSerial(t, again); !serialNewer(got, tail) {
		t.Fatalf("with no record the zone serves %d, not past the journal's tail %d", got, tail)
	}
}

// T14: T13 for an overlay zone -- an inline-signing secondary, which journals
// in the serial space it serves and skips the file replay. With no record, its
// first load must still land past its journal's tail rather than at the
// upstream's serial.
func TestOverlayZoneWithoutARecordFloorsOnTheJournalTail(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	for i := 1; i <= 3; i++ {
		if err := ovPublishCDS(t, zd, ovCDS(t, i)); err != nil {
			t.Fatalf("CDS publish %d: %v", i, err)
		}
	}
	tail, have, err := zd.KeyDB.LastZoneDeltaSerial(ovZone)
	if err != nil || !have {
		t.Fatalf("precondition: no journal tail (err %v)", err)
	}
	if err := zd.KeyDB.DeleteOutgoingSerial(ovZone); err != nil {
		t.Fatal(err)
	}

	again := ovRestarted(t, zd.KeyDB, zd.DnssecPolicy)
	ovTransfer(t, again, ovUpstreamZone(8), true)
	if got := ovServedSerial(t, again); !serialNewer(got, tail) {
		t.Fatalf("the restarted overlay zone serves %d, not past its journal's tail %d", got, tail)
	}
}

// T15: a journal purge leaves the record alone, so a restart after a purge and
// more unjournaled publishes still lands past them.
func TestPurgeKeepsTheRecord(t *testing.T) {
	kdb := newTestKeyDB(t)
	live := restartedPrimary(t, kdb, reloadBase, "")
	mustUpdate(t, live, kdb, "journal.example. 3600 IN A 10.1.1.1")
	purgedAt := unjournaledPublish(t, live)
	if _, err := live.JournalPurge(true); err != nil {
		t.Fatalf("JournalPurge: %v", err)
	}
	if got, err := kdb.LoadOutgoingSerial("example."); err != nil || got != purgedAt {
		t.Fatalf("after the purge the record is %d (err %v), want %d", got, err, purgedAt)
	}
	unjournaledPublish(t, live)
	high := unjournaledPublish(t, live)
	stopped(live)

	again := restartedPrimary(t, kdb, reloadBase, "")
	if got := servedSerial(t, again); !serialNewer(got, high) {
		t.Fatalf("after a purge and a restart the zone serves %d, not past %d", got, high)
	}
}
