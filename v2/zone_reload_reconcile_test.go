/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// reloadZone builds a Ready primary zone backed by a real file on disk, with
// its file identity recorded -- i.e. a zone as it stands after a successful
// load. zd.FirstZoneLoad is false, so a later Refresh takes the RELOAD path
// rather than the first-load one.
func reloadZone(t *testing.T, kdb *KeyDB, zoneText string) *ZoneData {
	t.Helper()
	path := filepath.Join(t.TempDir(), "example.zone")
	if err := os.WriteFile(path, []byte(zoneText), 0644); err != nil {
		t.Fatalf("writing the zone file: %v", err)
	}
	zd := &ZoneData{
		ZoneName:     "example.",
		ZoneStore:    MapZone,
		ZoneType:     Primary,
		Zonefile:     path,
		Logger:       log.New(os.Stderr, "", 0),
		Options:      map[ZoneOption]bool{OptAllowUpdates: true},
		KeyDB:        kdb,
		UpdatePolicy: policyAllowing(dns.TypeA, dns.TypeTXT),
	}
	if _, _, err := zd.ReadZoneFile(path, true); err != nil {
		t.Fatalf("ReadZoneFile: %v", err)
	}
	zd.Ready = true
	zd.InstallInitialSnapshot()
	t.Cleanup(zd.stopPublisher)
	registerZones(t, zd)
	if err := zd.RecordZoneFileState(zd.fileSerial, zd.fileDigest); err != nil {
		t.Fatalf("RecordZoneFileState: %v", err)
	}
	return zd
}

// operatorEdit replaces the zone file behind the server, exactly as an editor
// or a generator does.
func operatorEdit(t *testing.T, zd *ZoneData, zoneText string) {
	t.Helper()
	if err := os.WriteFile(zd.Zonefile, []byte(zoneText), 0644); err != nil {
		t.Fatalf("replacing the zone file: %v", err)
	}
}

// apiUpdate applies one add through the normal applier, which journals it.
func apiUpdate(t *testing.T, zd *ZoneData, kdb *KeyDB, rr string) error {
	t.Helper()
	actions, err := BuildZoneUpdateActions(zd.ZoneName, ZoneUpdateSpec{
		Verb: VerbAddRR, RRs: []string{rr},
	})
	if err != nil {
		t.Fatalf("BuildZoneUpdateActions: %v", err)
	}
	updated, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: zd.ZoneName, Actions: actions,
	}, kdb)
	if updated {
		// What the ZoneUpdater does for every non-internal update: memory now
		// differs from the file. Without it WriteZone declines to write and the
		// `zone sync` step below would be a no-op.
		zd.SetOption(OptDirty, true)
	}
	return err
}

const reloadBase = `example.	3600	IN	SOA	ns.example. hostmaster.example. 100 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
`

// TestReloadPicksUpAnEditThatDidNotAdvanceTheSerial is symptom 1 of #362.
//
// The refresh path decided whether to read the file by comparing SOA serials,
// so an edit that did not advance the serial past what was last read was not
// loaded at all -- and `zone reload` reported success.
func TestReloadPicksUpAnEditThatDidNotAdvanceTheSerial(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := reloadZone(t, kdb, reloadBase)

	if err := apiUpdate(t, zd, kdb, "journal.example. 3600 IN A 10.1.1.1"); err != nil {
		t.Fatalf("the API update failed: %v", err)
	}

	// The operator edits the file and leaves the serial exactly where it was.
	operatorEdit(t, zd, `example.	3600	IN	SOA	ns.example. hostmaster.example. 100 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
operator.example.	3600	IN	A	10.9.9.9
`)

	if _, err := zd.Refresh(false, false, false, &Config{}); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	if !hasARRset(t, zd, "operator.example.") {
		t.Error("the operator's edit was not loaded by the reload")
	}
	if !hasARRset(t, zd, "journal.example.") {
		t.Error("the reload discarded the journalled record")
	}
}

// TestReloadOfAFileWhoseSerialJumpedAhead is symptom 2 of #362: after the
// reload the journal anchored to the new file's serial while the served serial
// did not follow it, so every subsequent update was refused.
func TestReloadOfAFileWhoseSerialJumpedAhead(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := reloadZone(t, kdb, reloadBase)

	if err := apiUpdate(t, zd, kdb, "journal.example. 3600 IN A 10.1.1.1"); err != nil {
		t.Fatalf("the API update failed: %v", err)
	}
	// `zone sync`: the file catches up and the journal is dropped.
	if _, err := zd.WriteZone(true, false); err != nil {
		t.Fatalf("WriteZone: %v", err)
	}

	// The operator edits the file and bumps the serial well past what is served.
	operatorEdit(t, zd, `example.	3600	IN	SOA	ns.example. hostmaster.example. 500 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
journal.example.	3600	IN	A	10.1.1.1
operator.example.	3600	IN	A	10.9.9.9
`)

	if _, err := zd.Refresh(false, false, false, &Config{}); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !hasARRset(t, zd, "operator.example.") {
		t.Fatal("the operator's edit was not loaded by the reload")
	}

	zd.mu.Lock()
	served, fileSerial := zd.CurrentSerial, zd.fileSerial
	zd.mu.Unlock()
	if !serialNewer(served, fileSerial) {
		t.Errorf("after the reload the zone serves %d, which does not advance past the file's %d",
			served, fileSerial)
	}

	// The next update must still be journallable.
	if err := apiUpdate(t, zd, kdb, "later.example. 3600 IN A 10.2.2.2"); err != nil {
		t.Fatalf("an update after the reload was refused: %v", err)
	}
	if !hasARRset(t, zd, "later.example.") {
		t.Error("the update after the reload was not served")
	}
}

// TestReloadOfAnUnchangedFileIsANoOp: the ticker calls this path on every
// refresh interval. A zone that republished every time would churn its serial
// and NOTIFY its secondaries for nothing.
func TestReloadOfAnUnchangedFileIsANoOp(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := reloadZone(t, kdb, reloadBase)

	zd.mu.Lock()
	before := zd.CurrentSerial
	zd.mu.Unlock()

	updated, err := zd.Refresh(false, false, false, &Config{})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if updated {
		t.Error("an unchanged zone file reported an update")
	}
	zd.mu.Lock()
	after := zd.CurrentSerial
	zd.mu.Unlock()
	if after != before {
		t.Errorf("an unchanged zone file moved the serial from %d to %d", before, after)
	}
}

// TestReloadIgnoresReformatting: the digest is of zone CONTENT, so a file that
// was reordered and re-commented is not a change -- even though its bytes are.
func TestReloadIgnoresReformatting(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := reloadZone(t, kdb, reloadBase)

	zd.mu.Lock()
	before := zd.CurrentSerial
	zd.mu.Unlock()

	operatorEdit(t, zd, `; reordered, re-commented and reflowed -- same zone
www.example.   3600 IN A   192.0.2.1

; the name server
example.       3600 IN NS  ns.example.

example. 3600 IN SOA ns.example. hostmaster.example. 100 7200 1800 604800 7200
`)

	updated, err := zd.Refresh(false, false, false, &Config{})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if updated {
		t.Error("reformatting the zone file reported an update")
	}
	zd.mu.Lock()
	after := zd.CurrentSerial
	zd.mu.Unlock()
	if after != before {
		t.Errorf("reformatting moved the serial from %d to %d", before, after)
	}
}

// TestReloadMergesAConflictAndWritesTheArtefact: the reload path reaches the
// same merge as a load, conflicts included. The zone file still carries a
// record the journal deleted, db-wins resolves it, and the operator gets the
// .rejected artefact naming what lost.
func TestReloadMergesAConflictAndWritesTheArtefact(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := reloadZone(t, kdb, reloadBase)

	// The journal deletes www, which the operator's file still has.
	actions, err := BuildZoneUpdateActions(zd.ZoneName, ZoneUpdateSpec{
		Verb: VerbDelRR, RRs: []string{"www.example. 3600 IN A 192.0.2.1"},
	})
	if err != nil {
		t.Fatalf("BuildZoneUpdateActions: %v", err)
	}
	if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: zd.ZoneName, Actions: actions,
	}, kdb); err != nil {
		t.Fatalf("the delete failed: %v", err)
	}

	operatorEdit(t, zd, `example.	3600	IN	SOA	ns.example. hostmaster.example. 101 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
operator.example.	3600	IN	A	10.9.9.9
`)

	if _, err := zd.Refresh(false, false, false, &Config{}); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	if hasARRset(t, zd, "www.example.") {
		t.Error("db-wins did not win on the reload path: the deleted record is served again")
	}
	if !hasARRset(t, zd, "operator.example.") {
		t.Error("the operator's edit was not loaded by the reload")
	}

	matches, err := filepath.Glob(zd.Zonefile + ".*.rejected")
	if err != nil {
		t.Fatalf("looking for the artefact: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("got %d .rejected artefacts, want 1", len(matches))
	}
	body, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("reading the artefact: %v", err)
	}
	if !strings.Contains(string(body), "192.0.2.1") {
		t.Errorf("the artefact does not name the record that lost:\n%s", body)
	}
}

// TestForcedReloadOfAnUnchangedFileReapplies: --force means force. It used to
// mean "parse the file to validate it, then throw the result away", which is
// what made an unadvanced serial unrecoverable without a restart.
func TestForcedReloadOfAnUnchangedFileReapplies(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := reloadZone(t, kdb, reloadBase)

	if err := apiUpdate(t, zd, kdb, "journal.example. 3600 IN A 10.1.1.1"); err != nil {
		t.Fatalf("the API update failed: %v", err)
	}

	zd.mu.Lock()
	before := zd.CurrentSerial
	zd.mu.Unlock()

	updated, err := zd.Refresh(false, false, true, &Config{})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !updated {
		t.Fatal("a forced reload of an unchanged file did nothing")
	}
	zd.mu.Lock()
	after := zd.CurrentSerial
	zd.mu.Unlock()
	if !serialNewer(after, before) {
		t.Errorf("a forced reload left the serial at %d (was %d)", after, before)
	}
	// The file never had it; only the journal replay can put it back.
	if !hasARRset(t, zd, "journal.example.") {
		t.Error("the forced reload discarded the journalled record")
	}
}

// TestReloadRefusalTracksWhetherTheJournalHoldsTheChanges. "The zone is dirty"
// is the normal state of a zone with journalled changes -- both replay and
// merge set the flag themselves -- so refusing a reload on it alone made
// `zone reload` permanently unavailable to exactly those zones.
func TestReloadRefusalTracksWhetherTheJournalHoldsTheChanges(t *testing.T) {
	kdb := newTestKeyDB(t)

	clean := &ZoneData{ZoneName: "example.", Options: map[ZoneOption]bool{}, KeyDB: kdb}
	if reloadWouldLoseChanges(clean) {
		t.Error("a clean zone was reported as having changes to lose")
	}

	dirty := &ZoneData{ZoneName: "example.",
		Options: map[ZoneOption]bool{OptDirty: true}, KeyDB: kdb}
	if reloadWouldLoseChanges(dirty) {
		t.Error("a dirty zone whose changes are journalled was refused a reload")
	}

	noDB := &ZoneData{ZoneName: "example.", Options: map[ZoneOption]bool{OptDirty: true}}
	if !reloadWouldLoseChanges(noDB) {
		t.Error("a dirty zone with no database was allowed a reload that would discard its changes")
	}

	off := false
	prev := Conf.Journal.Active
	Conf.Journal.Active = &off
	t.Cleanup(func() { Conf.Journal.Active = prev })
	if !reloadWouldLoseChanges(dirty) {
		t.Error("a dirty zone was allowed a reload with the journal switched off")
	}
}

// TestRestartLoadsAZoneWhoseFileIsUnchanged. The identity recorded by the
// previous run says "unchanged", and on a reload that means there is nothing to
// do -- but a restart has published nothing, so the file is not what the zone
// already has, it is everything the zone is about to have. Getting this wrong
// leaves the zone never loaded at all.
func TestRestartLoadsAZoneWhoseFileIsUnchanged(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := reloadZone(t, kdb, reloadBase)

	// The restart: a second ZoneData over the same file and the same database,
	// with nothing published yet.
	fresh := &ZoneData{
		ZoneName:      "example.",
		ZoneStore:     MapZone,
		ZoneType:      Primary,
		Zonefile:      zd.Zonefile,
		Logger:        log.New(os.Stderr, "", 0),
		Options:       map[ZoneOption]bool{OptAllowUpdates: true},
		KeyDB:         kdb,
		UpdatePolicy:  policyAllowing(dns.TypeA, dns.TypeTXT),
		FirstZoneLoad: true,
		Data:          core.NewCmap[OwnerData](),
	}
	Zones.Set("example.", fresh)
	t.Cleanup(func() { Zones.Remove("example.") })
	t.Cleanup(fresh.stopPublisher)

	updated, err := fresh.Refresh(false, false, false, &Config{})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !updated {
		t.Fatal("a restart did not load the zone, because its file was unchanged")
	}
	// What completeFirstZonePolicyAndLoad does next, and what marks a
	// first-loaded zone Ready.
	fresh.InstallInitialSnapshot()
	if !hasARRset(t, fresh, "www.example.") {
		t.Error("the zone came up without its content")
	}
}

// TestRefreshNeverWritesAPrimaryBackToItsSourceFile. A merge leaves the zone
// dirty, and the refresh engine's write-back branch keys on dirty -- so
// without this rule a reload that merged would rewrite the operator's file
// immediately after reading it, which is exactly what the design forbids.
func TestRefreshNeverWritesAPrimaryBackToItsSourceFile(t *testing.T) {
	for _, tc := range []struct {
		name     string
		zd       *ZoneData
		expected bool
	}{
		{"primary with a source file", &ZoneData{ZoneType: Primary, Zonefile: "/tmp/z"}, false},
		{"secondary persisting a transfer", &ZoneData{ZoneType: Secondary, Zonefile: "/tmp/z"}, true},
		{"secondary with nowhere to write", &ZoneData{ZoneType: Secondary}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := refreshWritesZoneToSourceFile(tc.zd); got != tc.expected {
				t.Fatalf("refreshWritesZoneToSourceFile = %v, want %v", got, tc.expected)
			}
		})
	}
}

// TestReloadDetectsAnEditWithNoJournalAndNoSerialChange is the plainest form
// of the question, and the one with no journal in it at all: nothing in the
// database, records changed in the file, SOA serial left where it was.
//
// The serial comparison this replaced answers "no change" here, which is the
// dangerous direction -- it is also what a regenerated file that reuses its
// serial looks like. The digest answers on content and gets it right.
//
// The served serial must still advance, even though the file's did not. A
// secondary refreshes on a serial increase and nothing else, so publishing the
// new content under the file's own serial would leave every secondary serving
// the old zone indefinitely.
func TestReloadDetectsAnEditWithNoJournalAndNoSerialChange(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := reloadZone(t, kdb, reloadBase)

	if _, have, err := kdb.LastZoneDeltaSerial("example."); err != nil {
		t.Fatalf("LastZoneDeltaSerial: %v", err)
	} else if have {
		t.Fatal("the journal is not empty; this case is about a zone with no db changes")
	}

	zd.mu.Lock()
	servedBefore := zd.CurrentSerial
	zd.mu.Unlock()

	// One record changed, one added. The SOA serial does not move.
	operatorEdit(t, zd, `example.	3600	IN	SOA	ns.example. hostmaster.example. 100 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.99
operator.example.	3600	IN	A	10.9.9.9
`)

	updated, err := zd.Refresh(false, false, false, &Config{})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !updated {
		t.Fatal("an edited zone file went undetected because its SOA serial had not moved")
	}
	if !hasARRset(t, zd, "operator.example.") {
		t.Error("the added record is not served")
	}
	rrset, err := zd.GetRRset("www.example.", dns.TypeA)
	if err != nil {
		t.Fatalf("GetRRset: %v", err)
	}
	if rrset == nil || len(rrset.RRs) == 0 || !strings.Contains(rrset.RRs[0].String(), "192.0.2.99") {
		t.Errorf("the changed record is not served: %v", rrset)
	}

	zd.mu.Lock()
	servedAfter, fileSerial := zd.CurrentSerial, zd.fileSerial
	zd.mu.Unlock()
	if !serialNewer(servedAfter, servedBefore) {
		t.Errorf("the served serial did not advance (%d -> %d), so no secondary would ever fetch"+
			" the edit", servedBefore, servedAfter)
	}
	if fileSerial != 100 {
		t.Errorf("the file's serial was recorded as %d, want 100 (the operator did not move it)", fileSerial)
	}
}

// TestReloadWithNoRecordedIdentityFallsBackToTheSerial documents the one case
// the digest cannot answer: nothing recorded for this zone, so there is no
// left-hand side to compare against. Detection falls back to the serial, which
// is what this path did before the digest existed.
//
// It is not a hole in practice. The identity is recorded at every read of the
// file and every write to it, and a zone's FIRST load is a read -- so a running
// server has one for every zone it serves, and an existing database acquires
// them at the next startup.
//
// The file is deliberately NOT adopted here, and therefore deliberately not
// recorded either: recording an identity for a file the zone is not serving
// would make the next load call that file "unchanged" and never load it, which
// turns a missed edit into a permanently hidden one.
func TestReloadWithNoRecordedIdentityFallsBackToTheSerial(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := reloadZone(t, kdb, reloadBase)

	// An existing database that predates this code.
	if err := kdb.DeleteZoneFileState("example."); err != nil {
		t.Fatalf("DeleteZoneFileState: %v", err)
	}

	operatorEdit(t, zd, `example.	3600	IN	SOA	ns.example. hostmaster.example. 100 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.99
`)
	updated, err := zd.Refresh(false, false, false, &Config{})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if updated {
		t.Error("with nothing recorded to compare against, the serial should have decided")
	}

	// A serial bump still works, and adopting the file records the identity --
	// after which the digest decides from then on.
	operatorEdit(t, zd, `example.	3600	IN	SOA	ns.example. hostmaster.example. 101 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.99
`)
	if _, err := zd.Refresh(false, false, false, &Config{}); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if _, have, err := kdb.GetZoneFileState("example."); err != nil {
		t.Fatalf("GetZoneFileState: %v", err)
	} else if !have {
		t.Fatal("adopting the file did not record its identity, so the next edit could not be detected")
	}
}
