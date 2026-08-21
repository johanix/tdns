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
