/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// TestFindMergeConflictsDeleteAgainstPresentRecord: the one real conflict --
// the journal deletes a record the new file still has.
func TestFindMergeConflictsDeleteAgainstPresentRecord(t *testing.T) {
	const file = `example.	3600	IN	SOA	ns.example. hostmaster.example. 2 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
`
	insns := []ZoneDeltaRR{
		{Action: ZoneDeltaDel, RR: "www.example.\t3600\tIN\tA\t192.0.2.1"},
	}

	conflicts, err := findMergeConflicts(parseZoneRRs(t, "example.", file), insns)
	if err != nil {
		t.Fatalf("findMergeConflicts: %v", err)
	}
	if len(conflicts) != 1 {
		t.Fatalf("got %d conflicts, want 1", len(conflicts))
	}
	// The inverse of "the journal deleted it" is "add it back".
	if conflicts[0].Inverse.Action != ZoneDeltaAdd {
		t.Fatalf("inverse action = %q, want %q", conflicts[0].Inverse.Action, ZoneDeltaAdd)
	}
	if !strings.Contains(conflicts[0].Inverse.RR, "192.0.2.1") {
		t.Fatalf("inverse does not name the record: %q", conflicts[0].Inverse.RR)
	}
}

// TestFindMergeConflictsIgnoresTTLDifference. A TTL is not part of a record's
// identity: RFC 2136 ignores it when deleting, and this must agree with the
// applier it feeds. Otherwise a TTL-only difference reports a conflict and then
// "resolves" it by deleting a record the operator still has.
func TestFindMergeConflictsIgnoresTTLDifference(t *testing.T) {
	const file = `example.	3600	IN	SOA	ns.example. hostmaster.example. 2 7200 1800 604800 7200
www.example.	60	IN	A	192.0.2.1
`
	insns := []ZoneDeltaRR{
		{Action: ZoneDeltaDel, RR: "www.example.\t3600\tIN\tA\t192.0.2.1"},
	}
	conflicts, err := findMergeConflicts(parseZoneRRs(t, "example.", file), insns)
	if err != nil {
		t.Fatalf("findMergeConflicts: %v", err)
	}
	if len(conflicts) != 1 {
		t.Fatalf("a TTL-only difference hid the conflict: got %d, want 1", len(conflicts))
	}
}

// TestFindMergeConflictsNoneForAdds is the case the design doc got wrong.
//
// A journal ADD implies the OLD file lacked that record. So a new file that
// also lacks it agrees with the old one -- the operator removed nothing -- and
// a new file that HAS it added the same record independently. Neither is a
// conflict, and reporting them would flag every ordinary journal entry.
func TestFindMergeConflictsNoneForAdds(t *testing.T) {
	const fileWithout = `example.	3600	IN	SOA	ns.example. hostmaster.example. 2 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
`
	const fileWith = `example.	3600	IN	SOA	ns.example. hostmaster.example. 2 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
new.example.	3600	IN	A	10.0.0.1
`
	insns := []ZoneDeltaRR{
		{Action: ZoneDeltaAdd, RR: "new.example.\t3600\tIN\tA\t10.0.0.1"},
	}

	for _, tc := range []struct{ name, zone string }{
		{"file lacks the added record", fileWithout},
		{"file has it too", fileWith},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conflicts, err := findMergeConflicts(parseZoneRRs(t, "example.", tc.zone), insns)
			if err != nil {
				t.Fatalf("findMergeConflicts: %v", err)
			}
			if len(conflicts) != 0 {
				t.Fatalf("an ADD produced %d conflicts, want 0", len(conflicts))
			}
		})
	}
}

// TestFindMergeConflictsNoneWhenBothSidesAgreeItIsGone.
func TestFindMergeConflictsNoneWhenBothSidesAgreeItIsGone(t *testing.T) {
	const file = `example.	3600	IN	SOA	ns.example. hostmaster.example. 2 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
`
	insns := []ZoneDeltaRR{
		{Action: ZoneDeltaDel, RR: "gone.example.\t3600\tIN\tA\t192.0.2.9"},
	}
	conflicts, err := findMergeConflicts(parseZoneRRs(t, "example.", file), insns)
	if err != nil {
		t.Fatalf("findMergeConflicts: %v", err)
	}
	if len(conflicts) != 0 {
		t.Fatalf("got %d conflicts when both sides agree, want 0", len(conflicts))
	}
}

// TestRejectedArtefactIsAnExecutableInverse: what the merge writes must parse
// back as instructions and restore the file's version.
func TestRejectedArtefactIsAnExecutableInverse(t *testing.T) {
	zonefile := filepath.Join(t.TempDir(), "example.zone")
	conflicts := []ZoneMergeConflict{{
		RR:      "www.example.\t3600\tIN\tA\t192.0.2.1",
		Inverse: ZoneDeltaRR{Action: ZoneDeltaAdd, RR: "www.example.\t3600\tIN\tA\t192.0.2.1"},
	}}

	path, err := writeRejectedArtefact(zonefile, "example.", 42, ConflictDBWins, conflicts)
	if err != nil {
		t.Fatalf("writeRejectedArtefact: %v", err)
	}
	if !strings.HasSuffix(path, ".42.rejected") {
		t.Fatalf("artefact path %q does not name the file's serial", path)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the artefact: %v", err)
	}
	back, err := ParseUpdateInstructions(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("the artefact does not parse back: %v", err)
	}
	if len(back) != 1 || back[0].Action != ZoneDeltaAdd {
		t.Fatalf("round-tripped as %+v, want one ADD", back)
	}
	// And it must be usable as an update against the zone, not just parseable.
	if _, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{
		Verb: VerbInstructions, Instructions: back,
	}); err != nil {
		t.Fatalf("the artefact does not build into an update: %v", err)
	}
}

// TestMergeSerialFloor. dnslab. is the live case: file 01, served 03, journal
// head 06. Publishing at 02 would take the zone backwards for every secondary
// already holding 03 -- and a secondary refreshes on a serial increase and
// nothing else, so it would ignore the merged content indefinitely.
func TestMergeSerialFloor(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		file, served, journal, wantMore uint32
	}{
		{"the dnslab case", 2026081701, 2026081703, 2026081706, 2026081707},
		{"file ahead of everything", 100, 50, 60, 101},
		{"served ahead", 10, 90, 20, 91},
		{"journal head ahead", 10, 20, 90, 91},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeSerialFloor(tc.file, tc.served, tc.journal)
			if got != tc.wantMore {
				t.Fatalf("floor = %d, want %d", got, tc.wantMore)
			}
			for _, prior := range []uint32{tc.file, tc.served, tc.journal} {
				if !serialNewer(got, prior) {
					t.Fatalf("floor %d does not advance past %d", got, prior)
				}
			}
		})
	}
}

// mergeTestZone builds a zone with a journal, then hands back a SECOND
// ZoneData built from a different file text -- the "restart after someone
// replaced the zone file" situation, with the journal from the first still in
// the database.
func mergeTestZone(t *testing.T, kdb *KeyDB, newFile string, adds, dels []string) *ZoneData {
	t.Helper()

	live := testZone(t, "example.", deltaZone)
	registerZones(t, live)
	live.KeyDB = kdb
	live.UpdatePolicy = policyAllowing(dns.TypeA, dns.TypeTXT)

	for _, rr := range adds {
		actions, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{
			Verb: VerbAddRR, RRs: []string{rr},
		})
		if err != nil {
			t.Fatalf("build addrr: %v", err)
		}
		if _, err := live.ApplyZoneUpdateToZoneData(UpdateRequest{
			Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: actions,
		}, kdb); err != nil {
			t.Fatalf("apply addrr: %v", err)
		}
	}
	for _, rr := range dels {
		actions, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{
			Verb: VerbDelRR, RRs: []string{rr},
		})
		if err != nil {
			t.Fatalf("build delrr: %v", err)
		}
		if _, err := live.ApplyZoneUpdateToZoneData(UpdateRequest{
			Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: actions,
		}, kdb); err != nil {
			t.Fatalf("apply delrr: %v", err)
		}
	}

	// The restart: a new ZoneData from the REPLACED file.
	fresh := testZone(t, "example.", newFile)
	registerZones(t, fresh)
	fresh.KeyDB = kdb
	fresh.UpdatePolicy = policyAllowing(dns.TypeA, dns.TypeTXT)
	fresh.Zonefile = filepath.Join(t.TempDir(), "example.zone")
	return fresh
}

// TestMergeKeepsBothSidesWhenTheyDoNotOverlap is the case that should just
// work: the operator edited part of the zone the journal never touches.
func TestMergeKeepsBothSidesWhenTheyDoNotOverlap(t *testing.T) {
	kdb := newTestKeyDB(t)

	// The operator's replacement file: a new record, and a higher serial.
	const replaced = `example.	3600	IN	SOA	ns.example. hostmaster.example. 9 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
old.example.	3600	IN	TXT	"remove me"
operator.example.	3600	IN	A	10.9.9.9
`
	zd := mergeTestZone(t, kdb, replaced, []string{"journal.example. 3600 IN A 10.1.1.1"}, nil)

	res, err := zd.MergeJournalOverNewFile(kdb)
	if err != nil {
		t.Fatalf("MergeJournalOverNewFile: %v", err)
	}
	if len(res.Conflicts) != 0 {
		t.Fatalf("got %d conflicts on disjoint edits, want 0", len(res.Conflicts))
	}
	// Both sides survive.
	if !hasARRset(t, zd, "operator.example.") {
		t.Error("the operator's new record did not survive the merge")
	}
	if !hasARRset(t, zd, "journal.example.") {
		t.Error("the journalled record did not survive the merge")
	}
}

// TestMergeDBWinsAndRecordsTheLoser: the journal deletes a record the
// operator's new file still has. db-wins, and the artefact says what it cost.
func TestMergeDBWinsAndRecordsTheLoser(t *testing.T) {
	kdb := newTestKeyDB(t)

	// The operator's file still carries www 192.0.2.1, which the journal deleted.
	const replaced = `example.	3600	IN	SOA	ns.example. hostmaster.example. 9 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
old.example.	3600	IN	TXT	"remove me"
`
	zd := mergeTestZone(t, kdb, replaced, nil, []string{"www.example. 3600 IN A 192.0.2.1"})

	res, err := zd.MergeJournalOverNewFile(kdb)
	if err != nil {
		t.Fatalf("MergeJournalOverNewFile: %v", err)
	}
	if len(res.Conflicts) != 1 {
		t.Fatalf("got %d conflicts, want 1", len(res.Conflicts))
	}
	if hasARRset(t, zd, "www.example.") {
		t.Error("db-wins did not win: the deleted record is still served")
	}
	if res.Artefact == "" {
		t.Fatal("a conflict was resolved but no .rejected artefact was written")
	}

	// The artefact must restore the file's version when replayed.
	body, err := os.ReadFile(res.Artefact)
	if err != nil {
		t.Fatalf("reading the artefact: %v", err)
	}
	back, err := ParseUpdateInstructions(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("the artefact does not parse back: %v", err)
	}
	actions, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{
		Verb: VerbInstructions, Instructions: back,
	})
	if err != nil {
		t.Fatalf("building the artefact into an update: %v", err)
	}
	if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: actions,
	}, kdb); err != nil {
		t.Fatalf("replaying the artefact: %v", err)
	}
	if !hasARRset(t, zd, "www.example.") {
		t.Error("replaying the artefact did not restore the operator's record")
	}
}

// TestMergeReAnchorsTheJournal is what makes a merge repeatable. Afterwards the
// journal must chain from the file in hand -- otherwise the next load merges
// again, re-applying changes the zone already has and re-reporting resolved
// conflicts.
func TestMergeReAnchorsTheJournal(t *testing.T) {
	kdb := newTestKeyDB(t)
	const replaced = `example.	3600	IN	SOA	ns.example. hostmaster.example. 9 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
old.example.	3600	IN	TXT	"remove me"
`
	zd := mergeTestZone(t, kdb, replaced, []string{"journal.example. 3600 IN A 10.1.1.1"}, nil)
	fileSerial := zd.fileSerial

	if _, err := zd.MergeJournalOverNewFile(kdb); err != nil {
		t.Fatalf("MergeJournalOverNewFile: %v", err)
	}

	info, err := zd.JournalInfo(false)
	if err != nil {
		t.Fatalf("JournalInfo: %v", err)
	}
	if info.Deltas == 0 {
		t.Fatal("the merge left no journal at all; the merged change is in neither file nor journal")
	}
	if info.AnchorSerial != fileSerial {
		t.Fatalf("journal anchors at %d, want the new file's serial %d",
			info.AnchorSerial, fileSerial)
	}
	if !info.Replayable {
		t.Fatalf("the re-anchored journal does not replay: %s", info.Diagnosis)
	}
}

// TestMergeLiftsTheSerialClearOfWhatWasServed. The dnslab. shape: the
// replacement file's serial is BELOW what secondaries have already been handed.
func TestMergeLiftsTheSerialClearOfWhatWasServed(t *testing.T) {
	kdb := newTestKeyDB(t)

	// A secondary has already been handed serial 500.
	if err := kdb.SaveOutgoingSerial("example.", 500); err != nil {
		t.Fatalf("SaveOutgoingSerial: %v", err)
	}

	// ...and the operator restores a file at serial 9.
	const replaced = `example.	3600	IN	SOA	ns.example. hostmaster.example. 9 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
old.example.	3600	IN	TXT	"remove me"
`
	zd := mergeTestZone(t, kdb, replaced, []string{"journal.example. 3600 IN A 10.1.1.1"}, nil)

	if _, err := zd.MergeJournalOverNewFile(kdb); err != nil {
		t.Fatalf("MergeJournalOverNewFile: %v", err)
	}
	if !serialNewer(zd.CurrentSerial, 500) {
		t.Fatalf("merged serial %d does not advance past the served serial 500;"+
			" secondaries would never refresh", zd.CurrentSerial)
	}
}

// TestMergeWithAnEmptyJournalIsANoOp. A file that changed with nothing
// journalled is just a new zone, not a conflict of any kind.
func TestMergeWithAnEmptyJournalIsANoOp(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := testZone(t, "example.", deltaZone)
	registerZones(t, zd)
	zd.KeyDB = kdb

	res, err := zd.MergeJournalOverNewFile(kdb)
	if err != nil {
		t.Fatalf("MergeJournalOverNewFile: %v", err)
	}
	if len(res.Conflicts) != 0 || len(res.Instructions) != 0 {
		t.Fatalf("an empty journal produced %d conflicts / %d instructions",
			len(res.Conflicts), len(res.Instructions))
	}
}
