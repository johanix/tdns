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
