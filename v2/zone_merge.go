/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/miekg/dns"
)

// Reconciling a replaced zone file with the delta journal.
//
// When the file changed (ZoneFileChanged, see zone_file_state.go) the journal
// was computed against a file that no longer exists. Refusing the whole journal
// is what the code did before, and it loses every change the journal held while
// telling the operator their zone file was tampered with. Merging keeps both
// sides, and names the few records where they genuinely disagree.
//
// The resolution here is DB-WINS: the journal's version of a contested record
// is what the zone serves. See ZoneConflictPolicy for the other direction.

// ZoneConflictPolicy selects who wins a contested record.
type ZoneConflictPolicy int

const (
	// ConflictDBWins: the journal's version is served, and the zone file's
	// losing records are written to the .rejected artefact.
	ConflictDBWins ZoneConflictPolicy = iota
	// ConflictZonefileWins: the zone file's version is served, and the
	// journal's losing instructions go to the artefact instead.
	ConflictZonefileWins
)

func (p ZoneConflictPolicy) String() string {
	if p == ConflictZonefileWins {
		return "zonefile-wins"
	}
	return "db-wins"
}

// ZoneMergeConflict is one record the two sides disagree about.
type ZoneMergeConflict struct {
	// RR is the record as the zone file has it.
	RR string
	// Inverse is the instruction that would restore the file's version, i.e.
	// undo this merge decision for this record.
	Inverse ZoneDeltaRR
}

// ZoneMergeResult reports what a merge decided.
type ZoneMergeResult struct {
	Policy    ZoneConflictPolicy
	Conflicts []ZoneMergeConflict
	Artefact  string // where the inverse was written ("" if nowhere)
	// Instructions is the journal's flattened instruction list, i.e. what was
	// replayed onto the new file.
	Instructions []ZoneDeltaRR
}

// rrKey identifies a record for conflict comparison: owner, type and rdata,
// with the TTL deliberately excluded.
//
// The TTL is not part of a record's identity -- RFC 2136 §2.5.4 ignores it when
// deleting, and this code has to agree with the applier it feeds. Including it
// would report a conflict for a record whose only difference is a TTL the
// deleting side never specified, and then "resolve" it by deleting a record the
// operator still has.
func rrKey(rr dns.RR) string {
	c := dns.Copy(rr)
	c.Header().Ttl = 0
	c.Header().Name = dns.CanonicalName(c.Header().Name)
	return c.String()
}

// findMergeConflicts reports the records the zone file and the journal disagree
// about, given the file as freshly parsed and the journal's instructions.
//
// A conflict is exactly one thing:
//
//	a record present in the NEW zone file that the journal DELETES.
//
// That is the whole set, and the reasoning is worth writing down because the
// design doc originally claimed a second, mirror case -- "the journal adds R
// and the file lacks R" -- which does not exist.
//
// It does not exist because a journal ADD implies the OLD file lacked that
// record: the delta was computed as the difference from that file, so anything
// it adds was absent there. If the new file also lacks it, the two files agree
// and the operator removed nothing. If the new file HAS it, the operator added
// the same record independently, which is agreement, not conflict. Either way
// there is nothing to report and nothing to resolve.
//
// The consequence is that every conflict's inverse is an ADD, and the artefact
// never contains a DEL.
//
// One genuine conflict remains invisible, and no amount of care here would
// surface it: an operator who regenerates the file from the LIVE zone while
// deliberately omitting a record the journal added. That file is
// indistinguishable from one that simply predates the addition, and telling
// them apart needs the old file's contents, which is not something we store.
// Documented rather than guessed at.
func findMergeConflicts(fileRRs []dns.RR, insns []ZoneDeltaRR) ([]ZoneMergeConflict, error) {
	if len(insns) == 0 || len(fileRRs) == 0 {
		return nil, nil
	}

	inFile := make(map[string]dns.RR, len(fileRRs))
	for _, rr := range fileRRs {
		inFile[rrKey(rr)] = rr
	}

	var out []ZoneMergeConflict
	seen := map[string]bool{}

	for _, insn := range insns {
		if insn.Action != ZoneDeltaDel {
			continue
		}
		rr, err := dns.NewRR(insn.RR)
		if err != nil || rr == nil {
			return nil, fmt.Errorf("journal holds an unparseable record %q: %v", insn.RR, err)
		}
		key := rrKey(rr)
		victim, present := inFile[key]
		if !present || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ZoneMergeConflict{
			RR: victim.String(),
			// The inverse of "the journal deleted it" is "add it back".
			Inverse: ZoneDeltaRR{Action: ZoneDeltaAdd, RR: victim.String()},
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].RR < out[j].RR })
	return out, nil
}

// writeRejectedArtefact writes the merge's inverse to {zonefile}.{serial}.rejected.
//
// The file is not a description of what was rejected; it is the update that
// would undo the merge's decisions in favour of the zone file. An operator who
// disagrees edits it down to the records they care about and feeds it straight
// back through `zone update from-file`. A descriptive listing would make that a
// retyping exercise.
func writeRejectedArtefact(zonefile string, zone string, serial uint32,
	policy ZoneConflictPolicy, conflicts []ZoneMergeConflict) (string, error) {

	if zonefile == "" || len(conflicts) == 0 {
		return "", nil
	}
	path := fmt.Sprintf("%s.%d.rejected", zonefile, serial)

	insns := make([]ZoneDeltaRR, 0, len(conflicts))
	for _, c := range conflicts {
		insns = append(insns, c.Inverse)
	}

	comments := []string{
		"tdns: records from your zone file that lost a merge with the delta journal",
		fmt.Sprintf("zone:     %s", zone),
		fmt.Sprintf("file:     %s (serial %d)", zonefile, serial),
		fmt.Sprintf("policy:   %s", policy),
		fmt.Sprintf("merged:   %s", time.Now().Format(time.RFC3339)),
		"",
		"These are NOT a log of what happened -- they are the update that would put",
		"your version back. Delete the lines you agree with, keep the ones you do",
		"not, and replay what is left:",
		"",
		fmt.Sprintf("  tdns-cli auth zone update from-file --file %s --zone %s --via api",
			path, zone),
	}

	var buf bytes.Buffer
	if err := WriteUpdateInstructions(&buf, comments, insns); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		return "", err
	}
	return path, nil
}

// mergeSerialFloor returns the serial the merged zone must publish at: strictly
// newer (RFC 1982) than everything this server has already served AND than the
// new file's own serial.
//
// The second condition alone is not enough, and dnslab. is the live example --
// file at ...01, served at ...03, journal head at ...06. Publishing the merge at
// ...02 would take the zone BACKWARDS for every secondary already holding ...03:
// they would ignore the new content indefinitely, since a secondary refreshes on
// a serial increase and nothing else.
func mergeSerialFloor(fileSerial, servedSerial, journalHead uint32) uint32 {
	floor := fileSerial
	if serialNewer(servedSerial, floor) {
		floor = servedSerial
	}
	if serialNewer(journalHead, floor) {
		floor = journalHead
	}
	return floor + 1
}
