/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
// The comparison is on the RFC 4034 canonical wire form, not the presentation
// string, because domain names inside RDATA are case-insensitive too. A file
// spelling an NS target "NS1.Example.COM." and a journal spelling it
// "ns1.example.com." are the same record, and comparing presentation strings
// would call them different -- missing the conflict and deleting a record the
// operator still has.
func rrKey(rr dns.RR) string {
	c := dns.Copy(rr)
	c.Header().Ttl = 0
	if wire, _, err := canonicalRRWire(c); err == nil {
		return string(wire)
	}
	// Packing failed, which for a record we just parsed means something exotic.
	// The presentation form still identifies it; it only misses case
	// equivalence inside RDATA, which is strictly better than dropping it.
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
		// Abort rather than skip. This matches instructionActions, which the
		// merge feeds a few steps later and which fails on the same record --
		// so skipping here would only move the failure, not avoid it, and would
		// meanwhile have resolved conflicts against a record it could not read.
		// A corrupt journal is a thing to report, not to route around; nothing
		// is destroyed by refusing, and the journal is still there afterwards.
		rr, err := dns.NewRR(insn.RR)
		if err != nil {
			return nil, fmt.Errorf("journal holds an unparseable record %q: %v", insn.RR, err)
		}
		if rr == nil {
			return nil, fmt.Errorf("journal holds %q, which is not a resource record", insn.RR)
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

// freeArtefactPath returns the first unused "<base>.N" beside an artefact whose
// name is already taken by different content.
func freeArtefactPath(base string) (string, error) {
	for n := 1; n <= 1000; n++ {
		candidate := fmt.Sprintf("%s.%d", base, n)
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate, nil
		} else if err != nil {
			return "", err
		}
	}
	return "", fmt.Errorf("no free name beside %s after 1000 tries", base)
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

	insns := make([]ZoneDeltaRR, 0, len(conflicts))
	for _, c := range conflicts {
		insns = append(insns, c.Inverse)
	}
	return writeRejectedArtefactInstructions(zonefile, zone, serial, policy, insns)
}

// writeRejectedArtefactInstructions writes an already-composed instruction list.
// Under db-wins those are ADDs restoring the zone file's records; under
// zonefile-wins they are the journal's DELETEs that were not applied.
func writeRejectedArtefactInstructions(zonefile string, zone string, serial uint32,
	policy ZoneConflictPolicy, insns []ZoneDeltaRR) (string, error) {

	// Nothing to write is fine and common. Nowhere to write it is not: the
	// caller refuses the merge on an error from here, and returning a nil error
	// with an empty path would let it resolve conflicts in the journal's favour
	// without ever telling the operator which of their records lost. That is
	// the silent loss this whole path exists to prevent, so the two cases have
	// to be distinguishable.
	if len(insns) == 0 {
		return "", nil
	}
	if zonefile == "" {
		return "", fmt.Errorf("zone %s has no zone file path, so the %d record(s) that lose"+
			" the merge cannot be written anywhere", zone, len(insns))
	}
	path := fmt.Sprintf("%s.%d.rejected", zonefile, serial)

	losing := "records from your zone file that lost a merge with the delta journal"
	if policy == ConflictZonefileWins {
		losing = "changes from the delta journal that lost a merge with your zone file"
	}

	comments := []string{
		"tdns: " + losing,
		fmt.Sprintf("zone:     %s", zone),
		fmt.Sprintf("file:     %s (serial %d)", zonefile, serial),
		fmt.Sprintf("policy:   %s", policy),
		fmt.Sprintf("merged:   %s", time.Now().Format(time.RFC3339)),
		"",
		"These are NOT a log of what happened -- they are the update that would",
		"REVERSE the decisions below. Delete the lines you agree with, keep the",
		"ones you do not, and replay what is left:",
		"",
		fmt.Sprintf("  tdns-cli auth zone update from-file --file %s --zone %s --via api",
			path, zone),
	}

	var buf bytes.Buffer
	if err := WriteUpdateInstructions(&buf, comments, insns); err != nil {
		return "", err
	}
	// The path is keyed on the file's serial, which is not unique: a merge that
	// fails after writing the artefact is retried on the next load and writes
	// the same path again, and a regenerated file can reuse a serial. Rewriting
	// identical content is what the retry needs, so allow exactly that -- but
	// never overwrite an artefact holding something else, because the operator
	// may be part-way through replaying it and the losing records exist nowhere
	// else.
	//
	// Whatever occupies the path has to be a regular file first. os.ReadFile on
	// a DIRECTORY succeeds on some systems (NetBSD returns raw dirent bytes)
	// and fails on others, so without this check the same directory either
	// diverted the artefact to a sibling name or fell through to the rename --
	// platform-dependent behaviour for an operator mistake that should simply
	// be reported.
	if fi, serr := os.Stat(path); serr == nil && !fi.Mode().IsRegular() {
		return "", fmt.Errorf("cannot write the rejected-records artefact for zone %s:"+
			" %s exists and is not a regular file", zone, path)
	}
	if existing, rerr := os.ReadFile(path); rerr == nil {
		if bytes.Equal(existing, buf.Bytes()) {
			return path, nil
		}
		alt, aerr := freeArtefactPath(path)
		if aerr != nil {
			return "", aerr
		}
		path = alt
	}

	// Write through a temporary file in the same directory and rename. A
	// half-written artefact is worse than none at all: the operator is told to
	// feed this straight back through `zone update from-file`, and a truncated
	// file replays as though it were the complete set of records to restore.
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name()) // no-op once the rename below has succeeded
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp.Name(), 0644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}
	return path, nil
}

// mergeSerialFloor returns the serial the merged zone must publish at: strictly
// newer (RFC 1982) than everything this server has already served AND than the
// new file's own serial.
//
// The second condition alone is not enough. Take a file at ...01, a served
// serial of ...03 and a journal head at ...06: publishing the merge at
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

// MergeJournalOverNewFile reconciles a REPLACED zone file with the delta
// journal, and returns what it decided.
//
// Called instead of ReplayPersistedDeltas when the file's digest says it
// changed. The distinction matters: replay asserts the chain starts at this
// file and refuses otherwise, which is right when the file is the one the
// journal was computed against and wrong -- destructively wrong, since it
// discards every journalled change -- when it is not.
//
// The sequence, and why it is this order:
//
//  1. Snapshot the file as parsed. Conflict detection needs the file BEFORE
//     the journal touches it, and so does the re-anchor in step 6.
//  2. Find conflicts and write the artefact FIRST, before applying anything.
//     An artefact written after a failed apply describes a merge that did not
//     happen; one written before describes a decision we are about to make.
//  3. Lift the serial clear of everything already served, BEFORE applying, so
//     one publish does it.
//  4. Apply the journal (db-wins).
//  5. Re-anchor: replace the whole journal with one delta from THIS file.
//
// Step 5 is what makes the merge repeatable. Without it the chain still claims
// to start at a file that no longer exists, so the next load merges again --
// re-applying changes the zone already has and re-reporting conflicts already
// resolved.
// The error contract is two-valued on purpose, because the two failure modes
// need opposite advice:
//
//	(nil, err) -- nothing was applied. The zone serves its file alone and the
//	              journal is untouched, so the operator's recent changes are
//	              NOT present.
//	(res, err) -- the merge WAS applied and published; only the journal
//	              re-anchoring afterwards failed. The changes ARE present, and
//	              the cost is that the next load will merge again.
//
// Telling an operator their changes are missing when the zone is in fact
// serving them invites a restore or a replay on top of a zone that already has
// them, which is how a reporting bug becomes a data-loss bug.
func (zd *ZoneData) MergeJournalOverNewFile(kdb *KeyDB) (*ZoneMergeResult, error) {
	if zd == nil || kdb == nil {
		return nil, fmt.Errorf("no zone or no database")
	}

	insns, journalMaxID, err := zd.JournalInstructions()
	if err != nil {
		return nil, err
	}
	policy := zoneConflictPolicy(zd)

	if len(insns) == 0 {
		// Nothing to reconcile: the file changed but the journal is empty, so
		// the file is simply the zone. This is the common case after any
		// write-out, and it is not a conflict of any kind.
		return &ZoneMergeResult{Policy: policy}, nil
	}

	// (1) The file as parsed, before the journal is applied to it.
	fileSnap := zd.publishedSnapshot()
	if fileSnap == nil {
		return nil, fmt.Errorf("zone %s: no published snapshot to merge onto", zd.ZoneName)
	}
	fileData := fileSnap.Data
	fileRRs := zoneRRsFromSnapshot(fileSnap)

	zd.mu.Lock()
	fileSerial := zd.fileSerial
	zonefile := zd.Zonefile
	zd.mu.Unlock()

	// (2) Conflicts, and the inverse on disk before anything is applied.
	conflicts, err := findMergeConflicts(fileRRs, insns)
	if err != nil {
		return nil, err
	}
	res := &ZoneMergeResult{Policy: policy, Conflicts: conflicts, Instructions: insns}

	// Which instructions actually get applied, and what the artefact records,
	// both depend on who wins. The two directions are mirror images: the
	// artefact is always the update that would flip the merge's decision.
	apply, artefactInsns := applicableInstructions(insns, conflicts, policy)

	if len(artefactInsns) > 0 {
		path, werr := writeRejectedArtefactInstructions(zonefile, zd.ZoneName, fileSerial,
			policy, artefactInsns)
		if werr != nil {
			// Refuse the merge. Resolving conflicts in the journal's favour
			// without being able to tell the operator which of their records
			// lost is precisely the silent data loss this design exists to
			// avoid -- and the zone still serves the file, which is intact.
			return nil, fmt.Errorf("zone %s: refusing to merge, because the records that would"+
				" lose could not be saved to %s.%d.rejected: %v",
				zd.ZoneName, zonefile, fileSerial, werr)
		}
		res.Artefact = path
	}

	// (3) Lift the serial BEFORE applying, so the publish the apply performs
	// lands above everything already served rather than needing a second bump
	// afterwards (which secondaries would see as two changes, and which the
	// configured outbound-soa-serial mode would have to be fought over twice).
	//
	// LoadOutgoingSerial is the durable record of what secondaries have been
	// handed. Without this floor the merged zone can publish BELOW a serial one
	// of them already holds, and a secondary refreshes on a serial increase and
	// nothing else -- so it would serve the pre-merge zone indefinitely.
	//
	// Raising CurrentSerial rather than setting the final value: every bump
	// mode only ever moves forward, so starting the publish one below the floor
	// guarantees it lands at or above it whatever the mode.
	// A zone that has never notified a secondary has no outgoing serial, and
	// that is the normal case rather than a failure -- sql.ErrNoRows here means
	// "nothing has been served yet", so the floor is simply the file's own
	// serial. Only a real database error is worth warning about.
	outgoing, oerr := kdb.LoadOutgoingSerial(zd.ZoneName)
	if oerr != nil {
		outgoing = 0
		if !errors.Is(oerr, sql.ErrNoRows) {
			lg.Warn("could not read the outgoing serial; the merged zone may publish below"+
				" a serial some secondary already holds",
				"zone", zd.ZoneName, "error", oerr)
		}
	}
	zd.mu.Lock()
	floor := mergeSerialFloor(fileSerial, outgoing, zd.CurrentSerial)
	if serialNewer(floor-1, zd.CurrentSerial) {
		lg.Info("lifting the merged zone's serial clear of what has already been served",
			"zone", zd.ZoneName, "from", zd.CurrentSerial, "floor", floor,
			"file_serial", fileSerial, "outgoing_serial", outgoing)
		zd.CurrentSerial = floor - 1
	}
	zd.mu.Unlock()

	// (4) Apply. InternalUpdate: these changes were authorized when first
	// applied. Replay: suppresses re-persisting what we are replaying, since
	// step 5 rewrites the journal wholesale.
	if len(apply) == 0 {
		// zonefile-wins where every instruction was contested: the file already
		// says everything the merge would have said.
		lg.Info("zone file wins every contested record; nothing from the journal to apply",
			"zone", zd.ZoneName, "conflicts", len(conflicts))
	}
	actions, err := UpdateInstructionActions(apply)
	if err != nil {
		return nil, err
	}
	if len(actions) > 0 {
		if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
			Cmd:            "ZONE-UPDATE",
			ZoneName:       zd.ZoneName,
			Actions:        actions,
			InternalUpdate: true,
			Replay:         true,
			Description:    "merge of persisted deltas over a replaced zone file",
		}, kdb); err != nil {
			return nil, fmt.Errorf("zone %s: applying the journal to the new file: %v",
				zd.ZoneName, err)
		}
	}

	// (5) Re-anchor. The journal now means exactly "what this file does not
	// have", which is what it is supposed to mean and what the next load will
	// check it against.
	mergedSnap := zd.publishedSnapshot()
	if mergedSnap == nil {
		// Past this point the merge is APPLIED and the zone is serving it, so
		// every failure below returns the result alongside the error. See the
		// contract on MergeJournalOverNewFile.
		return res, fmt.Errorf("zone %s: no snapshot after the merge", zd.ZoneName)
	}
	removed, added, _ := computeZoneDelta(zd.ZoneName, fileData, mergedSnap.Data)
	if len(removed) == 0 && len(added) == 0 {
		// The merge changed nothing the file did not already have. Then the
		// file IS the zone and the journal has nothing left to carry.
		// Bounded by what this merge read, for the same reason
		// ReplaceZoneJournal is: a delta persisted since then is not in the
		// file either, so clearing it would lose it outright.
		if _, derr := kdb.DeleteZoneDeltasThroughID(zd.ZoneName, journalMaxID); derr != nil {
			return res, fmt.Errorf("zone %s: clearing a journal the file already contains: %v",
				zd.ZoneName, derr)
		}
	} else if rerr := kdb.ReplaceZoneJournal(zd.ZoneName, fileSerial,
		mergedSnap.Serial, removed, added, journalMaxID); rerr != nil {
		return res, fmt.Errorf("zone %s: re-anchoring the journal to the new file: %v",
			zd.ZoneName, rerr)
	}

	zd.mu.Lock()
	zd.deltasReplayed = true
	// Dirty: the file demonstrably lacks what was just merged in, and dirty is
	// the flag that says "memory differs from disk". Guarded because a nil
	// Options map must not panic the LOAD path -- a zone that fails to come up
	// is a worse outcome than a zone that comes up without a dirty flag.
	if zd.Options == nil {
		zd.Options = map[ZoneOption]bool{}
	}
	zd.Options[OptDirty] = true
	zd.mu.Unlock()

	return res, nil
}

// zoneConflictPolicy reads the policy the zone runs under.
//
// Exactly one of the two options is always set: the config parser materialises
// db-wins when neither is given, and rejects both together. So this is a
// question with two answers, not three, and there is no default to remember
// here. The fallback below exists only for a ZoneData built outside the config
// parser (tests, mainly) and agrees with the parser's default.
func zoneConflictPolicy(zd *ZoneData) ZoneConflictPolicy {
	if zd == nil {
		return ConflictDBWins
	}
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.Options[OptOnConflictZonefileWins] {
		return ConflictZonefileWins
	}
	return ConflictDBWins
}

// applicableInstructions returns the journal instructions to apply under the
// given policy, and the artefact contents describing what lost.
//
// Under db-wins every instruction is applied, and the artefact holds ADDs that
// would put the file's contested records back.
//
// Under zonefile-wins the contested DELETES are DROPPED -- the file keeps its
// records -- and the artefact holds those same deletes, so an operator who
// decides the journal was right after all can replay them. The two directions
// are mirror images: in both cases the artefact is the update that would flip
// the merge's decision.
func applicableInstructions(insns []ZoneDeltaRR, conflicts []ZoneMergeConflict,
	policy ZoneConflictPolicy) (apply []ZoneDeltaRR, artefact []ZoneDeltaRR) {

	if policy == ConflictDBWins {
		art := make([]ZoneDeltaRR, 0, len(conflicts))
		for _, c := range conflicts {
			art = append(art, c.Inverse)
		}
		return insns, art
	}

	// zonefile-wins: drop the deletes that contest a record the file still has.
	contested := make(map[string]bool, len(conflicts))
	for _, c := range conflicts {
		if rr, err := dns.NewRR(c.RR); err == nil && rr != nil {
			contested[rrKey(rr)] = true
		}
	}

	apply = make([]ZoneDeltaRR, 0, len(insns))
	for _, insn := range insns {
		if insn.Action == ZoneDeltaDel {
			if rr, err := dns.NewRR(insn.RR); err == nil && rr != nil && contested[rrKey(rr)] {
				// The journal wanted this gone; the file still has it and the
				// file wins. Record the instruction so the decision can be
				// reversed, and do not apply it.
				artefact = append(artefact, insn)
				continue
			}
		}
		apply = append(apply, insn)
	}
	return apply, artefact
}
