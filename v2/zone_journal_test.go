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

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// journalRRset wraps one record as the single-RRset slice PersistZoneDelta
// takes, for the tests that write to the store directly.
func journalRRset(t *testing.T, rrstr string) []core.RRset {
	t.Helper()
	rr, err := dns.NewRR(rrstr)
	if err != nil {
		t.Fatalf("parsing %q: %v", rrstr, err)
	}
	return []core.RRset{{
		Name:   rr.Header().Name,
		Class:  dns.ClassINET,
		RRtype: rr.Header().Rrtype,
		RRs:    []dns.RR{rr},
	}}
}

// journalTestZone builds a zone with a journal already in it: two applied
// updates, so the chain has two links. Returns the zone and its file serial.
func journalTestZone(t *testing.T, kdb *KeyDB) *ZoneData {
	t.Helper()

	zd := testZone(t, "example.", deltaZone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.UpdatePolicy = policyAllowing(dns.TypeA, dns.TypeTXT)

	for _, rr := range []string{
		"one.example. 3600 IN A 10.0.0.1",
		"two.example. 3600 IN A 10.0.0.2",
	} {
		actions, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{
			Verb: VerbAddRR, RRs: []string{rr},
		})
		if err != nil {
			t.Fatalf("build addrr %q: %v", rr, err)
		}
		if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
			Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: actions,
		}, kdb); err != nil {
			t.Fatalf("apply %q: %v", rr, err)
		}
	}
	return zd
}

// TestJournalStatusReportsAReplayableChain is the baseline: a healthy journal
// must report itself as such, and its numbers must describe what is in it.
func TestJournalStatusReportsAReplayableChain(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := journalTestZone(t, kdb)

	info, err := zd.JournalInfo(false)
	if err != nil {
		t.Fatalf("JournalInfo: %v", err)
	}
	if info.Deltas != 2 {
		t.Fatalf("Deltas = %d, want 2", info.Deltas)
	}
	if info.Records != 2 {
		t.Fatalf("Records = %d, want 2", info.Records)
	}
	if !info.Replayable {
		t.Fatalf("a chain built by ordinary updates reports Replayable=false: %s", info.Diagnosis)
	}
	if info.AnchorSerial != zd.fileSerial {
		t.Fatalf("AnchorSerial = %d, want the file serial %d", info.AnchorSerial, zd.fileSerial)
	}
	if info.HeadSerial != zd.CurrentSerial {
		t.Fatalf("HeadSerial = %d, want the served serial %d", info.HeadSerial, zd.CurrentSerial)
	}
}

// TestJournalStatusDiagnosesAnUnreplayableChain covers the cpt-proxy case: the
// zone file has been replaced, so the chain no longer starts where the file
// does. status must say so, and say it in the same words the load path would.
func TestJournalStatusDiagnosesAnUnreplayableChain(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := journalTestZone(t, kdb)

	// Someone replaced the zone file behind the server's back.
	zd.mu.Lock()
	zd.fileSerial = 99
	zd.mu.Unlock()

	info, err := zd.JournalInfo(false)
	if err != nil {
		t.Fatalf("JournalInfo: %v", err)
	}
	if info.Replayable {
		t.Fatal("a chain that does not start at the file reports Replayable=true")
	}
	if !strings.Contains(info.Diagnosis, "do not chain from this zone file") {
		t.Fatalf("Diagnosis does not name the problem: %q", info.Diagnosis)
	}
}

// TestPersistZoneDeltaRefusesANonAdvancingSerial is the §11 bug: the situation
// that produced a bare SQLite UNIQUE constraint on every single update must now
// produce a diagnosis naming the zone, the serials and where to look.
func TestPersistZoneDeltaRefusesANonAdvancingSerial(t *testing.T) {
	kdb := newTestKeyDB(t)

	rrset := journalRRset(t, "www.example. 3600 IN A 192.0.2.9")

	// The exact shape from cpt-proxy: the journal is at 06, the zone publishes
	// 04, because a replaced file left the two in different serial spaces.
	err := kdb.PersistZoneDelta("example.", 2026081706, 2026081704, nil, rrset)
	if err == nil {
		t.Fatal("a delta going backwards was accepted")
	}
	if strings.Contains(err.Error(), "UNIQUE constraint") {
		t.Fatalf("the operator still gets a raw SQLite error: %v", err)
	}
	for _, want := range []string{"does not advance", "example.", "journal status"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error does not mention %q: %v", want, err)
		}
	}
}

// TestPersistZoneDeltaRefusesACollidingSerial is the same defence one step
// over: the serial advances, but the journal already holds a delta ending
// there. Also a UNIQUE violation before this change.
func TestPersistZoneDeltaRefusesACollidingSerial(t *testing.T) {
	kdb := newTestKeyDB(t)
	rrset := journalRRset(t, "www.example. 3600 IN A 192.0.2.9")

	if err := kdb.PersistZoneDelta("example.", 10, 11, nil, rrset); err != nil {
		t.Fatalf("first delta: %v", err)
	}
	err := kdb.PersistZoneDelta("example.", 10, 11, nil, rrset)
	if err == nil {
		t.Fatal("a second delta at the same toserial was accepted")
	}
	if strings.Contains(err.Error(), "UNIQUE constraint") {
		t.Fatalf("the operator still gets a raw SQLite error: %v", err)
	}
	if !strings.Contains(err.Error(), "already holds a delta ending at") {
		t.Fatalf("error does not name the collision: %v", err)
	}
}

// TestJournalPurgeRefusesAHealthyJournalWithoutForce: a journal that will
// replay holds the only copy of those changes, so discarding it is a decision,
// not a cleanup.
func TestJournalPurgeRefusesAHealthyJournalWithoutForce(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := journalTestZone(t, kdb)

	if _, err := zd.JournalPurge(false); err == nil {
		t.Fatal("purge discarded a healthy journal without --force")
	} else if !strings.Contains(err.Error(), "zone sync") {
		t.Fatalf("the refusal does not point at the lossless alternative: %v", err)
	}

	// And the journal is still there.
	info, err := zd.JournalInfo(false)
	if err != nil {
		t.Fatalf("JournalInfo: %v", err)
	}
	if info.Deltas != 2 {
		t.Fatalf("a refused purge changed the journal: Deltas = %d, want 2", info.Deltas)
	}
}

// TestJournalPurgeAllowsAnUnreplayableJournal: the changes are already absent
// from what the zone serves, so there is nothing left to protect and requiring
// a flag would only obstruct the remedy.
func TestJournalPurgeAllowsAnUnreplayableJournal(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := journalTestZone(t, kdb)

	zd.mu.Lock()
	zd.fileSerial = 99
	zd.mu.Unlock()

	res, err := zd.JournalPurge(false)
	if err != nil {
		t.Fatalf("purge of an unreplayable journal was refused: %v", err)
	}
	if res.Deltas != 2 {
		t.Fatalf("purged Deltas = %d, want 2", res.Deltas)
	}
	if len(res.Instructions) != 2 {
		t.Fatalf("purge returned %d instructions, want 2", len(res.Instructions))
	}

	info, err := zd.JournalInfo(false)
	if err != nil {
		t.Fatalf("JournalInfo: %v", err)
	}
	if info.Deltas != 0 {
		t.Fatalf("journal survived the purge: Deltas = %d", info.Deltas)
	}
}

// TestJournalPurgeWritesTheArtefactBeforeDiscarding is what makes purge
// different from deleting the rows: the content must be on disk, in a form
// that can be replayed, before anything is destroyed.
func TestJournalPurgeWritesTheArtefactBeforeDiscarding(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := journalTestZone(t, kdb)
	zd.Zonefile = filepath.Join(t.TempDir(), "example.zone")

	res, err := zd.JournalPurge(true)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if res.Artefact == "" {
		t.Fatal("purge wrote no artefact")
	}

	body, err := os.ReadFile(res.Artefact)
	if err != nil {
		t.Fatalf("reading the artefact: %v", err)
	}
	// Round-trip: what was written must parse back into what was discarded.
	back, err := ParseUpdateInstructions(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("the artefact does not parse back: %v", err)
	}
	if len(back) != len(res.Instructions) {
		t.Fatalf("artefact holds %d instructions, purge discarded %d",
			len(back), len(res.Instructions))
	}
	for i := range back {
		if back[i] != res.Instructions[i] {
			t.Fatalf("instruction %d round-tripped as %+v, want %+v", i, back[i], res.Instructions[i])
		}
	}
}

// TestJournalTruncateDropsOnlyTheTail. The chain must remain replayable after
// a truncate, which is the entire reason middle deltas cannot be removed.
func TestJournalTruncateDropsOnlyTheTail(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := journalTestZone(t, kdb)

	before, err := zd.JournalInfo(false)
	if err != nil {
		t.Fatalf("JournalInfo: %v", err)
	}
	firstEnd := before.Deltalist[0].ToSerial

	if _, err := zd.JournalTruncate(firstEnd); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	after, err := zd.JournalInfo(false)
	if err != nil {
		t.Fatalf("JournalInfo: %v", err)
	}
	if after.Deltas != 1 {
		t.Fatalf("Deltas after truncate = %d, want 1", after.Deltas)
	}
	if after.HeadSerial != firstEnd {
		t.Fatalf("HeadSerial = %d, want %d", after.HeadSerial, firstEnd)
	}
	if !after.Replayable {
		t.Fatalf("truncation left an unreplayable chain: %s", after.Diagnosis)
	}
}

// TestJournalTruncateRefusesAnUnknownSerial. "Keep everything through 12345"
// is unambiguous when 12345 is a real boundary and a guess otherwise, and
// guessing silently discards changes.
func TestJournalTruncateRefusesAnUnknownSerial(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := journalTestZone(t, kdb)

	if _, err := zd.JournalTruncate(4242); err == nil {
		t.Fatal("truncate accepted a serial that is not a chain boundary")
	} else if !strings.Contains(err.Error(), "no journal delta ends at serial") {
		t.Fatalf("unhelpful error: %v", err)
	}

	info, err := zd.JournalInfo(false)
	if err != nil {
		t.Fatalf("JournalInfo: %v", err)
	}
	if info.Deltas != 2 {
		t.Fatalf("a refused truncate changed the journal: Deltas = %d, want 2", info.Deltas)
	}
}

// TestInstructionRoundTrip: write, read back, get the same list.
func TestInstructionRoundTrip(t *testing.T) {
	in := []ZoneDeltaRR{
		{Action: ZoneDeltaAdd, RR: "foo.example.\t3600\tIN\tA\t1.2.3.4"},
		{Action: ZoneDeltaDel, RR: "bar.example.\t3600\tIN\tTXT\t\"a ; not a comment\""},
	}

	var buf bytes.Buffer
	if err := WriteUpdateInstructions(&buf, []string{"a comment"}, in); err != nil {
		t.Fatalf("write: %v", err)
	}

	out, err := ParseUpdateInstructions(&buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("round-tripped %d instructions, wrote %d", len(out), len(in))
	}
	for i := range in {
		if out[i].Action != in[i].Action {
			t.Fatalf("instruction %d: action %q, want %q", i, out[i].Action, in[i].Action)
		}
	}
	// The TXT record carrying a semicolon must survive intact: a parser that
	// stripped trailing comments would silently truncate it into a different
	// record, which is why only leading ';' introduces a comment.
	if !strings.Contains(out[1].RR, "not a comment") {
		t.Fatalf("a ';' inside quoted rdata was treated as a comment: %q", out[1].RR)
	}
}

// TestParseInstructionsNamesTheLine. The file is meant to be hand-edited, so
// an error that does not say WHERE is an error the operator has to bisect.
func TestParseInstructionsNamesTheLine(t *testing.T) {
	const bad = `; a comment

ADD foo.example. 3600 IN A 1.2.3.4
# another comment
DEL this is not a record
`
	_, err := ParseUpdateInstructions(strings.NewReader(bad))
	if err == nil {
		t.Fatal("a malformed record parsed cleanly")
	}
	if !strings.Contains(err.Error(), "line 5") {
		t.Fatalf("error does not name line 5: %v", err)
	}
}

func TestParseInstructionsRejectsUnknownKeyword(t *testing.T) {
	_, err := ParseUpdateInstructions(strings.NewReader("UPSERT foo.example. 3600 IN A 1.2.3.4\n"))
	if err == nil {
		t.Fatal("an unknown instruction keyword was accepted")
	}
	if !strings.Contains(err.Error(), "unknown instruction") || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// TestInstructionsVerbBuildsBothDirections. One update carrying both an add
// and a delete is the whole point of the format; a builder that handled only
// one would make a purge artefact unreplayable.
func TestInstructionsVerbBuildsBothDirections(t *testing.T) {
	actions, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{
		Verb: VerbInstructions,
		Instructions: []ZoneDeltaRR{
			{Action: ZoneDeltaAdd, RR: "foo.example. 3600 IN A 1.2.3.4"},
			{Action: ZoneDeltaDel, RR: "bar.example. 3600 IN A 5.6.7.8"},
		},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(actions) != 2 {
		t.Fatalf("built %d actions, want 2", len(actions))
	}
	if actions[0].Header().Class != dns.ClassINET {
		t.Fatalf("ADD produced class %d, want IN", actions[0].Header().Class)
	}
	if actions[1].Header().Class != dns.ClassNONE {
		t.Fatalf("DEL produced class %d, want NONE", actions[1].Header().Class)
	}
	if actions[1].Header().Ttl != 0 {
		t.Fatalf("DEL kept a TTL of %d; the TTL is not part of RR identity", actions[1].Header().Ttl)
	}
}

// TestInstructionsVerbEnforcesBailiwick. An instruction file is likely to have
// been edited by hand, so a record for another zone -- pasted in, or left over
// from a different artefact -- must be named rather than applied.
func TestInstructionsVerbEnforcesBailiwick(t *testing.T) {
	_, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{
		Verb: VerbInstructions,
		Instructions: []ZoneDeltaRR{
			{Action: ZoneDeltaAdd, RR: "foo.elsewhere. 3600 IN A 1.2.3.4"},
		},
	})
	if err == nil {
		t.Fatal("a record outside the zone was accepted")
	}
	if !strings.Contains(err.Error(), "not in zone") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

// TestPurgedArtefactReplaysThroughTheOrdinaryUpdatePath closes the loop the
// whole design rests on: purge, then feed the artefact back, and the zone
// returns to the state the purge discarded.
func TestPurgedArtefactReplaysThroughTheOrdinaryUpdatePath(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := journalTestZone(t, kdb)
	zd.Zonefile = filepath.Join(t.TempDir(), "example.zone")

	if !hasARRset(t, zd, "one.example.") {
		t.Fatal("precondition: the journalled record is not in the live zone")
	}

	res, err := zd.JournalPurge(true)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}

	body, err := os.ReadFile(res.Artefact)
	if err != nil {
		t.Fatalf("reading the artefact: %v", err)
	}
	insns, err := ParseUpdateInstructions(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("parsing the artefact: %v", err)
	}

	// Apply it to a zone freshly loaded from the file, which is what an
	// operator would be doing: the file never had these records.
	fresh := testZone(t, "example.", deltaZone)
	registerZones(t, fresh)
	fresh.KeyDB = kdb
	fresh.UpdatePolicy = policyAllowing(dns.TypeA, dns.TypeTXT)

	if hasARRset(t, fresh, "one.example.") {
		t.Fatal("precondition: the zone file already contains the journalled record")
	}

	actions, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{
		Verb: VerbInstructions, Instructions: insns,
	})
	if err != nil {
		t.Fatalf("build from artefact: %v", err)
	}
	if _, err := fresh.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: actions,
	}, kdb); err != nil {
		t.Fatalf("apply from artefact: %v", err)
	}

	for _, name := range []string{"one.example.", "two.example."} {
		if !hasARRset(t, fresh, name) {
			t.Fatalf("%s did not come back from the purge artefact", name)
		}
	}
}

// hasARRset reports whether the zone publishes an A RRset at name.
//
// Not GetOwner: on a Ready MapZone that returns a nil error whether the name
// exists or not, so `err == nil` is not a test of anything. Ask for the RRset
// and look at what comes back.
func hasARRset(t *testing.T, zd *ZoneData, name string) bool {
	t.Helper()
	rrset, err := zd.GetRRset(name, dns.TypeA)
	if err != nil {
		t.Fatalf("GetRRset(%s): %v", name, err)
	}
	return rrset != nil && len(rrset.RRs) > 0
}

// TestParseInstructionsAcceptsATabSeparator. rr.String() renders with tabs, so
// every line this program writes and every line pasted out of a zone file has
// them. A space-only split would call that "not an instruction", naming the
// wrong mistake in a file whose whole purpose is to be hand-edited.
func TestParseInstructionsAcceptsATabSeparator(t *testing.T) {
	insns, err := ParseUpdateInstructions(strings.NewReader(
		"ADD\tfoo.example. 3600 IN A 1.2.3.4\nDEL\t\tbar.example. 3600 IN A 5.6.7.8\n"))
	if err != nil {
		t.Fatalf("a tab after the keyword was rejected: %v", err)
	}
	if len(insns) != 2 {
		t.Fatalf("parsed %d instructions, want 2", len(insns))
	}
	if insns[0].Action != ZoneDeltaAdd || insns[1].Action != ZoneDeltaDel {
		t.Fatalf("actions parsed as %q/%q", insns[0].Action, insns[1].Action)
	}
}

// TestPurgeKeepsADeltraPublishedDuringTheSnapshot: an update landing between
// the artefact snapshot and the delete must NOT be deleted -- it is not in the
// artefact, so deleting it would destroy content saved nowhere at all.
//
// The race is simulated by persisting a delta directly, in the window the real
// updater would publish in.
func TestPurgeKeepsADeltaPublishedDuringTheSnapshot(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := journalTestZone(t, kdb)
	zd.Zonefile = filepath.Join(t.TempDir(), "example.zone")

	insns, maxID, err := zd.JournalInstructions()
	if err != nil {
		t.Fatalf("JournalInstructions: %v", err)
	}

	// The concurrent publish: a delta chaining from the journal's head.
	info, err := zd.JournalInfo(false)
	if err != nil {
		t.Fatalf("JournalInfo: %v", err)
	}
	if err := kdb.PersistZoneDelta("example.", info.HeadSerial, info.HeadSerial+1, nil,
		journalRRset(t, "late.example. 3600 IN A 10.9.9.9")); err != nil {
		t.Fatalf("persisting the concurrent delta: %v", err)
	}

	// Now the purge's delete half, bounded by what the snapshot covered.
	n, err := kdb.DeleteZoneDeltasThroughID("example.", maxID)
	if err != nil {
		t.Fatalf("DeleteZoneDeltasThroughID: %v", err)
	}
	if int(n) != len(insns) {
		t.Fatalf("deleted %d rows, snapshot covered %d", n, len(insns))
	}

	after, err := zd.JournalInfo(false)
	if err != nil {
		t.Fatalf("JournalInfo: %v", err)
	}
	if after.Deltas != 1 {
		t.Fatalf("deltas left = %d, want the 1 that arrived during the purge", after.Deltas)
	}
	if after.HeadSerial != info.HeadSerial+1 {
		t.Fatalf("the surviving delta is %d, want the late one at %d",
			after.HeadSerial, info.HeadSerial+1)
	}
}

// TestJournalPurgeReportsWhatArrivedDuringIt. Keeping the late delta is only
// half the job: leaving it unmentioned means a journal that silently refuses to
// replay at the next restart, with no obvious cause.
func TestJournalPurgeReportsWhatArrivedDuringIt(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := journalTestZone(t, kdb)
	zd.Zonefile = filepath.Join(t.TempDir(), "example.zone")

	// Purge with nothing concurrent: nothing to report.
	res, err := zd.JournalPurge(true)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if res.Remaining != 0 {
		t.Fatalf("Remaining = %d on an uncontended purge, want 0", res.Remaining)
	}
}

// withJournalActive sets the deployment-wide kill-switch for the duration of a
// test. Absent config means ON, so the tests that need it OFF must say so.
func withJournalActive(t *testing.T, active bool) {
	t.Helper()
	confMu.Lock()
	prev := Conf.Journal.Active
	Conf.Journal.Active = &active
	confMu.Unlock()
	t.Cleanup(func() {
		confMu.Lock()
		Conf.Journal.Active = prev
		confMu.Unlock()
	})
}

// TestJournalActiveDefaultsOn is the single most important property of the
// switch. It is a *bool so that ABSENT means on -- a plain bool would default
// to false and silently disable persistence for every existing config on
// upgrade, which is the exact failure this subsystem exists to prevent.
func TestJournalActiveDefaultsOn(t *testing.T) {
	confMu.Lock()
	prev := Conf.Journal.Active
	Conf.Journal.Active = nil
	confMu.Unlock()
	t.Cleanup(func() {
		confMu.Lock()
		Conf.Journal.Active = prev
		confMu.Unlock()
	})

	if !JournalActive() {
		t.Fatal("an absent journal.active disabled persistence; it must default ON")
	}
}

func TestJournalActiveExplicitValues(t *testing.T) {
	withJournalActive(t, false)
	if JournalActive() {
		t.Fatal("journal.active=false did not disable persistence")
	}
	withJournalActive(t, true)
	if !JournalActive() {
		t.Fatal("journal.active=true did not enable persistence")
	}
}

// TestKillSwitchStopsNewDeltas: an update still applies and is served, it just
// is not recorded.
func TestKillSwitchStopsNewDeltas(t *testing.T) {
	withJournalActive(t, false)

	kdb := newTestKeyDB(t)
	zd := journalTestZone(t, kdb)

	info, err := zd.JournalInfo(false)
	if err != nil {
		t.Fatalf("JournalInfo: %v", err)
	}
	if info.Deltas != 0 {
		t.Fatalf("the kill-switch was set but %d delta(s) were recorded", info.Deltas)
	}
	if info.PersistenceActive {
		t.Fatal("status reports persistence active while the kill-switch is set")
	}
	// The update itself still landed -- off means "not durable", not "refused".
	if !hasARRset(t, zd, "one.example.") {
		t.Fatal("the kill-switch stopped the update being applied; it must only stop recording")
	}
}

// TestKillSwitchStillReplaysAnExistingJournal. Flipping the switch must not
// discard what is already recorded, or the escape hatch becomes a second way to
// lose data.
func TestKillSwitchStillReplaysAnExistingJournal(t *testing.T) {
	kdb := newTestKeyDB(t)

	// Build a journal with persistence ON.
	zd := journalTestZone(t, kdb)
	if info, err := zd.JournalInfo(false); err != nil {
		t.Fatalf("JournalInfo: %v", err)
	} else if info.Deltas == 0 {
		t.Fatal("precondition: no journal was recorded")
	}

	// Now the operator sets the kill-switch and restarts.
	withJournalActive(t, false)

	fresh := testZone(t, "example.", deltaZone)
	registerZones(t, fresh)
	fresh.KeyDB = kdb
	fresh.UpdatePolicy = policyAllowing(dns.TypeA, dns.TypeTXT)

	n, err := fresh.ReplayPersistedDeltas(kdb)
	if err != nil {
		t.Fatalf("replay with the kill-switch set: %v", err)
	}
	if n == 0 {
		t.Fatal("the kill-switch suppressed replay of an EXISTING journal;" +
			" it must only stop new deltas being recorded")
	}
	if !hasARRset(t, fresh, "one.example.") {
		t.Fatal("the already-recorded change did not come back")
	}
}
