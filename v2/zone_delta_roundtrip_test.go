/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

const deltaZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
old.example.	3600	IN	TXT	"remove me"
`

// TestZoneDeltaSurvivesRestart is the whole Phase 2 model in one test: a change
// applied to a running zone must still be there after the process restarts and
// re-reads a zone FILE that never contained it.
//
// The "restart" is a second ZoneData built from the same unchanged file text,
// which is exactly what a real restart sees.
func TestZoneDeltaSurvivesRestart(t *testing.T) {
	kdb := newTestKeyDB(t)

	live := testZone(t, "example.", deltaZone)
	registerZones(t, live)
	live.KeyDB = kdb
	live.UpdatePolicy = policyAllowing(dns.TypeA, dns.TypeTXT)

	// A REPLACE plus a delete: enough to catch ordering mistakes, since
	// replaying the adds before the delete would leave the RRset empty.
	actions, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{
		Verb: VerbReplaceRRset,
		RRs:  []string{"www.example. 3600 IN A 10.0.0.1", "www.example. 3600 IN A 10.0.0.2"},
	})
	if err != nil {
		t.Fatalf("build replace: %v", err)
	}
	drop, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{
		Verb: VerbDelRRset, Name: "old.example.", Rrtype: "TXT",
	})
	if err != nil {
		t.Fatalf("build delrrset: %v", err)
	}

	if _, err := live.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: "example.",
		Actions: append(actions, drop...),
	}, kdb); err != nil {
		t.Fatalf("apply: %v", err)
	}

	liveSerial := live.CurrentSerial

	// The delta must have reached the database.
	stored, err := kdb.LoadZoneDeltas("example.")
	if err != nil {
		t.Fatalf("LoadZoneDeltas: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("got %d persisted deltas, want 1 (one apply = one publish = one delta)", len(stored))
	}

	// --- restart: same file text, nothing of the change in it ---
	reloaded := testZone(t, "example.", deltaZone)
	registerZones(t, reloaded)
	reloaded.KeyDB = kdb
	reloaded.UpdatePolicy = policyAllowing(dns.TypeA, dns.TypeTXT)

	// Before replay the reloaded zone is the FILE: the old address is back and
	// the deleted name has returned. If this ever stops holding, the test is
	// no longer proving anything.
	if got := aAddrs(t, reloaded, "www.example."); len(got) != 1 || got[0] != "192.0.2.1" {
		t.Fatalf("precondition: freshly loaded file should hold 192.0.2.1, got %v", got)
	}

	n, err := reloaded.ReplayPersistedDeltas(kdb)
	if err != nil {
		t.Fatalf("ReplayPersistedDeltas: %v", err)
	}
	if n != 1 {
		t.Errorf("replayed %d deltas, want 1", n)
	}

	// The REPLACE must have survived, in full.
	got := aAddrs(t, reloaded, "www.example.")
	if len(got) != 2 {
		t.Fatalf("after replay www has %d A RRs, want 2: %v", len(got), got)
	}
	for _, a := range got {
		if a == "192.0.2.1" {
			t.Errorf("the replaced-away address is back after replay: %v", got)
		}
	}

	// And so must the delete.
	if od, err := reloaded.GetOwner("old.example."); err == nil && od != nil {
		if _, present := od.RRtypes.Get(dns.TypeTXT); present {
			t.Error("the deleted TXT RRset came back after replay")
		}
	}

	// The serial must end up STRICTLY past the one the zone last published.
	// Equal would mean secondaries hold a different image of that serial --
	// the RRSIGs were regenerated here -- and never transfer the difference.
	if !serialNewer(reloaded.CurrentSerial, liveSerial) {
		t.Errorf("serial after replay = %d, must be strictly newer than the last published serial %d",
			reloaded.CurrentSerial, liveSerial)
	}
}

// TestZoneDeltaReplaySerialStrictlyExceedsLastPublished is the guarantee stated
// plainly, in the default increment mode where it is not free.
//
// Replay regenerates RRSIGs, so the zone it publishes is NOT byte-identical to
// what was published under the recorded serial. Landing on that serial would
// leave every secondary holding a different "serial N" with no reason to ever
// re-transfer -- and a restart done to refresh signatures near expiry would
// refresh only the primary.
func TestZoneDeltaReplaySerialStrictlyExceedsLastPublished(t *testing.T) {
	kdb := newTestKeyDB(t)

	live := testZone(t, "example.", deltaZone)
	registerZones(t, live)
	live.KeyDB = kdb
	live.UpdatePolicy = policyAllowing(dns.TypeA)

	fileSerial := live.CurrentSerial

	actions, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{
		Verb: VerbAddRR, RRs: []string{"new.example. 3600 IN A 10.0.0.7"},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := live.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: actions,
	}, kdb); err != nil {
		t.Fatalf("apply: %v", err)
	}
	x := live.CurrentSerial
	if !serialNewer(x, fileSerial) {
		t.Fatalf("precondition: the update should have advanced the serial past %d, got %d",
			fileSerial, x)
	}

	reloaded := testZone(t, "example.", deltaZone)
	registerZones(t, reloaded)
	reloaded.KeyDB = kdb
	reloaded.UpdatePolicy = policyAllowing(dns.TypeA)
	if _, err := reloaded.ReplayPersistedDeltas(kdb); err != nil {
		t.Fatalf("replay: %v", err)
	}
	y := reloaded.CurrentSerial

	if !serialNewer(y, x) {
		t.Errorf("Y=%d is not strictly newer than X=%d; secondaries would never"+
			" pick up the regenerated signatures", y, x)
	}
}

// TestZoneDeltaReplayRefusesMismatchedChain: deltas are computed against one
// specific base. If the zone file has been edited or restored from an older
// copy since, replaying them produces a zone that never existed -- some changes
// land on content that is gone, and fresh operator edits are silently
// overwritten. Refuse instead.
func TestZoneDeltaReplayRefusesMismatchedChain(t *testing.T) {
	kdb := newTestKeyDB(t)

	live := testZone(t, "example.", deltaZone)
	registerZones(t, live)
	live.KeyDB = kdb
	live.UpdatePolicy = policyAllowing(dns.TypeA)

	actions, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{
		Verb: VerbAddRR, RRs: []string{"new.example. 3600 IN A 10.0.0.7"},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := live.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: actions,
	}, kdb); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// The operator edits the zone file: same content, bumped serial. The
	// deltas now chain from a serial this file no longer has.
	edited := `example.	3600	IN	SOA	ns.example. hostmaster.example. 42 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
`
	reloaded := testZone(t, "example.", edited)
	registerZones(t, reloaded)
	reloaded.KeyDB = kdb
	reloaded.UpdatePolicy = policyAllowing(dns.TypeA)

	n, err := reloaded.ReplayPersistedDeltas(kdb)
	if err == nil {
		t.Fatal("replay onto an edited zone file was accepted; expected a refusal")
	}
	if n != 0 {
		t.Errorf("refused replay still reported %d deltas applied", n)
	}
	for _, want := range []string{"do not chain", "serial"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

// TestZoneDeltaReplayDoesNotRePersist: a restart must be idempotent. If replay
// recorded what it replayed, the stored history would double on every restart
// and eventually replay a REPLACE twice.
func TestZoneDeltaReplayDoesNotRePersist(t *testing.T) {
	kdb := newTestKeyDB(t)

	live := testZone(t, "example.", deltaZone)
	registerZones(t, live)
	live.KeyDB = kdb
	live.UpdatePolicy = policyAllowing(dns.TypeA)

	actions, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{
		Verb: VerbAddRR, RRs: []string{"new.example. 3600 IN A 10.0.0.7"},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := live.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: actions,
	}, kdb); err != nil {
		t.Fatalf("apply: %v", err)
	}

	before, _ := kdb.LoadZoneDeltas("example.")

	// Three restarts in a row.
	for i := 0; i < 3; i++ {
		zd := testZone(t, "example.", deltaZone)
		registerZones(t, zd)
		zd.KeyDB = kdb
		zd.UpdatePolicy = policyAllowing(dns.TypeA)
		if _, err := zd.ReplayPersistedDeltas(kdb); err != nil {
			t.Fatalf("replay %d: %v", i, err)
		}
	}

	after, _ := kdb.LoadZoneDeltas("example.")
	if len(after) != len(before) {
		t.Errorf("stored deltas grew from %d to %d across three replays --"+
			" replay is re-persisting what it replays", len(before), len(after))
	}
}

// TestZoneDeltaDroppedOnWriteZone: once the changes are in the file, the deltas
// must go. Otherwise the next load applies them a second time on top of a file
// that already contains them.
func TestZoneDeltaDroppedOnWriteZone(t *testing.T) {
	kdb := newTestKeyDB(t)

	zd := testZone(t, "example.", deltaZone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.UpdatePolicy = policyAllowing(dns.TypeA)
	zd.Zonefile = t.TempDir() + "/example.zone"
	// testZone leaves Options nil, which is fine for the applier (it only
	// reads) but not for WriteZone, which clears OptDirty. In production the
	// map is always initialized by config parsing.
	zd.Options = map[ZoneOption]bool{}

	actions, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{
		Verb: VerbAddRR, RRs: []string{"new.example. 3600 IN A 10.0.0.7"},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: actions,
	}, kdb); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got, _ := kdb.LoadZoneDeltas("example."); len(got) != 1 {
		t.Fatalf("precondition: expected 1 persisted delta, got %d", len(got))
	}

	if _, err := zd.WriteZone(true, true); err != nil {
		t.Fatalf("WriteZone: %v", err)
	}

	got, err := kdb.LoadZoneDeltas("example.")
	if err != nil {
		t.Fatalf("LoadZoneDeltas: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("deltas survived the zone write: %d remain, want 0", len(got))
	}
}

// TestZoneDeltaPersistFailureRefusesPublish pins the durable-before-visible
// ordering. If the delta cannot be written, the change must not be published:
// once a snapshot is stored the content is being served and a secondary can
// pull it, and a change that is served but not recorded silently rolls back at
// the next restart, leaving that secondary holding content the primary has no
// record of.
//
// So a failed write must leave the zone exactly as it was -- old content, old
// serial -- and must be reported as an error rather than a quiet success.
func TestZoneDeltaPersistFailureRefusesPublish(t *testing.T) {
	kdb := newTestKeyDB(t)

	zd := testZone(t, "example.", deltaZone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.UpdatePolicy = policyAllowing(dns.TypeA)

	serialBefore := zd.CurrentSerial

	actions, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{
		Verb: VerbAddRR, RRs: []string{"new.example. 3600 IN A 10.0.0.7"},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// Break the database so the delta write cannot succeed.
	if err := kdb.DB.Close(); err != nil {
		t.Fatalf("closing test db: %v", err)
	}

	updated, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{
		Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: actions,
	}, kdb)
	if err == nil {
		t.Error("a change that could not be persisted was reported as applied")
	}
	if updated {
		t.Error("updated=true despite the publish being refused")
	}

	// The new name must not be served: it is neither durable nor visible.
	if od, gerr := zd.GetOwner("new.example."); gerr == nil && od != nil {
		if _, present := od.RRtypes.Get(dns.TypeA); present {
			t.Error("the unpersistable change was published anyway")
		}
	}
	// And the serial must not have moved, or the next real change would
	// publish under a serial a secondary has already seen.
	if zd.CurrentSerial != serialBefore {
		t.Errorf("serial advanced to %d despite the refused publish (was %d)",
			zd.CurrentSerial, serialBefore)
	}
}

func aAddrs(t *testing.T, zd *ZoneData, owner string) []string {
	t.Helper()
	od, err := zd.GetOwner(owner)
	if err != nil || od == nil {
		return nil
	}
	rrset, ok := od.RRtypes.Get(dns.TypeA)
	if !ok {
		return nil
	}
	var out []string
	for _, rr := range rrset.RRs {
		if a, ok := rr.(*dns.A); ok {
			out = append(out, a.A.String())
		}
	}
	return out
}

// The CHILD-UPDATE half of durable-before-visible.
//
// ApplyChildUpdateToZoneData stages wsPersistDelta and reads wsPersistErr in
// the same shape as ApplyZoneUpdateToZoneData, but its results were UNNAMED:
// `return updated, nil` copies the value into the result slot before deferred
// functions run, so the deferred `updated = false` on a persist failure landed
// on a local the caller never saw. A child update that could not be made
// durable was reported as applied -- and on the DSYNC API path, answered 200,
// which is exactly the promise this persistence work exists to keep.
func TestChildUpdatePersistFailureRefusesPublish(t *testing.T) {
	kdb := newTestKeyDB(t)

	zd := testZone(t, "example.", deltaZone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	// policyAllowing populates only the ZONE scope; the child applier gates on
	// UpdatePolicy.CHILD.RRtypes, so without this every action is skipped, the
	// deferred block never runs, and the test passes for the wrong reason.
	zd.UpdatePolicy = policyAllowing(dns.TypeA, dns.TypeNS)
	zd.UpdatePolicy.Child = UpdatePolicyDetail{
		Type:    "selfsub",
		RRtypes: map[uint16]bool{dns.TypeNS: true, dns.TypeA: true},
		TTL:     3600,
	}
	// The child applier sets zd.Options[OptDirty]; a real zone always has the
	// map from parseconfig, testZone does not.
	if zd.Options == nil {
		zd.Options = map[ZoneOption]bool{}
	}

	serialBefore := zd.CurrentSerial

	ns, err := dns.NewRR("child.example. 3600 IN NS ns1.child.example.")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}

	// Break the database so the delta write cannot succeed.
	if err := kdb.DB.Close(); err != nil {
		t.Fatalf("closing test db: %v", err)
	}

	updated, err := zd.ApplyChildUpdateToZoneData(UpdateRequest{
		Cmd: "CHILD-UPDATE", ZoneName: "example.", Actions: []dns.RR{ns},
	}, kdb)
	if err != nil {
		t.Fatalf("ApplyChildUpdateToZoneData: %v", err)
	}
	if updated {
		t.Error("updated=true despite the publish being refused -- the deferred" +
			" failure handling did not reach the caller (unnamed results?)")
	}
	if zd.CurrentSerial != serialBefore {
		t.Errorf("serial advanced to %d despite the refused publish (was %d)",
			zd.CurrentSerial, serialBefore)
	}
}

// A dropped publish must not leave the delta staged: the next publish for the
// zone -- a refresh, a reload, a signalSynth-only republish -- would otherwise
// write a ZoneDelta row it does not own, diffed against a working set no
// applier staged, and replay would later apply it as though it were an update.
func TestDroppedPublishDoesNotLeaveDeltaStaged(t *testing.T) {
	zd := testZone(t, "example.", deltaZone)
	registerZones(t, zd)
	zd.KeyDB = newTestKeyDB(t)

	zd.mu.Lock()
	// Stage a delta the way an applier does, then drop the publish by the
	// no-working-set path.
	zd.wsPersistDelta = true
	zd.workingSet = nil
	zd.publishWorkingSetLocked(zd.generation.Load(), true)
	staged := zd.wsPersistDelta
	zd.mu.Unlock()

	if staged {
		t.Error("wsPersistDelta survived a dropped publish; it would attach to the next unrelated one")
	}
}
