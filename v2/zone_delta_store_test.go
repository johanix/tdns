/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func deltaRRset(t *testing.T, rrs ...string) core.RRset {
	t.Helper()
	var set core.RRset
	for _, s := range rrs {
		set.RRs = append(set.RRs, mustRR(t, s))
	}
	return set
}

func TestZoneDeltaRoundTrip(t *testing.T) {
	kdb := newTestKeyDB(t)

	removed := []core.RRset{deltaRRset(t, "www.example. 3600 IN A 192.0.2.1")}
	added := []core.RRset{deltaRRset(t,
		"www.example. 3600 IN A 10.0.0.1",
		"www.example. 3600 IN A 10.0.0.2")}

	if err := kdb.PersistZoneDelta("example.", 1, 2, removed, added); err != nil {
		t.Fatalf("PersistZoneDelta: %v", err)
	}

	got, err := kdb.LoadZoneDeltas("example.")
	if err != nil {
		t.Fatalf("LoadZoneDeltas: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d deltas, want 1", len(got))
	}
	d := got[0]
	if d.FromSerial != 1 || d.ToSerial != 2 {
		t.Errorf("serials = %d->%d, want 1->2", d.FromSerial, d.ToSerial)
	}
	if len(d.RRs) != 3 {
		t.Fatalf("delta has %d records, want 3", len(d.RRs))
	}
	// Deletes must precede adds: a REPLACE replayed the other way round
	// leaves the RRset empty.
	if d.RRs[0].Action != ZoneDeltaDel {
		t.Errorf("first record is %q, want the delete first", d.RRs[0].Action)
	}
	for _, r := range d.RRs[1:] {
		if r.Action != ZoneDeltaAdd {
			t.Errorf("expected adds after the delete, got %q", r.Action)
		}
	}
}

// TestZoneDeltaReplayOrderIsInsertionOrder pins the ordering choice: replay
// follows insertion order, not serial order, because serials wrap (RFC 1982).
// A zone whose serial wrapped mid-history must still replay in the order the
// changes actually happened.
func TestZoneDeltaReplayOrderIsInsertionOrder(t *testing.T) {
	kdb := newTestKeyDB(t)

	// Three deltas whose serials wrap past 2^32-1.
	steps := []struct{ from, to uint32 }{
		{4294967294, 4294967295},
		{4294967295, 0},
		{0, 1},
	}
	for i, s := range steps {
		add := []core.RRset{deltaRRset(t, dns.Fqdn("step")+" 3600 IN TXT "+`"`+string(rune('a'+i))+`"`)}
		if err := kdb.PersistZoneDelta("example.", s.from, s.to, nil, add); err != nil {
			t.Fatalf("PersistZoneDelta step %d: %v", i, err)
		}
	}

	got, err := kdb.LoadZoneDeltas("example.")
	if err != nil {
		t.Fatalf("LoadZoneDeltas: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d deltas, want 3", len(got))
	}
	for i, s := range steps {
		if got[i].FromSerial != s.from || got[i].ToSerial != s.to {
			t.Errorf("delta[%d] = %d->%d, want %d->%d (replay must follow insertion order, "+
				"not the wrapped serial values)",
				i, got[i].FromSerial, got[i].ToSerial, s.from, s.to)
		}
	}
}

// An empty delta is not worth a row: serial-only advances publish with no
// content change and would grow the table without ever altering a replay.
func TestZoneDeltaEmptyIsNotPersisted(t *testing.T) {
	kdb := newTestKeyDB(t)

	if err := kdb.PersistZoneDelta("example.", 1, 2, nil, nil); err != nil {
		t.Fatalf("PersistZoneDelta: %v", err)
	}
	got, err := kdb.LoadZoneDeltas("example.")
	if err != nil {
		t.Fatalf("LoadZoneDeltas: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("an empty delta was persisted: %+v", got)
	}
}

// Deltas are per zone, and dropping one zone's history must not touch another's.
func TestZoneDeltaDeleteIsPerZone(t *testing.T) {
	kdb := newTestKeyDB(t)

	add := []core.RRset{deltaRRset(t, "www.example. 3600 IN A 10.0.0.1")}
	if err := kdb.PersistZoneDelta("example.", 1, 2, nil, add); err != nil {
		t.Fatalf("persist example: %v", err)
	}
	other := []core.RRset{deltaRRset(t, "www.other. 3600 IN A 10.0.0.9")}
	if err := kdb.PersistZoneDelta("other.", 1, 2, nil, other); err != nil {
		t.Fatalf("persist other: %v", err)
	}

	n, err := kdb.DeleteZoneDeltas("example.")
	if err != nil {
		t.Fatalf("DeleteZoneDeltas: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d rows, want 1", n)
	}

	if got, _ := kdb.LoadZoneDeltas("example."); len(got) != 0 {
		t.Errorf("example. still has %d deltas after delete", len(got))
	}
	if got, _ := kdb.LoadZoneDeltas("other."); len(got) != 1 {
		t.Errorf("other. lost its deltas: got %d, want 1", len(got))
	}
}

// ZoneDeltaActions must produce records the applier understands: CLASS=NONE for
// a record delete, CLASS=INET for an add.
func TestZoneDeltaActionsClasses(t *testing.T) {
	rec := ZoneDeltaRecord{
		FromSerial: 1, ToSerial: 2,
		RRs: []ZoneDeltaRR{
			{Action: ZoneDeltaDel, RR: "www.example. 3600 IN A 192.0.2.1"},
			{Action: ZoneDeltaAdd, RR: "www.example. 3600 IN A 10.0.0.1"},
		},
	}
	actions, err := ZoneDeltaActions(rec)
	if err != nil {
		t.Fatalf("ZoneDeltaActions: %v", err)
	}
	if len(actions) != 2 {
		t.Fatalf("got %d actions, want 2", len(actions))
	}
	if actions[0].Header().Class != dns.ClassNONE {
		t.Errorf("delete class = %d, want ClassNONE", actions[0].Header().Class)
	}
	if actions[0].Header().Ttl != 0 {
		t.Errorf("delete TTL = %d, want 0", actions[0].Header().Ttl)
	}
	if actions[1].Header().Class != dns.ClassINET {
		t.Errorf("add class = %d, want ClassINET", actions[1].Header().Class)
	}

	if _, err := ZoneDeltaActions(ZoneDeltaRecord{
		RRs: []ZoneDeltaRR{{Action: "frobnicate", RR: "www.example. 3600 IN A 10.0.0.1"}},
	}); err == nil {
		t.Error("an unknown action was accepted")
	}
}

// TestReplaceZoneJournalRefusesAnEmptyDelta: ReplaceZoneJournal clears the whole
// chain before writing the replacement, so a replacement that flattens to no
// records at all would leave the zone with its changes recorded in neither the
// file nor the journal -- and return nil, so the caller books it as success and
// the next restart loses them.
//
// The caller's own guard counts RRsets, not records, so RRsets that carry no RRs
// slip past it. That is the case here.
func TestReplaceZoneJournalRefusesAnEmptyDelta(t *testing.T) {
	kdb := newTestKeyDB(t)

	seedRemoved := []core.RRset{deltaRRset(t, "www.example. 3600 IN A 192.0.2.1")}
	if err := kdb.PersistZoneDelta("example.", 1, 2, seedRemoved, nil); err != nil {
		t.Fatalf("PersistZoneDelta: %v", err)
	}

	// Non-empty RRset slices whose RRs are all empty: rows comes out empty.
	empty := []core.RRset{{Name: "www.example.", RRtype: dns.TypeA}}
	err := kdb.ReplaceZoneJournal("example.", 2, 3, empty, empty)
	if err == nil {
		t.Fatal("an empty replacement was accepted; it would have erased the journal")
	}

	// And the seeded chain must still be there.
	got, lerr := kdb.LoadZoneDeltas("example.")
	if lerr != nil {
		t.Fatalf("LoadZoneDeltas: %v", lerr)
	}
	if len(got) == 0 {
		t.Fatal("the journal was erased despite the refusal")
	}
}
