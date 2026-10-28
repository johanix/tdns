package tdns

import (
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// A draft built by an inbound IXFR shares every owner the delta did not touch
// with the snapshot being served (materializeForIxfr). A pre-refresh write
// into such an owner must change the draft and nothing else, and the publish
// must then carry it like any other change (#965).

// ixfrDraft applies a delta that touches www.example. and the apex to a served
// zone, and returns the zone and the scratch zone its pre-refresh callbacks
// would be handed. ns.example. is untouched, so the draft shares it with the
// snapshot.
func ixfrDraft(t *testing.T) (*ZoneData, *ZoneData) {
	t.Helper()
	zd := ixBase(t, ixApplyZone)
	zd.IncomingSerial = 7
	rrs := []dns.RR{
		ixSOA(t, 8),
		ixSOA(t, 7), ixA(t, "www.example.", "10.0.0.3"),
		ixSOA(t, 8), ixA(t, "www.example.", "10.0.0.4"),
		ixSOA(t, 8),
	}
	newZd := &ZoneData{ZoneName: zd.ZoneName, ZoneStore: MapZone, Logger: discardLogger()}
	if err := zd.applyIxfrToScratch(newZd, rrs); err != nil {
		t.Fatalf("applyIxfrToScratch: %v", err)
	}
	if newZd.ixfrTouched["ns.example."] {
		t.Fatal("precondition: the delta touched ns.example.")
	}
	return zd, newZd
}

// snapshotA lists the A records a snapshot holds for one owner.
func snapshotA(snap *zoneSnapshot, owner string) []string {
	od := snap.Data[owner]
	if od == nil {
		return nil
	}
	var out []string
	for _, rr := range od.RRtypes.GetOnlyRRSet(dns.TypeA).RRs {
		out = append(out, rr.(*dns.A).A.String())
	}
	return out
}

// draftA lists the A records a draft holds for one owner.
func draftA(zd *ZoneData, owner string) []string {
	od, ok := zd.Data.Get(owner)
	if !ok {
		return nil
	}
	var out []string
	for _, rr := range od.RRtypes.GetOnlyRRSet(dns.TypeA).RRs {
		out = append(out, rr.(*dns.A).A.String())
	}
	return out
}

// deltaA lists the A records one side of a computeZoneDelta result holds for
// one owner.
func deltaA(sets []core.RRset, owner string) []string {
	var out []string
	for _, rs := range sets {
		if rs.Name != owner || rs.RRtype != dns.TypeA {
			continue
		}
		for _, rr := range rs.RRs {
			out = append(out, rr.(*dns.A).A.String())
		}
	}
	return out
}

// sameStrings reports whether two lists hold the same strings in the same
// order.
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A draft write to an untouched owner, and to a new one, changes the draft
// only, and both owners join the touched set.
func TestStageOnAnIxfrDraftLeavesTheServedZoneAlone(t *testing.T) {
	zd, newZd := ixfrDraft(t)

	newZd.StageRRset("ns.example.", coreRRset("ns.example.", dns.TypeA, "10.0.0.99"))
	newZd.StageRRset("new.example.", coreRRset("new.example.", dns.TypeA, "10.0.0.98"))

	if got := snapshotA(zd.publishedSnapshot(), "ns.example."); !sameStrings(got, []string{"10.0.0.1"}) {
		t.Fatalf("the served ns.example. A is %v after a draft write, want [10.0.0.1]", got)
	}
	if got := draftA(newZd, "ns.example."); !sameStrings(got, []string{"10.0.0.99"}) {
		t.Fatalf("the draft's ns.example. A is %v, want [10.0.0.99]", got)
	}
	// Both owners join the touched set, so a signing secondary signs them.
	for _, owner := range []string{"ns.example.", "new.example."} {
		if !newZd.ixfrTouched[owner] {
			t.Errorf("%s is not in ixfrTouched after a draft write", owner)
		}
	}
}

// A draft delete on an untouched owner removes the RRset from the draft only.
func TestDeleteOnAnIxfrDraftLeavesTheServedZoneAlone(t *testing.T) {
	zd, newZd := ixfrDraft(t)

	newZd.StageDelete("ns.example.", dns.TypeA)

	if got := snapshotA(zd.publishedSnapshot(), "ns.example."); !sameStrings(got, []string{"10.0.0.1"}) {
		t.Fatalf("the served ns.example. A is %v after a draft delete, want [10.0.0.1]", got)
	}
	if got := draftA(newZd, "ns.example."); len(got) != 0 {
		t.Fatalf("the draft's ns.example. A is %v after the delete, want none", got)
	}
}

// Deleting a type the owner does not have writes nothing, so the owner stays
// shared and out of the touched set: a signing secondary must not re-sign it.
func TestDeleteOfAnAbsentTypeLeavesAnIxfrDraftOwnerShared(t *testing.T) {
	zd, newZd := ixfrDraft(t)

	newZd.StageDelete("ns.example.", dns.TypeAAAA)

	if newZd.ixfrTouched["ns.example."] {
		t.Error("deleting an absent type put ns.example. in ixfrTouched")
	}
	od, ok := newZd.Data.Get("ns.example.")
	if !ok {
		t.Fatal("ns.example. is gone from the draft")
	}
	if !sharesOwnerStorage(zd.publishedSnapshot().Data["ns.example."], &od) {
		t.Error("deleting an absent type copied ns.example. out of the snapshot's store")
	}
}

// The combiner's path: one StageBatch on the draft (tdns-mp's MPPreRefresh).
func TestStageBatchOnAnIxfrDraftLeavesTheServedZoneAlone(t *testing.T) {
	zd, newZd := ixfrDraft(t)

	_, err := newZd.StageBatch(func(s Stager) (bool, error) {
		s.SetRRset("ns.example.", coreRRset("ns.example.", dns.TypeA, "10.0.0.99"))
		return true, nil
	})
	if err != nil {
		t.Fatalf("StageBatch: %v", err)
	}
	if got := snapshotA(zd.publishedSnapshot(), "ns.example."); !sameStrings(got, []string{"10.0.0.1"}) {
		t.Fatalf("the served ns.example. A is %v after a batch on the draft, want [10.0.0.1]", got)
	}
	if got := draftA(newZd, "ns.example."); !sameStrings(got, []string{"10.0.0.99"}) {
		t.Fatalf("the draft's ns.example. A is %v after the batch, want [10.0.0.99]", got)
	}
	if !newZd.ixfrTouched["ns.example."] {
		t.Fatal("ns.example. is not in ixfrTouched after the batch")
	}
}

// The publish that follows serves the draft's write, signed, and the outbound
// delta carries it. On a signing secondary the publish signs only the touched
// owners (wsSignOwners), so ns.example., which the delta never named, is
// signed only because the draft's write made it touched.
func TestAnIxfrDraftWriteIsPublishedSignedAndInTheDelta(t *testing.T) {
	zd := ixSigningSecondary(t, ixResignZone)
	before := zd.publishedSnapshot()

	newZd := &ZoneData{ZoneName: zd.ZoneName, ZoneStore: MapZone, Logger: discardLogger()}
	rrs := ixDeltaStream(t, 7, 8,
		[]dns.RR{ixA(t, "www.example.", "10.0.0.4")},
		[]dns.RR{ixA(t, "www.example.", "10.0.0.5")})
	if err := zd.applyIxfrToScratch(newZd, rrs); err != nil {
		t.Fatalf("applyIxfrToScratch: %v", err)
	}
	newZd.StageRRset("ns.example.", coreRRset("ns.example.", dns.TypeA, "10.0.0.99"))
	if got := snapshotA(before, "ns.example."); !sameStrings(got, []string{"10.0.0.1"}) {
		t.Fatalf("the served ns.example. A is %v before the publish, want [10.0.0.1]", got)
	}

	zd.mu.Lock()
	err := zd.applyRefreshReplacementLocked(newZd, nil, false, false)
	zd.mu.Unlock()
	if err != nil {
		t.Fatalf("applyRefreshReplacementLocked: %v", err)
	}
	assertPublishedAddresses(t, zd, "ns.example.", []string{"10.0.0.99"})
	assertPublishedRRsetVerifies(t, zd, "ns.example.", dns.TypeA)

	removed, added, _ := computeZoneDelta(zd.ZoneName, before.Data, zd.publishedSnapshot().Data)
	gone, came := deltaA(removed, "ns.example."), deltaA(added, "ns.example.")
	if !sameStrings(gone, []string{"10.0.0.1"}) || !sameStrings(came, []string{"10.0.0.99"}) {
		t.Fatalf("outbound delta at ns.example. A: removed %v, added %v; want removed [10.0.0.1], added [10.0.0.99]", gone, came)
	}
}
