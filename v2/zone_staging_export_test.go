package tdns

import (
	"errors"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The exported staging surface (B-MP T-A): StageRRset / StageDelete /
// StageOwnerDelete, StageBatch and its Stager, Publish, the analysis readers
// and CloneRRset. These are the calls a consumer in another package gets;
// everything they wrap is pinned by zone_snapshot_test.go.

const stagingTestZone = `example.	3600	IN	SOA	ns.example. hostmaster.example. 1 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.1
txt.example.	3600	IN	TXT	"one"
`

// draftZone builds the shape the OnZonePreRefresh callbacks receive: content
// in Data, nothing published.
func draftZone(t *testing.T, name, zoneStr string) *ZoneData {
	t.Helper()
	zd := &ZoneData{
		ZoneName:  name,
		ZoneStore: MapZone,
		Logger:    log.New(os.Stderr, "", 0),
	}
	if _, _, err := zd.ReadZoneData(zoneStr, true); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	if zd.HasPublishedData() {
		t.Fatal("a freshly read zone must not have a published snapshot")
	}
	return zd
}

func servedA(t *testing.T, zd *ZoneData, name string) string {
	t.Helper()
	od, err := zd.GetOwner(name)
	if err != nil {
		t.Fatalf("GetOwner(%s): %v", name, err)
	}
	if od == nil {
		return ""
	}
	a := od.RRtypes.GetOnlyRRSet(dns.TypeA)
	if len(a.RRs) == 0 {
		return ""
	}
	return a.RRs[0].(*dns.A).A.String()
}

func TestStageOnDraftWritesData(t *testing.T) {
	zd := draftZone(t, "example.", stagingTestZone)

	zd.StageRRset("www.example.", coreRRset("www.example.", dns.TypeA, "192.0.2.2"))
	zd.StageRRset("new.example.", coreRRset("new.example.", dns.TypeA, "192.0.2.3"))
	zd.StageDelete("txt.example.", dns.TypeTXT)
	zd.StageOwnerDelete("txt.example.")

	if zd.HasPublishedData() {
		t.Fatal("staging into a draft must not publish")
	}
	rs, err := zd.RRsetForAnalysis("www.example.", dns.TypeA)
	if err != nil || rs == nil || len(rs.RRs) == 0 {
		t.Fatalf("RRsetForAnalysis after a draft stage: rs=%v err=%v", rs, err)
	}
	if got := rs.RRs[0].(*dns.A).A.String(); got != "192.0.2.2" {
		t.Fatalf("draft stage did not reach Data: got %s", got)
	}
	if rs, _ := zd.RRsetForAnalysis("new.example.", dns.TypeA); rs == nil {
		t.Fatal("an owner staged into a draft is not readable")
	}
	if od, _ := zd.OwnerForAnalysis("txt.example."); od != nil {
		t.Fatal("StageOwnerDelete on a draft left the owner in Data")
	}

	// The refresh publish consumes Data; InstallInitialSnapshot stands in for
	// it here. The staged content is what gets served.
	Zones.Set(zd.ZoneName, zd)
	t.Cleanup(func() { Zones.Remove(zd.ZoneName) })
	zd.InstallInitialSnapshot()
	t.Cleanup(zd.StopPublisher)
	if got := servedA(t, zd, "www.example."); got != "192.0.2.2" {
		t.Fatalf("served %q after install, want the draft-staged 192.0.2.2", got)
	}
	if got := servedA(t, zd, "new.example."); got != "192.0.2.3" {
		t.Fatalf("served %q for the new owner, want 192.0.2.3", got)
	}
	if od, _ := zd.GetOwner("txt.example."); od != nil {
		t.Fatal("the deleted owner is still served")
	}
}

func TestStageOnLiveZoneLeavesSnapshot(t *testing.T) {
	zd := testSnapshotZone(t, "example.", stagingTestZone)
	before := zd.snapshot.Load()
	serial := zd.CurrentSerial

	// TestSnapshotImmutability's assertion, through the exported call.
	zd.StageRRset("www.example.", coreRRset("www.example.", dns.TypeA, "192.0.2.2"))
	if zd.snapshot.Load() != before {
		t.Fatal("published snapshot pointer changed without a publish")
	}
	if got := servedA(t, zd, "www.example."); got != "192.0.2.1" {
		t.Fatalf("published snapshot mutated during staging: serving %s", got)
	}
	if zd.CurrentSerial != serial {
		t.Fatal("staging bumped the serial")
	}

	resp, err := zd.Publish()
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if resp.NewSerial != serial+1 || zd.CurrentSerial != serial+1 {
		t.Fatalf("Publish: serial %d -> %d, want %d", resp.OldSerial, resp.NewSerial, serial+1)
	}
	if got := servedA(t, zd, "www.example."); got != "192.0.2.2" {
		t.Fatalf("served %q after Publish, want 192.0.2.2", got)
	}

	// The per-call deletes, same discipline.
	zd.StageDelete("txt.example.", dns.TypeTXT)
	zd.StageOwnerDelete("txt.example.")
	if od, _ := zd.GetOwner("txt.example."); od == nil {
		t.Fatal("a staged delete reached the served snapshot before the publish")
	}
	if _, err := zd.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if od, _ := zd.GetOwner("txt.example."); od != nil {
		t.Fatal("the deleted owner is still served after the publish")
	}
}

// Deleting from a name that is not there must not create it: cloneOwner
// brings owners into existence, and an empty owner publishes as a name.
func TestStageDeleteOnAnAbsentOwnerCreatesNothing(t *testing.T) {
	zd := testSnapshotZone(t, "example.", stagingTestZone)
	zd.StageDelete("ghost.example.", dns.TypeA)
	if _, err := zd.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if zd.NameExists("ghost.example.") {
		t.Fatal("StageDelete on an absent owner created it")
	}
}

func TestAnalysisReadersPreferSnapshot(t *testing.T) {
	zd := testSnapshotZone(t, "example.", stagingTestZone)

	// A stale Data beside a published snapshot: the snapshot wins. (A direct
	// write to Data is what the analysis reader must NOT be fooled by; a test
	// may do it, production code may not. A FRESH owner, because the snapshot
	// shares the RRTypeStore pointers of the Data it was built from.)
	stale := OwnerData{Name: "www.example.", RRtypes: NewRRTypeStore()}
	stale.RRtypes.Set(dns.TypeA, coreRRset("www.example.", dns.TypeA, "192.0.2.99"))
	zd.Data.Set("www.example.", stale)
	rs, err := zd.RRsetForAnalysis("www.example.", dns.TypeA)
	if err != nil || rs == nil || len(rs.RRs) == 0 {
		t.Fatalf("RRsetForAnalysis: rs=%v err=%v", rs, err)
	}
	if got := rs.RRs[0].(*dns.A).A.String(); got != "192.0.2.1" {
		t.Fatalf("analysis reader returned Data (%s) over the published snapshot", got)
	}

	// Not the serve path: a not-Ready zone refuses GetOwner and still answers
	// the analysis reader, and a missing apex is nil, not a panic.
	zd.mu.Lock()
	zd.Ready = false
	zd.mu.Unlock()
	if _, err := zd.GetOwner("www.example."); !errors.Is(err, ErrZoneNotReady) {
		t.Fatalf("GetOwner on a not-Ready zone: err=%v, want ErrZoneNotReady", err)
	}
	if od, err := zd.OwnerForAnalysis("www.example."); err != nil || od == nil {
		t.Fatalf("OwnerForAnalysis on a not-Ready zone: od=%v err=%v", od, err)
	}
	empty := &ZoneData{ZoneName: "empty.", ZoneStore: MapZone, Data: core.NewNameMap[OwnerData]()}
	if rs, err := empty.RRsetForAnalysis("empty.", dns.TypeSOA); err != nil || rs != nil {
		t.Fatalf("RRsetForAnalysis on an apex-less draft: rs=%v err=%v, want (nil, nil)", rs, err)
	}
}

func TestCloneRRsetDoesNotAlias(t *testing.T) {
	zd := testSnapshotZone(t, "example.", stagingTestZone)
	od, _ := zd.GetOwner("txt.example.")
	served, _ := od.RRtypes.Get(dns.TypeTXT)

	c := CloneRRset(served)
	c.RRs = append(c.RRs, &dns.TXT{
		Hdr: dns.RR_Header{Name: "txt.example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
		Txt: []string{"two"},
	})
	c.RRs[0].(*dns.TXT).Txt[0] = "changed"

	again, _ := od.RRtypes.Get(dns.TypeTXT)
	if len(again.RRs) != 1 || again.RRs[0].(*dns.TXT).Txt[0] != "one" {
		t.Fatalf("editing a CloneRRset result reached the served RRset: %v", again.RRs)
	}
}

func TestStageBatchOneSerial(t *testing.T) {
	q := withNotifyQ(t, 4)
	zd := testSnapshotZone(t, "example.", stagingTestZone)
	zd.Notify = []PeerConf{{Addr: aDownstream}}
	serial := zd.CurrentSerial

	// Three writes, one serial, one NOTIFY.
	resp, err := zd.StageBatch(func(s Stager) (bool, error) {
		s.SetRRset("www.example.", coreRRset("www.example.", dns.TypeA, "192.0.2.2"))
		s.SetRRset("a.example.", coreRRset("a.example.", dns.TypeA, "192.0.2.3"))
		s.SetRRset("b.example.", coreRRset("b.example.", dns.TypeA, "192.0.2.4"))
		// Nothing is served until the batch returns.
		if got := servedAUnlocked(zd, "www.example."); got != "192.0.2.1" {
			t.Errorf("served content changed inside the batch: %s", got)
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("StageBatch: %v", err)
	}
	if resp.OldSerial != serial || resp.NewSerial != serial+1 || zd.CurrentSerial != serial+1 {
		t.Fatalf("three writes: serial %d -> %d (zone %d), want %d -> %d",
			resp.OldSerial, resp.NewSerial, zd.CurrentSerial, serial, serial+1)
	}
	for name, want := range map[string]string{"www.example.": "192.0.2.2", "a.example.": "192.0.2.3", "b.example.": "192.0.2.4"} {
		if got := servedA(t, zd, name); got != want {
			t.Errorf("%s serves %q, want %q", name, got, want)
		}
	}
	if got := len(q); got != 1 {
		t.Fatalf("got %d NOTIFYs for one batch, want 1", got)
	}
	<-q

	// A batch that reports no change publishes nothing, and leaves no working
	// set behind for its reads.
	resp, err = zd.StageBatch(func(s Stager) (bool, error) {
		if rs := s.RRset("www.example.", dns.TypeA); rs == nil || rs.RRs[0].(*dns.A).A.String() != "192.0.2.2" {
			t.Errorf("Stager.RRset does not see the served content: %v", rs)
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("StageBatch (no change): %v", err)
	}
	if resp.NewSerial != serial+1 || zd.CurrentSerial != serial+1 {
		t.Fatalf("a no-change batch published: serial %d", zd.CurrentSerial)
	}
	if got := len(q); got != 0 {
		t.Fatalf("got %d NOTIFYs for a no-change batch", got)
	}
	zd.mu.Lock()
	leftover := zd.workingSet != nil
	zd.mu.Unlock()
	if leftover {
		t.Fatal("a no-change batch left a working set behind")
	}
}

// servedAUnlocked reads the served A record without GetOwner's Ready gate or
// any lock: for use INSIDE a StageBatch callback, which holds zd.mu.
func servedAUnlocked(zd *ZoneData, name string) string {
	od := getOwnerFrom(zd.publishedSnapshot(), name)
	if od == nil {
		return ""
	}
	a := od.RRtypes.GetOnlyRRSet(dns.TypeA)
	if len(a.RRs) == 0 {
		return ""
	}
	return a.RRs[0].(*dns.A).A.String()
}

// The Stager reads the zone's NEXT content: the served RRset before the
// batch's own write, the written one after it. Between publishes the working
// set is nil, so a literal read of it would have returned nothing for every
// existing RRset (re-review L2); the read seeds it from the snapshot.
func TestStagerReadsNextContent(t *testing.T) {
	zd := testSnapshotZone(t, "example.", stagingTestZone)
	_, err := zd.StageBatch(func(s Stager) (bool, error) {
		before := s.RRset("www.example.", dns.TypeA)
		if before == nil || before.RRs[0].(*dns.A).A.String() != "192.0.2.1" {
			t.Fatalf("first read does not see the served RRset: %v", before)
		}
		// The copy is the caller's to edit.
		before.RRs[0].(*dns.A).A = before.RRs[0].(*dns.A).A.To4()
		before.RRs[0].(*dns.A).A[3] = 7
		s.SetRRset("www.example.", *before)
		after := s.RRset("www.example.", dns.TypeA)
		if after == nil || after.RRs[0].(*dns.A).A.String() != "192.0.2.7" {
			t.Fatalf("read after write does not see the write: %v", after)
		}
		if s.RRset("nothere.example.", dns.TypeA) != nil {
			t.Fatal("an absent owner reads as non-nil")
		}
		if s.RRset("www.example.", dns.TypeTXT) != nil {
			t.Fatal("an absent type reads as non-nil")
		}
		if types := s.Types("www.example."); len(types) != 1 || types[0] != dns.TypeA {
			t.Fatalf("Types(www) = %v, want [A]", types)
		}
		if s.Types("nothere.example.") != nil {
			t.Fatal("Types of an absent owner is not nil")
		}
		s.Delete("www.example.", dns.TypeA)
		if types := s.Types("www.example."); len(types) != 0 {
			t.Fatalf("Types(www) after deleting its only type = %v, want none", types)
		}
		s.SetRRset("www.example.", *before)
		return true, nil
	})
	if err != nil {
		t.Fatalf("StageBatch: %v", err)
	}
	if got := servedA(t, zd, "www.example."); got != "192.0.2.7" {
		t.Fatalf("served %q, want 192.0.2.7", got)
	}
}

func TestStageBatchDeleteOwnerDropsTheName(t *testing.T) {
	zd := testSnapshotZone(t, "example.", stagingTestZone)
	_, err := zd.StageBatch(func(s Stager) (bool, error) {
		s.Delete("txt.example.", dns.TypeTXT)
		if len(s.Types("txt.example.")) != 0 {
			t.Fatal("txt.example. still has types after its only one was deleted")
		}
		s.DeleteOwner("txt.example.")
		s.Delete("ghost.example.", dns.TypeA) // absent: must not create it
		return true, nil
	})
	if err != nil {
		t.Fatalf("StageBatch: %v", err)
	}
	if zd.NameExists("txt.example.") {
		t.Fatal("DeleteOwner left the name in the published snapshot")
	}
	if zd.NameExists("ghost.example.") {
		t.Fatal("Delete on an absent owner created it")
	}
}

func TestStageBatchOnDraftPublishesNothing(t *testing.T) {
	zd := draftZone(t, "example.", stagingTestZone)
	serial := zd.CurrentSerial
	resp, err := zd.StageBatch(func(s Stager) (bool, error) {
		if rs := s.RRset("www.example.", dns.TypeA); rs == nil || rs.RRs[0].(*dns.A).A.String() != "192.0.2.1" {
			t.Errorf("Stager.RRset on a draft does not read Data: %v", rs)
		}
		s.SetRRset("www.example.", coreRRset("www.example.", dns.TypeA, "192.0.2.2"))
		s.Delete("txt.example.", dns.TypeTXT)
		s.DeleteOwner("txt.example.")
		return true, nil
	})
	if err != nil {
		t.Fatalf("StageBatch on a draft: %v", err)
	}
	if zd.HasPublishedData() {
		t.Fatal("a batch on a draft published a snapshot")
	}
	if resp.NewSerial != serial || zd.CurrentSerial != serial {
		t.Fatalf("a batch on a draft moved the serial: %d -> %d", serial, zd.CurrentSerial)
	}
	rs, _ := zd.RRsetForAnalysis("www.example.", dns.TypeA)
	if rs == nil || rs.RRs[0].(*dns.A).A.String() != "192.0.2.2" {
		t.Fatalf("the draft batch did not reach Data: %v", rs)
	}
	if od, _ := zd.OwnerForAnalysis("txt.example."); od != nil {
		t.Fatal("DeleteOwner on a draft left the owner in Data")
	}
	Zones.Set(zd.ZoneName, zd)
	t.Cleanup(func() { Zones.Remove(zd.ZoneName) })
	zd.InstallInitialSnapshot()
	t.Cleanup(zd.StopPublisher)
	if got := servedA(t, zd, "www.example."); got != "192.0.2.2" {
		t.Fatalf("served %q after install, want 192.0.2.2", got)
	}
}

func TestStageBatchErrorUnwinds(t *testing.T) {
	zd := testSnapshotZone(t, "example.", stagingTestZone)
	before := zd.snapshot.Load()
	serial := zd.CurrentSerial
	boom := errors.New("boom")

	resp, err := zd.StageBatch(func(s Stager) (bool, error) {
		s.SetRRset("www.example.", coreRRset("www.example.", dns.TypeA, "192.0.2.2"))
		return true, boom
	})
	if !errors.Is(err, boom) || !resp.Error {
		t.Fatalf("StageBatch: err=%v resp=%+v, want the callback's error", err, resp)
	}
	if zd.snapshot.Load() != before || zd.CurrentSerial != serial {
		t.Fatal("a failed batch published")
	}
	zd.mu.Lock()
	leftover := zd.workingSet != nil
	zd.mu.Unlock()
	if leftover {
		t.Fatal("a failed batch left its writes staged")
	}
	// And nothing rides out on the next publish.
	if _, err := zd.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := servedA(t, zd, "www.example."); got != "192.0.2.1" {
		t.Fatalf("the failed batch's write was published later: serving %s", got)
	}

	// With somebody else's work pending, only the batch's writes go.
	zd.StageRRset("a.example.", coreRRset("a.example.", dns.TypeA, "192.0.2.3"))
	_, err = zd.StageBatch(func(s Stager) (bool, error) {
		s.SetRRset("www.example.", coreRRset("www.example.", dns.TypeA, "192.0.2.2"))
		return true, boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("StageBatch: err=%v", err)
	}
	if _, err := zd.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := servedA(t, zd, "a.example."); got != "192.0.2.3" {
		t.Fatalf("the pending stage from before the failed batch was lost: serving %q", got)
	}
	if got := servedA(t, zd, "www.example."); got != "192.0.2.1" {
		t.Fatalf("the failed batch's write survived: serving %s", got)
	}
}

// A refresh that arrives while a batch is running waits for zd.mu and
// publishes AFTER it: the batch costs exactly one serial and its content is
// served before the refresh's, never republished by it (review A4).
func TestStageBatchHoldsOffARefresh(t *testing.T) {
	zd := testSnapshotZone(t, "example.", stagingTestZone)
	serial := zd.CurrentSerial

	refreshed := `example.	3600	IN	SOA	ns.example. hostmaster.example. 2 7200 1800 604800 7200
example.	3600	IN	NS	ns.example.
www.example.	3600	IN	A	192.0.2.50
`
	newZd := draftZone(t, "example.", refreshed)

	inBatch := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	var batchResp BumperResponse
	var batchErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		batchResp, batchErr = zd.StageBatch(func(s Stager) (bool, error) {
			s.SetRRset("www.example.", coreRRset("www.example.", dns.TypeA, "192.0.2.2"))
			close(inBatch)
			<-release
			return true, nil
		})
	}()
	<-inBatch

	refreshDone := make(chan struct{})
	go func() {
		defer close(refreshDone)
		zd.mu.Lock()
		defer zd.mu.Unlock()
		if err := zd.applyRefreshReplacementLocked(newZd, nil, false, true); err != nil {
			t.Errorf("applyRefreshReplacementLocked: %v", err)
		}
	}()

	// The refresh is parked on zd.mu: nothing has been published.
	select {
	case <-refreshDone:
		t.Fatal("the refresh published while the batch held zd.mu")
	case <-time.After(100 * time.Millisecond):
	}
	if got := servedAUnlocked(zd, "www.example."); got != "192.0.2.1" {
		t.Fatalf("served content moved while the batch held the lock: %s", got)
	}

	close(release)
	wg.Wait()
	<-refreshDone

	if batchErr != nil {
		t.Fatalf("StageBatch: %v", batchErr)
	}
	if batchResp.NewSerial != serial+1 {
		t.Fatalf("the batch got serial %d, want %d: the refresh went first", batchResp.NewSerial, serial+1)
	}
	if zd.CurrentSerial != serial+2 {
		t.Fatalf("after batch and refresh the serial is %d, want %d", zd.CurrentSerial, serial+2)
	}
	if got := servedA(t, zd, "www.example."); got != "192.0.2.50" {
		t.Fatalf("the refresh's content is not what is served: %s", got)
	}
}
