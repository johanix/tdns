/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"log"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Zone transactions and held creation: docs/2026-09-17-publish-gate-and-transactions.md,
// step 1. A transaction is a publish hold on one zone. The defect behind it is
// #653: an identity zone went out one record at a time, a secondary served an
// intermediate serial for a second, and a peer that asked in that second was
// told, under a valid signature, that a record about to arrive did not exist.

// syncBuffer is a log sink the publisher goroutine and the hold's timer can
// write while the test reads.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// captureTxLogs routes the package's loggers into a buffer for one test. They
// resolve slog.Default() per record, so swapping the default is enough.
func captureTxLogs(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// logLineWith reports whether one captured line carries every fragment.
func logLineWith(logs string, fragments ...string) bool {
	for _, line := range strings.Split(logs, "\n") {
		all := true
		for _, f := range fragments {
			if !strings.Contains(line, f) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// withTxHoldLimit shortens the hold's limit for one test.
func withTxHoldLimit(t *testing.T, d time.Duration) {
	t.Helper()
	prev := txHoldLimit
	txHoldLimit = d
	t.Cleanup(func() { txHoldLimit = prev })
}

func cleanupTxZone(t *testing.T, zd *ZoneData) {
	t.Helper()
	t.Cleanup(func() {
		zd.stopPublisher()
		Zones.Remove(zd.ZoneName)
	})
}

// newPublishedAutoZone is an auto zone created the ordinary way: published and
// Ready from the start, with no transaction anywhere near it.
func newPublishedAutoZone(t *testing.T, zone string) (*ZoneData, *KeyDB) {
	t.Helper()
	kdb := newTestKeyDB(t)
	zd, err := kdb.CreateAutoZone(zone, nil, []string{"ns.tx.example."})
	if err != nil {
		t.Fatalf("CreateAutoZone(%s): %v", zone, err)
	}
	cleanupTxZone(t, zd)
	return zd, kdb
}

// newHeldAutoZone is an auto zone whose first content is a transaction.
func newHeldAutoZone(t *testing.T, zone string) (*ZoneData, TxID, *KeyDB) {
	t.Helper()
	kdb := newTestKeyDB(t)
	zd, id, err := kdb.CreateAutoZoneHeld(zone, nil, []string{"ns.tx.example."})
	if err != nil {
		t.Fatalf("CreateAutoZoneHeld(%s): %v", zone, err)
	}
	cleanupTxZone(t, zd)
	return zd, id, kdb
}

func txTestRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("dns.NewRR(%q): %v", s, err)
	}
	return rr
}

// stageTxt stages one TXT RRset through the exported staging surface, the way
// a writer outside this package would.
func stageTxt(t *testing.T, zd *ZoneData, owner, text string) {
	t.Helper()
	rr := txTestRR(t, owner+` 300 IN TXT "`+text+`"`)
	zd.StageRRset(owner, core.RRset{Name: owner, RRtype: dns.TypeTXT, Class: dns.ClassINET, RRs: []dns.RR{rr}})
}

// txtUpdate is one internal ZONE-UPDATE adding a TXT record.
func txtUpdate(t *testing.T, zd *ZoneData, owner, text string) UpdateRequest {
	t.Helper()
	return UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        []dns.RR{txTestRR(t, owner+` 300 IN TXT "`+text+`"`)},
		InternalUpdate: true,
	}
}

// served reports whether the published snapshot, which is what a query is
// answered from, holds an RRset of this type at this owner.
func served(zd *ZoneData, owner string, rrtype uint16) bool {
	snap := zd.publishedSnapshot()
	if snap == nil {
		return false
	}
	od := snap.Data[core.CanonicalizeName(owner)]
	if od == nil || od.RRtypes == nil {
		return false
	}
	rs, ok := od.RRtypes.Get(rrtype)
	return ok && len(rs.RRs) > 0
}

// publishState is what a publish changes on the zone besides the snapshot.
type publishState struct {
	snap        *zoneSnapshot
	serial      uint32
	lastPublish time.Time
	persist     bool
}

func readPublishState(zd *ZoneData) publishState {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return publishState{
		snap:        zd.snapshot.Load(),
		serial:      zd.CurrentSerial,
		lastPublish: zd.lastPublish,
		persist:     zd.wsPersistDelta,
	}
}

// To prove first: the update path on a zone that has never published. The
// pieces exist -- a working set seeded from Data when there is no snapshot, an
// applier that stages, a publish that is silent before Ready -- and held
// creation leans on all of them together. This runs today, with no hold
// anywhere: the zone is built the way held creation will leave it, registered
// and without a snapshot.
func TestAnUpdateAppliesToAZoneThatHasNeverPublished(t *testing.T) {
	const zone = "neverpublished.tx.example."
	kdb := newTestKeyDB(t)
	zd := &ZoneData{
		ZoneName:  zone,
		ZoneStore: MapZone,
		Logger:    log.Default(),
		ZoneType:  Primary,
		Options:   map[ZoneOption]bool{OptAutomaticZone: true},
		KeyDB:     kdb,
	}
	if _, _, err := zd.ReadZoneData(`
$ORIGIN neverpublished.tx.example.
$TTL 3600
@ IN SOA ns1 hostmaster 17 3600 1800 1209600 60
@ IN NS ns.tx.example.
`, false); err != nil {
		t.Fatalf("ReadZoneData: %v", err)
	}
	Zones.Set(zone, zd)
	cleanupTxZone(t, zd)

	if zd.publishedSnapshot() != nil {
		t.Fatal("the zone has a snapshot before anything published it")
	}

	updated, err := zd.ApplyZoneUpdateToZoneData(txtUpdate(t, zd, "first."+zone, "one"), kdb)
	if err != nil || !updated {
		t.Fatalf("ApplyZoneUpdateToZoneData on a never-published zone: updated=%v err=%v", updated, err)
	}

	// No hold here, so the update's own publish installs the first snapshot. It
	// has to be the whole zone: what was in Data, and the update on top.
	if zd.publishedSnapshot() == nil {
		t.Fatal("the update's publish installed no snapshot")
	}
	for _, want := range []struct {
		owner  string
		rrtype uint16
	}{{zone, dns.TypeSOA}, {zone, dns.TypeNS}, {"first." + zone, dns.TypeTXT}} {
		if !served(zd, want.owner, want.rrtype) {
			t.Errorf("the first snapshot lacks %s %s", want.owner, dns.TypeToString[want.rrtype])
		}
	}

	// And a second update lands on top of the first, from the snapshot now.
	if updated, err := zd.ApplyZoneUpdateToZoneData(txtUpdate(t, zd, "second."+zone, "two"), kdb); err != nil || !updated {
		t.Fatalf("second update: updated=%v err=%v", updated, err)
	}
	if !served(zd, "first."+zone, dns.TypeTXT) || !served(zd, "second."+zone, dns.TypeTXT) {
		t.Error("the second publish lost a record")
	}
}

// Must not change: a zone that opens no transaction. CreateAutoZone publishes
// at creation, an update is served when the applier returns, and Publish bumps
// the serial, exactly as before this step.
func TestAZoneThatOpensNoTransactionPublishesAsBefore(t *testing.T) {
	const zone = "plain.tx.example."
	zd, kdb := newPublishedAutoZone(t, zone)

	if zd.publishedSnapshot() == nil || !zd.Ready {
		t.Fatalf("CreateAutoZone: snapshot=%v ready=%v, want a published, Ready zone",
			zd.publishedSnapshot() != nil, zd.Ready)
	}
	if n := zd.txOpenCount(); n != 0 {
		t.Fatalf("CreateAutoZone opened %d transaction(s)", n)
	}

	before := readPublishState(zd)
	if updated, err := zd.ApplyZoneUpdateToZoneData(txtUpdate(t, zd, "a."+zone, "one"), kdb); err != nil || !updated {
		t.Fatalf("update: updated=%v err=%v", updated, err)
	}
	if !served(zd, "a."+zone, dns.TypeTXT) {
		t.Fatal("the update is not served when the applier returns")
	}
	after := readPublishState(zd)
	if after.serial == before.serial {
		t.Errorf("the update did not bump the serial (%d)", after.serial)
	}

	resp, err := zd.Publish()
	if err != nil || resp.NewSerial == resp.OldSerial {
		t.Errorf("Publish: err=%v old=%d new=%d, want a new serial", err, resp.OldSerial, resp.NewSerial)
	}
	if n := zd.txStoppedPublishes(); n != 0 {
		t.Errorf("%d publish(es) were stopped on a zone with no transaction", n)
	}
}

// A zone created held is registered, so queued changes find it, and has no
// snapshot: that, and not Ready, is what keeps it out of sight. The commit
// installs the first snapshot, and it is the complete zone.
func TestAHeldZoneHasNoSnapshotUntilItsCommit(t *testing.T) {
	const zone = "held.tx.example."
	zd, id, _ := newHeldAutoZone(t, zone)

	if id == "" {
		t.Fatal("CreateAutoZoneHeld returned no transaction")
	}
	if cur, ok := Zones.Get(zone); !ok || cur != zd {
		t.Fatal("the held zone is not registered")
	}
	if zd.publishedSnapshot() != nil {
		t.Fatal("the held zone has a snapshot: it is visible as SOA and NS")
	}
	if zd.Ready {
		t.Fatal("the held zone is Ready")
	}
	if n := zd.txOpenCount(); n != 1 {
		t.Fatalf("%d open transactions, want the creation's one", n)
	}

	stageTxt(t, zd, "a."+zone, "one")
	if zd.publishedSnapshot() != nil {
		t.Fatal("staging published the held zone")
	}
	// The one way to a snapshot that is not a publish of the working set.
	zd.InstallInitialSnapshot()
	if zd.publishedSnapshot() != nil {
		t.Fatal("InstallInitialSnapshot got past the hold")
	}

	if err := zd.CommitTx(id); err != nil {
		t.Fatalf("CommitTx: %v", err)
	}
	if zd.publishedSnapshot() == nil {
		t.Fatal("the commit installed no snapshot")
	}
	for _, want := range []struct {
		owner  string
		rrtype uint16
	}{{zone, dns.TypeSOA}, {zone, dns.TypeNS}, {"a." + zone, dns.TypeTXT}} {
		if !served(zd, want.owner, want.rrtype) {
			t.Errorf("the first snapshot lacks %s %s", want.owner, dns.TypeToString[want.rrtype])
		}
	}
	if !zd.Ready {
		t.Error("an unsigned zone is not Ready after its first snapshot")
	}
	if n := zd.txOpenCount(); n != 0 {
		t.Errorf("%d transaction(s) still open after the commit", n)
	}

	// A transaction commits once.
	if err := zd.CommitTx(id); err == nil {
		t.Error("committing the same transaction twice succeeded")
	}
	if err := zd.CommitTx("no-such-transaction"); err == nil {
		t.Error("committing an unknown transaction succeeded")
	}
}

// A zone created held whose first content could not be signed has no hold and
// no snapshot. InstallInitialSnapshot builds from zd.Data, the creation's SOA
// and NS alone, so it must install nothing there either: the first snapshot
// comes from a publish, the next signing pass or a repeated commit.
func TestAZoneCreatedHeldGetsNoSnapshotFromItsTemplate(t *testing.T) {
	const zone = "template.tx.example."
	zd, id, _ := newHeldSigningZone(t, zone, nil) // no policy: "not yet"
	stageTxt(t, zd, "a."+zone, "one")
	if err := zd.CommitTx(id); err == nil {
		t.Fatal("precondition: the commit of a first content that cannot be signed reported success")
	}
	if zd.publishedSnapshot() != nil {
		t.Fatal("precondition: a snapshot after the refused first content")
	}
	if n := zd.txOpenCount(); n != 0 {
		t.Fatalf("precondition: %d open transaction(s), want the hold closed", n)
	}

	zd.InstallInitialSnapshot()
	if snap := zd.publishedSnapshot(); snap != nil {
		t.Fatalf("InstallInitialSnapshot installed the creation's template on a zone created held (serial %d)", snap.Serial)
	}
	if zd.Ready {
		t.Error("the zone is Ready with no snapshot")
	}
}

// The hold is enforced where every publish passes. The publishers below all
// call publishLocked directly today, so a check in the publisher's loop alone
// would let each of them through. A stopped publish changes nothing: not the
// snapshot, not the serial, not lastPublish, not what is staged for the journal.
func TestNoPublisherGetsThroughAHold(t *testing.T) {
	const zone = "choke.tx.example."
	zd, kdb := newPublishedAutoZone(t, zone)

	id := zd.BeginTx(TxUrgent)
	before := readPublishState(zd)

	publishers := []struct {
		name string
		run  func() error
	}{
		{"Publish", func() error {
			stageTxt(t, zd, "a."+zone, "one")
			resp, err := zd.Publish()
			if err == nil && resp.NewSerial != resp.OldSerial {
				t.Errorf("Publish reports a new serial (%d -> %d) on a held zone", resp.OldSerial, resp.NewSerial)
			}
			return err
		}},
		{"StageBatch", func() error {
			resp, err := zd.StageBatch(func(s Stager) (bool, error) {
				owner := "b." + zone
				s.SetRRset(owner, core.RRset{Name: owner, RRtype: dns.TypeTXT, Class: dns.ClassINET,
					RRs: []dns.RR{txTestRR(t, owner+` 300 IN TXT "two"`)}})
				return true, nil
			})
			if err == nil && resp.NewSerial != resp.OldSerial {
				t.Errorf("StageBatch reports a new serial (%d -> %d) on a held zone", resp.OldSerial, resp.NewSerial)
			}
			return err
		}},
		{"an update's applier", func() error {
			updated, err := zd.ApplyZoneUpdateToZoneData(txtUpdate(t, zd, "c."+zone, "three"), kdb)
			if err == nil && !updated {
				t.Error("the update was not applied")
			}
			return err
		}},
		{"publishNow", func() error {
			zd.publishNow(zd.generation.Load())
			return nil
		}},
		{"the publisher's loop", func() error {
			zd.requestPublish(false)
			time.Sleep(50 * time.Millisecond)
			return nil
		}},
		{"requestPublish(urgent)", func() error {
			zd.requestPublish(true)
			return nil
		}},
	}
	for _, p := range publishers {
		if err := p.run(); err != nil {
			t.Fatalf("%s: %v", p.name, err)
		}
		now := readPublishState(zd)
		if now.snap != before.snap {
			t.Fatalf("%s installed a snapshot on a held zone", p.name)
		}
		if now.serial != before.serial {
			t.Errorf("%s moved the serial on a held zone: %d -> %d", p.name, before.serial, now.serial)
		}
		if !now.lastPublish.Equal(before.lastPublish) {
			t.Errorf("%s moved lastPublish on a held zone", p.name)
		}
	}
	if !readPublishState(zd).persist {
		t.Error("the stopped publish dropped the update's journal mark (wsPersistDelta)")
	}
	if n := zd.txStoppedPublishes(); n == 0 {
		t.Error("the hold counted no stopped publishes")
	}

	// Everything staged during the hold goes out with the commit, as one
	// publish. The hold was urgent, so the commit publishes in the caller.
	if err := zd.CommitTx(id); err != nil {
		t.Fatalf("CommitTx: %v", err)
	}
	after := readPublishState(zd)
	if after.snap == before.snap {
		t.Fatal("an urgent commit did not publish in the caller")
	}
	for _, owner := range []string{"a." + zone, "b." + zone, "c." + zone} {
		if !served(zd, owner, dns.TypeTXT) {
			t.Errorf("%s was staged during the hold and is not in the commit's snapshot", owner)
		}
	}
	if after.serial == before.serial || after.snap.Serial != after.serial {
		t.Errorf("serial after the commit: zone %d, snapshot %d, was %d; want one new serial on both",
			after.serial, after.snap.Serial, before.serial)
	}
}

// The publisher's loop republishes for as long as a publish is queued and the
// cadence has run out. A publish stopped by a hold must not leave it in that
// state, or the loop spins on zd.mu for the length of the hold.
func TestThePublisherDoesNotSpinOnAHeldZone(t *testing.T) {
	const zone = "spin.tx.example."
	zd, _ := newPublishedAutoZone(t, zone)

	id := zd.BeginTx(0)
	stageTxt(t, zd, "a."+zone, "one")
	zd.requestPublish(false)
	time.Sleep(200 * time.Millisecond)

	if served(zd, "a."+zone, dns.TypeTXT) {
		t.Fatal("the publisher's loop published a held zone")
	}
	if n := zd.txStoppedPublishes(); n == 0 {
		t.Error("the publisher's loop never reached the hold")
	} else if n > 3 {
		t.Fatalf("the publisher tried a held zone %d times in 200 ms: it is spinning", n)
	}
	zd.mu.Lock()
	queued := zd.publishQueued
	zd.mu.Unlock()
	if queued {
		t.Error("publishQueued is still set on a held zone; the publisher's loop will retry it")
	}

	// The publish was wanted, and the commit delivers it.
	if err := zd.CommitTx(id); err != nil {
		t.Fatalf("CommitTx: %v", err)
	}
	waitFor(t, 2*time.Second, "the publish the hold had stopped", func() bool {
		return served(zd, "a."+zone, dns.TypeTXT)
	})
}

// Several transactions may be open on one zone. It publishes when the last
// one commits: a commit must not publish another transaction's half. Urgent is
// sticky for the hold.
func TestTheZonePublishesWhenTheLastTransactionCommits(t *testing.T) {
	const zone = "two.tx.example."
	zd, _ := newPublishedAutoZone(t, zone)

	plain := zd.BeginTx(0)
	urgent := zd.BeginTx(TxUrgent)
	if plain == urgent {
		t.Fatalf("two transactions share the id %q", plain)
	}
	stageTxt(t, zd, "a."+zone, "one")
	before := readPublishState(zd)

	if err := zd.CommitTx(urgent); err != nil {
		t.Fatalf("CommitTx(urgent): %v", err)
	}
	if readPublishState(zd).snap != before.snap {
		t.Fatal("the first commit published while another transaction was open")
	}
	if n := zd.txOpenCount(); n != 1 {
		t.Fatalf("%d open transactions after the first commit, want 1", n)
	}

	if err := zd.CommitTx(plain); err != nil {
		t.Fatalf("CommitTx(plain): %v", err)
	}
	// The closing transaction was plain, but one of the hold's was urgent.
	if !served(zd, "a."+zone, dns.TypeTXT) {
		t.Fatal("the closing commit of an urgent hold did not publish at once")
	}
}

// Without urgent, the commit of a Ready zone asks the gate: at once on an idle
// zone, otherwise at lastPublish + cadence. Wrapping every change in its own
// transaction must not bring per-record publishing back.
func TestAPlainCommitOnAReadyZoneAsksTheGate(t *testing.T) {
	const zone = "gate.tx.example."
	zd, _ := newPublishedAutoZone(t, zone)
	zd.mu.Lock()
	zd.publishCadence = 400 * time.Millisecond
	zd.mu.Unlock()

	// Make the zone busy: it published just now.
	if _, err := zd.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	busy := readPublishState(zd)

	id := zd.BeginTx(0)
	stageTxt(t, zd, "a."+zone, "one")
	if err := zd.CommitTx(id); err != nil {
		t.Fatalf("CommitTx: %v", err)
	}
	if readPublishState(zd).snap != busy.snap {
		t.Fatal("a plain commit on a busy zone published at once; it must wait for the gate")
	}
	waitFor(t, 3*time.Second, "the gate's publish", func() bool {
		return served(zd, "a."+zone, dns.TypeTXT)
	})
	if waited := readPublishState(zd).lastPublish.Sub(busy.lastPublish); waited < 350*time.Millisecond {
		t.Errorf("the gate published %v after the previous publish, cadence is 400 ms", waited)
	}
}

// A transaction is not isolation. A zone has one working set, and what another
// writer stages during the hold goes out with the commit.
func TestAnotherWritersChangeGoesOutWithTheCommit(t *testing.T) {
	const zone = "ride.tx.example."
	zd, id, kdb := newHeldAutoZone(t, zone)

	if updated, err := zd.ApplyZoneUpdateToZoneData(txtUpdate(t, zd, "other."+zone, "theirs"), kdb); err != nil || !updated {
		t.Fatalf("another writer's update: updated=%v err=%v", updated, err)
	}
	if zd.publishedSnapshot() != nil {
		t.Fatal("another writer's update published the held zone")
	}
	stageTxt(t, zd, "mine."+zone, "mine")

	if err := zd.CommitTx(id); err != nil {
		t.Fatalf("CommitTx: %v", err)
	}
	for _, owner := range []string{"other." + zone, "mine." + zone} {
		if !served(zd, owner, dns.TypeTXT) {
			t.Errorf("%s is not in the first snapshot", owner)
		}
	}
}

// A zone created held is never a draft. The exported staging surface takes a
// zone with no snapshot for the scratch zone of a pre-refresh callback: it
// writes zd.Data and publishes nothing, because the refresh is the publish.
// No refresh is coming for a held zone, and once its working set is seeded a
// write to zd.Data reaches nothing.
func TestAZoneCreatedHeldIsNeverADraft(t *testing.T) {
	const zone = "draft.tx.example."
	zd, id, kdb := newHeldAutoZone(t, zone)
	if zd.publishedSnapshot() != nil {
		t.Fatal("the zone is not held: it has a snapshot, so nothing here can take it for a draft")
	}

	// Before the working set exists.
	stageTxt(t, zd, "early."+zone, "early")
	// This seeds it.
	if updated, err := zd.ApplyZoneUpdateToZoneData(txtUpdate(t, zd, "queued."+zone, "queued"), kdb); err != nil || !updated {
		t.Fatalf("update: updated=%v err=%v", updated, err)
	}
	// After it exists: the write that a draft would lose.
	stageTxt(t, zd, "late."+zone, "late")
	if _, err := zd.StageBatch(func(s Stager) (bool, error) {
		owner := "batch." + zone
		if s.RRset("early."+zone, dns.TypeTXT) == nil {
			t.Error("a batch on a held zone cannot read what was staged before it")
		}
		s.SetRRset(owner, core.RRset{Name: owner, RRtype: dns.TypeTXT, Class: dns.ClassINET,
			RRs: []dns.RR{txTestRR(t, owner+` 300 IN TXT "batch"`)}})
		return true, nil
	}); err != nil {
		t.Fatalf("StageBatch: %v", err)
	}
	stageTxt(t, zd, "gone."+zone, "gone")
	zd.StageDelete("gone."+zone, dns.TypeTXT)
	zd.StageOwnerDelete("gone." + zone)

	if err := zd.CommitTx(id); err != nil {
		t.Fatalf("CommitTx: %v", err)
	}
	for _, owner := range []string{"early." + zone, "queued." + zone, "late." + zone, "batch." + zone} {
		if !served(zd, owner, dns.TypeTXT) {
			t.Errorf("%s was staged on a held zone and is not in its first snapshot", owner)
		}
	}
	if snap := zd.publishedSnapshot(); snap != nil && snap.Data[core.CanonicalizeName("gone."+zone)] != nil {
		t.Error("an owner deleted during the hold is in the first snapshot")
	}
}

// The hold's limit, on a zone that has published before: a commit marker can
// be lost. The hold is released with a WARN and what is staged publishes
// through the gate. The zone's previous content was valid, and so is each
// change added to it.
func TestALostCommitOnAPublishedZoneIsReleasedWithAWarning(t *testing.T) {
	withTxHoldLimit(t, 150*time.Millisecond)
	logs := captureTxLogs(t)
	const zone = "lost.tx.example."
	zd, _ := newPublishedAutoZone(t, zone)
	zd.mu.Lock()
	zd.publishCadence = 50 * time.Millisecond
	zd.mu.Unlock()

	id := zd.BeginTx(0)
	stageTxt(t, zd, "a."+zone, "one")
	if _, err := zd.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if served(zd, "a."+zone, dns.TypeTXT) {
		t.Fatal("the change was published during the hold")
	}

	waitFor(t, 3*time.Second, "the release of a hold past its limit", func() bool {
		return served(zd, "a."+zone, dns.TypeTXT)
	})
	if n := zd.txOpenCount(); n != 0 {
		t.Errorf("%d transaction(s) still open after the release", n)
	}
	if !logLineWith(logs.String(), "level=WARN", zone, string(id)) {
		t.Errorf("no WARN naming the zone and the transaction; log:\n%s", logs.String())
	}

	// The zone is an ordinary zone again.
	stageTxt(t, zd, "b."+zone, "two")
	if _, err := zd.Publish(); err != nil {
		t.Fatalf("Publish after the release: %v", err)
	}
	if !served(zd, "b."+zone, dns.TypeTXT) {
		t.Error("the zone stayed held after the release")
	}
	// The commit that was lost may still turn up. It finds nothing to commit.
	if err := zd.CommitTx(id); err == nil {
		t.Error("a commit for a released transaction succeeded")
	}
}

// The hold's limit, on a zone that has never published: fail closed. Releasing
// the hold would publish exactly the partial zone the first-content rule
// forbids. The zone stays unpublished, logs an ERROR, and carries the error in
// its status until a commit arrives.
func TestALostCommitOnANeverPublishedZoneFailsClosed(t *testing.T) {
	withTxHoldLimit(t, 150*time.Millisecond)
	logs := captureTxLogs(t)
	const zone = "closed.tx.example."
	zd, id, _ := newHeldAutoZone(t, zone)

	stageTxt(t, zd, "a."+zone, "one")

	waitFor(t, 3*time.Second, "the zone to report a hold past its limit", func() bool {
		return zd.HasError(FirstPublishError)
	})
	time.Sleep(200 * time.Millisecond)
	if zd.publishedSnapshot() != nil {
		t.Fatal("a never-published zone was released when its hold ran out: the partial zone is visible")
	}
	if zd.Ready {
		t.Error("the zone is Ready without a snapshot")
	}
	if !logLineWith(logs.String(), "level=ERROR", zone) {
		t.Errorf("no ERROR naming the zone; log:\n%s", logs.String())
	}
	if ErrorTypeIsServiceImpacting(FirstPublishError) {
		t.Error("FirstPublishError gates the zone; the retry of an unsigned first content depends on it gating nothing")
	}

	// Still held: no publisher gets through a hold that failed closed.
	if _, err := zd.Publish(); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if zd.publishedSnapshot() != nil {
		t.Fatal("Publish got through a hold that had failed closed")
	}

	// Until a commit arrives.
	if err := zd.CommitTx(id); err != nil {
		t.Fatalf("the late commit: %v", err)
	}
	if !served(zd, "a."+zone, dns.TypeTXT) {
		t.Fatal("the late commit did not publish the zone")
	}
	if zd.HasError(FirstPublishError) {
		t.Error("the error outlived the first publish")
	}
}

// The catalog zone was the other creator that showed a zone as SOA and NS
// first: CreateAutoZone, then the version record in a second publish. Created
// held, its first snapshot has the version record in it. This creator stages
// in-process, on a key store with no update queue, so it commits in-process.
func TestACatalogZonesFirstSnapshotHasItsVersionRecord(t *testing.T) {
	const zone = "catalog.tx.example."
	t.Cleanup(func() {
		stopZonePublisher(zone)
		Zones.Remove(zone)
		forgetCatalogMembership(zone)
	})

	if err := handleCatalogCreate(zone, &CatalogResponse{}); err != nil {
		t.Fatalf("handleCatalogCreate: %v", err)
	}
	zd, ok := Zones.Get(zone)
	if !ok {
		t.Fatal("the catalog zone is not registered")
	}
	snap := zd.publishedSnapshot()
	if snap == nil {
		t.Fatal("the catalog zone has no snapshot")
	}
	if !served(zd, "version."+zone, dns.TypeTXT) || !served(zd, zone, dns.TypeSOA) {
		t.Error("the catalog zone's snapshot lacks its SOA or its version record")
	}
	if !zd.Ready {
		t.Error("the catalog zone is not Ready")
	}
	if n := zd.txOpenCount(); n != 0 {
		t.Errorf("%d transaction(s) left open on the catalog zone", n)
	}
	// The window this closes lasted microseconds and cannot be seen after the
	// fact, so what is pinned is how the zone came to be: created held, which
	// is what TestAHeldZoneHasNoSnapshotUntilItsCommit gives its meaning to.
	zd.mu.Lock()
	createdHeld, draft := zd.tx.createdHeld, zd.isDraftLocked()
	zd.mu.Unlock()
	if !createdHeld {
		t.Error("the catalog zone was not created held: it was visible as SOA and NS before its version record")
	}
	if draft {
		t.Error("the catalog zone is taken for a draft")
	}
	if n := len(snap.IxfrChain); n != 0 {
		t.Errorf("the catalog zone has %d IXFR link(s): it was published more than once", n)
	}
	if catalogMembershipOf(zone) == nil {
		t.Error("the catalog zone has no membership after its create")
	}
}

// The create makes the catalog's membership only once the catalog exists, so
// a create that fails leaves none behind. A membership another catalog handler
// made before the create is kept, members and all.
func TestACatalogCreateKeepsAMembershipMadeBeforeIt(t *testing.T) {
	const zone = "catalog-early.tx.example."
	t.Cleanup(func() {
		stopZonePublisher(zone)
		Zones.Remove(zone)
		forgetCatalogMembership(zone)
	})

	early := GetOrCreateCatalogMembership(zone)
	if err := early.AddMemberZone("member.example."); err != nil {
		t.Fatalf("AddMemberZone: %v", err)
	}
	if err := handleCatalogCreate(zone, &CatalogResponse{}); err != nil {
		t.Fatalf("handleCatalogCreate: %v", err)
	}
	cm := catalogMembershipOf(zone)
	if cm != early {
		t.Fatal("the create replaced the membership made before it")
	}
	cm.mu.Lock()
	_, kept := cm.MemberZones["member.example."]
	cm.mu.Unlock()
	if !kept {
		t.Error("the create dropped a member of the membership made before it")
	}
}

func catalogMembershipOf(zone string) *CatalogMembership {
	catalogMembershipMutex.Lock()
	defer catalogMembershipMutex.Unlock()
	return catalogMemberships[zone]
}

func forgetCatalogMembership(zone string) {
	catalogMembershipMutex.Lock()
	defer catalogMembershipMutex.Unlock()
	delete(catalogMemberships, zone)
}
