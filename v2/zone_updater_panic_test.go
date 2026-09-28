package tdns

import (
	"context"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Panic recovery in the ZoneUpdater (#808): a panic applying one request fails
// that request, and leaves nothing behind -- no half-applied change staged,
// published or committed, no zone lock held, no keystore transaction open.

const updatePanicMsg = "malformed update data"

// Two private-use record types for these tests only, each with rdata that
// panics in one place, as a bug reached from an update's records would.
// Everything else behaves, so the record gets as far as the point under test.
const (
	typePANICCOPY = 65534 // copying it panics: the appliers copy every record
	typePANICTEXT = 65533 // printing it panics: the publish journals it as text
)

type panicCopyRdata struct{}

func (*panicCopyRdata) String() string              { return "x" }
func (*panicCopyRdata) Parse([]string) error        { return nil }
func (*panicCopyRdata) Pack([]byte) (int, error)    { return 0, nil }
func (*panicCopyRdata) Unpack([]byte) (int, error)  { return 0, nil }
func (*panicCopyRdata) Copy(dns.PrivateRdata) error { panic(updatePanicMsg) }
func (*panicCopyRdata) Len() int                    { return 0 }

type panicTextRdata struct{}

func (*panicTextRdata) String() string              { panic(updatePanicMsg) }
func (*panicTextRdata) Parse([]string) error        { return nil }
func (*panicTextRdata) Pack([]byte) (int, error)    { return 0, nil }
func (*panicTextRdata) Unpack([]byte) (int, error)  { return 0, nil }
func (*panicTextRdata) Copy(dns.PrivateRdata) error { return nil }
func (*panicTextRdata) Len() int                    { return 0 }

// privateTestRR registers a private type for the test and returns a record of
// it at owner.
func privateTestRR(t *testing.T, name string, rrtype uint16, gen func() dns.PrivateRdata, owner string) dns.RR {
	t.Helper()
	dns.PrivateHandle(name, rrtype, gen)
	t.Cleanup(func() { dns.PrivateHandleRemove(rrtype) })
	rr, err := dns.NewRR(owner + " 3600 IN " + name + " x")
	if err != nil {
		t.Fatalf("NewRR %s: %v", name, err)
	}
	return rr
}

// panicRR is a record at owner whose copy panics.
func panicRR(t *testing.T, owner string) dns.RR {
	t.Helper()
	return privateTestRR(t, "PANICCOPY", typePANICCOPY, func() dns.PrivateRdata { return new(panicCopyRdata) }, owner)
}

// recovered runs fn and returns what it panicked with, or nil.
func recovered(fn func()) (rec any) {
	defer func() { rec = recover() }()
	fn()
	return nil
}

// panicTestZone is example. (deltaZone) with a keystore, the zone and child
// update policies allowing A and NS, and registered for the updater.
func panicTestZone(t *testing.T) (*ZoneData, *KeyDB) {
	t.Helper()
	kdb := newTestKeyDB(t)
	zd := testZone(t, "example.", deltaZone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.ZoneType = Primary
	zd.UpdatePolicy = policyAllowing(dns.TypeA, dns.TypeNS)
	zd.UpdatePolicy.Child = UpdatePolicyDetail{
		Type:    "selfsub",
		RRtypes: map[uint16]bool{dns.TypeNS: true, dns.TypeA: true},
		TTL:     3600,
	}
	if zd.Options == nil {
		zd.Options = map[ZoneOption]bool{}
	}
	return zd, kdb
}

// assertNothingLeftBehind checks the zone after an update that panicked: its
// lock is free, nothing is staged, nothing was published or journalled, and
// owner -- which the update had staged before the panic -- is not served.
func assertNothingLeftBehind(t *testing.T, zd *ZoneData, kdb *KeyDB, serialBefore uint32, owner string) {
	t.Helper()
	if !zd.mu.TryLock() {
		t.Fatal("the zone is still locked after the update panicked")
	}
	staged := zd.workingSet != nil
	zd.mu.Unlock()
	if staged {
		t.Error("the working set still holds what the update staged before it panicked")
	}
	if zd.CurrentSerial != serialBefore {
		t.Errorf("serial %d, want %d: the half-applied update was published", zd.CurrentSerial, serialBefore)
	}
	if od, _ := zd.GetOwner(owner); od != nil {
		t.Errorf("%s is served: the half-applied update was published", owner)
	}
	if _, have, err := kdb.LastZoneDeltaSerial(zd.ZoneName); err != nil || have {
		t.Errorf("journal has a delta (err %v): the half-applied update was persisted", err)
	}
}

// The next update is applied, and carries only its own change: nothing the
// update that panicked had staged rides out with it.
func assertNextUpdateCarriesOnlyItself(t *testing.T, zd *ZoneData, apply func(dns.RR) (bool, error), next, stale string) {
	t.Helper()
	rr, err := dns.NewRR(next)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := apply(rr)
	if err != nil || !updated {
		t.Fatalf("next update: updated %v, err %v; want it applied", updated, err)
	}
	if od, _ := zd.GetOwner(rr.Header().Name); od == nil {
		t.Errorf("%s not served after the next update", rr.Header().Name)
	}
	if od, _ := zd.GetOwner(stale); od != nil {
		t.Errorf("%s is served: the next update published what the one that panicked had staged", stale)
	}
}

func TestZoneUpdateThatPanicsLeavesNothingBehind(t *testing.T) {
	zd, kdb := panicTestZone(t)
	serialBefore := zd.CurrentSerial
	add, err := dns.NewRR("new.example. 3600 IN A 192.0.2.9")
	if err != nil {
		t.Fatal(err)
	}
	apply := func(rrs ...dns.RR) (bool, error) {
		return zd.ApplyZoneUpdateToZoneData(UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: rrs}, kdb)
	}

	rec := recovered(func() { _, _ = apply(add, panicRR(t, "boom.example.")) })

	if rec != updatePanicMsg {
		t.Fatalf("panic %v, want %q", rec, updatePanicMsg)
	}
	assertNothingLeftBehind(t, zd, kdb, serialBefore, "new.example.")
	assertNextUpdateCarriesOnlyItself(t, zd, func(rr dns.RR) (bool, error) { return apply(rr) },
		"next.example. 3600 IN A 192.0.2.10", "new.example.")
}

func TestChildUpdateThatPanicsLeavesNothingBehind(t *testing.T) {
	zd, kdb := panicTestZone(t)
	serialBefore := zd.CurrentSerial
	ns, err := dns.NewRR("child.example. 3600 IN NS ns1.child.example.")
	if err != nil {
		t.Fatal(err)
	}
	apply := func(rrs ...dns.RR) (bool, error) {
		return zd.ApplyChildUpdateToZoneData(UpdateRequest{Cmd: "CHILD-UPDATE", ZoneName: "example.", Actions: rrs}, kdb)
	}

	rec := recovered(func() { _, _ = apply(ns, panicRR(t, "child.example.")) })

	if rec != updatePanicMsg {
		t.Fatalf("panic %v, want %q", rec, updatePanicMsg)
	}
	assertNothingLeftBehind(t, zd, kdb, serialBefore, "child.example.")
	assertNextUpdateCarriesOnlyItself(t, zd, func(rr dns.RR) (bool, error) { return apply(rr) },
		"other.example. 3600 IN NS ns1.other.example.", "child.example.")
}

// A publish that panics cannot be unwound: its working set is dropped, the
// zone says so until a reload settles it with the journal, and the lock is
// released.
func TestPublishThatPanicsDropsTheWorkingSetAndFlagsTheZone(t *testing.T) {
	zd, kdb := panicTestZone(t)

	broken := privateTestRR(t, "PANICTEXT", typePANICTEXT, func() dns.PrivateRdata { return new(panicTextRdata) }, "broken.example.")

	rec := recovered(func() {
		zd.mu.Lock()
		defer zd.mu.Unlock()
		_, _, _ = zd.stageAndPublishLocked(UpdateRequest{ZoneName: "example."}, func() bool {
			// Staged directly: the appliers print what they stage. The publish
			// prints it too, to journal it, after it has moved the serial.
			zd.stageRRsetLocked("broken.example.", core.RRset{Name: "broken.example.", RRtype: typePANICTEXT,
				Class: dns.ClassINET, RRs: []dns.RR{broken}})
			return true
		})
	})

	if rec == nil {
		t.Fatal("the publish did not panic; the test no longer reaches the case it is for")
	}
	if !zd.mu.TryLock() {
		t.Fatal("the zone is still locked after the publish panicked")
	}
	staged := zd.workingSet != nil
	zd.mu.Unlock()
	if staged {
		t.Error("the working set of the publish that panicked was kept")
	}
	if !zd.HasError(PublishError) {
		t.Error("no PublishError on a zone whose publish panicked")
	}
	if ErrorTypeIsServiceImpacting(PublishError) {
		t.Error("PublishError gates the zone; it serves its last published content and must go on doing so")
	}
	if od, _ := zd.GetOwner("www.example."); od == nil {
		t.Error("the zone stopped serving its published content")
	}

	add, err := dns.NewRR("after.example. 3600 IN A 192.0.2.11")
	if err != nil {
		t.Fatal(err)
	}
	if updated, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: "example.",
		Actions: []dns.RR{add}}, kdb); err != nil || !updated {
		t.Fatalf("update after the panic: updated %v, err %v; want it applied", updated, err)
	}

	zd.reconcileZoneFileWithJournal(ZoneFileUnchanged, nil, nil)
	if zd.HasError(PublishError) {
		t.Error("PublishError survived a reconcile with the journal")
	}
}

// A TX-COMMIT that publishes, and panics in the publish, is cleaned up like an
// applier's publish: the zone is not left locked, what the transaction staged
// is dropped rather than left to go out with a later publish, and the zone
// carries a PublishError.
func TestTxCommitWhosePublishPanicsIsCleanedUp(t *testing.T) {
	zd, kdb := panicTestZone(t)
	broken := privateTestRR(t, "PANICTEXT", typePANICTEXT, func() dns.PrivateRdata { return new(panicTextRdata) }, "broken.example.")
	ctx := context.Background()

	// Urgent, so that the commit publishes on the updater's goroutine rather
	// than through the gate.
	if stop := kdb.applyUpdate(ctx, UpdateRequest{Cmd: UpdateCmdTxBegin, ZoneName: "example.", TxID: "t1", TxFlags: TxUrgent}); stop {
		t.Fatal("the updater was told to stop on a TX-BEGIN")
	}
	// What a writer leaves staged under the hold: its own publish was stopped
	// by the hold, with the change and its journal flag still staged.
	zd.mu.Lock()
	zd.stageRRsetLocked("broken.example.", core.RRset{Name: "broken.example.", RRtype: typePANICTEXT,
		Class: dns.ClassINET, RRs: []dns.RR{broken}})
	zd.wsPersistDelta = true
	zd.mu.Unlock()

	resp := make(chan ZoneUpdateResult, 1)
	if stop := kdb.applyUpdate(ctx, UpdateRequest{Cmd: UpdateCmdTxCommit, ZoneName: "example.", TxID: "t1", Resp: resp}); stop {
		t.Fatal("the updater was told to stop after a TX-COMMIT panicked")
	}

	select {
	case res := <-resp:
		if res.Applied || res.Err == nil {
			t.Errorf("answer %+v, want the commit failed", res)
		}
	default:
		t.Error("the commit whose publish panicked got no answer")
	}
	if !zd.mu.TryLock() {
		t.Fatal("the zone is still locked after the commit's publish panicked")
	}
	staged := zd.workingSet != nil
	zd.mu.Unlock()
	if staged {
		t.Error("what the transaction staged was kept, for a later publish to send")
	}
	if !zd.HasError(PublishError) {
		t.Error("no PublishError on a zone whose commit publish panicked")
	}
}

// panicSiteForEndTxTest is where the panic in TestEndTxKeepsThePanicSiteOnTheStack
// starts. Not inlined, so that it is a frame of its own.
//
//go:noinline
func panicSiteForEndTxTest() { panic(updatePanicMsg) }

// endTx recovers, rolls back and panics again. The ZoneUpdater's recover logs
// the stack, and it must still show where the panic started, not only endTx:
// the frames of the first panic are still on the stack when the second begins.
func TestEndTxKeepsThePanicSiteOnTheStack(t *testing.T) {
	kdb := newTestKeyDB(t)
	var stack string
	func() {
		defer func() {
			if recover() != nil {
				stack = string(debug.Stack())
			}
		}()
		_ = func() (err error) {
			tx, err := kdb.Begin("endTx stack test")
			if err != nil {
				t.Fatal(err)
			}
			defer endTx(tx, &err)
			panicSiteForEndTxTest()
			return nil
		}()
	}()

	if !strings.Contains(stack, "endTx") || !strings.Contains(stack, "panicSiteForEndTxTest") {
		t.Errorf("the stack after endTx's panic does not show both endTx and where the panic started:\n%s", stack)
	}
	kdb.mu.Lock()
	open := kdb.Ctx
	kdb.mu.Unlock()
	if open != "" {
		t.Errorf("KeyDB transaction %q still open after endTx", open)
	}
}

// The delegation store rolls a panicking update back. It used to commit it:
// its deferred finishTx saw no error while the panic unwound.
func TestDelegationStoreRollsBackAnUpdateThatPanics(t *testing.T) {
	kdb := newTestKeyDB(t)
	b := &DBDelegationBackend{kdb: kdb}
	ns, err := dns.NewRR("child.example. 3600 IN NS ns1.child.example.")
	if err != nil {
		t.Fatal(err)
	}

	rec := recovered(func() {
		_ = b.ApplyChildUpdate("example.", UpdateRequest{Actions: []dns.RR{ns, panicRR(t, "child.example.")}})
	})

	if rec != updatePanicMsg {
		t.Fatalf("panic %v, want %q", rec, updatePanicMsg)
	}
	data, err := b.GetDelegationData("example.", "child.example.")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatalf("stored %v: the update that panicked was committed", data)
	}
	if err := b.ApplyChildUpdate("example.", UpdateRequest{Actions: []dns.RR{ns}}); err != nil {
		t.Fatalf("next update: %v; the transaction of the one that panicked was left open", err)
	}
}

// A truststore update that panics with its transaction open rolls it back. Left
// open, KeyDB would refuse every later transaction in the process.
func TestTruststoreUpdateThatPanicsRollsBackItsTransaction(t *testing.T) {
	zd, kdb := panicTestZone(t)
	prev := storeTrustKey
	storeTrustKey = func(*KeyDB, *Tx, TruststorePost) (*TruststoreResponse, error) { panic(updatePanicMsg) }
	t.Cleanup(func() { storeTrustKey = prev })
	key, err := dns.NewRR("child.example. 3600 IN KEY 256 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=")
	if err != nil {
		t.Fatal(err)
	}
	resp := make(chan ZoneUpdateResult, 1)

	stop := kdb.applyUpdate(context.Background(), UpdateRequest{Cmd: "TRUSTSTORE-UPDATE", ZoneName: zd.ZoneName,
		Actions: []dns.RR{key}, Resp: resp})

	if stop {
		t.Fatal("the updater was told to stop after a request panicked")
	}
	select {
	case res := <-resp:
		if res.Applied || res.Err == nil || !strings.Contains(res.Err.Error(), "panicked") {
			t.Errorf("answer %+v, want the update failed with the panic", res)
		}
	default:
		t.Error("the caller of the update that panicked got no answer")
	}
	kdb.mu.Lock()
	open := kdb.Ctx
	kdb.mu.Unlock()
	if open != "" {
		t.Fatalf("KeyDB transaction %q still open after the panic", open)
	}
	tx, err := kdb.Begin("after the panic")
	if err != nil {
		t.Fatalf("Begin after the panic: %v", err)
	}
	_ = tx.Rollback()
}

// The engine answers a request that panicked, and takes the next one for the
// same zone: the zone was not left locked, and the loop is still running.
func TestZoneUpdaterCarriesOnAfterAnUpdatePanics(t *testing.T) {
	zd, kdb := panicTestZone(t)
	zd.Options[OptAllowChildUpdates] = true
	zd.DelegationBackend = &DirectDelegationBackend{zd: zd, kdb: kdb}
	// Before the engine starts, so that the type is removed only after the
	// engine has stopped: cleanups run last first, and the engine reads the
	// type tables whenever it logs a record.
	boom := panicRR(t, "child.example.")
	kdb.UpdateQ = make(chan UpdateRequest)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- kdb.ZoneUpdaterEngine(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("ZoneUpdaterEngine did not return within 5s of being cancelled")
		}
	})
	send := func(actions ...dns.RR) ZoneUpdateResult {
		t.Helper()
		resp := make(chan ZoneUpdateResult, 1)
		select {
		case kdb.UpdateQ <- UpdateRequest{Cmd: "CHILD-UPDATE", ZoneName: "example.", Actions: actions, Resp: resp}:
		case <-time.After(5 * time.Second):
			t.Fatal("the updater did not take the request")
		}
		select {
		case res := <-resp:
			return res
		case <-time.After(10 * time.Second):
			t.Fatal("the updater did not answer the request")
		}
		return ZoneUpdateResult{}
	}
	ns, err := dns.NewRR("child.example. 3600 IN NS ns1.child.example.")
	if err != nil {
		t.Fatal(err)
	}

	res := send(ns, boom)
	if res.Applied || res.Err == nil || !strings.Contains(res.Err.Error(), "panicked") {
		t.Fatalf("answer %+v, want the update failed with the panic", res)
	}

	res = send(ns)
	if !res.Applied || res.Err != nil {
		t.Fatalf("next update: %+v, want it applied", res)
	}
	if od, _ := zd.GetOwner("child.example."); od == nil {
		t.Error("child.example. not served after the next update")
	}
}
