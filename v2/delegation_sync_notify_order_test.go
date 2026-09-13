/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

var errTestApplyRefused = errors.New("the updater refused this update")

// fakeUpdaterLog records what the NOTIFY scheme did, in the order it happened.
type fakeUpdaterLog struct {
	mu     sync.Mutex
	events []string
}

func (l *fakeUpdaterLog) record(event string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

func (l *fakeUpdaterLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

// notifySchemeRig stands up the two goroutines SyncZoneDelegationViaNotify
// talks to -- the zone updater and the notifier -- and logs which one acted
// first.
//
// The updater deliberately takes its time before it responds. That delay is
// the whole test: the ordering bug is invisible when the apply is instant,
// because the race is only ever won by a hair in production too.
// serveQueue runs handle for every request on q, on its own goroutine, until
// the test ends.
//
// One shape for every fake engine in this file, because each of them used to
// get it slightly wrong: a done channel closed on the way out and never waited
// for, a receive that ignored ok (so a closed queue delivered zero values
// forever), and a sleep inside the loop that cancellation could not reach.
// Here the loop exits on the context or on a closed queue, handle is given the
// context so any wait inside it can be abandoned, and cleanup cancels and then
// WAITS -- with a deadline, so a wedged fake fails the test instead of hanging
// the run.
func serveQueue[T any](t *testing.T, q <-chan T, handle func(ctx context.Context, req T)) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	exited := make(chan struct{})
	go func(ctx context.Context) {
		defer close(exited)
		for {
			select {
			case req, ok := <-q:
				if !ok {
					return
				}
				handle(ctx, req)
			case <-ctx.Done():
				return
			}
		}
	}(ctx)
	t.Cleanup(func() {
		cancel()
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			t.Error("a fake engine did not exit within 5s of cancellation")
		}
	})
}

func notifySchemeRig(t *testing.T, applyDelay time.Duration) (*ZoneData, chan NotifyRequest, *fakeUpdaterLog, func()) {
	t.Helper()

	updateq := make(chan UpdateRequest, 4)
	notifyq := make(chan NotifyRequest, 4)
	log := &fakeUpdaterLog{}

	zd := testZone(t, "example.", csyncTestZone)
	// publishWorkingSetLocked refuses to swap a snapshot for a zone that is not
	// in Zones (zoneStillLive), so the rig's updater could not publish anything
	// without this.
	registerZones(t, zd)
	zd.KeyDB = &KeyDB{UpdateQ: updateq}
	zd.Options = map[ZoneOption]bool{OptAllowUpdates: true}
	zd.CurrentSerial = 17

	// The zone updater.
	serveQueue(t, updateq, func(ctx context.Context, ur UpdateRequest) {
		// Cancellable, so a test that ends mid-delay does not leave this
		// goroutine asleep past its own cleanup.
		select {
		case <-time.After(applyDelay):
		case <-ctx.Done():
			return
		}
		// Actually publish it. A rig that only ANSWERS cannot tell a caller
		// that checks the postcondition from one that trusts the reply, and
		// the whole point here is which of those the NOTIFY scheme does.
		applyCsyncActions(zd, ur.Actions)
		log.record("published")
		ur.respond(true, nil)
	})

	// The notifier.
	serveQueue(t, notifyq, func(ctx context.Context, _ NotifyRequest) {
		log.record("notified")
	})

	// Kept for the callers' defer; serveQueue's cleanup does the stopping.
	return zd, notifyq, log, func() {}
}

// applyCsyncActions publishes the add half of a CSYNC update into the zone.
// The class-ANY delete that precedes it is a no-op here: nothing in these tests
// starts with a CSYNC.
func applyCsyncActions(zd *ZoneData, actions []dns.RR) {
	var rrs []dns.RR
	for _, rr := range actions {
		if rr.Header().Class == dns.ClassINET && rr.Header().Rrtype == dns.TypeCSYNC {
			rrs = append(rrs, rr)
		}
	}
	if len(rrs) == 0 {
		return
	}
	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.ensureWorkingSet()
	zd.stageRRsetLocked(zd.ZoneName, core.RRset{
		Name: zd.ZoneName, RRtype: dns.TypeCSYNC, Class: dns.ClassINET, RRs: rrs,
	})
	zd.publishLocked(zd.generation.Load())
}

// TestNotifySchemeTellsTheParentOnlyAfterTheCsyncIsPublished is the ordering
// contract of the whole scheme.
//
// A NOTIFY says "come and fetch my CSYNC". PublishCsyncRR only ENQUEUES a
// ZONE-UPDATE, so sending the NOTIFY straight after it told the parent to look
// before the record was there. A parent that looks and finds no CSYNC
// concludes there is nothing to do -- and both sides then report success while
// the delegation never converges. That is #507's shape on a different scheme:
// a silent no-op that reads as a completed sync.
func TestNotifySchemeTellsTheParentOnlyAfterTheCsyncIsPublished(t *testing.T) {
	zd, notifyq, log, stop := notifySchemeRig(t, 50*time.Millisecond)
	defer stop()

	syncstate := DelegationSyncStatus{
		NsAdds: []dns.RR{mustRR(t, "example. 3600 IN NS ns2.example.")},
	}
	target := &DsyncTarget{Name: "parent.", Addresses: []string{"192.0.2.53:53"}}

	_, rcode, err := zd.SyncZoneDelegationViaNotify(context.Background(), zd.KeyDB, notifyq, syncstate, target)
	if err != nil {
		t.Fatalf("SyncZoneDelegationViaNotify: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR", dns.RcodeToString[int(rcode)])
	}

	waitForEvents(t, log, 2)
	events := log.snapshot()
	if events[0] != "published" {
		t.Errorf("event order = %v; the parent was told to fetch a CSYNC that had not been published yet", events)
	}
}

// TestNotifySchemeReportsFailureWhenTheCsyncCannotBePublished: if the CSYNC
// never lands there is nothing for the parent to fetch, so claiming the sync
// succeeded would leave the delegation broken with no error anywhere.
func TestNotifySchemeReportsFailureWhenTheCsyncCannotBePublished(t *testing.T) {
	updateq := make(chan UpdateRequest, 1)
	notifyq := make(chan NotifyRequest, 4)

	zd := testZone(t, "example.", csyncTestZone)
	zd.KeyDB = &KeyDB{UpdateQ: updateq}
	zd.Options = map[ZoneOption]bool{OptAllowUpdates: true}

	serveQueue(t, updateq, func(_ context.Context, ur UpdateRequest) {
		ur.respond(false, errTestApplyRefused)
	})

	syncstate := DelegationSyncStatus{
		NsAdds: []dns.RR{mustRR(t, "example. 3600 IN NS ns2.example.")},
	}
	target := &DsyncTarget{Name: "parent.", Addresses: []string{"192.0.2.53:53"}}

	_, rcode, err := zd.SyncZoneDelegationViaNotify(context.Background(), zd.KeyDB, notifyq, syncstate, target)
	if err == nil {
		t.Fatal("a refused CSYNC publish reported success; the parent would never have found a CSYNC to fetch")
	}
	if rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL", dns.RcodeToString[int(rcode)])
	}
	if len(notifyq) != 0 {
		t.Error("a NOTIFY went out even though the CSYNC was never published")
	}
}

// TestNotifySchemeDoesNotBlockOnAStuckNotifier: notifyq is served by another
// goroutine, and the delegation syncher is the single goroutine that has to
// keep servicing every other zone. A bare send on a full queue used to wedge
// it with no way out at shutdown.
func TestNotifySchemeDoesNotBlockOnAStuckNotifier(t *testing.T) {
	zd, _, _, stop := notifySchemeRig(t, 0)
	defer stop()

	stuck := make(chan NotifyRequest) // unbuffered, nobody reading
	ctx, cancel := context.WithCancel(context.Background())

	syncstate := DelegationSyncStatus{
		NsAdds: []dns.RR{mustRR(t, "example. 3600 IN NS ns2.example.")},
	}
	target := &DsyncTarget{Name: "parent.", Addresses: []string{"192.0.2.53:53"}}

	returned := make(chan error, 1)
	go func() {
		_, _, err := zd.SyncZoneDelegationViaNotify(ctx, zd.KeyDB, stuck, syncstate, target)
		returned <- err
	}()

	// Give it time to get past the publish and reach the send, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-returned:
		if err == nil {
			t.Error("cancelled mid-send but reported the NOTIFY as sent")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SyncZoneDelegationViaNotify did not return after cancellation; the syncher is wedged on the notifier")
	}
}

func waitForEvents(t *testing.T, log *fakeUpdaterLog, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(log.snapshot()) >= n {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("only saw %v, wanted %d events", log.snapshot(), n)
}

// TestNotifySchemeRefusesWhenTheUpdateChangedNothing.
//
// ZONE-UPDATE answers with ur.respond(updated, err), and updated is false BOTH
// for a republish of an identical record -- where the CSYNC is there, and the
// NOTIFY is correct -- and for an update the zone declined to apply, where it is
// not. One bool, two opposite outcomes, so the wait checks the postcondition:
// is a CSYNC actually published?
func TestNotifySchemeRefusesWhenTheUpdateChangedNothing(t *testing.T) {
	updateq := make(chan UpdateRequest, 1)
	notifyq := make(chan NotifyRequest, 4)

	zd := testZone(t, "example.", csyncTestZone)
	zd.KeyDB = &KeyDB{UpdateQ: updateq}
	zd.Options = map[ZoneOption]bool{OptAllowUpdates: true}

	serveQueue(t, updateq, func(_ context.Context, ur UpdateRequest) {
		// Applied false, no error, and nothing published: the shape a
		// declined update takes.
		ur.respond(false, nil)
	})

	syncstate := DelegationSyncStatus{
		NsAdds: []dns.RR{mustRR(t, "example. 3600 IN NS ns2.example.")},
	}
	target := &DsyncTarget{Name: "parent.", Addresses: []string{"192.0.2.53:53"}}

	_, rcode, err := zd.SyncZoneDelegationViaNotify(context.Background(), zd.KeyDB, notifyq, syncstate, target)
	if err == nil {
		t.Fatal("reported success when no CSYNC was published; the parent would be told" +
			" to fetch a record that is not there")
	}
	if rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL", dns.RcodeToString[int(rcode)])
	}
	if len(notifyq) != 0 {
		t.Error("a NOTIFY went out for a CSYNC that was never published")
	}
}

// TestNotifySchemeRefusesWhenOnlyAStaleCsyncIsPublished.
//
// The wait checks that the CSYNC is published. It has to check that THIS CSYNC
// is published: a zone whose apex still holds an older record, whose
// replacement was then declined, satisfies "a CSYNC exists" while the parent
// would come and fetch the stale one -- and act on a serial the child is no
// longer advertising. That is the same silent divergence the wait was added to
// prevent, one level down.
func TestNotifySchemeRefusesWhenOnlyAStaleCsyncIsPublished(t *testing.T) {
	updateq := make(chan UpdateRequest, 1)
	notifyq := make(chan NotifyRequest, 4)

	zd := testZone(t, "example.", csyncTestZone)
	registerZones(t, zd)
	zd.KeyDB = &KeyDB{UpdateQ: updateq}
	zd.Options = map[ZoneOption]bool{OptAllowUpdates: true}
	zd.CurrentSerial = 17

	// An older CSYNC is already published, carrying a serial the child has
	// moved on from.
	stale := &dns.CSYNC{Serial: 11, Flags: csyncFlagImmediate, TypeBitMap: csyncPublishedTypes}
	stale.Hdr = dns.RR_Header{Name: zd.ZoneName, Rrtype: dns.TypeCSYNC, Class: dns.ClassINET, Ttl: 120}
	zd.mu.Lock()
	zd.ensureWorkingSet()
	zd.stageRRsetLocked(zd.ZoneName, core.RRset{
		Name: zd.ZoneName, RRtype: dns.TypeCSYNC, Class: dns.ClassINET, RRs: []dns.RR{stale},
	})
	zd.publishLocked(zd.generation.Load())
	zd.mu.Unlock()

	serveQueue(t, updateq, func(_ context.Context, ur UpdateRequest) {
		// Declined: the replacement never lands, the stale record stays.
		ur.respond(false, nil)
	})

	syncstate := DelegationSyncStatus{
		NsAdds: []dns.RR{mustRR(t, "example. 3600 IN NS ns2.example.")},
	}
	target := &DsyncTarget{Name: "parent.", Addresses: []string{"192.0.2.53:53"}}

	_, rcode, err := zd.SyncZoneDelegationViaNotify(context.Background(), zd.KeyDB, notifyq, syncstate, target)
	if err == nil {
		t.Fatal("reported success while only a STALE CSYNC was published; the parent would" +
			" fetch it and act on a serial the child no longer advertises")
	}
	if rcode != dns.RcodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL", dns.RcodeToString[int(rcode)])
	}
	if len(notifyq) != 0 {
		t.Error("a NOTIFY went out for a CSYNC that was never published")
	}
}
