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

	var wg sync.WaitGroup
	done := make(chan struct{})

	wg.Add(1)
	go func() { // the zone updater
		defer wg.Done()
		for {
			select {
			case ur := <-updateq:
				time.Sleep(applyDelay)
				// Actually publish it. A rig that only ANSWERS cannot tell a
				// caller that checks the postcondition from one that trusts
				// the reply, and the whole point here is which of those the
				// NOTIFY scheme does.
				applyCsyncActions(zd, ur.Actions)
				log.record("published")
				ur.respond(true, nil)
			case <-done:
				return
			}
		}
	}()

	wg.Add(1)
	go func() { // the notifier
		defer wg.Done()
		for {
			select {
			case <-notifyq:
				log.record("notified")
			case <-done:
				return
			}
		}
	}()

	return zd, notifyq, log, func() {
		close(done)
		wg.Wait()
	}
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

	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case ur := <-updateq:
				ur.respond(false, errTestApplyRefused)
			case <-done:
				return
			}
		}
	}()

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

	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case ur := <-updateq:
				// Applied false, no error, and nothing published: the shape a
				// declined update takes.
				ur.respond(false, nil)
			case <-done:
				return
			}
		}
	}()

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
