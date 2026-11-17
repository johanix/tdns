package tdns

import (
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// breakTheNextPublish makes the zone's next publish refuse: an RRset with no
// records is staged and put in the publish's signing scope, and SignRRset
// refuses it. The refusal keeps the working set (refuseUnsignableWorkingSetLocked),
// which is the case these tests are about. repairThePublish undoes it.
func breakTheNextPublish(t *testing.T, zd *ZoneData) {
	t.Helper()
	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.ensureWorkingSet()
	zd.stageRRsetLocked("broken."+zd.ZoneName, core.RRset{
		Name: "broken." + zd.ZoneName, RRtype: dns.TypeTXT, Class: dns.ClassINET,
	})
	zd.wsSignOwners = map[string]bool{"broken." + zd.ZoneName: true}
}

func repairThePublish(t *testing.T, zd *ZoneData) {
	t.Helper()
	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.stageOwnerDeleteLocked("broken." + zd.ZoneName)
	zd.wsSignOwners = nil
}

func afterPublishCount(zd *ZoneData) int {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return len(zd.afterPublish)
}

// An update whose publish ran in the caller and was refused before the
// journal is answered with the refusal, not reported as applied; its follow-up
// is not run, and stays registered for the publish that carries the change.
func TestAnUpdateRefusedInTheCallerIsAnsweredWithTheError(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := signingTestZone(t, kdb)
	t.Cleanup(func() { zd.stopPublisher(); zd.joinPublisher() })
	breakTheNextPublish(t, zd)
	before := zd.publishedSnapshot()

	ran := make(chan struct{}, 1)
	updated, deferred, err := zd.applyZoneUpdate(txtUpdate(t, zd, "a."+zd.ZoneName, "one"), kdb, func() { ran <- struct{}{} })
	if err == nil || !strings.Contains(err.Error(), "not published") {
		t.Fatalf("a refused publish was reported as applied: updated=%v deferred=%v err=%v", updated, deferred, err)
	}
	if updated || deferred {
		t.Fatalf("a refused publish reported updated=%v deferred=%v", updated, deferred)
	}
	if zd.publishedSnapshot() != before {
		t.Fatal("the refused publish installed a snapshot")
	}
	select {
	case <-ran:
		t.Fatal("the follow-up ran after a refused publish")
	case <-time.After(200 * time.Millisecond):
	}
	if n := afterPublishCount(zd); n != 1 {
		t.Fatalf("the follow-up of a change the refusal kept staged is not registered: %d registered", n)
	}

	// The change is still staged: once the zone can sign again, the next
	// publish carries it and runs what was to follow it.
	repairThePublish(t, zd)
	if _, err := zd.publishSync(); err != nil {
		t.Fatalf("publishSync after the repair: %v", err)
	}
	if !served(zd, "a."+zd.ZoneName, dns.TypeTXT) {
		t.Fatal("the change kept by the refusal was not carried by the next publish")
	}
	select {
	case <-ran:
	case <-time.After(3 * time.Second):
		t.Fatal("the follow-up did not run with the publish that carried the change")
	}
}

// The same on the deferred path: a refused publish of a queued change answers
// the waiter with the refusal and keeps the follow-up for the carrying publish.
func TestARefusedDeferredPublishKeepsTheFollowUp(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := signingTestZone(t, kdb)
	t.Cleanup(func() { zd.stopPublisher(); zd.joinPublisher() })
	zd.mu.Lock()
	zd.publishCadence = 500 * time.Millisecond
	zd.lastPublish = time.Now()
	zd.mu.Unlock()
	breakTheNextPublish(t, zd)
	before := zd.publishedSnapshot()

	ran := make(chan struct{}, 1)
	ur := txtUpdate(t, zd, "b."+zd.ZoneName, "two")
	ur.Resp = make(chan ZoneUpdateResult, 1)
	updated, deferred, err := zd.applyZoneUpdate(ur, kdb, func() { ran <- struct{}{} })
	if err != nil || !updated || !deferred {
		t.Fatalf("the update was not deferred on a busy zone: updated=%v deferred=%v err=%v", updated, deferred, err)
	}
	select {
	case res := <-ur.Resp:
		if res.Err == nil || !strings.Contains(res.Err.Error(), "not published") {
			t.Fatalf("the waiter of a refused publish was answered with %+v", res)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the waiter of a refused publish was not answered")
	}
	if zd.publishedSnapshot() != before {
		t.Fatal("the refused publish installed a snapshot")
	}
	if n := afterPublishCount(zd); n != 1 {
		t.Fatalf("the follow-up was dropped by a refusal that kept the change staged: %d registered", n)
	}

	repairThePublish(t, zd)
	if _, err := zd.publishSync(); err != nil {
		t.Fatalf("publishSync after the repair: %v", err)
	}
	if !served(zd, "b."+zd.ZoneName, dns.TypeTXT) {
		t.Fatal("the change kept by the refusal was not carried by the next publish")
	}
	select {
	case <-ran:
	case <-time.After(3 * time.Second):
		t.Fatal("the follow-up did not run with the publish that carried the change")
	}
}

// StageBatch and Publish report a refusal in the response instead of a serial
// that nothing serves.
func TestABatchAndAPublishRefusedInTheCallerSaySo(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := signingTestZone(t, kdb)
	t.Cleanup(func() { zd.stopPublisher(); zd.joinPublisher() })
	breakTheNextPublish(t, zd)

	resp, err := zd.StageBatch(func(s Stager) (bool, error) {
		s.SetRRset("c."+zd.ZoneName, core.RRset{Name: "c." + zd.ZoneName, RRtype: dns.TypeTXT, Class: dns.ClassINET,
			RRs: []dns.RR{txTestRR(t, "c."+zd.ZoneName+` 300 IN TXT "three"`)}})
		return true, nil
	})
	if err != nil {
		t.Fatalf("StageBatch: %v", err)
	}
	if resp.NewSerial != resp.OldSerial || !strings.Contains(resp.Msg, "not published") {
		t.Fatalf("a refused batch reported serial %d -> %d, msg %q", resp.OldSerial, resp.NewSerial, resp.Msg)
	}

	resp, err = zd.Publish()
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if resp.NewSerial != resp.OldSerial || !strings.Contains(resp.Msg, "not published") {
		t.Fatalf("a refused Publish reported serial %d -> %d, msg %q", resp.OldSerial, resp.NewSerial, resp.Msg)
	}
}
