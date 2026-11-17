/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The gate for every update: docs/2026-09-17-publish-gate-and-transactions.md,
// step 3. An update to an idle zone publishes in the caller, as it always
// did; an update to a busy zone (published within the cadence) is staged and
// published by the zone's publisher at lastPublish + cadence, together with
// everything staged meanwhile; the update's Resp is answered by the publish
// that carries it, never before.

// busyZone is a published auto zone that has just published: busy for one
// cadence, then idle.
func busyZone(t *testing.T, zone string, cadence time.Duration) (*ZoneData, *KeyDB) {
	t.Helper()
	zd, kdb := newPublishedAutoZone(t, zone)
	zd.mu.Lock()
	zd.publishCadence = cadence
	zd.mu.Unlock()
	stageTxt(t, zd, "warm."+zone, "x")
	if _, err := zd.BumpSerial(); err != nil { // the operator's immediate publish warms the zone
		t.Fatalf("BumpSerial: %v", err)
	}
	return zd, kdb
}

func currentSerial(zd *ZoneData) uint32 {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return zd.CurrentSerial
}

// answeredWithin reports what, if anything, arrived on resp within d.
func answeredWithin(resp chan ZoneUpdateResult, d time.Duration) (ZoneUpdateResult, bool) {
	select {
	case r := <-resp:
		return r, true
	case <-time.After(d):
		return ZoneUpdateResult{}, false
	}
}

func TestAnUpdateOnAnIdleZonePublishesInTheCaller(t *testing.T) {
	const zone = "idle.gate.example."
	zd, kdb := newPublishedAutoZone(t, zone)
	zd.mu.Lock()
	zd.publishCadence = 2 * time.Second
	zd.mu.Unlock()
	startTxUpdater(t, kdb)

	ur := txtUpdate(t, zd, "a."+zone, "one")
	ur.Resp = make(chan ZoneUpdateResult, 1)
	before := currentSerial(zd)
	res := sendTx(t, kdb, ur, true)
	if res.Err != nil || !res.Applied {
		t.Fatalf("the update's answer: applied=%v err=%v", res.Applied, res.Err)
	}
	if !served(zd, "a."+zone, dns.TypeTXT) {
		t.Fatal("an update to an idle zone was answered before it was served")
	}
	if got := currentSerial(zd); got != before+1 {
		t.Fatalf("serial %d, want %d", got, before+1)
	}
}

func TestABurstOfUpdatesToABusyZoneIsOnePublishPerCadence(t *testing.T) {
	const zone = "burst.gate.example."
	notifies := withNotifyQ(t, 16)
	zd, kdb := busyZone(t, zone, 500*time.Millisecond)
	zd.mu.Lock()
	zd.Notify = []PeerConf{{Addr: aDownstream}}
	zd.mu.Unlock()
	startTxUpdater(t, kdb)
	for len(notifies) > 0 {
		<-notifies
	}

	before := currentSerial(zd)
	for i := 0; i < 5; i++ {
		sendTx(t, kdb, txtUpdate(t, zd, "r."+zone, "v"+string(rune('a'+i))), false)
	}
	// Staged, not published: the zone is busy.
	waitFor(t, 2*time.Second, "the burst to be staged", func() bool {
		zd.mu.Lock()
		defer zd.mu.Unlock()
		return zd.publishQueued
	})
	if served(zd, "r."+zone, dns.TypeTXT) || currentSerial(zd) != before {
		t.Fatal("a busy zone published an update inside its cadence")
	}
	waitFor(t, 3*time.Second, "the gate's publish", func() bool { return served(zd, "r."+zone, dns.TypeTXT) })
	if got := currentSerial(zd); got != before+1 {
		t.Errorf("serial %d after a burst of five, want %d: one publish", got, before+1)
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(notifies); n != 1 {
		t.Errorf("%d NOTIFY(s) for a burst of five, want 1", n)
	}
}

func TestAnUpdatesRespIsAnsweredByThePublishThatCarriesIt(t *testing.T) {
	const zone = "resp.gate.example."
	zd, kdb := busyZone(t, zone, 600*time.Millisecond)
	startTxUpdater(t, kdb)

	ur := txtUpdate(t, zd, "a."+zone, "one")
	ur.Resp = make(chan ZoneUpdateResult, 1)
	sendTx(t, kdb, ur, false)
	if r, early := answeredWithin(ur.Resp, 200*time.Millisecond); early {
		t.Fatalf("the update was answered (applied=%v err=%v) before its change was published", r.Applied, r.Err)
	}
	if served(zd, "a."+zone, dns.TypeTXT) {
		t.Fatal("precondition: the change was published inside the cadence")
	}
	r, ok := answeredWithin(ur.Resp, 3*time.Second)
	if !ok {
		t.Fatal("the update was never answered")
	}
	if r.Err != nil || !r.Applied {
		t.Fatalf("answer: applied=%v err=%v", r.Applied, r.Err)
	}
	if !served(zd, "a."+zone, dns.TypeTXT) {
		t.Fatal("the update was answered before its change was served")
	}
}

// The known limit of steps 1 and 2 closes: an update that arrives inside a
// hold is answered by the commit's publish, not at staging.
func TestAnUpdateOnAHeldZoneIsAnsweredByTheCommit(t *testing.T) {
	const zone = "heldupdate.gate.example."
	zd, kdb := newPublishedAutoZone(t, zone)
	startTxUpdater(t, kdb)
	id := mustBeginTx(t, zd, TxUrgent)

	ur := txtUpdate(t, zd, "a."+zone, "one")
	ur.Resp = make(chan ZoneUpdateResult, 1)
	sendTx(t, kdb, ur, false)
	if r, early := answeredWithin(ur.Resp, 300*time.Millisecond); early {
		t.Fatalf("an update on a held zone was answered (applied=%v err=%v) before the commit", r.Applied, r.Err)
	}
	if served(zd, "a."+zone, dns.TypeTXT) {
		t.Fatal("precondition: the hold let the update through")
	}
	if err := zd.CommitTx(id); err != nil {
		t.Fatalf("CommitTx: %v", err)
	}
	r, ok := answeredWithin(ur.Resp, 2*time.Second)
	if !ok {
		t.Fatal("the update was not answered by the commit's publish")
	}
	if r.Err != nil || !r.Applied || !served(zd, "a."+zone, dns.TypeTXT) {
		t.Fatalf("answer: applied=%v err=%v served=%v", r.Applied, r.Err, served(zd, "a."+zone, dns.TypeTXT))
	}
}

// A replay (the journal at start, a merge) publishes in the caller: it is not
// churn, and what runs after it reads the zone back.
func TestAReplayPublishesInTheCaller(t *testing.T) {
	const zone = "replay.gate.example."
	zd, kdb := busyZone(t, zone, 2*time.Second)
	startTxUpdater(t, kdb)

	ur := txtUpdate(t, zd, "a."+zone, "one")
	ur.Replay = true
	ur.Resp = make(chan ZoneUpdateResult, 1)
	r, ok := answeredWithin(func() chan ZoneUpdateResult { sendTx(t, kdb, ur, false); return ur.Resp }(), 500*time.Millisecond)
	if !ok {
		t.Fatal("a replay on a busy zone waited for the cadence")
	}
	if r.Err != nil || !r.Applied || !served(zd, "a."+zone, dns.TypeTXT) {
		t.Fatalf("answer: applied=%v err=%v served=%v", r.Applied, r.Err, served(zd, "a."+zone, dns.TypeTXT))
	}
}

// Under coalescing wsPersistDelta accumulates: a fresh change staged on a busy
// zone and a replayed one staged after it are one publish, and that publish
// journals the fresh change. With the plain assignment the replay, staged
// last, would switch the journal off for both.
func TestAReplayedUpdateStagedLastKeepsTheJournalOn(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := journalTestZone(t, kdb)
	zd.mu.Lock()
	zd.publishCadence = 2 * time.Second
	zd.mu.Unlock()
	info, err := zd.JournalInfo(false)
	if err != nil {
		t.Fatalf("JournalInfo: %v", err)
	}
	before := info.Deltas

	fresh, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{Verb: VerbAddRR, RRs: []string{"three.example. 3600 IN A 10.0.0.3"}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: fresh}, kdb); err != nil {
		t.Fatalf("apply fresh: %v", err)
	}
	if served(zd, "three.example.", dns.TypeA) {
		t.Fatal("precondition: the fresh change was published at once on a busy zone")
	}
	replayed, err := BuildZoneUpdateActions("example.", ZoneUpdateSpec{Verb: VerbAddRR, RRs: []string{"four.example. 3600 IN A 10.0.0.4"}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := zd.ApplyZoneUpdateToZoneData(UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: "example.", Actions: replayed, InternalUpdate: true, Replay: true}, kdb); err != nil {
		t.Fatalf("apply replay: %v", err)
	}
	if !served(zd, "three.example.", dns.TypeA) || !served(zd, "four.example.", dns.TypeA) {
		t.Fatal("the replay's publish did not carry both changes")
	}
	info, err = zd.JournalInfo(false)
	if err != nil {
		t.Fatalf("JournalInfo: %v", err)
	}
	if info.Deltas != before+1 {
		t.Errorf("journal deltas %d, want %d: the fresh change was not journalled by the replay's publish", info.Deltas, before+1)
	}
}

// What the engine does after an update (the API-managed zone's file write,
// here) follows the publish that carries the change: a file never runs ahead
// of what is served.
func TestThePostPublishActionsFollowADeferredPublish(t *testing.T) {
	const zone = "file.gate.example."
	// The directory's removal is registered before the zone's cleanup, so it
	// runs after the publisher that writes into it has been stopped.
	dir, err := os.MkdirTemp("", "gate-file-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	zd, kdb := busyZone(t, zone, 700*time.Millisecond)
	file := filepath.Join(dir, "file.gate.example.zone")
	zd.mu.Lock()
	zd.Options[OptApiManagedZone] = true
	zd.Zonefile = file
	zd.mu.Unlock()
	startTxUpdater(t, kdb)

	sendTx(t, kdb, txtUpdate(t, zd, "a."+zone, "one"), false)
	waitFor(t, 2*time.Second, "the update to be staged", func() bool {
		zd.mu.Lock()
		defer zd.mu.Unlock()
		return zd.publishQueued
	})
	time.Sleep(100 * time.Millisecond)
	if b, err := os.ReadFile(file); err == nil && strings.Contains(string(b), `"one"`) {
		t.Fatal("the zone file was written with a change that was not published yet")
	}
	waitFor(t, 3*time.Second, "the gate's publish", func() bool { return served(zd, "a."+zone, dns.TypeTXT) })
	waitFor(t, 3*time.Second, "the zone file after the publish", func() bool {
		b, err := os.ReadFile(file)
		return err == nil && strings.Contains(string(b), `"one"`)
	})
	waitFor(t, 3*time.Second, "the post-publish action to have run", func() bool {
		zd.mu.Lock()
		defer zd.mu.Unlock()
		return len(zd.afterPublish) == 0 && len(zd.afterPublishReady) == 0
	})
}
