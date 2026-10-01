/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Step 3, part 2: a refresh publishes what is staged first and is refused
// under a hold (tdns #749); a hold cannot outlive its age cap; every sender
// waits the one bound.

// A transfer that arrives while a transaction holds the zone is refused
// before it touches the working set: the transaction's staged change is kept,
// the commit publishes it, and the transfer lands on the retry. The transfer
// is never journalled; the local change is (#749, both halves).
func TestARefreshUnderAHoldIsRefusedAndTheCommitKeepsTheLocalChange(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	id, err := zd.BeginTx(TxUrgent)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	local := ovCDS(t, 5) // an overlay record: kept across a full transfer
	if err := ovUpdate(t, zd, local); err != nil {
		t.Fatalf("a local change under the hold was refused: %v", err)
	}

	_, addr, stop := ixfrTestPrimary(t, ovUpstreamZone(20, srFresh))
	defer stop()
	zd.mu.Lock()
	zd.Upstreams = []PeerConf{{Addr: addr}}
	zd.mu.Unlock()
	status := zd.GetStatus()
	_, err = zd.FetchFromUpstream(context.Background(), false, false, true, zd.CollectDynamicRRs(&Config{}), &Config{})
	if !errors.Is(err, ErrRefreshHeld) {
		t.Fatalf("a refresh under a hold: err=%v, want ErrRefreshHeld", err)
	}
	if got := zd.GetStatus(); got != status {
		t.Errorf("the refused refresh left the status at %v, was %v", got, status)
	}
	if zd.HasError(RefreshError) {
		t.Error("a refresh refused by a hold set RefreshError")
	}
	zd.mu.Lock()
	staged := zd.workingSet != nil && !zd.wsFromReplacement
	zd.mu.Unlock()
	if !staged {
		t.Fatal("the refused refresh took the transaction's staged change")
	}

	if err := zd.CommitTx(id); err != nil {
		t.Fatalf("CommitTx: %v", err)
	}
	if !ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), local) {
		t.Error("the commit did not publish the transaction's change")
	}
	if ovHas(ovServed(t, zd, "fresh.example.", dns.TypeA), mustRR(t, srFresh)) {
		t.Error("the refused transfer's content is served")
	}
	if deltas := ovJournal(t, zd); len(deltas) != 1 {
		t.Errorf("journal after the commit has %d delta(s), want 1 (the local change):%s", len(deltas), ovJournalString(deltas))
	}

	// The retry, after the hold: the transfer lands, with the local change
	// kept by the overlay, and nothing more is journalled.
	ovTransferFrom(t, zd, addr, true)
	if !ovHas(ovServed(t, zd, "fresh.example.", dns.TypeA), mustRR(t, srFresh)) {
		t.Error("the retried transfer did not land")
	}
	if !ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), local) {
		t.Error("the retried transfer dropped the local change")
	}
	if deltas := ovJournal(t, zd); len(deltas) != 1 {
		t.Errorf("journal after the retry has %d delta(s), want 1:%s", len(deltas), ovJournalString(deltas))
	}
}

// With no hold, a refresh publishes what is staged first: the change is
// served and journalled and its waiter answered before the replacement takes
// the working set.
func TestARefreshPublishesWhatIsStagedFirst(t *testing.T) {
	zd := ixSigningSecondary(t, ixApplyZone)
	zd.mu.Lock()
	zd.publishCadence = 5 * time.Second
	zd.lastPublish = time.Now() // busy: the next change waits for the gate
	zd.mu.Unlock()

	local := ovCDS(t, 5) // an overlay record: kept across a full transfer
	ur := UpdateRequest{Cmd: "ZONE-UPDATE", ZoneName: zd.ZoneName, Actions: []dns.RR{local},
		InternalUpdate: true, Resp: make(chan ZoneUpdateResult, 1)}
	if _, err := zd.ApplyZoneUpdateToZoneData(ur, zd.KeyDB); err != nil {
		t.Fatalf("update: %v", err)
	}
	if ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), local) {
		t.Fatal("precondition: the change was published at once on a busy zone")
	}
	if _, early := answeredWithin(ur.Resp, 50*time.Millisecond); early {
		t.Fatal("precondition: the update was answered before its publish")
	}

	ovTransfer(t, zd, ovUpstreamZone(20, srFresh), true)

	r, ok := answeredWithin(ur.Resp, time.Second)
	if !ok || r.Err != nil || !r.Applied {
		t.Fatalf("the staged change's waiter after the refresh: answered=%v applied=%v err=%v", ok, r.Applied, r.Err)
	}
	if !ovHas(ovServed(t, zd, ovZone, dns.TypeCDS), local) {
		t.Error("the local change is not served after the refresh")
	}
	if !ovHas(ovServed(t, zd, "fresh.example.", dns.TypeA), mustRR(t, srFresh)) {
		t.Error("the transfer did not land")
	}
	if deltas := ovJournal(t, zd); len(deltas) != 1 {
		t.Errorf("journal has %d delta(s), want 1 (the local change, not the transfer):%s", len(deltas), ovJournalString(deltas))
	}
}

// A refresh refused by a hold is tried again soon, not after the SOA retry.
func TestARefusedRefreshIsRetriedSoon(t *testing.T) {
	rc := &RefreshCounter{Name: "x.", SOARefresh: 3600, SOARetry: 900}
	if got := nextRefreshAfterFailure(rc, errors.New("some other failure")); got != 900 {
		t.Errorf("after an ordinary failure the next attempt is in %d s, want the SOA retry 900", got)
	}
	if got := nextRefreshAfterFailure(rc, ErrRefreshHeld); got != refreshHeldRetrySeconds {
		t.Errorf("after a hold the next attempt is in %d s, want %d", got, refreshHeldRetrySeconds)
	}
}

// The hold's limit is per transaction. A writer that opens its next
// transaction before the last is released could hold a published zone for
// good; the hold's age, from its first begin, is capped. Every transaction
// here lives 50 ms of a 2 s limit, so only the cap can release the hold.
func TestAHoldCannotOutliveItsAgeCap(t *testing.T) {
	logs := captureTxLogs(t)
	withTxHoldLimit(t, 2*time.Second)
	prev := txHoldAgeCap
	txHoldAgeCap = 300 * time.Millisecond
	t.Cleanup(func() { txHoldAgeCap = prev })

	const zone = "agecap.tx.example."
	zd, _ := newPublishedAutoZone(t, zone)
	stageTxt(t, zd, "a."+zone, "one")
	start := time.Now()
	open := mustBeginTx(t, zd, 0)
	// Keep one transaction open at every moment, for a second at most.
	deadline := start.Add(time.Second)
	for time.Now().Before(deadline) && zd.txOpenCount() > 0 {
		next := mustBeginTx(t, zd, 0)
		if err := zd.CommitTx(open); err != nil {
			// The cap released open between the count and the begin, and
			// next opened a new hold: close it, the loop is done.
			_ = zd.CommitTx(next)
			break
		}
		open = next
		time.Sleep(50 * time.Millisecond)
	}
	if n := zd.txOpenCount(); n != 0 {
		t.Fatalf("%d transaction(s) still open after %v of 50 ms transactions: the cap (%v) did not release the hold",
			n, time.Since(start), txHoldAgeCap)
	}
	if logLineWith(logs.String(), "WARN", "past the hold's limit") {
		t.Error("a transaction reached its own limit; the cap was not what released the hold")
	}
	if !logLineWith(logs.String(), "WARN", "age cap") {
		t.Errorf("no WARN about the hold's age cap:\n%s", logs.String())
	}
	waitFor(t, 2*time.Second, "the staged change to publish through the gate", func() bool { return served(zd, "a."+zone, dns.TypeTXT) })
	if err := zd.CommitTx(open); err == nil {
		t.Error("committing a transaction the cap released succeeded")
	}
}

// On a zone that has never published the cap, like the limit, fails closed.
// The creation's transaction is inside its 2 s limit throughout; the error
// comes from the cap, within the second.
func TestAHoldPastItsAgeCapOnANeverPublishedZoneFailsClosed(t *testing.T) {
	logs := captureTxLogs(t)
	withTxHoldLimit(t, 2*time.Second)
	prev := txHoldAgeCap
	txHoldAgeCap = 200 * time.Millisecond
	t.Cleanup(func() { txHoldAgeCap = prev })

	const zone = "agecapfirst.tx.example."
	zd, id, _ := newHeldAutoZone(t, zone)
	stageTxt(t, zd, "a."+zone, "one")
	waitFor(t, time.Second, "the cap to fail the zone closed", func() bool { return zd.HasError(FirstPublishError) })
	if !logLineWith(logs.String(), "ERROR", "age cap") {
		t.Errorf("no ERROR about the hold's age cap:\n%s", logs.String())
	}
	if zd.publishedSnapshot() != nil {
		t.Fatal("the cap published a zone that had never published")
	}
	if n := zd.txOpenCount(); n != 1 {
		t.Errorf("%d open transaction(s), want the creation's still open", n)
	}
	// The commit still works, and installs the first snapshot.
	if err := zd.CommitTx(id); err != nil {
		t.Fatalf("CommitTx: %v", err)
	}
	if !served(zd, "a."+zone, dns.TypeTXT) {
		t.Error("the commit did not publish")
	}
}

// Every sender that waits for its change waits the larger of
// UpdateApplyTimeout and twice the zone's cadence: a wait equal to the cadence
// loses the race.
func TestEverySenderWaitsTheOneBound(t *testing.T) {
	if got := updateWaitBound("no.such.zone."); got != UpdateApplyTimeout {
		t.Errorf("unknown zone: %v, want %v", got, UpdateApplyTimeout)
	}
	const zone = "bound.gate.example."
	zd, _ := newPublishedAutoZone(t, zone)
	zd.mu.Lock()
	zd.publishCadence = time.Second
	zd.mu.Unlock()
	if got := updateWaitBound(zone); got != UpdateApplyTimeout {
		t.Errorf("cadence 1 s: %v, want %v", got, UpdateApplyTimeout)
	}
	zd.mu.Lock()
	zd.publishCadence = 8 * time.Second
	zd.mu.Unlock()
	if got := updateWaitBound(zone); got != 16*time.Second {
		t.Errorf("cadence 8 s: %v, want 16 s", got)
	}
}
