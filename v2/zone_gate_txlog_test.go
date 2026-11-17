/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"strings"
	"testing"
	"time"
)

// Step 4, observability: what is staged and not yet served (pendingChanges,
// tdns-cli debug zone-txlog) also shows the open transactions with their age,
// the hold with its cap, and when the gate's next publish is due.

// A held zone shows its hold and its transactions, staged change or not.
func TestTheTransactionLogShowsTheHold(t *testing.T) {
	const zone = "txlog.tx.example."
	zd, _ := newPublishedAutoZone(t, zone)
	if pc := zd.pendingChanges(); pc != nil {
		t.Fatalf("precondition: an idle zone with nothing staged has pending changes: %+v", pc)
	}
	id := mustBeginTx(t, zd, 0)
	pc := zd.pendingChanges()
	if pc == nil {
		t.Fatal("a held zone with nothing staged shows nothing")
	}
	if !pc.Held || pc.HoldSince.IsZero() || pc.HoldCap != txHoldAgeCap {
		t.Errorf("hold: held=%v since=%v cap=%v, want held since now with cap %v", pc.Held, pc.HoldSince, pc.HoldCap, txHoldAgeCap)
	}
	if len(pc.Transactions) != 1 || pc.Transactions[0].ID != id || pc.Transactions[0].Limit != txHoldLimit {
		t.Fatalf("transactions: %+v, want the one open, %s, with limit %v", pc.Transactions, id, txHoldLimit)
	}
	if age := time.Since(pc.Transactions[0].Started); age < 0 || age > 5*time.Second {
		t.Errorf("the transaction's start is %v ago", age)
	}
	text := FormatPendingChanges(pc)
	for _, want := range []string{"held", string(id)} {
		if !strings.Contains(text, want) {
			t.Errorf("the text does not say %q:\n%s", want, text)
		}
	}
	view := pendingChangesView(pc)
	if !view.Held || len(view.Transactions) != 1 || view.Transactions[0].ID != string(id) || view.Transactions[0].AgeSeconds < 0 {
		t.Errorf("the view: held=%v transactions=%+v", view.Held, view.Transactions)
	}
	stageTxt(t, zd, "a."+zone, "one")
	if _, err := zd.Publish(); err != nil {
		t.Fatal(err)
	}
	pc = zd.pendingChanges()
	if pc == nil || pc.HoldStopped != 1 {
		t.Errorf("after a publish the hold stopped: %+v, want 1 stopped publish", pc)
	}
	if err := zd.CommitTx(id); err != nil {
		t.Fatalf("CommitTx: %v", err)
	}
	// The commit's publish is the gate's, in the publisher's goroutine.
	waitFor(t, 3*time.Second, "nothing pending after the commit", func() bool { return zd.pendingChanges() == nil })
}

// A busy zone with a staged change shows when the gate's publish is due, and
// the waiters and follow-ups the publish will answer and run.
func TestTheTransactionLogShowsTheGatesDueTime(t *testing.T) {
	const zone = "txlogdue.gate.example."
	zd, kdb := busyZone(t, zone, 700*time.Millisecond)
	ur := txtUpdate(t, zd, "a."+zone, "one")
	ur.Resp = make(chan ZoneUpdateResult, 1)
	before := time.Now()
	if _, deferred, err := zd.applyZoneUpdate(ur, kdb, func() {}); err != nil || !deferred {
		t.Fatalf("applyZoneUpdate: deferred=%v err=%v", deferred, err)
	}
	pc := zd.pendingChanges()
	if pc == nil || !pc.PublishQueued {
		t.Fatalf("a staged change on a busy zone is not shown as queued: %+v", pc)
	}
	if pc.NextPublishAt.Before(before) || pc.NextPublishAt.After(before.Add(pc.Cadence+time.Second)) {
		t.Errorf("next publish at %v, want within one cadence (%v) of %v", pc.NextPublishAt, pc.Cadence, before)
	}
	if pc.Waiters != 1 || pc.FollowUps != 1 {
		t.Errorf("waiters=%d follow-ups=%d, want 1 and 1", pc.Waiters, pc.FollowUps)
	}
	if text := FormatPendingChanges(pc); !strings.Contains(text, "due") {
		t.Errorf("the text does not say when the publish is due:\n%s", text)
	}
	waitFor(t, 3*time.Second, "the gate's publish", func() bool { return zd.pendingChanges() == nil })
}
