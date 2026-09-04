/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"testing"
	"time"
)

func samplePublication() SignalPublication {
	return SignalPublication{
		Target: "foobar.com.",
		Owner:  "_sig0key.example._signal.ns.foobar.com.",
		Zone:   "example.",
		NS:     "ns.foobar.com.",
		Prefix: signalPrefixSig0Key,
		Source: signalSourceHsyncparam,
	}
}

func TestSignalPublicationRoundTrip(t *testing.T) {
	kdb := newTestKeyDB(t)
	p := samplePublication()
	if err := kdb.RecordSignalPublication(p); err != nil {
		t.Fatalf("RecordSignalPublication: %v", err)
	}

	byZone, err := kdb.SignalPublicationsForZone("example.")
	if err != nil {
		t.Fatalf("SignalPublicationsForZone: %v", err)
	}
	if len(byZone) != 1 || byZone[0] != p {
		t.Fatalf("by zone = %+v, want exactly %+v", byZone, p)
	}

	byTarget, err := kdb.SignalPublicationsForTarget("foobar.com.")
	if err != nil {
		t.Fatalf("SignalPublicationsForTarget: %v", err)
	}
	if len(byTarget) != 1 || byTarget[0] != p {
		t.Fatalf("by target = %+v, want exactly %+v", byTarget, p)
	}

	if err := kdb.ForgetSignalPublication(p.Target, p.Owner); err != nil {
		t.Fatalf("ForgetSignalPublication: %v", err)
	}
	if rows, _ := kdb.SignalPublicationsForZone("example."); len(rows) != 0 {
		t.Fatalf("row survived the forget: %+v", rows)
	}
	// Forgetting what is not there is not an error: the withdrawal path calls
	// this after finding the record already gone.
	if err := kdb.ForgetSignalPublication(p.Target, p.Owner); err != nil {
		t.Fatalf("second ForgetSignalPublication: %v", err)
	}
}

// A signal name is published once per target, so re-recording it updates the
// row rather than accumulating one per refresh.
func TestSignalPublicationIsOnePerName(t *testing.T) {
	kdb := newTestKeyDB(t)
	p := samplePublication()
	for i := 0; i < 3; i++ {
		if err := kdb.RecordSignalPublication(p); err != nil {
			t.Fatalf("RecordSignalPublication %d: %v", i, err)
		}
	}
	rows, err := kdb.SignalPublicationsForZone("example.")
	if err != nil {
		t.Fatalf("SignalPublicationsForZone: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows after three records, want 1: %+v", len(rows), rows)
	}

	// The publisher re-records on every refresh that finds the name published,
	// so an UNCHANGED re-record must not write the row at all: published_at
	// means "when this server first put the record there", not "the last time
	// anything asked". Stamped with a sentinel rather than compared against
	// CURRENT_TIMESTAMP, whose one-second resolution would not tell a rewrite
	// apart from a no-op.
	sentinel := time.Date(1999, 12, 31, 12, 34, 56, 0, time.UTC)
	if _, err := kdb.DB.Exec(`UPDATE SignalPublication SET published_at = ?`, sentinel); err != nil {
		t.Fatalf("stamp published_at: %v", err)
	}
	if err := kdb.RecordSignalPublication(p); err != nil {
		t.Fatalf("unchanged re-record: %v", err)
	}
	var publishedAt time.Time
	if err := kdb.DB.QueryRow(
		`SELECT published_at FROM SignalPublication WHERE target = ? AND owner = ?`,
		p.Target, p.Owner).Scan(&publishedAt); err != nil {
		t.Fatalf("read published_at: %v", err)
	}
	if !publishedAt.Equal(sentinel) {
		t.Errorf("an unchanged re-record rewrote the row: published_at = %s, want %s",
			publishedAt, sentinel)
	}

	// The other publisher republishing the same name takes the row over rather
	// than adding a second one.
	p.Source = signalSourceAtNs
	if err := kdb.RecordSignalPublication(p); err != nil {
		t.Fatalf("RecordSignalPublication (other source): %v", err)
	}
	rows, _ = kdb.SignalPublicationsForZone("example.")
	if len(rows) != 1 || rows[0].Source != signalSourceAtNs {
		t.Fatalf("rows = %+v, want one row now sourced at-ns", rows)
	}
}

// The empty-ledger flag is what keeps the reconciler off the database for the
// deployments that have never published anything. It must never claim "empty"
// while a row exists -- that would be a silently skipped withdrawal.
func TestSignalLedgerEmptyFlag(t *testing.T) {
	kdb := newTestKeyDB(t)
	if !signalLedgerEmpty.Load() {
		t.Fatal("a freshly opened keystore has no publications; flag should be set")
	}
	p := samplePublication()
	if err := kdb.RecordSignalPublication(p); err != nil {
		t.Fatalf("RecordSignalPublication: %v", err)
	}
	if signalLedgerEmpty.Load() {
		t.Fatal("flag still claims empty after a publication was recorded")
	}
	if err := kdb.ForgetSignalPublication(p.Target, p.Owner); err != nil {
		t.Fatalf("ForgetSignalPublication: %v", err)
	}
	if !signalLedgerEmpty.Load() {
		t.Fatal("flag not restored after the last publication was forgotten")
	}
}
