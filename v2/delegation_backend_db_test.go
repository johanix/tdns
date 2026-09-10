/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// zonefileBackend composes what the zonefile type name stands for: the sqlite
// store with the zonefile writer over dir.
func zonefileBackend(t *testing.T, kdb *KeyDB, dir string) *composedDelegationBackend {
	t.Helper()
	store := &DBDelegationBackend{kdb: kdb}
	return &composedDelegationBackend{
		name:   "frag",
		store:  store,
		writer: &zonefileWriter{directory: dir, store: store},
	}
}

// childDelete builds a CHILD-UPDATE that removes one RR (class NONE).
func childDelete(t *testing.T, rrstr string) UpdateRequest {
	t.Helper()
	rr, err := dns.NewRR(rrstr)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", rrstr, err)
	}
	rr.Header().Class = dns.ClassNONE
	rr.Header().Ttl = 0
	return UpdateRequest{Cmd: "CHILD-UPDATE", ZoneName: "example.", Actions: []dns.RR{rr}}
}

// A child with no rows is an empty delegation, and an unreadable store is an
// error. The two used to share one return value, and the zonefile backend
// acted on it by deleting the child's fragment.
func TestDBBackendNoRowsIsEmptyNotError(t *testing.T) {
	kdb := newTestKeyDB(t)
	b := &DBDelegationBackend{kdb: kdb}

	data, err := b.GetDelegationData("example.", "child.example.")
	if err != nil {
		t.Fatalf("a child with no rows must not be an error: %v", err)
	}
	if data == nil || len(data) != 0 {
		t.Fatalf("want an empty map for a child with no rows, got %v", data)
	}

	kdb.DB.Close()
	if _, err := b.GetDelegationData("example.", "child.example."); err == nil {
		t.Fatal("a closed database must surface as an error, not as an empty child")
	}
}

func TestDirectBackendNoDataIsEmptyNotError(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := directBackendZone(t, kdb)
	b := &DirectDelegationBackend{zd: zd, kdb: kdb}

	data, err := b.GetDelegationData("example.", "nosuch.example.")
	if err != nil {
		t.Fatalf("a child the zone does not delegate must not be an error: %v", err)
	}
	if data == nil || len(data) != 0 {
		t.Fatalf("want an empty map, got %v", data)
	}
}

// The fragment exists exactly while the store holds data for the child.
func TestZonefileBackendFragmentFollowsTheStore(t *testing.T) {
	kdb := newTestKeyDB(t)
	dir := t.TempDir()
	b := zonefileBackend(t, kdb, dir)
	const ns = "child.example. 3600 IN NS ns.child.example."

	if err := b.ApplyChildUpdate("example.", childUpdate(t, ns)); err != nil {
		t.Fatalf("ApplyChildUpdate(add): %v", err)
	}
	frag := filepath.Join(dir, "child.example.zone")
	body, err := os.ReadFile(frag)
	if err != nil {
		t.Fatalf("fragment not written after an add: %v", err)
	}
	if !strings.Contains(string(body), "ns.child.example.") {
		t.Fatalf("fragment does not carry the delegation:\n%s", body)
	}

	if err := b.ApplyChildUpdate("example.", childDelete(t, ns)); err != nil {
		t.Fatalf("ApplyChildUpdate(delete): %v", err)
	}
	if _, err := os.Stat(frag); !os.IsNotExist(err) {
		t.Fatalf("fragment must be removed once the child has no data left; stat: %v", err)
	}
}

// A store that cannot be read is not a child with no data. Before this the
// backend deleted the fragment on ANY error from the read, so a transient
// database failure removed a delegation from the generated parent zone.
func TestZonefileBackendKeepsFragmentWhenStoreUnreadable(t *testing.T) {
	kdb := newTestKeyDB(t)
	dir := t.TempDir()
	b := zonefileBackend(t, kdb, dir)

	if err := b.ApplyChildUpdate("example.", childUpdate(t, "child.example. 3600 IN NS ns.child.example.")); err != nil {
		t.Fatalf("ApplyChildUpdate: %v", err)
	}
	frag := filepath.Join(dir, "child.example.zone")
	if _, err := os.Stat(frag); err != nil {
		t.Fatalf("fragment not written: %v", err)
	}

	kdb.DB.Close()
	if err := b.writer.(*zonefileWriter).refreshFragments("example.", map[string]bool{"child.example.": true}); err == nil {
		t.Fatal("an unreadable store must be reported as an error, not read as an empty child")
	}
	if _, err := os.Stat(frag); err != nil {
		t.Fatalf("the fragment was removed on a store READ failure: %v", err)
	}
}

// A commit that fails is the caller's error. The old defer logged it and the
// function returned nil: a child heard NOERROR for a change the store did
// not keep, which is the one thing acceptance-means-recorded forbids.
func TestFinishTxReturnsTheCommitError(t *testing.T) {
	kdb := newTestKeyDB(t)

	tx, err := kdb.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	// A transaction that is already gone cannot be committed: the same
	// shape as any commit failure, without needing a full disk.
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := finishTx(tx, nil); err == nil || !strings.Contains(err.Error(), "committing") {
		t.Fatalf("a failed commit must come back as an error, got %v", err)
	}

	tx2, err := kdb.Begin("test")
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("the update was bad")
	if err := finishTx(tx2, cause); err != cause {
		t.Fatalf("with a cause, finishTx must roll back and return the cause, got %v", err)
	}
}

// A stored row that does not parse makes the child unreadable, in words. It
// must not read as a smaller delegation: the push engine would diff that
// against the served zone and delete at the primary what it could not parse.
func TestDBBackendUnreadableRowIsAnError(t *testing.T) {
	kdb := newTestKeyDB(t)
	b := &DBDelegationBackend{kdb: kdb}
	if _, err := kdb.DB.Exec(`INSERT INTO ChildDelegationData (parent, child, owner, rrtype, rr, origin) VALUES (?, ?, ?, ?, ?, ?)`,
		"example.", "child.example.", "child.example.", "NS", "this is not a record", "asserted"); err != nil {
		t.Fatal(err)
	}
	_, err := b.GetDelegationData("example.", "child.example.")
	if err == nil || !strings.Contains(err.Error(), "does not parse") {
		t.Fatalf("an unparsable row must be a read error naming it, got %v", err)
	}
}
