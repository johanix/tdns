/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// Two delegations, one with DS and in-bailiwick glue, one with an
// out-of-bailiwick nameserver, and an NS RRset UNDER the first cut that the
// parent does not serve (occluded) and must not adopt.
const adoptParentZone = `parent.example.	3600	IN	SOA	ns.parent.example. hostmaster.parent.example. 1 7200 1800 604800 7200
parent.example.	3600	IN	NS	ns.parent.example.
ns.parent.example.	3600	IN	A	192.0.2.1
alpha.parent.example.	3600	IN	NS	ns.alpha.parent.example.
alpha.parent.example.	3600	IN	DS	12345 13 2 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
ns.alpha.parent.example.	3600	IN	A	192.0.2.51
ns.alpha.parent.example.	3600	IN	AAAA	2001:db8::51
bravo.parent.example.	3600	IN	NS	ns.bravo.example.
deep.alpha.parent.example.	3600	IN	NS	ns.deep.alpha.parent.example.
`

func adoptParent(t *testing.T, kdb *KeyDB) *ZoneData {
	t.Helper()
	zd := testZone(t, "parent.example.", adoptParentZone)
	registerZones(t, zd)
	zd.KeyDB = kdb
	zd.Logger = log.New(os.Stderr, "", 0)
	zd.Options = map[ZoneOption]bool{OptChildSync: true}
	zd.DelegationBackend = &DBDelegationBackend{kdb: kdb}
	return zd
}

func storedChildren(t *testing.T, b DelegationBackend) []string {
	t.Helper()
	kids, err := b.ListChildren("parent.example.")
	if err != nil {
		t.Fatalf("ListChildren: %v", err)
	}
	sort.Strings(kids)
	return kids
}

func TestAdoptSeedsTheStoreFromTheServedZone(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := adoptParent(t, kdb)

	children, rows, err := zd.AdoptServedDelegations()
	if err != nil {
		t.Fatalf("AdoptServedDelegations: %v", err)
	}
	if children != 2 || rows != 5 {
		t.Fatalf("adopted children=%d rows=%d; want 2 children and 5 rows (alpha NS, DS, glue A, glue AAAA; bravo NS)", children, rows)
	}

	b := zd.DelegationBackend.(*DBDelegationBackend)
	alpha, err := b.GetDelegationData("parent.example.", "alpha.parent.example.")
	if err != nil {
		t.Fatalf("GetDelegationData(alpha): %v", err)
	}
	at := alpha["alpha.parent.example."]
	if len(at[dns.TypeNS]) != 1 || len(at[dns.TypeDS]) != 1 {
		t.Errorf("alpha's delegation point should carry NS and DS, got %v", at)
	}
	glue := alpha["ns.alpha.parent.example."]
	if len(glue[dns.TypeA]) != 1 || len(glue[dns.TypeAAAA]) != 1 {
		t.Errorf("alpha's glue should carry A and AAAA, got %v", glue)
	}
	origins, err := b.delegationOrigins("parent.example.", "alpha.parent.example.")
	if err != nil {
		t.Fatalf("delegationOrigins: %v", err)
	}
	for rr, origin := range origins {
		if origin != "observed" {
			t.Errorf("adopted row %q has origin %q, want observed", rr, origin)
		}
	}

	if got := storedChildren(t, b); strings.Join(got, ",") != "alpha.parent.example.,bravo.parent.example." {
		t.Errorf("stored children = %v; the occluded deep.alpha NS must not be adopted as a delegation", got)
	}
}

// The store is the intended state. A child that asserted its delegation before
// the pass ran keeps exactly what it asserted; the served zone's (older) copy
// is not merged in beside it.
func TestAdoptLeavesAnAssertedChildAlone(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := adoptParent(t, kdb)

	asserted := childUpdate(t, "alpha.parent.example. 3600 IN NS ns2.alpha.parent.example.")
	asserted.ZoneName = "parent.example."
	if err := zd.DelegationBackend.ApplyChildUpdate("parent.example.", asserted); err != nil {
		t.Fatalf("ApplyChildUpdate: %v", err)
	}

	children, rows, err := zd.AdoptServedDelegations()
	if err != nil {
		t.Fatalf("AdoptServedDelegations: %v", err)
	}
	if children != 1 || rows != 1 {
		t.Fatalf("adopted children=%d rows=%d; want only bravo", children, rows)
	}

	b := zd.DelegationBackend.(*DBDelegationBackend)
	alpha, _ := b.GetDelegationData("parent.example.", "alpha.parent.example.")
	if len(alpha) != 1 || len(alpha["alpha.parent.example."][dns.TypeNS]) != 1 {
		t.Fatalf("alpha should hold exactly its asserted NS, got %v", alpha)
	}
	if ns := alpha["alpha.parent.example."][dns.TypeNS][0].(*dns.NS).Ns; ns != "ns2.alpha.parent.example." {
		t.Errorf("alpha's NS is %s, want the asserted ns2", ns)
	}
	origins, _ := b.delegationOrigins("parent.example.", "alpha.parent.example.")
	for rr, origin := range origins {
		if origin != "asserted" {
			t.Errorf("asserted row %q now reads origin %q", rr, origin)
		}
	}
}

func TestAdoptIsIdempotent(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := adoptParent(t, kdb)

	if _, _, err := zd.AdoptServedDelegations(); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	children, rows, err := zd.AdoptServedDelegations()
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if children != 0 || rows != 0 {
		t.Fatalf("second pass adopted children=%d rows=%d; want nothing", children, rows)
	}
}

// A child's assertion supersedes an observation of the same record: the row
// flips to asserted. The rows the child did not mention stay observed.
func TestAChildAssertionSupersedesAnObservation(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := adoptParent(t, kdb)
	if _, _, err := zd.AdoptServedDelegations(); err != nil {
		t.Fatalf("AdoptServedDelegations: %v", err)
	}

	same := childUpdate(t, "alpha.parent.example. 3600 IN NS ns.alpha.parent.example.")
	same.ZoneName = "parent.example."
	if err := zd.DelegationBackend.ApplyChildUpdate("parent.example.", same); err != nil {
		t.Fatalf("ApplyChildUpdate: %v", err)
	}

	b := zd.DelegationBackend.(*DBDelegationBackend)
	origins, _ := b.delegationOrigins("parent.example.", "alpha.parent.example.")
	var asserted, observed int
	for _, origin := range origins {
		switch origin {
		case "asserted":
			asserted++
		case "observed":
			observed++
		}
	}
	if asserted != 1 || observed != 3 {
		t.Fatalf("after re-asserting the NS: asserted=%d observed=%d, want 1 and 3: %v", asserted, observed, origins)
	}
}

func TestAdoptIsNotForTheDirectBackend(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := adoptParent(t, kdb)
	zd.DelegationBackend = &DirectDelegationBackend{zd: zd, kdb: kdb}

	children, rows, err := zd.AdoptServedDelegations()
	if err != nil || children != 0 || rows != 0 {
		t.Fatalf("direct backend: children=%d rows=%d err=%v; the served zone IS its store", children, rows, err)
	}
}

// A database created by an older tdns has no origin column. The migration adds
// it with the default every existing row deserves -- they were all asserted by
// children -- and both write paths work on the migrated table.
func TestOriginColumnIsMigratedOntoAnOlderTable(t *testing.T) {
	f := filepath.Join(t.TempDir(), "old.db")
	old, err := sql.Open("sqlite3", f)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := old.Exec(`CREATE TABLE 'ChildDelegationData' (
id INTEGER PRIMARY KEY, parent TEXT, child TEXT, owner TEXT, rrtype TEXT, rr TEXT, UNIQUE (owner,rr))`); err != nil {
		t.Fatalf("old schema: %v", err)
	}
	if _, err := old.Exec(`INSERT INTO ChildDelegationData (parent, child, owner, rrtype, rr) VALUES
('parent.example.', 'alpha.parent.example.', 'alpha.parent.example.', 'NS', 'alpha.parent.example.	0	IN	NS	ns.alpha.parent.example.')`); err != nil {
		t.Fatalf("old row: %v", err)
	}
	old.Close()

	kdb, err := NewKeyDB(f, false, nil)
	if err != nil {
		t.Fatalf("NewKeyDB on the old file: %v", err)
	}
	b := &DBDelegationBackend{kdb: kdb}

	origins, err := b.delegationOrigins("parent.example.", "alpha.parent.example.")
	if err != nil {
		t.Fatalf("delegationOrigins after migration: %v", err)
	}
	if len(origins) != 1 {
		t.Fatalf("the pre-migration row is gone: %v", origins)
	}
	for _, origin := range origins {
		if origin != "asserted" {
			t.Errorf("a row written before the column existed reads origin %q, want asserted", origin)
		}
	}

	ur := childUpdate(t, "alpha.parent.example. 3600 IN NS ns2.alpha.parent.example.")
	ur.ZoneName = "parent.example."
	if err := b.ApplyChildUpdate("parent.example.", ur); err != nil {
		t.Fatalf("ApplyChildUpdate on the migrated table: %v", err)
	}
	rr, _ := dns.NewRR("bravo.parent.example. 3600 IN NS ns.bravo.example.")
	if n, err := b.AdoptChildDelegation("parent.example.", "bravo.parent.example.", []dns.RR{rr}); err != nil || n != 1 {
		t.Fatalf("AdoptChildDelegation on the migrated table: n=%d err=%v", n, err)
	}
	origins, _ = b.delegationOrigins("parent.example.", "bravo.parent.example.")
	for _, origin := range origins {
		if origin != "observed" {
			t.Errorf("adopted row reads origin %q, want observed", origin)
		}
	}
}

// What is adopted was read from the served zone, so it is already in whatever
// generated that zone: writing a fragment for it would duplicate it.
func TestZonefileAdoptWritesNoFragment(t *testing.T) {
	kdb := newTestKeyDB(t)
	dir := t.TempDir()
	b := zonefileBackend(t, kdb, dir)

	rr, _ := dns.NewRR("alpha.parent.example. 3600 IN NS ns.alpha.parent.example.")
	if n, err := b.AdoptChildDelegation("parent.example.", "alpha.parent.example.", []dns.RR{rr}); err != nil || n != 1 {
		t.Fatalf("AdoptChildDelegation: n=%d err=%v", n, err)
	}
	if got := storedChildren(t, b); len(got) != 1 {
		t.Fatalf("store does not hold the adopted child: %v", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("adoption wrote a fragment: %v", entries)
	}
}

// The join: SetupZoneSync runs the pass for a childsync zone, before the DSYNC
// publication that follows it can fail.
func TestSetupZoneSyncSeedsTheDelegationStore(t *testing.T) {
	prevApp := Globals.App.Type
	t.Cleanup(func() { Globals.App.Type = prevApp })
	Globals.App.Type = AppTypeAuth

	kdb := newTestKeyDB(t)
	zd := adoptParent(t, kdb)

	// With no childsync configuration there is no DSYNC to publish, and
	// PublishDsyncRRs says so. That is downstream of what this test is about.
	if err := zd.SetupZoneSync(nil); err != nil && !strings.Contains(err.Error(), "DSYNC") {
		t.Fatalf("SetupZoneSync: %v", err)
	}
	if got := storedChildren(t, zd.DelegationBackend); len(got) != 2 {
		t.Fatalf("SetupZoneSync did not seed the store: %v", got)
	}
	if zd.HasError(DelegationSyncWarning) {
		t.Fatalf("a successful seed left a warning: %+v", zd.Errors)
	}
}

// A store that cannot be written is a warning on the zone, not a reason to
// skip the rest of the setup, and the warning names the cause.
func TestSetupZoneSyncWarnsWhenTheStoreCannotBeSeeded(t *testing.T) {
	prevApp := Globals.App.Type
	t.Cleanup(func() { Globals.App.Type = prevApp })
	Globals.App.Type = AppTypeAuth

	kdb := newTestKeyDB(t)
	zd := adoptParent(t, kdb)
	kdb.DB.Close()

	_ = zd.SetupZoneSync(nil)
	ze, ok := zd.Errors[DelegationSyncWarning]
	if !ok || !strings.HasPrefix(ze.Msg, delegationSeedWarningPrefix) {
		t.Fatalf("expected the seed warning on the zone, got %+v", zd.Errors)
	}
}

// Only the seed warning is cleared by a later success: the category is shared.
func TestClearDelegationSeedWarningLeavesOtherWarningsAlone(t *testing.T) {
	kdb := newTestKeyDB(t)
	zd := adoptParent(t, kdb)

	zd.SetError(DelegationSyncWarning, "%ssomething", delegationSeedWarningPrefix)
	zd.clearDelegationSeedWarning()
	if zd.HasError(DelegationSyncWarning) {
		t.Fatal("the seed warning was not cleared")
	}

	zd.SetError(DelegationSyncWarning, "the proxy's advertisement is waiting for publication")
	zd.clearDelegationSeedWarning()
	if !zd.HasError(DelegationSyncWarning) {
		t.Fatal("a warning from another source was cleared")
	}
}
