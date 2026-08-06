/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// --- selection ---------------------------------------------------------

func TestKeySelectorSubtreeIsLabelBounded(t *testing.T) {
	// The whole reason --zones is not a string suffix: notpq.dnslab must not
	// be swept up by --zones pq.dnslab.
	sel := NewKeySelector(nil, []string{"pq.dnslab"})
	cases := map[string]bool{
		"pq.dnslab.":                 true,
		"mldsa87-ed25519.pq.dnslab.": true,
		"a.b.pq.dnslab.":             true,
		"notpq.dnslab.":              false,
		"dnslab.":                    false,
		"pq.dnslab.example.":         false,
	}
	for name, want := range cases {
		if got := sel.Matches(name); got != want {
			t.Errorf("Matches(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestKeySelectorExactAndCaseAndRoot(t *testing.T) {
	sel := NewKeySelector([]string{"DNSLAB"}, nil)
	if !sel.Matches("dnslab.") {
		t.Error("exact selection must be case- and trailing-dot-insensitive")
	}
	if sel.Matches("x.dnslab.") {
		t.Error("exact selection must not match subdomains")
	}

	// --zones . is the root's subtree, i.e. everything.
	root := NewKeySelector(nil, []string{"."})
	for _, n := range []string{".", "se.", "a.b.c."} {
		if !root.Matches(n) {
			t.Errorf("root subtree should match %q", n)
		}
	}
	// --zone . is the root alone.
	rootExact := NewKeySelector([]string{"."}, nil)
	if !rootExact.Matches(".") || rootExact.Matches("se.") {
		t.Error("exact root selection must match only the root")
	}
}

func TestKeySelectorEmptySelectsEverything(t *testing.T) {
	var sel KeySelector
	if !sel.Empty() || !sel.Matches("anything.") {
		t.Error("an empty selector must select everything (whole-keystore export)")
	}
}

// --- test fixtures -----------------------------------------------------

// testDnssecKey builds a real ED25519 DNSKEY so keytag/flags/owner validation
// has something genuine to check against.
func testDnssecKey(t *testing.T, zone string, flags uint16) BulkDnssecKey {
	t.Helper()
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ED25519,
	}
	priv, err := k.Generate(256)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	return BulkDnssecKey{
		Zone:       dns.Fqdn(zone),
		Keyid:      k.KeyTag(),
		Flags:      flags,
		Algorithm:  "ED25519",
		State:      DnskeyStateActive,
		Creator:    "test",
		PrivateKey: k.PrivateKeyString(priv),
		KeyRR:      k.String(),
	}
}

// --- import semantics --------------------------------------------------

func TestBulkImportDnssecInsertsThenReportsUnchanged(t *testing.T) {
	kdb := newTestKeyDB(t)
	key := testDnssecKey(t, "pq.dnslab.", 257)

	ds, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{key}, false)
	if err != nil {
		t.Fatalf("first import: %v", err)
	}
	if len(ds) != 1 || ds[0].Status != BulkStatusImported {
		t.Fatalf("first import: got %+v, want one %q", ds, BulkStatusImported)
	}

	// Re-importing the identical export is the normal repeated-pre-load case
	// and must be a no-op, not a conflict.
	ds, err = kdb.BulkImportDnssec(nil, []BulkDnssecKey{key}, false)
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if len(ds) != 1 || ds[0].Status != BulkStatusUnchanged {
		t.Fatalf("second import: got %+v, want one %q", ds, BulkStatusUnchanged)
	}
}

func TestBulkImportDnssecConflictIsSkippedUnlessForced(t *testing.T) {
	kdb := newTestKeyDB(t)
	key := testDnssecKey(t, "pq.dnslab.", 257)
	if _, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{key}, false); err != nil {
		t.Fatalf("seed import: %v", err)
	}

	// Same key, different state: the stale-export-un-rolls-a-rolled-key case.
	stale := key
	stale.State = DnskeyStateRetired

	ds, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{stale}, false)
	if err != nil {
		t.Fatalf("conflicting import: %v", err)
	}
	if len(ds) != 1 || ds[0].Status != BulkStatusConflict {
		t.Fatalf("conflicting import: got %+v, want one %q", ds, BulkStatusConflict)
	}
	if !strings.Contains(ds[0].Detail, "state") {
		t.Errorf("conflict detail should name the differing field, got %q", ds[0].Detail)
	}

	// The keystore must be untouched by the refused import.
	got, err := kdb.BulkExportDnssec(nil, KeySelector{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(got) != 1 || got[0].State != DnskeyStateActive {
		t.Fatalf("a skipped conflict must not modify the keystore, got %+v", got)
	}

	// force is the recovery path: it overwrites.
	ds, err = kdb.BulkImportDnssec(nil, []BulkDnssecKey{stale}, true)
	if err != nil {
		t.Fatalf("forced import: %v", err)
	}
	if len(ds) != 1 || ds[0].Status != BulkStatusReplaced {
		t.Fatalf("forced import: got %+v, want one %q", ds, BulkStatusReplaced)
	}
	got, err = kdb.BulkExportDnssec(nil, KeySelector{})
	if err != nil {
		t.Fatalf("export after force: %v", err)
	}
	if len(got) != 1 || got[0].State != DnskeyStateRetired {
		t.Fatalf("force must overwrite, got %+v", got)
	}
}

func TestBulkImportDnssecRejectsInconsistentMetadata(t *testing.T) {
	kdb := newTestKeyDB(t)

	bad := testDnssecKey(t, "pq.dnslab.", 257)
	bad.Keyid = bad.Keyid + 1 // manifest disagrees with its own key file
	if _, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{bad}, false); err == nil {
		t.Error("a keyid that does not match the DNSKEY must be refused")
	}

	wrongOwner := testDnssecKey(t, "pq.dnslab.", 257)
	wrongOwner.Zone = "other.dnslab."
	if _, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{wrongOwner}, false); err == nil {
		t.Error("a DNSKEY owner that does not match the zone must be refused")
	}

	noPriv := testDnssecKey(t, "pq.dnslab.", 257)
	noPriv.PrivateKey = ""
	if _, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{noPriv}, false); err == nil {
		t.Error("a key with no private material must be refused")
	}
}

func TestBulkImportIsAllOrNothing(t *testing.T) {
	kdb := newTestKeyDB(t)
	good := testDnssecKey(t, "good.dnslab.", 257)
	bad := testDnssecKey(t, "bad.dnslab.", 257)
	bad.Flags = 256 // contradicts the DNSKEY's own flags

	if _, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{good, bad}, false); err == nil {
		t.Fatal("import with an invalid key must fail")
	}
	// The valid key that preceded the bad one must have been rolled back: a
	// partially-restored keystore is the state nobody can reason about.
	got, err := kdb.BulkExportDnssec(nil, KeySelector{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("failed import must leave no rows behind, got %+v", got)
	}
}

func TestBulkExportSelectsSubtree(t *testing.T) {
	kdb := newTestKeyDB(t)
	keys := []BulkDnssecKey{
		testDnssecKey(t, "pq.dnslab.", 257),
		testDnssecKey(t, "mldsa87-ed25519.pq.dnslab.", 257),
		testDnssecKey(t, "notpq.dnslab.", 257),
	}
	if _, err := kdb.BulkImportDnssec(nil, keys, false); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := kdb.BulkExportDnssec(nil, NewKeySelector(nil, []string{"pq.dnslab"}))
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("subtree export should return 2 keys, got %d: %+v", len(got), got)
	}
	for _, k := range got {
		if k.PrivateKey == "" || strings.Contains(k.PrivateKey, "***") {
			t.Errorf("export must carry unredacted key material, got %q for %s", k.PrivateKey, k.Zone)
		}
	}
}

// --- TSIG --------------------------------------------------------------

func TestBulkImportTsigRoundTrip(t *testing.T) {
	kdb := newTestKeyDB(t)
	key := BulkTsigKey{
		Keyname:   "xfr.dnslab.",
		Algorithm: "hmac-sha256",
		Secret:    "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0Cg==",
		Origin:    "config",
	}
	ds, err := kdb.BulkImportTsig(nil, []BulkTsigKey{key}, false)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(ds) != 1 || ds[0].Status != BulkStatusImported {
		t.Fatalf("got %+v, want one %q", ds, BulkStatusImported)
	}

	got, err := kdb.BulkExportTsig(nil, KeySelector{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(got) != 1 || got[0].Secret != key.Secret || got[0].Origin != "config" {
		t.Fatalf("round trip lost data: %+v", got)
	}

	// A different secret under the same name is a conflict, not a silent swap.
	rotated := key
	rotated.Secret = "ZGlmZmVyZW50LXNlY3JldC1oZXJlLXBsZWFzZQo="
	ds, err = kdb.BulkImportTsig(nil, []BulkTsigKey{rotated}, false)
	if err != nil {
		t.Fatalf("conflicting import: %v", err)
	}
	if len(ds) != 1 || ds[0].Status != BulkStatusConflict {
		t.Fatalf("got %+v, want one %q", ds, BulkStatusConflict)
	}
}

// --- manifest ----------------------------------------------------------

func TestManifestMergePreservesEarlierExports(t *testing.T) {
	dir := t.TempDir()

	first := &KeystoreManifest{Version: KeystoreManifestVersion}
	first.UpsertDnssec(ManifestDnssecKey{Zone: "pq.dnslab.", Keyid: 111, Algorithm: "ED25519",
		State: "active", PrivateFile: "a.private", PublicFile: "a.key"})
	if err := first.Save(dir); err != nil {
		t.Fatalf("save: %v", err)
	}

	// A second export into the same directory, covering a different zone, must
	// not erase the first — that is what makes several narrow exports usable.
	second, err := LoadOrNewKeystoreManifest(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	second.UpsertDnssec(ManifestDnssecKey{Zone: "dnslab.", Keyid: 222, Algorithm: "ED25519",
		State: "active", PrivateFile: "b.private", PublicFile: "b.key"})
	if err := second.Save(dir); err != nil {
		t.Fatalf("save: %v", err)
	}

	final, err := LoadKeystoreManifest(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(final.Dnssec) != 2 {
		t.Fatalf("merge lost entries: %+v", final.Dnssec)
	}
	// Sorted on save, so re-exporting an unchanged keystore is a no-op diff.
	if final.Dnssec[0].Zone != "dnslab." || final.Dnssec[1].Zone != "pq.dnslab." {
		t.Errorf("entries should be sorted by zone, got %+v", final.Dnssec)
	}

	// Re-upserting the same identity replaces rather than duplicates.
	final.UpsertDnssec(ManifestDnssecKey{Zone: "dnslab.", Keyid: 222, Algorithm: "ED25519",
		State: "retired", PrivateFile: "b.private", PublicFile: "b.key"})
	if len(final.Dnssec) != 2 {
		t.Fatalf("upsert should replace, not append: %+v", final.Dnssec)
	}
}

func TestManifestRefusesNewerVersion(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, KeystoreManifestFile),
		[]byte("version: 99\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadKeystoreManifest(dir); err == nil {
		t.Error("a manifest from a newer format version must be refused, not half-read")
	}
}

func TestManifestFilePathsAreContained(t *testing.T) {
	dir := t.TempDir()
	m := &KeystoreManifest{Version: KeystoreManifestVersion}
	m.UpsertDnssec(ManifestDnssecKey{Zone: "x.", Keyid: 1, PrivateFile: "../../etc/shadow",
		PublicFile: "x.key"})
	if _, err := m.LoadDnssecKeys(dir); err == nil {
		t.Error("a manifest must not be able to read outside its own directory")
	}
}

func TestManifestSavedModeIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	m := &KeystoreManifest{Version: KeystoreManifestVersion}
	m.UpsertTsig(ManifestTsigKey{Keyname: "k.", Algorithm: "hmac-sha256", Secret: "shhh"})
	if err := m.Save(dir); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, KeystoreManifestFile))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("manifest holds TSIG secrets; mode is %04o, want owner-only", mode)
	}
}
