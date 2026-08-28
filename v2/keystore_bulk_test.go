/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// --- selection ---------------------------------------------------------

// mustSelector builds a selector for tests that supply known-good input.
func mustSelector(t *testing.T, exact, subtree []string) KeySelector {
	t.Helper()
	sel, err := NewKeySelector(exact, subtree)
	if err != nil {
		t.Fatalf("NewKeySelector(%v, %v): %v", exact, subtree, err)
	}
	return sel
}

func TestKeySelectorSubtreeIsLabelBounded(t *testing.T) {
	// The whole reason --zones is not a string suffix: notpq.dnslab must not
	// be swept up by --zones pq.dnslab.
	sel := mustSelector(t, nil, []string{"pq.dnslab"})
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
	sel := mustSelector(t, []string{"DNSLAB"}, nil)
	if !sel.Matches("dnslab.") {
		t.Error("exact selection must be case- and trailing-dot-insensitive")
	}
	if sel.Matches("x.dnslab.") {
		t.Error("exact selection must not match subdomains")
	}

	// --zones . is the root's subtree, i.e. everything.
	root := mustSelector(t, nil, []string{"."})
	for _, n := range []string{".", "se.", "a.b.c."} {
		if !root.Matches(n) {
			t.Errorf("root subtree should match %q", n)
		}
	}
	// --zone . is the root alone.
	rootExact := mustSelector(t, []string{"."}, nil)
	if !rootExact.Matches(".") || rootExact.Matches("se.") {
		t.Error("exact root selection must match only the root")
	}
}

func TestKeySelectorRefusesBlankValues(t *testing.T) {
	// `--zones "$SUBTREE"` with an unset variable. Dropping the blank would
	// leave the selector empty, and empty means everything -- so a typo or an
	// unset shell variable would export every private key in the keystore.
	for _, tc := range []struct{ exact, subtree []string }{
		{exact: []string{""}},
		{exact: []string{"  "}},
		{subtree: []string{""}},
		{exact: []string{"ok.example."}, subtree: []string{""}},
	} {
		if _, err := NewKeySelector(tc.exact, tc.subtree); err == nil {
			t.Errorf("NewKeySelector(%q, %q) should refuse a blank value", tc.exact, tc.subtree)
		}
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
//
// The private half is PKCS#8 PEM, not the BIND format dns.PrivateKeyString
// returns: PEM is what the keystore column actually holds, so a fixture using
// anything else would be testing a shape production never produces.
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
	privPEM, err := PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("converting test key to PEM: %v", err)
	}
	return BulkDnssecKey{
		Zone:       dns.Fqdn(zone),
		Keyid:      k.KeyTag(),
		Flags:      flags,
		Algorithm:  "ED25519",
		State:      DnskeyStateActive,
		Creator:    "test",
		PrivateKey: privPEM,
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

func TestBulkImportRefusesNonPEMPrivateKey(t *testing.T) {
	kdb := newTestKeyDB(t)

	// The realistic mistake: dropping a dnssec-keygen .private file into an
	// export directory. The single-key import converts BIND format; bulk import
	// stores verbatim, so it has to refuse rather than write a blob into a
	// column that is supposed to hold PEM.
	bindFormat := testDnssecKey(t, "pq.dnslab.", 257)
	bindFormat.PrivateKey = "Private-key-format: v1.3\nAlgorithm: 15 (ED25519)\n" +
		"PrivateKey: LrIfCpsKYav5oA8R9AoMipYE990WHLd6tceF2w+p4pM=\n"
	_, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{bindFormat}, false)
	if err == nil {
		t.Fatal("a BIND-format private key must be refused by bulk import")
	}
	if !strings.Contains(err.Error(), "PEM") {
		t.Errorf("the error should say what format was expected, got %q", err)
	}

	// Same rule on the SIG(0) side.
	sig0 := BulkSig0Key{
		Zone: "pq.dnslab.", Keyid: 1, Algorithm: "ED25519", State: Sig0StateActive,
		PrivateKey: "not pem at all", KeyRR: "pq.dnslab. 3600 IN KEY 512 3 15 aIufB25wu/A9nLOZOm7ZlAxkdQyeCqAQcH7wMCg8DVo=",
	}
	if _, err := kdb.BulkImportSig0(nil, []BulkSig0Key{sig0}, false); err == nil {
		t.Error("a non-PEM SIG(0) private key must be refused by bulk import")
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

	got, err := kdb.BulkExportDnssec(nil, mustSelector(t, nil, []string{"pq.dnslab"}))
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
	// An empty policy (no StillInConfig predicate) throughout: this case is
	// about the raw round trip, including that an explicitly-offered origin is
	// stored as offered. Config ownership is covered separately below.
	ds, err := kdb.BulkImportTsig(nil, []BulkTsigKey{key}, false, TsigBulkPolicy{})
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
	ds, err = kdb.BulkImportTsig(nil, []BulkTsigKey{rotated}, false, TsigBulkPolicy{})
	if err != nil {
		t.Fatalf("conflicting import: %v", err)
	}
	if len(ds) != 1 || ds[0].Status != BulkStatusConflict {
		t.Fatalf("got %+v, want one %q", ds, BulkStatusConflict)
	}

	// ...and with force it IS replaced. Until this case existed bulkUpdateTsigSql
	// had no coverage at all: every assertion above lands in the insert branch or
	// the conflict branch, so the UPDATE could have been syntactically broken and
	// the suite would still have been green.
	ds, err = kdb.BulkImportTsig(nil, []BulkTsigKey{rotated}, true, TsigBulkPolicy{})
	if err != nil {
		t.Fatalf("forced import: %v", err)
	}
	if len(ds) != 1 || ds[0].Status != BulkStatusReplaced {
		t.Fatalf("got %+v, want one %q", ds, BulkStatusReplaced)
	}
	got, err = kdb.BulkExportTsig(nil, KeySelector{})
	if err != nil {
		t.Fatalf("export after forced replace: %v", err)
	}
	if len(got) != 1 || got[0].Secret != rotated.Secret {
		t.Fatalf("forced replacement did not reach the row: %+v", got)
	}
}

// TestBulkImportTsigDefaultsOriginToApi pins the default origin for an import
// that does not state one. It used to be "import", which is neither value
// TsigKeyMgmt accepts: setowner and delete both refuse any origin but api (and
// config), so such a key was imported, looked fine, and could not afterwards be
// operated on at all.
func TestBulkImportTsigDefaultsOriginToApi(t *testing.T) {
	kdb := newTestKeyDB(t)
	ds, err := kdb.BulkImportTsig(nil, []BulkTsigKey{{
		Keyname:   "noorigin.dnslab.",
		Algorithm: "hmac-sha256",
		Secret:    "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0Cg==",
		// Origin deliberately omitted -- that is the whole point.
	}}, false, TsigBulkPolicy{})
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
	if len(got) != 1 || got[0].Origin != "api" {
		t.Fatalf("an import that states no origin must be stored as api-origin, got %+v", got)
	}
}

// TestBulkImportTsigYamlIsTruth covers the config-ownership rule. The test is
// NOT "is the row marked origin=config" but "is the key still in keys.tsig":
// SyncConfigTsigKeys deletes every config row the YAML no longer names, so a
// leftover config row is already condemned and protecting it protects nothing.
func TestBulkImportTsigYamlIsTruth(t *testing.T) {
	const (
		secretA = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0Cg=="
		secretB = "ZGlmZmVyZW50LXNlY3JldC1oZXJlLXBsZWFzZQo="
	)
	// Stands in for the live TSIG store on a running daemon.
	inConfig := func(names ...string) TsigBulkPolicy {
		set := map[string]bool{}
		for _, n := range names {
			set[core.CanonicalizeName(dns.Fqdn(n))] = true
		}
		// The same key function the production writer uses. A helper that keys
		// its fake set one way against a store keyed another is the store/lookup
		// split under test, reproduced in the test.
		return TsigBulkPolicy{StillInConfig: func(name string) bool {
			return set[core.CanonicalizeName(dns.Fqdn(name))]
		}}
	}

	// Declared in the YAML: the config owns it, so an import may not replace it
	// even with force -- force overrides "this differs", not "not yours".
	t.Run("declared in config: refused", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		seed := BulkTsigKey{Keyname: "cfg.dnslab.", Algorithm: "hmac-sha256",
			Secret: secretA, Origin: "config"}
		if _, err := kdb.BulkImportTsig(nil, []BulkTsigKey{seed}, false, TsigBulkPolicy{}); err != nil {
			t.Fatalf("seeding the config row: %v", err)
		}

		rotated := seed
		rotated.Secret = secretB
		ds, err := kdb.BulkImportTsig(nil, []BulkTsigKey{rotated}, true, inConfig("cfg.dnslab."))
		if err != nil {
			t.Fatalf("forced import over a config-declared key: %v", err)
		}
		if len(ds) != 1 || ds[0].Status != BulkStatusConflict {
			t.Fatalf("got %+v, want one %q", ds, BulkStatusConflict)
		}
		got, err := kdb.BulkExportTsig(nil, KeySelector{})
		if err != nil {
			t.Fatalf("export: %v", err)
		}
		if len(got) != 1 || got[0].Secret != secretA {
			t.Fatalf("a config-declared key was modified anyway: %+v", got)
		}
	})

	// Same stale origin=config row, but the operator has since removed the key
	// from keys.tsig. It is no longer config-managed in truth, and the next boot
	// deletes it regardless, so the import must be allowed through.
	t.Run("removed from config: allowed, and demoted to api", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		seed := BulkTsigKey{Keyname: "orphan.dnslab.", Algorithm: "hmac-sha256",
			Secret: secretA, Origin: "config"}
		if _, err := kdb.BulkImportTsig(nil, []BulkTsigKey{seed}, false, TsigBulkPolicy{}); err != nil {
			t.Fatalf("seeding the orphaned config row: %v", err)
		}

		rotated := seed
		rotated.Secret = secretB
		ds, err := kdb.BulkImportTsig(nil, []BulkTsigKey{rotated}, true, inConfig( /* nothing declared */ ))
		if err != nil {
			t.Fatalf("forced import over an orphaned config row: %v", err)
		}
		if len(ds) != 1 || ds[0].Status != BulkStatusReplaced {
			t.Fatalf("got %+v, want one %q", ds, BulkStatusReplaced)
		}
		got, err := kdb.BulkExportTsig(nil, KeySelector{})
		if err != nil {
			t.Fatalf("export: %v", err)
		}
		// Demoted: claiming config origin for a key keys.tsig does not name is
		// false, and self-deleting at the next SyncConfigTsigKeys.
		if len(got) != 1 || got[0].Secret != secretB || got[0].Origin != "api" {
			t.Fatalf("orphan should be replaced and stored as api-origin: %+v", got)
		}
	})

	// The predicate must answer "declared in keys.tsig", NOT "present in the
	// runtime TSIG store". Those differ: the store is loaded from the whole
	// TsigKeystore table and the dynamic-zone API Add()s into it, so it holds
	// api-origin keys too. Using it made an ordinary API-managed key
	// un-importable, reported as a config conflict that force could not clear.
	t.Run("api-managed key present at runtime but not declared", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		api := BulkTsigKey{Keyname: "apikey.dnslab.", Algorithm: "hmac-sha256",
			Secret: secretA, Origin: "api"}
		if _, err := kdb.BulkImportTsig(nil, []BulkTsigKey{api}, false, TsigBulkPolicy{}); err != nil {
			t.Fatalf("seeding the api-origin key: %v", err)
		}

		// The runtime store holds it -- as it would on a live daemon -- but
		// keys.tsig does not declare it, so the import must go through.
		conf := &Config{}
		conf.Internal.TsigKeyStore = NewTsigKeyStore()
		conf.Internal.TsigKeyStore.Add(TsigDetails{
			Name: "apikey.dnslab.", Algorithm: "hmac-sha256", Secret: secretA,
		})

		rotated := api
		rotated.Secret = secretB
		ds, err := kdb.BulkImportTsig(nil, []BulkTsigKey{rotated}, true,
			TsigBulkPolicy{StillInConfig: conf.tsigKeyDeclaredInConfig})
		if err != nil {
			t.Fatalf("import of an api-managed key: %v", err)
		}
		if len(ds) != 1 || ds[0].Status != BulkStatusReplaced {
			t.Fatalf("got %+v, want one %q -- an api key is not config-owned", ds, BulkStatusReplaced)
		}
	})

	// Minting a fresh row that claims config origin for a key the YAML does not
	// declare: allowed as a key, but stored as api, never as config.
	t.Run("undeclared new key is stored as api", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		ds, err := kdb.BulkImportTsig(nil, []BulkTsigKey{{
			Keyname: "minted.dnslab.", Algorithm: "hmac-sha256",
			Secret: secretA, Origin: "config",
		}}, false, inConfig())
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
		if len(got) != 1 || got[0].Origin != "api" {
			t.Fatalf("an undeclared key must not be stored as config-origin: %+v", got)
		}
	})
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

// TestBulkImportSig0InvalidatesTheCache is the regression test for a bulk
// import leaving a stale key in KeystoreSig0Cache. GetSig0Keys is read-through
// against that cache, so without invalidation a running daemon would keep
// signing UPDATEs with the superseded key until the next restart.
func TestBulkImportSig0InvalidatesTheCache(t *testing.T) {
	kdb := newTestKeyDB(t)
	key := testBulkSig0Key(t, "child.dnslab.")

	// Poison the cache the way a live daemon would have populated it.
	kdb.KeystoreSig0Cache["child.dnslab.+"+Sig0StateActive] = &Sig0ActiveKeys{}

	if _, err := kdb.BulkImportSig0(nil, []BulkSig0Key{key}, false); err != nil {
		t.Fatalf("import: %v", err)
	}
	if _, stale := kdb.KeystoreSig0Cache["child.dnslab.+"+Sig0StateActive]; stale {
		t.Error("bulk import must drop the cached SIG(0) keys for a zone it changed")
	}
}

// testBulkSig0Key builds a REAL SIG(0) keypair: the private half genuinely
// belongs to the KEY RR it is filed with.
//
// It used to pair a hardcoded PEM with an unrelated hardcoded public key, and
// only the keytag was made to line up. Every metadata check passed, so the
// fixture looked fine -- until the correspondence check went in and refused it.
// A fixture that could not be imported by a correct implementation is not
// testing what its name says.
func testBulkSig0Key(t *testing.T, zone string) BulkSig0Key {
	t.Helper()
	rr := &dns.KEY{DNSKEY: dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     512,
		Protocol:  3,
		Algorithm: dns.ED25519,
	}}
	priv, err := rr.Generate(256)
	if err != nil {
		t.Fatalf("generating test SIG(0) key: %v", err)
	}
	privPEM, err := PrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("converting test SIG(0) key to PEM: %v", err)
	}
	return BulkSig0Key{
		Zone: dns.Fqdn(zone), Keyid: rr.KeyTag(), Algorithm: "ED25519", State: Sig0StateActive,
		PrivateKey: privPEM,
		KeyRR:      rr.String(),
	}
}

// trustStoreEntry reads one Sig0TrustStore row, or reports absence.
//
// Keyed off the map key rather than the struct: the truststore "list" handler
// encodes the keyid into the map key ("<name>::<keyid>") and leaves the Keyid
// FIELD unset, so matching on k.Keyid silently compares against zero.
func trustStoreEntry(t *testing.T, kdb *KeyDB, name string, keyid uint16) (Sig0Key, bool) {
	t.Helper()
	resp, err := kdb.Sig0TrustMgmt(nil, TruststorePost{Command: "truststore", SubCommand: "list"})
	if err != nil {
		t.Fatalf("truststore list: %v", err)
	}
	k, ok := resp.ChildSig0keys[fmt.Sprintf("%s::%d", dns.Fqdn(name), keyid)]
	return k, ok
}

// TestSig0BulkImportSyncsTheTrustStore pins the invariant that "add" and
// "generate" already hold: a SIG(0) key tdns holds the private half of is one it
// must also be willing to VERIFY. bulk-import wrote Sig0KeyStore alone, so a
// restored key could sign and not verify -- and after a forced replace the
// TrustStore kept the SUPERSEDED public key, which is worse than absent.
func TestSig0BulkImportSyncsTheTrustStore(t *testing.T) {
	kdb := newTestKeyDB(t)
	key := testBulkSig0Key(t, "child.dnslab.")

	resp, err := kdb.Sig0KeyMgmt(nil, KeystorePost{
		Command: "sig0-mgmt", SubCommand: "bulk-import",
		BulkSig0Keys: []BulkSig0Key{key},
	})
	if err != nil {
		t.Fatalf("bulk-import: %v", err)
	}
	if len(resp.BulkDispositions) != 1 || resp.BulkDispositions[0].Status != BulkStatusImported {
		t.Fatalf("got %+v, want one %q", resp.BulkDispositions, BulkStatusImported)
	}

	got, found := trustStoreEntry(t, kdb, key.Zone, key.Keyid)
	if !found {
		t.Fatalf("bulk-import must mirror the public half into the TrustStore")
	}
	if !got.Validated || !got.Trusted {
		t.Errorf("a key we hold the private half of must be trusted, got validated=%v trusted=%v",
			got.Validated, got.Trusted)
	}

	// A key that was NOT changed must not be touched: an unchanged disposition
	// leaves the keystore alone, so it must leave the TrustStore alone too.
	resp, err = kdb.Sig0KeyMgmt(nil, KeystorePost{
		Command: "sig0-mgmt", SubCommand: "bulk-import",
		BulkSig0Keys: []BulkSig0Key{key},
	})
	if err != nil {
		t.Fatalf("re-import: %v", err)
	}
	if resp.BulkDispositions[0].Status != BulkStatusUnchanged {
		t.Fatalf("re-import: got %+v, want %q", resp.BulkDispositions, BulkStatusUnchanged)
	}
}

// TestSig0KeyMgmtBulkImportHandsBackTheCacheDelta covers BOTH commit owners.
// The invalidation cannot happen where the rows are written -- the commit that
// makes them visible has not happened yet -- so who does it depends on who
// commits, and neither path may drop it.
func TestSig0KeyMgmtBulkImportHandsBackTheCacheDelta(t *testing.T) {
	key := testBulkSig0Key(t, "child.dnslab.")
	cacheKey := "child.dnslab.+" + Sig0StateActive

	t.Run("local tx: invalidated after its own commit", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		kdb.KeystoreSig0Cache[cacheKey] = &Sig0ActiveKeys{}

		if _, err := kdb.Sig0KeyMgmt(nil, KeystorePost{
			Command: "sig0-mgmt", SubCommand: "bulk-import",
			BulkSig0Keys: []BulkSig0Key{key},
		}); err != nil {
			t.Fatalf("bulk-import: %v", err)
		}
		if _, stale := kdb.KeystoreSig0Cache[cacheKey]; stale {
			t.Error("the local-tx path must drop the cached SIG(0) keys after committing")
		}
	})

	t.Run("external tx: delegated to the caller", func(t *testing.T) {
		kdb := newTestKeyDB(t)
		kdb.KeystoreSig0Cache[cacheKey] = &Sig0ActiveKeys{}

		tx, err := kdb.Begin("test")
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		resp, err := kdb.Sig0KeyMgmt(tx, KeystorePost{
			Command: "sig0-mgmt", SubCommand: "bulk-import",
			BulkSig0Keys: []BulkSig0Key{key},
		})
		if err != nil {
			t.Fatalf("bulk-import: %v", err)
		}
		// Still cached: the caller has not committed, so invalidating now would
		// let a read-through GetSig0Keys repopulate from pre-commit rows.
		if _, present := kdb.KeystoreSig0Cache[cacheKey]; !present {
			t.Error("must NOT invalidate before the owning transaction commits")
		}
		if len(resp.BulkSig0InvalidateZones) != 1 || resp.BulkSig0InvalidateZones[0] != "child.dnslab." {
			t.Fatalf("the caller needs the zone list to act on after ITS commit, got %+v",
				resp.BulkSig0InvalidateZones)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
	})
}
