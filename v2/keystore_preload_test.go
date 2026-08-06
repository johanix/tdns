/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"os"
	"path/filepath"
	"testing"
)

// writeExportDir lays out a minimal export directory for one DNSSEC key.
func writeExportDir(t *testing.T, key BulkDnssecKey) string {
	t.Helper()
	dir := t.TempDir()
	base := "Ktest+015+00001"
	if err := os.WriteFile(filepath.Join(dir, base+".private"), []byte(key.PrivateKey), 0600); err != nil {
		t.Fatalf("write private: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, base+".key"), []byte(key.KeyRR+"\n"), 0644); err != nil {
		t.Fatalf("write public: %v", err)
	}
	m := &KeystoreManifest{Version: KeystoreManifestVersion}
	m.UpsertDnssec(ManifestEntryForDnssec(key, base))
	if err := m.Save(dir); err != nil {
		t.Fatalf("save manifest: %v", err)
	}
	return dir
}

func TestPreloadKeystoreLoadsBeforeAnythingElse(t *testing.T) {
	kdb := newTestKeyDB(t)
	key := testDnssecKey(t, "pq.dnslab.", 257)
	dir := writeExportDir(t, key)

	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Keystore.Preload.Dnssec = dir

	if err := conf.PreloadKeystore(); err != nil {
		t.Fatalf("PreloadKeystore: %v", err)
	}
	got, err := kdb.BulkExportDnssec(nil, KeySelector{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(got) != 1 || got[0].Zone != key.Zone || got[0].Keyid != key.Keyid {
		t.Fatalf("pre-load did not restore the key: %+v", got)
	}

	// Idempotent: the second boot must be a clean no-op, not a conflict storm.
	if err := conf.PreloadKeystore(); err != nil {
		t.Fatalf("second PreloadKeystore: %v", err)
	}
	got, err = kdb.BulkExportDnssec(nil, KeySelector{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("re-running pre-load must not duplicate keys: %+v", got)
	}
}

// TestPreloadIsAtomicAcrossClasses pins the all-or-nothing promise in
// PreloadKeystore's doc comment. Each class used to commit on its own, so a
// dnssec class that loaded followed by a sig0 class that failed left the daemon
// booting with half the operator's key material in place and an error saying
// none of it was -- the "pre-load that half worked" the feature exists to
// prevent, produced by pre-load itself.
//
// Ordering matters to the test: classOrder runs dnssec before sig0, so the
// class that must be rolled back is the one that already succeeded.
func TestPreloadIsAtomicAcrossClasses(t *testing.T) {
	kdb := newTestKeyDB(t)
	key := testDnssecKey(t, "pq.dnslab.", 257)
	dnssecDir := writeExportDir(t, key)

	// A sig0 directory whose manifest names a key file that is not there. The
	// failure is deliberately in the LOAD, not the import: it is the shape an
	// operator actually hits (a half-copied export directory), and it happens
	// after the dnssec class has already written its rows.
	sig0Dir := t.TempDir()
	m := &KeystoreManifest{Version: KeystoreManifestVersion}
	m.UpsertSig0(ManifestSig0Key{
		Zone: "pq.dnslab.", Keyid: 4242, Algorithm: "ED25519", State: "active",
		PrivateFile: "missing.private", PublicFile: "missing.key",
	})
	if err := m.Save(sig0Dir); err != nil {
		t.Fatalf("save sig0 manifest: %v", err)
	}

	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Keystore.Preload.Dnssec = dnssecDir
	conf.Keystore.Preload.Sig0 = sig0Dir

	if err := conf.PreloadKeystore(); err == nil {
		t.Fatalf("PreloadKeystore must fail when a class cannot be loaded")
	}

	got, err := kdb.BulkExportDnssec(nil, KeySelector{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("the dnssec class committed despite a later class failing: %+v", got)
	}
}

func TestPreloadNeverOverwritesTheLiveKeystore(t *testing.T) {
	kdb := newTestKeyDB(t)
	key := testDnssecKey(t, "pq.dnslab.", 257)

	// The export on disk says "active"; the running keystore has since rolled
	// the key to retired. Pre-load must leave the keystore alone — restoring
	// the stale copy would silently un-roll it on every restart.
	dir := writeExportDir(t, key)
	rolled := key
	rolled.State = DnskeyStateRetired
	if _, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{rolled}, false); err != nil {
		t.Fatalf("seed: %v", err)
	}

	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Keystore.Preload.Dnssec = dir

	if err := conf.PreloadKeystore(); err != nil {
		t.Fatalf("PreloadKeystore should report the conflict, not fail: %v", err)
	}
	got, err := kdb.BulkExportDnssec(nil, KeySelector{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(got) != 1 || got[0].State != DnskeyStateRetired {
		t.Fatalf("pre-load must not overwrite the keystore, got %+v", got)
	}
}

func TestPreloadOverwriteExistingKeysReplaces(t *testing.T) {
	kdb := newTestKeyDB(t)
	key := testDnssecKey(t, "pq.dnslab.", 257)

	// Same setup as the test above — export says "active", keystore says
	// "retired" — but with the knob set the on-disk copy now wins.
	dir := writeExportDir(t, key)
	rolled := key
	rolled.State = DnskeyStateRetired
	if _, err := kdb.BulkImportDnssec(nil, []BulkDnssecKey{rolled}, false); err != nil {
		t.Fatalf("seed: %v", err)
	}

	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Keystore.Preload.Dnssec = dir
	conf.Keystore.Preload.OverwriteExistingKeys = true

	if err := conf.PreloadKeystore(); err != nil {
		t.Fatalf("PreloadKeystore: %v", err)
	}
	got, err := kdb.BulkExportDnssec(nil, KeySelector{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(got) != 1 || got[0].State != DnskeyStateActive {
		t.Fatalf("overwrite-existing-keys must replace the keystore's copy, got %+v", got)
	}

	// Still idempotent: once the keystore matches, a further boot changes
	// nothing (and so logs no replacements).
	if err := conf.PreloadKeystore(); err != nil {
		t.Fatalf("second PreloadKeystore: %v", err)
	}
	got, err = kdb.BulkExportDnssec(nil, KeySelector{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(got) != 1 || got[0].State != DnskeyStateActive {
		t.Fatalf("second pass should be a no-op, got %+v", got)
	}
}

// TestPreloadTsigSurvivesTheStartupConfigSync is the regression test for the
// interaction that made TSIG pre-load useless: PreloadKeystore runs immediately
// before LoadTsigKeys, whose SyncConfigTsigKeys deletes every origin=config row
// that is not in this host's keys.tsig -- with no isReferenced withholding on
// the startup path. A key restored under its exported origin would therefore be
// deleted seconds after pre-load logged it as imported, on every boot.
func TestPreloadTsigSurvivesTheStartupConfigSync(t *testing.T) {
	kdb := newTestKeyDB(t)
	dir := t.TempDir()

	m := &KeystoreManifest{Version: KeystoreManifestVersion}
	m.UpsertTsig(ManifestTsigKey{
		Keyname: "xfr.dnslab.",
		// Dotted, because that IS the stored form: insertTsigKeystore and
		// updateTsigKeystore both write dns.CanonicalName(algorithm), so every
		// row a real export reads back carries the trailing dot. The fixture
		// asserts it below rather than leaving it unchecked.
		Algorithm: "hmac-sha256.",
		Secret:    "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0Cg==",
		Origin:    "config", // what a config-declared key carries when exported
	})
	if err := m.Save(dir); err != nil {
		t.Fatalf("save manifest: %v", err)
	}

	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Keystore.Preload.Tsig = dir

	if err := conf.PreloadKeystore(); err != nil {
		t.Fatalf("PreloadKeystore: %v", err)
	}

	// Exactly what MainInit does next: LoadTsigKeys -> SyncConfigTsigKeys with
	// this host's keys.tsig entries, which a pre-load-only host has none of.
	if err := kdb.SyncConfigTsigKeys(nil); err != nil {
		t.Fatalf("SyncConfigTsigKeys: %v", err)
	}

	got, err := kdb.BulkExportTsig(nil, KeySelector{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("pre-loaded TSIG key did not survive startup: %+v", got)
	}
	if got[0].Origin != "api" {
		t.Errorf("pre-load must restore TSIG keys as api-origin, got %q", got[0].Origin)
	}
	// The algorithm must land in the keystore's canonical (dotted) form, which
	// is what every non-bulk writer produces. Asserted rather than assumed: bulk
	// import used to store this column verbatim, so a manifest whose spelling
	// differed produced a row that no plain string compare in the tree matched,
	// and nothing on the pre-load path said a word about it.
	if got[0].Algorithm != "hmac-sha256." {
		t.Errorf("pre-loaded TSIG algorithm stored as %q, want %q", got[0].Algorithm, "hmac-sha256.")
	}
}

// TestBulkImportTsigCanonicalisesAlgorithm pins the normalisation directly:
// whichever spelling a manifest carries, the stored row must match what
// insertTsigKeystore/updateTsigKeystore write, or the two writers produce rows
// that do not compare equal to each other.
func TestBulkImportTsigCanonicalisesAlgorithm(t *testing.T) {
	kdb := newTestKeyDB(t)
	if _, err := kdb.BulkImportTsig(nil, []BulkTsigKey{{
		Keyname:   "undotted.dnslab.",
		Algorithm: "hmac-sha256", // no trailing dot, and mixed-case name below
		Secret:    "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0Cg==",
	}}, false, TsigBulkPolicy{}); err != nil {
		t.Fatalf("import: %v", err)
	}
	got, err := kdb.BulkExportTsig(nil, KeySelector{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(got) != 1 || got[0].Algorithm != "hmac-sha256." {
		t.Fatalf("algorithm not canonicalised on write: %+v", got)
	}

	// ...and re-importing the same key in EITHER spelling is then unchanged,
	// not a phantom conflict against the row it just wrote.
	for _, spelling := range []string{"hmac-sha256", "hmac-sha256."} {
		ds, err := kdb.BulkImportTsig(nil, []BulkTsigKey{{
			Keyname:   "undotted.dnslab.",
			Algorithm: spelling,
			Secret:    "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0Cg==",
		}}, false, TsigBulkPolicy{})
		if err != nil {
			t.Fatalf("re-import %q: %v", spelling, err)
		}
		if len(ds) != 1 || ds[0].Status != BulkStatusUnchanged {
			t.Fatalf("re-import of %q: got %+v, want one %q", spelling, ds, BulkStatusUnchanged)
		}
	}
}

// TestBulkImportTsigRejectsUnusableKeyMaterial covers the validation bulk import
// used to skip entirely: it was the one way into the keystore that did not run
// validateTsigKeySpec, so a key that could never sign imported clean and failed
// much later, at signing time, far from the import that caused it.
func TestBulkImportTsigRejectsUnusableKeyMaterial(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  BulkTsigKey
	}{
		{"unsupported algorithm", BulkTsigKey{Keyname: "bad.dnslab.", Algorithm: "hmac-md5",
			Secret: "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0Cg=="}},
		{"secret is not base64", BulkTsigKey{Keyname: "bad.dnslab.", Algorithm: "hmac-sha256",
			Secret: "this is not base64!!"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kdb := newTestKeyDB(t)
			if _, err := kdb.BulkImportTsig(nil, []BulkTsigKey{tc.key}, false, TsigBulkPolicy{}); err == nil {
				t.Fatalf("import must refuse %s", tc.name)
			}
			got, err := kdb.BulkExportTsig(nil, KeySelector{})
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("refused key must not reach the keystore: %+v", got)
			}
		})
	}
}

func TestPreloadWithoutKeystoreIsAWarningNotAFailure(t *testing.T) {
	// A keystore: block reaching an app that has no keystore (tdns-imr, or any
	// daemon sharing a config file via include:) must not stop it from starting.
	conf := &Config{}
	conf.Keystore.Preload.Tsig = t.TempDir()
	if err := conf.PreloadKeystore(); err != nil {
		t.Errorf("an app with no keystore should warn and continue, got %v", err)
	}
}

func TestPreloadFailsLoudlyOnMissingDirectory(t *testing.T) {
	conf := &Config{}
	conf.Internal.KeyDB = newTestKeyDB(t)
	conf.Keystore.Preload.Dnssec = filepath.Join(t.TempDir(), "does-not-exist")

	if err := conf.PreloadKeystore(); err == nil {
		t.Error("a configured pre-load directory that does not exist must abort startup")
	}
}

func TestPreloadUnconfiguredIsANoOp(t *testing.T) {
	conf := &Config{}
	// No KeyDB either: apps without a keystore must not trip over this.
	if err := conf.PreloadKeystore(); err != nil {
		t.Errorf("unconfigured pre-load should do nothing, got %v", err)
	}
}

func TestPreloadDirsSkipsUnset(t *testing.T) {
	c := KeystorePreloadConf{Dnssec: "/a", Tsig: "  "}
	dirs := c.Dirs()
	if len(dirs) != 1 || dirs["dnssec"] != "/a" {
		t.Fatalf("Dirs() should return only the set entries, got %+v", dirs)
	}
}
