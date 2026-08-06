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
		Keyname:   "xfr.dnslab.",
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
