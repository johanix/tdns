package tdns

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigrateDynamicConfigTsigKeys(t *testing.T) {
	kdb := newTestKeyDB(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "dynamic.yaml")

	conf := &Config{
		DynamicZones: DynamicZonesConf{ConfigFile: cfgPath},
	}
	conf.Internal.KeyDB = kdb
	conf.Internal.TsigKeyStore = NewTsigKeyStore()

	cf := &DynamicConfigFile{
		Zones: []ZoneConf{{Name: "z.", Type: "secondary"}},
		Keys: &KeyConf{Tsig: []TsigDetails{
			{Name: "dyn.", Algorithm: "hmac-sha256", Secret: b64Secret16},
		}},
	}
	if err := conf.migrateDynamicConfigTsigKeys(cf); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if cf.Keys != nil {
		t.Fatal("keys block should be cleared after migration")
	}
	if !conf.Internal.TsigKeyStore.Has("dyn.") {
		t.Fatal("migrated key missing from cache")
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if contains := string(data); containsKeysBlock(contains) {
		t.Fatal("rewritten file must not contain keys: block")
	}

	// Idempotent second pass (no keys block).
	if err := conf.migrateDynamicConfigTsigKeys(cf); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
}

func containsKeysBlock(s string) bool {
	return len(s) > 0 && (containsSubstring(s, "\nkeys:") || containsSubstring(s, "\nkeys:\n"))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestMigrateDynamicConfigTsigKeys_SkipsExisting(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("seed")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := insertTsigKeystore(tx, TsigKeystoreRow{
		Keyname: "shared.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "config", Creator: "config",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	dir := t.TempDir()
	conf := &Config{DynamicZones: DynamicZonesConf{ConfigFile: filepath.Join(dir, "dynamic.yaml")}}
	conf.Internal.KeyDB = kdb
	conf.Internal.TsigKeyStore = NewTsigKeyStore()
	if err := kdb.LoadTsigKeystoreInto(conf.Internal.TsigKeyStore); err != nil {
		t.Fatalf("load: %v", err)
	}

	cf := &DynamicConfigFile{
		Keys: &KeyConf{Tsig: []TsigDetails{
			{Name: "shared.", Algorithm: "hmac-sha256", Secret: "YWJjZGVmZ2hpamtsbW5vcA=="},
			{Name: "new.", Algorithm: "hmac-sha256", Secret: b64Secret16},
		}},
	}
	if err := conf.migrateDynamicConfigTsigKeys(cf); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	got, _ := conf.Internal.TsigKeyStore.Get("shared.")
	if got.Secret != b64Secret16 {
		t.Fatalf("existing config key must not be overwritten, got %q", got.Secret)
	}
	if !conf.Internal.TsigKeyStore.Has("new.") {
		t.Fatal("new key should be migrated")
	}
}
