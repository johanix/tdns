package tdns

import (
	"os"
	"path/filepath"
	"strings"
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
	row, err := getTsigKeystoreByName(kdb, "dyn.")
	if err != nil || row.Origin != "api" || row.Owner != "api" || row.Creator != "dynamic-config-migration" {
		t.Fatalf("row metadata: %+v err=%v", row, err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	for _, ln := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "keys:") {
			t.Fatal("rewritten file must not contain keys: block")
		}
	}
	if err := conf.migrateDynamicConfigTsigKeys(cf); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
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
			// Same name AND same secret as the seeded key => idempotent skip.
			{Name: "shared.", Algorithm: "hmac-sha256", Secret: b64Secret16},
			{Name: "new.", Algorithm: "hmac-sha256", Secret: b64Secret16},
		}},
	}
	if err := conf.migrateDynamicConfigTsigKeys(cf); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	got, _ := conf.Internal.TsigKeyStore.Get("shared.")
	if got.Secret != b64Secret16 {
		t.Fatalf("existing key must be left intact, got %q", got.Secret)
	}
	if !conf.Internal.TsigKeyStore.Has("new.") {
		t.Fatal("new key should be migrated")
	}
}

// TestMigrateDynamicConfigTsigKeys_ConflictRejected pins the safety fix: a legacy
// YAML key whose name collides with an existing keystore key but carries a
// DIFFERENT secret must abort the migration (dropping the keys: block would
// silently switch the zone's secret), and no key is migrated (all-or-nothing).
func TestMigrateDynamicConfigTsigKeys_ConflictRejected(t *testing.T) {
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
			{Name: "shared.", Algorithm: "hmac-sha256", Secret: "YWJjZGVmZ2hpamtsbW5vcA=="}, // different secret
			{Name: "new.", Algorithm: "hmac-sha256", Secret: b64Secret16},
		}},
	}
	if err := conf.migrateDynamicConfigTsigKeys(cf); err == nil {
		t.Fatal("expected a conflict error, got nil")
	}
	if conf.Internal.TsigKeyStore.Has("new.") {
		t.Fatal("on conflict the migration must roll back — no key migrated")
	}
}
