package tdns

import (
	"database/sql"
	"encoding/base64"
	"testing"
)

func TestTsigKeystoreTableExists(t *testing.T) {
	kdb := newTestKeyDB(t)
	var name string
	err := kdb.DB.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='table' AND name='TsigKeystore'`,
	).Scan(&name)
	if err != nil {
		t.Fatalf("TsigKeystore table missing: %v", err)
	}
}

func TestInsertTsigKeystore(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("TestInsertTsigKeystore")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	defer tx.Rollback()

	row := TsigKeystoreRow{
		Keyname:   "transfer-key.",
		Algorithm: "hmac-sha256",
		Secret:    b64Secret16,
		Origin:    "api",
		Owner:     "api",
		Creator:   "test",
	}
	if err := insertTsigKeystore(tx, row); err != nil {
		t.Fatalf("insertTsigKeystore: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	got, err := getTsigKeystoreByName(kdb, "transfer-key.")
	if err != nil {
		t.Fatalf("getTsigKeystoreByName: %v", err)
	}
	if got.Keyname != "transfer-key." || got.Algorithm != "hmac-sha256." || got.Secret != b64Secret16 {
		t.Fatalf("got %+v", got)
	}
	if got.Origin != "api" || got.Owner != "api" || got.Creator != "test" {
		t.Fatalf("metadata: got %+v", got)
	}
	if got.CreatedAt == "" {
		t.Error("expected created_at to be stamped")
	}
}

func TestInsertTsigKeystore_ReservedName(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("TestInsertTsigKeystore_ReservedName")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	defer tx.Rollback()

	err = insertTsigKeystore(tx, TsigKeystoreRow{
		Keyname:   "BLOCKED",
		Algorithm: "hmac-sha256",
		Secret:    b64Secret16,
		Origin:    "api",
	})
	if err == nil {
		t.Fatal("expected error for reserved name BLOCKED")
	}

	err = insertTsigKeystore(tx, TsigKeystoreRow{
		Keyname:   "k",
		Algorithm: "md5",
		Secret:    b64Secret16,
		Origin:    "config",
	})
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestGetTsigKeystoreByName_Missing(t *testing.T) {
	kdb := newTestKeyDB(t)
	_, err := getTsigKeystoreByName(kdb, "missing.")
	if err != sql.ErrNoRows {
		t.Fatalf("got err %v, want sql.ErrNoRows", err)
	}
}

func TestLoadTsigKeystoreInto(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("TestLoadTsigKeystoreInto")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	for _, row := range []TsigKeystoreRow{
		{Keyname: "a.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "api", Owner: "api", Creator: "test"},
		{Keyname: "b.", Algorithm: "hmac-sha512", Secret: b64Secret16, Origin: "config", Owner: "catalog", Creator: "test"},
	} {
		if err := insertTsigKeystore(tx, row); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	store := NewTsigKeyStore()
	if err := kdb.LoadTsigKeystoreInto(store); err != nil {
		t.Fatalf("LoadTsigKeystoreInto: %v", err)
	}
	if !store.Has("a.") || !store.Has("b.") {
		t.Fatalf("expected both keys loaded, names=%v", store.Names())
	}
}

func TestGenerateTsigSecret(t *testing.T) {
	s, err := GenerateTsigSecret("hmac-sha256")
	if err != nil {
		t.Fatalf("GenerateTsigSecret: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 {
		t.Fatalf("got len %d err=%v", len(raw), err)
	}
	if _, err := GenerateTsigSecret("md5"); err == nil {
		t.Fatal("expected error for md5")
	}
}

func TestTsigKeyMgmtGenerate(t *testing.T) {
	kdb := newTestKeyDB(t)
	store := NewTsigKeyStore()
	resp, err := kdb.TsigKeyMgmt(nil, nil, KeystorePost{
		SubCommand:    "generate",
		TsigKeyname:   "gen.",
		TsigAlgorithm: "hmac-sha256",
		Creator:       "test",
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := ApplyTsigCacheDelta(store, kdb, resp.TsigCacheDelta); err != nil {
		t.Fatalf("delta: %v", err)
	}
	if !store.Has("gen.") {
		t.Fatal("generated key not in cache after delta")
	}
}

func TestTsigKeyMgmtAddListDeleteAndCacheDelta(t *testing.T) {
	kdb := newTestKeyDB(t)
	store := NewTsigKeyStore()

	resp, err := kdb.TsigKeyMgmt(nil, nil, KeystorePost{
		SubCommand:    "add",
		TsigKeyname:   "mgmt-key.",
		TsigAlgorithm: "hmac-sha256",
		TsigSecret:    b64Secret16,
		Creator:       "test",
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if resp.TsigCacheDelta == nil || len(resp.TsigCacheDelta.Changed) != 1 {
		t.Fatalf("add delta: %+v", resp.TsigCacheDelta)
	}
	if err := ApplyTsigCacheDelta(store, kdb, resp.TsigCacheDelta); err != nil {
		t.Fatalf("ApplyTsigCacheDelta after add: %v", err)
	}
	if !store.Has("mgmt-key.") {
		t.Fatal("store missing key after add delta")
	}

	resp, err = kdb.TsigKeyMgmt(nil, nil, KeystorePost{SubCommand: "list"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(resp.TsigKeys) != 1 || resp.TsigKeys[0].Name != "mgmt-key." {
		t.Fatalf("list: %+v", resp.TsigKeys)
	}

	resp, err = kdb.TsigKeyMgmt(nil, nil, KeystorePost{SubCommand: "delete", TsigKeyname: "mgmt-key."})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := ApplyTsigCacheDelta(store, kdb, resp.TsigCacheDelta); err != nil {
		t.Fatalf("ApplyTsigCacheDelta after delete: %v", err)
	}
	if store.Has("mgmt-key.") {
		t.Fatal("store still has deleted key")
	}
}

func TestTsigKeyMgmtDeleteConfigOriginRejected(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("TestTsigKeyMgmtDeleteConfigOriginRejected")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := insertTsigKeystore(tx, TsigKeystoreRow{
		Keyname: "static.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "config", Creator: "test",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	_, err = kdb.TsigKeyMgmt(nil, nil, KeystorePost{SubCommand: "delete", TsigKeyname: "static."})
	if err == nil {
		t.Fatal("expected delete of config-origin key to fail")
	}
}

func TestLoadTsigKeysFromDB_SyncsConfigAndKeepsAPI(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("TestLoadTsigKeysFromDB")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := insertTsigKeystore(tx, TsigKeystoreRow{
		Keyname: "api-only.", Algorithm: "hmac-sha512", Secret: b64Secret16, Origin: "api", Creator: "test",
	}); err != nil {
		t.Fatalf("insert api: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	conf := &Config{
		Keys: KeyConf{
			Tsig: []TsigDetails{{Name: "cfg.", Algorithm: "hmac-sha256", Secret: b64Secret16}},
		},
	}
	conf.Internal.KeyDB = kdb
	if err := conf.LoadTsigKeys(); err != nil {
		t.Fatalf("LoadTsigKeys: %v", err)
	}
	if !conf.Internal.TsigKeyStore.Has("cfg.") || !conf.Internal.TsigKeyStore.Has("api-only.") {
		t.Fatalf("expected config+api keys, names=%v", conf.Internal.TsigKeyStore.Names())
	}
	row, err := getTsigKeystoreByName(kdb, "cfg.")
	if err != nil || row.Origin != "config" {
		t.Fatalf("cfg row: %+v err=%v", row, err)
	}
}

func TestSyncConfigTsigKeys_DropsRemovedConfigKey(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("TestSyncConfigTsigKeys_DropsRemovedConfigKey")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	for _, row := range []TsigKeystoreRow{
		{Keyname: "keep.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "config", Creator: "config"},
		{Keyname: "drop.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "config", Creator: "config"},
		{Keyname: "api.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "api", Creator: "test"},
	} {
		if err := insertTsigKeystore(tx, row); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if err := kdb.SyncConfigTsigKeys([]TsigDetails{
		{Name: "keep.", Algorithm: "hmac-sha256", Secret: b64Secret16},
	}); err != nil {
		t.Fatalf("SyncConfigTsigKeys: %v", err)
	}
	if _, err := getTsigKeystoreByName(kdb, "drop."); err != sql.ErrNoRows {
		t.Fatalf("drop. should be gone, err=%v", err)
	}
	if _, err := getTsigKeystoreByName(kdb, "api."); err != nil {
		t.Fatalf("api-origin key must remain: %v", err)
	}
}

func TestTsigKeyMgmtListRefCount(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf := &Config{Catalog: &CatalogConf{ConfigGroups: map[string]*ConfigGroupConfig{
		"g": {TsigKey: "cat-key."},
	}}}
	tx, err := kdb.Begin("TestTsigKeyMgmtListRefCount")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	for _, row := range []TsigKeystoreRow{
		{Keyname: "cat-key.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "api", Creator: "test"},
		{Keyname: "zone-key.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "api", Creator: "test"},
	} {
		if err := insertTsigKeystore(tx, row); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	Zones.Set("z.", &ZoneData{ZoneName: "z.", PrimariesConf: []PeerConf{{Key: "zone-key."}}})
	t.Cleanup(func() { Zones.Remove("z.") })

	resp, err := kdb.TsigKeyMgmt(conf, nil, KeystorePost{SubCommand: "list"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	byName := map[string]TsigKeyInfo{}
	for _, k := range resp.TsigKeys {
		byName[k.Name] = k
	}
	if byName["cat-key."].RefCount != 1 || byName["zone-key."].RefCount != 1 {
		t.Fatalf("refcounts: %+v", resp.TsigKeys)
	}
}

func TestTsigKeyMgmtDeleteReferencedRejected(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf := &Config{}
	tx, err := kdb.Begin("TestTsigKeyMgmtDeleteReferencedRejected")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := insertTsigKeystore(tx, TsigKeystoreRow{
		Keyname: "in-use.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "api", Creator: "test",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	Zones.Set("z.", &ZoneData{ZoneName: "z.", Downstreams: []AclEntry{{Key: "in-use."}}})
	t.Cleanup(func() { Zones.Remove("z.") })

	_, err = kdb.TsigKeyMgmt(conf, nil, KeystorePost{SubCommand: "delete", TsigKeyname: "in-use."})
	if err == nil {
		t.Fatal("expected delete of referenced key to fail")
	}
}
