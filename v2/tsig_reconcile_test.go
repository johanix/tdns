package tdns

import (
	"database/sql"
	"testing"
)

func TestReconcileConfigTsigKeys_WithholdsSecretConflict(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("seed")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := insertTsigKeystore(tx, TsigKeystoreRow{
		Keyname: "k.", Algorithm: "hmac-sha512", Secret: b64Secret16, Origin: "api", Creator: "test",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	res, err := kdb.ReconcileConfigTsigKeys([]TsigDetails{
		{Name: "k.", Algorithm: "hmac-sha256", Secret: b64Secret16},
	}, TsigReconcileOptions{}, nil)
	if err != nil {
		t.Fatalf("ReconcileConfigTsigKeys: %v", err)
	}
	if len(res.Conflicts) != 1 || res.Conflicts[0] != "k." {
		t.Fatalf("conflicts: %+v", res.Conflicts)
	}
	row, err := getTsigKeystoreByName(kdb, "k.")
	if err != nil || row.Algorithm != "hmac-sha512." {
		t.Fatalf("row should be unchanged: %+v err=%v", row, err)
	}
}

func TestReconcileConfigTsigKeys_ForceOverwritesConflict(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("seed")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := insertTsigKeystore(tx, TsigKeystoreRow{
		Keyname: "k.", Algorithm: "hmac-sha512", Secret: b64Secret16, Origin: "api", Creator: "test",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	_, err = kdb.ReconcileConfigTsigKeys([]TsigDetails{
		{Name: "k.", Algorithm: "hmac-sha256", Secret: b64Secret16},
	}, TsigReconcileOptions{Force: true}, nil)
	if err != nil {
		t.Fatalf("ReconcileConfigTsigKeys: %v", err)
	}
	row, err := getTsigKeystoreByName(kdb, "k.")
	if err != nil || row.Origin != "config" || row.Algorithm != "hmac-sha256." {
		t.Fatalf("got %+v err=%v", row, err)
	}
}

func TestReconcileConfigTsigKeys_PromotesIdenticalApiKey(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("seed")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := insertTsigKeystore(tx, TsigKeystoreRow{
		Keyname: "k.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "api", Owner: "api", Creator: "test",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	res, err := kdb.ReconcileConfigTsigKeys([]TsigDetails{
		{Name: "k.", Algorithm: "hmac-sha256", Secret: b64Secret16},
	}, TsigReconcileOptions{}, nil)
	if err != nil {
		t.Fatalf("ReconcileConfigTsigKeys: %v", err)
	}
	row, err := getTsigKeystoreByName(kdb, "k.")
	if err != nil || row.Origin != "config" {
		t.Fatalf("got %+v err=%v", row, err)
	}
	if len(res.Conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %+v", res.Conflicts)
	}
}

func TestReconcileConfigTsigKeys_UnchangedConfigKeyEmptyDelta(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("seed")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := insertTsigKeystore(tx, TsigKeystoreRow{
		Keyname: "k.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "config", Owner: "config", Creator: "config",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	res, err := kdb.ReconcileConfigTsigKeys([]TsigDetails{
		{Name: "k.", Algorithm: "hmac-sha256", Secret: b64Secret16, Owner: "config"},
	}, TsigReconcileOptions{}, nil)
	if err != nil {
		t.Fatalf("ReconcileConfigTsigKeys: %v", err)
	}
	if res.TsigCacheDelta == nil || len(res.TsigCacheDelta.Changed) != 0 || len(res.TsigCacheDelta.Deleted) != 0 {
		t.Fatalf("expected empty cache delta, got %+v", res.TsigCacheDelta)
	}
}

func TestReconcileConfigTsigKeys_WithholdsReferencedRemoval(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("seed")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := insertTsigKeystore(tx, TsigKeystoreRow{
		Keyname: "ref.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "config", Creator: "config",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	res, err := kdb.ReconcileConfigTsigKeys(nil, TsigReconcileOptions{}, func(name string) bool {
		return name == "ref."
	})
	if err != nil {
		t.Fatalf("ReconcileConfigTsigKeys: %v", err)
	}
	if len(res.WithheldRemovals) != 1 {
		t.Fatalf("withheld: %+v", res.WithheldRemovals)
	}
	if _, err := getTsigKeystoreByName(kdb, "ref."); err != nil {
		t.Fatalf("key should remain: %v", err)
	}
}

func TestReconcileConfigTsigKeys_ForceDoesNotDropReferencedRemoval(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("seed")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := insertTsigKeystore(tx, TsigKeystoreRow{
		Keyname: "ref.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "config", Creator: "config",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	res, err := kdb.ReconcileConfigTsigKeys(nil, TsigReconcileOptions{Force: true}, func(name string) bool {
		return name == "ref."
	})
	if err != nil {
		t.Fatalf("ReconcileConfigTsigKeys: %v", err)
	}
	if len(res.WithheldRemovals) != 1 {
		t.Fatalf("withheld: %+v", res.WithheldRemovals)
	}
	if _, err := getTsigKeystoreByName(kdb, "ref."); err != nil {
		t.Fatal("referenced config key must survive even with Force")
	}
}

func TestReconcileConfigTsigKeys_DropsUnreferencedRemoval(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("seed")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := insertTsigKeystore(tx, TsigKeystoreRow{
		Keyname: "gone.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "config", Creator: "config",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	_, err = kdb.ReconcileConfigTsigKeys(nil, TsigReconcileOptions{}, func(string) bool { return false })
	if err != nil {
		t.Fatalf("ReconcileConfigTsigKeys: %v", err)
	}
	if _, err := getTsigKeystoreByName(kdb, "gone."); err != sql.ErrNoRows {
		t.Fatalf("expected removal, err=%v", err)
	}
}

func TestTsigKeyZoneRefCount(t *testing.T) {
	conf := &Config{}
	Zones.Set("z.example.", &ZoneData{
		ZoneName:      "z.example.",
		PrimariesConf: []PeerConf{{Addr: "1.2.3.4", Key: "tsig."}},
	})
	t.Cleanup(func() { Zones.Remove("z.example.") })

	if n := conf.tsigKeyZoneRefCount("tsig."); n != 1 {
		t.Fatalf("refcount = %d, want 1", n)
	}
	if n := conf.tsigKeyZoneRefCount("missing."); n != 0 {
		t.Fatalf("refcount = %d, want 0", n)
	}
}

func TestTsigKeyZoneRefCount_AllFields(t *testing.T) {
	conf := &Config{}
	fields := []struct {
		name string
		zd   *ZoneData
	}{
		{"upstream", &ZoneData{ZoneName: "u.example.", Upstreams: []PeerConf{{Key: "k."}}}},
		{"notify", &ZoneData{ZoneName: "n.example.", Notify: []PeerConf{{Key: "k."}}}},
		{"allownotify", &ZoneData{ZoneName: "a.example.", AllowNotify: []AclEntry{{Key: "k."}}}},
		{"downstream", &ZoneData{ZoneName: "d.example.", Downstreams: []AclEntry{{Key: "k."}}}},
	}
	for _, tc := range fields {
		Zones.Set(tc.zd.ZoneName, tc.zd)
		if n := conf.tsigKeyZoneRefCount("k."); n != 1 {
			t.Fatalf("%s: refcount = %d, want 1", tc.name, n)
		}
		Zones.Remove(tc.zd.ZoneName)
	}
}

func TestTsigKeyZoneRefCount_DedupPerZone(t *testing.T) {
	conf := &Config{}
	Zones.Set("z.example.", &ZoneData{
		ZoneName:      "z.example.",
		PrimariesConf: []PeerConf{{Key: "dup."}},
		Upstreams:     []PeerConf{{Key: "dup."}},
	})
	t.Cleanup(func() { Zones.Remove("z.example.") })
	if n := conf.tsigKeyZoneRefCount("dup."); n != 1 {
		t.Fatalf("refcount = %d, want 1 (dedup per zone)", n)
	}
}

func TestReloadTsigConfig_ReconcileInPlace(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf := &Config{
		Keys: KeyConf{
			Tsig: []TsigDetails{{Name: "live.", Algorithm: "hmac-sha256", Secret: b64Secret16}},
		},
	}
	conf.Internal.KeyDB = kdb
	conf.Internal.TsigKeyStore = NewTsigKeyStore()
	tx, err := kdb.Begin("seed-api")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := insertTsigKeystore(tx, TsigKeystoreRow{
		Keyname: "api.", Algorithm: "hmac-sha512", Secret: b64Secret16, Origin: "api", Creator: "test",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := kdb.LoadTsigKeystoreInto(conf.Internal.TsigKeyStore); err != nil {
		t.Fatalf("LoadTsigKeystoreInto: %v", err)
	}

	result, err := conf.reconcileAndRefreshTsigKeys(TsigReconcileOptions{})
	if err != nil {
		t.Fatalf("reconcileAndRefreshTsigKeys: %v", err)
	}
	if len(result.Conflicts) != 0 {
		t.Fatalf("unexpected conflicts: %+v", result.Conflicts)
	}
	if !conf.Internal.TsigKeyStore.Has("live.") || !conf.Internal.TsigKeyStore.Has("api.") {
		t.Fatalf("cache: %v", conf.Internal.TsigKeyStore.Names())
	}
}
