package tdns

import "testing"

func TestTsigKeyMgmtPurge(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf := &Config{}
	tx, err := kdb.Begin("TestTsigKeyMgmtPurge")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	for _, row := range []TsigKeystoreRow{
		{Keyname: "purge-me.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "api", Owner: "api", Creator: "test"},
		{Keyname: "keep-ref.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "api", Owner: "api", Creator: "test"},
		{Keyname: "config.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "config", Creator: "config"},
	} {
		if err := insertTsigKeystore(tx, row); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	Zones.Set("z.", &ZoneData{ZoneName: "z.", Downstreams: []AclEntry{{Key: "keep-ref."}}})
	t.Cleanup(func() { Zones.Remove("z.") })

	dry, err := kdb.TsigKeyMgmt(conf, nil, KeystorePost{SubCommand: "purge"})
	if err != nil {
		t.Fatalf("dry purge: %v", err)
	}
	if len(dry.TsigKeys) != 1 || dry.TsigKeys[0].Name != "purge-me." {
		t.Fatalf("dry candidates: %+v", dry.TsigKeys)
	}
	if _, err := getTsigKeystoreByName(kdb, "purge-me."); err != nil {
		t.Fatalf("dry-run should not delete: %v", err)
	}

	store := NewTsigKeyStore()
	force, err := kdb.TsigKeyMgmt(conf, nil, KeystorePost{SubCommand: "purge", Force: true})
	if err != nil {
		t.Fatalf("force purge: %v", err)
	}
	if err := ApplyTsigCacheDelta(store, kdb, force.TsigCacheDelta); err != nil {
		t.Fatalf("delta: %v", err)
	}
	if _, err := getTsigKeystoreByName(kdb, "purge-me."); err == nil {
		t.Fatal("purge-me should be gone")
	}
	if _, err := getTsigKeystoreByName(kdb, "keep-ref."); err != nil {
		t.Fatal("referenced key must remain")
	}
}
