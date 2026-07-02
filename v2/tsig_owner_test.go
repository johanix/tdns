package tdns

import "testing"

func TestSyncConfigTsigKeys_OwnerFromYAML(t *testing.T) {
	kdb := newTestKeyDB(t)
	if err := kdb.SyncConfigTsigKeys([]TsigDetails{
		{Name: "cat.", Algorithm: "hmac-sha256", Secret: b64Secret16, Owner: "catalog"},
	}); err != nil {
		t.Fatalf("sync: %v", err)
	}
	row, err := getTsigKeystoreByName(kdb, "cat.")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if row.Owner != "catalog" {
		t.Fatalf("owner = %q, want catalog", row.Owner)
	}
}

func TestReconcileConfigTsigKeys_UpdatesOwner(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("seed-owner")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := insertTsigKeystore(tx, TsigKeystoreRow{
		Keyname: "cfg.", Algorithm: "hmac-sha256", Secret: b64Secret16,
		Origin: "config", Owner: "config", Creator: "config",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	_, err = kdb.ReconcileConfigTsigKeys([]TsigDetails{
		{Name: "cfg.", Algorithm: "hmac-sha256", Secret: b64Secret16, Owner: "catalog"},
	}, TsigReconcileOptions{}, nil)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	row, err := getTsigKeystoreByName(kdb, "cfg.")
	if err != nil || row.Owner != "catalog" {
		t.Fatalf("owner not updated: %+v err=%v", row, err)
	}
}
