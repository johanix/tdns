package tdns

import (
	"database/sql"
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
