package tdns

import "testing"

const bindSample = `
options { directory "/var/named"; };
key "transfer-key." {
    algorithm hmac-sha256;
    secret "MTIzNDU2Nzg5MDEyMzQ1Ng==";
};
zone "example.com" { type master; file "example.com.zone"; };
`

const nsdSample = `
server:
    username: nsd
key:
    name: nsd-key.
    algorithm: hmac-sha512
    secret: "MTIzNDU2Nzg5MDEyMzQ1Ng=="
`

func TestExtractBindTsigKeys(t *testing.T) {
	keys, err := extractBindTsigKeys(bindSample)
	if err != nil || len(keys) != 1 {
		t.Fatalf("extract: %+v err=%v", keys, err)
	}
	if keys[0].Name != "transfer-key." || keys[0].Algorithm != "hmac-sha256" {
		t.Fatalf("got %+v", keys[0])
	}
}

func TestExtractNsdTsigKeys(t *testing.T) {
	keys, err := extractNsdTsigKeys(nsdSample)
	if err != nil || len(keys) != 1 {
		t.Fatalf("extract: %+v err=%v", keys, err)
	}
	if keys[0].Name != "nsd-key." {
		t.Fatalf("got %+v", keys[0])
	}
}

func TestTsigKeyMgmtImport(t *testing.T) {
	kdb := newTestKeyDB(t)

	tx, err := kdb.Begin("seed-conflict")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := insertTsigKeystore(tx, TsigKeystoreRow{
		Keyname: "existing.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "api", Creator: "test",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	data := `key "new-key." { algorithm hmac-sha256; secret "MTIzNDU2Nzg5MDEyMzQ1Ng=="; };
key "existing." { algorithm hmac-sha256; secret "YWJjZGVmZ2hpamtsbW5vcA=="; };`

	store := NewTsigKeyStore()
	if err := kdb.LoadTsigKeystoreInto(store); err != nil {
		t.Fatalf("LoadTsigKeystoreInto: %v", err)
	}

	resp, err := kdb.TsigKeyMgmt(nil, nil, KeystorePost{
		SubCommand:       "import",
		TsigImportData:   data,
		TsigImportFormat: "bind",
		Creator:          "test",
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !resp.Error {
		t.Fatal("expected withheld conflicts to set resp.Error")
	}
	if err := ApplyTsigCacheDelta(store, kdb, resp.TsigCacheDelta); err != nil {
		t.Fatalf("delta: %v", err)
	}
	if !store.Has("new-key.") {
		t.Fatal("safe subset key should be imported")
	}
	byName := map[string]string{}
	for _, d := range resp.TsigImport {
		byName[d.Name] = d.Status
	}
	if byName["new-key."] != "imported" || byName["existing."] != "conflict" {
		t.Fatalf("dispositions: %+v", resp.TsigImport)
	}

	resp2, err := kdb.TsigKeyMgmt(nil, nil, KeystorePost{
		SubCommand:       "import",
		TsigImportData:   data,
		TsigImportFormat: "bind",
		TsigOverwrite:    []string{"existing."},
		Creator:          "test",
	})
	if err != nil {
		t.Fatalf("overwrite import: %v", err)
	}
	if err := ApplyTsigCacheDelta(store, kdb, resp2.TsigCacheDelta); err != nil {
		t.Fatalf("delta2: %v", err)
	}
	got, ok := store.Get("existing.")
	if !ok || got.Secret != "YWJjZGVmZ2hpamtsbW5vcA==" {
		t.Fatalf("overwrite failed: %+v ok=%v", got, ok)
	}
}
