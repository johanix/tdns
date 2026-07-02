package tdns

import (
	"encoding/base64"
	"testing"

	"github.com/miekg/dns"
)

func TestTsigKeyMgmtSetOwner(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("seed-setowner")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := insertTsigKeystore(tx, TsigKeystoreRow{
		Keyname: "api.", Algorithm: "hmac-sha256", Secret: b64Secret16,
		Origin: "api", Owner: "api", Creator: "test",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	resp, err := kdb.TsigKeyMgmt(nil, nil, KeystorePost{
		SubCommand: "setowner", TsigKeyname: "api.", Owner: "ops",
	})
	if err != nil {
		t.Fatalf("setowner: %v", err)
	}
	if resp.Msg == "" {
		t.Fatal("expected confirmation message")
	}
	row, err := getTsigKeystoreByName(kdb, "api.")
	if err != nil || row.Owner != "ops" {
		t.Fatalf("owner not updated: %+v err=%v", row, err)
	}
}

func TestTsigKeyMgmtSetOwner_ConfigOriginRejected(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("seed-setowner-cfg")
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

	_, err = kdb.TsigKeyMgmt(nil, nil, KeystorePost{
		SubCommand: "setowner", TsigKeyname: "cfg.", Owner: "ops",
	})
	if err == nil {
		t.Fatal("expected setowner on config-origin key to fail")
	}
}

func TestTsigKeyMgmtAdd_ForceOverwriteAndIdempotent(t *testing.T) {
	kdb := newTestKeyDB(t)
	store := NewTsigKeyStore()

	_, err := kdb.TsigKeyMgmt(nil, nil, KeystorePost{
		SubCommand: "add", TsigKeyname: "k.", TsigAlgorithm: "hmac-sha256",
		TsigSecret: b64Secret16, Creator: "test",
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	_, err = kdb.TsigKeyMgmt(nil, nil, KeystorePost{
		SubCommand: "add", TsigKeyname: "k.", TsigAlgorithm: "hmac-sha512",
		TsigSecret: "YWJjZGVmZ2hpamtsbW5vcA==", Creator: "test",
	})
	if err == nil {
		t.Fatal("expected conflict without force")
	}

	resp, err := kdb.TsigKeyMgmt(nil, nil, KeystorePost{
		SubCommand: "add", TsigKeyname: "k.", TsigAlgorithm: "hmac-sha512",
		TsigSecret: "YWJjZGVmZ2hpamtsbW5vcA==", Force: true, Creator: "test",
	})
	if err != nil {
		t.Fatalf("force add: %v", err)
	}
	if err := ApplyTsigCacheDelta(store, kdb, resp.TsigCacheDelta); err != nil {
		t.Fatalf("delta: %v", err)
	}
	got, ok := store.Get("k.")
	if !ok || dns.CanonicalName(got.Algorithm) != dns.CanonicalName("hmac-sha512") {
		t.Fatalf("overwrite failed: %+v ok=%v", got, ok)
	}

	resp2, err := kdb.TsigKeyMgmt(nil, nil, KeystorePost{
		SubCommand: "add", TsigKeyname: "k.", TsigAlgorithm: "hmac-sha512",
		TsigSecret: "YWJjZGVmZ2hpamtsbW5vcA==", Creator: "test",
	})
	if err != nil {
		t.Fatalf("idempotent add: %v", err)
	}
	if resp2.TsigCacheDelta != nil {
		t.Fatalf("unchanged add should not produce cache delta: %+v", resp2.TsigCacheDelta)
	}
}

func TestTsigKeyMgmtImport_ConflictAndForce(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("seed-import")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := insertTsigKeystore(tx, TsigKeystoreRow{
		Keyname: "same.", Algorithm: "hmac-sha256", Secret: b64Secret16,
		Origin: "api", Owner: "api", Creator: "test",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	data := `key "new-key." { algorithm hmac-sha256; secret "MTIzNDU2Nzg5MDEyMzQ1Ng=="; };
key "same." { algorithm hmac-sha256; secret "YWJjZGVmZ2hpamtsbW5vcA=="; };`

	resp, err := kdb.TsigKeyMgmt(nil, nil, KeystorePost{
		SubCommand: "import", TsigImportData: data, TsigImportFormat: "bind", Creator: "test",
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !resp.Error {
		t.Fatal("expected conflict on differing existing key without force")
	}
	byName := map[string]string{}
	for _, d := range resp.TsigImport {
		byName[d.Name] = d.Status
	}
	if byName["same."] != "conflict" || byName["new-key."] != "imported" {
		t.Fatalf("dispositions: %+v", resp.TsigImport)
	}
	if _, err := getTsigKeystoreByName(kdb, "new-key."); err != nil {
		t.Fatal("new key should be imported even when another key conflicts")
	}

	resp2, err := kdb.TsigKeyMgmt(nil, nil, KeystorePost{
		SubCommand: "import", TsigImportData: data, TsigImportFormat: "bind",
		Force: true, Creator: "test",
	})
	if err != nil || resp2.Error {
		t.Fatalf("force import: err=%v resp=%+v", err, resp2)
	}
	got, err := getTsigKeystoreByName(kdb, "same.")
	if err != nil || got.Secret != "YWJjZGVmZ2hpamtsbW5vcA==" {
		t.Fatalf("conflict key not overwritten: %+v err=%v", got, err)
	}
}

func TestTsigKeyMgmtPurge_InteractiveSubsetAndOwnerFilter(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf := &Config{}
	tx, err := kdb.Begin("seed-purge-subset")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	for _, row := range []TsigKeystoreRow{
		{Keyname: "a.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "api", Owner: "api", Creator: "test"},
		{Keyname: "b.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "api", Owner: "api", Creator: "test"},
		{Keyname: "cat.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "api", Owner: "catalog", Creator: "test"},
	} {
		if err := insertTsigKeystore(tx, row); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	dry, err := kdb.TsigKeyMgmt(conf, nil, KeystorePost{SubCommand: "purge"})
	if err != nil {
		t.Fatalf("dry: %v", err)
	}
	if len(dry.TsigKeys) != 2 {
		t.Fatalf("expected 2 purge candidates (owner=api only), got %+v", dry.TsigKeys)
	}

	_, err = kdb.TsigKeyMgmt(conf, nil, KeystorePost{
		SubCommand: "purge", TsigOverwrite: []string{"a."},
	})
	if err != nil {
		t.Fatalf("subset purge: %v", err)
	}
	if _, err := getTsigKeystoreByName(kdb, "a."); err == nil {
		t.Fatal("a. should be purged")
	}
	if _, err := getTsigKeystoreByName(kdb, "b."); err != nil {
		t.Fatal("b. should remain")
	}
	if _, err := getTsigKeystoreByName(kdb, "cat."); err != nil {
		t.Fatal("catalog-owner key must remain")
	}
}

func TestCommitStagedTsigKey_WithKeyDB(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Internal.TsigKeyStore = NewTsigKeyStore()

	staged := &TsigDetails{Name: "inline.", Algorithm: "hmac-sha256", Secret: b64Secret16}
	rollback, err := conf.commitStagedTsigKey(staged)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !conf.Internal.TsigKeyStore.Has("inline.") {
		t.Fatal("cache missing inline key")
	}
	row, err := getTsigKeystoreByName(kdb, "inline.")
	if err != nil || row.Origin != "api" {
		t.Fatalf("db row: %+v err=%v", row, err)
	}

	rollback()
	if conf.Internal.TsigKeyStore.Has("inline.") {
		t.Fatal("rollback should remove newly added key")
	}
	if _, err := getTsigKeystoreByName(kdb, "inline."); err == nil {
		t.Fatal("rollback should delete DB row for newly added key")
	}
}

func TestCommitStagedTsigKey_IdempotentWhenUnchanged(t *testing.T) {
	kdb := newTestKeyDB(t)
	conf := &Config{}
	conf.Internal.KeyDB = kdb
	conf.Internal.TsigKeyStore = NewTsigKeyStore()
	conf.Internal.TsigKeyStore.Add(TsigDetails{Name: "exists.", Algorithm: "hmac-sha256", Secret: b64Secret16})

	rollback, err := conf.commitStagedTsigKey(&TsigDetails{
		Name: "exists.", Algorithm: "hmac-sha256", Secret: b64Secret16,
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	rollback() // no-op rollback
	if !conf.Internal.TsigKeyStore.Has("exists.") {
		t.Fatal("idempotent commit must not remove existing key")
	}
}

func TestReconcileConfigTsigKeys_InteractiveOverwrite(t *testing.T) {
	kdb := newTestKeyDB(t)
	tx, err := kdb.Begin("seed-interactive")
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
		t.Fatalf("unexpected reconcile error: %v", err)
	}
	if len(res.Conflicts) != 1 {
		t.Fatalf("expected conflict, got %+v err=%v", res.Conflicts, err)
	}

	_, err = kdb.ReconcileConfigTsigKeys([]TsigDetails{
		{Name: "k.", Algorithm: "hmac-sha256", Secret: b64Secret16},
	}, TsigReconcileOptions{Overwrite: []string{"k."}}, nil)
	if err != nil {
		t.Fatalf("interactive overwrite: %v", err)
	}
	row, err := getTsigKeystoreByName(kdb, "k.")
	if err != nil || row.Origin != "config" || row.Algorithm != "hmac-sha256." {
		t.Fatalf("got %+v err=%v", row, err)
	}
}

func TestGenerateTsigSecret_AllAlgorithms(t *testing.T) {
	want := map[string]int{
		"hmac-sha1": 20, "hmac-sha224": 28, "hmac-sha256": 32,
		"hmac-sha384": 48, "hmac-sha512": 64,
	}
	for algo, n := range want {
		s, err := GenerateTsigSecret(algo)
		if err != nil {
			t.Fatalf("%s: %v", algo, err)
		}
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(raw) != n {
			t.Fatalf("%s: len=%d err=%v", algo, len(raw), err)
		}
	}
}

func TestExtractBindTsigKeys_DuplicateRejected(t *testing.T) {
	data := `key "dup." { algorithm hmac-sha256; secret "` + b64Secret16 + `"; };
key "dup." { algorithm hmac-sha512; secret "` + b64Secret16 + `"; };`
	if _, err := extractBindTsigKeys(data); err == nil {
		t.Fatal("expected duplicate name error")
	}
}

func TestApplyTsigCacheDelta_MixedChangedAndDeleted(t *testing.T) {
	kdb := newTestKeyDB(t)
	store := NewTsigKeyStore()
	tx, err := kdb.Begin("seed-delta")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	for _, row := range []TsigKeystoreRow{
		{Keyname: "keep.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "api", Creator: "test"},
		{Keyname: "drop.", Algorithm: "hmac-sha256", Secret: b64Secret16, Origin: "api", Creator: "test"},
	} {
		if err := insertTsigKeystore(tx, row); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := kdb.LoadTsigKeystoreInto(store); err != nil {
		t.Fatalf("load: %v", err)
	}

	tx2, err := kdb.Begin("mutate")
	if err != nil {
		t.Fatalf("Begin2: %v", err)
	}
	if err := deleteTsigKeystore(tx2, "drop."); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := overwriteTsigKeystore(tx2, TsigKeystoreRow{
		Keyname: "keep.", Algorithm: "hmac-sha512", Secret: b64Secret16,
		Origin: "api", Owner: "api", Creator: "test",
	}); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	if err := tx2.Commit(); err != nil {
		t.Fatalf("Commit2: %v", err)
	}

	delta := &TsigCacheDelta{Deleted: []string{"drop."}, Changed: []string{"keep."}}
	if err := ApplyTsigCacheDelta(store, kdb, delta); err != nil {
		t.Fatalf("ApplyTsigCacheDelta: %v", err)
	}
	if store.Has("drop.") {
		t.Fatal("deleted key still in cache")
	}
	got, ok := store.Get("keep.")
	if !ok || dns.CanonicalName(got.Algorithm) != dns.CanonicalName("hmac-sha512") {
		t.Fatalf("changed key not refreshed: %+v ok=%v", got, ok)
	}
}

func TestCollectValidConfigTsigKeys_PreservesOwner(t *testing.T) {
	out, err := collectValidConfigTsigKeys([]TsigDetails{
		{Name: "k.", Algorithm: "hmac-sha256", Secret: b64Secret16, Owner: "catalog"},
	})
	if err != nil || len(out) != 1 || out[0].Owner != "catalog" {
		t.Fatalf("got %+v err=%v", out, err)
	}
}
