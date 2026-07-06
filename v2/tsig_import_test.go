package tdns

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

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

func TestExtractBindTsigKeys_IgnoresComments(t *testing.T) {
	data := `
/* key "ghost." { algorithm hmac-sha512; secret "` + b64Secret16 + `"; }; */
# key "hash." { algorithm hmac-sha512; secret "` + b64Secret16 + `"; };
key "live." {
    # algorithm hmac-sha1;
    algorithm hmac-sha256;
    secret "` + b64Secret16 + `";
};
`
	keys, err := extractBindTsigKeys(data)
	if err != nil || len(keys) != 1 {
		t.Fatalf("extract: %+v err=%v", keys, err)
	}
	if keys[0].Name != "live." || keys[0].Algorithm != "hmac-sha256" {
		t.Fatalf("got %+v", keys[0])
	}
}

func TestExtractNsdTsigKeys_IgnoresComments(t *testing.T) {
	data := `
key:
    name: live.
    # algorithm: hmac-sha512
    algorithm: hmac-sha256
    secret: "` + b64Secret16 + `"
# name: ghost.
`
	keys, err := extractNsdTsigKeys(data)
	if err != nil || len(keys) != 1 {
		t.Fatalf("extract: %+v err=%v", keys, err)
	}
	if keys[0].Name != "live." || keys[0].Algorithm != "hmac-sha256" {
		t.Fatalf("got %+v", keys[0])
	}
}

func TestExtractBindTsigKeys_ReservedNameRejected(t *testing.T) {
	data := `key "NOKEY." { algorithm hmac-sha256; secret "` + b64Secret16 + `"; };`
	if _, err := extractBindTsigKeys(data); err == nil {
		t.Fatal("expected reserved name error")
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

// TestExtractBindTsigKeys_SlashInSecret pins the quote-awareness of the comment
// stripper: a std-base64 secret can contain "//", which must not be truncated as a
// line comment, while a genuinely "//"-commented-out key is still ignored.
func TestExtractBindTsigKeys_SlashInSecret(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 16))
	if !strings.Contains(secret, "//") {
		t.Fatalf("fixture secret %q lacks the // it is meant to exercise", secret)
	}
	data := `
// key "commented." { algorithm hmac-sha256; secret "` + secret + `"; };
key "live." {
    algorithm hmac-sha256;
    secret "` + secret + `";
};
`
	keys, err := extractBindTsigKeys(data)
	if err != nil || len(keys) != 1 {
		t.Fatalf("extract: %+v err=%v", keys, err)
	}
	if keys[0].Name != "live." {
		t.Fatalf("expected only the live key, got %+v", keys)
	}
	if keys[0].Secret != secret {
		t.Fatalf("secret truncated by comment stripper: got %q want %q", keys[0].Secret, secret)
	}
}
