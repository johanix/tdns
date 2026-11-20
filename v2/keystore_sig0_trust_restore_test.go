/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Single-key import: a JWK with a "keys":null member is a key, not a Set,
 * and an identical SIG(0) re-import restores a TrustStore row that was
 * deleted.
 */

package tdns

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// "keys" is an unknown member of a single-key JWK (RFC 7517 says to ignore
// it) unless it is an array: only an array makes the file a JWK Set. A null
// used to count as one, because it unmarshals into a nil slice without error.
func TestJWKWithAKeysMemberIsASetOnlyWhenItIsAnArray(t *testing.T) {
	k := storedJWKTestKey(t, dns.TypeDNSKEY, dns.ED25519, 256)
	j, err := JWKForExport(dns.TypeDNSKEY, k.keyRR, k.privPEM)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(j), &m); err != nil {
		t.Fatal(err)
	}
	with := func(v any) string {
		m["keys"] = v
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for name, v := range map[string]any{"null": nil, "a string": "x", "an object": map[string]any{}} {
		if _, err := ImportJWK(dns.TypeDNSKEY, with(v), ""); err != nil {
			t.Errorf(`"keys" as %s: a single-key JWK was refused: %v`, name, err)
		}
	}
	for name, v := range map[string]any{"an empty array": []any{}, "an array": []any{"x"}} {
		if _, err := ImportJWK(dns.TypeDNSKEY, with(v), ""); !errors.Is(err, ErrJWKSet) {
			t.Errorf(`"keys" as %s: err = %v, want ErrJWKSet`, name, err)
		}
	}
}

// An identical re-import writes nothing to the SIG(0) keystore, but the
// TrustStore delete command removes only the public copy, and the add this
// replaced put it back. A missing row is restored; an existing row is left
// as it is (it may carry a trust decision); a key its child retired stays
// refused. The private row and its state are never touched.
func TestSig0ReimportRestoresAMissingTrustStoreRow(t *testing.T) {
	a := storedJWKTestKey(t, dns.TypeKEY, dns.ED25519, 256)
	zone, keyid := a.rr.Hdr.Name, a.rr.KeyTag()
	jwk, err := JWKForExport(dns.TypeKEY, a.keyRR, a.privPEM)
	if err != nil {
		t.Fatal(err)
	}
	kdb := newTestKeyDB(t)
	add := func() (*KeystoreResponse, error) {
		return kdb.Sig0KeyMgmt(nil, KeystorePost{SubCommand: "add", Zone: zone, JWK: jwk, State: Sig0StateCreated})
	}
	trustRow := func() (found, trusted bool) {
		var n int
		if err := kdb.DB.QueryRow(`SELECT COUNT(*), COALESCE(MAX(trusted), 0) FROM Sig0TrustStore WHERE zonename=? AND keyid=?`,
			zone, int(keyid)).Scan(&n, &trusted); err != nil {
			t.Fatal(err)
		}
		return n == 1, trusted
	}
	dropTrustRow := func() {
		if _, err := kdb.DB.Exec(`DELETE FROM Sig0TrustStore WHERE zonename=? AND keyid=?`, zone, int(keyid)); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := add(); err != nil {
		t.Fatalf("new key: %v", err)
	}
	if found, trusted := trustRow(); !found || !trusted {
		t.Fatalf("a new key must land in the TrustStore, trusted: found=%v trusted=%v", found, trusted)
	}
	setStoredState(t, kdb, "Sig0KeyStore", keyid, Sig0StateActive)
	before := readKeyStoreRow(t, kdb, "Sig0KeyStore", zone, keyid)

	// The operator deleted the public copy; the identical re-import restores it.
	dropTrustRow()
	resp, err := add()
	if err != nil || !strings.Contains(resp.Msg, "Unchanged") || !strings.Contains(resp.Msg, "Restored the public key in the TrustStore") {
		t.Fatalf("identical re-import after a TrustStore delete: %v %+v", err, resp)
	}
	if found, trusted := trustRow(); !found || !trusted {
		t.Errorf("TrustStore row not restored: found=%v trusted=%v", found, trusted)
	}
	if after := readKeyStoreRow(t, kdb, "Sig0KeyStore", zone, keyid); after != before {
		t.Errorf("the private row changed: before %+v, after %+v", before, after)
	}

	// A row that is there stays as it is, a trust decision included.
	if _, err := kdb.DB.Exec(`UPDATE Sig0TrustStore SET trusted=0 WHERE zonename=? AND keyid=?`, zone, int(keyid)); err != nil {
		t.Fatal(err)
	}
	resp, err = add()
	if err != nil || strings.Contains(resp.Msg, "Restored") {
		t.Fatalf("identical re-import with the row present: %v %+v", err, resp)
	}
	if found, trusted := trustRow(); !found || trusted {
		t.Errorf("an existing TrustStore row was rewritten: found=%v trusted=%v", found, trusted)
	}

	// A key its child retired is still refused, and nothing is restored.
	dropTrustRow()
	tx, err := kdb.Begin("test tombstone")
	if err != nil {
		t.Fatal(err)
	}
	if err := tombstoneSig0Key(tx, zone, &dns.KEY{DNSKEY: *a.rr}, "test"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := add(); !errors.Is(err, ErrSig0KeyTombstoned) {
		t.Fatalf("re-import of a tombstoned key: err = %v, want ErrSig0KeyTombstoned", err)
	}
	if found, _ := trustRow(); found {
		t.Error("a tombstoned key was restored to the TrustStore")
	}
	if after := readKeyStoreRow(t, kdb, "Sig0KeyStore", zone, keyid); after != before {
		t.Errorf("the private row changed on a refused re-import: before %+v, after %+v", before, after)
	}
}
