/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// tombstoneParent is a parent that takes unvalidated uploads, so that the only
// thing standing between a retired key and the truststore is the tombstone.
func tombstoneParent(t *testing.T) (*ZoneData, *KeyDB) {
	t.Helper()
	kdb := newTestKeyDB(t)
	zd := cuParentZone(t)
	zd.KeyDB = kdb
	registerZones(t, zd)
	pol := compiledDefaultDelegationPolicy()
	pol.AllowUnvalidatedUpload = true
	zd.DelegationPolicy = &pol
	return zd, kdb
}

// retireChildKey stores key trusted, as a completed bootstrap leaves it, and
// then deletes it the way the end of a roll does: a class-NONE KEY in a
// trusted UPDATE, through the updater.
func retireChildKey(t *testing.T, zd *ZoneData, kdb *KeyDB, key *dns.KEY) {
	t.Helper()
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "add", Src: "child-update",
		Keyname: key.Hdr.Name, Keyid: int(key.KeyTag()), KeyRR: key.String(),
		Validated: true, Trusted: true,
	}); err != nil {
		t.Fatalf("storing the child's key: %v", err)
	}
	del := dns.Copy(key)
	del.Header().Class = dns.ClassNONE
	del.Header().Ttl = 0
	res := runTruststoreUpdate(t, kdb, UpdateRequest{
		Cmd:       "TRUSTSTORE-UPDATE",
		ZoneName:  zd.ZoneName,
		Actions:   []dns.RR{del},
		Validated: true,
		Trusted:   true,
	})
	if !res.Applied || res.Err != nil {
		t.Fatalf("the child's trusted delete was not applied: applied=%v err=%v", res.Applied, res.Err)
	}
	if _, ok := trustStoreEntry(t, kdb, key.Hdr.Name, key.KeyTag()); ok {
		t.Fatal("the deleted key is still in the truststore")
	}
}

// selfSignedUploadFrom is the plain bootstrap: one ADD KEY, signed (as far as
// stubSig0Verify is concerned) by the key it carries.
func selfSignedUploadFrom(t *testing.T, zone string, key *dns.KEY) *dns.Msg {
	t.Helper()
	m := ceremonyUpdateFrom(t, zone, key)
	m.Ns = []dns.RR{dns.Copy(key)}
	return m
}

// uploadVerdict runs an upload through the parent's own validation and
// approval, and returns whether it was approved and the EDE it was refused
// with.
func uploadVerdict(t *testing.T, zd *ZoneData, r *dns.Msg) (bool, uint16) {
	t.Helper()
	us := &UpdateStatus{Type: "TRUSTSTORE-UPDATE"}
	if err := zd.ValidateUpdate(context.Background(), r, us); err != nil {
		t.Fatalf("ValidateUpdate: %v", err)
	}
	if err := zd.TrustUpdate(r, us); err != nil {
		t.Fatalf("TrustUpdate: %v", err)
	}
	if us.SignatureType != "self-signed" {
		t.Fatalf("SignatureType %q, want self-signed: the upload did not take the bootstrap path", us.SignatureType)
	}
	approved, _, err := zd.ApproveTrustUpdate(zd.ZoneName, us, r)
	if err != nil {
		t.Fatalf("ApproveTrustUpdate: %v", err)
	}
	return approved, us.RejectionEDE
}

// sameTagOtherKey is a different public key with key's tag. The tag is a
// checksum that adds even-offset bytes high and odd-offset bytes low, so
// swapping two bytes two apart keeps it.
func sameTagOtherKey(t *testing.T, key *dns.KEY) *dns.KEY {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil {
		t.Fatalf("decoding the public key: %v", err)
	}
	for i := 0; i+2 < len(raw); i++ {
		if raw[i] != raw[i+2] {
			raw[i], raw[i+2] = raw[i+2], raw[i]
			other := dns.Copy(key).(*dns.KEY)
			other.PublicKey = base64.StdEncoding.EncodeToString(raw)
			if other.KeyTag() != key.KeyTag() {
				t.Fatalf("tag changed: %d, want %d", other.KeyTag(), key.KeyTag())
			}
			return other
		}
	}
	t.Fatal("no two bytes to swap")
	return nil
}

// THE DEFECT. The child's roll deleted its old key with a trusted UPDATE, and
// whoever still held the old private half -- the provider that left -- could
// bootstrap it straight back with a self-signed upload: the parent had no
// memory that the key was ever there.
func TestABootstrapOfAKeyTheChildDeletedIsRefused(t *testing.T) {
	zd, kdb := tombstoneParent(t)
	stubSig0Verify(t)
	stubDnsDiscovery(t, nil) // the parent finds nothing in DNS; the upload is all it has
	old := discoveredTestKey(t).Key
	clearChildKeyCooldown(t, old.Hdr.Name, old.KeyTag())
	retireChildKey(t, zd, kdb, &old)

	for _, tc := range []struct {
		name string
		r    *dns.Msg
	}{
		{"the bootstrap ceremony", ceremonyUpdateFrom(t, zd.ZoneName, &old)},
		{"a plain self-signed upload", selfSignedUploadFrom(t, zd.ZoneName, &old)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			approved, ede := uploadVerdict(t, zd, tc.r)
			if approved {
				t.Fatal("the deleted key was bootstrapped back by whoever holds its private half")
			}
			if ede != edns0.EDESig0KeyRetired {
				t.Errorf("EDE %d, want %d (key retired)", ede, edns0.EDESig0KeyRetired)
			}
		})
	}

	// And the apply stage, should an upload ever get that far.
	res := runTruststoreUpdate(t, kdb, UpdateRequest{
		Cmd:       "TRUSTSTORE-UPDATE",
		ZoneName:  zd.ZoneName,
		Actions:   []dns.RR{dns.Copy(&old)},
		Validated: true,
	})
	if res.Applied {
		t.Error("the updater stored the deleted key")
	}
	if _, ok := trustStoreEntry(t, kdb, old.Hdr.Name, old.KeyTag()); ok {
		t.Error("the deleted key is back in the truststore")
	}
}

// Every way into the truststore refuses the retired key, whatever source it
// claims and however its name is spelled.
func TestEveryAddOfAKeyTheChildDeletedIsRefused(t *testing.T) {
	zd, kdb := tombstoneParent(t)
	old := discoveredTestKey(t).Key
	retireChildKey(t, zd, kdb, &old)

	upper := dns.Copy(&old).(*dns.KEY)
	upper.Hdr.Name = strings.ToUpper(old.Hdr.Name)
	for _, src := range []string{"child-update", "dns", "file", "keystore"} {
		for _, key := range []*dns.KEY{&old, upper} {
			_, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
				Command: "child-sig0-mgmt", SubCommand: "add", Src: src,
				Keyname: key.Hdr.Name, Keyid: int(key.KeyTag()), KeyRR: key.String(), Validated: true,
			})
			if !errors.Is(err, ErrSig0KeyTombstoned) {
				t.Errorf("src=%s name=%s: err=%v, want ErrSig0KeyTombstoned", src, key.Hdr.Name, err)
			}
		}
	}
	if _, ok := trustStoreEntry(t, kdb, old.Hdr.Name, old.KeyTag()); ok {
		t.Error("the deleted key is back in the truststore")
	}
}

// The leaver need not upload anything: an UPDATE signed with the old key,
// while that KEY is still published at the child's apex, used to have the
// parent record the key it found in DNS and start verifying it.
func TestADeletedKeyFoundInDnsIsNotRecorded(t *testing.T) {
	zd, kdb := tombstoneParent(t)
	ctx, waitForVerifier := boundedVerification(t, zd)
	discovered := discoveredTestKey(t)
	retireChildKey(t, zd, kdb, &discovered.Key)
	stubDnsDiscovery(t, discovered)
	stubSig0Verify(t)

	us := &UpdateStatus{}
	if err := zd.ValidateUpdate(ctx, signedUpdateFrom(t, zd.ZoneName, discovered.Name, discovered.Keyid), us); err != nil {
		t.Fatalf("ValidateUpdate: %v", err)
	}
	for _, done := range us.verifications {
		waitForVerifier(done)
		t.Error("a verification was started for a key its child deleted")
	}
	if _, ok := trustStoreEntry(t, kdb, discovered.Name, discovered.Keyid); ok {
		t.Error("the deleted key, found in DNS, was recorded again")
	}
}

// The tombstone is for that one key. A new key bootstraps as before, and so
// does a different key that happens to share the retired key's tag.
func TestANewKeyStillBootstrapsAfterAnotherWasDeleted(t *testing.T) {
	zd, kdb := tombstoneParent(t)
	stubSig0Verify(t)
	stubDnsDiscovery(t, nil)
	old := discoveredTestKey(t).Key
	retireChildKey(t, zd, kdb, &old)

	for _, tc := range []struct {
		name string
		key  *dns.KEY
	}{
		{"a new key", truststoreTestKEY(t, old.Hdr.Name)},
		{"a new key with the retired key's tag", sameTagOtherKey(t, &old)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearChildKeyCooldown(t, tc.key.Hdr.Name, tc.key.KeyTag())
			approved, ede := uploadVerdict(t, zd, ceremonyUpdateFrom(t, zd.ZoneName, tc.key))
			if !approved {
				t.Fatalf("a key the child never deleted was refused (EDE %d)", ede)
			}
			if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
				Command: "child-sig0-mgmt", SubCommand: "add", Src: "child-update",
				Keyname: tc.key.Hdr.Name, Keyid: int(tc.key.KeyTag()), KeyRR: tc.key.String(), Validated: true,
			}); err != nil {
				t.Fatalf("storing it: %v", err)
			}
		})
	}
}

// The operator's way out: "truststore sig0 tombstone list" shows the retired
// key, "clear" removes the tombstone, and the key can then bootstrap again.
func TestAnOperatorCanClearATombstone(t *testing.T) {
	zd, kdb := tombstoneParent(t)
	stubSig0Verify(t)
	stubDnsDiscovery(t, nil)
	old := discoveredTestKey(t).Key
	clearChildKeyCooldown(t, old.Hdr.Name, old.KeyTag())
	before := time.Now().UTC().Add(-time.Second)
	retireChildKey(t, zd, kdb, &old)

	list := func() []Sig0Tombstone {
		t.Helper()
		resp, err := kdb.Sig0TrustMgmt(nil, TruststorePost{Command: "child-sig0-mgmt", SubCommand: "tombstone-list"})
		if err != nil || resp.Error {
			t.Fatalf("tombstone-list: %v %s", err, resp.ErrorMsg)
		}
		return resp.Sig0Tombstones
	}
	ts := list()
	if len(ts) != 1 {
		t.Fatalf("%d tombstones, want 1: %+v", len(ts), ts)
	}
	if ts[0].Name != old.Hdr.Name || ts[0].Keyid != old.KeyTag() || ts[0].Algorithm != old.Algorithm || ts[0].Source != "child-update" {
		t.Errorf("tombstone %+v does not describe the deleted key", ts[0])
	}
	if at, err := time.Parse(time.RFC3339, ts[0].DeletedAt); err != nil || at.Before(before) {
		t.Errorf("deleted_at %q: %v", ts[0].DeletedAt, err)
	}

	clear := func(keyid uint16) *TruststoreResponse {
		t.Helper()
		resp, _ := kdb.Sig0TrustMgmt(nil, TruststorePost{
			Command: "child-sig0-mgmt", SubCommand: "tombstone-clear", Keyname: old.Hdr.Name, Keyid: int(keyid),
		})
		return resp
	}
	if resp := clear(old.KeyTag() + 1); !resp.Error {
		t.Errorf("clearing a tombstone that does not exist reported success: %s", resp.Msg)
	}
	if len(list()) != 1 {
		t.Fatal("clearing another keyid removed this key's tombstone")
	}
	if resp := clear(old.KeyTag()); resp.Error {
		t.Fatalf("tombstone-clear: %s", resp.ErrorMsg)
	}
	if ts := list(); len(ts) != 0 {
		t.Fatalf("tombstone still listed after clear: %+v", ts)
	}

	if approved, ede := uploadVerdict(t, zd, ceremonyUpdateFrom(t, zd.ZoneName, &old)); !approved {
		t.Fatalf("the key was refused after its tombstone was cleared (EDE %d)", ede)
	}
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "add", Src: "child-update",
		Keyname: old.Hdr.Name, Keyid: int(old.KeyTag()), KeyRR: old.String(), Validated: true,
	}); err != nil {
		t.Fatalf("the key could not be stored after its tombstone was cleared: %v", err)
	}
}

// Only the child's own trusted UPDATE retires a key. An operator's delete
// removes the row as it always did and leaves the key free to come back.
func TestAnOperatorDeleteLeavesNoTombstone(t *testing.T) {
	_, kdb := tombstoneParent(t)
	key := discoveredTestKey(t).Key
	post := TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "add", Src: "file",
		Keyname: key.Hdr.Name, Keyid: int(key.KeyTag()), KeyRR: key.String(),
	}
	if _, err := kdb.Sig0TrustMgmt(nil, post); err != nil {
		t.Fatalf("add: %v", err)
	}
	if resp, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "delete", Keyname: key.Hdr.Name, Keyid: int(key.KeyTag()),
	}); err != nil || resp.Error {
		t.Fatalf("delete: %v %s", err, resp.ErrorMsg)
	}
	if resp, _ := kdb.Sig0TrustMgmt(nil, TruststorePost{Command: "child-sig0-mgmt", SubCommand: "tombstone-list"}); len(resp.Sig0Tombstones) != 0 {
		t.Errorf("an operator's delete left a tombstone: %+v", resp.Sig0Tombstones)
	}
	if _, err := kdb.Sig0TrustMgmt(nil, post); err != nil {
		t.Errorf("the key could not be added again after an operator's delete: %v", err)
	}
}

// The row is found by tag alone. A trusted delete that names a different key
// under the same tag must not remove -- and tombstone -- the key that is
// stored, which the child may still be using.
func TestATrustedDeleteOfADifferentKeyUnderTheSameTagIsRefused(t *testing.T) {
	zd, kdb := tombstoneParent(t)
	named := discoveredTestKey(t).Key
	stored := sameTagOtherKey(t, &named)
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "add", Src: "child-update",
		Keyname: stored.Hdr.Name, Keyid: int(stored.KeyTag()), KeyRR: stored.String(),
		Validated: true, Trusted: true,
	}); err != nil {
		t.Fatalf("storing the child's key: %v", err)
	}
	del := dns.Copy(&named)
	del.Header().Class = dns.ClassNONE
	del.Header().Ttl = 0
	res := runTruststoreUpdate(t, kdb, UpdateRequest{
		Cmd: "TRUSTSTORE-UPDATE", ZoneName: zd.ZoneName, Actions: []dns.RR{del},
		Validated: true, Trusted: true,
	})
	if res.Applied {
		t.Error("a delete of one key was applied to another key with the same tag")
	}
	sk, ok := trustStoreEntry(t, kdb, stored.Hdr.Name, stored.KeyTag())
	if !ok || sk.Keystr != stored.String() {
		t.Error("the stored key was deleted by a delete that named a different key")
	}
	if resp, _ := kdb.Sig0TrustMgmt(nil, TruststorePost{Command: "child-sig0-mgmt", SubCommand: "tombstone-list"}); len(resp.Sig0Tombstones) != 0 {
		t.Errorf("a tombstone was written for a key the child did not delete: %+v", resp.Sig0Tombstones)
	}
}

// Through the management API a delete is an operator's, whatever Src the
// client sends, and leaves no tombstone.
func TestAnAPIDeleteLeavesNoTombstoneWhateverItsSrc(t *testing.T) {
	_, kdb := tombstoneParent(t)
	key := discoveredTestKey(t).Key
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "add", Src: "child-update",
		Keyname: key.Hdr.Name, Keyid: int(key.KeyTag()), KeyRR: key.String(), Validated: true, Trusted: true,
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	body, _ := json.Marshal(TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "delete", Src: "child-update",
		Keyname: key.Hdr.Name, Keyid: int(key.KeyTag()),
	})
	w := httptest.NewRecorder()
	kdb.APItruststore()(w, httptest.NewRequest("POST", "/truststore", bytes.NewReader(body)))
	var resp TruststoreResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.Error {
		t.Fatalf("API delete: %v %s", err, resp.ErrorMsg)
	}
	if _, ok := trustStoreEntry(t, kdb, key.Hdr.Name, key.KeyTag()); ok {
		t.Fatal("the API delete did not delete")
	}
	if r, _ := kdb.Sig0TrustMgmt(nil, TruststorePost{Command: "child-sig0-mgmt", SubCommand: "tombstone-list"}); len(r.Sig0Tombstones) != 0 {
		t.Errorf("an API delete claiming src=child-update wrote a tombstone: %+v", r.Sig0Tombstones)
	}
}

// Keyid 0 is a key tag like any other; its tombstone can be cleared.
func TestATombstoneWithKeyidZeroCanBeCleared(t *testing.T) {
	_, kdb := tombstoneParent(t)
	if _, err := kdb.Exec(`INSERT INTO Sig0TrustStoreTombstone (zonename, keyid, algorithm, publickey, keyrr, deleted_at, source)
VALUES ('child.example.', 0, 15, 'AAAA', 'child.example. 3600 IN KEY 256 3 15 AAAA', '2026-11-05T00:00:00Z', 'child-update')`); err != nil {
		t.Fatalf("inserting the tombstone: %v", err)
	}
	resp, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "tombstone-clear", Keyname: "child.example.", Keyid: 0,
	})
	if err != nil || resp.Error {
		t.Fatalf("clearing keyid 0 refused: %v %s", err, resp.ErrorMsg)
	}
}

// The tombstone and the delete land together or not at all.
func TestAFailedChildDeleteLeavesNoTombstone(t *testing.T) {
	zd, kdb := tombstoneParent(t)
	key := discoveredTestKey(t).Key
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "add", Src: "child-update",
		Keyname: key.Hdr.Name, Keyid: int(key.KeyTag()), KeyRR: key.String(), Validated: true, Trusted: true,
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := kdb.Exec(`CREATE TRIGGER fail_delete BEFORE DELETE ON Sig0TrustStore BEGIN SELECT RAISE(ABORT, 'delete refused by test'); END`); err != nil {
		t.Fatalf("creating the trigger: %v", err)
	}
	del := dns.Copy(&key)
	del.Header().Class = dns.ClassNONE
	del.Header().Ttl = 0
	res := runTruststoreUpdate(t, kdb, UpdateRequest{
		Cmd: "TRUSTSTORE-UPDATE", ZoneName: zd.ZoneName, Actions: []dns.RR{del},
		Validated: true, Trusted: true,
	})
	if res.Applied {
		t.Error("a delete that failed was reported as applied")
	}
	if _, ok := trustStoreEntry(t, kdb, key.Hdr.Name, key.KeyTag()); !ok {
		t.Error("the key's row is gone although its delete failed")
	}
	if r, _ := kdb.Sig0TrustMgmt(nil, TruststorePost{Command: "child-sig0-mgmt", SubCommand: "tombstone-list"}); len(r.Sig0Tombstones) != 0 {
		t.Errorf("a tombstone outlived the delete that failed: %+v", r.Sig0Tombstones)
	}
}

// THE RACE. The keystore runs in WAL mode, so while a child's delete is still
// uncommitted, a cache miss on another connection reads the row as it was --
// trusted -- and cached it. Nothing dropped that entry after the commit, and
// the retired key went on verifying UPDATEs from the cache.
func TestACacheFillDuringAChildsDeleteDoesNotOutliveTheCommit(t *testing.T) {
	f := filepath.Join(t.TempDir(), "keys.db")
	if err := os.WriteFile(f, nil, 0664); err != nil {
		t.Fatal(err)
	}
	kdb, err := NewKeyDB(f, false, nil)
	if err != nil {
		t.Fatalf("NewKeyDB: %v", err)
	}
	t.Cleanup(func() { kdb.Close() })
	key := discoveredTestKey(t).Key
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "add", Src: "child-update",
		Keyname: key.Hdr.Name, Keyid: int(key.KeyTag()), KeyRR: key.String(), Validated: true, Trusted: true,
	}); err != nil {
		t.Fatalf("add: %v", err)
	}

	tx, err := kdb.Begin("test child delete")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	del := dns.Copy(&key)
	del.Header().Class = dns.ClassNONE
	if resp, err := kdb.Sig0TrustMgmt(tx, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "delete", Src: "child-update",
		Keyname: key.Hdr.Name, Keyid: int(key.KeyTag()), KeyRR: del.String(),
	}); err != nil || resp.Error {
		tx.Rollback()
		t.Fatalf("delete: %v %s", err, resp.ErrorMsg)
	}
	// A validation elsewhere, before the commit: it sees the committed row.
	if sk, err := kdb.FindSig0TrustedKey(key.Hdr.Name, key.KeyTag()); err != nil || !sk.Trusted {
		tx.Rollback()
		t.Fatalf("the read before the commit did not see the committed row (err=%v); the test does not reach the race", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if sk, err := kdb.FindSig0TrustedKey(key.Hdr.Name, key.KeyTag()); err == nil {
		t.Fatalf("the deleted key is still found after the commit (trusted=%v): a cache fill made before the commit survived it", sk.Trusted)
	}
}

// A fill whose read began before a change committed must not store what it
// read, even when it gets to the cache after the change has dropped the entry.
func TestACacheFillStartedBeforeACommitIsNotStored(t *testing.T) {
	s := NewSig0StoreT()
	gen := s.generation()
	s.invalidate("child.example.::1")
	s.fillIfCurrent(gen, "child.example.::1", Sig0Key{Name: "child.example.", Trusted: true})
	if _, ok := s.Map.Get("child.example.::1"); ok {
		t.Error("a fill read before the change committed was cached after it")
	}
	s.fillIfCurrent(s.generation(), "child.example.::1", Sig0Key{Name: "child.example."})
	if _, ok := s.Map.Get("child.example.::1"); !ok {
		t.Error("a fill with no change since its read was not cached")
	}
}

// OnCommit work runs after a commit and never after a rollback.
func TestOnCommitRunsOnlyAfterACommit(t *testing.T) {
	kdb := newTestKeyDB(t)
	ran := 0
	tx, err := kdb.Begin("rollback")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	tx.OnCommit(func() { ran++ })
	tx.Rollback()
	if ran != 0 {
		t.Fatal("OnCommit work ran after a rollback")
	}
	tx, err = kdb.Begin("commit")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	tx.OnCommit(func() { ran++ })
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if ran != 1 {
		t.Errorf("OnCommit work ran %d times after a commit, want 1", ran)
	}
}
