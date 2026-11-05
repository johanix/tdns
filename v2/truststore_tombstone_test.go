/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"encoding/base64"
	"errors"
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
