package tdns

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// K-4 code 8 (KEY_VALIDATION_FAILED): the parent's automatic verification of
// a child key can run out of attempts, and that outcome is recorded on the
// truststore row so it is distinguishable from "in progress" -- across a
// restart, for the KeyState inquiry and for the UPDATE-response EDE.

const vfChild = "child.example."

// addChildKey stores a child KEY the way a self-signed upload does
// (source child-update, untrusted, unvalidated) and returns its keyid.
func addVfChildKey(t *testing.T, kdb *KeyDB, trusted bool) (uint16, string) {
	t.Helper()
	keyRR := validChildKeyRR(t)
	rr, _ := dns.NewRR(keyRR)
	keyid := rr.(*dns.KEY).KeyTag()
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "add", Src: "child-update",
		Keyname: vfChild, Keyid: int(keyid), KeyRR: keyRR, Trusted: trusted, Validated: trusted,
	}); err != nil {
		t.Fatalf("truststore add: %v", err)
	}
	return keyid, keyRR
}

func recordFailure(t *testing.T, kdb *KeyDB, keyid uint16, why string) {
	t.Helper()
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "validation-failed",
		Keyname: vfChild, Keyid: int(keyid), ValidationError: why,
	}); err != nil {
		t.Fatalf("validation-failed: %v", err)
	}
}

func lookupChildKey(t *testing.T, kdb *KeyDB, keyid uint16) *Sig0Key {
	t.Helper()
	sk, err := kdb.FindSig0TrustedKey(vfChild, keyid)
	if err != nil {
		t.Fatalf("FindSig0TrustedKey: %v", err)
	}
	return sk
}

func TestValidationFailedPersistsAndReadsBack(t *testing.T) {
	kdb := newTestKeyDB(t)
	keyid, _ := addVfChildKey(t, kdb, false)

	if sk := lookupChildKey(t, kdb, keyid); sk.ValidationFailed {
		t.Fatal("fresh upload must not be marked failed")
	}
	recordFailure(t, kdb, keyid, "5 attempts via [at-apex at-ns]: KEY not found")

	// FindSig0TrustedKey (the UPDATE path's lookup; cache invalidated by the write).
	sk := lookupChildKey(t, kdb, keyid)
	if !sk.ValidationFailed || !strings.Contains(sk.ValidationError, "KEY not found") {
		t.Fatalf("FindSig0TrustedKey: failed=%v err=%q", sk.ValidationFailed, sk.ValidationError)
	}
	if sk.Trusted || sk.Validated {
		t.Fatal("recording a failure must not touch validated/trusted")
	}

	// list (the KeyState path's lookup).
	tr, err := kdb.Sig0TrustMgmt(nil, TruststorePost{Command: "child-sig0-mgmt", SubCommand: "list"})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := tr.ChildSig0keys[fmt.Sprintf("%s::%d", vfChild, keyid)]
	if !ok || !got.ValidationFailed || got.ValidationError == "" {
		t.Fatalf("list: %+v (ok=%v)", got, ok)
	}

	// The runtime cache built at startup carries it too, since
	// FindSig0TrustedKey answers from that cache first.
	kdb.TruststoreSig0Cache.Map.Remove(fmt.Sprintf("%s::%d", vfChild, keyid))
	if err := kdb.LoadSig0ChildKeys(); err != nil {
		t.Fatalf("LoadSig0ChildKeys: %v", err)
	}
	cached, ok := kdb.TruststoreSig0Cache.Map.Get(fmt.Sprintf("%s::%d", vfChild, keyid))
	if !ok || !cached.ValidationFailed || cached.ValidationError == "" {
		t.Fatalf("startup cache: %+v (ok=%v)", cached, ok)
	}
}

func TestValidationFailedClearedByVerifyAndByReupload(t *testing.T) {
	kdb := newTestKeyDB(t)
	keyid, _ := addVfChildKey(t, kdb, false)
	recordFailure(t, kdb, keyid, "gave up")

	// A later successful verification clears it (the key IS verifiable after all).
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "verify", Keyname: vfChild, Keyid: int(keyid), DnssecValidated: true,
	}); err != nil {
		t.Fatal(err)
	}
	if sk := lookupChildKey(t, kdb, keyid); sk.ValidationFailed || sk.ValidationError != "" || !sk.Trusted || !sk.Validated {
		t.Fatalf("after verify: %+v", sk)
	}

	// A re-upload (the child re-bootstrapping) replaces the row and starts over.
	recordFailure(t, kdb, keyid, "gave up again") // no-op: trusted now
	if sk := lookupChildKey(t, kdb, keyid); sk.ValidationFailed {
		t.Fatal("a trusted key must never be marked failed")
	}
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "untrust", Keyname: vfChild, Keyid: int(keyid),
	}); err != nil {
		t.Fatal(err)
	}
	recordFailure(t, kdb, keyid, "gave up again")
	if sk := lookupChildKey(t, kdb, keyid); !sk.ValidationFailed {
		t.Fatal("untrusted key: failure should record")
	}
	addVfChildKey(t, kdb, false) // same key, re-uploaded
	if sk := lookupChildKey(t, kdb, keyid); sk.ValidationFailed || sk.ValidationError != "" {
		t.Fatalf("after re-upload: %+v", sk)
	}
}

// An existing database gains the three columns through dbMigrateSchema.
func TestSig0TrustStoreMigrationAddsValidationColumns(t *testing.T) {
	f := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite3", f)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE Sig0TrustStore (
id INTEGER PRIMARY KEY, zonename TEXT, keyid INTEGER, validated INTEGER DEFAULT 0,
trusted INTEGER DEFAULT 0, dnssecvalidated INTEGER DEFAULT 0, source TEXT, keyrr TEXT, comment TEXT,
UNIQUE (zonename, keyid))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO Sig0TrustStore (zonename, keyid, source, keyrr) VALUES ('old.example.', 1, 'file', 'x')`); err != nil {
		t.Fatal(err)
	}
	dbMigrateSchema(db)
	for _, col := range []string{"validation_failed", "validation_error", "validation_failed_at"} {
		if !dbColumnExists(db, "Sig0TrustStore", col) {
			t.Errorf("column %s missing after migration", col)
		}
	}
	var failed int
	var errText string
	if err := db.QueryRow(`SELECT validation_failed, validation_error FROM Sig0TrustStore WHERE zonename='old.example.'`).Scan(&failed, &errText); err != nil {
		t.Fatal(err)
	}
	if failed != 0 || errText != "" {
		t.Fatalf("pre-existing row: failed=%d err=%q, want 0 and empty", failed, errText)
	}
}

// The retry/exhaustion engine: exhaustion records the failure with the last
// reason; the KeyState inquiry then reports 8 with that reason; a later
// success promotes the key and clears the failure; the inquiry reports 4.
func TestRunChildKeyVerificationRecordsExhaustion(t *testing.T) {
	kdb := newTestKeyDB(t)
	keyid, _ := addVfChildKey(t, kdb, false)
	pol := DelegationPolicy{Name: "t", Mechanisms: []string{"at-apex", "at-ns"}, RequireDnssec: true,
		RetryMaxAttempts: 3, RetryInterval: time.Millisecond}

	calls := 0
	ok := kdb.runChildKeyVerification(context.Background(), vfChild, keyid, pol,
		func(context.Context) (bool, bool, error) {
			calls++
			return false, false, errors.New("KEY found but not DNSSEC-validated, and require-dnssec is set")
		})
	if ok || calls != 3 {
		t.Fatalf("ok=%v calls=%d, want false and 3", ok, calls)
	}
	sk := lookupChildKey(t, kdb, keyid)
	if !sk.ValidationFailed {
		t.Fatal("exhaustion must record a validation failure")
	}
	for _, want := range []string{"3 attempts", "at-apex", "not DNSSEC-validated"} {
		if !strings.Contains(sk.ValidationError, want) {
			t.Errorf("ValidationError %q lacks %q", sk.ValidationError, want)
		}
	}
	ks, err := kdb.GetKeyStatus(vfChild, keyid)
	if err != nil {
		t.Fatal(err)
	}
	if ks.KeyState != edns0.KeyStateValidationFail || !strings.Contains(ks.ExtraText, "3 attempts") || ks.KeyData != 0 {
		t.Fatalf("KeyState after exhaustion: %+v, want 8 with the reason and KEY-DATA 0", ks)
	}

	// The operator republishes the key; the next verification succeeds.
	calls = 0
	ok = kdb.runChildKeyVerification(context.Background(), vfChild, keyid, pol,
		func(context.Context) (bool, bool, error) {
			calls++
			if calls == 1 {
				return false, false, errors.New("still not there")
			}
			return true, true, nil
		})
	if !ok || calls != 2 {
		t.Fatalf("ok=%v calls=%d, want true and 2", ok, calls)
	}
	sk = lookupChildKey(t, kdb, keyid)
	if sk.ValidationFailed || sk.ValidationError != "" || !sk.Trusted || !sk.Validated || !sk.DnssecValidated {
		t.Fatalf("after success: %+v", sk)
	}
	if ks, _ := kdb.GetKeyStatus(vfChild, keyid); ks.KeyState != edns0.KeyStateTrusted {
		t.Fatalf("KeyState after success = %d, want 4", ks.KeyState)
	}
}

// A cancel that lands INSIDE the last attempt is a shutdown too, not an
// exhaustion: nothing is recorded (review T2).
func TestRunChildKeyVerificationCancelledOnLastAttemptRecordsNothing(t *testing.T) {
	kdb := newTestKeyDB(t)
	keyid, _ := addVfChildKey(t, kdb, false)
	pol := DelegationPolicy{Name: "t", Mechanisms: []string{"at-apex"}, RetryMaxAttempts: 2, RetryInterval: time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	ok := kdb.runChildKeyVerification(ctx, vfChild, keyid, pol,
		func(context.Context) (bool, bool, error) {
			calls++
			if calls == pol.RetryMaxAttempts {
				cancel() // shutdown arrives during the final lookup
				return false, false, context.Canceled
			}
			return false, false, errors.New("not yet")
		})
	if ok || calls != 2 {
		t.Fatalf("ok=%v calls=%d, want false and 2", ok, calls)
	}
	if sk := lookupChildKey(t, kdb, keyid); sk.ValidationFailed {
		t.Fatalf("a cancel during the last attempt must not record a failure: %+v", sk)
	}
	if ks, _ := kdb.GetKeyStatus(vfChild, keyid); ks.KeyState != edns0.KeyStateBootstrapAutoOngoing {
		t.Fatalf("KeyState after cancel = %d, want 9", ks.KeyState)
	}
}

// An operator's trust decision clears a recorded failure (review T3): the row
// must not say trusted AND failed.
func TestTrustClearsValidationFailure(t *testing.T) {
	kdb := newTestKeyDB(t)
	keyid, _ := addVfChildKey(t, kdb, false)
	recordFailure(t, kdb, keyid, "gave up")
	if sk := lookupChildKey(t, kdb, keyid); !sk.ValidationFailed {
		t.Fatal("precondition: failure recorded")
	}
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "trust", Keyname: vfChild, Keyid: int(keyid),
	}); err != nil {
		t.Fatal(err)
	}
	sk := lookupChildKey(t, kdb, keyid)
	if !sk.Trusted || sk.ValidationFailed || sk.ValidationError != "" {
		t.Fatalf("after trust: %+v, want trusted with the failure cleared", sk)
	}
	// untrust leaves the (now clear) failure columns alone
	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "untrust", Keyname: vfChild, Keyid: int(keyid),
	}); err != nil {
		t.Fatal(err)
	}
	if sk := lookupChildKey(t, kdb, keyid); sk.Trusted || sk.ValidationFailed {
		t.Fatalf("after untrust: %+v", sk)
	}
}

// A shutdown mid-way is not a verdict: nothing is recorded and the row stays
// "in progress" (9) for a re-upload to restart.
func TestRunChildKeyVerificationCancelledRecordsNothing(t *testing.T) {
	kdb := newTestKeyDB(t)
	keyid, _ := addVfChildKey(t, kdb, false)
	pol := DelegationPolicy{Name: "t", Mechanisms: []string{"at-apex"}, RetryMaxAttempts: 5, RetryInterval: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	ok := kdb.runChildKeyVerification(ctx, vfChild, keyid, pol,
		func(context.Context) (bool, bool, error) {
			cancel() // shutdown arrives during the backoff that follows
			return false, false, errors.New("not yet")
		})
	if ok {
		t.Fatal("cancelled verification must not report success")
	}
	if sk := lookupChildKey(t, kdb, keyid); sk.ValidationFailed {
		t.Fatal("a cancelled verification must not record a failure")
	}
	if ks, _ := kdb.GetKeyStatus(vfChild, keyid); ks.KeyState != edns0.KeyStateBootstrapAutoOngoing {
		t.Fatalf("KeyState after cancel = %d, want 9", ks.KeyState)
	}
}
