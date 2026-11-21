/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"strings"
	"testing"
	"time"
)

// revalidateNow runs "truststore sig0 revalidate" for vfChild's key keyid on
// a fresh transaction, as the API handler does.
func revalidateNow(t *testing.T, kdb *KeyDB, keyid uint16, trigger childKeyVerificationTrigger, wait time.Duration) (*TruststoreResponse, error) {
	t.Helper()
	tx, err := kdb.Begin("revalidate test")
	if err != nil {
		t.Fatal(err)
	}
	return kdb.revalidateChildKey(tx, vfChild, keyid, trigger, wait)
}

// A failed key is verified again at once, its failure cleared before the
// verification starts; the outcome is reported when it comes quickly (#1172).
func TestRevalidateAFailedKey(t *testing.T) {
	kdb := newTestKeyDB(t)
	keyid, keyRR := addVfChildKey(t, kdb, false)
	recordFailure(t, kdb, keyid, "at-ns: no KEY at the signal name")
	clearChildKeyCooldown(t, vfChild, keyid)
	noteChildKeyVerificationEnded(vfChild, keyid, time.Now) // the re-bootstrap cooldown does not apply

	var gotRR string
	trigger := func(child string, kid uint16, rr string) <-chan struct{} {
		gotRR = rr
		if sk := lookupChildKey(t, kdb, kid); sk.ValidationFailed {
			t.Error("the verification started with the old failure still recorded")
		}
		// What a verification that accepts the key writes.
		if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
			Command: "child-sig0-mgmt", SubCommand: "verify", Keyname: child, Keyid: int(kid), DnssecValidated: true,
		}); err != nil {
			t.Error(err)
		}
		done := make(chan struct{})
		close(done)
		return done
	}
	resp, err := revalidateNow(t, kdb, keyid, trigger, time.Second)
	if err != nil || resp.Error {
		t.Fatalf("revalidate: %v / %+v", err, resp)
	}
	if gotRR != keyRR {
		t.Errorf("verified %q, want the stored key %q", gotRR, keyRR)
	}
	if !strings.Contains(resp.Msg, "verified and trusted") {
		t.Errorf("Msg %q does not report the outcome", resp.Msg)
	}
	if sk := lookupChildKey(t, kdb, keyid); !sk.Trusted || sk.ValidationFailed {
		t.Errorf("after revalidate: %+v", sk)
	}
}

// A verification that outlives the wait is reported as running; one that
// fails again leaves the failure recorded and says so.
func TestRevalidateReportsRunningAndFailedAgain(t *testing.T) {
	kdb := newTestKeyDB(t)
	keyid, _ := addVfChildKey(t, kdb, false)
	clearChildKeyCooldown(t, vfChild, keyid)

	never := make(chan struct{})
	t.Cleanup(func() { close(never) })
	resp, err := revalidateNow(t, kdb, keyid, func(string, uint16, string) <-chan struct{} { return never }, 10*time.Millisecond)
	if err != nil || resp.Error || !strings.Contains(resp.Msg, "still running") {
		t.Errorf("slow verification: %v / %+v", err, resp)
	}

	resp, err = revalidateNow(t, kdb, keyid, func(child string, kid uint16, _ string) <-chan struct{} {
		recordFailure(t, kdb, kid, "at-apex: unsigned")
		done := make(chan struct{})
		close(done)
		return done
	}, time.Second)
	if err != nil || resp.Error || !strings.Contains(resp.Msg, "still failed validation: at-apex: unsigned") {
		t.Errorf("failed again: %v / %+v", err, resp)
	}
}

// Refused: an unknown key, a trusted one, one already being verified, and a
// verification the trigger did not start. None of them starts a verification.
func TestRevalidateRefusals(t *testing.T) {
	kdb := newTestKeyDB(t)
	keyid, _ := addVfChildKey(t, kdb, false)
	clearChildKeyCooldown(t, vfChild, keyid)
	started := false
	trigger := func(string, uint16, string) <-chan struct{} { started = true; return nil }

	if resp, err := revalidateNow(t, kdb, keyid+1, trigger, time.Second); err == nil || !strings.Contains(resp.ErrorMsg, "no SIG(0) key") {
		t.Errorf("unknown key: %v / %+v", err, resp)
	}

	id := childKeyVerificationID(vfChild, keyid)
	childKeyVerifications.Store(id, struct{}{})
	resp, err := revalidateNow(t, kdb, keyid, trigger, time.Second)
	childKeyVerifications.Delete(id)
	if err == nil || !strings.Contains(resp.ErrorMsg, "already running") {
		t.Errorf("running verification: %v / %+v", err, resp)
	}
	if started {
		t.Fatal("a refused revalidate started a verification")
	}

	resp, err = revalidateNow(t, kdb, keyid, trigger, time.Second)
	if err != nil || !resp.Error || !strings.Contains(resp.ErrorMsg, "not started") {
		t.Errorf("trigger started nothing: %v / %+v", err, resp)
	}

	if _, err := kdb.Sig0TrustMgmt(nil, TruststorePost{
		Command: "child-sig0-mgmt", SubCommand: "trust", Keyname: vfChild, Keyid: int(keyid),
	}); err != nil {
		t.Fatal(err)
	}
	started = false
	if resp, err := revalidateNow(t, kdb, keyid, trigger, time.Second); err == nil || !strings.Contains(resp.ErrorMsg, "already trusted") {
		t.Errorf("trusted key: %v / %+v", err, resp)
	}
	if started {
		t.Error("revalidate of a trusted key started a verification")
	}
}

// The text a refused re-bootstrap carries says how long to wait, never less
// than a second.
func TestReBootstrapTooSoonText(t *testing.T) {
	got := reBootstrapTooSoonText(16282, 3*time.Minute+12*time.Second+400*time.Millisecond)
	if !strings.Contains(got, "key 16282") || !strings.Contains(got, "re-bootstrap again in 3m12s") {
		t.Errorf("%q", got)
	}
	if got := reBootstrapTooSoonText(1, 10*time.Millisecond); !strings.Contains(got, "again in 1s") {
		t.Errorf("%q", got)
	}
}
