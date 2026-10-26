package tdns

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestKeyDBBeginWaitsForPriorCommit: a second Begin must wait for the first
// transaction to finish, then succeed — not fail at once (#927).
func TestKeyDBBeginWaitsForPriorCommit(t *testing.T) {
	kdb := newTestKeyDB(t)

	first, err := kdb.Begin("holder")
	if err != nil {
		t.Fatalf("first Begin: %v", err)
	}

	started := make(chan struct{})
	gotSecond := make(chan error, 1)
	var second *Tx
	go func() {
		close(started)
		var err error
		second, err = kdb.Begin("waiter")
		gotSecond <- err
	}()
	<-started

	// The waiter must still be blocked while the holder is open.
	select {
	case err := <-gotSecond:
		t.Fatalf("second Begin returned while first was open: err=%v", err)
	case <-time.After(100 * time.Millisecond):
	}

	if err := first.Commit(); err != nil {
		t.Fatalf("first Commit: %v", err)
	}

	select {
	case err := <-gotSecond:
		if err != nil {
			t.Fatalf("second Begin after commit: %v", err)
		}
		if second == nil {
			t.Fatal("second Begin returned nil Tx")
		}
		if err := second.Commit(); err != nil {
			t.Fatalf("second Commit: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second Begin did not proceed after first Commit")
	}
}

// TestKeyDBBeginTimeoutNamesHolderAndWaiter: when the holder never finishes
// within the wait bound, Begin fails naming both contexts (#927).
func TestKeyDBBeginTimeoutNamesHolderAndWaiter(t *testing.T) {
	kdb := newTestKeyDB(t)

	prev := keystoreBeginWait
	keystoreBeginWait = 50 * time.Millisecond
	t.Cleanup(func() { keystoreBeginWait = prev })

	// Abandoned holder: Ctx set, no Commit/Rollback to clear it.
	kdb.mu.Lock()
	kdb.Ctx = "stuck-holder"
	kdb.mu.Unlock()

	_, err := kdb.Begin("impatient-waiter")
	if err == nil {
		t.Fatal("Begin must time out while holder never clears Ctx")
	}
	msg := err.Error()
	if !strings.Contains(msg, "stuck-holder") || !strings.Contains(msg, "impatient-waiter") {
		t.Fatalf("timeout error must name holder and waiter, got %q", msg)
	}
}

// TestKeyDBSecondEndDoesNotClearTheNextTxCtx: once a transaction has ended,
// the next Begin holds Ctx. A second end of the first transaction must leave
// that Ctx alone, or a third Begin runs alongside the second.
func TestKeyDBSecondEndDoesNotClearTheNextTxCtx(t *testing.T) {
	kdb := newTestKeyDB(t)

	prev := keystoreBeginWait
	keystoreBeginWait = 50 * time.Millisecond
	t.Cleanup(func() { keystoreBeginWait = prev })

	first, err := kdb.Begin("first")
	if err != nil {
		t.Fatalf("first Begin: %v", err)
	}
	if err := first.Commit(); err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	second, err := kdb.Begin("second")
	if err != nil {
		t.Fatalf("second Begin: %v", err)
	}
	defer second.Rollback()

	if err := first.Rollback(); !errors.Is(err, sql.ErrTxDone) {
		t.Errorf("second end of the first tx: err = %v, want sql.ErrTxDone", err)
	}
	if err := first.Commit(); !errors.Is(err, sql.ErrTxDone) {
		t.Errorf("third end of the first tx: err = %v, want sql.ErrTxDone", err)
	}
	kdb.mu.Lock()
	ctx := kdb.Ctx
	kdb.mu.Unlock()
	if ctx != "second" {
		t.Fatalf("Ctx = %q after the first tx was ended again, want %q", ctx, "second")
	}
	if third, err := kdb.Begin("third"); err == nil {
		third.Rollback()
		t.Fatal("a third Begin ran while the second tx was open")
	}
}

// TestGetSig0KeysDoesNotCacheAcrossAnInvalidation: a read that saw the rows
// before a commit must not store them after that commit's invalidation, or
// the retired key stays cached as active (#943).
func TestGetSig0KeysDoesNotCacheAcrossAnInvalidation(t *testing.T) {
	kdb := newTestKeyDB(t)
	const zone = "stale.example."
	keyid := generateSig0Key(t, kdb, zone, Sig0StateActive)

	// Between GetSig0Keys' read and its store, retire the key. With a nil tx
	// Sig0KeyMgmt commits and then invalidates.
	getSig0KeysBeforeStore = func() {
		getSig0KeysBeforeStore = nil
		if _, err := kdb.Sig0KeyMgmt(nil, KeystorePost{
			Command: "sig0-mgmt", SubCommand: "setstate",
			Keyname: zone, Keyid: keyid, State: Sig0StateRetired,
		}); err != nil {
			t.Errorf("setstate: %v", err)
		}
	}
	t.Cleanup(func() { getSig0KeysBeforeStore = nil })

	if _, err := kdb.GetSig0Keys(zone, Sig0StateActive); err != nil {
		t.Fatalf("GetSig0Keys: %v", err)
	}
	if getSig0KeysBeforeStore != nil {
		t.Fatal("the key was not retired between the read and the store")
	}
	assertNoActiveSig0Key(t, kdb, zone)
}

// The paths that apply the post-commit invalidation in production, not the
// response field alone: Sig0KeyMgmt's own transaction (nil tx), and the
// keystore API, which passes its transaction and applies
// BulkSig0InvalidateZones after its commit (#943).
func TestSig0KeyMgmtOwnTxInvalidatesAfterCommit(t *testing.T) {
	for _, sub := range []string{"setstate", "delete"} {
		t.Run(sub, func(t *testing.T) {
			kdb := newTestKeyDB(t)
			const zone = "own.example."
			keyid := primeActiveSig0Key(t, kdb, zone)
			if _, err := kdb.Sig0KeyMgmt(nil, KeystorePost{
				Command: "sig0-mgmt", SubCommand: sub,
				Zone: zone, Keyname: zone, Keyid: keyid, State: Sig0StateRetired,
			}); err != nil {
				t.Fatalf("%s: %v", sub, err)
			}
			assertNoActiveSig0Key(t, kdb, zone)
		})
	}
}

func TestAPIkeystoreSig0SetstateInvalidatesAfterCommit(t *testing.T) {
	kdb := newTestKeyDB(t)
	const zone = "api.example."
	keyid := primeActiveSig0Key(t, kdb, zone)

	body, err := json.Marshal(KeystorePost{
		Command: "sig0-mgmt", SubCommand: "setstate",
		Zone: zone, Keyname: zone, Keyid: keyid, State: Sig0StateRetired,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	w := httptest.NewRecorder()
	kdb.APIkeystore(&Config{})(w, httptest.NewRequest(http.MethodPost, "/api/v1/keystore", bytes.NewReader(body)))
	var kr KeystoreResponse
	if err := json.NewDecoder(w.Result().Body).Decode(&kr); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if kr.Error {
		t.Fatalf("setstate through the API: %s", kr.ErrorMsg)
	}
	assertNoActiveSig0Key(t, kdb, zone)
}

// primeActiveSig0Key makes an active SIG(0) key for zone and reads it once, so
// that it is in KeystoreSig0Cache.
func primeActiveSig0Key(t *testing.T, kdb *KeyDB, zone string) uint16 {
	t.Helper()
	keyid := generateSig0Key(t, kdb, zone, Sig0StateActive)
	sak, err := kdb.GetSig0Keys(zone, Sig0StateActive)
	if err != nil || len(sak.Keys) != 1 {
		t.Fatalf("priming the cache: err=%v keys=%+v", err, sak)
	}
	kdb.sig0CacheMu.RLock()
	_, cached := kdb.KeystoreSig0Cache[zone+"+"+Sig0StateActive]
	kdb.sig0CacheMu.RUnlock()
	if !cached {
		t.Fatal("the active key was not cached")
	}
	return keyid
}

// assertNoActiveSig0Key fails if GetSig0Keys, cache included, still gives zone
// an active key.
func assertNoActiveSig0Key(t *testing.T, kdb *KeyDB, zone string) {
	t.Helper()
	sak, err := kdb.GetSig0Keys(zone, Sig0StateActive)
	if err != nil {
		t.Fatalf("GetSig0Keys: %v", err)
	}
	if len(sak.Keys) != 0 {
		t.Fatalf("zone %s still has an active SIG(0) key %d after the commit", zone, sak.Keys[0].KeyRR.KeyTag())
	}
}

// TestSig0CacheConcurrentAccessDoesNotRace hammers GetSig0Keys and
// invalidateSig0Cache together under the race detector (#943). The zone has a
// key, so GetSig0Keys stores as well as reads.
func TestSig0CacheConcurrentAccessDoesNotRace(t *testing.T) {
	kdb := newTestKeyDB(t)
	const zone = "race.example."
	generateSig0Key(t, kdb, zone, Sig0StateActive)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = kdb.GetSig0Keys(zone, Sig0StateActive)
		}()
		go func() {
			defer wg.Done()
			kdb.invalidateSig0Cache(zone)
		}()
	}
	wg.Wait()
}

// TestSig0KeyMgmtSetstateInvalidatesAfterCommit: with an external transaction,
// setstate must not drop the cache until the caller commits (#943).
func TestSig0KeyMgmtSetstateInvalidatesAfterCommit(t *testing.T) {
	kdb := newTestKeyDB(t)
	key := testBulkSig0Key(t, "child.dnslab.")

	if _, err := kdb.Sig0KeyMgmt(nil, KeystorePost{
		Command: "sig0-mgmt", SubCommand: "bulk-import",
		BulkSig0Keys: []BulkSig0Key{key},
	}); err != nil {
		t.Fatalf("import: %v", err)
	}

	cacheKey := key.Zone + "+" + Sig0StateActive
	kdb.sig0CacheMu.Lock()
	kdb.KeystoreSig0Cache[cacheKey] = &Sig0ActiveKeys{}
	kdb.sig0CacheMu.Unlock()

	tx, err := kdb.Begin("setstate-external")
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	resp, err := kdb.Sig0KeyMgmt(tx, KeystorePost{
		Command:    "sig0-mgmt",
		SubCommand: "setstate",
		Keyname:    key.Zone,
		Keyid:      key.Keyid,
		State:      Sig0StateRetired,
	})
	if err != nil {
		t.Fatalf("setstate: %v", err)
	}

	kdb.sig0CacheMu.RLock()
	_, present := kdb.KeystoreSig0Cache[cacheKey]
	kdb.sig0CacheMu.RUnlock()
	if !present {
		t.Fatal("must NOT invalidate KeystoreSig0Cache before the owning transaction commits")
	}
	if len(resp.BulkSig0InvalidateZones) != 1 || resp.BulkSig0InvalidateZones[0] != key.Zone {
		t.Fatalf("external-tx caller needs the zone list, got %+v", resp.BulkSig0InvalidateZones)
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	for _, zone := range resp.BulkSig0InvalidateZones {
		kdb.invalidateSig0Cache(zone)
	}

	kdb.sig0CacheMu.RLock()
	_, stale := kdb.KeystoreSig0Cache[cacheKey]
	kdb.sig0CacheMu.RUnlock()
	if stale {
		t.Fatal("cache entry must be gone after commit + invalidate")
	}
}
