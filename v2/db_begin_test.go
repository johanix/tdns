package tdns

import (
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

// TestSig0CacheConcurrentAccessDoesNotRace hammers GetSig0Keys and
// invalidateSig0Cache together under the race detector (#943).
func TestSig0CacheConcurrentAccessDoesNotRace(t *testing.T) {
	kdb := newTestKeyDB(t)
	const zone = "race.example."

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
