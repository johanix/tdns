/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// holdKeyDB makes kdb's transaction look held by another writer for the rest
// of the test, and shortens Begin's wait so a waiter gives up at once.
func holdKeyDB(t *testing.T, kdb *KeyDB) {
	t.Helper()
	prev := keystoreBeginWait
	keystoreBeginWait = 50 * time.Millisecond
	t.Cleanup(func() { keystoreBeginWait = prev })
	kdb.mu.Lock()
	kdb.Ctx = "another-zones-setup"
	kdb.mu.Unlock()
}

// The join: a zone's first setup generates its key in Sig0KeyMgmt's own
// transaction. When another writer holds the keystore past Begin's wait, the
// error that comes out of the key preparation must still say so, or the
// setup arm cannot tell it from a verdict and drops the zone's setup.
func TestSig0KeyPreparationReportsABusyKeystore(t *testing.T) {
	zd, kdb, _ := newSig0KeyPrepZone(t, sig0KeyPrepZone, Primary)
	zd.Options = map[ZoneOption]bool{OptParentSync: true}
	holdKeyDB(t, kdb)

	err := zd.Sig0KeyPreparation("example.", dns.ED25519, kdb)
	if !errors.Is(err, ErrKeyDBBusy) {
		t.Fatalf("Sig0KeyPreparation with the keystore held = %v, want an error that is ErrKeyDBBusy", err)
	}
}

// A setup that found the keystore busy is retried with the setup backoff, not
// logged and dropped (the arm returns nil when it drops).
func TestSetupRetriesABusyKeystore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conf, q := setupRig(t, true)
	ds := DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: "example."}

	zd, kdb, _ := newSig0KeyPrepZone(t, sig0KeyPrepZone, Primary)
	zd.Options = map[ZoneOption]bool{OptParentSync: true}
	holdKeyDB(t, kdb)

	scheduled := handleDelegationSyncSetupWith(ctx, conf, q, ds, func() error {
		return zd.Sig0KeyPreparation("example.", dns.ED25519, kdb)
	})
	defer awaitExit(t, cancel, scheduled)
	if scheduled == nil {
		t.Fatal("a setup that found the keystore busy was dropped; the same setup succeeds once the holder is done")
	}
}

// The retry is bounded like the setup's other non-final failures.
func TestSetupGivesUpOnAKeystoreThatStaysBusy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conf, q := setupRig(t, true)
	ds := DelegationSyncRequest{Command: "DELEGATION-SYNC-SETUP", ZoneName: "example.",
		Attempt: delegationSyncMaxRetries - 1}

	scheduled := handleDelegationSyncSetupWith(ctx, conf, q, ds, func() error {
		return ErrKeyDBBusy
	})
	defer awaitExit(t, cancel, scheduled)
	if scheduled != nil {
		t.Fatalf("attempt %d of %d was retried again; the backoff must end", ds.Attempt+1, delegationSyncMaxRetries)
	}
}
