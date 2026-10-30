package tdns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// impatientTestKeyDB is an in-memory keystore whose pool does not wait for a
// lock: a read through the pool beside an open transaction fails at once with
// "database is locked", where newTestKeyDB's waits out the busy timeout first.
func impatientTestKeyDB(t *testing.T) *KeyDB {
	t.Helper()
	wait := fmt.Sprintf("_busy_timeout=%d", keystoreBusyTimeoutMs)
	dsn := keystoreDSN("/tdns-keystore-impatient-"+t.Name()) + "&vfs=memdb"
	if !strings.Contains(dsn, wait) {
		t.Fatalf("the keystore DSN %q sets no %s", dsn, wait)
	}
	kdb, err := newKeyDBInMemoryDSN(strings.Replace(dsn, wait, "_busy_timeout=0", 1))
	if err != nil {
		t.Fatalf("newKeyDBInMemoryDSN: %v", err)
	}
	t.Cleanup(func() { kdb.Close() })
	return kdb
}

// TestKeystoreReadsUnderATransactionGoThroughIt: code that holds a keystore
// transaction reads through it (#986). On a keystore that fails a read through
// the pool at once, each read #986 moved onto the transaction runs under one
// and must succeed. One that reads through the pool again fails here at once,
// not after the 5 s an in-memory test keystore waits.
func TestKeystoreReadsUnderATransactionGoThroughIt(t *testing.T) {
	kdb := impatientTestKeyDB(t)
	const zone = "txreads.example." // not loaded: no zone work rides along
	gen := func(state, keytype string) uint16 {
		pkc, _, err := kdb.GenerateKeypair(zone, "test", state, dns.TypeDNSKEY, dns.ED25519, keytype, nil)
		if err != nil {
			t.Fatalf("generate a %s %s: %v", state, keytype, err)
		}
		return pkc.KeyId
	}
	gen(DnskeyStateActive, "KSK")
	activeZSK := gen(DnskeyStateActive, "ZSK")
	gen(DnskeyStateStandby, "ZSK")
	gen(DnskeyStateCreated, "KSK")
	if err := UpdateDnssecKeyState(kdb, zone, gen(DnskeyStateActive, "ZSK"), DnskeyStateRetired); err != nil {
		t.Fatalf("retire a ZSK: %v", err)
	}
	ctx := context.Background()

	// underTx runs f in a transaction of its own, rolled back at the end:
	// the subtests share the keystore's keys, not each other's writes.
	underTx := func(name string, f func(tx *Tx) error) {
		t.Run(name, func(t *testing.T) {
			tx, err := kdb.Begin(t.Name())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if err := f(tx); err != nil {
				t.Fatal(err)
			}
		})
	}
	mgmt := func(tx *Tx, sub string) (*KeystoreResponse, error) {
		resp, err := kdb.DnssecKeyMgmt(ctx, tx, KeystorePost{Command: "dnssec-mgmt", SubCommand: sub, Zone: zone})
		if err == nil && resp.Error {
			err = errors.New(resp.ErrorMsg)
		}
		return resp, err
	}

	// The keystore is as impatient as the rest of the test needs.
	underTx("a read through the pool fails at once", func(tx *Tx) error {
		start := time.Now()
		_, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
		if err == nil {
			return errors.New("the pool read the keystore beside an open transaction")
		}
		if !strings.Contains(err.Error(), "database is locked") {
			return fmt.Errorf("the pool's read failed, but not on the lock: %v", err)
		}
		if took := time.Since(start); took > time.Second {
			return fmt.Errorf("the pool's read took %v to fail", took)
		}
		return nil
	})

	underTx("the DS confirm", func(tx *Tx) error {
		_, err := advanceCreatedKeysInRangeTx(tx, kdb, zone, 0, 10, time.Now())
		return err
	})
	underTx("a ZSK rollover on the caller's transaction", func(tx *Tx) error {
		_, _, err := kdb.RolloverKey(zone, "ZSK", tx)
		return err
	})
	underTx("policy-cleanup", func(tx *Tx) error {
		_, err := mgmt(tx, "policy-cleanup")
		return err
	})
	// What the transaction wrote is what it reads: a key retired earlier in
	// the transaction is retired to policy-cleanup, which removes it. Read
	// through the pool, on a keystore that lets it through, the retire is not
	// there yet, and the key would stay.
	underTx("a read sees the transaction's earlier write", func(tx *Tx) error {
		if err := UpdateDnssecKeyStateTx(tx, kdb, zone, activeZSK, DnskeyStateRetired); err != nil {
			return err
		}
		hasKey := func(state string) (bool, error) {
			keys, err := GetDnssecKeysByStateTx(tx, zone, state)
			for _, k := range keys {
				if k.KeyTag == activeZSK {
					return true, err
				}
			}
			return false, err
		}
		if retired, err := hasKey(DnskeyStateRetired); err != nil || !retired {
			return fmt.Errorf("key %d retired in the transaction does not read as retired (err %v)", activeZSK, err)
		}
		if _, err := mgmt(tx, "policy-cleanup"); err != nil {
			return err
		}
		if removed, err := hasKey(DnskeyStateRemoved); err != nil || !removed {
			return fmt.Errorf("policy-cleanup did not remove key %d, retired earlier in its transaction (err %v)", activeZSK, err)
		}
		return nil
	})
	underTx("check", func(tx *Tx) error {
		resp, err := kdb.DnssecKeyMgmt(ctx, tx, KeystorePost{Command: "dnssec-mgmt", SubCommand: "check"})
		if err != nil {
			return err
		}
		for _, v := range resp.KeyViolations {
			if v.Invariant == "error" {
				return errors.New(v.Detail)
			}
		}
		return nil
	})
	underTx("sig0 list", func(tx *Tx) error {
		resp, err := kdb.Sig0KeyMgmt(tx, KeystorePost{Command: "sig0-mgmt", SubCommand: "list"})
		if err == nil && resp.Error {
			err = errors.New(resp.ErrorMsg)
		}
		return err
	})
}
