package tdns

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// GenerateKskRolloverCreated inserts a new KSK in state created with RolloverKeyState (multi-ds / double-signature pipeline).
func GenerateKskRolloverCreated(kdb *KeyDB, zone, creator string, alg uint8, method RolloverMethod) (keyid uint16, rolloverIndex int, err error) {
	zone = dns.Fqdn(zone)
	tx, err := kdb.Begin("GenerateKskRolloverCreated")
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			err = tx.Commit()
		}
	}()

	ri, err := nextRolloverIndexTx(tx, zone)
	if err != nil {
		return 0, 0, err
	}

	pkc, _, err := kdb.GenerateKeypair(zone, creator, DnskeyStateCreated, dns.TypeDNSKEY, alg, "KSK", tx)
	if err != nil {
		return 0, 0, fmt.Errorf("GenerateKskRolloverCreated: %w", err)
	}

	if err := insertRolloverKeyStateTx(tx, zone, pkc.KeyId, ri, method); err != nil {
		return 0, 0, fmt.Errorf("GenerateKskRolloverCreated: rollover state: %w", err)
	}

	delete(kdb.KeystoreDnskeyCache, zone+"+"+DnskeyStateCreated)

	return pkc.KeyId, ri, nil
}

// RegisterBootstrapActiveKSK records a KSK that was generated directly into
// state=active (e.g. by EnsureActiveDnssecKeys when no KSK existed yet) into
// RolloverKeyState, assigning it the next rollover_index for the zone and
// stamping active_at = now. Without this, rolloverDue cannot fire scheduled
// rollovers (active_at is unset) and the K-step clamp scheduler refuses to
// run (tNextRoll returns ok=false).
//
// Idempotent: if a row already exists for (zone, keyid), only active_at is
// updated. Skips when method == RolloverMethodNone (zone has no rollover
// policy).
func RegisterBootstrapActiveKSK(kdb *KeyDB, zone string, keyid uint16, method RolloverMethod, alg uint8) error {
	if method == RolloverMethodNone {
		return nil
	}
	zone = dns.Fqdn(zone)
	if err := EnsureRolloverZoneRow(kdb, zone); err != nil {
		return err
	}

	tx, err := kdb.Begin("RegisterBootstrapActiveKSK")
	if err != nil {
		return err
	}
	commit := false
	defer func() {
		if !commit {
			tx.Rollback()
		}
	}()

	// If a row already exists for this key, just stamp active_at.
	var existing int
	err = tx.QueryRow(`SELECT COUNT(*) FROM RolloverKeyState WHERE zone = ? AND keyid = ?`, zone, int(keyid)).Scan(&existing)
	if err != nil {
		return fmt.Errorf("query existing: %w", err)
	}
	if existing == 0 {
		ri, err := nextRolloverIndexTx(tx, zone)
		if err != nil {
			return fmt.Errorf("next rollover index: %w", err)
		}
		if err := insertRolloverKeyStateTx(tx, zone, keyid, ri, method); err != nil {
			return fmt.Errorf("insert rollover state: %w", err)
		}
	}

	now := time.Now().UTC()
	if err := setRolloverKeyActiveAtTx(tx, zone, keyid, now); err != nil {
		return fmt.Errorf("stamp active_at: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	commit = true
	return nil
}

// CountKskInRolloverPipeline counts SEP keys in pre-terminal rollover pipeline states.
func CountKskInRolloverPipeline(kdb *KeyDB, zone string) (int, error) {
	zone = dns.Fqdn(zone)
	const q = `
SELECT COUNT(*) FROM DnssecKeyStore
WHERE zonename = ? AND (CAST(flags AS INTEGER) & ?) != 0
  AND state IN ('created','ds-published','standby','published','active','retired')`
	var n int
	err := kdb.DB.QueryRow(q, zone, int(dns.SEP)).Scan(&n)
	return n, err
}
