package tdns

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// AtomicRollover performs the active→retired / standby→active swap for a
// zone's KSK in a single transaction. Implements the §3.4 invariant: at any
// instant a zone has exactly one active KSK.
//
// For multi-ds the new KSK is collapsed published→active in this same TX
// (§8.8: pending-child-publish covers the visibility wait). The
// double-signature method is not handled here — that's 4E.
//
// Atomically:
//   - selects KSK_old (the active SEP)
//   - selects KSK_new (standby SEP with oldest standby_at; tie-break by
//     rollover_index, then by keytag)
//   - KSK_old: active → retired (DnssecKeyStore: state, retired_at;
//     RolloverKeyState: rollover_state_at)
//   - KSK_new: standby → active (DnssecKeyStore: state;
//     RolloverKeyState: rollover_state_at, active_at)
//   - sets RolloverZoneState.rollover_in_progress = TRUE
//   - sets rollover_phase = pending-child-publish (with rollover_phase_at)
//
// On commit, fires triggerResign so the zone re-signs with KSK_new (and
// without KSK_old).
//
// rollover_due is the caller's responsibility; AtomicRollover assumes the
// trigger has already fired and there is a usable standby. Returns an error
// (no state change) if no standby SEP key exists.
func AtomicRollover(conf *Config, kdb *KeyDB, zone string) (oldKid, newKid uint16, err error) {
	zone = dns.Fqdn(strings.TrimSpace(zone))
	if zone == "" {
		return 0, 0, fmt.Errorf("AtomicRollover: empty zone")
	}

	if err := EnsureRolloverZoneRow(kdb, zone); err != nil {
		return 0, 0, fmt.Errorf("ensure rollover zone row: %w", err)
	}

	tx, err := kdb.Begin("AtomicRollover")
	if err != nil {
		return 0, 0, fmt.Errorf("begin tx: %w", err)
	}
	commit := false
	defer func() {
		if !commit {
			tx.Rollback()
		}
	}()

	now := time.Now().UTC()

	// Pick KSK_old: the (single) active SEP key for the zone.
	oldKid, err = pickActiveSEPTx(tx, zone)
	if err != nil {
		return 0, 0, fmt.Errorf("pick active KSK: %w", err)
	}
	if oldKid == 0 {
		return 0, 0, fmt.Errorf("AtomicRollover: zone %s has no active KSK", zone)
	}

	// Pick KSK_new: SEP key in standby with oldest standby_at, tie-break
	// rollover_index then keytag. Excludes KSK_old (which is in active,
	// not standby — but be defensive).
	standbys, err := listRolloverStandbyKeysTx(tx, zone)
	if err != nil {
		return 0, 0, fmt.Errorf("list standbys: %w", err)
	}
	newKid, err = pickStandbyForPromotion(tx, zone, standbys)
	if err != nil {
		return 0, 0, fmt.Errorf("pick standby: %w", err)
	}
	if newKid == 0 {
		return 0, 0, fmt.Errorf("AtomicRollover: zone %s has no standby SEP key to promote", zone)
	}
	if newKid == oldKid {
		return 0, 0, fmt.Errorf("AtomicRollover: refusing to promote keyid %d (same as active)", oldKid)
	}

	// active → retired (DnssecKeyStore.state + retired_at via
	// UpdateDnssecKeyStateTx, plus rollover_state_at on RolloverKeyState).
	if err := UpdateDnssecKeyStateTx(tx, kdb, zone, oldKid, DnskeyStateRetired); err != nil {
		return 0, 0, fmt.Errorf("active→retired (keyid %d): %w", oldKid, err)
	}
	if err := stampRolloverStateAtTx(tx, zone, oldKid, now); err != nil {
		return 0, 0, fmt.Errorf("rollover_state_at (keyid %d): %w", oldKid, err)
	}

	// standby → active. UpdateDnssecKeyStateTx does not stamp active_at on
	// DnssecKeyStore (no such column there). active_at lives in
	// RolloverKeyState (4B); stamp it explicitly.
	if err := UpdateDnssecKeyStateTx(tx, kdb, zone, newKid, DnskeyStateActive); err != nil {
		return 0, 0, fmt.Errorf("standby→active (keyid %d): %w", newKid, err)
	}
	if err := setRolloverKeyActiveAtTx(tx, zone, newKid, now); err != nil {
		return 0, 0, fmt.Errorf("active_at (keyid %d): %w", newKid, err)
	}
	if err := stampRolloverStateAtTx(tx, zone, newKid, now); err != nil {
		return 0, 0, fmt.Errorf("rollover_state_at (keyid %d): %w", newKid, err)
	}

	// Mark zone as mid-rollover and arm the §8.8 pending-child-publish phase.
	if err := setRolloverInProgressTx(tx, zone, true); err != nil {
		return 0, 0, fmt.Errorf("set rollover_in_progress: %w", err)
	}
	if err := setRolloverPhaseTx(tx, zone, rolloverPhasePendingChildPublish); err != nil {
		return 0, 0, fmt.Errorf("set rollover_phase: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit: %w", err)
	}
	commit = true

	lgSigner.Info("rollover: atomic_rollover committed",
		"zone", zone, "old_keyid", oldKid, "new_keyid", newKid,
		"phase", rolloverPhasePendingChildPublish)

	triggerResign(conf, zone)
	return oldKid, newKid, nil
}

// pickActiveSEPTx returns the (single) active SEP keyid for the zone, or 0
// if no active SEP exists. Returns an error if the zone has more than one
// active SEP key (violates §3.4 invariant).
func pickActiveSEPTx(tx *Tx, zone string) (uint16, error) {
	rows, err := tx.Query(`
SELECT keyid FROM DnssecKeyStore
WHERE zonename = ? AND state = ? AND (flags & 1) = 1`,
		zone, DnskeyStateActive)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var found []uint16
	for rows.Next() {
		var k int
		if err := rows.Scan(&k); err != nil {
			return 0, err
		}
		found = append(found, uint16(k))
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(found) == 0 {
		return 0, nil
	}
	if len(found) > 1 {
		return 0, fmt.Errorf("invariant violated: zone %s has %d active SEP keys (expected 1)", zone, len(found))
	}
	return found[0], nil
}

// pickStandbyForPromotion picks the standby SEP key with the oldest standby_at;
// ties are broken by rollover_index ascending, then keytag ascending. Returns 0
// if the standby list is empty.
func pickStandbyForPromotion(tx *Tx, zone string, standbys []struct {
	KeyID     uint16
	StandbyAt sql.NullString
}) (uint16, error) {
	if len(standbys) == 0 {
		return 0, nil
	}
	// listRolloverStandbyKeysTx already orders NULL/empty standby_at last,
	// then standby_at ascending, then keyid ascending. The first non-null
	// row is our oldest. If all standby_at are null/empty (legacy keys),
	// fall back to lowest rollover_index, then lowest keytag.
	for _, s := range standbys {
		if s.StandbyAt.Valid && strings.TrimSpace(s.StandbyAt.String) != "" {
			return s.KeyID, nil
		}
	}
	// All NULL: tie-break by rollover_index then keytag.
	type cand struct {
		kid uint16
		idx int
	}
	var cands []cand
	for _, s := range standbys {
		var ri sql.NullInt64
		err := tx.QueryRow(`SELECT rollover_index FROM RolloverKeyState WHERE zone = ? AND keyid = ?`,
			zone, int(s.KeyID)).Scan(&ri)
		if err != nil && err != sql.ErrNoRows {
			return 0, err
		}
		idx := -1
		if ri.Valid {
			idx = int(ri.Int64)
		}
		cands = append(cands, cand{kid: s.KeyID, idx: idx})
	}
	best := cands[0]
	for _, c := range cands[1:] {
		// Prefer rows with valid rollover_index (idx >= 0).
		bestHas := best.idx >= 0
		cHas := c.idx >= 0
		switch {
		case cHas && !bestHas:
			best = c
		case !cHas && bestHas:
			// keep best
		case cHas && bestHas:
			if c.idx < best.idx {
				best = c
			} else if c.idx == best.idx && c.kid < best.kid {
				best = c
			}
		default:
			if c.kid < best.kid {
				best = c
			}
		}
	}
	return best.kid, nil
}

// stampRolloverStateAtTx updates rollover_state_at on RolloverKeyState. Used
// by AtomicRollover to record the time of each per-key state advance inside
// the same TX as the DnssecKeyStore.state write (§9.4 two-store consistency).
func stampRolloverStateAtTx(tx *Tx, zone string, keyid uint16, at time.Time) error {
	s := at.UTC().Format(time.RFC3339)
	_, err := tx.Exec(`UPDATE RolloverKeyState SET rollover_state_at = ? WHERE zone = ? AND keyid = ?`,
		s, zone, int(keyid))
	return err
}
