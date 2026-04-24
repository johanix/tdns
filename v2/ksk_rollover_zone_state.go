package tdns

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// RolloverZoneRow is persisted rollover coordination for one zone (RolloverZoneState).
type RolloverZoneRow struct {
	Zone               string
	LastSubmittedLow   sql.NullInt64
	LastSubmittedHigh  sql.NullInt64
	LastConfirmedLow   sql.NullInt64
	LastConfirmedHigh  sql.NullInt64
	RolloverPhase      string
	RolloverInProgress bool
	ObserveStartedAt   sql.NullString
	ObserveNextPollAt  sql.NullString
	ObserveBackoffSecs sql.NullInt64
}

func EnsureRolloverZoneRow(kdb *KeyDB, zone string) error {
	zone = strings.TrimSpace(zone)
	if zone == "" {
		return fmt.Errorf("EnsureRolloverZoneRow: empty zone")
	}
	const q = `
INSERT INTO RolloverZoneState (zone, rollover_phase, rollover_in_progress, next_rollover_index)
VALUES (?, 'idle', 0, 0)
ON CONFLICT(zone) DO NOTHING`
	_, err := kdb.DB.Exec(q, zone)
	return err
}

func LoadRolloverZoneRow(kdb *KeyDB, zone string) (*RolloverZoneRow, error) {
	zone = strings.TrimSpace(zone)
	const q = `
SELECT zone,
       last_ds_submitted_index_low, last_ds_submitted_index_high,
       last_ds_confirmed_index_low, last_ds_confirmed_index_high,
       rollover_phase, rollover_in_progress,
       observe_started_at, observe_next_poll_at, observe_backoff_seconds
FROM RolloverZoneState WHERE zone = ?`
	var r RolloverZoneRow
	var inProg int
	err := kdb.DB.QueryRow(q, zone).Scan(
		&r.Zone,
		&r.LastSubmittedLow, &r.LastSubmittedHigh,
		&r.LastConfirmedLow, &r.LastConfirmedHigh,
		&r.RolloverPhase, &inProg,
		&r.ObserveStartedAt, &r.ObserveNextPollAt, &r.ObserveBackoffSecs,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.RolloverInProgress = inProg != 0
	return &r, nil
}

func SetRolloverPhase(kdb *KeyDB, zone, phase string) error {
	if err := EnsureRolloverZoneRow(kdb, zone); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := kdb.DB.Exec(`UPDATE RolloverZoneState SET rollover_phase = ?, rollover_phase_at = ? WHERE zone = ?`, phase, now, zone)
	return err
}

func saveLastDSConfirmedRange(kdb *KeyDB, zone string, low, high int) error {
	const q = `
INSERT INTO RolloverZoneState (zone, last_ds_confirmed_index_low, last_ds_confirmed_index_high, last_ds_confirmed_at, rollover_phase, rollover_in_progress, next_rollover_index)
VALUES (?, ?, ?, ?, 'idle', 0, 0)
ON CONFLICT(zone) DO UPDATE SET
  last_ds_confirmed_index_low = excluded.last_ds_confirmed_index_low,
  last_ds_confirmed_index_high = excluded.last_ds_confirmed_index_high,
  last_ds_confirmed_at = excluded.last_ds_confirmed_at`
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := kdb.DB.Exec(q, zone, low, high, now)
	return err
}

func RolloverIndexForKey(kdb *KeyDB, zone string, keyid uint16) (int, bool, error) {
	var ri sql.NullInt64
	err := kdb.DB.QueryRow(`SELECT rollover_index FROM RolloverKeyState WHERE zone = ? AND keyid = ?`, zone, int(keyid)).Scan(&ri)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if !ri.Valid {
		return 0, false, nil
	}
	return int(ri.Int64), true, nil
}

func insertRolloverKeyStateTx(tx *Tx, zone string, keyid uint16, rolloverIndex int, method RolloverMethod) error {
	meth := ""
	switch method {
	case RolloverMethodMultiDS:
		meth = "multi-ds"
	case RolloverMethodDoubleSignature:
		meth = "double-signature"
	default:
		meth = "none"
	}
	now := time.Now().UTC().Format(time.RFC3339)
	const q = `
INSERT INTO RolloverKeyState (zone, keyid, rollover_index, rollover_method, rollover_state_at)
VALUES (?, ?, ?, ?, ?)`
	_, err := tx.Exec(q, zone, int(keyid), rolloverIndex, meth, now)
	return err
}

func nextRolloverIndexTx(tx *Tx, zone string) (int, error) {
	var max sql.NullInt64
	err := tx.QueryRow(`SELECT MAX(rollover_index) FROM RolloverKeyState WHERE zone = ?`, zone).Scan(&max)
	if err != nil {
		return 0, err
	}
	if !max.Valid {
		return 0, nil
	}
	return int(max.Int64) + 1, nil
}

func setRolloverKeyDsObservedAt(kdb *KeyDB, zone string, keyid uint16, at time.Time) error {
	s := at.UTC().Format(time.RFC3339)
	_, err := kdb.DB.Exec(`UPDATE RolloverKeyState SET ds_observed_at = ? WHERE zone = ? AND keyid = ?`, s, zone, int(keyid))
	return err
}

// setRolloverPhaseTx updates the zone's rollover_phase on an existing TX.
// The caller is responsible for row existence (EnsureRolloverZoneRow).
func setRolloverPhaseTx(tx *Tx, zone, phase string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := tx.Exec(`UPDATE RolloverZoneState SET rollover_phase = ?, rollover_phase_at = ? WHERE zone = ?`, phase, now, zone)
	return err
}

// saveLastDSConfirmedRangeTx persists the confirmed DS index range on an existing TX.
func saveLastDSConfirmedRangeTx(tx *Tx, zone string, low, high int) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := tx.Exec(`UPDATE RolloverZoneState
SET last_ds_confirmed_index_low = ?,
    last_ds_confirmed_index_high = ?,
    last_ds_confirmed_at = ?
WHERE zone = ?`, low, high, now, zone)
	return err
}

// setRolloverKeyDsObservedAtTx stamps ds_observed_at for one key on an existing TX.
func setRolloverKeyDsObservedAtTx(tx *Tx, zone string, keyid uint16, at time.Time) error {
	s := at.UTC().Format(time.RFC3339)
	_, err := tx.Exec(`UPDATE RolloverKeyState SET ds_observed_at = ? WHERE zone = ? AND keyid = ?`, s, zone, int(keyid))
	return err
}

// setObserveSchedule persists the observe-phase backoff state (start time, next
// poll time, current backoff interval in seconds). Zero startedAt clears the
// start marker (used when leaving the observe phase).
func setObserveSchedule(kdb *KeyDB, zone string, startedAt time.Time, nextPollAt time.Time, backoffSecs int) error {
	var started, next sql.NullString
	if !startedAt.IsZero() {
		started = sql.NullString{String: startedAt.UTC().Format(time.RFC3339), Valid: true}
	}
	if !nextPollAt.IsZero() {
		next = sql.NullString{String: nextPollAt.UTC().Format(time.RFC3339), Valid: true}
	}
	_, err := kdb.DB.Exec(`UPDATE RolloverZoneState
SET observe_started_at = ?,
    observe_next_poll_at = ?,
    observe_backoff_seconds = ?
WHERE zone = ?`, started, next, sql.NullInt64{Int64: int64(backoffSecs), Valid: backoffSecs > 0}, zone)
	return err
}

// clearObserveSchedule clears all three observe-phase fields.
func clearObserveSchedule(kdb *KeyDB, zone string) error {
	_, err := kdb.DB.Exec(`UPDATE RolloverZoneState
SET observe_started_at = NULL,
    observe_next_poll_at = NULL,
    observe_backoff_seconds = NULL
WHERE zone = ?`, zone)
	return err
}

// setLastRolloverError stamps last_rollover_error on one key.
func setLastRolloverError(kdb *KeyDB, zone string, keyid uint16, msg string) error {
	_, err := kdb.DB.Exec(`UPDATE RolloverKeyState SET last_rollover_error = ? WHERE zone = ? AND keyid = ?`, msg, zone, int(keyid))
	return err
}

func rolloverKeyDsObservedAt(kdb *KeyDB, zone string, keyid uint16) (*time.Time, error) {
	var dsObs sql.NullString
	err := kdb.DB.QueryRow(`SELECT ds_observed_at FROM RolloverKeyState WHERE zone = ? AND keyid = ?`, zone, int(keyid)).Scan(&dsObs)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !dsObs.Valid || strings.TrimSpace(dsObs.String) == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(dsObs.String))
	if err != nil {
		return nil, err
	}
	return &t, nil
}
