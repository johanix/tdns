package tdns

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// RolloverZoneRow is persisted rollover coordination for one zone (RolloverZoneState).
type RolloverZoneRow struct {
	Zone                      string
	LastSubmittedLow          sql.NullInt64
	LastSubmittedHigh         sql.NullInt64
	LastConfirmedLow          sql.NullInt64
	LastConfirmedHigh         sql.NullInt64
	RolloverPhase             string
	RolloverPhaseAt           sql.NullString
	RolloverInProgress        bool
	ManualRolloverRequestedAt sql.NullString
	ManualRolloverEarliest    sql.NullString
	ObserveStartedAt          sql.NullString
	ObserveNextPollAt         sql.NullString
	ObserveBackoffSecs        sql.NullInt64
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
       rollover_phase, rollover_phase_at, rollover_in_progress,
       manual_rollover_requested_at, manual_rollover_earliest,
       observe_started_at, observe_next_poll_at, observe_backoff_seconds
FROM RolloverZoneState WHERE zone = ?`
	var r RolloverZoneRow
	var inProg int
	err := kdb.DB.QueryRow(q, zone).Scan(
		&r.Zone,
		&r.LastSubmittedLow, &r.LastSubmittedHigh,
		&r.LastConfirmedLow, &r.LastConfirmedHigh,
		&r.RolloverPhase, &r.RolloverPhaseAt, &inProg,
		&r.ManualRolloverRequestedAt, &r.ManualRolloverEarliest,
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

// setRolloverKeyStandbyAtTx stamps standby_at for one key on an existing TX.
// Called when a SEP key transitions published → standby in a rollover-managed
// zone; drives the oldest-standby selection in AtomicRollover.
func setRolloverKeyStandbyAtTx(tx *Tx, zone string, keyid uint16, at time.Time) error {
	s := at.UTC().Format(time.RFC3339)
	_, err := tx.Exec(`UPDATE RolloverKeyState SET standby_at = ? WHERE zone = ? AND keyid = ?`, s, zone, int(keyid))
	return err
}

// setRolloverKeyActiveAtTx stamps active_at for one key on an existing TX.
// Called when a SEP key transitions standby → active (or the collapsed
// published → active in multi-ds AtomicRollover); drives the rollover_due
// check.
func setRolloverKeyActiveAtTx(tx *Tx, zone string, keyid uint16, at time.Time) error {
	s := at.UTC().Format(time.RFC3339)
	_, err := tx.Exec(`UPDATE RolloverKeyState SET active_at = ? WHERE zone = ? AND keyid = ?`, s, zone, int(keyid))
	return err
}

// nextActiveSeqTx returns the next per-zone active_seq value: MAX(active_seq) + 1
// for the zone, or 0 if no key has ever been active. Used at standby→active
// transitions (AtomicRollover, PromoteStandbyKskIfNoActive) to stamp the
// "n-th active KSK in this zone's history" counter.
//
// active_seq is the operator-facing rollover counter: keys are numbered in
// the order they first became active. Distinct from rollover_index, which
// tracks RolloverKeyState insertion order and is used by the DS-pipeline
// plumbing.
func nextActiveSeqTx(tx *Tx, zone string) (int, error) {
	var max sql.NullInt64
	err := tx.QueryRow(`SELECT MAX(active_seq) FROM RolloverKeyState WHERE zone = ?`, zone).Scan(&max)
	if err != nil {
		return 0, err
	}
	if !max.Valid {
		return 0, nil
	}
	return int(max.Int64) + 1, nil
}

// setRolloverKeyActiveSeqTx stamps active_seq for one key on an existing TX.
// Called immediately after standby→active in AtomicRollover and the bootstrap
// path. Idempotent: if active_seq is already set, this overwrites.
func setRolloverKeyActiveSeqTx(tx *Tx, zone string, keyid uint16, seq int) error {
	_, err := tx.Exec(`UPDATE RolloverKeyState SET active_seq = ? WHERE zone = ? AND keyid = ?`, seq, zone, int(keyid))
	return err
}

// RolloverKeyActiveSeq returns the active_seq for one key, or (-1, nil) if
// the key has never been active (the column is NULL). Used by the
// auto-rollover status CLI for read-only display.
func RolloverKeyActiveSeq(kdb *KeyDB, zone string, keyid uint16) (int, error) {
	var v sql.NullInt64
	err := kdb.DB.QueryRow(`SELECT active_seq FROM RolloverKeyState WHERE zone = ? AND keyid = ?`, zone, int(keyid)).Scan(&v)
	if err == sql.ErrNoRows {
		return -1, nil
	}
	if err != nil {
		return -1, err
	}
	if !v.Valid {
		return -1, nil
	}
	return int(v.Int64), nil
}

// RolloverKeyidsByIndexRange returns the keyids whose rollover_index lies in
// [low, high] (inclusive), ordered by rollover_index ascending. Used by the
// auto-rollover status CLI to translate the submitted/confirmed index ranges
// into operator-meaningful keyids that match the per-key table.
func RolloverKeyidsByIndexRange(kdb *KeyDB, zone string, low, high int64) ([]uint16, error) {
	rows, err := kdb.DB.Query(
		`SELECT keyid FROM RolloverKeyState WHERE zone = ? AND rollover_index BETWEEN ? AND ? ORDER BY rollover_index ASC`,
		zone, low, high)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uint16
	for rows.Next() {
		var k int
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, uint16(k))
	}
	return out, rows.Err()
}

// setRolloverKeyStandbyAt is the non-TX variant for callers outside of
// AtomicRollover (e.g. TransitionRolloverKskDsPublishedToStandby's
// per-key loop).
func setRolloverKeyStandbyAt(kdb *KeyDB, zone string, keyid uint16, at time.Time) error {
	s := at.UTC().Format(time.RFC3339)
	_, err := kdb.DB.Exec(`UPDATE RolloverKeyState SET standby_at = ? WHERE zone = ? AND keyid = ?`, s, zone, int(keyid))
	return err
}

// setRolloverInProgressTx flips RolloverZoneState.rollover_in_progress on an
// existing TX. Set TRUE inside AtomicRollover; cleared when the last retired
// SEP key in the zone reaches removed at the end of pending-child-withdraw.
func setRolloverInProgressTx(tx *Tx, zone string, inProgress bool) error {
	v := 0
	if inProgress {
		v = 1
	}
	_, err := tx.Exec(`UPDATE RolloverZoneState SET rollover_in_progress = ? WHERE zone = ?`, v, zone)
	return err
}

// getRolloverInProgressTx reads rollover_in_progress on an existing TX. Used
// by confirmDSAndAdvanceCreatedKeysTx to route the post-observe phase write
// to either pending-child-withdraw (if a rollover is in flight) or idle.
func getRolloverInProgressTx(tx *Tx, zone string) (bool, error) {
	var v int
	err := tx.QueryRow(`SELECT rollover_in_progress FROM RolloverZoneState WHERE zone = ?`, zone).Scan(&v)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return v != 0, nil
}

// RolloverKeyActiveAt returns the active_at timestamp for one key, or nil if
// unset. Used by rollover_due to determine whether the active KSK has lived
// past policy.ksk.lifetime, and by the auto-rollover status CLI.
func RolloverKeyActiveAt(kdb *KeyDB, zone string, keyid uint16) (*time.Time, error) {
	return readKeyTimestamp(kdb, zone, keyid, "active_at")
}

// RolloverKeyStandbyAt returns the standby_at timestamp, or nil if unset.
func RolloverKeyStandbyAt(kdb *KeyDB, zone string, keyid uint16) (*time.Time, error) {
	return readKeyTimestamp(kdb, zone, keyid, "standby_at")
}

// RolloverKeyDsObservedAt returns the ds_observed_at timestamp, or nil if unset.
func RolloverKeyDsObservedAt(kdb *KeyDB, zone string, keyid uint16) (*time.Time, error) {
	return readKeyTimestamp(kdb, zone, keyid, "ds_observed_at")
}

// RolloverKeyStateAt returns the rollover_state_at timestamp, or nil if unset.
// This is the most recent transition time recorded by the rollover machinery
// for this key — useful as a fallback "current state since" reading.
func RolloverKeyStateAt(kdb *KeyDB, zone string, keyid uint16) (*time.Time, error) {
	return readKeyTimestamp(kdb, zone, keyid, "rollover_state_at")
}

// readKeyTimestamp is the shared body for the per-column timestamp readers.
// Returns (nil, nil) for missing rows / NULL / empty / unparseable values.
func readKeyTimestamp(kdb *KeyDB, zone string, keyid uint16, col string) (*time.Time, error) {
	var s sql.NullString
	err := kdb.DB.QueryRow(
		"SELECT "+col+" FROM RolloverKeyState WHERE zone = ? AND keyid = ?",
		zone, int(keyid)).Scan(&s)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !s.Valid || strings.TrimSpace(s.String) == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(s.String))
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// listRolloverStandbyKeysTx returns (keyid, standby_at) for all SEP keys in
// state=standby for the zone, ordered by standby_at (NULLs last) then keyid.
// Used by AtomicRollover to pick the oldest standby for promotion.
func listRolloverStandbyKeysTx(tx *Tx, zone string) ([]struct {
	KeyID     uint16
	StandbyAt sql.NullString
}, error) {
	rows, err := tx.Query(`
SELECT d.keyid, r.standby_at
FROM DnssecKeyStore d
LEFT JOIN RolloverKeyState r ON r.zone = d.zonename AND r.keyid = d.keyid
WHERE d.zonename = ? AND d.state = ? AND (d.flags & 1) = 1
ORDER BY (r.standby_at IS NULL OR r.standby_at = '') ASC, r.standby_at ASC, d.keyid ASC`,
		zone, DnskeyStateStandby)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []struct {
		KeyID     uint16
		StandbyAt sql.NullString
	}
	for rows.Next() {
		var kid int
		var sa sql.NullString
		if err := rows.Scan(&kid, &sa); err != nil {
			return nil, err
		}
		out = append(out, struct {
			KeyID     uint16
			StandbyAt sql.NullString
		}{KeyID: uint16(kid), StandbyAt: sa})
	}
	return out, rows.Err()
}

// UpsertZoneSigningMaxTTL records the maximum RRset TTL observed during a
// full zone-sign pass. Called at end-of-pass from SignZone. The value is
// reset (not accumulated) per pass so a TTL reduction in the zone takes
// effect after one complete sign cycle. Read by the rollover worker's
// pending-child-withdraw phase to bound wait time by the longest-lived
// RRSIG that could still be cached at resolvers.
func UpsertZoneSigningMaxTTL(kdb *KeyDB, zone string, maxTTL uint32) error {
	zone = strings.TrimSpace(zone)
	if zone == "" {
		return fmt.Errorf("UpsertZoneSigningMaxTTL: empty zone")
	}
	now := time.Now().UTC().Format(time.RFC3339)
	const q = `
INSERT INTO ZoneSigningState (zone, max_observed_ttl, updated_at)
VALUES (?, ?, ?)
ON CONFLICT(zone) DO UPDATE SET
  max_observed_ttl = excluded.max_observed_ttl,
  updated_at = excluded.updated_at`
	_, err := kdb.DB.Exec(q, zone, int64(maxTTL), now)
	return err
}

// LoadZoneSigningMaxTTL returns the most recently persisted max_observed_ttl
// for the zone, or 0 if no row exists yet (e.g. zone has never completed a
// full sign pass since the column was introduced).
func LoadZoneSigningMaxTTL(kdb *KeyDB, zone string) (uint32, error) {
	zone = strings.TrimSpace(zone)
	var v sql.NullInt64
	err := kdb.DB.QueryRow(`SELECT max_observed_ttl FROM ZoneSigningState WHERE zone = ?`, zone).Scan(&v)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !v.Valid {
		return 0, nil
	}
	return uint32(v.Int64), nil
}

// setLastRolloverError stamps last_rollover_error on one key.
func setLastRolloverError(kdb *KeyDB, zone string, keyid uint16, msg string) error {
	_, err := kdb.DB.Exec(`UPDATE RolloverKeyState SET last_rollover_error = ? WHERE zone = ? AND keyid = ?`, msg, zone, int(keyid))
	return err
}

// LoadLastRolloverError returns last_rollover_error for one key (empty
// string if unset or the row doesn't exist). Used by the `auto-rollover
// status` CLI for read-only inspection.
func LoadLastRolloverError(kdb *KeyDB, zone string, keyid uint16) (string, error) {
	var s sql.NullString
	err := kdb.DB.QueryRow(`SELECT last_rollover_error FROM RolloverKeyState WHERE zone = ? AND keyid = ?`, zone, int(keyid)).Scan(&s)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !s.Valid {
		return "", nil
	}
	return s.String, nil
}

// ClearLastRolloverError zeroes last_rollover_error for one key. Used by the
// `rollover reset` CLI to unstick a hard-failed key after operator action.
func ClearLastRolloverError(kdb *KeyDB, zone string, keyid uint16) error {
	res, err := kdb.DB.Exec(`UPDATE RolloverKeyState SET last_rollover_error = NULL WHERE zone = ? AND keyid = ?`, zone, int(keyid))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("no RolloverKeyState row for zone %s keyid %d", zone, keyid)
	}
	return nil
}

// UnstickRollover clears the persisted DS-submitted range on the zone row and
// last_rollover_error on every key row for the zone, in a single transaction.
// Returns the number of key rows whose last_rollover_error was cleared.
//
// Why: observeHardFail leaves last_ds_submitted_index_low/high populated when
// it returns the zone to idle. The idle branch's kskIndexPushNeeded then sees
// the target DS set unchanged from what was last submitted and never re-arms
// a push, leaving the zone permanently stuck even after the operator has
// fixed whatever caused the original observation timeout. UnstickRollover is
// the operator nudge: drop the submitted range so the next idle tick re-arms
// pending-parent-push, and clear stale per-key errors so status output isn't
// misleading.
func UnstickRollover(kdb *KeyDB, zone string) (int, error) {
	zone = strings.TrimSpace(zone)
	if zone == "" {
		return 0, fmt.Errorf("UnstickRollover: empty zone")
	}
	tx, err := kdb.Begin("UnstickRollover")
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	commit := false
	defer func() {
		if !commit {
			tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`UPDATE RolloverZoneState
SET last_ds_submitted_index_low = NULL,
    last_ds_submitted_index_high = NULL
WHERE zone = ?`, zone); err != nil {
		return 0, fmt.Errorf("clear submitted range: %w", err)
	}
	res, err := tx.Exec(`UPDATE RolloverKeyState SET last_rollover_error = NULL WHERE zone = ? AND last_rollover_error IS NOT NULL`, zone)
	if err != nil {
		return 0, fmt.Errorf("clear last_rollover_error: %w", err)
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	commit = true
	return int(n), nil
}

// SetManualRolloverRequest stamps manual_rollover_requested_at = now and
// manual_rollover_earliest = earliest. Called by `rollover asap` after
// ComputeEarliestRollover succeeds.
func SetManualRolloverRequest(kdb *KeyDB, zone string, requestedAt, earliest time.Time) error {
	if err := EnsureRolloverZoneRow(kdb, zone); err != nil {
		return err
	}
	_, err := kdb.DB.Exec(`UPDATE RolloverZoneState
SET manual_rollover_requested_at = ?,
    manual_rollover_earliest = ?
WHERE zone = ?`,
		requestedAt.UTC().Format(time.RFC3339),
		earliest.UTC().Format(time.RFC3339),
		zone)
	return err
}

// ClearManualRolloverRequest nulls both manual_rollover_* columns. Called by
// `rollover cancel` and after a manual-ASAP rollover fires.
func ClearManualRolloverRequest(kdb *KeyDB, zone string) error {
	_, err := kdb.DB.Exec(`UPDATE RolloverZoneState
SET manual_rollover_requested_at = NULL,
    manual_rollover_earliest = NULL
WHERE zone = ?`, zone)
	return err
}

// clearManualRolloverRequestTx is the in-TX variant used inside the rollover
// fire path so the manual_* clear and the AtomicRollover state writes commit
// atomically.
func clearManualRolloverRequestTx(tx *Tx, zone string) error {
	_, err := tx.Exec(`UPDATE RolloverZoneState
SET manual_rollover_requested_at = NULL,
    manual_rollover_earliest = NULL
WHERE zone = ?`, zone)
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
