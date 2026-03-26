/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Data access layer for combiner edit management tables.
 * Provides CRUD operations for pending, approved, and rejected edits.
 */

package tdns

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// PendingEditRecord represents a row in the CombinerPendingEdits table.
type PendingEditRecord struct {
	EditID         int                 `json:"edit_id"`
	Zone           string              `json:"zone"`
	SenderID       string              `json:"sender_id"`
	DeliveredBy    string              `json:"delivered_by"`
	DistributionID string              `json:"distribution_id"`
	Records        map[string][]string `json:"records"`
	ReceivedAt     time.Time           `json:"received_at"`
}

// ApprovedEditRecord represents a row in the CombinerApprovedEdits table.
type ApprovedEditRecord struct {
	EditID         int                 `json:"edit_id"`
	Zone           string              `json:"zone"`
	SenderID       string              `json:"sender_id"`
	DistributionID string              `json:"distribution_id"`
	Records        map[string][]string `json:"records"`
	ReceivedAt     time.Time           `json:"received_at"`
	ApprovedAt     time.Time           `json:"approved_at"`
}

// RejectedEditRecord represents a row in the CombinerRejectedEdits table.
type RejectedEditRecord struct {
	EditID         int                 `json:"edit_id"`
	Zone           string              `json:"zone"`
	SenderID       string              `json:"sender_id"`
	DistributionID string              `json:"distribution_id"`
	Records        map[string][]string `json:"records"`
	ReceivedAt     time.Time           `json:"received_at"`
	RejectedAt     time.Time           `json:"rejected_at"`
	Reason         string              `json:"reason"`
}

// NextEditID returns the next available edit ID across all three tables.
func NextEditID(kdb *KeyDB) (int, error) {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	var maxID sql.NullInt64
	err := kdb.DB.QueryRow(`
		SELECT MAX(edit_id) FROM (
			SELECT edit_id FROM CombinerPendingEdits
			UNION ALL
			SELECT edit_id FROM CombinerApprovedEdits
			UNION ALL
			SELECT edit_id FROM CombinerRejectedEdits
		)
	`).Scan(&maxID)
	if err != nil {
		return 1, err
	}

	if !maxID.Valid {
		return 1, nil
	}
	return int(maxID.Int64) + 1, nil
}

// SavePendingEdit inserts a new pending edit.
func SavePendingEdit(kdb *KeyDB, rec *PendingEditRecord) error {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	recordsJSON, err := json.Marshal(rec.Records)
	if err != nil {
		return fmt.Errorf("failed to marshal records: %w", err)
	}

	_, err = kdb.DB.Exec(`
		INSERT INTO CombinerPendingEdits (edit_id, zone, sender_id, delivered_by, distribution_id, records_json, received_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, rec.EditID, rec.Zone, rec.SenderID, rec.DeliveredBy, rec.DistributionID, string(recordsJSON), rec.ReceivedAt.Unix())
	return err
}

// ListPendingEdits returns all pending edits for a zone.
func ListPendingEdits(kdb *KeyDB, zone string) ([]*PendingEditRecord, error) {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	rows, err := kdb.DB.Query(`
		SELECT edit_id, zone, sender_id, delivered_by, distribution_id, records_json, received_at
		FROM CombinerPendingEdits WHERE zone = ? ORDER BY edit_id
	`, zone)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*PendingEditRecord
	for rows.Next() {
		rec := &PendingEditRecord{}
		var recordsJSON string
		var receivedAt int64
		if err := rows.Scan(&rec.EditID, &rec.Zone, &rec.SenderID, &rec.DeliveredBy, &rec.DistributionID, &recordsJSON, &receivedAt); err != nil {
			return nil, err
		}
		rec.ReceivedAt = time.Unix(receivedAt, 0)
		if err := json.Unmarshal([]byte(recordsJSON), &rec.Records); err != nil {
			return nil, fmt.Errorf("failed to unmarshal records for edit %d: %w", rec.EditID, err)
		}
		result = append(result, rec)
	}
	return result, rows.Err()
}

// GetPendingEdit retrieves a single pending edit by edit_id.
func GetPendingEdit(kdb *KeyDB, editID int) (*PendingEditRecord, error) {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	rec := &PendingEditRecord{}
	var recordsJSON string
	var receivedAt int64

	err := kdb.DB.QueryRow(`
		SELECT edit_id, zone, sender_id, delivered_by, distribution_id, records_json, received_at
		FROM CombinerPendingEdits WHERE edit_id = ?
	`, editID).Scan(&rec.EditID, &rec.Zone, &rec.SenderID, &rec.DeliveredBy, &rec.DistributionID, &recordsJSON, &receivedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("pending edit #%d not found", editID)
		}
		return nil, err
	}

	rec.ReceivedAt = time.Unix(receivedAt, 0)
	if err := json.Unmarshal([]byte(recordsJSON), &rec.Records); err != nil {
		return nil, fmt.Errorf("failed to unmarshal records for edit %d: %w", rec.EditID, err)
	}
	return rec, nil
}

// ApprovePendingEdit moves a pending edit to the approved table.
// Returns the original pending edit data for processing.
func ApprovePendingEdit(kdb *KeyDB, editID int) (*PendingEditRecord, error) {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	tx, err := kdb.DB.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Read the pending edit
	rec := &PendingEditRecord{}
	var recordsJSON string
	var receivedAt int64

	err = tx.QueryRow(`
		SELECT edit_id, zone, sender_id, delivered_by, distribution_id, records_json, received_at
		FROM CombinerPendingEdits WHERE edit_id = ?
	`, editID).Scan(&rec.EditID, &rec.Zone, &rec.SenderID, &rec.DeliveredBy, &rec.DistributionID, &recordsJSON, &receivedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("pending edit #%d not found", editID)
		}
		return nil, err
	}

	rec.ReceivedAt = time.Unix(receivedAt, 0)
	if err := json.Unmarshal([]byte(recordsJSON), &rec.Records); err != nil {
		return nil, fmt.Errorf("failed to unmarshal records: %w", err)
	}

	// Insert into approved table
	now := time.Now().Unix()
	_, err = tx.Exec(`
		INSERT INTO CombinerApprovedEdits (edit_id, zone, sender_id, distribution_id, records_json, received_at, approved_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, rec.EditID, rec.Zone, rec.SenderID, rec.DistributionID, recordsJSON, receivedAt, now)
	if err != nil {
		return nil, fmt.Errorf("failed to insert into approved: %w", err)
	}

	// Delete from pending table
	_, err = tx.Exec(`DELETE FROM CombinerPendingEdits WHERE edit_id = ?`, editID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete from pending: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit: %w", err)
	}

	return rec, nil
}

// RejectPendingEdit moves a pending edit to the rejected table with a reason.
// Returns the original pending edit data for sending rejection confirmation.
func RejectPendingEdit(kdb *KeyDB, editID int, reason string) (*PendingEditRecord, error) {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	tx, err := kdb.DB.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Read the pending edit
	rec := &PendingEditRecord{}
	var recordsJSON string
	var receivedAt int64

	err = tx.QueryRow(`
		SELECT edit_id, zone, sender_id, delivered_by, distribution_id, records_json, received_at
		FROM CombinerPendingEdits WHERE edit_id = ?
	`, editID).Scan(&rec.EditID, &rec.Zone, &rec.SenderID, &rec.DeliveredBy, &rec.DistributionID, &recordsJSON, &receivedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("pending edit #%d not found", editID)
		}
		return nil, err
	}

	rec.ReceivedAt = time.Unix(receivedAt, 0)
	if err := json.Unmarshal([]byte(recordsJSON), &rec.Records); err != nil {
		return nil, fmt.Errorf("failed to unmarshal records: %w", err)
	}

	// Insert into rejected table
	now := time.Now().Unix()
	_, err = tx.Exec(`
		INSERT INTO CombinerRejectedEdits (edit_id, zone, sender_id, distribution_id, records_json, received_at, rejected_at, reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, rec.EditID, rec.Zone, rec.SenderID, rec.DistributionID, recordsJSON, receivedAt, now, reason)
	if err != nil {
		return nil, fmt.Errorf("failed to insert into rejected: %w", err)
	}

	// Delete from pending table
	_, err = tx.Exec(`DELETE FROM CombinerPendingEdits WHERE edit_id = ?`, editID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete from pending: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit: %w", err)
	}

	return rec, nil
}

// ResolvePendingEdit removes a pending edit and writes the approved and rejected
// portions to their respective tables. This correctly handles partial results
// where some records were applied and others were rejected by policy.
//
// approvedRecords: owner→[]rrstring for records that were applied or removed
// rejectedRecords: owner→[]rrstring for records that were rejected
// reason: rejection reason (used for all rejected records)
func ResolvePendingEdit(kdb *KeyDB, editID int, approvedRecords, rejectedRecords map[string][]string, reason string) error {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	tx, err := kdb.DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Read the pending edit to get metadata
	var zone, senderID, distributionID string
	var receivedAt int64
	err = tx.QueryRow(`
		SELECT zone, sender_id, distribution_id, received_at
		FROM CombinerPendingEdits WHERE edit_id = ?
	`, editID).Scan(&zone, &senderID, &distributionID, &receivedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("pending edit #%d not found", editID)
		}
		return err
	}

	now := time.Now().Unix()

	// Write approved portion (if any)
	if len(approvedRecords) > 0 {
		approvedJSON, err := json.Marshal(approvedRecords)
		if err != nil {
			return fmt.Errorf("failed to marshal approved records: %w", err)
		}
		_, err = tx.Exec(`
			INSERT INTO CombinerApprovedEdits (edit_id, zone, sender_id, distribution_id, records_json, received_at, approved_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
		`, editID, zone, senderID, distributionID, string(approvedJSON), receivedAt, now)
		if err != nil {
			return fmt.Errorf("failed to insert approved portion: %w", err)
		}
	}

	// Write rejected portion (if any) — uses a separate edit_id
	if len(rejectedRecords) > 0 {
		// Get a new edit_id for the rejected portion
		var maxID sql.NullInt64
		err := tx.QueryRow(`
			SELECT MAX(edit_id) FROM (
				SELECT edit_id FROM CombinerPendingEdits
				UNION ALL
				SELECT edit_id FROM CombinerApprovedEdits
				UNION ALL
				SELECT edit_id FROM CombinerRejectedEdits
			)
		`).Scan(&maxID)
		if err != nil {
			return fmt.Errorf("failed to query max edit_id for rejected portion: %w", err)
		}
		rejEditID := editID + 1
		if maxID.Valid && int(maxID.Int64) >= rejEditID {
			rejEditID = int(maxID.Int64) + 1
		}

		rejectedJSON, err := json.Marshal(rejectedRecords)
		if err != nil {
			return fmt.Errorf("failed to marshal rejected records: %w", err)
		}
		_, err = tx.Exec(`
			INSERT INTO CombinerRejectedEdits (edit_id, zone, sender_id, distribution_id, records_json, received_at, rejected_at, reason)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, rejEditID, zone, senderID, distributionID, string(rejectedJSON), receivedAt, now, reason)
		if err != nil {
			return fmt.Errorf("failed to insert rejected portion: %w", err)
		}
	}

	// Delete from pending
	_, err = tx.Exec(`DELETE FROM CombinerPendingEdits WHERE edit_id = ?`, editID)
	if err != nil {
		return fmt.Errorf("failed to delete from pending: %w", err)
	}

	return tx.Commit()
}

// ListRejectedEdits returns all rejected edits for a zone.
func ListRejectedEdits(kdb *KeyDB, zone string) ([]*RejectedEditRecord, error) {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	rows, err := kdb.DB.Query(`
		SELECT edit_id, zone, sender_id, distribution_id, records_json, received_at, rejected_at, reason
		FROM CombinerRejectedEdits WHERE zone = ? ORDER BY edit_id
	`, zone)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*RejectedEditRecord
	for rows.Next() {
		rec := &RejectedEditRecord{}
		var recordsJSON string
		var receivedAt, rejectedAt int64
		if err := rows.Scan(&rec.EditID, &rec.Zone, &rec.SenderID, &rec.DistributionID, &recordsJSON, &receivedAt, &rejectedAt, &rec.Reason); err != nil {
			return nil, err
		}
		rec.ReceivedAt = time.Unix(receivedAt, 0)
		rec.RejectedAt = time.Unix(rejectedAt, 0)
		if err := json.Unmarshal([]byte(recordsJSON), &rec.Records); err != nil {
			return nil, fmt.Errorf("failed to unmarshal records for edit %d: %w", rec.EditID, err)
		}
		result = append(result, rec)
	}
	return result, rows.Err()
}

// ListApprovedEdits returns all approved edits, optionally filtered by zone.
// If zone is empty, returns all approved edits across all zones.
func ListApprovedEdits(kdb *KeyDB, zone string) ([]*ApprovedEditRecord, error) {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	var rows *sql.Rows
	var err error

	if zone != "" {
		rows, err = kdb.DB.Query(`
			SELECT edit_id, zone, sender_id, distribution_id, records_json, received_at, approved_at
			FROM CombinerApprovedEdits WHERE zone = ? ORDER BY edit_id
		`, zone)
	} else {
		rows, err = kdb.DB.Query(`
			SELECT edit_id, zone, sender_id, distribution_id, records_json, received_at, approved_at
			FROM CombinerApprovedEdits ORDER BY edit_id
		`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*ApprovedEditRecord
	for rows.Next() {
		rec := &ApprovedEditRecord{}
		var recordsJSON string
		var receivedAt, approvedAt int64
		if err := rows.Scan(&rec.EditID, &rec.Zone, &rec.SenderID, &rec.DistributionID, &recordsJSON, &receivedAt, &approvedAt); err != nil {
			return nil, err
		}
		rec.ReceivedAt = time.Unix(receivedAt, 0)
		rec.ApprovedAt = time.Unix(approvedAt, 0)
		if err := json.Unmarshal([]byte(recordsJSON), &rec.Records); err != nil {
			return nil, fmt.Errorf("failed to unmarshal records for edit %d: %w", rec.EditID, err)
		}
		result = append(result, rec)
	}
	return result, rows.Err()
}

// ClearPendingEdits deletes rows from CombinerPendingEdits.
// If zone is empty, all rows are deleted; otherwise only rows for that zone.
func ClearPendingEdits(kdb *KeyDB, zone string) (int64, error) {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	var result sql.Result
	var err error
	if zone == "" {
		result, err = kdb.DB.Exec(`DELETE FROM CombinerPendingEdits`)
	} else {
		result, err = kdb.DB.Exec(`DELETE FROM CombinerPendingEdits WHERE zone=?`, zone)
	}
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ClearApprovedEdits deletes rows from CombinerApprovedEdits.
// If zone is empty, all rows are deleted; otherwise only rows for that zone.
func ClearApprovedEdits(kdb *KeyDB, zone string) (int64, error) {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	var result sql.Result
	var err error
	if zone == "" {
		result, err = kdb.DB.Exec(`DELETE FROM CombinerApprovedEdits`)
	} else {
		result, err = kdb.DB.Exec(`DELETE FROM CombinerApprovedEdits WHERE zone=?`, zone)
	}
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ClearRejectedEdits deletes rows from CombinerRejectedEdits.
// If zone is empty, all rows are deleted; otherwise only rows for that zone.
func ClearRejectedEdits(kdb *KeyDB, zone string) (int64, error) {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	var result sql.Result
	var err error
	if zone == "" {
		result, err = kdb.DB.Exec(`DELETE FROM CombinerRejectedEdits`)
	} else {
		result, err = kdb.DB.Exec(`DELETE FROM CombinerRejectedEdits WHERE zone=?`, zone)
	}
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ClearContributions deletes rows from CombinerContributions.
// If zone is empty, all rows are deleted; otherwise only rows for that zone.
func ClearContributions(kdb *KeyDB, zone string) (int64, error) {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	var result sql.Result
	var err error
	if zone == "" {
		result, err = kdb.DB.Exec(`DELETE FROM CombinerContributions`)
	} else {
		result, err = kdb.DB.Exec(`DELETE FROM CombinerContributions WHERE zone=?`, zone)
	}
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
