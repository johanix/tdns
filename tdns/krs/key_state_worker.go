/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Background worker for automatic DNSSEC key state transitions in KRS
 */

package krs

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"
)

// KeyStateWorker runs periodic checks for automatic state transitions
func KeyStateWorker(ctx context.Context, krsDB *KrsDB) error {
	ticker := time.NewTicker(1 * time.Minute) // Check every minute
	defer ticker.Stop()

	log.Printf("KRS: KeyStateWorker started (check interval: 1 minute)")

	for {
		select {
		case <-ctx.Done():
			log.Printf("KRS: KeyStateWorker stopping (context cancelled)")
			return nil
		case <-ticker.C:
			if err := checkAndTransitionKeys(krsDB); err != nil {
				log.Printf("KRS: Error in key state transition check: %v", err)
			}
		}
	}
}

// checkAndTransitionKeys checks for keys that need automatic state transitions
func checkAndTransitionKeys(krsDB *KrsDB) error {
	now := time.Now()

	// Get all keys in "retired" state
	retiredKeys, err := krsDB.GetKeysByState("retired")
	if err != nil {
		log.Printf("KRS: Error getting retired keys: %v", err)
		return err
	}

	// Check each retired key to see if it should transition to "removed"
	for _, key := range retiredKeys {
		if key.RetiredAt == nil {
			log.Printf("KRS: Warning: Key %s is in retired state but has no retired_at timestamp", key.ID)
			continue
		}

		// Parse retire_time from key (duration string from KDC, e.g., "168h0m0s")
		if key.RetireTime == "" {
			log.Printf("KRS: Warning: Key %s has no retire_time configured, skipping transition to removed", key.ID)
			continue
		}

		retireDuration, err := time.ParseDuration(key.RetireTime)
		if err != nil {
			log.Printf("KRS: Warning: Failed to parse retire_time '%s' for key %s: %v", key.RetireTime, key.ID, err)
			continue
		}

		elapsed := now.Sub(*key.RetiredAt)
		if elapsed >= retireDuration {
			log.Printf("KRS: Auto-transitioning key %s from retired to removed (elapsed: %v, retire_time: %v)", key.ID, elapsed, retireDuration)
			if err := krsDB.UpdateReceivedKeyState(key.ID, "removed", key.ActivatedAt, key.RetiredAt); err != nil {
				log.Printf("KRS: Error transitioning key %s: %v", key.ID, err)
			} else {
				log.Printf("KRS: Successfully transitioned key %s to removed", key.ID)
			}
		}
	}

	return nil
}

// GetKeysByState retrieves keys in a specific state
func (krs *KrsDB) GetKeysByState(state string) ([]*ReceivedKey, error) {
	rows, err := krs.DB.Query(
		`SELECT id, zone_name, key_id, key_type, algorithm, flags, public_key, private_key, 
			state, received_at, activated_at, retired_at, distribution_id, comment, retire_time
			FROM received_keys WHERE state = ? ORDER BY received_at`,
		state,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query keys by state: %v", err)
	}
	defer rows.Close()

	var keys []*ReceivedKey
	for rows.Next() {
		key := &ReceivedKey{}
		var activatedAt, retiredAt sql.NullTime
		var retireTime sql.NullString

		if err := rows.Scan(
			&key.ID, &key.ZoneName, &key.KeyID, &key.KeyType, &key.Algorithm, &key.Flags,
			&key.PublicKey, &key.PrivateKey, &key.State, &key.ReceivedAt,
			&activatedAt, &retiredAt, &key.DistributionID, &key.Comment, &retireTime,
		); err != nil {
			return nil, fmt.Errorf("failed to scan received key: %v", err)
		}

		if activatedAt.Valid {
			key.ActivatedAt = &activatedAt.Time
		}
		if retiredAt.Valid {
			key.RetiredAt = &retiredAt.Time
		}
		if retireTime.Valid {
			key.RetireTime = retireTime.String
		}

		keys = append(keys, key)
	}

	return keys, rows.Err()
}

// DeleteKeysByState deletes all keys in the specified state
// If zoneName is provided, only deletes keys for that zone; otherwise deletes for all zones
// Returns the number of keys deleted
func (krs *KrsDB) DeleteKeysByState(state string, zoneName string) (int64, error) {
	var result sql.Result
	var err error

	if zoneName != "" {
		result, err = krs.DB.Exec(
			`DELETE FROM received_keys WHERE state = ? AND zone_name = ?`,
			state, zoneName,
		)
	} else {
		result, err = krs.DB.Exec(
			`DELETE FROM received_keys WHERE state = ?`,
			state,
		)
	}
	if err != nil {
		return 0, fmt.Errorf("failed to delete keys by state: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %v", err)
	}

	return rowsAffected, nil
}

