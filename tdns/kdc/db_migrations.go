/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Temporary database migrations for upgrading existing databases
 * These migrations should be removed once all databases have been upgraded
 */

package kdc

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// migrateAddCompletedAtColumn adds the completed_at column to distribution_records if it doesn't exist
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) migrateAddCompletedAtColumn() error {
	var columnExists bool
	
	if kdc.DBType == "sqlite" {
		// SQLite: Check if column exists using pragma
		var count int
		err := kdc.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('distribution_records') WHERE name='completed_at'").Scan(&count)
		columnExists = (err == nil && count > 0)
	} else {
		// MySQL/MariaDB: Check if column exists by querying information_schema
		var count int
		err := kdc.DB.QueryRow(
			"SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'distribution_records' AND COLUMN_NAME = 'completed_at'",
		).Scan(&count)
		columnExists = (err == nil && count > 0)
	}
	
	if columnExists {
		// Column already exists, nothing to do
		return nil
	}
	
	// Column doesn't exist, add it
	var alterStmt string
	if kdc.DBType == "sqlite" {
		alterStmt = "ALTER TABLE distribution_records ADD COLUMN completed_at DATETIME"
	} else {
		alterStmt = "ALTER TABLE distribution_records ADD COLUMN completed_at TIMESTAMP NULL"
	}
	
	_, err := kdc.DB.Exec(alterStmt)
	if err != nil {
		// Check if error is "duplicate column" (column already exists - race condition)
		if strings.Contains(err.Error(), "duplicate column") || 
		   strings.Contains(err.Error(), "already exists") ||
		   strings.Contains(err.Error(), "Duplicate column name") {
			return nil // Column already exists, that's fine
		}
		return fmt.Errorf("failed to add completed_at column: %v", err)
	}
	log.Printf("KDC: Added completed_at column to distribution_records table")
	return nil
}

// migrateAddCompletedStatus updates the status ENUM/CHECK constraint to include 'completed'
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) migrateAddCompletedStatus() error {
	if kdc.DBType == "sqlite" {
		// SQLite: Check if constraint already allows 'completed' by trying to update a test record
		// We'll check if we can set status to 'completed' on an existing record
		// If it fails, we need to recreate the table
		var testID, originalStatus string
		err := kdc.DB.QueryRow("SELECT id, status FROM distribution_records LIMIT 1").Scan(&testID, &originalStatus)
		if err == nil && testID != "" {
			// Try to update a record to 'completed' to test the constraint
			_, err = kdc.DB.Exec("UPDATE distribution_records SET status = 'completed' WHERE id = ?", testID)
			if err != nil && strings.Contains(err.Error(), "CHECK constraint failed") {
				// Constraint doesn't allow 'completed', need to recreate table
				log.Printf("KDC: Recreating distribution_records table to update CHECK constraint for 'completed' status")
				
				// Create new table with correct constraint
				_, err = kdc.DB.Exec(`
					CREATE TABLE IF NOT EXISTS distribution_records_new (
						id TEXT PRIMARY KEY,
						zone_name TEXT NOT NULL,
						key_id TEXT NOT NULL,
						node_id TEXT,
						encrypted_key BLOB NOT NULL,
						ephemeral_pub_key BLOB NOT NULL,
						created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
						expires_at DATETIME,
						status TEXT NOT NULL DEFAULT 'pending',
						distribution_id TEXT NOT NULL,
						completed_at DATETIME,
						FOREIGN KEY (zone_name) REFERENCES zones(name) ON DELETE CASCADE,
						FOREIGN KEY (key_id) REFERENCES dnssec_keys(id) ON DELETE CASCADE,
						FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
						CHECK (status IN ('pending', 'delivered', 'active', 'revoked', 'completed'))
					)`)
				if err != nil {
					return fmt.Errorf("failed to create new distribution_records table: %v", err)
				}
				
				// Copy data
				_, err = kdc.DB.Exec(`
					INSERT INTO distribution_records_new 
					SELECT id, zone_name, key_id, node_id, encrypted_key, ephemeral_pub_key, 
					       created_at, expires_at, status, distribution_id, completed_at
					FROM distribution_records`)
				if err != nil {
					return fmt.Errorf("failed to copy data to new table: %v", err)
				}
				
				// Drop old table
				_, err = kdc.DB.Exec("DROP TABLE distribution_records")
				if err != nil {
					return fmt.Errorf("failed to drop old table: %v", err)
				}
				
				// Rename new table
				_, err = kdc.DB.Exec("ALTER TABLE distribution_records_new RENAME TO distribution_records")
				if err != nil {
					return fmt.Errorf("failed to rename new table: %v", err)
				}
				
				// Recreate indexes
				indexes := []string{
					"CREATE INDEX IF NOT EXISTS idx_distribution_records_zone_name ON distribution_records(zone_name)",
					"CREATE INDEX IF NOT EXISTS idx_distribution_records_key_id ON distribution_records(key_id)",
					"CREATE INDEX IF NOT EXISTS idx_distribution_records_node_id ON distribution_records(node_id)",
					"CREATE INDEX IF NOT EXISTS idx_distribution_records_status ON distribution_records(status)",
					"CREATE INDEX IF NOT EXISTS idx_distribution_records_distribution_id ON distribution_records(distribution_id)",
					"CREATE INDEX IF NOT EXISTS idx_distribution_records_completed_at ON distribution_records(completed_at)",
				}
				for _, idxStmt := range indexes {
					if _, err := kdc.DB.Exec(idxStmt); err != nil {
						log.Printf("KDC: Warning: Failed to recreate index: %v", err)
					}
				}
				
				log.Printf("KDC: Successfully updated distribution_records table CHECK constraint")
			} else if err == nil {
				// Update succeeded, revert it to original status
				_, _ = kdc.DB.Exec("UPDATE distribution_records SET status = ? WHERE id = ?", originalStatus, testID)
			}
		}
		// If no records exist or constraint already allows 'completed', nothing to do
		return nil
	} else {
		// MySQL/MariaDB: Alter ENUM to include 'completed'
		// Check if 'completed' is already in the ENUM
		var enumValues string
		err := kdc.DB.QueryRow(
			"SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'distribution_records' AND COLUMN_NAME = 'status'",
		).Scan(&enumValues)
		if err != nil {
			return fmt.Errorf("failed to check status ENUM: %v", err)
		}
		
		if !strings.Contains(enumValues, "completed") {
			// Update ENUM to include 'completed'
			_, err = kdc.DB.Exec(
				"ALTER TABLE distribution_records MODIFY COLUMN status ENUM('pending', 'delivered', 'active', 'revoked', 'completed') NOT NULL DEFAULT 'pending'",
			)
			if err != nil {
				return fmt.Errorf("failed to update status ENUM: %v", err)
			}
			log.Printf("KDC: Updated status ENUM to include 'completed'")
		}
		return nil
	}
}

// migrateAddActiveDistState updates the state ENUM/CHECK constraint to include 'active_dist'
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) migrateAddActiveDistState() error {
	if kdc.DBType == "sqlite" {
		// SQLite: Check if constraint already allows 'active_dist' by trying to update a test record
		var testID, originalState string
		err := kdc.DB.QueryRow("SELECT id, state FROM dnssec_keys LIMIT 1").Scan(&testID, &originalState)
		if err == nil && testID != "" {
			// Try to update a record to 'active_dist' to test the constraint
			_, err = kdc.DB.Exec("UPDATE dnssec_keys SET state = 'active_dist' WHERE id = ?", testID)
			if err != nil && strings.Contains(err.Error(), "CHECK constraint failed") {
				// Constraint doesn't allow 'active_dist', need to recreate table
				log.Printf("KDC: Recreating dnssec_keys table to update CHECK constraint for 'active_dist' state")
				
				// Create new table with correct constraint
				_, err = kdc.DB.Exec(`
					CREATE TABLE IF NOT EXISTS dnssec_keys_new (
						id TEXT PRIMARY KEY,
						zone_name TEXT NOT NULL,
						key_type TEXT NOT NULL,
						key_id INTEGER NOT NULL,
						algorithm INTEGER NOT NULL,
						flags INTEGER NOT NULL,
						public_key TEXT NOT NULL,
						private_key BLOB NOT NULL,
						state TEXT NOT NULL DEFAULT 'created',
						created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
						published_at DATETIME,
						activated_at DATETIME,
						retired_at DATETIME,
						comment TEXT,
						FOREIGN KEY (zone_name) REFERENCES zones(name) ON DELETE CASCADE,
						CHECK (key_type IN ('KSK', 'ZSK', 'CSK')),
						CHECK (state IN ('created', 'published', 'standby', 'active', 'active_dist', 'distributed', 'edgesigner', 'retired', 'removed', 'revoked'))
					)`)
				if err != nil {
					return fmt.Errorf("failed to create new dnssec_keys table: %v", err)
				}
				
				// Copy data
				_, err = kdc.DB.Exec(`
					INSERT INTO dnssec_keys_new 
					SELECT id, zone_name, key_type, key_id, algorithm, flags, public_key, private_key, 
					       state, created_at, published_at, activated_at, retired_at, comment
					FROM dnssec_keys`)
				if err != nil {
					return fmt.Errorf("failed to copy data to new table: %v", err)
				}
				
				// Drop old table
				_, err = kdc.DB.Exec("DROP TABLE dnssec_keys")
				if err != nil {
					return fmt.Errorf("failed to drop old table: %v", err)
				}
				
				// Rename new table
				_, err = kdc.DB.Exec("ALTER TABLE dnssec_keys_new RENAME TO dnssec_keys")
				if err != nil {
					return fmt.Errorf("failed to rename new table: %v", err)
				}
				
				// Recreate indexes
				indexes := []string{
					"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_zone_name ON dnssec_keys(zone_name)",
					"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_key_type ON dnssec_keys(key_type)",
					"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_state ON dnssec_keys(state)",
					"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_zone_key_type_state ON dnssec_keys(zone_name, key_type, state)",
				}
				for _, idxStmt := range indexes {
					if _, err := kdc.DB.Exec(idxStmt); err != nil {
						log.Printf("KDC: Warning: Failed to recreate index: %v", err)
					}
				}
				
				log.Printf("KDC: Successfully updated dnssec_keys table CHECK constraint")
			} else if err == nil {
				// Update succeeded, revert it to original state
				_, _ = kdc.DB.Exec("UPDATE dnssec_keys SET state = ? WHERE id = ?", originalState, testID)
			}
		}
		// If no records exist or constraint already allows 'active_dist', nothing to do
		return nil
	} else {
		// MySQL/MariaDB: Alter ENUM to include 'active_dist'
		// Check if 'active_dist' is already in the ENUM
		var enumValues string
		err := kdc.DB.QueryRow(
			"SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'dnssec_keys' AND COLUMN_NAME = 'state'",
		).Scan(&enumValues)
		if err != nil {
			return fmt.Errorf("failed to check state ENUM: %v", err)
		}
		
		if !strings.Contains(enumValues, "active_dist") {
			// Update ENUM to include 'active_dist'
			_, err = kdc.DB.Exec(
				"ALTER TABLE dnssec_keys MODIFY COLUMN state ENUM('created', 'published', 'standby', 'active', 'active_dist', 'distributed', 'edgesigner', 'retired', 'removed', 'revoked') NOT NULL DEFAULT 'created'",
			)
			if err != nil {
				return fmt.Errorf("failed to update state ENUM: %v", err)
			}
			log.Printf("KDC: Updated state ENUM to include 'active_dist'")
		}
		return nil
	}
}

// migrateAddActiveCEState updates the state ENUM/CHECK constraint to include 'active_ce'
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) migrateAddActiveCEState() error {
	if kdc.DBType == "sqlite" {
		// SQLite: Check if constraint already allows 'active_ce' by trying to update a test record
		var testID, originalState string
		err := kdc.DB.QueryRow("SELECT id, state FROM dnssec_keys LIMIT 1").Scan(&testID, &originalState)
		if err == nil && testID != "" {
			// Try to update a record to 'active_ce' to test the constraint
			_, err = kdc.DB.Exec("UPDATE dnssec_keys SET state = 'active_ce' WHERE id = ?", testID)
			if err != nil && strings.Contains(err.Error(), "CHECK constraint failed") {
				// Constraint doesn't allow 'active_ce', need to recreate table
				log.Printf("KDC: Recreating dnssec_keys table to update CHECK constraint for 'active_ce' state")
				
				// Create new table with correct constraint
				_, err = kdc.DB.Exec(`
					CREATE TABLE IF NOT EXISTS dnssec_keys_new (
						id TEXT PRIMARY KEY,
						zone_name TEXT NOT NULL,
						key_type TEXT NOT NULL,
						key_id INTEGER NOT NULL,
						algorithm INTEGER NOT NULL,
						flags INTEGER NOT NULL,
						public_key TEXT NOT NULL,
						private_key BLOB NOT NULL,
						state TEXT NOT NULL DEFAULT 'created',
						created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
						published_at DATETIME,
						activated_at DATETIME,
						retired_at DATETIME,
						comment TEXT,
						FOREIGN KEY (zone_name) REFERENCES zones(name) ON DELETE CASCADE,
						CHECK (key_type IN ('KSK', 'ZSK', 'CSK')),
						CHECK (state IN ('created', 'published', 'standby', 'active', 'active_dist', 'active_ce', 'distributed', 'edgesigner', 'retired', 'removed', 'revoked'))
					)`)
				if err != nil {
					return fmt.Errorf("failed to create new dnssec_keys table: %v", err)
				}
				
				// Copy data
				_, err = kdc.DB.Exec(`
					INSERT INTO dnssec_keys_new 
					SELECT id, zone_name, key_type, key_id, algorithm, flags, public_key, private_key, 
					       state, created_at, published_at, activated_at, retired_at, comment
					FROM dnssec_keys`)
				if err != nil {
					return fmt.Errorf("failed to copy data to new table: %v", err)
				}
				
				// Drop old table
				_, err = kdc.DB.Exec("DROP TABLE dnssec_keys")
				if err != nil {
					return fmt.Errorf("failed to drop old table: %v", err)
				}
				
				// Rename new table
				_, err = kdc.DB.Exec("ALTER TABLE dnssec_keys_new RENAME TO dnssec_keys")
				if err != nil {
					return fmt.Errorf("failed to rename new table: %v", err)
				}
				
				// Recreate indexes
				indexes := []string{
					"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_zone_name ON dnssec_keys(zone_name)",
					"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_key_type ON dnssec_keys(key_type)",
					"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_state ON dnssec_keys(state)",
					"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_zone_key_type_state ON dnssec_keys(zone_name, key_type, state)",
				}
				for _, idxStmt := range indexes {
					if _, err := kdc.DB.Exec(idxStmt); err != nil {
						log.Printf("KDC: Warning: Failed to recreate index: %v", err)
					}
				}
				
				log.Printf("KDC: Successfully updated dnssec_keys table CHECK constraint for 'active_ce'")
			} else if err == nil {
				// Update succeeded, revert it to original state
				_, _ = kdc.DB.Exec("UPDATE dnssec_keys SET state = ? WHERE id = ?", originalState, testID)
			}
		}
		// If no records exist or constraint already allows 'active_ce', nothing to do
		return nil
	} else {
		// MySQL/MariaDB: Alter ENUM to include 'active_ce'
		// Check if 'active_ce' is already in the ENUM
		var enumValues string
		err := kdc.DB.QueryRow(
			"SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'dnssec_keys' AND COLUMN_NAME = 'state'",
		).Scan(&enumValues)
		if err != nil {
			return fmt.Errorf("failed to check state ENUM: %v", err)
		}
		
		if !strings.Contains(enumValues, "active_ce") {
			// Update ENUM to include 'active_ce'
			_, err = kdc.DB.Exec(
				"ALTER TABLE dnssec_keys MODIFY COLUMN state ENUM('created', 'published', 'standby', 'active', 'active_dist', 'active_ce', 'distributed', 'edgesigner', 'retired', 'removed', 'revoked') NOT NULL DEFAULT 'created'",
			)
			if err != nil {
				return fmt.Errorf("failed to update state ENUM: %v", err)
			}
			log.Printf("KDC: Updated state ENUM to include 'active_ce'")
		}
		return nil
	}
}

// markOldCompletedDistributions marks old distributions as complete if they have all confirmations
// This handles distributions that were completed before we added completion tracking
// TEMPORARY: Remove this migration once all databases have been upgraded
func (kdc *KdcDB) markOldCompletedDistributions() {
	// Find distributions that:
	// 1. Are not already marked as completed
	// 2. Are older than 1 minute (to avoid race conditions)
	// 3. Have all nodes confirmed
	rows, err := kdc.DB.Query(
		`SELECT DISTINCT dr.distribution_id, dr.zone_name
		 FROM distribution_records dr
		 WHERE dr.status != 'completed'
		   AND dr.created_at < datetime('now', '-1 minute')
		   AND NOT EXISTS (
		     SELECT 1 FROM distribution_records dr2
		     WHERE dr2.distribution_id = dr.distribution_id
		       AND dr2.status = 'completed'
		   )`,
	)
	if err != nil {
		log.Printf("KDC: Warning: Failed to query old distributions: %v", err)
		return
	}
	defer rows.Close()

	var distributionsToComplete []struct {
		distID   string
		zoneName string
	}

	for rows.Next() {
		var distID, zoneName string
		if err := rows.Scan(&distID, &zoneName); err != nil {
			continue
		}

		// Check if all nodes have confirmed
		allConfirmed, err := kdc.CheckAllNodesConfirmed(distID, zoneName)
		if err == nil && allConfirmed {
			distributionsToComplete = append(distributionsToComplete, struct {
				distID   string
				zoneName string
			}{distID, zoneName})
		}
	}

	// Mark distributions as complete with retry logic to handle SQLite locking
	for _, dist := range distributionsToComplete {
		maxRetries := 3
		retryDelay := 100 * time.Millisecond
		
		for attempt := 0; attempt < maxRetries; attempt++ {
			if attempt > 0 {
				// Exponential backoff
				time.Sleep(retryDelay * time.Duration(1<<uint(attempt-1)))
			}
			
			err := kdc.MarkDistributionComplete(dist.distID)
			if err == nil {
				log.Printf("KDC: Marked old distribution %s as complete (had all confirmations)", dist.distID)
				break
			}
			
			// If it's a locking error and we have retries left, try again
			if strings.Contains(err.Error(), "database is locked") && attempt < maxRetries-1 {
				continue
			}
			
			// Final attempt failed or non-locking error
			log.Printf("KDC: Warning: Failed to mark old distribution %s as complete: %v", dist.distID, err)
			break
		}
	}
}

