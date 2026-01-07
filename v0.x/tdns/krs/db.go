/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Database schema and operations for tdns-krs
 * Uses SQLite for edge nodes
 */

package krs

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// KrsDB represents the KRS database connection
type KrsDB struct {
	DB *sql.DB
}

// NewKrsDB creates a new KRS database connection
// dsn should be a SQLite file path
func NewKrsDB(dsn string) (*KrsDB, error) {
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}

	krs := &KrsDB{
		DB: db,
	}

	// Initialize schema
	if err := krs.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %v", err)
	}

	// Migrate: Add retire_time column and 'removed' state if needed
	if err := krs.migrateAddRetireTimeAndRemovedState(); err != nil {
		log.Printf("KRS: Warning: Failed to migrate retire_time column and removed state: %v", err)
	}

	return krs, nil
}

// initSchema creates the database tables if they don't exist
func (krs *KrsDB) initSchema() error {
	schema := []string{
		// Received keys table
		`CREATE TABLE IF NOT EXISTS received_keys (
			id TEXT PRIMARY KEY,
			zone_name TEXT NOT NULL,
			key_id INTEGER NOT NULL,
			key_type TEXT NOT NULL,
			algorithm INTEGER NOT NULL,
			flags INTEGER NOT NULL,
			public_key TEXT NOT NULL,
			private_key BLOB NOT NULL,
			state TEXT NOT NULL DEFAULT 'received',
			received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			activated_at TIMESTAMP NULL,
			retired_at TIMESTAMP NULL,
			retire_time TEXT NULL,
			distribution_id TEXT NOT NULL,
			comment TEXT,
			UNIQUE(zone_name, key_id),
			CHECK (state IN ('received', 'active', 'edgesigner', 'retired', 'removed'))
		)`,

		// Node config table (stores node identity)
		`CREATE TABLE IF NOT EXISTS node_config (
			id TEXT PRIMARY KEY,
			long_term_pub_key BLOB NOT NULL,
			long_term_priv_key BLOB NOT NULL,
			kdc_address TEXT NOT NULL,
			control_zone TEXT NOT NULL,
			registered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,

		// Create indexes
		`CREATE INDEX IF NOT EXISTS idx_received_keys_zone_name ON received_keys(zone_name)`,
		`CREATE INDEX IF NOT EXISTS idx_received_keys_key_id ON received_keys(key_id)`,
		`CREATE INDEX IF NOT EXISTS idx_received_keys_state ON received_keys(state)`,
		`CREATE INDEX IF NOT EXISTS idx_received_keys_distribution_id ON received_keys(distribution_id)`,
	}

	for _, stmt := range schema {
		if _, err := krs.DB.Exec(stmt); err != nil {
			return fmt.Errorf("failed to execute schema statement: %v\nStatement: %s", err, stmt)
		}
	}

	return nil
}

// AddReceivedKey adds a new received key to the database
func (krs *KrsDB) AddReceivedKey(key *ReceivedKey) error {
	query := `INSERT INTO received_keys 
		(id, zone_name, key_id, key_type, algorithm, flags, public_key, private_key, state, received_at, distribution_id, comment, retire_time)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := krs.DB.Exec(query,
		key.ID, key.ZoneName, key.KeyID, key.KeyType, key.Algorithm, key.Flags,
		key.PublicKey, key.PrivateKey, key.State, key.ReceivedAt, key.DistributionID, key.Comment, key.RetireTime,
	)
	if err != nil {
		return fmt.Errorf("failed to add received key: %v", err)
	}
	return nil
}

// GetReceivedKey retrieves a received key by ID
func (krs *KrsDB) GetReceivedKey(id string) (*ReceivedKey, error) {
	var key ReceivedKey
	var activatedAt, retiredAt sql.NullTime
	var retireTime sql.NullString

	err := krs.DB.QueryRow(
		`SELECT id, zone_name, key_id, key_type, algorithm, flags, public_key, private_key, 
			state, received_at, activated_at, retired_at, distribution_id, comment, retire_time
			FROM received_keys WHERE id = ?`,
		id,
	).Scan(
		&key.ID, &key.ZoneName, &key.KeyID, &key.KeyType, &key.Algorithm, &key.Flags,
		&key.PublicKey, &key.PrivateKey, &key.State, &key.ReceivedAt,
		&activatedAt, &retiredAt, &key.DistributionID, &key.Comment, &retireTime,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("key %s not found", id)
		}
		return nil, fmt.Errorf("failed to get received key: %v", err)
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

	return &key, nil
}

// GetReceivedKeysForZone retrieves all received keys for a zone
func (krs *KrsDB) GetReceivedKeysForZone(zoneName string) ([]*ReceivedKey, error) {
	rows, err := krs.DB.Query(
		`SELECT id, zone_name, key_id, key_type, algorithm, flags, public_key, private_key, 
			state, received_at, activated_at, retired_at, distribution_id, comment, retire_time
			FROM received_keys WHERE zone_name = ? ORDER BY received_at DESC`,
		zoneName,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query received keys: %v", err)
	}
	defer rows.Close()

	var keys []*ReceivedKey
	for rows.Next() {
		var key ReceivedKey
		var activatedAt, retiredAt sql.NullTime
		var retireTime sql.NullString

		err := rows.Scan(
			&key.ID, &key.ZoneName, &key.KeyID, &key.KeyType, &key.Algorithm, &key.Flags,
			&key.PublicKey, &key.PrivateKey, &key.State, &key.ReceivedAt,
			&activatedAt, &retiredAt, &key.DistributionID, &key.Comment, &retireTime,
		)
		if err != nil {
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

		keys = append(keys, &key)
	}

	return keys, nil
}

// GetAllReceivedKeys retrieves all received keys
func (krs *KrsDB) GetAllReceivedKeys() ([]*ReceivedKey, error) {
	rows, err := krs.DB.Query(
		`SELECT id, zone_name, key_id, key_type, algorithm, flags, public_key, private_key, 
			state, received_at, activated_at, retired_at, distribution_id, comment, retire_time
			FROM received_keys ORDER BY received_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query received keys: %v", err)
	}
	defer rows.Close()

	var keys []*ReceivedKey
	for rows.Next() {
		var key ReceivedKey
		var activatedAt, retiredAt sql.NullTime
		var retireTime sql.NullString

		err := rows.Scan(
			&key.ID, &key.ZoneName, &key.KeyID, &key.KeyType, &key.Algorithm, &key.Flags,
			&key.PublicKey, &key.PrivateKey, &key.State, &key.ReceivedAt,
			&activatedAt, &retiredAt, &key.DistributionID, &key.Comment, &retireTime,
		)
		if err != nil {
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

		keys = append(keys, &key)
	}

	return keys, nil
}

// UpdateReceivedKeyState updates the state of a received key
func (krs *KrsDB) UpdateReceivedKeyState(id string, state string, activatedAt, retiredAt *time.Time) error {
	var activatedAtVal, retiredAtVal interface{}
	if activatedAt != nil {
		activatedAtVal = *activatedAt
	}
	if retiredAt != nil {
		retiredAtVal = *retiredAt
	}

	_, err := krs.DB.Exec(
		`UPDATE received_keys SET state = ?, activated_at = ?, retired_at = ? WHERE id = ?`,
		state, activatedAtVal, retiredAtVal, id,
	)
	if err != nil {
		return fmt.Errorf("failed to update received key state: %v", err)
	}
	return nil
}

// RetireEdgesignerKeysForZone retires all keys in "edgesigner" state for a given zone
// This ensures only one key per zone is in "edgesigner" state at a time
func (krs *KrsDB) RetireEdgesignerKeysForZone(zoneName string) error {
	now := time.Now()
	_, err := krs.DB.Exec(
		`UPDATE received_keys SET state = ?, retired_at = ? WHERE zone_name = ? AND state = ?`,
		"retired", now, zoneName, "edgesigner",
	)
	if err != nil {
		return fmt.Errorf("failed to retire edgesigner keys for zone %s: %v", zoneName, err)
	}
	return nil
}

// GetReceivedKeyByZoneAndKeyID retrieves a received key by zone name and key ID
func (krs *KrsDB) GetReceivedKeyByZoneAndKeyID(zoneName string, keyID uint16) (*ReceivedKey, error) {
	var key ReceivedKey
	var activatedAt, retiredAt sql.NullTime
	var retireTime sql.NullString

	err := krs.DB.QueryRow(
		`SELECT id, zone_name, key_id, key_type, algorithm, flags, public_key, private_key, 
			state, received_at, activated_at, retired_at, distribution_id, comment, retire_time
			FROM received_keys WHERE zone_name = ? AND key_id = ?`,
		zoneName, keyID,
	).Scan(
		&key.ID, &key.ZoneName, &key.KeyID, &key.KeyType, &key.Algorithm, &key.Flags,
		&key.PublicKey, &key.PrivateKey, &key.State, &key.ReceivedAt,
		&activatedAt, &retiredAt, &key.DistributionID, &key.Comment, &retireTime,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Key doesn't exist, that's fine
		}
		return nil, fmt.Errorf("failed to get received key: %v", err)
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

	return &key, nil
}

// compareKeys compares two keys to see if they have identical key material
// Returns true if keys are identical, false otherwise
func compareKeys(key1, key2 *ReceivedKey) bool {
	if key1.Algorithm != key2.Algorithm {
		return false
	}
	if key1.Flags != key2.Flags {
		return false
	}
	if key1.PublicKey != key2.PublicKey {
		return false
	}
	// Compare private keys byte-by-byte
	if len(key1.PrivateKey) != len(key2.PrivateKey) {
		return false
	}
	for i := range key1.PrivateKey {
		if key1.PrivateKey[i] != key2.PrivateKey[i] {
			return false
		}
	}
	return true
}

// AddEdgesignerKeyWithRetirement atomically retires existing edgesigner keys for a zone
// and adds a new edgesigner key. This ensures only one key per zone is in "edgesigner" state.
// If either operation fails, the transaction is rolled back.
// If a key with the same zone_name and key_id already exists, compares the keys.
// If identical, accepts (idempotent). If different, returns an error.
func (krs *KrsDB) AddEdgesignerKeyWithRetirement(key *ReceivedKey) error {
	// Ensure the key state is "edgesigner"
	if key.State != "edgesigner" {
		return fmt.Errorf("key state must be 'edgesigner', got '%s'", key.State)
	}

	// Check if a key with the same zone_name and key_id already exists
	existingKey, err := krs.GetReceivedKeyByZoneAndKeyID(key.ZoneName, key.KeyID)
	if err != nil {
		return fmt.Errorf("failed to check for existing key: %v", err)
	}
	
	if existingKey != nil {
		// Key with same ID exists - compare them
		if compareKeys(existingKey, key) {
			// Keys are identical - this is an idempotent retry, log and accept
			log.Printf("KRS: Key %d for zone %s already exists with identical key material (idempotent retry), accepting", key.KeyID, key.ZoneName)
			return nil
		} else {
			// Keys are different - this is an error (key ID collision or compromise)
			return fmt.Errorf("key %d for zone %s already exists but with different key material (algorithm: %d vs %d, flags: %d vs %d, public_key differs). This may indicate a key ID collision or compromise", 
				key.KeyID, key.ZoneName, existingKey.Algorithm, key.Algorithm, existingKey.Flags, key.Flags)
		}
	}

	// Start a transaction
	tx, err := krs.DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback() // Will be a no-op if Commit succeeds

	// Step 1: Retire existing edgesigner keys for this zone
	now := time.Now()
	_, err = tx.Exec(
		`UPDATE received_keys SET state = ?, retired_at = ? WHERE zone_name = ? AND state = ?`,
		"retired", now, key.ZoneName, "edgesigner",
	)
	if err != nil {
		return fmt.Errorf("failed to retire existing edgesigner keys for zone %s: %v", key.ZoneName, err)
	}

	// Step 2: Insert the new edgesigner key
	_, err = tx.Exec(
		`INSERT INTO received_keys 
			(id, zone_name, key_id, key_type, algorithm, flags, public_key, private_key, state, received_at, distribution_id, comment, retire_time)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID, key.ZoneName, key.KeyID, key.KeyType, key.Algorithm, key.Flags,
		key.PublicKey, key.PrivateKey, key.State, key.ReceivedAt, key.DistributionID, key.Comment, key.RetireTime,
	)
	if err != nil {
		return fmt.Errorf("failed to add new edgesigner key: %v", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	return nil
}

// AddActiveKeyWithRetirement atomically retires existing active KSKs for a zone
// and adds a new active KSK. This ensures only one KSK per zone is in "active" state.
// If either operation fails, the transaction is rolled back.
// If a key with the same zone_name and key_id already exists, compares the keys.
// If identical, accepts (idempotent). If different, returns an error.
func (krs *KrsDB) AddActiveKeyWithRetirement(key *ReceivedKey) error {
	// Ensure the key state is "active" and key type is KSK
	if key.State != "active" {
		return fmt.Errorf("key state must be 'active', got '%s'", key.State)
	}
	if key.KeyType != "KSK" {
		return fmt.Errorf("key type must be 'KSK', got '%s'", key.KeyType)
	}

	// Check if a key with the same zone_name and key_id already exists
	existingKey, err := krs.GetReceivedKeyByZoneAndKeyID(key.ZoneName, key.KeyID)
	if err != nil {
		return fmt.Errorf("failed to check for existing key: %v", err)
	}
	
	if existingKey != nil {
		// Key with same ID exists - compare them
		if compareKeys(existingKey, key) {
			// Keys are identical - this is an idempotent retry, log and accept
			log.Printf("KRS: Key %d for zone %s already exists with identical key material (idempotent retry), accepting", key.KeyID, key.ZoneName)
			return nil
		} else {
			// Keys are different - this is an error (key ID collision or compromise)
			return fmt.Errorf("key %d for zone %s already exists but with different key material (algorithm: %d vs %d, flags: %d vs %d, public_key differs). This may indicate a key ID collision or compromise", 
				key.KeyID, key.ZoneName, existingKey.Algorithm, key.Algorithm, existingKey.Flags, key.Flags)
		}
	}

	// Start a transaction
	tx, err := krs.DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback() // Will be a no-op if Commit succeeds

	// Step 1: Retire existing active KSKs for this zone
	now := time.Now()
	_, err = tx.Exec(
		`UPDATE received_keys SET state = ?, retired_at = ? WHERE zone_name = ? AND state = ? AND key_type = ?`,
		"retired", now, key.ZoneName, "active", "KSK",
	)
	if err != nil {
		return fmt.Errorf("failed to retire existing active KSKs for zone %s: %v", key.ZoneName, err)
	}

	// Step 2: Insert the new active KSK (set activated_at to now since it's immediately active)
	_, err = tx.Exec(
		`INSERT INTO received_keys 
			(id, zone_name, key_id, key_type, algorithm, flags, public_key, private_key, state, received_at, activated_at, distribution_id, comment, retire_time)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID, key.ZoneName, key.KeyID, key.KeyType, key.Algorithm, key.Flags,
		key.PublicKey, key.PrivateKey, key.State, key.ReceivedAt, now, key.DistributionID, key.Comment, key.RetireTime,
	)
	if err != nil {
		return fmt.Errorf("failed to add new active KSK: %v", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	return nil
}

// SetNodeConfig stores the node configuration
func (krs *KrsDB) SetNodeConfig(config *NodeConfig) error {
	query := `INSERT OR REPLACE INTO node_config 
		(id, long_term_pub_key, long_term_priv_key, kdc_address, control_zone, registered_at, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err := krs.DB.Exec(query,
		config.ID, config.LongTermPubKey, config.LongTermPrivKey,
		config.KdcAddress, config.ControlZone, config.RegisteredAt, config.LastSeen,
	)
	if err != nil {
		return fmt.Errorf("failed to set node config: %v", err)
	}
	return nil
}

// GetNodeConfig retrieves the node configuration
func (krs *KrsDB) GetNodeConfig() (*NodeConfig, error) {
	var config NodeConfig

	err := krs.DB.QueryRow(
		`SELECT id, long_term_pub_key, long_term_priv_key, kdc_address, control_zone, registered_at, last_seen
			FROM node_config LIMIT 1`,
	).Scan(
		&config.ID, &config.LongTermPubKey, &config.LongTermPrivKey,
		&config.KdcAddress, &config.ControlZone, &config.RegisteredAt, &config.LastSeen,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("node config not found")
		}
		return nil, fmt.Errorf("failed to get node config: %v", err)
	}

	return &config, nil
}

// UpdateNodeLastSeen updates the last_seen timestamp
func (krs *KrsDB) UpdateNodeLastSeen() error {
	_, err := krs.DB.Exec(
		`UPDATE node_config SET last_seen = CURRENT_TIMESTAMP`,
	)
	if err != nil {
		return fmt.Errorf("failed to update last_seen: %v", err)
	}
	return nil
}

// DeleteReceivedKeyByZoneAndKeyID deletes a specific key by zone name and key ID
func (krs *KrsDB) DeleteReceivedKeyByZoneAndKeyID(zoneName, keyID string) error {
	result, err := krs.DB.Exec(
		`DELETE FROM received_keys WHERE zone_name = ? AND key_id = ?`,
		zoneName, keyID,
	)
	if err != nil {
		return fmt.Errorf("failed to delete key: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %v", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("key %s not found for zone %s", keyID, zoneName)
	}

	return nil
}

// migrateAddRetireTimeAndRemovedState adds retire_time column and updates CHECK constraint to include 'removed'
// TEMPORARY: Remove this migration once all databases have been upgraded
func (krs *KrsDB) migrateAddRetireTimeAndRemovedState() error {
	// Check if retire_time column exists
	var columnExists bool
	var count int
	err := krs.DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('received_keys') WHERE name='retire_time'").Scan(&count)
	columnExists = (err == nil && count > 0)

	if !columnExists {
		// Add retire_time column
		_, err = krs.DB.Exec("ALTER TABLE received_keys ADD COLUMN retire_time TEXT NULL")
		if err != nil {
			// Check if error is "duplicate column" (column already exists - race condition)
			if !strings.Contains(err.Error(), "duplicate column") &&
			   !strings.Contains(err.Error(), "already exists") &&
			   !strings.Contains(err.Error(), "Duplicate column name") {
				return fmt.Errorf("failed to add retire_time column: %v", err)
			}
		} else {
			log.Printf("KRS: Added retire_time column to received_keys table")
		}
	}

	// Check if constraint already allows 'removed' by trying to update a test record
	var testID, originalState string
	err = krs.DB.QueryRow("SELECT id, state FROM received_keys LIMIT 1").Scan(&testID, &originalState)
	if err == nil && testID != "" {
		// Try to update a record to 'removed' to test the constraint
		_, err = krs.DB.Exec("UPDATE received_keys SET state = 'removed' WHERE id = ?", testID)
		if err != nil && strings.Contains(err.Error(), "CHECK constraint failed") {
			// Constraint doesn't allow 'removed', need to recreate table
			log.Printf("KRS: Recreating received_keys table to update CHECK constraint for 'removed' state")

			// Create new table with correct constraint
			_, err = krs.DB.Exec(`
				CREATE TABLE IF NOT EXISTS received_keys_new (
					id TEXT PRIMARY KEY,
					zone_name TEXT NOT NULL,
					key_id INTEGER NOT NULL,
					key_type TEXT NOT NULL,
					algorithm INTEGER NOT NULL,
					flags INTEGER NOT NULL,
					public_key TEXT NOT NULL,
					private_key BLOB NOT NULL,
					state TEXT NOT NULL DEFAULT 'received',
					received_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
					activated_at TIMESTAMP NULL,
					retired_at TIMESTAMP NULL,
					retire_time TEXT NULL,
					distribution_id TEXT NOT NULL,
					comment TEXT,
					UNIQUE(zone_name, key_id),
					CHECK (state IN ('received', 'active', 'edgesigner', 'retired', 'removed'))
				)`)
			if err != nil {
				return fmt.Errorf("failed to create new received_keys table: %v", err)
			}

			// Copy data
			_, err = krs.DB.Exec(`
				INSERT INTO received_keys_new 
				SELECT id, zone_name, key_id, key_type, algorithm, flags, public_key, private_key, 
				       state, received_at, activated_at, retired_at, 
				       COALESCE(retire_time, '') as retire_time,
				       distribution_id, comment
				FROM received_keys`)
			if err != nil {
				return fmt.Errorf("failed to copy data to new table: %v", err)
			}

			// Drop old table
			_, err = krs.DB.Exec("DROP TABLE received_keys")
			if err != nil {
				return fmt.Errorf("failed to drop old table: %v", err)
			}

			// Rename new table
			_, err = krs.DB.Exec("ALTER TABLE received_keys_new RENAME TO received_keys")
			if err != nil {
				return fmt.Errorf("failed to rename new table: %v", err)
			}

			// Recreate indexes
			indexes := []string{
				"CREATE INDEX IF NOT EXISTS idx_received_keys_zone_name ON received_keys(zone_name)",
				"CREATE INDEX IF NOT EXISTS idx_received_keys_key_id ON received_keys(key_id)",
				"CREATE INDEX IF NOT EXISTS idx_received_keys_state ON received_keys(state)",
				"CREATE INDEX IF NOT EXISTS idx_received_keys_distribution_id ON received_keys(distribution_id)",
			}
			for _, idxStmt := range indexes {
				if _, err := krs.DB.Exec(idxStmt); err != nil {
					log.Printf("KRS: Warning: Failed to recreate index: %v", err)
				}
			}

			log.Printf("KRS: Successfully updated received_keys table CHECK constraint")
		} else if err == nil {
			// Update succeeded, revert it to original state
			_, _ = krs.DB.Exec("UPDATE received_keys SET state = ? WHERE id = ?", originalState, testID)
		}
	}
	// If no records exist or constraint already allows 'removed', nothing to do
	return nil
}

