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

	return krs, nil
}

// initSchema creates the database tables if they don't exist
func (krs *KrsDB) initSchema() error {
	schema := []string{
		// Received keys table
		`CREATE TABLE IF NOT EXISTS received_keys (
			id TEXT PRIMARY KEY,
			zone_id TEXT NOT NULL,
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
			distribution_id TEXT NOT NULL,
			comment TEXT,
			UNIQUE(zone_id, key_id)
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
		`CREATE INDEX IF NOT EXISTS idx_received_keys_zone_id ON received_keys(zone_id)`,
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
		(id, zone_id, key_id, key_type, algorithm, flags, public_key, private_key, state, received_at, distribution_id, comment)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := krs.DB.Exec(query,
		key.ID, key.ZoneID, key.KeyID, key.KeyType, key.Algorithm, key.Flags,
		key.PublicKey, key.PrivateKey, key.State, key.ReceivedAt, key.DistributionID, key.Comment,
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

	err := krs.DB.QueryRow(
		`SELECT id, zone_id, key_id, key_type, algorithm, flags, public_key, private_key, 
			state, received_at, activated_at, retired_at, distribution_id, comment
			FROM received_keys WHERE id = ?`,
		id,
	).Scan(
		&key.ID, &key.ZoneID, &key.KeyID, &key.KeyType, &key.Algorithm, &key.Flags,
		&key.PublicKey, &key.PrivateKey, &key.State, &key.ReceivedAt,
		&activatedAt, &retiredAt, &key.DistributionID, &key.Comment,
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

	return &key, nil
}

// GetReceivedKeysForZone retrieves all received keys for a zone
func (krs *KrsDB) GetReceivedKeysForZone(zoneID string) ([]*ReceivedKey, error) {
	rows, err := krs.DB.Query(
		`SELECT id, zone_id, key_id, key_type, algorithm, flags, public_key, private_key, 
			state, received_at, activated_at, retired_at, distribution_id, comment
			FROM received_keys WHERE zone_id = ? ORDER BY received_at DESC`,
		zoneID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query received keys: %v", err)
	}
	defer rows.Close()

	var keys []*ReceivedKey
	for rows.Next() {
		var key ReceivedKey
		var activatedAt, retiredAt sql.NullTime

		err := rows.Scan(
			&key.ID, &key.ZoneID, &key.KeyID, &key.KeyType, &key.Algorithm, &key.Flags,
			&key.PublicKey, &key.PrivateKey, &key.State, &key.ReceivedAt,
			&activatedAt, &retiredAt, &key.DistributionID, &key.Comment,
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

		keys = append(keys, &key)
	}

	return keys, nil
}

// GetAllReceivedKeys retrieves all received keys
func (krs *KrsDB) GetAllReceivedKeys() ([]*ReceivedKey, error) {
	rows, err := krs.DB.Query(
		`SELECT id, zone_id, key_id, key_type, algorithm, flags, public_key, private_key, 
			state, received_at, activated_at, retired_at, distribution_id, comment
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

		err := rows.Scan(
			&key.ID, &key.ZoneID, &key.KeyID, &key.KeyType, &key.Algorithm, &key.Flags,
			&key.PublicKey, &key.PrivateKey, &key.State, &key.ReceivedAt,
			&activatedAt, &retiredAt, &key.DistributionID, &key.Comment,
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
func (krs *KrsDB) RetireEdgesignerKeysForZone(zoneID string) error {
	now := time.Now()
	_, err := krs.DB.Exec(
		`UPDATE received_keys SET state = ?, retired_at = ? WHERE zone_id = ? AND state = ?`,
		"retired", now, zoneID, "edgesigner",
	)
	if err != nil {
		return fmt.Errorf("failed to retire edgesigner keys for zone %s: %v", zoneID, err)
	}
	return nil
}

// AddEdgesignerKeyWithRetirement atomically retires existing edgesigner keys for a zone
// and adds a new edgesigner key. This ensures only one key per zone is in "edgesigner" state.
// If either operation fails, the transaction is rolled back.
func (krs *KrsDB) AddEdgesignerKeyWithRetirement(key *ReceivedKey) error {
	// Ensure the key state is "edgesigner"
	if key.State != "edgesigner" {
		return fmt.Errorf("key state must be 'edgesigner', got '%s'", key.State)
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
		`UPDATE received_keys SET state = ?, retired_at = ? WHERE zone_id = ? AND state = ?`,
		"retired", now, key.ZoneID, "edgesigner",
	)
	if err != nil {
		return fmt.Errorf("failed to retire existing edgesigner keys for zone %s: %v", key.ZoneID, err)
	}

	// Step 2: Insert the new edgesigner key
	_, err = tx.Exec(
		`INSERT INTO received_keys 
			(id, zone_id, key_id, key_type, algorithm, flags, public_key, private_key, state, received_at, distribution_id, comment)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID, key.ZoneID, key.KeyID, key.KeyType, key.Algorithm, key.Flags,
		key.PublicKey, key.PrivateKey, key.State, key.ReceivedAt, key.DistributionID, key.Comment,
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

