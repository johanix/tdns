/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Database schema and operations for tdns-kdc
 * Uses MariaDB for production-grade reliability
 */

package kdc

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql" // MariaDB driver
	"github.com/johanix/tdns/tdns/hpke"
	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// KdcDB represents the KDC database connection
type KdcDB struct {
	DB     *sql.DB
	DBType string // "sqlite" or "mariadb"
}

// NewKdcDB creates a new KDC database connection
// dbType should be "sqlite" or "mariadb"
// dsn should be a file path for SQLite or a MySQL DSN for MariaDB
func NewKdcDB(dbType, dsn string) (*KdcDB, error) {
	var driverName string
	switch strings.ToLower(dbType) {
	case "sqlite", "sqlite3":
		driverName = "sqlite3"
		// SQLite DSN is just the file path
	case "mariadb", "mysql":
		driverName = "mysql"
	default:
		return nil, fmt.Errorf("unsupported database type: %s (must be 'sqlite' or 'mariadb')", dbType)
	}

	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}

	kdc := &KdcDB{
		DB:     db,
		DBType: strings.ToLower(dbType),
	}

	// Initialize schema
	if err := kdc.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %v", err)
	}

	return kdc, nil
}

// initSchema creates the database tables if they don't exist
func (kdc *KdcDB) initSchema() error {
	if kdc.DBType == "sqlite" {
		if err := kdc.initSchemaSQLite(); err != nil {
			return err
		}
		return kdc.migrateSchemaSQLite()
	}
	if err := kdc.initSchemaMySQL(); err != nil {
		return err
	}
	return kdc.migrateSchemaMySQL()
}

// initSchemaMySQL creates MySQL/MariaDB tables
func (kdc *KdcDB) initSchemaMySQL() error {
	schema := []string{
		// Zones table
		`CREATE TABLE IF NOT EXISTS zones (
			id VARCHAR(255) PRIMARY KEY,
			name VARCHAR(255) NOT NULL UNIQUE,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			active BOOLEAN NOT NULL DEFAULT TRUE,
			comment TEXT,
			INDEX idx_name (name),
			INDEX idx_active (active)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// Nodes table
		// Note: MySQL/MariaDB doesn't support UNIQUE directly on BLOB, so we rely on application-level checks
		`CREATE TABLE IF NOT EXISTS nodes (
			id VARCHAR(255) PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			long_term_pub_key BLOB NOT NULL,
			notify_address VARCHAR(255),
			registered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			state ENUM('online', 'offline', 'compromised', 'suspended') NOT NULL DEFAULT 'online',
			comment TEXT,
			INDEX idx_state (state),
			INDEX idx_last_seen (last_seen),
			INDEX idx_long_term_pub_key (long_term_pub_key(32))
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// DNSSEC keys table
		`CREATE TABLE IF NOT EXISTS dnssec_keys (
			id VARCHAR(255) PRIMARY KEY,
			zone_id VARCHAR(255) NOT NULL,
			key_type ENUM('KSK', 'ZSK', 'CSK') NOT NULL,
			key_id SMALLINT UNSIGNED NOT NULL,
			algorithm TINYINT UNSIGNED NOT NULL,
			flags SMALLINT UNSIGNED NOT NULL,
			public_key TEXT NOT NULL,
			private_key BLOB NOT NULL,
			state ENUM('created', 'published', 'standby', 'active', 'distributed', 'edgesigner', 'retired', 'removed', 'revoked') NOT NULL DEFAULT 'created',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			published_at TIMESTAMP NULL,
			activated_at TIMESTAMP NULL,
			retired_at TIMESTAMP NULL,
			comment TEXT,
			FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
			INDEX idx_zone_id (zone_id),
			INDEX idx_key_type (key_type),
			INDEX idx_state (state),
			INDEX idx_zone_key_type_state (zone_id, key_type, state)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// Distribution records table
		`CREATE TABLE IF NOT EXISTS distribution_records (
			id VARCHAR(255) PRIMARY KEY,
			zone_id VARCHAR(255) NOT NULL,
			key_id VARCHAR(255) NOT NULL,
			node_id VARCHAR(255),
			encrypted_key BLOB NOT NULL,
			ephemeral_pub_key BLOB NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NULL,
			status ENUM('pending', 'delivered', 'active', 'revoked') NOT NULL DEFAULT 'pending',
			distribution_id VARCHAR(255) NOT NULL,
			FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
			FOREIGN KEY (key_id) REFERENCES dnssec_keys(id) ON DELETE CASCADE,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
			INDEX idx_zone_id (zone_id),
			INDEX idx_key_id (key_id),
			INDEX idx_node_id (node_id),
			INDEX idx_status (status),
			INDEX idx_distribution_id (distribution_id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// Zone-node assignments table
		`CREATE TABLE IF NOT EXISTS zone_node_assignments (
			zone_id VARCHAR(255) NOT NULL,
			node_id VARCHAR(255) NOT NULL,
			active BOOLEAN NOT NULL DEFAULT TRUE,
			since TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (zone_id, node_id),
			FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
			INDEX idx_node_id (node_id),
			INDEX idx_active (active)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// Distribution confirmations table - tracks which nodes have confirmed receipt of distributed keys
		`CREATE TABLE IF NOT EXISTS distribution_confirmations (
			id VARCHAR(255) PRIMARY KEY,
			distribution_id VARCHAR(255) NOT NULL,
			zone_id VARCHAR(255) NOT NULL,
			key_id VARCHAR(255) NOT NULL,
			node_id VARCHAR(255) NOT NULL,
			confirmed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
			FOREIGN KEY (key_id) REFERENCES dnssec_keys(id) ON DELETE CASCADE,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
			INDEX idx_distribution_id (distribution_id),
			INDEX idx_zone_key (zone_id, key_id),
			INDEX idx_node_id (node_id),
			UNIQUE KEY idx_distribution_node (distribution_id, node_id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}

	for _, stmt := range schema {
		if _, err := kdc.DB.Exec(stmt); err != nil {
			return fmt.Errorf("failed to execute schema statement: %v\nStatement: %s", err, stmt)
		}
	}

	log.Printf("KDC database schema initialized successfully (MySQL/MariaDB)")
	return nil
}

// migrateSchemaMySQL applies migrations to MySQL/MariaDB schema
func (kdc *KdcDB) migrateSchemaMySQL() error {
	// Check if notify_address column exists in nodes table
	var columnExists int
	err := kdc.DB.QueryRow(`
		SELECT COUNT(*) FROM information_schema.COLUMNS 
		WHERE TABLE_SCHEMA = DATABASE() 
		AND TABLE_NAME = 'nodes' 
		AND COLUMN_NAME = 'notify_address'
	`).Scan(&columnExists)
	
	if err != nil {
		// If we can't check, assume column doesn't exist and try to add it
		log.Printf("KDC: Could not check for notify_address column, attempting to add it")
		_, err := kdc.DB.Exec("ALTER TABLE nodes ADD COLUMN notify_address VARCHAR(255)")
		if err != nil && !strings.Contains(err.Error(), "Duplicate column name") {
			log.Printf("KDC: Warning: failed to add notify_address column (may already exist): %v", err)
		} else {
			log.Printf("KDC: Added notify_address column to nodes table")
		}
	} else if columnExists == 0 {
		// Column doesn't exist, add it
		_, err := kdc.DB.Exec("ALTER TABLE nodes ADD COLUMN notify_address VARCHAR(255)")
		if err != nil {
			return fmt.Errorf("failed to add notify_address column: %v", err)
		}
		log.Printf("KDC: Added notify_address column to nodes table")
	}
	
	// Update ENUM for dnssec_keys.state to include all new states
	// MySQL/MariaDB requires ALTER TABLE to modify ENUM
	_, err = kdc.DB.Exec(`
		ALTER TABLE dnssec_keys 
		MODIFY COLUMN state ENUM('created', 'published', 'standby', 'active', 'distributed', 'edgesigner', 'retired', 'removed', 'revoked') 
		NOT NULL DEFAULT 'created'
	`)
	if err != nil {
		// If the ENUM already has the correct values, this will fail with a "Duplicate" error
		// which we can safely ignore
		if !strings.Contains(err.Error(), "Duplicate") && !strings.Contains(err.Error(), "already exists") {
			log.Printf("KDC: Warning: failed to update dnssec_keys.state ENUM (may already be correct): %v", err)
		} else {
			log.Printf("KDC: Updated dnssec_keys.state ENUM to include all states")
		}
	} else {
		log.Printf("KDC: Updated dnssec_keys.state ENUM to include all states")
	}
	
	return nil
}

// initSchemaSQLite creates SQLite tables
func (kdc *KdcDB) initSchemaSQLite() error {
	// Enable foreign keys
	if _, err := kdc.DB.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("failed to enable foreign keys: %v", err)
	}

	schema := []string{
		// Zones table
		`CREATE TABLE IF NOT EXISTS zones (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			active INTEGER NOT NULL DEFAULT 1,
			comment TEXT,
			CHECK (active IN (0, 1))
		)`,

		// Trigger to update updated_at on zones
		`CREATE TRIGGER IF NOT EXISTS zones_updated_at 
			AFTER UPDATE ON zones
			BEGIN
				UPDATE zones SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
			END`,

		// Nodes table
		`CREATE TABLE IF NOT EXISTS nodes (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			long_term_pub_key BLOB NOT NULL UNIQUE,
			notify_address TEXT,
			registered_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			state TEXT NOT NULL DEFAULT 'online',
			comment TEXT,
			CHECK (state IN ('online', 'offline', 'compromised', 'suspended'))
		)`,

		// Trigger to update last_seen on nodes
		`CREATE TRIGGER IF NOT EXISTS nodes_last_seen 
			AFTER UPDATE ON nodes
			BEGIN
				UPDATE nodes SET last_seen = CURRENT_TIMESTAMP WHERE id = NEW.id;
			END`,

		// DNSSEC keys table
		`CREATE TABLE IF NOT EXISTS dnssec_keys (
			id TEXT PRIMARY KEY,
			zone_id TEXT NOT NULL,
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
			FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
			CHECK (key_type IN ('KSK', 'ZSK', 'CSK')),
			CHECK (state IN ('created', 'published', 'standby', 'active', 'distributed', 'edgesigner', 'retired', 'removed', 'revoked'))
		)`,

		// Distribution records table
		`CREATE TABLE IF NOT EXISTS distribution_records (
			id TEXT PRIMARY KEY,
			zone_id TEXT NOT NULL,
			key_id TEXT NOT NULL,
			node_id TEXT,
			encrypted_key BLOB NOT NULL,
			ephemeral_pub_key BLOB NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME,
			status TEXT NOT NULL DEFAULT 'pending',
			distribution_id TEXT NOT NULL,
			FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
			FOREIGN KEY (key_id) REFERENCES dnssec_keys(id) ON DELETE CASCADE,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
			CHECK (status IN ('pending', 'delivered', 'active', 'revoked'))
		)`,

		// Zone-node assignments table
		`CREATE TABLE IF NOT EXISTS zone_node_assignments (
			zone_id TEXT NOT NULL,
			node_id TEXT NOT NULL,
			active INTEGER NOT NULL DEFAULT 1,
			since DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (zone_id, node_id),
			FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
			CHECK (active IN (0, 1))
		)`,

		// Distribution confirmations table - tracks which nodes have confirmed receipt of distributed keys
		`CREATE TABLE IF NOT EXISTS distribution_confirmations (
			id TEXT PRIMARY KEY,
			distribution_id TEXT NOT NULL,
			zone_id TEXT NOT NULL,
			key_id TEXT NOT NULL,
			node_id TEXT NOT NULL,
			confirmed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
			FOREIGN KEY (key_id) REFERENCES dnssec_keys(id) ON DELETE CASCADE,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
			UNIQUE (distribution_id, node_id)
		)`,

		// Create indexes
		`CREATE INDEX IF NOT EXISTS idx_zones_name ON zones(name)`,
		`CREATE INDEX IF NOT EXISTS idx_zones_active ON zones(active)`,
		`CREATE INDEX IF NOT EXISTS idx_nodes_state ON nodes(state)`,
		`CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen)`,
		`CREATE INDEX IF NOT EXISTS idx_dnssec_keys_zone_id ON dnssec_keys(zone_id)`,
		`CREATE INDEX IF NOT EXISTS idx_dnssec_keys_key_type ON dnssec_keys(key_type)`,
		`CREATE INDEX IF NOT EXISTS idx_dnssec_keys_state ON dnssec_keys(state)`,
		`CREATE INDEX IF NOT EXISTS idx_dnssec_keys_zone_key_type_state ON dnssec_keys(zone_id, key_type, state)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_records_zone_id ON distribution_records(zone_id)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_records_key_id ON distribution_records(key_id)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_records_node_id ON distribution_records(node_id)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_records_status ON distribution_records(status)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_records_distribution_id ON distribution_records(distribution_id)`,
		`CREATE INDEX IF NOT EXISTS idx_zone_node_assignments_node_id ON zone_node_assignments(node_id)`,
		`CREATE INDEX IF NOT EXISTS idx_zone_node_assignments_active ON zone_node_assignments(active)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_confirmations_distribution_id ON distribution_confirmations(distribution_id)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_confirmations_zone_key ON distribution_confirmations(zone_id, key_id)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_confirmations_node_id ON distribution_confirmations(node_id)`,
	}

	for _, stmt := range schema {
		if _, err := kdc.DB.Exec(stmt); err != nil {
			return fmt.Errorf("failed to execute schema statement: %v\nStatement: %s", err, stmt)
		}
	}

	log.Printf("KDC database schema initialized successfully (SQLite)")
	return nil
}

// migrateSchemaSQLite applies migrations to SQLite schema
func (kdc *KdcDB) migrateSchemaSQLite() error {
	// Check if notify_address column exists in nodes table
	rows, err := kdc.DB.Query("PRAGMA table_info(nodes)")
	if err != nil {
		log.Printf("KDC: Could not check table schema, attempting to add notify_address column")
		_, err := kdc.DB.Exec("ALTER TABLE nodes ADD COLUMN notify_address TEXT")
		if err != nil && !strings.Contains(err.Error(), "duplicate column name") && !strings.Contains(err.Error(), "duplicate") {
			log.Printf("KDC: Warning: failed to add notify_address column: %v", err)
		} else {
			log.Printf("KDC: Added notify_address column to nodes table")
		}
		return nil
	}
	defer rows.Close()
	
	columnExists := false
	for rows.Next() {
		var cid int
		var name string
		var colType string
		var notnull int
		var dfltValue interface{}
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notnull, &dfltValue, &pk); err != nil {
			continue
		}
		if name == "notify_address" {
			columnExists = true
			break
		}
	}
	rows.Close()
	
	if !columnExists {
		// Column doesn't exist, add it
		_, err := kdc.DB.Exec("ALTER TABLE nodes ADD COLUMN notify_address TEXT")
		if err != nil {
			return fmt.Errorf("failed to add notify_address column: %v", err)
		}
		log.Printf("KDC: Added notify_address column to nodes table")
	}
	
	// Check if dnssec_keys table has the old CHECK constraint (missing distributed, edgesigner, removed)
	// SQLite doesn't support ALTER TABLE to modify CHECK constraints, so we need to recreate the table
	// We detect this by trying to insert a test row with one of the new states, then delete it
	// First, check if the table exists
	var tableExists int
	err = kdc.DB.QueryRow(`
		SELECT COUNT(*) FROM sqlite_master 
		WHERE type='table' AND name='dnssec_keys'
	`).Scan(&tableExists)
	if err != nil || tableExists == 0 {
		// Table doesn't exist, nothing to migrate
		return nil
	}
	
	// Try to insert a test row with a new state to see if the constraint allows it
	// We'll use a transaction and rollback afterwards
	tx, err := kdc.DB.Begin()
	if err != nil {
		log.Printf("KDC: Could not begin transaction to test CHECK constraint: %v", err)
		return nil // Don't fail migration if we can't test
	}
	
	// Try to insert a test row with 'distributed' state
	// We need at least one zone to exist for the foreign key constraint
	var zoneExists string
	err = kdc.DB.QueryRow("SELECT id FROM zones LIMIT 1").Scan(&zoneExists)
	if err != nil {
		// No zones exist, can't test - assume migration not needed
		tx.Rollback()
		return nil
	}
	
	_, err = tx.Exec(`
		INSERT INTO dnssec_keys 
		(id, zone_id, key_type, key_id, algorithm, flags, public_key, private_key, state)
		VALUES ('__migration_test__', ?, 'ZSK', 0, 15, 256, 'test', X'00', 'distributed')
	`, zoneExists)
	
	if err != nil && strings.Contains(err.Error(), "CHECK constraint failed") {
		// Old constraint detected, need to migrate
		log.Printf("KDC: Detected old CHECK constraint in dnssec_keys table, recreating table...")
		tx.Rollback()
		
		// Recreate the table with the correct schema
		// Step 1: Create new table with correct schema
		_, err = kdc.DB.Exec(`
			CREATE TABLE IF NOT EXISTS dnssec_keys_new (
				id TEXT PRIMARY KEY,
				zone_id TEXT NOT NULL,
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
				FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,
				CHECK (key_type IN ('KSK', 'ZSK', 'CSK')),
				CHECK (state IN ('created', 'published', 'standby', 'active', 'distributed', 'edgesigner', 'retired', 'removed', 'revoked'))
			)
		`)
		if err != nil {
			return fmt.Errorf("failed to create new dnssec_keys table: %v", err)
		}
		
		// Step 2: Copy all data from old table to new table
		_, err = kdc.DB.Exec(`
			INSERT INTO dnssec_keys_new 
			SELECT id, zone_id, key_type, key_id, algorithm, flags, public_key, private_key, 
			       state, created_at, published_at, activated_at, retired_at, comment
			FROM dnssec_keys
		`)
		if err != nil {
			return fmt.Errorf("failed to copy data to new dnssec_keys table: %v", err)
		}
		
		// Step 3: Drop old table
		_, err = kdc.DB.Exec("DROP TABLE dnssec_keys")
		if err != nil {
			return fmt.Errorf("failed to drop old dnssec_keys table: %v", err)
		}
		
		// Step 4: Rename new table to original name
		_, err = kdc.DB.Exec("ALTER TABLE dnssec_keys_new RENAME TO dnssec_keys")
		if err != nil {
			return fmt.Errorf("failed to rename new dnssec_keys table: %v", err)
		}
		
		// Step 5: Recreate indexes
		indexes := []string{
			"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_zone_id ON dnssec_keys(zone_id)",
			"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_key_type ON dnssec_keys(key_type)",
			"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_state ON dnssec_keys(state)",
			"CREATE INDEX IF NOT EXISTS idx_dnssec_keys_zone_key_type_state ON dnssec_keys(zone_id, key_type, state)",
		}
		for _, idxStmt := range indexes {
			if _, err := kdc.DB.Exec(idxStmt); err != nil {
				log.Printf("KDC: Warning: failed to create index: %v", err)
			}
		}
		
		log.Printf("KDC: Successfully migrated dnssec_keys table to include all key states")
	} else {
		// Constraint allows new states, or some other error - rollback test insert
		tx.Rollback()
		if err == nil {
			// Test insert succeeded, delete the test row
			kdc.DB.Exec("DELETE FROM dnssec_keys WHERE id = '__migration_test__'")
		}
	}
	
	return nil
}

// Close closes the database connection
func (kdc *KdcDB) Close() error {
	if kdc.DB != nil {
		return kdc.DB.Close()
	}
	return nil
}

// GetZone retrieves a zone by ID
func (kdc *KdcDB) GetZone(zoneID string) (*Zone, error) {
	var z Zone
	var updatedAt sql.NullTime
	err := kdc.DB.QueryRow(
		"SELECT id, name, created_at, updated_at, active, comment FROM zones WHERE id = ?",
		zoneID,
	).Scan(&z.ID, &z.Name, &z.CreatedAt, &updatedAt, &z.Active, &z.Comment)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("zone not found: %s", zoneID)
		}
		return nil, fmt.Errorf("failed to get zone: %v", err)
	}
	if updatedAt.Valid {
		z.UpdatedAt = updatedAt.Time
	}
	return &z, nil
}

// GetAllZones retrieves all zones
func (kdc *KdcDB) GetAllZones() ([]*Zone, error) {
	rows, err := kdc.DB.Query("SELECT id, name, created_at, updated_at, active, comment FROM zones ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("failed to query zones: %v", err)
	}
	defer rows.Close()

	var zones []*Zone
	for rows.Next() {
		var z Zone
		var updatedAt sql.NullTime
		if err := rows.Scan(&z.ID, &z.Name, &z.CreatedAt, &updatedAt, &z.Active, &z.Comment); err != nil {
			return nil, fmt.Errorf("failed to scan zone: %v", err)
		}
		if updatedAt.Valid {
			z.UpdatedAt = updatedAt.Time
		}
		zones = append(zones, &z)
	}
	return zones, rows.Err()
}

// AddZone adds a new zone
func (kdc *KdcDB) AddZone(zone *Zone) error {
	_, err := kdc.DB.Exec(
		"INSERT INTO zones (id, name, active, comment) VALUES (?, ?, ?, ?)",
		zone.ID, zone.Name, zone.Active, zone.Comment,
	)
	if err != nil {
		return fmt.Errorf("failed to add zone: %v", err)
	}
	return nil
}

// UpdateZone updates an existing zone
func (kdc *KdcDB) UpdateZone(zone *Zone) error {
	_, err := kdc.DB.Exec(
		"UPDATE zones SET name = ?, active = ?, comment = ? WHERE id = ?",
		zone.Name, zone.Active, zone.Comment, zone.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update zone: %v", err)
	}
	return nil
}

// DeleteZone deletes a zone (cascade deletes keys and distributions)
func (kdc *KdcDB) DeleteZone(zoneID string) error {
	_, err := kdc.DB.Exec("DELETE FROM zones WHERE id = ?", zoneID)
	if err != nil {
		return fmt.Errorf("failed to delete zone: %v", err)
	}
	return nil
}

// GetNode retrieves a node by ID
func (kdc *KdcDB) GetNode(nodeID string) (*Node, error) {
	var n Node
	var notifyAddr sql.NullString
	err := kdc.DB.QueryRow(
		"SELECT id, name, long_term_pub_key, notify_address, registered_at, last_seen, state, comment FROM nodes WHERE id = ?",
		nodeID,
	).Scan(&n.ID, &n.Name, &n.LongTermPubKey, &notifyAddr, &n.RegisteredAt, &n.LastSeen, &n.State, &n.Comment)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("node not found: %s", nodeID)
		}
		return nil, fmt.Errorf("failed to get node: %v", err)
	}
	if notifyAddr.Valid {
		n.NotifyAddress = notifyAddr.String
	}
	return &n, nil
}

// GetAllNodes retrieves all nodes
func (kdc *KdcDB) GetAllNodes() ([]*Node, error) {
	rows, err := kdc.DB.Query("SELECT id, name, long_term_pub_key, notify_address, registered_at, last_seen, state, comment FROM nodes ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("failed to query nodes: %v", err)
	}
	defer rows.Close()

	var nodes []*Node
	for rows.Next() {
		var n Node
		var notifyAddr sql.NullString
		if err := rows.Scan(&n.ID, &n.Name, &n.LongTermPubKey, &notifyAddr, &n.RegisteredAt, &n.LastSeen, &n.State, &n.Comment); err != nil {
			return nil, fmt.Errorf("failed to scan node: %v", err)
		}
		if notifyAddr.Valid {
			n.NotifyAddress = notifyAddr.String
		}
		nodes = append(nodes, &n)
	}
	return nodes, rows.Err()
}

// GetActiveNodes retrieves all active (online) nodes
func (kdc *KdcDB) GetActiveNodes() ([]*Node, error) {
	rows, err := kdc.DB.Query(
		"SELECT id, name, long_term_pub_key, notify_address, registered_at, last_seen, state, comment FROM nodes WHERE state = 'online' ORDER BY name",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query active nodes: %v", err)
	}
	defer rows.Close()

	var nodes []*Node
	for rows.Next() {
		var n Node
		var notifyAddr sql.NullString
		if err := rows.Scan(&n.ID, &n.Name, &n.LongTermPubKey, &notifyAddr, &n.RegisteredAt, &n.LastSeen, &n.State, &n.Comment); err != nil {
			return nil, fmt.Errorf("failed to scan node: %v", err)
		}
		if notifyAddr.Valid {
			n.NotifyAddress = notifyAddr.String
		}
		nodes = append(nodes, &n)
	}
	return nodes, rows.Err()
}

// GetNodeByPublicKey retrieves a node by its long-term public key
func (kdc *KdcDB) GetNodeByPublicKey(pubKey []byte) (*Node, error) {
	var n Node
	var notifyAddr sql.NullString
	err := kdc.DB.QueryRow(
		"SELECT id, name, long_term_pub_key, notify_address, registered_at, last_seen, state, comment FROM nodes WHERE long_term_pub_key = ?",
		pubKey,
	).Scan(&n.ID, &n.Name, &n.LongTermPubKey, &notifyAddr, &n.RegisteredAt, &n.LastSeen, &n.State, &n.Comment)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No node found with this public key
		}
		return nil, fmt.Errorf("failed to get node by public key: %v", err)
	}
	if notifyAddr.Valid {
		n.NotifyAddress = notifyAddr.String
	}
	return &n, nil
}

// AddNode adds a new node
func (kdc *KdcDB) AddNode(node *Node) error {
	// Check if a node with this public key already exists
	existingNode, err := kdc.GetNodeByPublicKey(node.LongTermPubKey)
	if err != nil {
		return fmt.Errorf("failed to check for existing node: %v", err)
	}
	if existingNode != nil {
		return fmt.Errorf("a node with this public key already exists: %s (id: %s)", existingNode.Name, existingNode.ID)
	}

	_, err = kdc.DB.Exec(
		"INSERT INTO nodes (id, name, long_term_pub_key, notify_address, state, comment) VALUES (?, ?, ?, ?, ?, ?)",
		node.ID, node.Name, node.LongTermPubKey, node.NotifyAddress, node.State, node.Comment,
	)
	if err != nil {
		// Check for unique constraint violation (in case the constraint wasn't in the schema)
		if strings.Contains(err.Error(), "UNIQUE constraint") || strings.Contains(err.Error(), "Duplicate entry") {
			return fmt.Errorf("a node with this public key already exists")
		}
		return fmt.Errorf("failed to add node: %v", err)
	}
	return nil
}

// UpdateNode updates an existing node
func (kdc *KdcDB) UpdateNode(node *Node) error {
	_, err := kdc.DB.Exec(
		"UPDATE nodes SET name = ?, long_term_pub_key = ?, notify_address = ?, state = ?, comment = ? WHERE id = ?",
		node.Name, node.LongTermPubKey, node.NotifyAddress, node.State, node.Comment, node.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update node: %v", err)
	}
	return nil
}

// UpdateNodeState updates a node's state
func (kdc *KdcDB) UpdateNodeState(nodeID string, state NodeState) error {
	_, err := kdc.DB.Exec("UPDATE nodes SET state = ? WHERE id = ?", state, nodeID)
	if err != nil {
		return fmt.Errorf("failed to update node state: %v", err)
	}
	return nil
}

// UpdateNodeLastSeen updates a node's last seen timestamp
func (kdc *KdcDB) UpdateNodeLastSeen(nodeID string) error {
	_, err := kdc.DB.Exec("UPDATE nodes SET last_seen = CURRENT_TIMESTAMP WHERE id = ?", nodeID)
	if err != nil {
		return fmt.Errorf("failed to update node last seen: %v", err)
	}
	return nil
}

// DeleteNode deletes a node
func (kdc *KdcDB) DeleteNode(nodeID string) error {
	_, err := kdc.DB.Exec("DELETE FROM nodes WHERE id = ?", nodeID)
	if err != nil {
		return fmt.Errorf("failed to delete node: %v", err)
	}
	return nil
}

// AddDNSSECKey adds a new DNSSEC key
func (kdc *KdcDB) AddDNSSECKey(key *DNSSECKey) error {
	_, err := kdc.DB.Exec(
		`INSERT INTO dnssec_keys 
			(id, zone_id, key_type, key_id, algorithm, flags, public_key, private_key, state, comment)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID, key.ZoneID, key.KeyType, key.KeyID, key.Algorithm, key.Flags,
		key.PublicKey, key.PrivateKey, key.State, key.Comment,
	)
	if err != nil {
		return fmt.Errorf("failed to add DNSSEC key: %v", err)
	}
	return nil
}

// GetDNSSECKeysForZone retrieves all DNSSEC keys for a zone
func (kdc *KdcDB) GetDNSSECKeysForZone(zoneID string) ([]*DNSSECKey, error) {
	rows, err := kdc.DB.Query(
		`SELECT id, zone_id, key_type, key_id, algorithm, flags, public_key, private_key, 
			state, created_at, published_at, activated_at, retired_at, comment
			FROM dnssec_keys WHERE zone_id = ? ORDER BY key_type, created_at`,
		zoneID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query DNSSEC keys: %v", err)
	}
	defer rows.Close()

	var keys []*DNSSECKey
	for rows.Next() {
		key := &DNSSECKey{}
		var publishedAt, activatedAt, retiredAt sql.NullTime
		if err := rows.Scan(
			&key.ID, &key.ZoneID, &key.KeyType, &key.KeyID, &key.Algorithm, &key.Flags,
			&key.PublicKey, &key.PrivateKey, &key.State, &key.CreatedAt,
			&publishedAt, &activatedAt, &retiredAt, &key.Comment,
		); err != nil {
			return nil, fmt.Errorf("failed to scan DNSSEC key: %v", err)
		}
		if publishedAt.Valid {
			key.PublishedAt = &publishedAt.Time
		}
		if activatedAt.Valid {
			key.ActivatedAt = &activatedAt.Time
		}
		if retiredAt.Valid {
			key.RetiredAt = &retiredAt.Time
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// GetAllDNSSECKeys retrieves all DNSSEC keys for all zones
func (kdc *KdcDB) GetAllDNSSECKeys() ([]*DNSSECKey, error) {
	rows, err := kdc.DB.Query(
		`SELECT id, zone_id, key_type, key_id, algorithm, flags, public_key, private_key, 
			state, created_at, published_at, activated_at, retired_at, comment
			FROM dnssec_keys ORDER BY zone_id, key_type, created_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query all DNSSEC keys: %v", err)
	}
	defer rows.Close()

	var keys []*DNSSECKey
	for rows.Next() {
		key := &DNSSECKey{}
		var publishedAt, activatedAt, retiredAt sql.NullTime
		if err := rows.Scan(
			&key.ID, &key.ZoneID, &key.KeyType, &key.KeyID, &key.Algorithm, &key.Flags,
			&key.PublicKey, &key.PrivateKey, &key.State, &key.CreatedAt,
			&publishedAt, &activatedAt, &retiredAt, &key.Comment,
		); err != nil {
			return nil, fmt.Errorf("failed to scan DNSSEC key: %v", err)
		}
		if publishedAt.Valid {
			key.PublishedAt = &publishedAt.Time
		}
		if activatedAt.Valid {
			key.ActivatedAt = &activatedAt.Time
		}
		if retiredAt.Valid {
			key.RetiredAt = &retiredAt.Time
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// GetActiveZSKsForZone retrieves active ZSK keys for a zone
func (kdc *KdcDB) GetActiveZSKsForZone(zoneID string) ([]*DNSSECKey, error) {
	rows, err := kdc.DB.Query(
		`SELECT id, zone_id, key_type, key_id, algorithm, flags, public_key, private_key, 
			state, created_at, published_at, activated_at, retired_at, comment
			FROM dnssec_keys 
			WHERE zone_id = ? AND key_type = 'ZSK' AND state = 'active'
			ORDER BY created_at`,
		zoneID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query active ZSKs: %v", err)
	}
	defer rows.Close()

	var keys []*DNSSECKey
	for rows.Next() {
		key := &DNSSECKey{}
		var publishedAt, activatedAt, retiredAt sql.NullTime
		if err := rows.Scan(
			&key.ID, &key.ZoneID, &key.KeyType, &key.KeyID, &key.Algorithm, &key.Flags,
			&key.PublicKey, &key.PrivateKey, &key.State, &key.CreatedAt,
			&publishedAt, &activatedAt, &retiredAt, &key.Comment,
		); err != nil {
			return nil, fmt.Errorf("failed to scan DNSSEC key: %v", err)
		}
		if publishedAt.Valid {
			key.PublishedAt = &publishedAt.Time
		}
		if activatedAt.Valid {
			key.ActivatedAt = &activatedAt.Time
		}
		if retiredAt.Valid {
			key.RetiredAt = &retiredAt.Time
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// DeleteDNSSECKey deletes a DNSSEC key
func (kdc *KdcDB) DeleteDNSSECKey(zoneID, keyID string) error {
	_, err := kdc.DB.Exec(
		`DELETE FROM dnssec_keys WHERE zone_id = ? AND id = ?`,
		zoneID, keyID,
	)
	if err != nil {
		return fmt.Errorf("failed to delete DNSSEC key: %v", err)
	}
	return nil
}

// AddDistributionRecord adds a distribution record
func (kdc *KdcDB) AddDistributionRecord(record *DistributionRecord) error {
	_, err := kdc.DB.Exec(
		`INSERT INTO distribution_records 
			(id, zone_id, key_id, node_id, encrypted_key, ephemeral_pub_key, expires_at, status, distribution_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID, record.ZoneID, record.KeyID, record.NodeID, record.EncryptedKey,
		record.EphemeralPubKey, record.ExpiresAt, record.Status, record.DistributionID,
	)
	if err != nil {
		return fmt.Errorf("failed to add distribution record: %v", err)
	}
	return nil
}

// UpdateDistributionStatus updates a distribution record's status
func (kdc *KdcDB) UpdateDistributionStatus(distributionID string, status hpke.DistributionStatus) error {
	_, err := kdc.DB.Exec(
		"UPDATE distribution_records SET status = ? WHERE distribution_id = ?",
		status, distributionID,
	)
	if err != nil {
		return fmt.Errorf("failed to update distribution status: %v", err)
	}
	return nil
}

// GetDistributionRecordsForZoneKey retrieves distribution records for a specific zone and key
// Returns the most recent active/pending distribution record, or nil if none exists
func (kdc *KdcDB) GetDistributionRecordsForZoneKey(zoneID, keyID string) ([]*DistributionRecord, error) {
	rows, err := kdc.DB.Query(
		`SELECT id, zone_id, key_id, node_id, encrypted_key, ephemeral_pub_key, 
			created_at, expires_at, status, distribution_id
			FROM distribution_records 
			WHERE zone_id = ? AND key_id = ? 
			ORDER BY created_at DESC`,
		zoneID, keyID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query distribution records: %v", err)
	}
	defer rows.Close()

	var records []*DistributionRecord
	for rows.Next() {
		record := &DistributionRecord{}
		var nodeID sql.NullString
		var expiresAt sql.NullTime
		var statusStr string
		if err := rows.Scan(
			&record.ID, &record.ZoneID, &record.KeyID, &nodeID,
			&record.EncryptedKey, &record.EphemeralPubKey, &record.CreatedAt,
			&expiresAt, &statusStr, &record.DistributionID,
		); err != nil {
			return nil, fmt.Errorf("failed to scan distribution record: %v", err)
		}
		if nodeID.Valid {
			record.NodeID = nodeID.String
		}
		if expiresAt.Valid {
			record.ExpiresAt = &expiresAt.Time
		}
		record.Status = hpke.DistributionStatus(statusStr)
		records = append(records, record)
	}
	return records, rows.Err()
}

// GetOrCreateDistributionID gets an existing distribution ID for a key, or generates a stable one
// The distribution ID is a hex-encoded string based on zone and key ID, ensuring stability
func (kdc *KdcDB) GetOrCreateDistributionID(zoneID string, key *DNSSECKey) (string, error) {
	// Check if there's an existing distribution record for this key
	records, err := kdc.GetDistributionRecordsForZoneKey(zoneID, key.ID)
	if err == nil && len(records) > 0 {
		// Use the distribution ID from the most recent record
		return records[0].DistributionID, nil
	}

	// Generate a stable distribution ID: hex-encoded keytag (16-bit, so 4 hex chars)
	// Format: <keytag-hex> (e.g., "a1b2" for keytag 41394)
	distributionID := fmt.Sprintf("%04x", key.KeyID)
	return distributionID, nil
}

// AddDistributionConfirmation records that a node has confirmed receipt of a distributed key
func (kdc *KdcDB) AddDistributionConfirmation(distributionID, zoneID, keyID, nodeID string) error {
	// Generate a unique ID for this confirmation
	confirmationID := fmt.Sprintf("%s-%s-%d", distributionID, nodeID, time.Now().Unix())
	
	var err error
	if kdc.DBType == "sqlite" {
		// SQLite: Use INSERT OR REPLACE (works with UNIQUE constraint)
		_, err = kdc.DB.Exec(
			`INSERT OR REPLACE INTO distribution_confirmations 
				(id, distribution_id, zone_id, key_id, node_id, confirmed_at)
				VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
			confirmationID, distributionID, zoneID, keyID, nodeID,
		)
	} else {
		// MySQL/MariaDB: Use ON DUPLICATE KEY UPDATE
		_, err = kdc.DB.Exec(
			`INSERT INTO distribution_confirmations 
				(id, distribution_id, zone_id, key_id, node_id, confirmed_at)
				VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
				ON DUPLICATE KEY UPDATE confirmed_at = CURRENT_TIMESTAMP`,
			confirmationID, distributionID, zoneID, keyID, nodeID,
		)
	}
	if err != nil {
		return fmt.Errorf("failed to add distribution confirmation: %v", err)
	}
	return nil
}

// GetDistributionConfirmations returns all confirmations for a given distribution ID
func (kdc *KdcDB) GetDistributionConfirmations(distributionID string) ([]string, error) {
	rows, err := kdc.DB.Query(
		`SELECT DISTINCT node_id FROM distribution_confirmations WHERE distribution_id = ?`,
		distributionID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query distribution confirmations: %v", err)
	}
	defer rows.Close()

	var nodeIDs []string
	for rows.Next() {
		var nodeID string
		if err := rows.Scan(&nodeID); err != nil {
			return nil, fmt.Errorf("failed to scan confirmation: %v", err)
		}
		nodeIDs = append(nodeIDs, nodeID)
	}
	return nodeIDs, rows.Err()
}

// CheckAllNodesConfirmed checks if all active nodes for a zone have confirmed receipt of a distributed key
func (kdc *KdcDB) CheckAllNodesConfirmed(distributionID, zoneID string) (bool, error) {
	// Get all active nodes for this zone
	// For now, assume all nodes serve all zones (simplified model)
	rows, err := kdc.DB.Query(
		`SELECT id FROM nodes WHERE state = 'online'`,
	)
	if err != nil {
		return false, fmt.Errorf("failed to query active nodes: %v", err)
	}
	defer rows.Close()

	var activeNodeIDs []string
	for rows.Next() {
		var nodeID string
		if err := rows.Scan(&nodeID); err != nil {
			return false, fmt.Errorf("failed to scan node ID: %v", err)
		}
		activeNodeIDs = append(activeNodeIDs, nodeID)
	}
	if err := rows.Err(); err != nil {
		return false, err
	}

	if len(activeNodeIDs) == 0 {
		// No active nodes, so technically all have "confirmed" (trivially true)
		return true, nil
	}

	// Get confirmed node IDs for this distribution
	confirmedNodeIDs, err := kdc.GetDistributionConfirmations(distributionID)
	if err != nil {
		return false, err
	}

	// Check if all active nodes have confirmed
	confirmedMap := make(map[string]bool)
	for _, nodeID := range confirmedNodeIDs {
		confirmedMap[nodeID] = true
	}

	for _, nodeID := range activeNodeIDs {
		if !confirmedMap[nodeID] {
			return false, nil
		}
	}

	return true, nil
}

// UpdateKeyState updates the state of a DNSSEC key
func (kdc *KdcDB) UpdateKeyState(zoneID, keyID string, newState KeyState) error {
	now := time.Now()
	var err error
	
	switch newState {
	case KeyStatePublished:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ?, published_at = ? WHERE zone_id = ? AND id = ?`,
			newState, now, zoneID, keyID,
		)
	case KeyStateStandby:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ? WHERE zone_id = ? AND id = ?`,
			newState, zoneID, keyID,
		)
	case KeyStateActive:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ?, activated_at = ? WHERE zone_id = ? AND id = ?`,
			newState, now, zoneID, keyID,
		)
	case KeyStateDistributed:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ? WHERE zone_id = ? AND id = ?`,
			newState, zoneID, keyID,
		)
	case KeyStateEdgeSigner:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ? WHERE zone_id = ? AND id = ?`,
			newState, zoneID, keyID,
		)
	case KeyStateRetired:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ?, retired_at = ? WHERE zone_id = ? AND id = ?`,
			newState, now, zoneID, keyID,
		)
	case KeyStateRemoved:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ? WHERE zone_id = ? AND id = ?`,
			newState, zoneID, keyID,
		)
	default:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ? WHERE zone_id = ? AND id = ?`,
			newState, zoneID, keyID,
		)
	}
	
	if err != nil {
		return fmt.Errorf("failed to update key state: %v", err)
	}
	return nil
}

// GetKeysByState retrieves keys in a specific state for a zone (or all zones if zoneID is empty)
func (kdc *KdcDB) GetKeysByState(zoneID string, state KeyState) ([]*DNSSECKey, error) {
	var rows *sql.Rows
	var err error
	
	if zoneID == "" {
		rows, err = kdc.DB.Query(
			`SELECT id, zone_id, key_type, key_id, algorithm, flags, public_key, private_key,
				state, created_at, published_at, activated_at, retired_at, comment
				FROM dnssec_keys WHERE state = ? ORDER BY zone_id, created_at`,
			state,
		)
	} else {
		rows, err = kdc.DB.Query(
			`SELECT id, zone_id, key_type, key_id, algorithm, flags, public_key, private_key,
				state, created_at, published_at, activated_at, retired_at, comment
				FROM dnssec_keys WHERE zone_id = ? AND state = ? ORDER BY created_at`,
			zoneID, state,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query keys by state: %v", err)
	}
	defer rows.Close()

	var keys []*DNSSECKey
	for rows.Next() {
		key := &DNSSECKey{}
		var publishedAt, activatedAt, retiredAt sql.NullTime
		if err := rows.Scan(
			&key.ID, &key.ZoneID, &key.KeyType, &key.KeyID, &key.Algorithm, &key.Flags,
			&key.PublicKey, &key.PrivateKey, &key.State, &key.CreatedAt,
			&publishedAt, &activatedAt, &retiredAt, &key.Comment,
		); err != nil {
			return nil, fmt.Errorf("failed to scan DNSSEC key: %v", err)
		}
		if publishedAt.Valid {
			key.PublishedAt = &publishedAt.Time
		}
		if activatedAt.Valid {
			key.ActivatedAt = &activatedAt.Time
		}
		if retiredAt.Valid {
			key.RetiredAt = &retiredAt.Time
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// GetDNSSECKeyByID retrieves a DNSSEC key by its ID (keytag) for a zone
func (kdc *KdcDB) GetDNSSECKeyByID(zoneID, keyID string) (*DNSSECKey, error) {
	var key DNSSECKey
	var publishedAt, activatedAt, retiredAt sql.NullTime
	err := kdc.DB.QueryRow(
		`SELECT id, zone_id, key_type, key_id, algorithm, flags, public_key, private_key, 
			state, created_at, published_at, activated_at, retired_at, comment
			FROM dnssec_keys WHERE zone_id = ? AND id = ?`,
		zoneID, keyID,
	).Scan(
		&key.ID, &key.ZoneID, &key.KeyType, &key.KeyID, &key.Algorithm, &key.Flags,
		&key.PublicKey, &key.PrivateKey, &key.State, &key.CreatedAt,
		&publishedAt, &activatedAt, &retiredAt, &key.Comment,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("key %s not found for zone %s", keyID, zoneID)
		}
		return nil, fmt.Errorf("failed to get DNSSEC key: %v", err)
	}
	if publishedAt.Valid {
		key.PublishedAt = &publishedAt.Time
	}
	if activatedAt.Valid {
		key.ActivatedAt = &activatedAt.Time
	}
	if retiredAt.Valid {
		key.RetiredAt = &retiredAt.Time
	}
	return &key, nil
}

