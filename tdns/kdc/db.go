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
		return kdc.initSchemaSQLite()
	}
	return kdc.initSchemaMySQL()
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
			state ENUM('created', 'published', 'active', 'standby', 'retired', 'revoked') NOT NULL DEFAULT 'created',
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
	}

	for _, stmt := range schema {
		if _, err := kdc.DB.Exec(stmt); err != nil {
			return fmt.Errorf("failed to execute schema statement: %v\nStatement: %s", err, stmt)
		}
	}

	log.Printf("KDC database schema initialized successfully (MySQL/MariaDB)")
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
			CHECK (state IN ('created', 'published', 'active', 'standby', 'retired', 'revoked'))
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
	}

	for _, stmt := range schema {
		if _, err := kdc.DB.Exec(stmt); err != nil {
			return fmt.Errorf("failed to execute schema statement: %v\nStatement: %s", err, stmt)
		}
	}

	log.Printf("KDC database schema initialized successfully (SQLite)")
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
	err := kdc.DB.QueryRow(
		"SELECT id, name, long_term_pub_key, registered_at, last_seen, state, comment FROM nodes WHERE id = ?",
		nodeID,
	).Scan(&n.ID, &n.Name, &n.LongTermPubKey, &n.RegisteredAt, &n.LastSeen, &n.State, &n.Comment)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("node not found: %s", nodeID)
		}
		return nil, fmt.Errorf("failed to get node: %v", err)
	}
	return &n, nil
}

// GetAllNodes retrieves all nodes
func (kdc *KdcDB) GetAllNodes() ([]*Node, error) {
	rows, err := kdc.DB.Query("SELECT id, name, long_term_pub_key, registered_at, last_seen, state, comment FROM nodes ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("failed to query nodes: %v", err)
	}
	defer rows.Close()

	var nodes []*Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Name, &n.LongTermPubKey, &n.RegisteredAt, &n.LastSeen, &n.State, &n.Comment); err != nil {
			return nil, fmt.Errorf("failed to scan node: %v", err)
		}
		nodes = append(nodes, &n)
	}
	return nodes, rows.Err()
}

// GetActiveNodes retrieves all active (online) nodes
func (kdc *KdcDB) GetActiveNodes() ([]*Node, error) {
	rows, err := kdc.DB.Query(
		"SELECT id, name, long_term_pub_key, registered_at, last_seen, state, comment FROM nodes WHERE state = 'online' ORDER BY name",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query active nodes: %v", err)
	}
	defer rows.Close()

	var nodes []*Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Name, &n.LongTermPubKey, &n.RegisteredAt, &n.LastSeen, &n.State, &n.Comment); err != nil {
			return nil, fmt.Errorf("failed to scan node: %v", err)
		}
		nodes = append(nodes, &n)
	}
	return nodes, rows.Err()
}

// GetNodeByPublicKey retrieves a node by its long-term public key
func (kdc *KdcDB) GetNodeByPublicKey(pubKey []byte) (*Node, error) {
	var n Node
	err := kdc.DB.QueryRow(
		"SELECT id, name, long_term_pub_key, registered_at, last_seen, state, comment FROM nodes WHERE long_term_pub_key = ?",
		pubKey,
	).Scan(&n.ID, &n.Name, &n.LongTermPubKey, &n.RegisteredAt, &n.LastSeen, &n.State, &n.Comment)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No node found with this public key
		}
		return nil, fmt.Errorf("failed to get node by public key: %v", err)
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
		"INSERT INTO nodes (id, name, long_term_pub_key, state, comment) VALUES (?, ?, ?, ?, ?)",
		node.ID, node.Name, node.LongTermPubKey, node.State, node.Comment,
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
		"UPDATE nodes SET name = ?, long_term_pub_key = ?, state = ?, comment = ? WHERE id = ?",
		node.Name, node.LongTermPubKey, node.State, node.Comment, node.ID,
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

// UpdateKeyState updates a key's state and timestamps
func (kdc *KdcDB) UpdateKeyState(keyID string, state KeyState) error {
	now := time.Now()
	var updateStmt string
	switch state {
	case KeyStatePublished:
		updateStmt = "UPDATE dnssec_keys SET state = ?, published_at = ? WHERE id = ?"
	case KeyStateActive:
		updateStmt = "UPDATE dnssec_keys SET state = ?, activated_at = ? WHERE id = ?"
	case KeyStateRetired:
		updateStmt = "UPDATE dnssec_keys SET state = ?, retired_at = ? WHERE id = ?"
	default:
		updateStmt = "UPDATE dnssec_keys SET state = ? WHERE id = ?"
		_, err := kdc.DB.Exec(updateStmt, state, keyID)
		return err
	}
	_, err := kdc.DB.Exec(updateStmt, state, now, keyID)
	if err != nil {
		return fmt.Errorf("failed to update key state: %v", err)
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

