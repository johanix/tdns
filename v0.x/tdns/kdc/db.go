/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Database schema and operations for tdns-kdc
 * Uses MariaDB for production-grade reliability
 */

package kdc

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql" // MariaDB driver
	"github.com/johanix/tdns/v0.x/tdns/hpke"
	_ "github.com/mattn/go-sqlite3" // SQLite driver
	"github.com/miekg/dns"
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

	var dsnWithParams string
	if strings.ToLower(dbType) == "sqlite" || strings.ToLower(dbType) == "sqlite3" {
		// SQLite: Add busy_timeout and other pragmas via query parameters
		// busy_timeout=5000 means wait up to 5 seconds for locks to clear
		// WAL mode provides better concurrency
		if strings.Contains(dsn, "?") {
			dsnWithParams = dsn + "&_busy_timeout=5000&_journal_mode=WAL"
		} else {
			dsnWithParams = dsn + "?_busy_timeout=5000&_journal_mode=WAL"
		}
	} else {
		dsnWithParams = dsn
	}

	db, err := sql.Open(driverName, dsnWithParams)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}
	
	// For SQLite, set additional pragmas after connection
	if strings.ToLower(dbType) == "sqlite" || strings.ToLower(dbType) == "sqlite3" {
		// Set busy timeout (in milliseconds) - wait up to 5 seconds for locks
		if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
			return nil, fmt.Errorf("failed to set busy_timeout: %v", err)
		}
		// Enable WAL mode for better concurrency (if not already set via DSN)
		if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
			log.Printf("KDC: Warning: Failed to set journal_mode to WAL: %v", err)
		}
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
		// Services table
		`CREATE TABLE IF NOT EXISTS services (
			id VARCHAR(255) PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			active BOOLEAN NOT NULL DEFAULT TRUE,
			comment TEXT,
			INDEX idx_active (active)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// Components table
		`CREATE TABLE IF NOT EXISTS components (
			id VARCHAR(255) PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			active BOOLEAN NOT NULL DEFAULT TRUE,
			comment TEXT,
			INDEX idx_active (active)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// Zones table
		// Note: signing_mode is derived from component assignment, not stored here
		`CREATE TABLE IF NOT EXISTS zones (
			name VARCHAR(255) PRIMARY KEY,
			service_id VARCHAR(255),
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			active BOOLEAN NOT NULL DEFAULT TRUE,
			comment TEXT,
			FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE SET NULL,
			INDEX idx_active (active),
			INDEX idx_service_id (service_id)
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
			zone_name VARCHAR(255) NOT NULL,
			key_type ENUM('KSK', 'ZSK', 'CSK') NOT NULL,
			key_id SMALLINT UNSIGNED NOT NULL,
			algorithm TINYINT UNSIGNED NOT NULL,
			flags SMALLINT UNSIGNED NOT NULL,
			public_key TEXT NOT NULL,
			private_key BLOB NOT NULL,
			state ENUM('created', 'published', 'standby', 'active', 'active_dist', 'active_ce', 'distributed', 'edgesigner', 'retired', 'removed', 'revoked') NOT NULL DEFAULT 'created',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			published_at TIMESTAMP NULL,
			activated_at TIMESTAMP NULL,
			retired_at TIMESTAMP NULL,
			comment TEXT,
			FOREIGN KEY (zone_name) REFERENCES zones(name) ON DELETE CASCADE,
			INDEX idx_zone_name (zone_name),
			INDEX idx_key_type (key_type),
			INDEX idx_state (state),
			INDEX idx_zone_key_type_state (zone_name, key_type, state)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// Distribution records table
		`CREATE TABLE IF NOT EXISTS distribution_records (
			id VARCHAR(255) PRIMARY KEY,
			zone_name VARCHAR(255) NOT NULL,
			key_id VARCHAR(255) NOT NULL,
			node_id VARCHAR(255),
			encrypted_key BLOB NOT NULL,
			ephemeral_pub_key BLOB NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NULL,
			status ENUM('pending', 'delivered', 'active', 'revoked', 'completed') NOT NULL DEFAULT 'pending',
			distribution_id VARCHAR(255) NOT NULL,
			FOREIGN KEY (zone_name) REFERENCES zones(name) ON DELETE CASCADE,
			FOREIGN KEY (key_id) REFERENCES dnssec_keys(id) ON DELETE CASCADE,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
			INDEX idx_zone_name (zone_name),
			INDEX idx_key_id (key_id),
			INDEX idx_node_id (node_id),
			INDEX idx_status (status),
			INDEX idx_distribution_id (distribution_id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// Service-component assignments table (many-to-many)
		`CREATE TABLE IF NOT EXISTS service_component_assignments (
			service_id VARCHAR(255) NOT NULL,
			component_id VARCHAR(255) NOT NULL,
			active BOOLEAN NOT NULL DEFAULT TRUE,
			since TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (service_id, component_id),
			FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
			FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE CASCADE,
			INDEX idx_component_id (component_id),
			INDEX idx_active (active)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// Node-component assignments table (many-to-many)
		`CREATE TABLE IF NOT EXISTS node_component_assignments (
			node_id VARCHAR(255) NOT NULL,
			component_id VARCHAR(255) NOT NULL,
			active BOOLEAN NOT NULL DEFAULT TRUE,
			since TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (node_id, component_id),
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
			FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE CASCADE,
			INDEX idx_component_id (component_id),
			INDEX idx_active (active)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// Distribution confirmations table - tracks which nodes have confirmed receipt of distributed keys
		`CREATE TABLE IF NOT EXISTS distribution_confirmations (
			id VARCHAR(255) PRIMARY KEY,
			distribution_id VARCHAR(255) NOT NULL,
			zone_name VARCHAR(255) NOT NULL,
			key_id VARCHAR(255) NOT NULL,
			node_id VARCHAR(255) NOT NULL,
			confirmed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (zone_name) REFERENCES zones(name) ON DELETE CASCADE,
			FOREIGN KEY (key_id) REFERENCES dnssec_keys(id) ON DELETE CASCADE,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
			INDEX idx_distribution_id (distribution_id),
			INDEX idx_zone_key (zone_name, key_id),
			INDEX idx_node_id (node_id),
			UNIQUE KEY idx_distribution_node (distribution_id, node_id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// Service transactions table - tracks pending service modifications
		`CREATE TABLE IF NOT EXISTS service_transactions (
			id VARCHAR(255) PRIMARY KEY,
			service_id VARCHAR(255) NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			state ENUM('open', 'committed', 'rolled_back') NOT NULL DEFAULT 'open',
			changes JSON NOT NULL,
			created_by VARCHAR(255),
			comment TEXT,
			service_snapshot JSON,
			FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
			INDEX idx_service_id (service_id),
			INDEX idx_state (state),
			INDEX idx_expires_at (expires_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}

	for _, stmt := range schema {
		if _, err := kdc.DB.Exec(stmt); err != nil {
			return fmt.Errorf("failed to execute schema statement: %v\nStatement: %s", err, stmt)
		}
	}

	log.Printf("KDC database schema initialized successfully (MySQL/MariaDB)")
	
	// Migrate: Add completed_at column if it doesn't exist
	if err := kdc.migrateAddCompletedAtColumn(); err != nil {
		log.Printf("KDC: Warning: Failed to migrate completed_at column: %v", err)
	} else {
		// Create index on completed_at after the column has been added
		if _, err := kdc.DB.Exec(`CREATE INDEX IF NOT EXISTS idx_distribution_records_completed_at ON distribution_records(completed_at)`); err != nil {
			log.Printf("KDC: Warning: Failed to create index on completed_at: %v", err)
		}
	}
	
	// Migrate: Update status ENUM to include 'completed'
	if err := kdc.migrateAddCompletedStatus(); err != nil {
		log.Printf("KDC: Warning: Failed to migrate status ENUM: %v", err)
	}
	
	// Migrate: Update state ENUM to include 'active_dist'
	if err := kdc.migrateAddActiveDistState(); err != nil {
		log.Printf("KDC: Warning: Failed to migrate state ENUM: %v", err)
	}
	
	// Migrate: Update state ENUM to include 'active_ce'
	if err := kdc.migrateAddActiveCEState(); err != nil {
		log.Printf("KDC: Warning: Failed to migrate state ENUM for active_ce: %v", err)
	}
	
	// Ensure default service/component exist
	if err := kdc.ensureDefaultServiceAndComponent(); err != nil {
		return fmt.Errorf("failed to ensure default service/component: %v", err)
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
		// Services table
		`CREATE TABLE IF NOT EXISTS services (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			active INTEGER NOT NULL DEFAULT 1,
			comment TEXT,
			CHECK (active IN (0, 1))
		)`,

		// Components table
		`CREATE TABLE IF NOT EXISTS components (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			active INTEGER NOT NULL DEFAULT 1,
			comment TEXT,
			CHECK (active IN (0, 1))
		)`,

		// Zones table
		// Note: signing_mode is derived from component assignment, not stored here
		`CREATE TABLE IF NOT EXISTS zones (
			name TEXT PRIMARY KEY,
			service_id TEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			active INTEGER NOT NULL DEFAULT 1,
			comment TEXT,
			FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE SET NULL,
			CHECK (active IN (0, 1))
		)`,

		// Trigger to update updated_at on services
		`CREATE TRIGGER IF NOT EXISTS services_updated_at 
			AFTER UPDATE ON services
			BEGIN
				UPDATE services SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
			END`,

		// Trigger to update updated_at on components
		`CREATE TRIGGER IF NOT EXISTS components_updated_at 
			AFTER UPDATE ON components
			BEGIN
				UPDATE components SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
			END`,

		// Trigger to update updated_at on zones
		`CREATE TRIGGER IF NOT EXISTS zones_updated_at 
			AFTER UPDATE ON zones
			BEGIN
				UPDATE zones SET updated_at = CURRENT_TIMESTAMP WHERE name = NEW.name;
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
		)`,

		// Distribution records table
		`CREATE TABLE IF NOT EXISTS distribution_records (
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
		)`,

		// Service-component assignments table (many-to-many)
		`CREATE TABLE IF NOT EXISTS service_component_assignments (
			service_id TEXT NOT NULL,
			component_id TEXT NOT NULL,
			active INTEGER NOT NULL DEFAULT 1,
			since DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (service_id, component_id),
			FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
			FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE CASCADE,
			CHECK (active IN (0, 1))
		)`,

		// Node-component assignments table (many-to-many)
		`CREATE TABLE IF NOT EXISTS node_component_assignments (
			node_id TEXT NOT NULL,
			component_id TEXT NOT NULL,
			active INTEGER NOT NULL DEFAULT 1,
			since DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (node_id, component_id),
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
			FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE CASCADE,
			CHECK (active IN (0, 1))
		)`,

		// Distribution confirmations table - tracks which nodes have confirmed receipt of distributed keys
		`CREATE TABLE IF NOT EXISTS distribution_confirmations (
			id TEXT PRIMARY KEY,
			distribution_id TEXT NOT NULL,
			zone_name TEXT NOT NULL,
			key_id TEXT NOT NULL,
			node_id TEXT NOT NULL,
			confirmed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (zone_name) REFERENCES zones(name) ON DELETE CASCADE,
			FOREIGN KEY (key_id) REFERENCES dnssec_keys(id) ON DELETE CASCADE,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
			UNIQUE (distribution_id, node_id)
		)`,

		// Service transactions table - tracks pending service modifications
		`CREATE TABLE IF NOT EXISTS service_transactions (
			id TEXT PRIMARY KEY,
			service_id TEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL,
			state TEXT NOT NULL DEFAULT 'open',
			changes TEXT NOT NULL,
			created_by TEXT,
			comment TEXT,
			service_snapshot TEXT,
			FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
			CHECK (state IN ('open', 'committed', 'rolled_back'))
		)`,

		// Create indexes
		`CREATE INDEX IF NOT EXISTS idx_services_active ON services(active)`,
		`CREATE INDEX IF NOT EXISTS idx_components_active ON components(active)`,
		`CREATE INDEX IF NOT EXISTS idx_zones_active ON zones(active)`,
		`CREATE INDEX IF NOT EXISTS idx_zones_service_id ON zones(service_id)`,
		`CREATE INDEX IF NOT EXISTS idx_zones_signing_mode ON zones(signing_mode)`,
		`CREATE INDEX IF NOT EXISTS idx_nodes_state ON nodes(state)`,
		`CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen)`,
		`CREATE INDEX IF NOT EXISTS idx_dnssec_keys_zone_name ON dnssec_keys(zone_name)`,
		`CREATE INDEX IF NOT EXISTS idx_dnssec_keys_key_type ON dnssec_keys(key_type)`,
		`CREATE INDEX IF NOT EXISTS idx_dnssec_keys_state ON dnssec_keys(state)`,
		`CREATE INDEX IF NOT EXISTS idx_dnssec_keys_zone_key_type_state ON dnssec_keys(zone_name, key_type, state)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_records_zone_name ON distribution_records(zone_name)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_records_key_id ON distribution_records(key_id)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_records_node_id ON distribution_records(node_id)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_records_status ON distribution_records(status)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_records_distribution_id ON distribution_records(distribution_id)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_confirmations_distribution_id ON distribution_confirmations(distribution_id)`,
		`CREATE INDEX IF NOT EXISTS idx_service_transactions_service_id ON service_transactions(service_id)`,
		`CREATE INDEX IF NOT EXISTS idx_service_transactions_state ON service_transactions(state)`,
		`CREATE INDEX IF NOT EXISTS idx_service_transactions_expires_at ON service_transactions(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_confirmations_zone_key ON distribution_confirmations(zone_name, key_id)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_confirmations_node_id ON distribution_confirmations(node_id)`,
	}

	for _, stmt := range schema {
		if _, err := kdc.DB.Exec(stmt); err != nil {
			return fmt.Errorf("failed to execute schema statement: %v\nStatement: %s", err, stmt)
		}
	}

	log.Printf("KDC database schema initialized successfully (SQLite)")
	
	// Migrate: Add completed_at column if it doesn't exist
	if err := kdc.migrateAddCompletedAtColumn(); err != nil {
		log.Printf("KDC: Warning: Failed to migrate completed_at column: %v", err)
	} else {
		// Create index on completed_at after the column has been added
		if _, err := kdc.DB.Exec(`CREATE INDEX IF NOT EXISTS idx_distribution_records_completed_at ON distribution_records(completed_at)`); err != nil {
			log.Printf("KDC: Warning: Failed to create index on completed_at: %v", err)
		}
	}
	
	// Migrate: Update status CHECK constraint to include 'completed'
	if err := kdc.migrateAddCompletedStatus(); err != nil {
		log.Printf("KDC: Warning: Failed to migrate status CHECK constraint: %v", err)
	}
	
	// Migrate: Update state CHECK constraint to include 'active_dist'
	if err := kdc.migrateAddActiveDistState(); err != nil {
		log.Printf("KDC: Warning: Failed to migrate state CHECK constraint: %v", err)
	}
	
	// Migrate: Update state CHECK constraint to include 'active_ce'
	if err := kdc.migrateAddActiveCEState(); err != nil {
		log.Printf("KDC: Warning: Failed to migrate state CHECK constraint for active_ce: %v", err)
	}
	
	// Ensure default service/component exist
	if err := kdc.ensureDefaultServiceAndComponent(); err != nil {
		return fmt.Errorf("failed to ensure default service/component: %v", err)
	}
	
	return nil
}

// DeriveSigningModeFromComponent derives the signing mode from a component ID
// Component IDs are in the format "sign_<signing_mode>" (e.g., "sign_edge_full", "sign_kdc", "sign_upstream")
// Also handles legacy "sign_edge_all" for backward compatibility
func DeriveSigningModeFromComponent(componentID string) ZoneSigningMode {
	if strings.HasPrefix(componentID, "sign_") {
		mode := strings.TrimPrefix(componentID, "sign_")
		switch mode {
		case "upstream":
			return ZoneSigningModeUpstream
		case "kdc":
			return ZoneSigningModeCentral
		case "edge_dyn":
			return ZoneSigningModeEdgesignDyn
		case "edge_zsk":
			return ZoneSigningModeEdgesignZsk
		case "edge_full":
			return ZoneSigningModeEdgesignFull
		case "edge_all": // Legacy name, map to edgesign_full
			return ZoneSigningModeEdgesignFull
		case "unsigned":
			return ZoneSigningModeUnsigned
		}
	}
	// Default to central if component ID doesn't match expected pattern
	return ZoneSigningModeCentral
}

// GetZoneSigningMode retrieves the signing mode for a zone by looking at its service's components
// Zones derive components from their service, not from direct component assignments
func (kdc *KdcDB) GetZoneSigningMode(zoneName string) (ZoneSigningMode, error) {
	zone, err := kdc.GetZone(zoneName)
	if err != nil {
		return ZoneSigningModeCentral, fmt.Errorf("failed to get zone: %v", err)
	}
	
	if zone.ServiceID == "" {
		// No service assignment, default to central
		return ZoneSigningModeCentral, nil
	}
	
	// Get components from the service
	components, err := kdc.GetComponentsForService(zone.ServiceID)
	if err != nil {
		return ZoneSigningModeCentral, fmt.Errorf("failed to get components for service: %v", err)
	}
	if len(components) == 0 {
		// No components in service, default to central
		return ZoneSigningModeCentral, nil
	}
	
	// Use the first signing component's signing mode
	// Prefer sign_kdc if available, otherwise use first sign_* component
	for _, compID := range components {
		if compID == "sign_kdc" {
			return DeriveSigningModeFromComponent(compID), nil
		}
	}
	for _, compID := range components {
		if strings.HasPrefix(compID, "sign_") {
			return DeriveSigningModeFromComponent(compID), nil
		}
	}
	
	// No signing component found, default to central
	return ZoneSigningModeCentral, nil
}

// GetZone retrieves a zone by name
func (kdc *KdcDB) GetZone(zoneName string) (*Zone, error) {
	var z Zone
	var updatedAt sql.NullTime
	var serviceID sql.NullString
	err := kdc.DB.QueryRow(
		"SELECT name, service_id, created_at, updated_at, active, comment FROM zones WHERE name = ?",
		zoneName,
	).Scan(&z.Name, &serviceID, &z.CreatedAt, &updatedAt, &z.Active, &z.Comment)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("zone not found: %s", zoneName)
		}
		return nil, fmt.Errorf("failed to get zone: %v", err)
	}
	if updatedAt.Valid {
		z.UpdatedAt = updatedAt.Time
	}
	if serviceID.Valid {
		z.ServiceID = serviceID.String
	}
	return &z, nil
}

// GetAllZones retrieves all zones
func (kdc *KdcDB) GetAllZones() ([]*Zone, error) {
	rows, err := kdc.DB.Query("SELECT name, service_id, created_at, updated_at, active, comment FROM zones ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("failed to query zones: %v", err)
	}
	defer rows.Close()

	var zones []*Zone
	for rows.Next() {
		var z Zone
		var updatedAt sql.NullTime
		var serviceID sql.NullString
		if err := rows.Scan(&z.Name, &serviceID, &z.CreatedAt, &updatedAt, &z.Active, &z.Comment); err != nil {
			return nil, fmt.Errorf("failed to scan zone: %v", err)
		}
		if updatedAt.Valid {
			z.UpdatedAt = updatedAt.Time
		}
		if serviceID.Valid {
			z.ServiceID = serviceID.String
		}
		zones = append(zones, &z)
	}
	return zones, rows.Err()
}

// ensureDefaultServiceAndComponent ensures that default_service and signing-mode components exist
// Creates components for each signing mode: upstream, central, unsigned, edgesign_dyn, edgesign_zsk, edgesign_full
func (kdc *KdcDB) ensureDefaultServiceAndComponent() error {
	const defaultServiceID = "default_service"
	const defaultComponentID = "default_comp"
	
	// Check if default service exists
	var serviceExists bool
	err := kdc.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM services WHERE id = ?)", defaultServiceID).Scan(&serviceExists)
	if err != nil {
		return fmt.Errorf("failed to check default service: %v", err)
	}
	
	if !serviceExists {
		// Create default service
		defaultService := &Service{
			ID:      defaultServiceID,
			Name:    "Default Service",
			Active:  true,
			Comment: "Default service for zones without explicit service assignment",
		}
		if err := kdc.AddService(defaultService); err != nil {
			return fmt.Errorf("failed to create default service: %v", err)
		}
		log.Printf("KDC: Created default service: %s", defaultServiceID)
	}
	
	// Create components for each signing mode
	signingModeComponents := map[string]string{
		"upstream":   "Component for upstream-signed zones",
		"kdc":        "Component for centrally-signed zones",
		"unsigned":   "Component for unsigned zones",
		"edge_dyn":   "Component for edgesigned zones (dynamic responses only)",
		"edge_zsk":   "Component for edgesigned zones (all responses)",
		"edge_full":  "Component for fully edgesigned zones (KSK+ZSK)",
	}
	
	// Only assign sign_kdc to default_service (default signing mode)
	// Other sign_* components are created but not assigned (users must create services for them)
	defaultSigningComponentID := "sign_kdc"
	
	for mode, description := range signingModeComponents {
		componentID := fmt.Sprintf("sign_%s", mode)
		var componentExists bool
		err = kdc.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM components WHERE id = ?)", componentID).Scan(&componentExists)
		if err != nil {
			return fmt.Errorf("failed to check component %s: %v", componentID, err)
		}
		
		if !componentExists {
			component := &Component{
				ID:      componentID,
				Name:    fmt.Sprintf("Component for %s zones", mode),
				Active:  true,
				Comment: description,
			}
			if err := kdc.AddComponent(component); err != nil {
				return fmt.Errorf("failed to create component %s: %v", componentID, err)
			}
			log.Printf("KDC: Created component: %s", componentID)
		}
	}
	
	// Clean up any invalid sign_* component assignments on default_service
	// This handles cases where the database has multiple sign_* components assigned (from old code or manual edits)
	existingComponents, err := kdc.GetComponentsForService(defaultServiceID)
	if err != nil {
		return fmt.Errorf("failed to get existing components for default service: %v", err)
	}
	
	var signingComponents []string
	for _, compID := range existingComponents {
		if strings.HasPrefix(compID, "sign_") {
			signingComponents = append(signingComponents, compID)
		}
	}
	
	// Remove all sign_* components except sign_kdc (if it exists)
	// If sign_kdc doesn't exist in the list, we'll add it below
	hasSignKdc := false
	for _, compID := range signingComponents {
		if compID == defaultSigningComponentID {
			hasSignKdc = true
		} else {
			// Remove this signing component from default_service
			if err := kdc.RemoveServiceComponentAssignment(defaultServiceID, compID); err != nil {
				log.Printf("KDC: Warning: Failed to remove invalid signing component %s from default service: %v", compID, err)
			} else {
				log.Printf("KDC: Removed invalid signing component %s from default service (only sign_kdc allowed)", compID)
			}
		}
	}
	
	// Ensure sign_kdc is assigned to default_service
	if !hasSignKdc {
		// Check if sign_kdc component exists (it should after the loop above)
		var signKdcExists bool
		err = kdc.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM components WHERE id = ?)", defaultSigningComponentID).Scan(&signKdcExists)
		if err != nil {
			return fmt.Errorf("failed to check if sign_kdc component exists: %v", err)
		}
		if signKdcExists {
			// Check if assignment already exists (even if inactive)
			var assignmentExists bool
			err = kdc.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM service_component_assignments WHERE service_id = ? AND component_id = ?)", 
				defaultServiceID, defaultSigningComponentID).Scan(&assignmentExists)
			if err != nil {
				return fmt.Errorf("failed to check if assignment exists: %v", err)
			}
			
			if assignmentExists {
				// Reactivate existing assignment
				_, err = kdc.DB.Exec(
					"UPDATE service_component_assignments SET active = 1 WHERE service_id = ? AND component_id = ?",
					defaultServiceID, defaultSigningComponentID,
				)
				if err != nil {
					return fmt.Errorf("failed to reactivate component %s assignment to default service: %v", defaultSigningComponentID, err)
				}
				log.Printf("KDC: Reactivated component %s assignment to default service %s", defaultSigningComponentID, defaultServiceID)
			} else {
				// Create new assignment
				if err := kdc.AddServiceComponentAssignment(defaultServiceID, defaultSigningComponentID); err != nil {
					return fmt.Errorf("failed to assign component %s to default service: %v", defaultSigningComponentID, err)
				}
				log.Printf("KDC: Assigned component %s to default service %s", defaultSigningComponentID, defaultServiceID)
			}
		}
	}
	
	// Clean up old comp_* system components (migrated to sign_* naming)
	// Map old comp_* names to new sign_* names
	oldToNewComponentMap := map[string]string{
		"comp_central":        "sign_kdc",
		"comp_upstream":       "sign_upstream",
		"comp_unsigned":       "sign_unsigned",
		"comp_edgesign_dyn":   "sign_edge_dyn",
		"comp_edgesign_zsk":   "sign_edge_zsk",
		"comp_edgesign_all":   "sign_edge_full",
	}
	
	// Find all old comp_* components
	rows, err := kdc.DB.Query("SELECT id FROM components WHERE id LIKE 'comp_%'")
	if err != nil {
		log.Printf("KDC: Warning: Failed to query old comp_* components: %v", err)
	} else {
		defer rows.Close()
		var oldComponentIDs []string
		for rows.Next() {
			var compID string
			if err := rows.Scan(&compID); err != nil {
				log.Printf("KDC: Warning: Failed to scan old component ID: %v", err)
				continue
			}
			oldComponentIDs = append(oldComponentIDs, compID)
		}
		
		// Process each old component
		for _, oldCompID := range oldComponentIDs {
			newCompID, isSystemComponent := oldToNewComponentMap[oldCompID]
			
			if isSystemComponent {
				// This is a system component that should be migrated
				log.Printf("KDC: Migrating old system component %s to %s", oldCompID, newCompID)
				
				// Check if zones are assigned to old component
				zones, err := kdc.GetZonesForComponent(oldCompID)
				// Note: Zones are now related to services, not directly to components
				// Component-zone assignments no longer exist, so no migration needed for zones
				// Zones will automatically use the new component via their service assignment
				if err == nil && len(zones) > 0 {
					log.Printf("KDC: Component %s had %d zones assigned (via old component_zone_assignments table). Zones will now use component %s via their service assignments.", oldCompID, len(zones), newCompID)
				}
				
				// Check if nodes are assigned to old component
				nodes, err := kdc.GetNodesForComponent(oldCompID)
				if err == nil && len(nodes) > 0 {
					log.Printf("KDC: Warning: Component %s has %d nodes assigned. Migrating to %s", oldCompID, len(nodes), newCompID)
					for _, nodeID := range nodes {
						// Remove from old component (deactivate assignment)
						_, err := kdc.DB.Exec(
							"UPDATE node_component_assignments SET active = 0 WHERE node_id = ? AND component_id = ?",
							nodeID, oldCompID,
						)
						if err != nil {
							log.Printf("KDC: Warning: Failed to remove node %s from old component %s: %v", nodeID, oldCompID, err)
						} else {
							// Add to new component (check if already exists first)
							var exists bool
							err = kdc.DB.QueryRow(
								"SELECT EXISTS(SELECT 1 FROM node_component_assignments WHERE node_id = ? AND component_id = ?)",
								nodeID, newCompID,
							).Scan(&exists)
							if err == nil && !exists {
								_, err = kdc.DB.Exec(
									"INSERT INTO node_component_assignments (node_id, component_id, active, since) VALUES (?, ?, 1, CURRENT_TIMESTAMP)",
									nodeID, newCompID,
								)
								if err != nil {
									log.Printf("KDC: Warning: Failed to assign node %s to new component %s: %v", nodeID, newCompID, err)
								}
							}
						}
					}
				}
				
				// Remove service-component assignments for old component
				serviceRows, err := kdc.DB.Query(
					"SELECT service_id FROM service_component_assignments WHERE component_id = ? AND active = 1",
					oldCompID,
				)
				if err == nil {
					var serviceIDs []string
					for serviceRows.Next() {
						var serviceID string
						if err := serviceRows.Scan(&serviceID); err == nil {
							serviceIDs = append(serviceIDs, serviceID)
						}
					}
					serviceRows.Close()
					
					for _, serviceID := range serviceIDs {
						// Remove old assignment
						if err := kdc.RemoveServiceComponentAssignment(serviceID, oldCompID); err != nil {
							log.Printf("KDC: Warning: Failed to remove old component %s from service %s: %v", oldCompID, serviceID, err)
						} else {
							// Add new assignment (if not already present)
							existingComps, err := kdc.GetComponentsForService(serviceID)
							hasNewComp := false
							if err == nil {
								for _, compID := range existingComps {
									if compID == newCompID {
										hasNewComp = true
										break
									}
								}
							}
							if !hasNewComp {
								if err := kdc.AddServiceComponentAssignment(serviceID, newCompID); err != nil {
									log.Printf("KDC: Warning: Failed to assign new component %s to service %s: %v", newCompID, serviceID, err)
								} else {
									log.Printf("KDC: Migrated component assignment: service %s: %s -> %s", serviceID, oldCompID, newCompID)
								}
							}
						}
					}
				}
				
				// Delete the old component
				if err := kdc.DeleteComponent(oldCompID); err != nil {
					log.Printf("KDC: Warning: Failed to delete old component %s: %v", oldCompID, err)
				} else {
					log.Printf("KDC: Deleted old system component %s (replaced by %s)", oldCompID, newCompID)
				}
			} else {
				// Unknown comp_* component - might be user-created, leave it alone
				log.Printf("KDC: Found comp_* component %s (not a known system component, leaving as-is)", oldCompID)
			}
		}
	}
	
	// Migrate sign_edge_all components to sign_edge_full (naming consistency fix)
	rows, err = kdc.DB.Query("SELECT id FROM components WHERE id = 'sign_edge_all'")
	if err != nil {
		log.Printf("KDC: Warning: Failed to query sign_edge_all components: %v", err)
	} else {
		defer rows.Close()
		if rows.Next() {
			// sign_edge_all component exists, migrate it
			log.Printf("KDC: Migrating sign_edge_all component to sign_edge_full")
			
			// Get all services using sign_edge_all
			serviceRows, err := kdc.DB.Query(
				"SELECT service_id FROM service_component_assignments WHERE component_id = 'sign_edge_all' AND active = 1",
			)
			if err == nil {
				var serviceIDs []string
				for serviceRows.Next() {
					var serviceID string
					if err := serviceRows.Scan(&serviceID); err == nil {
						serviceIDs = append(serviceIDs, serviceID)
					}
				}
				serviceRows.Close()
				
				// Migrate service-component assignments
				for _, serviceID := range serviceIDs {
					// Remove old assignment
					if err := kdc.RemoveServiceComponentAssignment(serviceID, "sign_edge_all"); err != nil {
						log.Printf("KDC: Warning: Failed to remove sign_edge_all from service %s: %v", serviceID, err)
					} else {
						// Add new assignment (if not already present)
						existingComps, err := kdc.GetComponentsForService(serviceID)
						hasNewComp := false
						if err == nil {
							for _, compID := range existingComps {
								if compID == "sign_edge_full" {
									hasNewComp = true
									break
								}
							}
						}
						if !hasNewComp {
							if err := kdc.AddServiceComponentAssignment(serviceID, "sign_edge_full"); err != nil {
								log.Printf("KDC: Warning: Failed to assign sign_edge_full to service %s: %v", serviceID, err)
							} else {
								log.Printf("KDC: Migrated component assignment: service %s: sign_edge_all -> sign_edge_full", serviceID)
							}
						}
					}
				}
			}
			
			// Migrate node-component assignments
			nodeRows, err := kdc.DB.Query(
				"SELECT node_id FROM node_component_assignments WHERE component_id = 'sign_edge_all' AND active = 1",
			)
			if err == nil {
				var nodeIDs []string
				for nodeRows.Next() {
					var nodeID string
					if err := nodeRows.Scan(&nodeID); err == nil {
						nodeIDs = append(nodeIDs, nodeID)
					}
				}
				nodeRows.Close()
				
				for _, nodeID := range nodeIDs {
					// Remove from old component
					_, err := kdc.DB.Exec(
						"UPDATE node_component_assignments SET active = 0 WHERE node_id = ? AND component_id = 'sign_edge_all'",
						nodeID,
					)
					if err == nil {
						// Add to new component (if not already present)
						var exists bool
						err = kdc.DB.QueryRow(
							"SELECT EXISTS(SELECT 1 FROM node_component_assignments WHERE node_id = ? AND component_id = 'sign_edge_full')",
							nodeID,
						).Scan(&exists)
						if err == nil && !exists {
							_, err = kdc.DB.Exec(
								"INSERT INTO node_component_assignments (node_id, component_id, active, since) VALUES (?, 'sign_edge_full', 1, CURRENT_TIMESTAMP)",
								nodeID,
							)
							if err != nil {
								log.Printf("KDC: Warning: Failed to assign node %s to sign_edge_full: %v", nodeID, err)
							}
						}
					}
				}
			}
			
			// Delete the old component
			if err := kdc.DeleteComponent("sign_edge_all"); err != nil {
				log.Printf("KDC: Warning: Failed to delete sign_edge_all component: %v", err)
			} else {
				log.Printf("KDC: Deleted sign_edge_all component (replaced by sign_edge_full)")
			}
		}
		rows.Close()
	}
	
	// Check if default component exists (for backward compatibility)
	var defaultComponentExists bool
	err = kdc.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM components WHERE id = ?)", defaultComponentID).Scan(&defaultComponentExists)
	if err != nil {
		return fmt.Errorf("failed to check default component: %v", err)
	}
	
	if !defaultComponentExists {
		// Create default component (maps to central mode)
		defaultComponent := &Component{
			ID:      defaultComponentID,
			Name:    "Default Component",
			Active:  true,
			Comment: "Default component for default service (maps to sign_kdc)",
		}
		if err := kdc.AddComponent(defaultComponent); err != nil {
			return fmt.Errorf("failed to create default component: %v", err)
		}
		log.Printf("KDC: Created default component: %s", defaultComponentID)
		
		// Only assign default_comp to default service if sign_kdc is not already assigned
		// (to avoid conflicts - default_comp is deprecated)
		existingComponents, err := kdc.GetComponentsForService(defaultServiceID)
		if err == nil {
			hasSignKdc := false
			for _, compID := range existingComponents {
				if compID == "sign_kdc" {
					hasSignKdc = true
					break
				}
			}
			if !hasSignKdc {
				// Only assign if sign_kdc is not present (shouldn't happen, but be safe)
				if err := kdc.AddServiceComponentAssignment(defaultServiceID, defaultComponentID); err != nil {
					log.Printf("KDC: Warning: Failed to assign default component to default service: %v", err)
				} else {
					log.Printf("KDC: Assigned default component %s to default service %s", defaultComponentID, defaultServiceID)
				}
			}
		}
	}
	
	return nil
}

// AddZone adds a new zone
// Note: Zone signing mode is derived from service components, not stored directly
// Zones are only assigned to services; components are derived from the service
// If no service_id is provided, zone is assigned to default_service
func (kdc *KdcDB) AddZone(zone *Zone) error {
	// If no service_id provided, use default_service
	serviceID := zone.ServiceID
	if serviceID == "" {
		serviceID = "default_service"
		log.Printf("KDC: Zone %s assigned to default_service (no service_id provided)", zone.Name)
	}
	
	_, err := kdc.DB.Exec(
		"INSERT INTO zones (name, service_id, active, comment) VALUES (?, ?, ?, ?)",
		zone.Name, serviceID, zone.Active, zone.Comment,
	)
	if err != nil {
		return fmt.Errorf("failed to add zone: %v", err)
	}
	
	return nil
}

// UpdateZone updates an existing zone
// Note: zone name cannot be changed (it's the primary key)
// Zones are related to services only; components are derived from the service, not directly assigned
func (kdc *KdcDB) UpdateZone(zone *Zone) error {
	// Convert empty ServiceID to nil (NULL) for foreign key constraint
	var serviceID interface{}
	if zone.ServiceID == "" {
		serviceID = nil
	} else {
		serviceID = zone.ServiceID
	}
	_, err := kdc.DB.Exec(
		"UPDATE zones SET service_id = ?, active = ?, comment = ? WHERE name = ?",
		serviceID, zone.Active, zone.Comment, zone.Name,
	)
	if err != nil {
		return fmt.Errorf("failed to update zone: %v", err)
	}
	return nil
}

// DeleteZone deletes a zone (cascade deletes keys and distributions)
// Note: Foreign key constraints with ON DELETE CASCADE should automatically clean up
// related records in component_zone_assignments, dnssec_keys, distribution_records, etc.
// However, we explicitly delete component assignments first as a safety measure.
func (kdc *KdcDB) DeleteZone(zoneName string) error {
	// First, verify the zone exists
	_, err := kdc.GetZone(zoneName)
	if err != nil {
		return fmt.Errorf("zone not found: %s", zoneName)
	}
	
	// Note: Zones are now related to services, not directly to components
	// Foreign key constraints with ON DELETE CASCADE will automatically clean up
	// related records in dnssec_keys, distribution_records, etc.
	
	// Now delete the zone itself
	result, err := kdc.DB.Exec("DELETE FROM zones WHERE name = ?", zoneName)
	if err != nil {
		return fmt.Errorf("failed to delete zone: %v", err)
	}
	
	// Verify that a row was actually deleted
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Printf("KDC: Warning: Could not determine rows affected for zone deletion: %v", err)
	} else if rowsAffected == 0 {
		return fmt.Errorf("zone not found or could not be deleted: %s", zoneName)
	}
	
	return nil
}

// GetNode retrieves a node by ID
// nodeID should be normalized to FQDN format, but we'll try both FQDN and non-FQDN versions
// to handle legacy data
func (kdc *KdcDB) GetNode(nodeID string) (*Node, error) {
	// Normalize to FQDN
	nodeIDFQDN := dns.Fqdn(nodeID)
	
	var n Node
	var notifyAddr sql.NullString
	err := kdc.DB.QueryRow(
		"SELECT id, name, long_term_pub_key, notify_address, registered_at, last_seen, state, comment FROM nodes WHERE id = ?",
		nodeIDFQDN,
	).Scan(&n.ID, &n.Name, &n.LongTermPubKey, &notifyAddr, &n.RegisteredAt, &n.LastSeen, &n.State, &n.Comment)
	if err != nil {
		if err == sql.ErrNoRows {
			// Try without trailing dot (for legacy data)
			if strings.HasSuffix(nodeIDFQDN, ".") {
				nodeIDNoDot := strings.TrimSuffix(nodeIDFQDN, ".")
				err2 := kdc.DB.QueryRow(
					"SELECT id, name, long_term_pub_key, notify_address, registered_at, last_seen, state, comment FROM nodes WHERE id = ?",
					nodeIDNoDot,
				).Scan(&n.ID, &n.Name, &n.LongTermPubKey, &notifyAddr, &n.RegisteredAt, &n.LastSeen, &n.State, &n.Comment)
				if err2 != nil {
					if err2 == sql.ErrNoRows {
						return nil, fmt.Errorf("node not found: %s (tried both FQDN and non-FQDN formats)", nodeID)
					}
					return nil, fmt.Errorf("failed to get node: %v", err2)
				}
			} else {
				return nil, fmt.Errorf("node not found: %s", nodeID)
			}
		} else {
			return nil, fmt.Errorf("failed to get node: %v", err)
		}
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
// nodeID should be normalized to FQDN format, but we'll try both FQDN and non-FQDN versions
// to handle legacy data
func (kdc *KdcDB) DeleteNode(nodeID string) error {
	// Normalize to FQDN
	nodeIDFQDN := nodeID
	if !strings.HasSuffix(nodeIDFQDN, ".") {
		nodeIDFQDN = nodeIDFQDN + "."
	}
	
	// Try deleting with FQDN first
	result, err := kdc.DB.Exec("DELETE FROM nodes WHERE id = ?", nodeIDFQDN)
	if err != nil {
		return fmt.Errorf("failed to delete node: %v", err)
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %v", err)
	}
	
	// If no rows affected with FQDN, try without trailing dot (for legacy data)
	if rowsAffected == 0 && strings.HasSuffix(nodeIDFQDN, ".") {
		nodeIDNoDot := strings.TrimSuffix(nodeIDFQDN, ".")
		result, err = kdc.DB.Exec("DELETE FROM nodes WHERE id = ?", nodeIDNoDot)
		if err != nil {
			return fmt.Errorf("failed to delete node (non-FQDN): %v", err)
		}
		rowsAffected, err = result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %v", err)
		}
	}
	
	if rowsAffected == 0 {
		return fmt.Errorf("node not found: %s (tried both FQDN and non-FQDN formats)", nodeID)
	}
	
	return nil
}

// AddDNSSECKey adds a new DNSSEC key
func (kdc *KdcDB) AddDNSSECKey(key *DNSSECKey) error {
	_, err := kdc.DB.Exec(
		`INSERT INTO dnssec_keys 
			(id, zone_name, key_type, key_id, algorithm, flags, public_key, private_key, state, comment)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID, key.ZoneName, key.KeyType, key.KeyID, key.Algorithm, key.Flags,
		key.PublicKey, key.PrivateKey, key.State, key.Comment,
	)
	if err != nil {
		return fmt.Errorf("failed to add DNSSEC key: %v", err)
	}
	return nil
}

// GetDNSSECKeysForZone retrieves all DNSSEC keys for a zone
func (kdc *KdcDB) GetDNSSECKeysForZone(zoneName string) ([]*DNSSECKey, error) {
	rows, err := kdc.DB.Query(
		`SELECT id, zone_name, key_type, key_id, algorithm, flags, public_key, private_key, 
			state, created_at, published_at, activated_at, retired_at, comment
			FROM dnssec_keys WHERE zone_name = ? ORDER BY key_type, created_at`,
		zoneName,
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
			&key.ID, &key.ZoneName, &key.KeyType, &key.KeyID, &key.Algorithm, &key.Flags,
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
		`SELECT id, zone_name, key_type, key_id, algorithm, flags, public_key, private_key, 
			state, created_at, published_at, activated_at, retired_at, comment
			FROM dnssec_keys ORDER BY zone_name, key_type, created_at`,
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
			&key.ID, &key.ZoneName, &key.KeyType, &key.KeyID, &key.Algorithm, &key.Flags,
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
func (kdc *KdcDB) GetActiveZSKsForZone(zoneName string) ([]*DNSSECKey, error) {
	rows, err := kdc.DB.Query(
		`SELECT id, zone_name, key_type, key_id, algorithm, flags, public_key, private_key, 
			state, created_at, published_at, activated_at, retired_at, comment
			FROM dnssec_keys 
			WHERE zone_name = ? AND key_type = 'ZSK' AND state = 'active'
			ORDER BY created_at`,
		zoneName,
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
			&key.ID, &key.ZoneName, &key.KeyType, &key.KeyID, &key.Algorithm, &key.Flags,
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
func (kdc *KdcDB) DeleteDNSSECKey(zoneName, keyID string) error {
	_, err := kdc.DB.Exec(
		`DELETE FROM dnssec_keys WHERE zone_name = ? AND id = ?`,
		zoneName, keyID,
	)
	if err != nil {
		return fmt.Errorf("failed to delete DNSSEC key: %v", err)
	}
	return nil
}

// DeleteKeysByState deletes all DNSSEC keys in the specified state
// If zoneName is provided, only deletes keys for that zone; otherwise deletes for all zones
// Returns the number of keys deleted
func (kdc *KdcDB) DeleteKeysByState(state KeyState, zoneName string) (int64, error) {
	var result sql.Result
	var err error
	
	if zoneName != "" {
		result, err = kdc.DB.Exec(
			`DELETE FROM dnssec_keys WHERE state = ? AND zone_name = ?`,
			state, zoneName,
		)
	} else {
		result, err = kdc.DB.Exec(
			`DELETE FROM dnssec_keys WHERE state = ?`,
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

// AddDistributionRecord adds a distribution record
func (kdc *KdcDB) AddDistributionRecord(record *DistributionRecord) error {
	_, err := kdc.DB.Exec(
		`INSERT INTO distribution_records 
			(id, zone_name, key_id, node_id, encrypted_key, ephemeral_pub_key, expires_at, status, distribution_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		record.ID, record.ZoneName, record.KeyID, record.NodeID, record.EncryptedKey,
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

// MarkDistributionComplete marks a distribution as complete by setting completed_at timestamp
func (kdc *KdcDB) MarkDistributionComplete(distributionID string) error {
	now := time.Now()
	_, err := kdc.DB.Exec(
		"UPDATE distribution_records SET status = 'completed', completed_at = ? WHERE distribution_id = ?",
		now, distributionID,
	)
	if err != nil {
		return fmt.Errorf("failed to mark distribution as complete: %v", err)
	}
	return nil
}

// PurgeCompletedDistributions deletes all completed distributions immediately
// Returns the number of distributions deleted
func (kdc *KdcDB) PurgeCompletedDistributions() (int, error) {
	// Delete distribution records
	result, err := kdc.DB.Exec(
		"DELETE FROM distribution_records WHERE status = 'completed'",
	)
	if err != nil {
		return 0, fmt.Errorf("failed to delete completed distributions: %v", err)
	}
	
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %v", err)
	}
	
	// Also delete orphaned confirmations (confirmations without distribution records)
	_, err = kdc.DB.Exec(
		`DELETE FROM distribution_confirmations 
		 WHERE distribution_id NOT IN (SELECT DISTINCT distribution_id FROM distribution_records)`,
	)
	if err != nil {
		log.Printf("KDC: Warning: Failed to clean up orphaned confirmations: %v", err)
	}
	
	return int(deleted), nil
}

// PurgeAllDistributions deletes ALL distributions (regardless of status) immediately
// Returns the number of distributions deleted
func (kdc *KdcDB) PurgeAllDistributions() (int, error) {
	// Delete all distribution records
	result, err := kdc.DB.Exec(
		"DELETE FROM distribution_records",
	)
	if err != nil {
		return 0, fmt.Errorf("failed to delete all distributions: %v", err)
	}
	
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %v", err)
	}
	
	// Also delete all confirmations
	_, err = kdc.DB.Exec(
		"DELETE FROM distribution_confirmations",
	)
	if err != nil {
		log.Printf("KDC: Warning: Failed to clean up confirmations: %v", err)
	}
	
	return int(deleted), nil
}

// GarbageCollectCompletedDistributions deletes completed distributions older than the specified duration
func (kdc *KdcDB) GarbageCollectCompletedDistributions(olderThan time.Duration) error {
	cutoffTime := time.Now().Add(-olderThan)
	
	// Delete distribution records
	result, err := kdc.DB.Exec(
		"DELETE FROM distribution_records WHERE status = 'completed' AND completed_at < ?",
		cutoffTime,
	)
	if err != nil {
		return fmt.Errorf("failed to delete old distribution records: %v", err)
	}
	
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		log.Printf("KDC: Garbage collected %d completed distribution record(s) older than %v", rowsAffected, olderThan)
	}
	
	// Also delete related confirmations (they're no longer needed)
	_, err = kdc.DB.Exec(
		`DELETE FROM distribution_confirmations 
		 WHERE distribution_id NOT IN (SELECT DISTINCT distribution_id FROM distribution_records)`,
	)
	if err != nil {
		log.Printf("KDC: Warning: Failed to clean up orphaned confirmations: %v", err)
	}
	
	return nil
}

// GetDistributionSummaries returns detailed summary information for all distributions
func (kdc *KdcDB) GetDistributionSummaries() ([]DistributionSummaryInfo, error) {
	// First, mark old distributions as complete if they have all confirmations but weren't marked
	// This handles distributions that were completed before we added the completion tracking
	kdc.markOldCompletedDistributions()
	
	// Get all distribution records grouped by distribution_id
	// Show:
	// - All non-completed distributions (regardless of age - they're still pending)
	// - Completed distributions less than 5 minutes old (before GC)
	rows, err := kdc.DB.Query(
		`SELECT distribution_id, zone_name, key_id, node_id, created_at, completed_at, status
		 FROM distribution_records 
		 WHERE status != 'completed' OR (status = 'completed' AND completed_at > datetime('now', '-5 minutes'))
		 ORDER BY distribution_id, zone_name, key_id`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query distribution records: %v", err)
	}
	defer rows.Close()

	// Group by distribution_id
	distMap := make(map[string]*DistributionSummaryInfo)
	zoneKeyMap := make(map[string]map[string]bool) // distID -> zone:key -> bool

	for rows.Next() {
		var distID, zoneName, keyID string
		var nodeID sql.NullString
		var createdAt time.Time
		var completedAt sql.NullTime
		var status string

		if err := rows.Scan(&distID, &zoneName, &keyID, &nodeID, &createdAt, &completedAt, &status); err != nil {
			return nil, fmt.Errorf("failed to scan distribution record: %v", err)
		}

		// Initialize summary if needed
		if distMap[distID] == nil {
			distMap[distID] = &DistributionSummaryInfo{
				DistributionID: distID,
				Nodes:          []string{},
				Zones:          []string{},
				Keys:           make(map[string]string),
				CreatedAt:      createdAt.Format(time.RFC3339),
				AllConfirmed:   status == "completed",
			}
			if completedAt.Valid {
				completedAtStr := completedAt.Time.Format(time.RFC3339)
				distMap[distID].CompletedAt = &completedAtStr
			}
			zoneKeyMap[distID] = make(map[string]bool)
		}

		// Add node if not already present
		if nodeID.Valid && nodeID.String != "" {
			found := false
			for _, n := range distMap[distID].Nodes {
				if n == nodeID.String {
					found = true
					break
				}
			}
			if !found {
				distMap[distID].Nodes = append(distMap[distID].Nodes, nodeID.String)
			}
		}

		// Track zone-key pairs
		zoneKey := zoneName + ":" + keyID
		if !zoneKeyMap[distID][zoneKey] {
			zoneKeyMap[distID][zoneKey] = true
			// Add zone if not already present
			found := false
			for _, z := range distMap[distID].Zones {
				if z == zoneName {
					found = true
					break
				}
			}
			if !found {
				distMap[distID].Zones = append(distMap[distID].Zones, zoneName)
			}
			// Store key for zone (for verbose mode - show first key, or comma-separated if multiple)
			if distMap[distID].Keys[zoneName] == "" {
				distMap[distID].Keys[zoneName] = keyID
			} else {
				// Multiple keys for same zone - append
				distMap[distID].Keys[zoneName] = distMap[distID].Keys[zoneName] + ", " + keyID
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Get key types to count ZSK/KSK - count all unique zone:key pairs from zoneKeyMap
	for distID, zoneKeys := range zoneKeyMap {
		for zoneKey := range zoneKeys {
			parts := strings.Split(zoneKey, ":")
			if len(parts) == 2 {
				zoneName := parts[0]
				keyID := parts[1]
				key, err := kdc.GetDNSSECKeyByID(zoneName, keyID)
				if err == nil {
					if key.KeyType == KeyTypeZSK {
						distMap[distID].ZSKCount++
					} else if key.KeyType == KeyTypeKSK {
						distMap[distID].KSKCount++
					}
				}
			}
		}
	}

	// For each distribution, get confirmed and pending nodes
	for distID, summary := range distMap {
		if len(summary.Zones) > 0 {
			// Use first zone to get target nodes (all zones in same distribution should have same target nodes)
			zoneName := summary.Zones[0]
			zoneNodes, _ := kdc.GetActiveNodesForZone(zoneName)
			var targetNodes []string
			for _, node := range zoneNodes {
				if node.NotifyAddress != "" {
					targetNodes = append(targetNodes, node.ID)
				}
			}
			
			// Get confirmed nodes
			confirmedNodes, _ := kdc.GetDistributionConfirmations(distID)
			summary.ConfirmedNodes = confirmedNodes
			
			// Calculate pending nodes
			confirmedMap := make(map[string]bool)
			for _, nodeID := range confirmedNodes {
				confirmedMap[nodeID] = true
			}
			var pendingNodes []string
			for _, nodeID := range targetNodes {
				if !confirmedMap[nodeID] {
					pendingNodes = append(pendingNodes, nodeID)
				}
			}
			summary.PendingNodes = pendingNodes
			
			// Update AllConfirmed based on actual confirmations
			summary.AllConfirmed = len(pendingNodes) == 0 && len(targetNodes) > 0
		}
	}

	// Convert map to slice
	summaries := make([]DistributionSummaryInfo, 0, len(distMap))
	for _, summary := range distMap {
		summaries = append(summaries, *summary)
	}

	// Sort by completion timestamp (most recent first), then by creation time
	sort.Slice(summaries, func(i, j int) bool {
		// If both have completion times, sort by completion time (newest first)
		if summaries[i].CompletedAt != nil && summaries[j].CompletedAt != nil {
			return *summaries[i].CompletedAt > *summaries[j].CompletedAt
		}
		// If only one has completion time, completed ones come first
		if summaries[i].CompletedAt != nil {
			return true
		}
		if summaries[j].CompletedAt != nil {
			return false
		}
		// Neither completed, sort by creation time (newest first)
		return summaries[i].CreatedAt > summaries[j].CreatedAt
	})

	return summaries, nil
}

// GetDistributionRecordsForZoneKey retrieves distribution records for a specific zone and key
// Returns the most recent active/pending distribution record, or nil if none exists
func (kdc *KdcDB) GetDistributionRecordsForZoneKey(zoneName, keyID string) ([]*DistributionRecord, error) {
	rows, err := kdc.DB.Query(
		`SELECT id, zone_name, key_id, node_id, encrypted_key, ephemeral_pub_key, 
			created_at, expires_at, status, distribution_id
			FROM distribution_records 
			WHERE zone_name = ? AND key_id = ? 
			ORDER BY created_at DESC`,
		zoneName, keyID,
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
			&record.ID, &record.ZoneName, &record.KeyID, &nodeID,
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
func (kdc *KdcDB) GetOrCreateDistributionID(zoneName string, key *DNSSECKey) (string, error) {
	// Check if there's an existing distribution record for this key
	records, err := kdc.GetDistributionRecordsForZoneKey(zoneName, key.ID)
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
func (kdc *KdcDB) AddDistributionConfirmation(distributionID, zoneName, keyID, nodeID string) error {
	// Generate a unique ID for this confirmation
	confirmationID := fmt.Sprintf("%s-%s-%d", distributionID, nodeID, time.Now().Unix())
	
	var err error
	if kdc.DBType == "sqlite" {
		// SQLite: Use INSERT OR REPLACE (works with UNIQUE constraint)
		_, err = kdc.DB.Exec(
			`INSERT OR REPLACE INTO distribution_confirmations 
				(id, distribution_id, zone_name, key_id, node_id, confirmed_at)
				VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
			confirmationID, distributionID, zoneName, keyID, nodeID,
		)
	} else {
		// MySQL/MariaDB: Use ON DUPLICATE KEY UPDATE
		_, err = kdc.DB.Exec(
			`INSERT INTO distribution_confirmations 
				(id, distribution_id, zone_name, key_id, node_id, confirmed_at)
				VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
				ON DUPLICATE KEY UPDATE confirmed_at = CURRENT_TIMESTAMP`,
			confirmationID, distributionID, zoneName, keyID, nodeID,
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

// CheckAllNodesConfirmed checks if all nodes that are part of this distribution have confirmed receipt
func (kdc *KdcDB) CheckAllNodesConfirmed(distributionID, zoneName string) (bool, error) {
	// Get all distribution records for this distribution ID to find which nodes are part of it
	records, err := kdc.GetDistributionRecordsForDistributionID(distributionID)
	if err != nil {
		return false, fmt.Errorf("failed to get distribution records: %v", err)
	}

	if len(records) == 0 {
		// No distribution records, so technically all have "confirmed" (trivially true)
		return true, nil
	}

	// Get unique node IDs from distribution records
	targetNodeIDs := make(map[string]bool)
	for _, record := range records {
		if record.NodeID != "" {
			targetNodeIDs[record.NodeID] = true
		}
	}

	if len(targetNodeIDs) == 0 {
		// No target nodes in distribution records, so technically all have "confirmed" (trivially true)
		return true, nil
	}

	// Get confirmed node IDs for this distribution
	confirmedNodeIDs, err := kdc.GetDistributionConfirmations(distributionID)
	if err != nil {
		return false, err
	}

	// Check if all target nodes have confirmed
	confirmedMap := make(map[string]bool)
	for _, nodeID := range confirmedNodeIDs {
		confirmedMap[nodeID] = true
	}

	for nodeID := range targetNodeIDs {
		if !confirmedMap[nodeID] {
			return false, nil
		}
	}

	return true, nil
}

// updateKeyComment replaces the key's comment field with the latest timestamped event
func (kdc *KdcDB) updateKeyComment(zoneName, keyID, event string) error {
	// Format timestamp
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	
	// Build new comment (replace, don't append)
	newComment := fmt.Sprintf("%s at %s", event, timestamp)

	// Update comment
	_, err := kdc.DB.Exec(
		`UPDATE dnssec_keys SET comment = ? WHERE zone_name = ? AND id = ?`,
		newComment, zoneName, keyID,
	)
	if err != nil {
		return fmt.Errorf("failed to update comment: %v", err)
	}
	return nil
}

// UpdateKeyState updates the state of a DNSSEC key
func (kdc *KdcDB) UpdateKeyState(zoneName, keyID string, newState KeyState) error {
	now := time.Now()
	var err error
	var commentEvent string
	
	switch newState {
	case KeyStatePublished:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ?, published_at = ? WHERE zone_name = ? AND id = ?`,
			newState, now, zoneName, keyID,
		)
		if err == nil {
			commentEvent = "published"
		}
	case KeyStateStandby:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ? WHERE zone_name = ? AND id = ?`,
			newState, zoneName, keyID,
		)
		if err == nil {
			commentEvent = "transitioned to standby"
		}
	case KeyStateActive:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ?, activated_at = ? WHERE zone_name = ? AND id = ?`,
			newState, now, zoneName, keyID,
		)
		if err == nil {
			commentEvent = "activated"
		}
	case KeyStateActiveDist:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ? WHERE zone_name = ? AND id = ?`,
			newState, zoneName, keyID,
		)
		if err == nil {
			commentEvent = "activated and being distributed"
		}
	case KeyStateActiveCE:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ? WHERE zone_name = ? AND id = ?`,
			newState, zoneName, keyID,
		)
		if err == nil {
			commentEvent = "activated at central and edges"
		}
	case KeyStateDistributed:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ? WHERE zone_name = ? AND id = ?`,
			newState, zoneName, keyID,
		)
		if err == nil {
			commentEvent = "distributed"
		}
	case KeyStateEdgeSigner:
		// Get zone to find signing component
		zone, zoneErr := kdc.GetZone(zoneName)
		var componentInfo string
		if zoneErr == nil && zone.ServiceID != "" {
			// Get signing component from service
			components, compErr := kdc.GetComponentsForService(zone.ServiceID)
			if compErr == nil {
				for _, compID := range components {
					if strings.HasPrefix(compID, "sign_") {
						componentInfo = fmt.Sprintf(" (%s)", compID)
						break
					}
				}
			}
		}
		
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ? WHERE zone_name = ? AND id = ?`,
			newState, zoneName, keyID,
		)
		if err == nil {
			commentEvent = fmt.Sprintf("activated as edgesigner%s", componentInfo)
		}
	case KeyStateRetired:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ?, retired_at = ? WHERE zone_name = ? AND id = ?`,
			newState, now, zoneName, keyID,
		)
		if err == nil {
			commentEvent = "retired"
		}
	case KeyStateRemoved:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ? WHERE zone_name = ? AND id = ?`,
			newState, zoneName, keyID,
		)
		if err == nil {
			commentEvent = "removed"
		}
	default:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ? WHERE zone_name = ? AND id = ?`,
			newState, zoneName, keyID,
		)
	}
	
	if err != nil {
		return fmt.Errorf("failed to update key state: %v", err)
	}
	
	// Update comment if we have an event
	if commentEvent != "" {
		if err := kdc.updateKeyComment(zoneName, keyID, commentEvent); err != nil {
			// Log but don't fail the state update
			log.Printf("KDC: Warning: Failed to update comment for key %s: %v", keyID, err)
		}
	}
	
	return nil
}

// GetKeysByState retrieves keys in a specific state for a zone (or all zones if zoneName is empty)
func (kdc *KdcDB) GetKeysByState(zoneName string, state KeyState) ([]*DNSSECKey, error) {
	var rows *sql.Rows
	var err error
	
		if zoneName == "" {
		rows, err = kdc.DB.Query(
			`SELECT id, zone_name, key_type, key_id, algorithm, flags, public_key, private_key,
				state, created_at, published_at, activated_at, retired_at, comment
				FROM dnssec_keys WHERE state = ? ORDER BY zone_name, created_at`,
			state,
		)
	} else {
		rows, err = kdc.DB.Query(
			`SELECT id, zone_name, key_type, key_id, algorithm, flags, public_key, private_key,
				state, created_at, published_at, activated_at, retired_at, comment
				FROM dnssec_keys WHERE zone_name = ? AND state = ? ORDER BY created_at`,
			zoneName, state,
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
			&key.ID, &key.ZoneName, &key.KeyType, &key.KeyID, &key.Algorithm, &key.Flags,
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

// RetireOldKeysForZone retires all keys in the specified state for a zone and key type,
// excluding the newly activated key. This ensures only one key per zone/key-type is in
// edgesigner/active_dist/active_ce state at a time.
func (kdc *KdcDB) RetireOldKeysForZone(zoneName string, keyType KeyType, excludeKeyID string, state KeyState) error {
	// Only retire keys that are in edgesigner, active_dist, or active_ce state
	if state != KeyStateEdgeSigner && state != KeyStateActiveDist && state != KeyStateActiveCE {
		return nil // Nothing to retire
	}
	
	// Get all keys for the zone in the same state and key type
	keys, err := kdc.GetDNSSECKeysForZone(zoneName)
	if err != nil {
		return fmt.Errorf("failed to get keys for zone: %v", err)
	}
	
	retiredCount := 0
	for _, key := range keys {
		// Skip the newly activated key
		if key.ID == excludeKeyID {
			continue
		}
		
		// Only retire keys of the same type
		if key.KeyType != keyType {
			continue
		}
		
		// Retire keys in the same state
		// For KSKs transitioning to active_ce: also retire keys in active_dist (intermediate state)
		shouldRetire := false
		if key.State == state {
			shouldRetire = true
		} else if state == KeyStateActiveCE && key.State == KeyStateActiveDist {
			// When transitioning to active_ce, also retire keys stuck in active_dist
			shouldRetire = true
		}
		
		if shouldRetire {
			if err := kdc.UpdateKeyState(zoneName, key.ID, KeyStateRetired); err != nil {
				log.Printf("KDC: Warning: Failed to retire old key %s: %v", key.ID, err)
			} else {
				retiredCount++
				log.Printf("KDC: Retired old key %s (zone: %s, type: %s, previous state: %s)", key.ID, zoneName, keyType, key.State)
			}
		}
	}
	
	if retiredCount > 0 {
		log.Printf("KDC: Retired %d old key(s) for zone %s (type: %s)", retiredCount, zoneName, keyType)
	}
	
	return nil
}

// GetDNSSECKeyByID retrieves a DNSSEC key by its ID (keytag) for a zone
func (kdc *KdcDB) GetDNSSECKeyByID(zoneName, keyID string) (*DNSSECKey, error) {
	var key DNSSECKey
	var publishedAt, activatedAt, retiredAt sql.NullTime
	err := kdc.DB.QueryRow(
		`SELECT id, zone_name, key_type, key_id, algorithm, flags, public_key, private_key, 
			state, created_at, published_at, activated_at, retired_at, comment
			FROM dnssec_keys WHERE zone_name = ? AND id = ?`,
		zoneName, keyID,
	).Scan(
		&key.ID, &key.ZoneName, &key.KeyType, &key.KeyID, &key.Algorithm, &key.Flags,
		&key.PublicKey, &key.PrivateKey, &key.State, &key.CreatedAt,
		&publishedAt, &activatedAt, &retiredAt, &key.Comment,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("key %s not found for zone %s", keyID, zoneName)
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

// ============================================================================
// Service operations
// ============================================================================

// GetService retrieves a service by ID
func (kdc *KdcDB) GetService(serviceID string) (*Service, error) {
	var s Service
	var updatedAt sql.NullTime
	err := kdc.DB.QueryRow(
		"SELECT id, name, created_at, updated_at, active, comment FROM services WHERE id = ?",
		serviceID,
	).Scan(&s.ID, &s.Name, &s.CreatedAt, &updatedAt, &s.Active, &s.Comment)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("service not found: %s", serviceID)
		}
		return nil, fmt.Errorf("failed to get service: %v", err)
	}
	if updatedAt.Valid {
		s.UpdatedAt = updatedAt.Time
	}
	return &s, nil
}

// GetAllServices retrieves all services
func (kdc *KdcDB) GetAllServices() ([]*Service, error) {
	rows, err := kdc.DB.Query("SELECT id, name, created_at, updated_at, active, comment FROM services ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("failed to query services: %v", err)
	}
	defer rows.Close()

	var services []*Service
	for rows.Next() {
		var s Service
		var updatedAt sql.NullTime
		if err := rows.Scan(&s.ID, &s.Name, &s.CreatedAt, &updatedAt, &s.Active, &s.Comment); err != nil {
			return nil, fmt.Errorf("failed to scan service: %v", err)
		}
		if updatedAt.Valid {
			s.UpdatedAt = updatedAt.Time
		}
		services = append(services, &s)
	}
	return services, rows.Err()
}

// AddService adds a new service
func (kdc *KdcDB) AddService(service *Service) error {
	_, err := kdc.DB.Exec(
		"INSERT INTO services (id, name, active, comment) VALUES (?, ?, ?, ?)",
		service.ID, service.Name, service.Active, service.Comment,
	)
	if err != nil {
		return fmt.Errorf("failed to add service: %v", err)
	}
	return nil
}

// UpdateService updates an existing service
func (kdc *KdcDB) UpdateService(service *Service) error {
	_, err := kdc.DB.Exec(
		"UPDATE services SET name = ?, active = ?, comment = ? WHERE id = ?",
		service.Name, service.Active, service.Comment, service.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update service: %v", err)
	}
	return nil
}

// DeleteService deletes a service
// System-defined services (default_service) cannot be deleted
func (kdc *KdcDB) DeleteService(serviceID string) error {
	// Prevent deletion of default_service
	if serviceID == "default_service" {
		return fmt.Errorf("cannot delete default_service (system-defined)")
	}
	_, err := kdc.DB.Exec("DELETE FROM services WHERE id = ?", serviceID)
	if err != nil {
		return fmt.Errorf("failed to delete service: %v", err)
	}
	return nil
}

// ============================================================================
// Component operations
// ============================================================================

// GetComponent retrieves a component by ID
func (kdc *KdcDB) GetComponent(componentID string) (*Component, error) {
	var c Component
	var updatedAt sql.NullTime
	err := kdc.DB.QueryRow(
		"SELECT id, name, created_at, updated_at, active, comment FROM components WHERE id = ?",
		componentID,
	).Scan(&c.ID, &c.Name, &c.CreatedAt, &updatedAt, &c.Active, &c.Comment)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("component not found: %s", componentID)
		}
		return nil, fmt.Errorf("failed to get component: %v", err)
	}
	if updatedAt.Valid {
		c.UpdatedAt = updatedAt.Time
	}
	return &c, nil
}

// GetAllComponents retrieves all components
func (kdc *KdcDB) GetAllComponents() ([]*Component, error) {
	rows, err := kdc.DB.Query("SELECT id, name, created_at, updated_at, active, comment FROM components ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("failed to query components: %v", err)
	}
	defer rows.Close()

	var components []*Component
	for rows.Next() {
		var c Component
		var updatedAt sql.NullTime
		if err := rows.Scan(&c.ID, &c.Name, &c.CreatedAt, &updatedAt, &c.Active, &c.Comment); err != nil {
			return nil, fmt.Errorf("failed to scan component: %v", err)
		}
		if updatedAt.Valid {
			c.UpdatedAt = updatedAt.Time
		}
		components = append(components, &c)
	}
	return components, rows.Err()
}

// AddComponent adds a new component
func (kdc *KdcDB) AddComponent(component *Component) error {
	_, err := kdc.DB.Exec(
		"INSERT INTO components (id, name, active, comment) VALUES (?, ?, ?, ?)",
		component.ID, component.Name, component.Active, component.Comment,
	)
	if err != nil {
		return fmt.Errorf("failed to add component: %v", err)
	}
	return nil
}

// UpdateComponent updates an existing component
func (kdc *KdcDB) UpdateComponent(component *Component) error {
	_, err := kdc.DB.Exec(
		"UPDATE components SET name = ?, active = ?, comment = ? WHERE id = ?",
		component.Name, component.Active, component.Comment, component.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update component: %v", err)
	}
	return nil
}

// DeleteComponent deletes a component
// System-defined components (sign_*) cannot be deleted
func (kdc *KdcDB) DeleteComponent(componentID string) error {
	// Prevent deletion of system-defined components
	if strings.HasPrefix(componentID, "sign_") {
		return fmt.Errorf("cannot delete system-defined component: %s", componentID)
	}
	_, err := kdc.DB.Exec("DELETE FROM components WHERE id = ?", componentID)
	if err != nil {
		return fmt.Errorf("failed to delete component: %v", err)
	}
	return nil
}

// ============================================================================
// Assignment operations
// ============================================================================

// AddServiceComponentAssignment assigns a component to a service
// Validates that only one sign_* component can be assigned to a service at a time
func (kdc *KdcDB) AddServiceComponentAssignment(serviceID, componentID string) error {
	// Check if this is a signing component (sign_*)
	if strings.HasPrefix(componentID, "sign_") {
		// Get all existing components for this service
		existingComponents, err := kdc.GetComponentsForService(serviceID)
		if err != nil {
			return fmt.Errorf("failed to get existing components: %v", err)
		}
		
		// Check if there's already a sign_* component assigned
		for _, existingCompID := range existingComponents {
			if strings.HasPrefix(existingCompID, "sign_") {
				return fmt.Errorf("service %s already has signing component %s assigned (cannot have multiple sign_* components)", serviceID, existingCompID)
			}
		}
	}
	
	_, err := kdc.DB.Exec(
		"INSERT INTO service_component_assignments (service_id, component_id, active, since) VALUES (?, ?, 1, CURRENT_TIMESTAMP)",
		serviceID, componentID,
	)
	if err != nil {
		return fmt.Errorf("failed to add service-component assignment: %v", err)
	}
	return nil
}

// RemoveServiceComponentAssignment removes a component from a service
func (kdc *KdcDB) RemoveServiceComponentAssignment(serviceID, componentID string) error {
	_, err := kdc.DB.Exec(
		"UPDATE service_component_assignments SET active = 0 WHERE service_id = ? AND component_id = ?",
		serviceID, componentID,
	)
	if err != nil {
		return fmt.Errorf("failed to remove service-component assignment: %v", err)
	}
	return nil
}

// ReplaceServiceComponentAssignment atomically replaces one component with another in a service
// This ensures there's never a state with no signing component when replacing sign_* components
// The operation is atomic: if adding the new component fails, the old one remains
func (kdc *KdcDB) ReplaceServiceComponentAssignment(serviceID, oldComponentID, newComponentID string) error {
	// Validate that old component exists and is assigned to the service
	existingComponents, err := kdc.GetComponentsForService(serviceID)
	if err != nil {
		return fmt.Errorf("failed to get existing components: %v", err)
	}
	
	oldComponentFound := false
	for _, compID := range existingComponents {
		if compID == oldComponentID {
			oldComponentFound = true
			break
		}
	}
	if !oldComponentFound {
		return fmt.Errorf("component %s is not assigned to service %s", oldComponentID, serviceID)
	}
	
	// Validate that new component is not already assigned
	for _, compID := range existingComponents {
		if compID == newComponentID {
			return fmt.Errorf("component %s is already assigned to service %s", newComponentID, serviceID)
		}
	}
	
	// If replacing sign_* components, ensure we're replacing one sign_* with another
	oldIsSigning := strings.HasPrefix(oldComponentID, "sign_")
	newIsSigning := strings.HasPrefix(newComponentID, "sign_")
	
	if oldIsSigning && !newIsSigning {
		// Check if there are other sign_* components (shouldn't happen, but be safe)
		for _, compID := range existingComponents {
			if compID != oldComponentID && strings.HasPrefix(compID, "sign_") {
				return fmt.Errorf("cannot remove signing component %s: service %s has other signing components", oldComponentID, serviceID)
			}
		}
		// Allow removing sign_* and replacing with non-signing component
	}
	
	if !oldIsSigning && newIsSigning {
		// Check if there's already a sign_* component
		for _, compID := range existingComponents {
			if strings.HasPrefix(compID, "sign_") {
				return fmt.Errorf("service %s already has signing component %s assigned (cannot have multiple sign_* components)", serviceID, compID)
			}
		}
	}
	
	if oldIsSigning && newIsSigning {
		// Replacing one sign_* with another - this is the main use case
		// Ensure atomic operation: remove old and add new in a transaction
		tx, err := kdc.DB.Begin()
		if err != nil {
			return fmt.Errorf("failed to begin transaction: %v", err)
		}
		defer tx.Rollback()
		
		// Remove old component
		_, err = tx.Exec(
			"UPDATE service_component_assignments SET active = 0 WHERE service_id = ? AND component_id = ?",
			serviceID, oldComponentID,
		)
		if err != nil {
			return fmt.Errorf("failed to remove old component: %v", err)
		}
		
		// Add new component
		_, err = tx.Exec(
			"INSERT INTO service_component_assignments (service_id, component_id, active, since) VALUES (?, ?, 1, CURRENT_TIMESTAMP)",
			serviceID, newComponentID,
		)
		if err != nil {
			return fmt.Errorf("failed to add new component: %v", err)
		}
		
		// Commit transaction
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit transaction: %v", err)
		}
		
		return nil
	}
	
	// Non-signing component replacement - can be done without transaction
	// Remove old
	if err := kdc.RemoveServiceComponentAssignment(serviceID, oldComponentID); err != nil {
		return fmt.Errorf("failed to remove old component: %v", err)
	}
	
	// Add new
	if err := kdc.AddServiceComponentAssignment(serviceID, newComponentID); err != nil {
		// Try to restore old component if adding new fails
		kdc.AddServiceComponentAssignment(serviceID, oldComponentID)
		return fmt.Errorf("failed to add new component: %v", err)
	}
	
	return nil
}

// GetComponentsForService returns all component IDs assigned to a service
func (kdc *KdcDB) GetComponentsForService(serviceID string) ([]string, error) {
	rows, err := kdc.DB.Query(
		`SELECT component_id FROM service_component_assignments 
		 WHERE service_id = ? AND active = 1`,
		serviceID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query service components: %v", err)
	}
	defer rows.Close()

	var components []string
	for rows.Next() {
		var componentID string
		if err := rows.Scan(&componentID); err != nil {
			return nil, fmt.Errorf("failed to scan component ID: %v", err)
		}
		components = append(components, componentID)
	}

	return components, rows.Err()
}

// AddNodeComponentAssignment assigns a component to a node
// If kdcConf is provided, it will automatically trigger key distribution for newly served zones
func (kdc *KdcDB) AddNodeComponentAssignment(nodeID, componentID string, kdcConf *KdcConf) error {
	// Add the assignment
	_, err := kdc.DB.Exec(
		"INSERT INTO node_component_assignments (node_id, component_id, active, since) VALUES (?, ?, 1, CURRENT_TIMESTAMP)",
		nodeID, componentID,
	)
	if err != nil {
		return fmt.Errorf("failed to add node-component assignment: %v", err)
	}

	// Compute which zones are newly served by this node
	newlyServedZones, err := kdc.GetZonesNewlyServedByNode(nodeID, componentID)
	if err != nil {
		log.Printf("KDC: Warning: Failed to compute newly served zones for node %s, component %s: %v", nodeID, componentID, err)
		// Don't fail the assignment if delta computation fails
	} else if len(newlyServedZones) > 0 {
		log.Printf("KDC: Node %s now serves %d new zone(s) after adding component %s: %v", nodeID, len(newlyServedZones), componentID, newlyServedZones)
		
		// Trigger key distribution for newly served zones
		if kdcConf != nil {
			for _, zoneName := range newlyServedZones {
				if err := kdc.distributeKeysForZone(zoneName, nodeID, kdcConf); err != nil {
					log.Printf("KDC: Warning: Failed to distribute keys for zone %s to node %s: %v", zoneName, nodeID, err)
					// Continue with other zones
				}
			}
		} else {
			log.Printf("KDC: KdcConf not provided, skipping automatic key distribution for %d zone(s)", len(newlyServedZones))
		}
	}

	return nil
}

// RemoveNodeComponentAssignment removes a component from a node
// If kdcConf is provided, it will log zones that are no longer served (key deletion can be handled separately)
func (kdc *KdcDB) RemoveNodeComponentAssignment(nodeID, componentID string, kdcConf *KdcConf) error {
	// Compute which zones will no longer be served BEFORE removing the assignment
	noLongerServedZones, err := kdc.GetZonesNoLongerServedByNode(nodeID, componentID)
	if err != nil {
		log.Printf("KDC: Warning: Failed to compute no-longer-served zones for node %s, component %s: %v", nodeID, componentID, err)
		// Continue with removal even if delta computation fails
	} else if len(noLongerServedZones) > 0 {
		log.Printf("KDC: Node %s will no longer serve %d zone(s) after removing component %s: %v", nodeID, len(noLongerServedZones), componentID, noLongerServedZones)
		// TODO: Trigger key deletion/revocation for these zones
		// For now, just log - key deletion can be implemented separately
	}

	// Remove the assignment
	_, err = kdc.DB.Exec(
		"UPDATE node_component_assignments SET active = 0 WHERE node_id = ? AND component_id = ?",
		nodeID, componentID,
	)
	if err != nil {
		return fmt.Errorf("failed to remove node-component assignment: %v", err)
	}

	return nil
}

// GetAllNodeComponentAssignments returns all active node-component assignments
func (kdc *KdcDB) GetAllNodeComponentAssignments() ([]*NodeComponentAssignment, error) {
	rows, err := kdc.DB.Query(
		`SELECT node_id, component_id, active, since FROM node_component_assignments 
		 WHERE active = 1 ORDER BY node_id, component_id`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query node-component assignments: %v", err)
	}
	defer rows.Close()

	var assignments []*NodeComponentAssignment
	for rows.Next() {
		var assignment NodeComponentAssignment
		var activeInt int
		if err := rows.Scan(&assignment.NodeID, &assignment.ComponentID, &activeInt, &assignment.Since); err != nil {
			return nil, fmt.Errorf("failed to scan assignment: %v", err)
		}
		assignment.Active = activeInt != 0
		assignments = append(assignments, &assignment)
	}

	return assignments, rows.Err()
}

// GetZonesForNode returns all zone names served by a node (via components)
// A node serves a zone if the node serves at least one component that belongs to the zone's service
func (kdc *KdcDB) GetZonesForNode(nodeID string) ([]string, error) {
	rows, err := kdc.DB.Query(
		`SELECT DISTINCT z.name
		 FROM zones z
		 JOIN service_component_assignments sc ON sc.service_id = z.service_id
		 JOIN node_component_assignments nc ON nc.component_id = sc.component_id
		 WHERE nc.node_id = ? 
		   AND nc.active = 1 
		   AND sc.active = 1
		   AND z.active = 1
		   AND z.service_id IS NOT NULL`,
		nodeID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query zones for node: %v", err)
	}
	defer rows.Close()

	var zones []string
	for rows.Next() {
		var zoneName string
		if err := rows.Scan(&zoneName); err != nil {
			return nil, fmt.Errorf("failed to scan zone name: %v", err)
		}
		zones = append(zones, zoneName)
	}

	return zones, rows.Err()
}

// GetZonesNewlyServedByNode returns zones that become newly served by a node after adding a component
// A zone becomes newly served if:
// - The component is part of the zone's service, AND
// - The node did not previously serve any other component of that service
func (kdc *KdcDB) GetZonesNewlyServedByNode(nodeID, componentID string) ([]string, error) {
	rows, err := kdc.DB.Query(
		`SELECT DISTINCT z.name
		 FROM zones z
		 JOIN service_component_assignments sc ON sc.service_id = z.service_id
		 WHERE sc.component_id = ?
		   AND sc.active = 1
		   AND z.active = 1
		   AND z.service_id IS NOT NULL
		   AND NOT EXISTS (
		       SELECT 1
		       FROM service_component_assignments sc2
		       JOIN node_component_assignments nc ON nc.component_id = sc2.component_id
		       WHERE sc2.service_id = z.service_id
		         AND nc.node_id = ?
		         AND nc.active = 1
		         AND sc2.active = 1
		         AND sc2.component_id != ?
		   )`,
		componentID, nodeID, componentID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query newly served zones: %v", err)
	}
	defer rows.Close()

	var zones []string
	for rows.Next() {
		var zoneName string
		if err := rows.Scan(&zoneName); err != nil {
			return nil, fmt.Errorf("failed to scan zone name: %v", err)
		}
		zones = append(zones, zoneName)
	}

	return zones, rows.Err()
}

// GetZonesNoLongerServedByNode returns zones that are no longer served by a node after removing a component
// A zone becomes unserved if:
// - The component was part of the zone's service, AND
// - The component was the only component of that service that the node had
func (kdc *KdcDB) GetZonesNoLongerServedByNode(nodeID, componentID string) ([]string, error) {
	rows, err := kdc.DB.Query(
		`SELECT DISTINCT z.name
		 FROM zones z
		 JOIN service_component_assignments sc ON sc.service_id = z.service_id
		 WHERE sc.component_id = ?
		   AND sc.active = 1
		   AND z.active = 1
		   AND z.service_id IS NOT NULL
		   AND NOT EXISTS (
		       SELECT 1
		       FROM service_component_assignments sc2
		       JOIN node_component_assignments nc ON nc.component_id = sc2.component_id
		       WHERE sc2.service_id = z.service_id
		         AND nc.node_id = ?
		         AND nc.active = 1
		         AND sc2.active = 1
		         AND sc2.component_id != ?
		   )`,
		componentID, nodeID, componentID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query no-longer-served zones: %v", err)
	}
	defer rows.Close()

	var zones []string
	for rows.Next() {
		var zoneName string
		if err := rows.Scan(&zoneName); err != nil {
			return nil, fmt.Errorf("failed to scan zone name: %v", err)
		}
		zones = append(zones, zoneName)
	}

	return zones, rows.Err()
}

// ============================================================================
// Service Transaction Management
// ============================================================================

// StartServiceTransaction creates a new transaction for modifying a service
// Returns a transaction token that can be used for subsequent operations
func (kdc *KdcDB) StartServiceTransaction(serviceID, createdBy, comment string) (string, error) {
	// Generate transaction ID: tx-{2 letters} (e.g., tx-aa, tx-ab)
	// Use random 2 lowercase letters for simplicity
	// Since transactions expire after 24h and typically only one is active, collisions are unlikely
	// Generate 2 random bytes and convert to letters (a-z)
	randBytes := make([]byte, 2)
	if _, err := rand.Read(randBytes); err != nil {
		// Fallback to timestamp-based if rand fails
		nanos := time.Now().UnixNano()
		randBytes[0] = byte(nanos % 26)
		randBytes[1] = byte((nanos / 26) % 26)
	}
	letter1 := 'a' + rune(randBytes[0]%26)
	letter2 := 'a' + rune(randBytes[1]%26)
	txID := fmt.Sprintf("tx-%c%c", letter1, letter2)
	
	// Get current service state snapshot for conflict detection
	components, err := kdc.GetComponentsForService(serviceID)
	if err != nil {
		return "", fmt.Errorf("failed to get service components: %v", err)
	}
	
	service, err := kdc.GetService(serviceID)
	if err != nil {
		return "", fmt.Errorf("failed to get service: %v", err)
	}
	
	// Create snapshot
	snapshot := map[string]interface{}{
		"components": components,
		"service_id": serviceID,
		"service_name": service.Name,
		"timestamp": time.Now().Unix(),
	}
	
	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil {
		return "", fmt.Errorf("failed to marshal snapshot: %v", err)
	}
	
	// Default expiration: 24 hours
	expiresAt := time.Now().Add(24 * time.Hour)
	
	// Initialize empty changes
	changes := ServiceTransactionChanges{
		AddComponents:    []string{},
		RemoveComponents: []string{},
	}
	changesJSON, err := json.Marshal(changes)
	if err != nil {
		return "", fmt.Errorf("failed to marshal changes: %v", err)
	}
	
	// Insert transaction
	var snapshotSQL interface{}
	if kdc.DBType == "sqlite" {
		snapshotSQL = string(snapshotJSON)
	} else {
		snapshotSQL = snapshotJSON
	}
	
	_, err = kdc.DB.Exec(
		`INSERT INTO service_transactions (id, service_id, created_at, expires_at, state, changes, created_by, comment, service_snapshot)
		 VALUES (?, ?, CURRENT_TIMESTAMP, ?, 'open', ?, ?, ?, ?)`,
		txID, serviceID, expiresAt, changesJSON, createdBy, comment, snapshotSQL,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create transaction: %v", err)
	}
	
	return txID, nil
}

// GetServiceTransaction retrieves a transaction by ID
func (kdc *KdcDB) GetServiceTransaction(txID string) (*ServiceTransaction, error) {
	var tx ServiceTransaction
	var changesJSON, snapshotJSON sql.NullString
	var createdBy, comment sql.NullString
	
	err := kdc.DB.QueryRow(
		`SELECT id, service_id, created_at, expires_at, state, changes, created_by, comment, service_snapshot
		 FROM service_transactions WHERE id = ?`,
		txID,
	).Scan(&tx.ID, &tx.ServiceID, &tx.CreatedAt, &tx.ExpiresAt, &tx.State, &changesJSON, &createdBy, &comment, &snapshotJSON)
	
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("transaction not found: %s", txID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction: %v", err)
	}
	
	// Parse changes JSON
	if changesJSON.Valid {
		if err := json.Unmarshal([]byte(changesJSON.String), &tx.Changes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal changes: %v", err)
		}
	}
	
	// Parse snapshot JSON
	if snapshotJSON.Valid {
		if err := json.Unmarshal([]byte(snapshotJSON.String), &tx.ServiceSnapshot); err != nil {
			return nil, fmt.Errorf("failed to unmarshal snapshot: %v", err)
		}
	}
	
	if createdBy.Valid {
		tx.CreatedBy = createdBy.String
	}
	if comment.Valid {
		tx.Comment = comment.String
	}
	
	return &tx, nil
}

// ListServiceTransactions returns all transactions, optionally filtered by state
func (kdc *KdcDB) ListServiceTransactions(stateFilter string) ([]*ServiceTransaction, error) {
	var query string
	var args []interface{}
	
	if stateFilter != "" {
		query = `SELECT id, service_id, created_at, expires_at, state, changes, created_by, comment, service_snapshot
		         FROM service_transactions WHERE state = ? ORDER BY created_at DESC`
		args = []interface{}{stateFilter}
	} else {
		query = `SELECT id, service_id, created_at, expires_at, state, changes, created_by, comment, service_snapshot
		         FROM service_transactions ORDER BY created_at DESC`
	}
	
	rows, err := kdc.DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query transactions: %v", err)
	}
	defer rows.Close()
	
	var transactions []*ServiceTransaction
	for rows.Next() {
		var tx ServiceTransaction
		var changesJSON, snapshotJSON sql.NullString
		var createdBy, comment sql.NullString
		
		if err := rows.Scan(&tx.ID, &tx.ServiceID, &tx.CreatedAt, &tx.ExpiresAt, &tx.State, &changesJSON, &createdBy, &comment, &snapshotJSON); err != nil {
			return nil, fmt.Errorf("failed to scan transaction: %v", err)
		}
		
		// Parse changes JSON
		if changesJSON.Valid {
			if err := json.Unmarshal([]byte(changesJSON.String), &tx.Changes); err != nil {
				return nil, fmt.Errorf("failed to unmarshal changes: %v", err)
			}
		}
		
		// Parse snapshot JSON
		if snapshotJSON.Valid {
			if err := json.Unmarshal([]byte(snapshotJSON.String), &tx.ServiceSnapshot); err != nil {
				return nil, fmt.Errorf("failed to unmarshal snapshot: %v", err)
			}
		}
		
		if createdBy.Valid {
			tx.CreatedBy = createdBy.String
		}
		if comment.Valid {
			tx.Comment = comment.String
		}
		
		transactions = append(transactions, &tx)
	}
	
	return transactions, rows.Err()
}

// AddComponentToTransaction adds a component to the add list in a transaction
func (kdc *KdcDB) AddComponentToTransaction(txID, componentID string) error {
	tx, err := kdc.GetServiceTransaction(txID)
	if err != nil {
		return err
	}
	
	if tx.State != ServiceTransactionStateOpen {
		return fmt.Errorf("transaction %s is not open (state: %s)", txID, tx.State)
	}
	
	// Check if component is already in remove list (remove it from there)
	for i, compID := range tx.Changes.RemoveComponents {
		if compID == componentID {
			// Remove from remove list
			tx.Changes.RemoveComponents = append(tx.Changes.RemoveComponents[:i], tx.Changes.RemoveComponents[i+1:]...)
			break
		}
	}
	
	// Check if already in add list
	for _, compID := range tx.Changes.AddComponents {
		if compID == componentID {
			return nil // Already in add list, no-op
		}
	}
	
	// Add to add list
	tx.Changes.AddComponents = append(tx.Changes.AddComponents, componentID)
	
	// Update transaction
	changesJSON, err := json.Marshal(tx.Changes)
	if err != nil {
		return fmt.Errorf("failed to marshal changes: %v", err)
	}
	
	_, err = kdc.DB.Exec(
		"UPDATE service_transactions SET changes = ? WHERE id = ?",
		changesJSON, txID,
	)
	if err != nil {
		return fmt.Errorf("failed to update transaction: %v", err)
	}
	
	return nil
}

// RemoveComponentFromTransaction adds a component to the remove list in a transaction
func (kdc *KdcDB) RemoveComponentFromTransaction(txID, componentID string) error {
	tx, err := kdc.GetServiceTransaction(txID)
	if err != nil {
		return err
	}
	
	if tx.State != ServiceTransactionStateOpen {
		return fmt.Errorf("transaction %s is not open (state: %s)", txID, tx.State)
	}
	
	// Check if component is already in add list (remove it from there)
	for i, compID := range tx.Changes.AddComponents {
		if compID == componentID {
			// Remove from add list
			tx.Changes.AddComponents = append(tx.Changes.AddComponents[:i], tx.Changes.AddComponents[i+1:]...)
			break
		}
	}
	
	// Check if already in remove list
	for _, compID := range tx.Changes.RemoveComponents {
		if compID == componentID {
			return nil // Already in remove list, no-op
		}
	}
	
	// Add to remove list
	tx.Changes.RemoveComponents = append(tx.Changes.RemoveComponents, componentID)
	
	// Update transaction
	changesJSON, err := json.Marshal(tx.Changes)
	if err != nil {
		return fmt.Errorf("failed to marshal changes: %v", err)
	}
	
	_, err = kdc.DB.Exec(
		"UPDATE service_transactions SET changes = ? WHERE id = ?",
		changesJSON, txID,
	)
	if err != nil {
		return fmt.Errorf("failed to update transaction: %v", err)
	}
	
	return nil
}

// RollbackServiceTransaction marks a transaction as rolled back
func (kdc *KdcDB) RollbackServiceTransaction(txID string) error {
	_, err := kdc.DB.Exec(
		"UPDATE service_transactions SET state = 'rolled_back' WHERE id = ? AND state = 'open'",
		txID,
	)
	if err != nil {
		return fmt.Errorf("failed to rollback transaction: %v", err)
	}
	return nil
}

// ============================================================================
// Delta Computation for Service-Component Changes
// ============================================================================

// GetZonesNewlyServedByNodes returns zones that become newly served by nodes
// when a component is added to a service.
// A zone becomes newly served if:
// - The component is part of the zone's service, AND
// - The node serves that component, AND
// - The node did not previously serve any other component of that service
func (kdc *KdcDB) GetZonesNewlyServedByNodes(serviceID, componentID string) (map[string][]string, error) {
	// Get all zones in the service
	zones, err := kdc.DB.Query(
		`SELECT name FROM zones WHERE service_id = ? AND active = 1`,
		serviceID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query zones: %v", err)
	}
	defer zones.Close()
	
	result := make(map[string][]string)
	
	for zones.Next() {
		var zoneName string
		if err := zones.Scan(&zoneName); err != nil {
			return nil, fmt.Errorf("failed to scan zone name: %v", err)
		}
		
		// Find nodes that serve this component and would newly serve this zone
		// A node newly serves a zone if:
		// - The node serves the component being added
		// - The node did not previously serve any other component of this service
		nodes, err := kdc.DB.Query(
			`SELECT DISTINCT nc.node_id
			 FROM node_component_assignments nc
			 WHERE nc.component_id = ?
			   AND nc.active = 1
			   AND NOT EXISTS (
			       SELECT 1
			       FROM service_component_assignments sc2
			       JOIN node_component_assignments nc2 ON nc2.component_id = sc2.component_id
			       WHERE sc2.service_id = ?
			         AND nc2.node_id = nc.node_id
			         AND sc2.active = 1
			         AND nc2.active = 1
			         AND sc2.component_id != ?
			   )`,
			componentID, serviceID, componentID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to query nodes for zone %s: %v", zoneName, err)
		}
		
		var nodeList []string
		for nodes.Next() {
			var nodeID string
			if err := nodes.Scan(&nodeID); err != nil {
				nodes.Close()
				return nil, fmt.Errorf("failed to scan node ID: %v", err)
			}
			nodeList = append(nodeList, nodeID)
		}
		nodes.Close()
		
		if len(nodeList) > 0 {
			result[zoneName] = nodeList
		}
	}
	
	return result, zones.Err()
}

// GetZonesNoLongerServedByNodes returns zones that are no longer served by nodes
// when a component is removed from a service.
// A zone becomes unserved if:
// - The component was part of the zone's service, AND
// - The component was the only component of that service that the node had
func (kdc *KdcDB) GetZonesNoLongerServedByNodes(serviceID, componentID string) (map[string][]string, error) {
	// Get all zones in the service
	zones, err := kdc.DB.Query(
		`SELECT name FROM zones WHERE service_id = ? AND active = 1`,
		serviceID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query zones: %v", err)
	}
	defer zones.Close()
	
	result := make(map[string][]string)
	
	for zones.Next() {
		var zoneName string
		if err := zones.Scan(&zoneName); err != nil {
			return nil, fmt.Errorf("failed to scan zone name: %v", err)
		}
		
		// Find nodes that served this component and will no longer serve this zone
		// A node stops serving a zone if:
		// - The node served the component being removed
		// - The node does not serve any other component of this service
		nodes, err := kdc.DB.Query(
			`SELECT DISTINCT nc.node_id
			 FROM node_component_assignments nc
			 WHERE nc.component_id = ?
			   AND nc.active = 1
			   AND NOT EXISTS (
			       SELECT 1
			       FROM service_component_assignments sc2
			       JOIN node_component_assignments nc2 ON nc2.component_id = sc2.component_id
			       WHERE sc2.service_id = ?
			         AND nc2.node_id = nc.node_id
			         AND sc2.active = 1
			         AND nc2.active = 1
			         AND sc2.component_id != ?
			   )`,
			componentID, serviceID, componentID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to query nodes for zone %s: %v", zoneName, err)
		}
		
		var nodeList []string
		for nodes.Next() {
			var nodeID string
			if err := nodes.Scan(&nodeID); err != nil {
				nodes.Close()
				return nil, fmt.Errorf("failed to scan node ID: %v", err)
			}
			nodeList = append(nodeList, nodeID)
		}
		nodes.Close()
		
		if len(nodeList) > 0 {
			result[zoneName] = nodeList
		}
	}
	
	return result, zones.Err()
}

// GetZonesNewlyServedByNodesWithExclusions is like GetZonesNewlyServedByNodes but accounts for
// transaction changes: excludes components being removed and only considers future service state
func (kdc *KdcDB) GetZonesNewlyServedByNodesWithExclusions(serviceID, componentID string, componentsBeingRemoved []string, futureComponents map[string]bool) (map[string][]string, error) {
	// Get all zones in the service
	zones, err := kdc.DB.Query(
		`SELECT name FROM zones WHERE service_id = ? AND active = 1`,
		serviceID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query zones: %v", err)
	}
	defer zones.Close()
	
	result := make(map[string][]string)
	
	// Build exclusion list: components being removed + components that will be in future service (excluding the one being added)
	excludeComponents := make(map[string]bool)
	for _, compID := range componentsBeingRemoved {
		excludeComponents[compID] = true
	}
	for compID := range futureComponents {
		if compID != componentID {
			excludeComponents[compID] = true
		}
	}
	
	// Build SQL exclusion clause
	excludeList := make([]string, 0, len(excludeComponents))
	for range excludeComponents {
		excludeList = append(excludeList, "?")
	}
	excludeClause := ""
	if len(excludeList) > 0 {
		excludeClause = " AND sc2.component_id NOT IN (" + strings.Join(excludeList, ", ") + ")"
	}
	
	for zones.Next() {
		var zoneName string
		if err := zones.Scan(&zoneName); err != nil {
			return nil, fmt.Errorf("failed to scan zone name: %v", err)
		}
		
		// Find nodes that serve this component and would newly serve this zone
		// A node newly serves a zone if:
		// - The node serves the component being added
		// - The node does not serve any other component that will remain in the service
		query := `SELECT DISTINCT nc.node_id
			 FROM node_component_assignments nc
			 WHERE nc.component_id = ?
			   AND nc.active = 1
			   AND NOT EXISTS (
			       SELECT 1
			       FROM service_component_assignments sc2
			       JOIN node_component_assignments nc2 ON nc2.component_id = sc2.component_id
			       WHERE sc2.service_id = ?
			         AND nc2.node_id = nc.node_id
			         AND sc2.active = 1
			         AND nc2.active = 1` + excludeClause + `
			   )`
		
		args := []interface{}{componentID, serviceID}
		for compID := range excludeComponents {
			args = append(args, compID)
		}
		
		nodes, err := kdc.DB.Query(query, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to query nodes for zone %s: %v", zoneName, err)
		}
		
		var nodeList []string
		for nodes.Next() {
			var nodeID string
			if err := nodes.Scan(&nodeID); err != nil {
				nodes.Close()
				return nil, fmt.Errorf("failed to scan node ID: %v", err)
			}
			nodeList = append(nodeList, nodeID)
		}
		nodes.Close()
		
		if len(nodeList) > 0 {
			result[zoneName] = nodeList
		}
	}
	
	return result, zones.Err()
}

// GetZonesNoLongerServedByNodesWithExclusions is like GetZonesNoLongerServedByNodes but accounts for
// transaction changes: excludes components being added and only considers future service state
func (kdc *KdcDB) GetZonesNoLongerServedByNodesWithExclusions(serviceID, componentID string, componentsBeingAdded []string, futureComponents map[string]bool) (map[string][]string, error) {
	// Get all zones in the service
	zones, err := kdc.DB.Query(
		`SELECT name FROM zones WHERE service_id = ? AND active = 1`,
		serviceID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query zones: %v", err)
	}
	defer zones.Close()
	
	result := make(map[string][]string)
	
	// Build exclusion list: components being added + components that will remain in future service
	excludeComponents := make(map[string]bool)
	for _, compID := range componentsBeingAdded {
		excludeComponents[compID] = true
	}
	for compID := range futureComponents {
		if compID != componentID {
			excludeComponents[compID] = true
		}
	}
	
	// Build SQL exclusion clause
	excludeList := make([]string, 0, len(excludeComponents))
	for range excludeComponents {
		excludeList = append(excludeList, "?")
	}
	excludeClause := ""
	if len(excludeList) > 0 {
		excludeClause = " AND sc2.component_id NOT IN (" + strings.Join(excludeList, ", ") + ")"
	}
	
	for zones.Next() {
		var zoneName string
		if err := zones.Scan(&zoneName); err != nil {
			return nil, fmt.Errorf("failed to scan zone name: %v", err)
		}
		
		// Find nodes that served this component and will no longer serve this zone
		// A node stops serving a zone if:
		// - The node served the component being removed
		// - The node does not serve any other component that will remain in the service
		query := `SELECT DISTINCT nc.node_id
			 FROM node_component_assignments nc
			 WHERE nc.component_id = ?
			   AND nc.active = 1
			   AND NOT EXISTS (
			       SELECT 1
			       FROM service_component_assignments sc2
			       JOIN node_component_assignments nc2 ON nc2.component_id = sc2.component_id
			       WHERE sc2.service_id = ?
			         AND nc2.node_id = nc.node_id
			         AND sc2.active = 1
			         AND nc2.active = 1` + excludeClause + `
			   )`
		
		args := []interface{}{componentID, serviceID}
		for compID := range excludeComponents {
			args = append(args, compID)
		}
		
		nodes, err := kdc.DB.Query(query, args...)
		if err != nil {
			return nil, fmt.Errorf("failed to query nodes for zone %s: %v", zoneName, err)
		}
		
		var nodeList []string
		for nodes.Next() {
			var nodeID string
			if err := nodes.Scan(&nodeID); err != nil {
				nodes.Close()
				return nil, fmt.Errorf("failed to scan node ID: %v", err)
			}
			nodeList = append(nodeList, nodeID)
		}
		nodes.Close()
		
		if len(nodeList) > 0 {
			result[zoneName] = nodeList
		}
	}
	
	return result, zones.Err()
}

// ViewServiceTransaction computes the delta report for a transaction without applying changes (dry-run)
func (kdc *KdcDB) ViewServiceTransaction(txID string) (*DeltaReport, error) {
	tx, err := kdc.GetServiceTransaction(txID)
	if err != nil {
		return nil, err
	}
	
	if tx.State != ServiceTransactionStateOpen {
		return nil, fmt.Errorf("transaction %s is not open (state: %s)", txID, tx.State)
	}
	
	// Get original components (current state)
	originalComponents, err := kdc.GetComponentsForService(tx.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get original components: %v", err)
	}
	
	// Compute updated components (after applying transaction)
	updatedComponents := make([]string, 0)
	updatedMap := make(map[string]bool)
	
	// Start with original components
	for _, compID := range originalComponents {
		updatedMap[compID] = true
	}
	
	// Remove components being removed
	for _, compID := range tx.Changes.RemoveComponents {
		delete(updatedMap, compID)
	}
	
	// Add components being added
	for _, compID := range tx.Changes.AddComponents {
		updatedMap[compID] = true
	}
	
	// Convert map to slice
	for compID := range updatedMap {
		updatedComponents = append(updatedComponents, compID)
	}
	sort.Strings(updatedComponents)
	
	// Validate service: must have exactly one signing component
	validationErrors := []string{}
	signingComponentCount := 0
	for _, compID := range updatedComponents {
		if strings.HasPrefix(compID, "sign_") {
			signingComponentCount++
		}
	}
	
	isValid := true
	if signingComponentCount == 0 {
		validationErrors = append(validationErrors, "Service must have exactly one signing component (found 0)")
		isValid = false
	} else if signingComponentCount > 1 {
		validationErrors = append(validationErrors, fmt.Sprintf("Service must have exactly one signing component (found %d)", signingComponentCount))
		isValid = false
	}
	
	report := &DeltaReport{
		ServiceID:            tx.ServiceID,
		TransactionID:        txID,
		OriginalComponents:   originalComponents,
		UpdatedComponents:    updatedComponents,
		AddedComponents:      tx.Changes.AddComponents,
		RemovedComponents:    tx.Changes.RemoveComponents,
		IsValid:              isValid,
		ValidationErrors:     validationErrors,
		ZonesNewlyServed:     make(map[string][]string),
		ZonesNoLongerServed:  make(map[string][]string),
		DistributionsToCreate: []DistributionPlan{},
		DistributionsToRevoke: []DistributionPlan{},
	}
	
	// Compute deltas for each component change
	// We need to account for BOTH additions and removals when computing deltas
	// Build a set of components that will be in the service AFTER the transaction
	futureComponents := make(map[string]bool)
	for _, compID := range originalComponents {
		futureComponents[compID] = true
	}
	for _, compID := range tx.Changes.RemoveComponents {
		delete(futureComponents, compID)
	}
	for _, compID := range tx.Changes.AddComponents {
		futureComponents[compID] = true
	}
	
	// First, handle additions
	for _, componentID := range tx.Changes.AddComponents {
		newlyServed, err := kdc.GetZonesNewlyServedByNodesWithExclusions(tx.ServiceID, componentID, tx.Changes.RemoveComponents, futureComponents)
		if err != nil {
			return nil, fmt.Errorf("failed to compute newly served zones for component %s: %v", componentID, err)
		}
		
		// Merge into report
		for zoneName, nodes := range newlyServed {
			if existing, exists := report.ZonesNewlyServed[zoneName]; exists {
				// Merge node lists, avoiding duplicates
				nodeMap := make(map[string]bool)
				for _, n := range existing {
					nodeMap[n] = true
				}
				for _, n := range nodes {
					if !nodeMap[n] {
						existing = append(existing, n)
						nodeMap[n] = true
					}
				}
				report.ZonesNewlyServed[zoneName] = existing
			} else {
				report.ZonesNewlyServed[zoneName] = nodes
			}
		}
	}
	
	// Then, handle removals
	for _, componentID := range tx.Changes.RemoveComponents {
		noLongerServed, err := kdc.GetZonesNoLongerServedByNodesWithExclusions(tx.ServiceID, componentID, tx.Changes.AddComponents, futureComponents)
		if err != nil {
			return nil, fmt.Errorf("failed to compute no-longer-served zones for component %s: %v", componentID, err)
		}
		
		// Merge into report
		for zoneName, nodes := range noLongerServed {
			if existing, exists := report.ZonesNoLongerServed[zoneName]; exists {
				// Merge node lists, avoiding duplicates
				nodeMap := make(map[string]bool)
				for _, n := range existing {
					nodeMap[n] = true
				}
				for _, n := range nodes {
					if !nodeMap[n] {
						existing = append(existing, n)
						nodeMap[n] = true
					}
				}
				report.ZonesNoLongerServed[zoneName] = existing
			} else {
				report.ZonesNoLongerServed[zoneName] = nodes
			}
		}
	}
	
	// Get zone count for debugging
	zoneCountRows, err := kdc.DB.Query(
		`SELECT COUNT(*) FROM zones WHERE service_id = ? AND active = 1`,
		tx.ServiceID,
	)
	var zoneCount int
	if err == nil && zoneCountRows.Next() {
		zoneCountRows.Scan(&zoneCount)
	}
	zoneCountRows.Close()
	
	// Build distribution plans for newly served zones
	for zoneName, nodes := range report.ZonesNewlyServed {
		// Get keys that would be distributed
		keys, err := kdc.GetDNSSECKeysForZone(zoneName)
		if err != nil {
			log.Printf("KDC: Warning: Failed to get keys for zone %s: %v", zoneName, err)
			continue
		}
		
		// Check signing mode
		signingMode, err := kdc.GetZoneSigningMode(zoneName)
		if err != nil {
			log.Printf("KDC: Warning: Failed to get signing mode for zone %s: %v", zoneName, err)
			continue
		}
		
		if signingMode != ZoneSigningModeEdgesignDyn && signingMode != ZoneSigningModeEdgesignZsk && signingMode != ZoneSigningModeEdgesignFull {
			continue // Skip zones that don't need key distribution
		}
		
		var keyIDs []string
		// Find standby ZSK keys
		for _, key := range keys {
			if key.KeyType == KeyTypeZSK && key.State == KeyStateStandby {
				keyIDs = append(keyIDs, key.ID)
			}
		}
		
		// For edgesign_full zones, also include active KSK
		if signingMode == ZoneSigningModeEdgesignFull {
			for _, key := range keys {
				if key.KeyType == KeyTypeKSK && key.State == KeyStateActive {
					keyIDs = append(keyIDs, key.ID)
					break // Only one active KSK
				}
			}
		}
		
		// Create distribution plan for each node
		for _, nodeID := range nodes {
			if len(keyIDs) > 0 {
				report.DistributionsToCreate = append(report.DistributionsToCreate, DistributionPlan{
					ZoneName: zoneName,
					NodeID:   nodeID,
					KeyIDs:   keyIDs,
				})
			}
		}
	}
	
	// Build distribution plans for zones no longer served (for revocation tracking)
	for zoneName, nodes := range report.ZonesNoLongerServed {
		// Get currently distributed keys
		keys, err := kdc.GetDNSSECKeysForZone(zoneName)
		if err != nil {
			log.Printf("KDC: Warning: Failed to get keys for zone %s: %v", zoneName, err)
			continue
		}
		
		var keyIDs []string
		// Find distributed ZSK keys
		for _, key := range keys {
			if key.KeyType == KeyTypeZSK && (key.State == KeyStateDistributed || key.State == KeyStateEdgeSigner) {
				keyIDs = append(keyIDs, key.ID)
			}
		}
		
		// For edgesign_full zones, also include active_dist KSK
		signingMode, err := kdc.GetZoneSigningMode(zoneName)
		if err == nil && signingMode == ZoneSigningModeEdgesignFull {
			for _, key := range keys {
				if key.KeyType == KeyTypeKSK && key.State == KeyStateActiveDist {
					keyIDs = append(keyIDs, key.ID)
					break
				}
			}
		}
		
		// Create distribution plan for each node (for revocation)
		for _, nodeID := range nodes {
			if len(keyIDs) > 0 {
				report.DistributionsToRevoke = append(report.DistributionsToRevoke, DistributionPlan{
					ZoneName: zoneName,
					NodeID:   nodeID,
					KeyIDs:   keyIDs,
				})
			}
		}
	}
	
	// Compute summary
	allZones := make(map[string]bool)
	for zoneName := range report.ZonesNewlyServed {
		allZones[zoneName] = true
	}
	for zoneName := range report.ZonesNoLongerServed {
		allZones[zoneName] = true
	}
	
	allNodes := make(map[string]bool)
	for _, nodes := range report.ZonesNewlyServed {
		for _, nodeID := range nodes {
			allNodes[nodeID] = true
		}
	}
	for _, nodes := range report.ZonesNoLongerServed {
		for _, nodeID := range nodes {
			allNodes[nodeID] = true
		}
	}
	
	report.Summary = DeltaSummary{
		TotalZonesAffected:      len(allZones),
		TotalDistributions:      len(report.DistributionsToCreate) + len(report.DistributionsToRevoke),
		TotalNodesAffected:      len(allNodes),
		ZonesNewlyServed:        len(report.ZonesNewlyServed),
		ZonesNoLongerServed:     len(report.ZonesNoLongerServed),
		DistributionsToCreate:   len(report.DistributionsToCreate),
		DistributionsToRevoke:   len(report.DistributionsToRevoke),
	}
	
	return report, nil
}

// CommitServiceTransaction applies the transaction changes and creates distributions
func (kdc *KdcDB) CommitServiceTransaction(txID string, kdcConf *KdcConf, dryRun bool) (*DeltaReport, error) {
	tx, err := kdc.GetServiceTransaction(txID)
	if err != nil {
		return nil, err
	}
	
	if tx.State != ServiceTransactionStateOpen {
		return nil, fmt.Errorf("transaction %s is not open (state: %s)", txID, tx.State)
	}
	
	// Check for conflicts (optimistic locking)
	// Verify service hasn't changed since transaction started
	currentComponents, err := kdc.GetComponentsForService(tx.ServiceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current service components: %v", err)
	}
	
	snapshotComponents, ok := tx.ServiceSnapshot["components"].([]interface{})
	if !ok {
		// Try to parse from JSON if it's a string slice
		if comps, ok := tx.ServiceSnapshot["components"].([]string); ok {
			// Convert to interface slice for comparison
			snapshotComponents = make([]interface{}, len(comps))
			for i, c := range comps {
				snapshotComponents[i] = c
			}
		} else {
			log.Printf("KDC: Warning: Could not parse snapshot components, skipping conflict check")
		}
	}
	
	if snapshotComponents != nil {
		snapshotMap := make(map[string]bool)
		for _, comp := range snapshotComponents {
			if compStr, ok := comp.(string); ok {
				snapshotMap[compStr] = true
			}
		}
		
		currentMap := make(map[string]bool)
		for _, comp := range currentComponents {
			currentMap[comp] = true
		}
		
		// Check if components changed (excluding our pending changes)
		// This is a simplified check - in practice, we'd want to account for the pending changes
		if len(snapshotMap) != len(currentMap) {
			// Components count changed - might be a conflict
			log.Printf("KDC: Warning: Service %s component count changed from %d to %d since transaction started", tx.ServiceID, len(snapshotMap), len(currentMap))
		}
	}
	
	// Get delta report
	report, err := kdc.ViewServiceTransaction(txID)
	if err != nil {
		return nil, fmt.Errorf("failed to compute delta: %v", err)
	}
	
	if dryRun {
		// Just return the report without applying changes
		return report, nil
	}
	
	// Start database transaction for atomicity
	dbTx, err := kdc.DB.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin database transaction: %v", err)
	}
	defer dbTx.Rollback()
	
	// Apply component changes
	for _, componentID := range tx.Changes.AddComponents {
		_, err = dbTx.Exec(
			"INSERT INTO service_component_assignments (service_id, component_id, active, since) VALUES (?, ?, 1, CURRENT_TIMESTAMP) ON DUPLICATE KEY UPDATE active = 1",
			tx.ServiceID, componentID,
		)
		if err != nil {
			// Try without ON DUPLICATE KEY for SQLite
			if strings.Contains(err.Error(), "syntax error") || strings.Contains(err.Error(), "ON DUPLICATE") {
				_, err = dbTx.Exec(
					"INSERT OR IGNORE INTO service_component_assignments (service_id, component_id, active, since) VALUES (?, ?, 1, CURRENT_TIMESTAMP)",
					tx.ServiceID, componentID,
				)
				if err != nil {
					return nil, fmt.Errorf("failed to add component %s: %v", componentID, err)
				}
			} else {
				return nil, fmt.Errorf("failed to add component %s: %v", componentID, err)
			}
		}
	}
	
	for _, componentID := range tx.Changes.RemoveComponents {
		_, err = dbTx.Exec(
			"UPDATE service_component_assignments SET active = 0 WHERE service_id = ? AND component_id = ?",
			tx.ServiceID, componentID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to remove component %s: %v", componentID, err)
		}
	}
	
	// Mark transaction as committed
	_, err = dbTx.Exec(
		"UPDATE service_transactions SET state = 'committed' WHERE id = ?",
		txID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to mark transaction as committed: %v", err)
	}
	
	// Commit database transaction
	if err := dbTx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit database transaction: %v", err)
	}
	
	// Create distributions (outside of DB transaction for better error handling)
	if kdcConf != nil {
		for _, plan := range report.DistributionsToCreate {
			if err := kdc.distributeKeysForZone(plan.ZoneName, plan.NodeID, kdcConf); err != nil {
				log.Printf("KDC: Warning: Failed to distribute keys for zone %s to node %s: %v", plan.ZoneName, plan.NodeID, err)
				// Continue with other distributions
			}
		}
		
		// TODO: Implement key revocation for report.DistributionsToRevoke
		// For now, just log
		if len(report.DistributionsToRevoke) > 0 {
			log.Printf("KDC: Note: %d distributions should be revoked (not yet implemented)", len(report.DistributionsToRevoke))
		}
	} else {
		log.Printf("KDC: KdcConf not provided, skipping automatic key distribution")
	}
	
	return report, nil
}

// distributeKeysForZone distributes standby ZSK keys for a zone to a specific node
// This is a helper function called when a node starts serving a zone
func (kdc *KdcDB) distributeKeysForZone(zoneName, nodeID string, kdcConf *KdcConf) error {
	// Check zone signing mode - only distribute keys for edgesigned zones
	signingMode, err := kdc.GetZoneSigningMode(zoneName)
	if err != nil {
		return fmt.Errorf("failed to get signing mode: %v", err)
	}
	
	if signingMode != ZoneSigningModeEdgesignDyn && signingMode != ZoneSigningModeEdgesignZsk && signingMode != ZoneSigningModeEdgesignFull {
		log.Printf("KDC: Zone %s has signing_mode=%s, skipping key distribution (only edgesign_* modes support key distribution)", zoneName, signingMode)
		return nil // Not an error, just skip
	}

	// Get the node
	node, err := kdc.GetNode(nodeID)
	if err != nil {
		return fmt.Errorf("failed to get node: %v", err)
	}
	
	if node.State != NodeStateOnline {
		log.Printf("KDC: Node %s is not online (state: %s), skipping key distribution", nodeID, node.State)
		return nil // Not an error, just skip
	}
	
	if node.NotifyAddress == "" {
		log.Printf("KDC: Node %s has no notify_address configured, skipping key distribution", nodeID)
		return nil // Not an error, just skip
	}

	// Get all keys for the zone
	keys, err := kdc.GetDNSSECKeysForZone(zoneName)
	if err != nil {
		return fmt.Errorf("failed to get keys for zone: %v", err)
	}

	// Find standby ZSK keys
	var standbyZSKs []*DNSSECKey
	for _, key := range keys {
		if key.KeyType == KeyTypeZSK && key.State == KeyStateStandby {
			standbyZSKs = append(standbyZSKs, key)
		}
	}

	// For edgesign_full zones, also find active KSK
	var activeKSK *DNSSECKey
	if signingMode == ZoneSigningModeEdgesignFull {
		for _, key := range keys {
			if key.KeyType == KeyTypeKSK && key.State == KeyStateActive {
				activeKSK = key
				break
			}
		}
		if activeKSK == nil {
			log.Printf("KDC: Zone %s uses sign_edge_full but no active KSK found, skipping KSK distribution", zoneName)
		}
	}

	if len(standbyZSKs) == 0 && activeKSK == nil {
		log.Printf("KDC: No standby ZSK keys or active KSK found for zone %s, nothing to distribute", zoneName)
		return nil // Not an error, just no keys to distribute
	}

	// Distribute each standby ZSK
	encryptedCount := 0
	var lastDistributionID string
	for _, key := range standbyZSKs {
		// Get or create distribution ID
		distributionID, err := kdc.GetOrCreateDistributionID(zoneName, key)
		if err != nil {
			log.Printf("KDC: Warning: Failed to get/create distribution ID for key %s: %v", key.ID, err)
			continue
		}
		lastDistributionID = distributionID

		// Transition to distributed state
		if err := kdc.UpdateKeyState(zoneName, key.ID, KeyStateDistributed); err != nil {
			log.Printf("KDC: Warning: Failed to update key state for key %s: %v", key.ID, err)
			continue
		}

		// Encrypt key for the node
		_, _, _, err = kdc.EncryptKeyForNode(key, node, kdcConf)
		if err != nil {
			log.Printf("KDC: Warning: Failed to encrypt key %s for node %s: %v", key.ID, nodeID, err)
			continue
		}

		encryptedCount++
		log.Printf("KDC: Distributed key %s for zone %s to node %s (distribution ID: %s)", key.ID, zoneName, nodeID, distributionID)
	}

	// Distribute active KSK for edgesign_full zones
	if activeKSK != nil {
		// Get or create distribution ID for KSK
		distributionID, err := kdc.GetOrCreateDistributionID(zoneName, activeKSK)
		if err != nil {
			log.Printf("KDC: Warning: Failed to get/create distribution ID for KSK %s: %v", activeKSK.ID, err)
		} else {
			lastDistributionID = distributionID
			// Transition to active_dist state (not distributed, since it's already active)
			if err := kdc.UpdateKeyState(zoneName, activeKSK.ID, KeyStateActiveDist); err != nil {
				log.Printf("KDC: Warning: Failed to update KSK state for key %s: %v", activeKSK.ID, err)
			} else {
				// Encrypt key for the node
				_, _, _, err = kdc.EncryptKeyForNode(activeKSK, node, kdcConf)
				if err != nil {
					log.Printf("KDC: Warning: Failed to encrypt KSK %s for node %s: %v", activeKSK.ID, nodeID, err)
				} else {
					encryptedCount++
					log.Printf("KDC: Distributed KSK %s for zone %s to node %s (distribution ID: %s)", activeKSK.ID, zoneName, nodeID, distributionID)
				}
			}
		}
	}

	if encryptedCount > 0 && lastDistributionID != "" {
		// Send NOTIFY to the node
		if kdcConf != nil && kdcConf.ControlZone != "" {
			if err := kdc.SendNotifyWithDistributionID(lastDistributionID, kdcConf.ControlZone); err != nil {
				log.Printf("KDC: Warning: Failed to send NOTIFY for distribution %s: %v", lastDistributionID, err)
			}
		}
		log.Printf("KDC: Distributed %d key(s) for zone %s to node %s", encryptedCount, zoneName, nodeID)
	}

	return nil
}

