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
			state ENUM('created', 'published', 'standby', 'active', 'distributed', 'edgesigner', 'retired', 'removed', 'revoked') NOT NULL DEFAULT 'created',
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
			status ENUM('pending', 'delivered', 'active', 'revoked') NOT NULL DEFAULT 'pending',
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

		// Component-zone assignments table (many-to-many)
		`CREATE TABLE IF NOT EXISTS component_zone_assignments (
			component_id VARCHAR(255) NOT NULL,
			zone_name VARCHAR(255) NOT NULL,
			active BOOLEAN NOT NULL DEFAULT TRUE,
			since TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (component_id, zone_name),
			FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE CASCADE,
			FOREIGN KEY (zone_name) REFERENCES zones(name) ON DELETE CASCADE,
			INDEX idx_zone_name (zone_name),
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

		// Zone-node assignments table (deprecated, kept for backward compatibility)
		`CREATE TABLE IF NOT EXISTS zone_node_assignments (
			zone_name VARCHAR(255) NOT NULL,
			node_id VARCHAR(255) NOT NULL,
			active BOOLEAN NOT NULL DEFAULT TRUE,
			since TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (zone_name, node_id),
			FOREIGN KEY (zone_name) REFERENCES zones(name) ON DELETE CASCADE,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
			INDEX idx_node_id (node_id),
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
	}

	for _, stmt := range schema {
		if _, err := kdc.DB.Exec(stmt); err != nil {
			return fmt.Errorf("failed to execute schema statement: %v\nStatement: %s", err, stmt)
		}
	}

	log.Printf("KDC database schema initialized successfully (MySQL/MariaDB)")
	
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
			CHECK (state IN ('created', 'published', 'standby', 'active', 'distributed', 'edgesigner', 'retired', 'removed', 'revoked'))
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
			FOREIGN KEY (zone_name) REFERENCES zones(name) ON DELETE CASCADE,
			FOREIGN KEY (key_id) REFERENCES dnssec_keys(id) ON DELETE CASCADE,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
			CHECK (status IN ('pending', 'delivered', 'active', 'revoked'))
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

		// Component-zone assignments table (many-to-many)
		`CREATE TABLE IF NOT EXISTS component_zone_assignments (
			component_id TEXT NOT NULL,
			zone_name TEXT NOT NULL,
			active INTEGER NOT NULL DEFAULT 1,
			since DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (component_id, zone_name),
			FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE CASCADE,
			FOREIGN KEY (zone_name) REFERENCES zones(name) ON DELETE CASCADE,
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

		// Zone-node assignments table (deprecated, kept for backward compatibility)
		`CREATE TABLE IF NOT EXISTS zone_node_assignments (
			zone_name TEXT NOT NULL,
			node_id TEXT NOT NULL,
			active INTEGER NOT NULL DEFAULT 1,
			since DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (zone_name, node_id),
			FOREIGN KEY (zone_name) REFERENCES zones(name) ON DELETE CASCADE,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
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
		`CREATE INDEX IF NOT EXISTS idx_zone_node_assignments_node_id ON zone_node_assignments(node_id)`,
		`CREATE INDEX IF NOT EXISTS idx_zone_node_assignments_active ON zone_node_assignments(active)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_confirmations_distribution_id ON distribution_confirmations(distribution_id)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_confirmations_zone_key ON distribution_confirmations(zone_name, key_id)`,
		`CREATE INDEX IF NOT EXISTS idx_distribution_confirmations_node_id ON distribution_confirmations(node_id)`,
	}

	for _, stmt := range schema {
		if _, err := kdc.DB.Exec(stmt); err != nil {
			return fmt.Errorf("failed to execute schema statement: %v\nStatement: %s", err, stmt)
		}
	}

	log.Printf("KDC database schema initialized successfully (SQLite)")
	
	// Ensure default service/component exist
	if err := kdc.ensureDefaultServiceAndComponent(); err != nil {
		return fmt.Errorf("failed to ensure default service/component: %v", err)
	}
	
	return nil
}

// DeriveSigningModeFromComponent derives the signing mode from a component ID
// Component IDs are in the format "sign_<signing_mode>" (e.g., "sign_edge_all", "sign_kdc", "sign_upstream")
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
		case "edge_all":
			return ZoneSigningModeEdgesignAll
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
// Creates components for each signing mode: upstream, central, unsigned, edgesign_dyn, edgesign_zsk, edgesign_all
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
		"edge_all":   "Component for fully edgesigned zones (KSK+ZSK)",
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
			if err := kdc.AddServiceComponentAssignment(defaultServiceID, defaultSigningComponentID); err != nil {
				return fmt.Errorf("failed to assign component %s to default service: %v", defaultSigningComponentID, err)
			}
			log.Printf("KDC: Assigned component %s to default service %s", defaultSigningComponentID, defaultServiceID)
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
		"comp_edgesign_all":   "sign_edge_all",
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
				if err == nil && len(zones) > 0 {
					log.Printf("KDC: Warning: Component %s has %d zones assigned. Migrating to %s", oldCompID, len(zones), newCompID)
					for _, zoneName := range zones {
						// Remove from old component
						if err := kdc.RemoveComponentZoneAssignment(oldCompID, zoneName); err != nil {
							log.Printf("KDC: Warning: Failed to remove zone %s from old component %s: %v", zoneName, oldCompID, err)
						} else {
							// Add to new component
							if err := kdc.AddComponentZoneAssignment(newCompID, zoneName); err != nil {
								log.Printf("KDC: Warning: Failed to assign zone %s to new component %s: %v", zoneName, newCompID, err)
							}
						}
					}
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
	
	// Explicitly remove component assignments (in case CASCADE doesn't work as expected)
	// This is a safety measure - CASCADE should handle it, but we do it explicitly to be sure
	_, err = kdc.DB.Exec("DELETE FROM component_zone_assignments WHERE zone_name = ?", zoneName)
	if err != nil {
		log.Printf("KDC: Warning: Failed to delete component assignments for zone %s: %v", zoneName, err)
		// Continue anyway - CASCADE might handle it
	}
	
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

// CheckAllNodesConfirmed checks if all active nodes for a zone have confirmed receipt of a distributed key
func (kdc *KdcDB) CheckAllNodesConfirmed(distributionID, zoneName string) (bool, error) {
	// Get all active nodes that serve this zone (via components)
	nodes, err := kdc.GetActiveNodesForZone(zoneName)
	if err != nil {
		return false, fmt.Errorf("failed to get nodes for zone: %v", err)
	}

	var activeNodeIDs []string
	for _, node := range nodes {
		activeNodeIDs = append(activeNodeIDs, node.ID)
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
func (kdc *KdcDB) UpdateKeyState(zoneName, keyID string, newState KeyState) error {
	now := time.Now()
	var err error
	
	switch newState {
	case KeyStatePublished:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ?, published_at = ? WHERE zone_name = ? AND id = ?`,
			newState, now, zoneName, keyID,
		)
	case KeyStateStandby:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ? WHERE zone_name = ? AND id = ?`,
			newState, zoneName, keyID,
		)
	case KeyStateActive:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ?, activated_at = ? WHERE zone_name = ? AND id = ?`,
			newState, now, zoneName, keyID,
		)
	case KeyStateDistributed:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ? WHERE zone_name = ? AND id = ?`,
			newState, zoneName, keyID,
		)
	case KeyStateEdgeSigner:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ? WHERE zone_name = ? AND id = ?`,
			newState, zoneName, keyID,
		)
	case KeyStateRetired:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ?, retired_at = ? WHERE zone_name = ? AND id = ?`,
			newState, now, zoneName, keyID,
		)
	case KeyStateRemoved:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ? WHERE zone_name = ? AND id = ?`,
			newState, zoneName, keyID,
		)
	default:
		_, err = kdc.DB.Exec(
			`UPDATE dnssec_keys SET state = ? WHERE zone_name = ? AND id = ?`,
			newState, zoneName, keyID,
		)
	}
	
	if err != nil {
		return fmt.Errorf("failed to update key state: %v", err)
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

// GetComponentsForZone returns all component IDs that serve a zone
func (kdc *KdcDB) GetComponentsForZone(zoneName string) ([]string, error) {
	rows, err := kdc.DB.Query(
		`SELECT component_id FROM component_zone_assignments 
		 WHERE zone_name = ? AND active = 1`,
		zoneName,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query zone components: %v", err)
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

// AddComponentZoneAssignment assigns a zone to a component
func (kdc *KdcDB) AddComponentZoneAssignment(componentID, zoneName string) error {
	_, err := kdc.DB.Exec(
		"INSERT INTO component_zone_assignments (component_id, zone_name, active, since) VALUES (?, ?, 1, CURRENT_TIMESTAMP)",
		componentID, zoneName,
	)
	if err != nil {
		return fmt.Errorf("failed to add component-zone assignment: %v", err)
	}
	return nil
}

// RemoveComponentZoneAssignment removes a zone from a component
func (kdc *KdcDB) RemoveComponentZoneAssignment(componentID, zoneName string) error {
	_, err := kdc.DB.Exec(
		"UPDATE component_zone_assignments SET active = 0 WHERE component_id = ? AND zone_name = ?",
		componentID, zoneName,
	)
	if err != nil {
		return fmt.Errorf("failed to remove component-zone assignment: %v", err)
	}
	return nil
}

// AddNodeComponentAssignment assigns a component to a node
func (kdc *KdcDB) AddNodeComponentAssignment(nodeID, componentID string) error {
	_, err := kdc.DB.Exec(
		"INSERT INTO node_component_assignments (node_id, component_id, active, since) VALUES (?, ?, 1, CURRENT_TIMESTAMP)",
		nodeID, componentID,
	)
	if err != nil {
		return fmt.Errorf("failed to add node-component assignment: %v", err)
	}
	return nil
}

// RemoveNodeComponentAssignment removes a component from a node
func (kdc *KdcDB) RemoveNodeComponentAssignment(nodeID, componentID string) error {
	_, err := kdc.DB.Exec(
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

