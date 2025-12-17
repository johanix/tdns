/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Configuration structures for tdns-kdc
 */

package kdc

import (
	"time"
)

// KdcConf represents the KDC configuration
type KdcConf struct {
	Database DatabaseConf `yaml:"database" mapstructure:"database"`
	ControlZone string    `yaml:"control_zone" mapstructure:"control_zone"` // DNS zone for KMCTRL records
	DefaultAlgorithm uint8 `yaml:"default_algorithm" mapstructure:"default_algorithm"` // Default DNSSEC algorithm (e.g., 15 for ED25519)
	KeyRotationInterval time.Duration `yaml:"key_rotation_interval" mapstructure:"key_rotation_interval"` // How often to rotate ZSKs
	StandbyKeyCount int `yaml:"standby_key_count" mapstructure:"standby_key_count"` // Number of standby ZSKs to maintain
}

// DatabaseConf represents database configuration
type DatabaseConf struct {
	Type string `yaml:"type" mapstructure:"type" validate:"required,oneof=sqlite mariadb"` // Database type: "sqlite" or "mariadb"
	DSN  string `yaml:"dsn" mapstructure:"dsn" validate:"required"`                        // DSN: SQLite file path or MariaDB "user:password@tcp(host:port)/dbname"
}

