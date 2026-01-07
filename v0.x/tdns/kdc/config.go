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
	PublishTime time.Duration `yaml:"publish_time" mapstructure:"publish_time"` // Time to wait before published -> standby
	RetireTime time.Duration `yaml:"retire_time" mapstructure:"retire_time"` // Time to wait before retired -> removed
	DistributionTTL time.Duration `yaml:"distribution_ttl" mapstructure:"distribution_ttl"` // TTL for distributions (default: 5 minutes, like TSIG)
	JsonchunkMaxSize int `yaml:"jsonchunk_max_size" mapstructure:"jsonchunk_max_size"` // Maximum RDATA size per JSONCHUNK (bytes, default: 60000)
}

// DatabaseConf represents database configuration
type DatabaseConf struct {
	Type string `yaml:"type" mapstructure:"type" validate:"required,oneof=sqlite mariadb"` // Database type: "sqlite" or "mariadb"
	DSN  string `yaml:"dsn" mapstructure:"dsn" validate:"required"`                        // DSN: SQLite file path or MariaDB "user:password@tcp(host:port)/dbname"
}

// GetJsonchunkMaxSize returns the configured chunk size, or default (60000) if not set
func (conf *KdcConf) GetJsonchunkMaxSize() int {
	if conf.JsonchunkMaxSize <= 0 {
		return 60000 // Default: 60KB
	}
	return conf.JsonchunkMaxSize
}

// GetDistributionTTL returns the configured distribution TTL, or default (5 minutes) if not set
func (conf *KdcConf) GetDistributionTTL() time.Duration {
	if conf.DistributionTTL <= 0 {
		return 5 * time.Minute // Default: 5 minutes (like TSIG signatures)
	}
	return conf.DistributionTTL
}

