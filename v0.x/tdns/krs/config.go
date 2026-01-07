/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Configuration structures for tdns-krs
 */

package krs

// KrsConf represents the KRS configuration
type KrsConf struct {
	Database    DatabaseConf `yaml:"database" mapstructure:"database"`
	Node        NodeConf     `yaml:"node" mapstructure:"node"`
	ControlZone string       `yaml:"control_zone" mapstructure:"control_zone"` // DNS zone for KMCTRL records
	DnsEngine   DnsEngineConf `yaml:"dnsengine" mapstructure:"dnsengine"`       // DNS engine config for NOTIFY
}

// DatabaseConf represents database configuration (SQLite only for edge nodes)
type DatabaseConf struct {
	DSN string `yaml:"dsn" mapstructure:"dsn" validate:"required"` // SQLite file path
}

// NodeConf represents the edge node's identity and connection info
type NodeConf struct {
	ID              string `yaml:"id" mapstructure:"id" validate:"required"`              // Node ID (must match KDC)
	LongTermPrivKey string `yaml:"long_term_priv_key" mapstructure:"long_term_priv_key" validate:"required"` // Path to HPKE long-term private key file
	KdcAddress      string `yaml:"kdc_address" mapstructure:"kdc_address" validate:"required"` // KDC server address (IP:port)
}

// DnsEngineConf represents DNS engine configuration for NOTIFY receiver
type DnsEngineConf struct {
	Addresses []string `yaml:"addresses" mapstructure:"addresses" validate:"required"` // Addresses to listen on
	Transports []string `yaml:"transports" mapstructure:"transports" validate:"required,min=1,dive,oneof=do53"` // Only do53 for now
}

