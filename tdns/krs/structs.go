/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Data structures for tdns-krs (Key Receiving Service)
 */

package krs

import (
	"time"
)

// ReceivedKey represents a DNSSEC key received from the KDC
type ReceivedKey struct {
	ID              string    `json:"id"`              // Unique identifier (distribution ID)
	ZoneName        string    `json:"zone_name"`      // Zone name this key is for
	KeyID           uint16    `json:"key_id"`         // DNSSEC KeyTag
	KeyType         string    `json:"key_type"`       // "KSK", "ZSK", or "CSK"
	Algorithm       uint8     `json:"algorithm"`      // DNSSEC algorithm
	Flags           uint16    `json:"flags"`          // DNSSEC flags
	PublicKey       string    `json:"public_key"`     // Public key RR string (DNSKEY record)
	PrivateKey      []byte    `json:"-"`              // Decrypted private key (never sent in API responses)
	State           string    `json:"state"`          // "received", "active", "edgesigner", "retired", "removed"
	ReceivedAt      time.Time `json:"received_at"`    // When the key was received
	ActivatedAt     *time.Time `json:"activated_at,omitempty"` // When the key was activated
	RetiredAt       *time.Time `json:"retired_at,omitempty"`   // When the key was retired
	RetireTime      string    `json:"retire_time,omitempty"`   // Duration string from KDC (e.g., "168h0m0s")
	DistributionID  string    `json:"distribution_id"` // KDC distribution ID
	Comment         string    `json:"comment"`        // Optional comment
}

// NodeConfig represents the edge node's configuration
type NodeConfig struct {
	ID              string    `json:"id"`              // Node ID (must match KDC)
	LongTermPubKey  []byte    `json:"-"`               // HPKE long-term public key (never sent in API)
	LongTermPrivKey []byte    `json:"-"`               // HPKE long-term private key (never sent in API)
	KdcAddress      string    `json:"kdc_address"`     // KDC server address (IP:port)
	ControlZone     string    `json:"control_zone"`   // Control zone name (e.g., "kdc.example.com.")
	RegisteredAt    time.Time `json:"registered_at"`
	LastSeen        time.Time `json:"last_seen"`
}

