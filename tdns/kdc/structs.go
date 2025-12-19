/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Data structures for tdns-kdc (Key Distribution Center)
 */

package kdc

import (
	"time"

	"github.com/johanix/tdns/tdns/hpke"
)

// Zone represents a DNS zone managed by the KDC
type Zone struct {
	ID          string    `json:"id"`          // Unique identifier (typically the zone name)
	Name        string    `json:"name"`        // Zone name (e.g., "example.com.")
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Active      bool      `json:"active"`      // Whether the zone is actively managed
	Comment     string    `json:"comment"`     // Optional comment/description
}

// NodeState represents the state of an edge node
type NodeState string

const (
	NodeStateOnline     NodeState = "online"
	NodeStateOffline    NodeState = "offline"
	NodeStateCompromised NodeState = "compromised"
	NodeStateSuspended  NodeState = "suspended"
)

// Node represents an edge server that receives ZSK keys
type Node struct {
	ID              string    `json:"id"`              // Unique identifier for the node
	Name            string    `json:"name"`            // Human-readable name
	LongTermPubKey  []byte    `json:"long_term_pub_key"` // HPKE long-term public key (32 bytes, X25519)
	NotifyAddress   string    `json:"notify_address"`  // Address:port for sending NOTIFY messages (e.g., "192.0.2.1:53")
	RegisteredAt    time.Time `json:"registered_at"`
	LastSeen        time.Time `json:"last_seen"`
	State           NodeState `json:"state"`
	Comment         string    `json:"comment"`         // Optional comment/description
	Zones           []string  `json:"zones"`           // List of zone IDs this node serves (for future use)
}

// KeyType represents the type of DNSSEC key
type KeyType string

const (
	KeyTypeKSK KeyType = "KSK"
	KeyTypeZSK KeyType = "ZSK"
	KeyTypeCSK KeyType = "CSK"
)

// KeyState represents the state of a DNSSEC key in the KDC
type KeyState string

const (
	KeyStateCreated     KeyState = "created"
	KeyStatePublished   KeyState = "published"
	KeyStateStandby     KeyState = "standby"
	KeyStateActive      KeyState = "active"      // Central signer (stays in KDC)
	KeyStateDistributed KeyState = "distributed"  // Currently being distributed to nodes
	KeyStateEdgeSigner  KeyState = "edgesigner"  // Active on edge nodes
	KeyStateRetired     KeyState = "retired"
	KeyStateRemoved     KeyState = "removed"
	KeyStateRevoked     KeyState = "revoked"
)

// DNSSECKey represents a DNSSEC key (KSK, ZSK, or CSK) for a zone
type DNSSECKey struct {
	ID          string    `json:"id"`          // Unique identifier
	ZoneID      string    `json:"zone_id"`    // Zone this key belongs to
	KeyType     KeyType   `json:"key_type"`   // KSK, ZSK, or CSK
	KeyID       uint16    `json:"key_id"`     // DNSSEC KeyTag
	Algorithm   uint8     `json:"algorithm"`  // DNSSEC algorithm (e.g., 13 for ECDSA256, 15 for ED25519)
	Flags       uint16    `json:"flags"`      // DNSSEC flags (257 for KSK/CSK, 256 for ZSK)
	PublicKey   string    `json:"public_key"` // Public key RR string (DNSKEY record)
	PrivateKey  []byte    `json:"-"`          // Private key (never sent in API responses)
	State       KeyState  `json:"state"`      // Current state of the key
	CreatedAt   time.Time `json:"created_at"`
	PublishedAt *time.Time `json:"published_at,omitempty"` // When the key was published
	ActivatedAt *time.Time `json:"activated_at,omitempty"` // When the key was activated
	RetiredAt   *time.Time `json:"retired_at,omitempty"`   // When the key was retired
	Comment     string    `json:"comment"`    // Optional comment
}

// DistributionRecord represents a record of a key distribution to a node
type DistributionRecord struct {
	ID               string             // Unique ID for this distribution
	ZoneID           string             // Zone name
	KeyID            string             // DNSSEC key ID
	NodeID           string             // Target node ID (empty if to all nodes)
	EncryptedKey     []byte             // HPKE-encrypted private key
	EphemeralPubKey  []byte             // Ephemeral public key used for encryption
	CreatedAt        time.Time
	ExpiresAt        *time.Time         // Optional expiration of the distributed key
	Status           hpke.DistributionStatus
	DistributionID   string             // HPKE distribution ID (for tracking)
}

// ZoneNodeAssignment represents which zones are assigned to which nodes
// For now, we assume all zones are served by all nodes, but this structure
// allows for future per-node zone assignments
type ZoneNodeAssignment struct {
	ZoneID string
	NodeID string
	Active bool      // Whether this assignment is active
	Since  time.Time
}

