/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Type definitions for HPKE key distribution
 */

package hpke

// KeyState defines the state of a DNSSEC key in the distribution system
type KeyState string

const (
	KeyStateCreated     KeyState = "created"
	KeyStatePublished   KeyState = "published"
	KeyStateStandby     KeyState = "standby"
	KeyStateActive      KeyState = "active"      // Central signer (stays in KDC)
	KeyStateDistributed KeyState = "distributed" // Currently being distributed to nodes
	KeyStateEdgeSigner  KeyState = "edgesigner"  // Active on edge nodes
	KeyStateRetired     KeyState = "retired"
	KeyStateRemoved     KeyState = "removed"
	KeyStateRevoked     KeyState = "revoked"
)

// EdgeStatus defines the status of an edge node in the KDC
type EdgeStatus string

const (
	EdgeStatusActive    EdgeStatus = "active"
	EdgeStatusRevoked   EdgeStatus = "revoked"
	EdgeStatusSuspended EdgeStatus = "suspended"
)

// DistributionStatus defines the status of a key distribution
type DistributionStatus string

const (
	DistributionStatusPending   DistributionStatus = "pending"
	DistributionStatusDelivered DistributionStatus = "delivered"
	DistributionStatusActive    DistributionStatus = "active"
	DistributionStatusRevoked   DistributionStatus = "revoked"
)
