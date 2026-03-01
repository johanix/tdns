/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Database schema for HSYNC (multi-provider DNSSEC coordination).
 * Provides persistent storage for:
 * - Peer information (discovered agents, addresses, keys)
 * - Sync confirmations (operation tracking, audit trail)
 * - Zone-peer relationships
 * - Operational metrics
 */

package tdns

import (
	"fmt"
	"time"
)

// HsyncTables defines the database tables for HSYNC functionality.
// These are added to the KeyDB during initialization.
var HsyncTables = map[string]string{

	// PeerRegistry stores discovered peer information.
	// Peers are remote agents that we communicate with for zone synchronization.
	"PeerRegistry": `CREATE TABLE IF NOT EXISTS 'PeerRegistry' (
		id                    INTEGER PRIMARY KEY AUTOINCREMENT,
		peer_id               TEXT NOT NULL UNIQUE,

		-- Discovery information
		discovery_time        INTEGER NOT NULL,          -- Unix timestamp when first discovered
		discovery_source      TEXT,                       -- "hsync", "manual", "dns"

		-- API transport details
		api_endpoint          TEXT,                       -- Full URL for API transport
		api_host              TEXT,                       -- Hostname for API transport
		api_port              INTEGER,                    -- Port for API transport
		api_tlsa_record       TEXT,                       -- TLSA record (wire format, base64)
		api_available         INTEGER DEFAULT 0,          -- 1 if API transport is available

		-- DNS transport details
		dns_host              TEXT,                       -- Hostname for DNS transport
		dns_port              INTEGER DEFAULT 53,         -- Port for DNS transport
		dns_key_record        TEXT,                       -- KEY record (wire format, base64)
		dns_available         INTEGER DEFAULT 0,          -- 1 if DNS transport is available

		-- Operational address (may differ from discovery address for DDoS mitigation)
		operational_host      TEXT,
		operational_port      INTEGER,
		operational_transport TEXT,                       -- "udp", "tcp", "https"

		-- Public keys for encryption/verification
		encryption_pubkey     TEXT,                       -- JWK format public key for encryption
		verification_pubkey   TEXT,                       -- JWK format public key for signature verification

		-- State and preferences
		state                 TEXT DEFAULT 'needed',      -- needed, known, introducing, operational, degraded, interrupted, error
		state_reason          TEXT,                       -- Reason for current state
		state_changed_at      INTEGER,                    -- Unix timestamp of last state change
		preferred_transport   TEXT DEFAULT 'api',         -- api, dns

		-- Metrics
		last_contact_at       INTEGER,                    -- Unix timestamp of last successful contact
		last_hello_at         INTEGER,                    -- Unix timestamp of last hello handshake
		last_beat_at          INTEGER,                    -- Unix timestamp of last heartbeat received
		beat_interval         INTEGER DEFAULT 30,         -- Expected heartbeat interval in seconds
		beats_sent            INTEGER DEFAULT 0,          -- Total heartbeats sent
		beats_received        INTEGER DEFAULT 0,          -- Total heartbeats received
		failed_contacts       INTEGER DEFAULT 0,          -- Consecutive failed contact attempts

		-- Metadata
		created_at            INTEGER NOT NULL,
		updated_at            INTEGER NOT NULL,

		UNIQUE(peer_id)
	)`,

	// PeerZones tracks which zones are shared with which peers.
	// A peer may be responsible for multiple zones.
	"PeerZones": `CREATE TABLE IF NOT EXISTS 'PeerZones' (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		peer_id         TEXT NOT NULL,
		zone_name       TEXT NOT NULL,

		-- Relationship details
		relationship    TEXT DEFAULT 'peer',          -- peer, upstream, downstream
		role            TEXT,                          -- provider, owner, backup
		hsync_identity  TEXT,                          -- Identity from HSYNC record

		-- Sync state per zone
		last_sync_at    INTEGER,                       -- Unix timestamp of last successful sync
		sync_serial     INTEGER,                       -- Last synced SOA serial
		sync_state      TEXT DEFAULT 'pending',        -- pending, synced, conflict, error

		-- Metadata
		added_at        INTEGER NOT NULL,
		updated_at      INTEGER NOT NULL,

		UNIQUE(peer_id, zone_name),
		FOREIGN KEY(peer_id) REFERENCES PeerRegistry(peer_id) ON DELETE CASCADE
	)`,

	// SyncOperations tracks individual sync operations for audit and debugging.
	// Each row represents a sync operation (NS, DNSKEY, CDS, CSYNC, GLUE).
	"SyncOperations": `CREATE TABLE IF NOT EXISTS 'SyncOperations' (
		id                INTEGER PRIMARY KEY AUTOINCREMENT,
		correlation_id    TEXT NOT NULL UNIQUE,

		-- Operation details
		zone_name         TEXT NOT NULL,
		sync_type         TEXT NOT NULL,              -- NS, DNSKEY, GLUE, CDS, CSYNC
		direction         TEXT NOT NULL,              -- outbound, inbound

		-- Participants
		sender_id         TEXT NOT NULL,
		receiver_id       TEXT NOT NULL,

		-- Payload
		records           TEXT,                        -- JSON array of RR strings
		serial            INTEGER,                     -- SOA serial at time of sync

		-- Transport used
		transport         TEXT,                        -- api, dns
		encrypted         INTEGER DEFAULT 0,           -- 1 if payload was encrypted

		-- Status tracking
		status            TEXT DEFAULT 'pending',      -- pending, sent, received, confirmed, failed, rejected
		status_message    TEXT,

		-- Timestamps
		created_at        INTEGER NOT NULL,
		sent_at           INTEGER,
		received_at       INTEGER,
		confirmed_at      INTEGER,
		expires_at        INTEGER,                     -- For replay protection

		-- Error tracking
		retry_count       INTEGER DEFAULT 0,
		last_error        TEXT,
		last_error_at     INTEGER
	)`,

	// SyncConfirmations stores detailed confirmations for sync operations.
	// Linked to SyncOperations via correlation_id.
	"SyncConfirmations": `CREATE TABLE IF NOT EXISTS 'SyncConfirmations' (
		id                INTEGER PRIMARY KEY AUTOINCREMENT,
		correlation_id    TEXT NOT NULL,

		-- Confirmation source
		confirmer_id      TEXT NOT NULL,              -- Peer that sent the confirmation

		-- Status
		status            TEXT NOT NULL,              -- success, partial, failed, rejected
		message           TEXT,

		-- Detailed results (JSON)
		items_processed   TEXT,                        -- JSON: [{record_type, zone, status, details}]

		-- Proof (optional)
		signed_proof      TEXT,                        -- DNSSEC signatures from signer
		confirmer_signature TEXT,                      -- JWS signature from confirmer

		-- Timestamps
		confirmed_at      INTEGER NOT NULL,
		received_at       INTEGER NOT NULL,

		FOREIGN KEY(correlation_id) REFERENCES SyncOperations(correlation_id) ON DELETE CASCADE
	)`,

	// OperationalMetrics stores time-series metrics for monitoring.
	// Aggregated periodically for dashboard/alerting.
	"OperationalMetrics": `CREATE TABLE IF NOT EXISTS 'OperationalMetrics' (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		metric_time     INTEGER NOT NULL,             -- Unix timestamp (rounded to minute)
		peer_id         TEXT,                          -- NULL for aggregate metrics
		zone_name       TEXT,                          -- NULL for aggregate metrics

		-- Communication metrics
		syncs_sent      INTEGER DEFAULT 0,
		syncs_received  INTEGER DEFAULT 0,
		syncs_confirmed INTEGER DEFAULT 0,
		syncs_failed    INTEGER DEFAULT 0,

		-- Heartbeat metrics
		beats_sent      INTEGER DEFAULT 0,
		beats_received  INTEGER DEFAULT 0,
		beats_missed    INTEGER DEFAULT 0,

		-- Latency (milliseconds)
		avg_latency     INTEGER,
		max_latency     INTEGER,

		-- Transport breakdown
		api_operations  INTEGER DEFAULT 0,
		dns_operations  INTEGER DEFAULT 0,

		UNIQUE(metric_time, peer_id, zone_name)
	)`,

	// TransportEvents logs transport-related events for debugging.
	// Useful for diagnosing connectivity issues.
	"TransportEvents": `CREATE TABLE IF NOT EXISTS 'TransportEvents' (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		event_time      INTEGER NOT NULL,
		peer_id         TEXT,
		zone_name       TEXT,

		-- Event details
		event_type      TEXT NOT NULL,                -- hello, beat, sync, relocate, confirm, error, state_change
		transport       TEXT,                          -- api, dns
		direction       TEXT,                          -- outbound, inbound

		-- Result
		success         INTEGER,                       -- 1 for success, 0 for failure
		error_code      TEXT,
		error_message   TEXT,

		-- Additional context (JSON)
		context         TEXT,

		-- Auto-cleanup: events older than 7 days can be purged
		expires_at      INTEGER
	)`,

	// CombinerPendingEdits stores agent UPDATEs awaiting manual approval.
	// Created when a zone has the mp-manual-approval option.
	"CombinerPendingEdits": `CREATE TABLE IF NOT EXISTS 'CombinerPendingEdits' (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		edit_id         INTEGER NOT NULL UNIQUE,
		zone            TEXT NOT NULL,
		sender_id       TEXT NOT NULL,
		delivered_by    TEXT NOT NULL DEFAULT '',
		distribution_id TEXT NOT NULL,
		records_json    TEXT NOT NULL,
		received_at     INTEGER NOT NULL
	)`,

	// CombinerApprovedEdits records edits that were approved by the operator.
	"CombinerApprovedEdits": `CREATE TABLE IF NOT EXISTS 'CombinerApprovedEdits' (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		edit_id         INTEGER NOT NULL UNIQUE,
		zone            TEXT NOT NULL,
		sender_id       TEXT NOT NULL,
		distribution_id TEXT NOT NULL,
		records_json    TEXT NOT NULL,
		received_at     INTEGER NOT NULL,
		approved_at     INTEGER NOT NULL
	)`,

	// CombinerRejectedEdits records edits that were rejected by the operator.
	"CombinerRejectedEdits": `CREATE TABLE IF NOT EXISTS 'CombinerRejectedEdits' (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		edit_id         INTEGER NOT NULL UNIQUE,
		zone            TEXT NOT NULL,
		sender_id       TEXT NOT NULL,
		distribution_id TEXT NOT NULL,
		records_json    TEXT NOT NULL,
		received_at     INTEGER NOT NULL,
		rejected_at     INTEGER NOT NULL,
		reason          TEXT NOT NULL
	)`,
}

// HsyncIndexes defines indexes for the HSYNC tables.
var HsyncIndexes = []string{
	// PeerRegistry indexes
	`CREATE INDEX IF NOT EXISTS idx_peer_registry_state ON PeerRegistry(state)`,
	`CREATE INDEX IF NOT EXISTS idx_peer_registry_last_contact ON PeerRegistry(last_contact_at)`,

	// PeerZones indexes
	`CREATE INDEX IF NOT EXISTS idx_peer_zones_zone ON PeerZones(zone_name)`,
	`CREATE INDEX IF NOT EXISTS idx_peer_zones_peer ON PeerZones(peer_id)`,

	// SyncOperations indexes
	`CREATE INDEX IF NOT EXISTS idx_sync_ops_zone ON SyncOperations(zone_name)`,
	`CREATE INDEX IF NOT EXISTS idx_sync_ops_status ON SyncOperations(status)`,
	`CREATE INDEX IF NOT EXISTS idx_sync_ops_created ON SyncOperations(created_at)`,
	`CREATE INDEX IF NOT EXISTS idx_sync_ops_sender ON SyncOperations(sender_id)`,
	`CREATE INDEX IF NOT EXISTS idx_sync_ops_receiver ON SyncOperations(receiver_id)`,

	// SyncConfirmations indexes
	`CREATE INDEX IF NOT EXISTS idx_sync_confirm_correlation ON SyncConfirmations(correlation_id)`,
	`CREATE INDEX IF NOT EXISTS idx_sync_confirm_status ON SyncConfirmations(status)`,

	// OperationalMetrics indexes
	`CREATE INDEX IF NOT EXISTS idx_metrics_time ON OperationalMetrics(metric_time)`,
	`CREATE INDEX IF NOT EXISTS idx_metrics_peer ON OperationalMetrics(peer_id)`,

	// TransportEvents indexes
	`CREATE INDEX IF NOT EXISTS idx_events_time ON TransportEvents(event_time)`,
	`CREATE INDEX IF NOT EXISTS idx_events_peer ON TransportEvents(peer_id)`,
	`CREATE INDEX IF NOT EXISTS idx_events_type ON TransportEvents(event_type)`,
	`CREATE INDEX IF NOT EXISTS idx_events_expires ON TransportEvents(expires_at)`,

	// CombinerPendingEdits indexes
	`CREATE INDEX IF NOT EXISTS idx_pending_edits_zone ON CombinerPendingEdits(zone)`,

	// CombinerApprovedEdits indexes
	`CREATE INDEX IF NOT EXISTS idx_approved_edits_zone ON CombinerApprovedEdits(zone)`,

	// CombinerRejectedEdits indexes
	`CREATE INDEX IF NOT EXISTS idx_rejected_edits_zone ON CombinerRejectedEdits(zone)`,
}

// InitHsyncTables initializes the HSYNC tables in the KeyDB.
// Call this during application startup after KeyDB is created.
func (kdb *KeyDB) InitHsyncTables() error {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	// Create tables
	for name, schema := range HsyncTables {
		_, err := kdb.DB.Exec(schema)
		if err != nil {
			return fmt.Errorf("failed to create table %s: %w", name, err)
		}
	}

	// Create indexes
	for _, indexSQL := range HsyncIndexes {
		_, err := kdb.DB.Exec(indexSQL)
		if err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// InitCombinerEditTables initializes only the combiner edit tables.
// Call this on combiner startup — avoids creating agent-only HSYNC tables.
func (kdb *KeyDB) InitCombinerEditTables() error {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	combinerTables := []string{
		"CombinerPendingEdits",
		"CombinerApprovedEdits",
		"CombinerRejectedEdits",
	}

	for _, name := range combinerTables {
		schema, ok := HsyncTables[name]
		if !ok {
			return fmt.Errorf("table schema %q not found in HsyncTables", name)
		}
		if _, err := kdb.DB.Exec(schema); err != nil {
			return fmt.Errorf("failed to create table %s: %w", name, err)
		}
	}

	combinerIndexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_pending_edits_zone ON CombinerPendingEdits(zone)`,
		`CREATE INDEX IF NOT EXISTS idx_approved_edits_zone ON CombinerApprovedEdits(zone)`,
		`CREATE INDEX IF NOT EXISTS idx_rejected_edits_zone ON CombinerRejectedEdits(zone)`,
	}

	for _, indexSQL := range combinerIndexes {
		if _, err := kdb.DB.Exec(indexSQL); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

// CleanupExpiredData removes expired data from HSYNC tables.
// Should be called periodically (e.g., daily).
func (kdb *KeyDB) CleanupExpiredHsyncData() error {
	kdb.mu.Lock()
	defer kdb.mu.Unlock()

	now := time.Now().Unix()

	// Clean up expired transport events (older than 7 days)
	_, err := kdb.DB.Exec(`DELETE FROM TransportEvents WHERE expires_at < ?`, now)
	if err != nil {
		return fmt.Errorf("failed to cleanup transport events: %w", err)
	}

	// Clean up expired sync operations (older than 30 days)
	thirtyDaysAgo := now - (30 * 24 * 60 * 60)
	_, err = kdb.DB.Exec(`DELETE FROM SyncOperations WHERE created_at < ? AND status IN ('confirmed', 'failed', 'rejected')`, thirtyDaysAgo)
	if err != nil {
		return fmt.Errorf("failed to cleanup sync operations: %w", err)
	}

	// Clean up old metrics (older than 90 days)
	ninetyDaysAgo := now - (90 * 24 * 60 * 60)
	_, err = kdb.DB.Exec(`DELETE FROM OperationalMetrics WHERE metric_time < ?`, ninetyDaysAgo)
	if err != nil {
		return fmt.Errorf("failed to cleanup operational metrics: %w", err)
	}

	return nil
}
