package distrib

import "context"

// DistributionStore defines the interface for persisting distribution records.
//
// This interface abstracts the storage backend, allowing implementations
// to use SQLite, PostgreSQL, or other storage systems.
type DistributionStore interface {
	// Save persists a distribution record. If the record already exists
	// (by ID), it is updated.
	Save(ctx context.Context, record *DistributionRecord) error

	// Get retrieves a distribution record by its ID.
	// Returns nil, nil if the record is not found.
	Get(ctx context.Context, id string) (*DistributionRecord, error)

	// GetByDistributionID retrieves all records for a given distribution ID.
	GetByDistributionID(ctx context.Context, distributionID string) ([]*DistributionRecord, error)

	// List retrieves distribution records matching the filter criteria.
	List(ctx context.Context, filter DistributionFilter) ([]*DistributionRecord, error)

	// Delete removes a distribution record by ID.
	Delete(ctx context.Context, id string) error

	// UpdateStatus updates the status of a distribution record.
	UpdateStatus(ctx context.Context, id string, status DistributionState, reason string) error

	// MarkConfirmed marks a distribution as confirmed with the current timestamp.
	MarkConfirmed(ctx context.Context, id string) error

	// MarkExpired marks all pending distributions older than the given time as expired.
	// Returns the number of records updated.
	MarkExpired(ctx context.Context, olderThan int64) (int, error)
}

// SQL Schema for distribution records (reference implementation)
const SchemaSQL = `
-- Generic distribution records table
-- Used by KDC, HSYNC, and other applications
CREATE TABLE IF NOT EXISTS distribution_records (
    id TEXT PRIMARY KEY,
    distribution_id TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    receiver_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    content_type TEXT NOT NULL,
    encrypted_key BLOB,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    confirmed_at INTEGER,
    expires_at INTEGER,

    -- Domain-specific extension fields (nullable)
    zone_name TEXT,
    key_id TEXT,
    sequence INTEGER,
    total INTEGER
);

CREATE INDEX IF NOT EXISTS idx_distribution_records_status
    ON distribution_records(status);
CREATE INDEX IF NOT EXISTS idx_distribution_records_distribution_id
    ON distribution_records(distribution_id);
CREATE INDEX IF NOT EXISTS idx_distribution_records_receiver_id
    ON distribution_records(receiver_id);
`
