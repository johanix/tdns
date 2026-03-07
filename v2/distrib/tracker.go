package distrib

import (
	"context"
	"time"
)

// DistributionTracker defines the interface for managing distribution lifecycle.
//
// Implementations of this interface handle the state transitions of distributions
// from creation through confirmation or failure.
type DistributionTracker interface {
	// CreateDistribution creates a new distribution record in pending state.
	CreateDistribution(ctx context.Context, dist *DistributionRecord) error

	// ConfirmDistribution marks a distribution as confirmed.
	ConfirmDistribution(ctx context.Context, distributionID string) error

	// FailDistribution marks a distribution as failed with a reason.
	FailDistribution(ctx context.Context, distributionID string, reason string) error

	// GetDistribution retrieves a distribution by ID.
	GetDistribution(ctx context.Context, distributionID string) (*DistributionRecord, error)

	// ListPendingDistributions returns all pending distributions for a receiver.
	// If receiverID is empty, returns all pending distributions.
	ListPendingDistributions(ctx context.Context, receiverID string) ([]*DistributionRecord, error)

	// ListDistributions returns distributions matching the given filter.
	ListDistributions(ctx context.Context, filter DistributionFilter) ([]*DistributionRecord, error)

	// ExpireOldDistributions marks pending distributions older than the given duration as expired.
	// Returns the number of distributions expired.
	ExpireOldDistributions(ctx context.Context, olderThan time.Duration) (int, error)
}

// DistributionFilter specifies criteria for filtering distributions.
type DistributionFilter struct {
	// DistributionID filters by distribution ID (exact match)
	DistributionID string

	// SenderID filters by sender ID
	SenderID string

	// ReceiverID filters by receiver ID
	ReceiverID string

	// Status filters by distribution state
	Status *DistributionState

	// Operation filters by operation type
	Operation string

	// CreatedAfter filters for distributions created after this time
	CreatedAfter *time.Time

	// CreatedBefore filters for distributions created before this time
	CreatedBefore *time.Time

	// Limit limits the number of results (0 = no limit)
	Limit int

	// Offset skips the first N results
	Offset int
}
