package distrib

import "time"

// DistributionState represents the lifecycle state of a distribution.
type DistributionState string

const (
	StatePending   DistributionState = "pending"
	StateConfirmed DistributionState = "confirmed"
	StateFailed    DistributionState = "failed"
	StateExpired   DistributionState = "expired"
)

// OperationType represents the type of distribution operation.
// Applications can define additional operation types beyond these base types.
type OperationType string

const (
	// OperationPing is a health check / nonce challenge-response.
	OperationPing OperationType = "ping"

	// OperationCustom indicates a domain-specific operation.
	// The actual operation is specified in OperationEntry.Operation.
	OperationCustom OperationType = "custom"
)

// OperationEntry represents a single operation in a distribution payload.
// This is the generic format for operations that can be encrypted and sent
// via the CHUNK transport.
//
// Domain-specific applications (like KDC) can embed this struct or use
// the Metadata field for additional operation-specific data.
type OperationEntry struct {
	// Operation is the operation type (e.g., "ping", "roll_key", "delete_key")
	Operation string `json:"operation"`

	// TargetID identifies the target of the operation (e.g., zone name, key ID)
	// The interpretation depends on the operation type.
	TargetID string `json:"target_id,omitempty"`

	// Payload contains operation-specific data
	// For encrypted operations, this may contain the actual content to deliver.
	Payload []byte `json:"payload,omitempty"`

	// Metadata contains additional operation-specific fields
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// DistributionMetadata contains metadata about a distribution that appears
// in the CHUNK manifest. This is used for tracking and confirmation purposes.
type DistributionMetadata struct {
	// DistributionID is a unique identifier for this distribution
	DistributionID string `json:"distribution_id"`

	// SenderID identifies the sender (e.g., KDC ID)
	SenderID string `json:"sender_id"`

	// ReceiverID identifies the intended receiver (e.g., node ID)
	ReceiverID string `json:"receiver_id"`

	// ContentType describes what kind of content is being distributed
	ContentType string `json:"content_type,omitempty"`

	// OperationCount is the number of operations in this distribution
	OperationCount int `json:"operation_count,omitempty"`

	// CreatedAt is when the distribution was created
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when the distribution expires (optional)
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// Extra contains additional application-specific metadata
	Extra map[string]interface{} `json:"extra,omitempty"`
}

// DistributionRecord represents a record of a distribution operation.
// This is the generic record that tracks distribution state in persistence.
//
// Domain-specific applications should embed this struct or create their own
// record type that maps to/from this generic type.
type DistributionRecord struct {
	// ID is the unique identifier for this distribution record
	ID string `json:"id"`

	// DistributionID is the logical distribution ID (may group multiple records)
	DistributionID string `json:"distribution_id"`

	// SenderID identifies who initiated the distribution
	SenderID string `json:"sender_id"`

	// ReceiverID identifies the target of the distribution
	ReceiverID string `json:"receiver_id"`

	// Operation is the operation type
	Operation string `json:"operation"`

	// ContentType describes what is being distributed
	ContentType string `json:"content_type"`

	// EncryptedPayload is the encrypted content (if applicable)
	EncryptedPayload []byte `json:"encrypted_payload,omitempty"`

	// Status is the current state of the distribution
	Status DistributionState `json:"status"`

	// CreatedAt is when the distribution was created
	CreatedAt time.Time `json:"created_at"`

	// ConfirmedAt is when the distribution was confirmed (nil if not confirmed)
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`

	// ExpiresAt is when the distribution expires (nil if no expiration)
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// FailReason contains the failure reason if Status is StateFailed
	FailReason string `json:"fail_reason,omitempty"`

	// Metadata contains additional application-specific data
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// DistributionSummary provides summary information about a distribution
// for listing and display purposes.
type DistributionSummary struct {
	DistributionID string   `json:"distribution_id"`
	SenderID       string   `json:"sender_id"`
	ReceiverIDs    []string `json:"receiver_ids"`
	ContentType    string   `json:"content_type"`
	Operations     []string `json:"operations"`
	CreatedAt      string   `json:"created_at"`
	CompletedAt    *string  `json:"completed_at,omitempty"`
	AllConfirmed   bool     `json:"all_confirmed"`
	ConfirmedCount int      `json:"confirmed_count"`
	PendingCount   int      `json:"pending_count"`
}
