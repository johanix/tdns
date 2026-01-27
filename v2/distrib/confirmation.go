package distrib

import "time"

// ConfirmationRequest represents a request to confirm receipt of a distribution.
// This is sent from the receiver back to the sender (e.g., via DNS NOTIFY).
type ConfirmationRequest struct {
	// DistributionID identifies the distribution being confirmed
	DistributionID string `json:"distribution_id"`

	// ReceiverID identifies who is sending the confirmation
	ReceiverID string `json:"receiver_id"`

	// Status indicates the result of processing the distribution
	Status ConfirmationStatus `json:"status"`

	// Message contains optional details about the confirmation
	Message string `json:"message,omitempty"`

	// Timestamp is when the confirmation was generated
	Timestamp time.Time `json:"timestamp"`

	// Nonce is used for replay protection (echoes the distribution nonce)
	Nonce string `json:"nonce,omitempty"`

	// Signature is an optional signature over the confirmation
	Signature []byte `json:"signature,omitempty"`
}

// ConfirmationStatus represents the result of processing a distribution.
type ConfirmationStatus string

const (
	// ConfirmationSuccess indicates the distribution was successfully processed.
	ConfirmationSuccess ConfirmationStatus = "success"

	// ConfirmationPartial indicates partial success (some operations failed).
	ConfirmationPartial ConfirmationStatus = "partial"

	// ConfirmationFailed indicates the distribution could not be processed.
	ConfirmationFailed ConfirmationStatus = "failed"

	// ConfirmationRejected indicates the distribution was rejected (e.g., expired, invalid).
	ConfirmationRejected ConfirmationStatus = "rejected"
)

// ConfirmationResponse represents the sender's response to a confirmation request.
type ConfirmationResponse struct {
	// DistributionID echoes the distribution ID from the request
	DistributionID string `json:"distribution_id"`

	// Acknowledged indicates whether the confirmation was accepted
	Acknowledged bool `json:"acknowledged"`

	// Message contains optional details about the response
	Message string `json:"message,omitempty"`
}

// ConfirmationHandler defines the interface for handling confirmation callbacks.
// Implementations can perform application-specific actions when confirmations arrive.
type ConfirmationHandler interface {
	// HandleConfirmation processes an incoming confirmation request.
	// It should update the distribution state and perform any necessary side effects.
	HandleConfirmation(req *ConfirmationRequest) (*ConfirmationResponse, error)
}
