/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Transport abstraction layer for multi-provider DNSSEC coordination (HSYNC).
 * This interface allows API mode and DNS mode to share business logic.
 */

package transport

import (
	"context"
	"crypto"
	"time"

	"github.com/johanix/tdns/v2/core"
)

// SyncType identifies what type of data is being synchronized.
type SyncType uint8

const (
	SyncTypeNS     SyncType = iota + 1 // NS record coordination
	SyncTypeDNSKEY                     // DNSKEY sharing for multi-signer
	SyncTypeGLUE                       // Glue record coordination
	SyncTypeCDS                        // CDS/CDNSKEY for key rollover
	SyncTypeCSYNC                      // CSYNC for delegation updates
)

func (s SyncType) String() string {
	switch s {
	case SyncTypeNS:
		return "NS"
	case SyncTypeDNSKEY:
		return "DNSKEY"
	case SyncTypeGLUE:
		return "GLUE"
	case SyncTypeCDS:
		return "CDS"
	case SyncTypeCSYNC:
		return "CSYNC"
	default:
		return "UNKNOWN"
	}
}

// ConfirmStatus indicates the result of processing a sync operation.
type ConfirmStatus uint8

const (
	ConfirmSuccess  ConfirmStatus = iota + 1 // Operation succeeded
	ConfirmPartial                           // Partial success
	ConfirmFailed                            // Operation failed
	ConfirmRejected                          // Rejected (invalid, expired)
	ConfirmPending                           // Received, processing in progress
)

func (c ConfirmStatus) String() string {
	switch c {
	case ConfirmSuccess:
		return "SUCCESS"
	case ConfirmPartial:
		return "PARTIAL"
	case ConfirmFailed:
		return "FAILED"
	case ConfirmRejected:
		return "REJECTED"
	case ConfirmPending:
		return "PENDING"
	default:
		return "UNKNOWN"
	}
}

// Transport defines the interface for agent-to-agent communication.
// Both API mode and DNS mode implement this interface, allowing the
// business logic in hsyncengine.go to be transport-agnostic.
type Transport interface {
	// Hello initiates or responds to a hello handshake with a peer.
	// This establishes identity and negotiates capabilities.
	Hello(ctx context.Context, peer *Peer, req *HelloRequest) (*HelloResponse, error)

	// Beat sends or responds to a heartbeat, maintaining the relationship.
	Beat(ctx context.Context, peer *Peer, req *BeatRequest) (*BeatResponse, error)

	// Sync sends or responds to a data synchronization request.
	// All sync operations are zone-specific.
	Sync(ctx context.Context, peer *Peer, req *SyncRequest) (*SyncResponse, error)

	// Relocate requests the peer to use a different address for future communication.
	// Used for DDoS mitigation after discovery is complete.
	Relocate(ctx context.Context, peer *Peer, req *RelocateRequest) (*RelocateResponse, error)

	// Confirm sends acknowledgment of a received sync operation.
	Confirm(ctx context.Context, peer *Peer, req *ConfirmRequest) error

	// Ping sends a lightweight liveness probe; responder echoes the nonce.
	Ping(ctx context.Context, peer *Peer, req *PingRequest) (*PingResponse, error)

	// Name returns the transport name (e.g., "API", "DNS") for logging.
	Name() string
}

// HelloRequest represents a hello handshake initiation.
type HelloRequest struct {
	SenderID     string           // Identity of the sender (provider name or agent ID)
	Capabilities []string         // List of supported capabilities
	SharedZones  []string         // Zones we believe we share with this peer
	PublicKey    crypto.PublicKey // Long-term public key for identity
	KeyType      string           // Key algorithm (e.g., "Ed25519", "ECDSA-P256")
	Timestamp    time.Time        // Request timestamp
	Nonce        string           // For replay protection
}

// HelloResponse represents a hello handshake response.
type HelloResponse struct {
	ResponderID  string           // Identity of the responder
	Capabilities []string         // Responder's supported capabilities
	SharedZones  []string         // Confirmed shared zones
	PublicKey    crypto.PublicKey // Responder's long-term public key
	KeyType      string           // Key algorithm
	Timestamp    time.Time        // Response timestamp
	Nonce        string           // Echoed nonce from request
	Accepted     bool             // Whether the hello was accepted
	RejectReason string           // If not accepted, why
}

// BeatRequest represents a heartbeat message.
type BeatRequest struct {
	SenderID  string    // Identity of the sender
	Timestamp time.Time // Current timestamp
	Sequence  uint64    // Monotonic sequence number
	State     string    // Sender's current state
}

// BeatResponse represents a heartbeat acknowledgment.
type BeatResponse struct {
	ResponderID string    // Identity of the responder
	Timestamp   time.Time // Response timestamp
	Sequence    uint64    // Echoed sequence number
	State       string    // Responder's current state
	Ack         bool      // Whether the beat was acknowledged
}

// SyncRequest represents a data synchronization request.
// Important: All sync operations are zone-specific. An agent can only
// make statements about zones and data under its own control.
type SyncRequest struct {
	SenderID       string                   // Identity of the sender
	Zone           string                   // The zone this sync applies to (FQDN)
	SyncType       SyncType                 // What type of data is being synced
	Records        map[string][]string      // RRs grouped by owner name (legacy: Class-overloaded)
	Operations     []core.RROperation       // Explicit operations (takes precedence over Records)
	Timestamp      time.Time                // When this data was generated
	Serial         uint32                   // Zone serial at time of sync
	DistributionID string                   // For tracking confirmations
	Nonce          string                   // Unique nonce for replay protection
	Signature      []byte                   // Optional signature over the request
	MessageType    string                   // "sync" (agent→agent), "update" (agent→combiner), "rfi" (RFI)
	RfiType        string                   // For RFI messages: "SYNC", "AUDIT", "CONFIG"
	RfiSubtype     string                   // Subtype within an RFI type (e.g. "upstream", "sig0key" for CONFIG)
	ZoneClass      string                   // "mp" (default) or "provider"
	Publish        *core.PublishInstruction // KEY/CDS publication instruction for combiner
}

// SyncResponse represents a synchronization response.
type SyncResponse struct {
	ResponderID    string            // Identity of the responder
	Zone           string            // Echoed zone name
	DistributionID string            // Echoed correlation ID
	Status         ConfirmStatus     // Result of processing
	Message        string            // Optional status message
	Timestamp      time.Time         // Response timestamp
	AppliedRecords []string          // RRs accepted by recipient (additions)
	RemovedRecords []string          // RRs confirmed removed by recipient (deletions)
	RejectedItems  []RejectedItemDTO // RRs rejected with reasons
	Truncated      bool              // True if applied/removed_records was dropped for size
}

// RelocateRequest asks a peer to use a different address.
// This is used for DDoS mitigation: after discovery via well-known
// addresses, agents can relocate to private addresses.
type RelocateRequest struct {
	SenderID   string    // Identity of the sender
	NewAddress Address   // The new address to use
	Reason     string    // Why we're relocating (e.g., "ddos-mitigation")
	ValidUntil time.Time // When this address should be refreshed
	Signature  []byte    // Signature proving we control the new address
}

// RelocateResponse acknowledges a relocation request.
type RelocateResponse struct {
	ResponderID string    // Identity of the responder
	Accepted    bool      // Whether relocation was accepted
	Message     string    // Optional message
	Timestamp   time.Time // Response timestamp
}

// PingRequest is a lightweight liveness probe.
type PingRequest struct {
	SenderID  string    // Identity of the sender
	Nonce     string    // Random nonce to be echoed in response
	Timestamp time.Time // Request timestamp
}

// PingResponse is the response to a ping; echoes the nonce on success.
type PingResponse struct {
	ResponderID string    // Identity of the responder
	Nonce       string    // Echoed nonce from request
	OK          bool      // True if responder acknowledged
	Timestamp   time.Time // Response timestamp
}

// KeyInventoryEntry describes a single DNSKEY in a KEYSTATE inventory message.
// Used when Signal == "inventory" to carry the complete set of keys for a zone.
type KeyInventoryEntry struct {
	KeyTag    uint16 `json:"key_tag"`
	Algorithm uint8  `json:"algorithm"`
	Flags     uint16 `json:"flags"`
	State     string `json:"state"` // "created","published","standby","active","retired","foreign"
	KeyRR     string `json:"keyrr"` // Full DNSKEY RR string (public key data)
}

// KeystateRequest carries a key lifecycle signal between agent and signer.
// Direction: Agent→Signer (propagated, rejected, removed) or Signer→Agent (published, retired, inventory).
// When Signal == "inventory", KeyInventory carries the complete key set for the zone.
type KeystateRequest struct {
	SenderID     string              // Identity of the sender
	Zone         string              // Zone this key belongs to (FQDN)
	KeyTag       uint16              // DNSKEY key tag (unused for inventory)
	Algorithm    uint8               // DNSKEY algorithm number (unused for inventory)
	Signal       string              // "propagated", "rejected", "removed", "published", "retired", "inventory"
	Message      string              // Optional detail (e.g. rejection reason)
	KeyInventory []KeyInventoryEntry // Complete key inventory (only when Signal == "inventory")
	Timestamp    time.Time           // Request timestamp
}

// KeystateResponse acknowledges a KEYSTATE signal.
type KeystateResponse struct {
	ResponderID string    // Identity of the responder
	Zone        string    // Echoed zone name
	KeyTag      uint16    // Echoed key tag
	Signal      string    // Echoed signal
	Accepted    bool      // Whether the signal was accepted
	Message     string    // Optional status message
	Timestamp   time.Time // Response timestamp
}

// EditsRequest carries an agent's current contributions from the combiner back to the agent.
// Modeled on KeystateRequest. Sent by the combiner in response to an RFI EDITS.
type EditsRequest struct {
	SenderID     string                         // Combiner identity
	Zone         string                         // Zone (FQDN)
	AgentRecords map[string]map[string][]string // All agents' contributions (agentID → owner → []RR strings)
	Message      string                         // Optional status
	Timestamp    time.Time
}

// EditsResponse acknowledges receipt of an EDITS message.
type EditsResponse struct {
	ResponderID string    // Identity of the responder
	Zone        string    // Echoed zone name
	Accepted    bool      // Whether the message was accepted
	Message     string    // Optional status message
	Timestamp   time.Time // Response timestamp
}

// ConfigRequest carries config data from a peer agent back to the requester.
// Sent by the receiving agent in response to an RFI CONFIG.
type ConfigRequest struct {
	SenderID   string            // Sender identity
	Zone       string            // Zone (FQDN)
	Subtype    string            // Config subtype: "upstream", "downstream", "sig0key"
	ConfigData map[string]string // Key-value config data
	Message    string            // Optional status
	Timestamp  time.Time
}

// ConfigResponse acknowledges receipt of a CONFIG message.
type ConfigResponse struct {
	ResponderID string
	Zone        string
	Accepted    bool
	Message     string
	Timestamp   time.Time
}

// AuditRequest carries audit data from a peer agent back to the requester.
// Sent by the receiving agent in response to an RFI AUDIT.
type AuditRequest struct {
	SenderID  string      // Sender identity
	Zone      string      // Zone (FQDN)
	AuditData interface{} // Zone data repo snapshot (placeholder)
	Message   string      // Optional status
	Timestamp time.Time
}

// AuditResponse acknowledges receipt of an AUDIT message.
type AuditResponse struct {
	ResponderID string
	Zone        string
	Accepted    bool
	Message     string
	Timestamp   time.Time
}

// ConfirmRequest confirms receipt and processing of a sync operation.
type ConfirmRequest struct {
	SenderID       string            // Identity of the sender (who is confirming)
	Zone           string            // The zone the sync was for
	DistributionID string            // The correlation ID from the sync
	Nonce          string            // Echoed nonce from the original sync request
	Status         ConfirmStatus     // Result of processing
	Message        string            // Optional details
	AppliedRecords []string          // RRs accepted (additions)
	RemovedRecords []string          // RRs confirmed removed (deletions)
	RejectedItems  []RejectedItemDTO // RRs rejected with reasons
	Truncated      bool              // True if applied/removed_records was dropped for size
	Timestamp      time.Time         // Confirmation timestamp
	Signature      []byte            // Optional signature
}

// Address represents a network address that can be used for communication.
type Address struct {
	Host      string // Hostname or IP address
	Port      uint16 // Port number
	Transport string // Transport protocol ("tcp", "udp", "https")
	Path      string // Path for HTTP-based transports
}

func (a Address) String() string {
	if a.Path != "" {
		return a.Transport + "://" + a.Host + ":" + string(rune(a.Port)) + a.Path
	}
	return a.Host + ":" + string(rune(a.Port))
}

// TransportError represents an error from the transport layer.
type TransportError struct {
	Op        string // Operation that failed
	Transport string // Transport that failed
	PeerID    string // Peer involved
	Err       error  // Underlying error
	Retryable bool   // Whether the operation can be retried
}

func (e *TransportError) Error() string {
	if e.PeerID != "" {
		return e.Transport + " " + e.Op + " to " + e.PeerID + ": " + e.Err.Error()
	}
	return e.Transport + " " + e.Op + ": " + e.Err.Error()
}

func (e *TransportError) Unwrap() error {
	return e.Err
}

// NewTransportError creates a new TransportError.
func NewTransportError(transport, op, peerID string, err error, retryable bool) *TransportError {
	return &TransportError{
		Op:        op,
		Transport: transport,
		PeerID:    peerID,
		Err:       err,
		Retryable: retryable,
	}
}
