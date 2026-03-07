package core

import (
	"time"

	"github.com/miekg/dns"
)

// AgentMsg identifies the type of agent message.
// String type for human-readable JSON and easy extensibility.
type AgentMsg string

const (
	AgentMsgHello    AgentMsg = "hello"
	AgentMsgBeat     AgentMsg = "beat"
	AgentMsgNotify   AgentMsg = "sync"   // sync: agent→agent zone data synchronization
	AgentMsgUpdate   AgentMsg = "update" // update: agent→combiner zone data contribution
	AgentMsgRfi      AgentMsg = "rfi"
	AgentMsgStatus   AgentMsg = "status"
	AgentMsgPing     AgentMsg = "ping"
	AgentMsgKeystate AgentMsg = "keystate"
	AgentMsgEdits    AgentMsg = "edits"
)

var AgentMsgToString = map[AgentMsg]string{
	AgentMsgHello:    "HELLO",
	AgentMsgBeat:     "BEAT",
	AgentMsgNotify:   "SYNC",
	AgentMsgUpdate:   "UPDATE",
	AgentMsgRfi:      "RFI",
	AgentMsgStatus:   "STATUS",
	AgentMsgPing:     "PING",
	AgentMsgKeystate: "KEYSTATE",
	AgentMsgEdits:    "EDITS",
}

// AgentHelloPost represents a hello handshake message.
// Used by both API and DNS transports.
type AgentHelloPost struct {
	MessageType  AgentMsg
	Name         string    `json:"name,omitempty"` // DEPRECATED: Unused field
	MyIdentity   string    // Agent identity (FQDN)
	YourIdentity string    // Recipient identity (FQDN)
	Addresses    []string  `json:"addresses,omitempty"` // DEPRECATED: Use DNS discovery (SVCB records) instead
	Port         uint16    `json:"port,omitempty"`      // DEPRECATED: Use DNS discovery (URI scheme) instead
	TLSA         dns.TLSA  `json:"tlsa,omitempty"`      // DEPRECATED: Use DNS discovery (TLSA query) instead
	Zone         string    // Zone that triggered this hello (only one zone per hello)
	Time         time.Time // Message timestamp
}

// AgentHelloResponse represents the response to a hello message.
type AgentHelloResponse struct {
	Status       string // ok | error
	MyIdentity   string // Responder's identity
	YourIdentity string // Original sender
	Time         time.Time
	Msg          string
	Error        bool
	ErrorMsg     string
}

// AgentBeatPost represents a heartbeat message.
// Used by both API and DNS transports.
type AgentBeatPost struct {
	MessageType    AgentMsg
	MyIdentity     string    // Sender's identity
	YourIdentity   string    // Recipient's identity
	MyBeatInterval uint32    // Intended beat interval in seconds
	Zones          []string  // Zones shared with the remote agent
	Time           time.Time // Message timestamp
}

// AgentBeatResponse represents the response to a heartbeat.
type AgentBeatResponse struct {
	Status       string // ok | error
	MyIdentity   string // Responder's identity
	YourIdentity string // Original sender
	Time         time.Time
	Client       string
	Msg          string
	Error        bool
	ErrorMsg     string
}

// RROperation describes an explicit operation on DNS records.
// When Operations is populated on a message, Records is ignored by the receiver.
// Operations use explicit semantics instead of overloading the DNS Class field.
type RROperation struct {
	Operation string   `json:"operation"`         // "add", "delete", "replace"
	RRtype    string   `json:"rrtype"`            // DNS RR type name (e.g. "DNSKEY", "NS", "A")
	Records   []string `json:"records,omitempty"` // RR strings in ClassINET text format
}

// AgentMsgPost represents a generic agent message (sync, update, rfi, status).
// Used by both API and DNS transports.
type AgentMsgPost struct {
	MessageType  AgentMsg            // "sync", "update", "rfi", "status"
	OriginatorID string              // Original author of the update
	YourIdentity string              // Recipient's identity
	Addresses    []string            `json:"addresses,omitempty"` // DEPRECATED: Use DNS discovery (SVCB records) instead
	Port         uint16              `json:"port,omitempty"`      // DEPRECATED: Use DNS discovery (URI scheme) instead
	TLSA         dns.TLSA            `json:"tlsa,omitempty"`      // DEPRECATED: Use DNS discovery (TLSA query) instead
	Zone         string              // Zone this message refers to (only one zone per message)
	Records      map[string][]string `json:"records,omitempty"`    // Resource records grouped by owner name (legacy: Class-overloaded)
	Operations   []RROperation       `json:"operations,omitempty"` // Explicit operations (takes precedence over Records)
	Time         time.Time           // Message timestamp
	RfiType      string              // Type of RFI request if MessageType is RFI
}

// AgentMsgResponse represents the response to an AgentMsgPost.
type AgentMsgResponse struct {
	Status      string // ok | error
	Time        time.Time
	AgentId     string
	Msg         string
	Zone        string
	RfiResponse map[string]*RfiData
	Error       bool
	ErrorMsg    string
}

// RfiData contains response data for RFI (Request For Information) messages.
type RfiData struct {
	Status      string // ok | error
	Time        time.Time
	Msg         string
	Error       bool
	ErrorMsg    string
	ZoneXfrSrcs []string
	ZoneXfrAuth []string
	ZoneXfrDsts []string
	AuditData   interface{} `json:"audit_data,omitempty"` // zone data repo snapshot for RFI AUDIT
}

// AgentPingPost represents a ping message for connectivity testing.
// Used by both API and DNS transports.
type AgentPingPost struct {
	MessageType  AgentMsg  // AgentMsgPing
	MyIdentity   string    // Sender's identity
	YourIdentity string    // Recipient's identity
	Nonce        string    // For round-trip verification
	Time         time.Time // Message timestamp
}

// AgentPingResponse represents the response to a ping message.
type AgentPingResponse struct {
	Status       string // ok | error
	MyIdentity   string // Responder's identity
	YourIdentity string // Original sender
	Nonce        string // Echo from request
	Time         time.Time
	Msg          string
	Error        bool
	ErrorMsg     string
}

// AgentKeystatePost represents a KEYSTATE message for key lifecycle signaling.
// Used for agent↔signer communication about DNSKEY propagation status.
// When Signal == "inventory", KeyInventory carries the complete key set for the zone.
type AgentKeystatePost struct {
	MessageType  AgentMsg            // AgentMsgKeystate
	MyIdentity   string              // Sender's identity
	YourIdentity string              // Recipient's identity
	Zone         string              // Zone this key belongs to (FQDN)
	KeyTag       uint16              // DNSKEY key tag (unused for inventory)
	Algorithm    uint8               // DNSKEY algorithm number (unused for inventory)
	Signal       string              // "propagated", "rejected", "removed", "published", "retired", "inventory"
	Message      string              // Optional detail (e.g. rejection reason)
	KeyInventory []KeyInventoryEntry // Complete key inventory (only when Signal == "inventory")
	Time         time.Time           // Message timestamp
}

// KeyInventoryEntry describes a single DNSKEY in a KEYSTATE inventory message.
type KeyInventoryEntry struct {
	KeyTag    uint16 `json:"key_tag"`
	Algorithm uint8  `json:"algorithm"`
	Flags     uint16 `json:"flags"`
	State     string `json:"state"` // "created","published","standby","active","retired","foreign"
	KeyRR     string `json:"keyrr"` // Full DNSKEY RR string (public key data)
}

// AgentKeystateResponse represents the response to a KEYSTATE message.
type AgentKeystateResponse struct {
	Status       string // ok | error
	MyIdentity   string // Responder's identity
	YourIdentity string // Original sender
	Zone         string // Echoed zone
	KeyTag       uint16 // Echoed key tag
	Signal       string // Echoed signal
	Time         time.Time
	Msg          string
	Error        bool
	ErrorMsg     string
}

// AgentEditsPost represents an EDITS message carrying an agent's current contributions
// from the combiner back to the requesting agent.
// Modeled on AgentKeystatePost. The combiner sends this in response to an RFI EDITS request.
type AgentEditsPost struct {
	MessageType  AgentMsg            // AgentMsgEdits
	MyIdentity   string              // Combiner identity
	YourIdentity string              // Requesting agent identity
	Zone         string              // Zone (FQDN)
	Records      map[string][]string // Agent's current contributions (owner → []RR strings)
	Message      string              // Optional status message
	Time         time.Time           // Timestamp
}
