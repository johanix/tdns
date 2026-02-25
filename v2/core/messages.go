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

// AgentMsgPost represents a generic agent message (sync, update, rfi, status).
// Used by both API and DNS transports.
type AgentMsgPost struct {
	MessageType  AgentMsg            // "sync", "update", "rfi", "status"
	MyIdentity   string              // Sender's identity
	YourIdentity string              // Recipient's identity
	Addresses    []string            `json:"addresses,omitempty"` // DEPRECATED: Use DNS discovery (SVCB records) instead
	Port         uint16              `json:"port,omitempty"`      // DEPRECATED: Use DNS discovery (URI scheme) instead
	TLSA         dns.TLSA            `json:"tlsa,omitempty"`      // DEPRECATED: Use DNS discovery (TLSA query) instead
	Zone         string              // Zone this message refers to (only one zone per message)
	Records      map[string][]string // Resource records grouped by owner name (owner → []RR strings)
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
type AgentKeystatePost struct {
	MessageType  AgentMsg  // AgentMsgKeystate
	MyIdentity   string    // Sender's identity
	YourIdentity string    // Recipient's identity
	Zone         string    // Zone this key belongs to (FQDN)
	KeyTag       uint16    // DNSKEY key tag
	Algorithm    uint8     // DNSKEY algorithm number
	Signal       string    // "propagated", "rejected", "removed", "published", "retired"
	Message      string    // Optional detail (e.g. rejection reason)
	Time         time.Time // Message timestamp
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
