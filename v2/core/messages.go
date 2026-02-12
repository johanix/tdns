package core

import (
	"time"

	"github.com/miekg/dns"
)

// AgentMsg identifies the type of agent message.
// String type for human-readable JSON and easy extensibility.
type AgentMsg string

const (
	AgentMsgHello  AgentMsg = "hello"
	AgentMsgBeat   AgentMsg = "beat"
	AgentMsgNotify AgentMsg = "sync" // sync/notify: agent notifies about a change in zone data
	AgentMsgRfi    AgentMsg = "rfi"
	AgentMsgStatus AgentMsg = "status"
	AgentMsgPing   AgentMsg = "ping"
)

var AgentMsgToString = map[AgentMsg]string{
	AgentMsgHello:  "HELLO",
	AgentMsgBeat:   "BEAT",
	AgentMsgNotify: "SYNC",
	AgentMsgRfi:    "RFI",
	AgentMsgStatus: "STATUS",
	AgentMsgPing:   "PING",
}

// AgentHelloPost represents a hello handshake message.
// Used by both API and DNS transports.
type AgentHelloPost struct {
	MessageType  AgentMsg
	Name         string    `json:"name,omitempty"`      // DEPRECATED: Unused field
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

// AgentMsgPost represents a generic agent-to-agent message (sync, rfi, status).
// Used by both API and DNS transports.
type AgentMsgPost struct {
	MessageType  AgentMsg            // "sync", "rfi", "status"
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
