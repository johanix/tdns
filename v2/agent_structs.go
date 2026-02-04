/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"net/http"
	"sync"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

type AgentState uint8

const (
	AgentStateNeeded      AgentState = iota + 1 // Agent is required but we don't have complete information
	AgentStateKnown                             // We have complete information but haven't established communication
	AgentStateIntroduced                        // We got a nice reply to our HELLO
	AgentStateOperational                       // We got a nice reply to our (secure) BEAT
	AgentStateDegraded                          // Last successful heartbeat (in either direction) was more than 2x normal interval ago
	AgentStateInterrupted                       // Last successful heartbeat (in either direction) was more than 10x normal interval ago
	AgentStateError                             // We have tried to establish communication but failed
)

var AgentStateToString = map[AgentState]string{
	AgentStateNeeded:      "NEEDED",
	AgentStateKnown:       "KNOWN",
	AgentStateIntroduced:  "INTRODUCED",
	AgentStateOperational: "OPERATIONAL",
	AgentStateDegraded:    "DEGRADED",
	AgentStateInterrupted: "INTERRUPTED",
	AgentStateError:       "ERROR",
}

type AgentMsg uint8

const (
	AgentMsgHello AgentMsg = iota + 1
	AgentMsgBeat
	AgentMsgNotify
	AgentMsgRfi
	AgentMsgStatus
)

var AgentMsgToString = map[AgentMsg]string{
	AgentMsgHello:  "HELLO",
	AgentMsgBeat:   "BEAT",
	AgentMsgNotify: "NOTIFY", // local agent notifies remote agent about a change in local zone data
	AgentMsgRfi:    "RFI",
	AgentMsgStatus: "STATUS",
}

// Remote agent states: first occurence of a remote agent identity is when it appears in a
// HSYNC record for a zone where we also appear in the HSYNC RRset (i.e. we are both part of it).
// Then the remote agent becomes NEEDED. Data collection starts. When all data (URI, SVCB,
// TLSA, etc) has been collected (and verified) the state changes to KNOWN. At the tail end
// of LocateAgent(), when the state changes to KNOWN, a HELLO message is sent to the remote agent.
// If we get at positive response to that state changes to INTRODUCED and we're ready to start
// sending heartbeats. After the first positive response to a heartbeat that we sent is received
// the state finally changes to OPERATIONAL. Should subsequent heartbeats fail, the state changes
// to DEGRADED. If the heartbeats have failed for more than 10x the normal interval, the state
// changes to INTERRUPTED.

type Agent struct {
	Identity      AgentId
	mu            sync.RWMutex
	InitialZone   ZoneName
	ApiDetails    *AgentDetails
	DnsDetails    *AgentDetails
	ApiMethod     bool
	DnsMethod     bool
	Zones         map[ZoneName]bool
	Api           *AgentApi
	State         AgentState // Agent states: needed, known, hello-done, operational, error
	LastState     time.Time  // When state last changed
	ErrorMsg      string     // Error message if state is error
	DeferredTasks []DeferredAgentTask
}

type AgentDetails struct {
	Addrs        []string
	Port         uint16
	BaseUri      string
	UriRR        *dns.URI
	//	SvcbRR  *dns.SVCB
	Host         string    // the host part of the BaseUri
	KeyRR        *dns.KEY  // for DNS transport (legacy)
	JWKData      string    // JWK data (preferred for DNS transport)
	KeyAlgorithm string    // Key algorithm (e.g., "ES256")
	TlsaRR       *dns.TLSA // for HTTPS transport
	//	LastHB      time.Time
	Endpoint    string
	ContactInfo string // "none", "partial", "complete"
	//	Zones           map[ZoneName]bool // zones we share with this agent
	State           AgentState // "discovered", "contact_attempted", "connected", "failed"
	LatestError     string
	LatestErrorTime time.Time
	HelloTime       time.Time
	BeatInterval    uint32
	SentBeats       uint32
	ReceivedBeats   uint32
	LatestSBeat     time.Time
	LatestRBeat     time.Time
}

// AgentTask is a task that needs to be executed once the Precondition is met.
// A typical case is when we need to talk to a remote agent regarding zone transfer
// provisioning, but cannot do that until the remote agent is operational.
// The Precondition is checked every time a heartbeat is received from the remote agent.
type DeferredAgentTask struct {
	Precondition func() bool
	Action       func() (bool, error)
	Desc         string
}

type AgentApi struct {
	Name       string
	Client     *http.Client
	BaseUrl    string
	ApiKey     string // TODO: to remove, but we still need it for a while
	Authmethod string
	//	Verbose    bool
	//	Debug      bool

	// normal TDNS API client, we're using most of the tdns API client,
	ApiClient *ApiClient
}

type AgentRegistry struct {
	S                core.ConcurrentMap[AgentId, *Agent]
	RegularS         map[AgentId]*Agent
	RemoteAgents     map[ZoneName][]AgentId
	mu               sync.RWMutex    // protects remoteAgents
	LocalAgent       *LocalAgentConf // our own identity
	LocateInterval   int             // seconds to wait between locating agents (until success)
	helloContexts    map[AgentId]context.CancelFunc
	TransportManager *TransportManager // optional; when set, Hello/Beat/Sync use transport fallback (API → DNS)
}

type AgentBeatPost struct {
	MessageType    AgentMsg
	MyIdentity     AgentId
	YourIdentity   AgentId
	MyBeatInterval uint32   // intended, in seconds
	Zones          []string // Zones that we share with the remote agent
	Time           time.Time
}

type AgentBeatResponse struct {
	Status       string // ok | error | ...
	MyIdentity   AgentId
	YourIdentity AgentId
	Time         time.Time
	Client       string
	Msg          string
	Error        bool
	ErrorMsg     string
}
type AgentBeatReport struct {
	Time time.Time
	Beat AgentBeatPost
}

type AgentHelloPost struct {
	MessageType  AgentMsg
	Name         string
	MyIdentity   AgentId
	YourIdentity AgentId
	Addresses    []string
	Port         uint16
	TLSA         dns.TLSA
	Zone         ZoneName // in the /hello we only send one zone, the one that triggered the /hello
}

type AgentHelloResponse struct {
	Status       string // ok | error | ...
	MyIdentity   AgentId
	YourIdentity AgentId
	Time         time.Time
	// Client       string
	Msg      string
	Error    bool
	ErrorMsg string
}

// AgentMsg{Post,Response} are intended for agent-to-agent messaging
type AgentMsgPost struct {
	MessageType  AgentMsg // "NOTIFY", ...
	MyIdentity   AgentId
	YourIdentity AgentId
	Addresses    []string
	Port         uint16
	TLSA         dns.TLSA
	Zone         ZoneName // An AgentMsgPost should always only refer to one zone.
	// Data	     map[AgentId]map[uint16]RRset
	RRs []string // cannot send more structured format, as dns.RR cannot be json marshalled.
	// Zones []string
	Time    time.Time
	RfiType string
}

type AgentMsgPostPlus struct {
	AgentMsgPost
	Response chan *AgentMsgResponse
}

type AgentMsgResponse struct {
	Status string // ok | error | ...
	Time   time.Time
	// Client      string
	AgentId     AgentId
	Msg         string
	Zone        ZoneName
	RfiResponse map[AgentId]*RfiData
	Error       bool
	ErrorMsg    string
}

type RfiData struct {
	Status      string // ok | error | ...
	Time        time.Time
	Msg         string
	Error       bool
	ErrorMsg    string
	ZoneXfrSrcs []string
	ZoneXfrAuth []string
	ZoneXfrDsts []string
}

// AgentMgmt{Post,Response} are used in the mgmt API
type AgentMgmtPost struct {
	Command     string `json:"command"`
	MessageType AgentMsg
	Zone        ZoneName `json:"zone"`
	AgentId     AgentId  `json:"agent_id"`
	RRType      uint16
	RR          string
	RRs         []string
	AddedRRs    []string // for update-local-zonedata
	RemovedRRs  []string // for update-local-zonedata
	Upstream    AgentId
	Downstream  AgentId
	RfiType     string
	// Response    chan *AgentMgmtResponse
}

// also mgmt API, same response struct
type AgentDebugPost struct {
	Command string   `json:"command"`
	Zone    ZoneName `json:"zone"`
	AgentId AgentId  `json:"agent_id"`
	RRType  uint16
	RR      string
	Data    ZoneUpdate
}

type AgentMgmtResponse struct {
	Identity      AgentId
	Status        string
	Time          time.Time
	Agents        []*Agent // used for hsync-agentstatus
	ZoneAgentData *ZoneAgentData
	HsyncRRs      []string
	AgentConfig   LocalAgentConf
	RfiType       string
	RfiResponse   map[AgentId]*RfiData
	AgentRegistry *AgentRegistry
	// ZoneDataRepo  *ZoneDataRepo
	// ZoneDataRepo map[ZoneName]map[AgentId]*OwnerData
	ZoneDataRepo map[ZoneName]map[AgentId]map[uint16][]string
	Msg          string
	Error        bool
	ErrorMsg     string

	// HSYNC debug data (Phase 5)
	HsyncPeers         []*HsyncPeerInfo         `json:"hsync_peers,omitempty"`
	HsyncSyncOps       []*HsyncSyncOpInfo       `json:"hsync_sync_ops,omitempty"`
	HsyncConfirmations []*HsyncConfirmationInfo `json:"hsync_confirmations,omitempty"`
	HsyncEvents        []*HsyncTransportEvent   `json:"hsync_events,omitempty"`
	HsyncMetrics       *HsyncMetricsInfo        `json:"hsync_metrics,omitempty"`
}

// HsyncPeerInfo contains peer information for CLI display
type HsyncPeerInfo struct {
	PeerID             string    `json:"peer_id"`
	State              string    `json:"state"`
	StateReason        string    `json:"state_reason,omitempty"`
	DiscoverySource    string    `json:"discovery_source,omitempty"`
	DiscoveryTime      time.Time `json:"discovery_time,omitempty"`
	PreferredTransport string    `json:"preferred_transport"`
	APIHost            string    `json:"api_host,omitempty"`
	APIPort            int       `json:"api_port,omitempty"`
	APIAvailable       bool      `json:"api_available"`
	DNSHost            string    `json:"dns_host,omitempty"`
	DNSPort            int       `json:"dns_port,omitempty"`
	DNSAvailable       bool      `json:"dns_available"`
	LastContactAt      time.Time `json:"last_contact_at,omitempty"`
	LastHelloAt        time.Time `json:"last_hello_at,omitempty"`
	LastBeatAt         time.Time `json:"last_beat_at,omitempty"`
	BeatInterval       int       `json:"beat_interval"`
	BeatsSent          int64     `json:"beats_sent"`
	BeatsReceived      int64     `json:"beats_received"`
	FailedContacts     int       `json:"failed_contacts"`
}

// HsyncSyncOpInfo contains sync operation information for CLI display
type HsyncSyncOpInfo struct {
	CorrelationID string    `json:"correlation_id"`
	ZoneName      string    `json:"zone_name"`
	SyncType      string    `json:"sync_type"`
	Direction     string    `json:"direction"`
	SenderID      string    `json:"sender_id"`
	ReceiverID    string    `json:"receiver_id"`
	Status        string    `json:"status"`
	StatusMessage string    `json:"status_message,omitempty"`
	Transport     string    `json:"transport,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	SentAt        time.Time `json:"sent_at,omitempty"`
	ReceivedAt    time.Time `json:"received_at,omitempty"`
	ConfirmedAt   time.Time `json:"confirmed_at,omitempty"`
	RetryCount    int       `json:"retry_count"`
}

// HsyncConfirmationInfo contains confirmation information for CLI display
type HsyncConfirmationInfo struct {
	CorrelationID string    `json:"correlation_id"`
	ConfirmerID   string    `json:"confirmer_id"`
	Status        string    `json:"status"`
	Message       string    `json:"message,omitempty"`
	ConfirmedAt   time.Time `json:"confirmed_at"`
	ReceivedAt    time.Time `json:"received_at"`
}

// HsyncTransportEvent contains transport event information for CLI display
type HsyncTransportEvent struct {
	EventTime    time.Time `json:"event_time"`
	PeerID       string    `json:"peer_id,omitempty"`
	ZoneName     string    `json:"zone_name,omitempty"`
	EventType    string    `json:"event_type"`
	Transport    string    `json:"transport,omitempty"`
	Direction    string    `json:"direction,omitempty"`
	Success      bool      `json:"success"`
	ErrorCode    string    `json:"error_code,omitempty"`
	ErrorMessage string    `json:"error_message,omitempty"`
}

// HsyncMetricsInfo contains aggregated metrics for CLI display
type HsyncMetricsInfo struct {
	SyncsSent      int64 `json:"syncs_sent"`
	SyncsReceived  int64 `json:"syncs_received"`
	SyncsConfirmed int64 `json:"syncs_confirmed"`
	SyncsFailed    int64 `json:"syncs_failed"`
	BeatsSent      int64 `json:"beats_sent"`
	BeatsReceived  int64 `json:"beats_received"`
	BeatsMissed    int64 `json:"beats_missed"`
	AvgLatency     int64 `json:"avg_latency"`
	MaxLatency     int64 `json:"max_latency"`
	APIOperations  int64 `json:"api_operations"`
	DNSOperations  int64 `json:"dns_operations"`
}

// The ...Plus structs are always the original struct + a response channel
type AgentMgmtPostPlus struct {
	AgentMgmtPost
	Response chan *AgentMgmtResponse
}

type AgentMsgReport struct {
	Transport    string
	MessageType  AgentMsg
	Zone         ZoneName
	Identity     AgentId
	BeatInterval uint32
	Msg          interface{}
	RfiType      string
	Response     chan *SynchedDataResponse
}
