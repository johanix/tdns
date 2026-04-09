/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 *
 * MP types: type definitions used by multi-provider code.
 * Relocated from legacy_* files to enable incremental removal
 * of MP functions from tdns.
 */
package tdns

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/johanix/tdns-transport/v2/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// --- from legacy_agent_structs.go ---

type AgentState uint8

const (
	AgentStateNeeded      AgentState = iota + 1 // Agent is required but we don't have complete information
	AgentStateKnown                             // We have complete information but haven't established communication
	AgentStateIntroduced                        // We got a nice reply to our HELLO
	AgentStateOperational                       // We got a nice reply to our (secure) BEAT
	AgentStateLegacy                            // Established relationship but no shared zones (previously OPERATIONAL)
	AgentStateDegraded                          // Last successful heartbeat (in either direction) was more than 2x normal interval ago
	AgentStateInterrupted                       // Last successful heartbeat (in either direction) was more than 10x normal interval ago
	AgentStateError                             // We have tried to establish communication but failed
)

var AgentStateToString = map[AgentState]string{
	AgentStateNeeded:      "NEEDED",
	AgentStateKnown:       "KNOWN",
	AgentStateIntroduced:  "INTRODUCED",
	AgentStateOperational: "OPERATIONAL",
	AgentStateLegacy:      "LEGACY",
	AgentStateDegraded:    "DEGRADED",
	AgentStateInterrupted: "INTERRUPTED",
	AgentStateError:       "ERROR",
}

// AgentMsg and related constants are defined in core package to avoid circular dependencies
type AgentMsg = core.AgentMsg

const (
	AgentMsgHello  = core.AgentMsgHello
	AgentMsgBeat   = core.AgentMsgBeat
	AgentMsgNotify = core.AgentMsgNotify
	AgentMsgRfi    = core.AgentMsgRfi
	AgentMsgStatus = core.AgentMsgStatus
	AgentMsgPing   = core.AgentMsgPing
	AgentMsgEdits  = core.AgentMsgEdits
)

var AgentMsgToString = core.AgentMsgToString

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
	Mu            sync.RWMutex
	InitialZone   ZoneName
	ApiDetails    *AgentDetails
	DnsDetails    *AgentDetails
	ApiMethod     bool
	DnsMethod     bool
	IsInfraPeer   bool // true for combiner/signer — handled by StartInfraBeatLoop, not SendHeartbeats
	Zones         map[ZoneName]bool
	Api           *AgentApi
	State         AgentState // Agent states: needed, known, hello-done, operational, error
	LastState     time.Time  // When state last changed
	ErrorMsg      string     // Error message if state is error
	DeferredTasks []DeferredAgentTask
}

type AgentDetails struct {
	Addrs   []string
	Port    uint16
	BaseUri string
	UriRR   *dns.URI
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
	State             AgentState // "discovered", "contact_attempted", "connected", "failed"
	LatestError       string
	LatestErrorTime   time.Time
	DiscoveryFailures uint32 // consecutive discovery failures (for IMR cache flush)
	HelloTime         time.Time
	LastContactTime   time.Time // Last contact of any type (Hello, Beat, Ping, Sync, etc.)
	BeatInterval      uint32
	SentBeats         uint32
	ReceivedBeats     uint32
	LatestSBeat       time.Time
	LatestRBeat       time.Time
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
	S                     core.ConcurrentMap[AgentId, *Agent]
	RegularS              map[AgentId]*Agent
	RemoteAgents          map[ZoneName][]AgentId
	mu                    sync.RWMutex       // protects remoteAgents
	LocalAgent            *MultiProviderConf // our own identity
	LocateInterval        int                // seconds to wait between locating agents (until success)
	helloContexts         map[AgentId]context.CancelFunc
	TransportManager      *transport.TransportManager // Generic transport (Router, PeerRegistry, etc.)
	MPTransport           *MPTransportBridge          // MP transport bridge (authorization, discovery, enqueue, beats, hellos)
	LeaderElectionManager *LeaderElectionManager      // optional; when set, election messages are processed
	ProviderGroupManager  *ProviderGroupManager       // optional; manages provider group computation
	GossipStateTable      *GossipStateTable           // optional; gossip protocol state
}

// AgentBeatPost is defined in core package to avoid circular dependencies.
// We keep a wrapper type here that uses AgentId instead of string for backward compatibility.
type AgentBeatPost struct {
	MessageType    AgentMsg
	MyIdentity     AgentId
	YourIdentity   AgentId
	MyBeatInterval uint32   // intended, in seconds
	Zones          []string // Zones that we share with the remote agent
	Time           time.Time
	Gossip         []GossipMessage `json:"Gossip,omitempty"`
}

// AgentBeatResponse is defined in core package to avoid circular dependencies.
// We keep a wrapper type here that uses AgentId instead of string for backward compatibility.
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

// AgentHelloPost is defined in core package to avoid circular dependencies.
// We keep a wrapper type here that uses AgentId/ZoneName instead of string for backward compatibility.
type AgentHelloPost struct {
	MessageType  AgentMsg
	Name         string `json:"name,omitempty"` // DEPRECATED: Unused field
	MyIdentity   AgentId
	YourIdentity AgentId
	Addresses    []string  `json:"addresses,omitempty"` // DEPRECATED: Use DNS discovery (SVCB records) instead
	Port         uint16    `json:"port,omitempty"`      // DEPRECATED: Use DNS discovery (URI scheme) instead
	TLSA         dns.TLSA  `json:"tlsa,omitempty"`      // DEPRECATED: Use DNS discovery (TLSA query) instead
	Zone         ZoneName  // in the /hello we only send one zone, the one that triggered the /hello
	Time         time.Time // message timestamp
}

// AgentHelloResponse is defined in core package to avoid circular dependencies.
// We keep a wrapper type here that uses AgentId instead of string for backward compatibility.
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

// AgentMsgPost is defined in core package to avoid circular dependencies.
// We keep a wrapper type here that uses AgentId/ZoneName instead of string for backward compatibility.
// AgentMsg{Post,Response} are intended for agent-to-agent messaging
type AgentMsgPost struct {
	MessageType    AgentMsg // "sync", "update", "rfi", "status"
	OriginatorID   AgentId  // Original author of the update
	DeliveredBy    AgentId  // Transport-level sender (who delivered this message to us)
	YourIdentity   AgentId
	Addresses      []string            `json:"addresses,omitempty"` // DEPRECATED: Use DNS discovery (SVCB records) instead
	Port           uint16              `json:"port,omitempty"`      // DEPRECATED: Use DNS discovery (URI scheme) instead
	TLSA           dns.TLSA            `json:"tlsa,omitempty"`      // DEPRECATED: Use DNS discovery (TLSA query) instead
	Zone           ZoneName            // An AgentMsgPost should always only refer to one zone.
	Records        map[string][]string // Resource records grouped by owner name (legacy: Class-overloaded)
	Operations     []core.RROperation  // Explicit operations (takes precedence over Records)
	Time           time.Time
	RfiType        string
	RfiSubtype     string
	DistributionID string                   // Originating distribution ID from the sending agent
	Nonce          string                   // Nonce from the incoming sync/update message (for confirmation echo)
	ZoneClass      string                   // "mp" (default) or "provider"
	Publish        *core.PublishInstruction // KEY/CDS publication instruction for combiner
}

type AgentMsgPostPlus struct {
	AgentMsgPost
	Response chan *AgentMsgResponse
}

// AgentMsgResponse is defined in core package to avoid circular dependencies.
// We keep a wrapper type here that uses AgentId/ZoneName instead of string for backward compatibility.
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

// RfiData is defined in core package to avoid circular dependencies.
type RfiData struct {
	Status      string // ok | error | ...
	Time        time.Time
	Msg         string
	Error       bool
	ErrorMsg    string
	ZoneXfrSrcs []string
	ZoneXfrAuth []string
	ZoneXfrDsts []string
	AuditData   map[ZoneName]map[AgentId]map[uint16][]TrackedRRInfo `json:"audit_data,omitempty"`
	ConfigData  map[string]string                                   `json:"config_data,omitempty"` // key-value config data for RFI CONFIG
}

// AgentPingPost is defined in core package to avoid circular dependencies.
// We keep a wrapper type here that uses AgentId instead of string for backward compatibility.
// AgentPingPost is used for ping operations (connectivity testing)
type AgentPingPost struct {
	MessageType  AgentMsg  // AgentMsgPing
	MyIdentity   AgentId   // sender's identity
	YourIdentity AgentId   // recipient's identity
	Nonce        string    // for round-trip verification
	Time         time.Time // message timestamp
}

// AgentPingResponse is defined in core package to avoid circular dependencies.
// We keep a wrapper type here that uses AgentId instead of string for backward compatibility.
// AgentPingResponse is the response to a ping operation
type AgentPingResponse struct {
	Status       string  // "ok" | "error"
	MyIdentity   AgentId // responder's identity
	YourIdentity AgentId // original sender
	Nonce        string  // echo from request
	Time         time.Time
	Msg          string
	Error        bool
	ErrorMsg     string
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
	RfiSubtype  string
	Data        map[string]interface{} `json:"data,omitempty"` // Generic data field for custom parameters
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

// KeystateInfo reports the health of the KEYSTATE exchange with the signer for a zone.
type KeystateInfo struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

type AgentMgmtResponse struct {
	Identity       AgentId
	Status         string
	Time           time.Time
	Agents         []*Agent // used for hsync-agentstatus
	ZoneAgentData  *ZoneAgentData
	HsyncRRs       []string
	AgentConfig    MultiProviderConf
	RfiType        string
	RfiResponse    map[AgentId]*RfiData
	AgentRegistry  *AgentRegistry
	ZoneDataRepo   map[ZoneName]map[AgentId]map[uint16][]TrackedRRInfo
	KeystateStatus map[ZoneName]KeystateInfo `json:"keystate_status,omitempty"`
	Msg            string
	Error          bool
	ErrorMsg       string
	Data           interface{} `json:"data,omitempty"` // Generic data field for custom responses

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
	DistributionID string    `json:"distribution_id"`
	ZoneName       string    `json:"zone_name"`
	SyncType       string    `json:"sync_type"`
	Direction      string    `json:"direction"`
	SenderID       string    `json:"sender_id"`
	ReceiverID     string    `json:"receiver_id"`
	Status         string    `json:"status"`
	StatusMessage  string    `json:"status_message,omitempty"`
	Transport      string    `json:"transport,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	SentAt         time.Time `json:"sent_at,omitempty"`
	ReceivedAt     time.Time `json:"received_at,omitempty"`
	ConfirmedAt    time.Time `json:"confirmed_at,omitempty"`
	RetryCount     int       `json:"retry_count"`
}

// HsyncConfirmationInfo contains confirmation information for CLI display
type HsyncConfirmationInfo struct {
	DistributionID string    `json:"distribution_id"`
	ConfirmerID    string    `json:"confirmer_id"`
	Status         string    `json:"status"`
	Message        string    `json:"message,omitempty"`
	ConfirmedAt    time.Time `json:"confirmed_at"`
	ReceivedAt     time.Time `json:"received_at"`
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
	Transport      string
	MessageType    AgentMsg
	Zone           ZoneName
	Identity       AgentId
	BeatInterval   uint32
	Msg            interface{}
	RfiType        string
	DistributionID string
	Response       chan *SynchedDataResponse
}

// --- from legacy_syncheddataengine.go ---

type SynchedDataUpdate struct {
	Zone              ZoneName
	AgentId           AgentId
	UpdateType        string // "local" or "remote"
	Update            *ZoneUpdate
	OriginatingDistID string   // Distribution ID from the originating agent (for remote updates)
	Force             bool     // Bypass dedup check (always send even if RR already present)
	SkipCombiner      bool     // Don't send to combiner (e.g. local DNSKEY changes — signer adds its own)
	DnskeyKeyTags     []uint16 // Key tags for DNSKEY propagation tracking (mpdist flow)
	// Response chan *SynchedDataResponse
	Response chan *AgentMsgResponse
}

type SynchedDataResponse struct {
	Zone    ZoneName
	AgentId AgentId
	Time    time.Time
	Msg     string
	// RfiType     string
	RfiResponse RfiData
	Error       bool
	ErrorMsg    string
}

type SynchedDataCmd struct {
	Cmd         string
	Zone        ZoneName
	TargetAgent AgentId // For "resync-targeted": send only to this agent
	Response    chan *SynchedDataCmdResponse
}

type SynchedDataCmdResponse struct {
	Cmd      string
	Msg      string
	Error    bool
	ErrorMsg string
	Zone     ZoneName
	ZDR      map[ZoneName]map[AgentId]map[uint16][]TrackedRRInfo
}

type ZoneUpdate struct {
	Zone       ZoneName
	AgentId    AgentId
	ZoneClass  string                   // "mp" (default) or "provider"
	RRsets     map[uint16]core.RRset    // remote updates are only per RRset (i.e. full replace)
	RRs        []dns.RR                 // local updates can be per RR
	Operations []core.RROperation       // explicit operations (takes precedence over RRsets/RRs)
	Publish    *core.PublishInstruction // KEY/CDS publication instruction for combiner
}

type AgentId string

type ZoneName string

type ZoneDataRepo struct {
	// Repo map[ZoneName]ZoneRepo // map[zonename]ZoneRepo
	Repo core.ConcurrentMap[ZoneName, *AgentRepo] // map[zonename]ZoneRepo

	// Tracking stores per-RR lifecycle state parallel to Repo.
	// Accessed only from the SynchedDataEngine goroutine.
	// Structure: zone → agentId → rrtype → TrackedRRset
	Tracking map[ZoneName]map[AgentId]map[uint16]*TrackedRRset

	// mu protects PendingRemoteConfirms.
	mu sync.Mutex

	// PendingRemoteConfirms maps a combiner distID (generated by this remote agent)
	// to the originating agent's distID and sender identity. When the combiner confirms
	// the remote agent's enqueue, this mapping is used to send the final confirmation
	// back to the originating agent with the correct originating distID.
	PendingRemoteConfirms map[string]*PendingRemoteConfirmation
}

// PendingRemoteConfirmation tracks the relationship between a combiner distID
// (generated locally on the remote agent) and the originating agent's distID/identity.
type PendingRemoteConfirmation struct {
	OriginatingDistID string
	OriginatingSender string
	Zone              ZoneName
	CreatedAt         time.Time
}

// RemoteConfirmationDetail carries per-RR confirmation detail to send back
// to the originating agent after the remote agent's combiner confirms.
type RemoteConfirmationDetail struct {
	OriginatingDistID string
	OriginatingSender string
	Zone              ZoneName
	Status            string
	Message           string
	AppliedRecords    []string
	RemovedRecords    []string
	RejectedItems     []RejectedItemInfo
	Truncated         bool
}

type AgentRepo struct {
	// Data map[AgentId]OwnerData // map[agentid]data
	Data core.ConcurrentMap[AgentId, *OwnerData] // map[agentid]data
}

// RRState represents the lifecycle state of a tracked RR.
type RRState uint8

const (
	RRStatePending        RRState = iota // Sent to combiner, awaiting confirmation
	RRStateAccepted                      // Combiner accepted
	RRStateRejected                      // Combiner rejected (see Reason)
	RRStatePendingRemoval                // Delete sent to combiner, awaiting confirmation
	RRStateRemoved                       // Combiner confirmed removal (audit trail)
)

// RRConfirmation records a single recipient's confirmation status for a tracked RR.
type RRConfirmation struct {
	Status    string    `json:"status"`           // "accepted", "rejected", "removed", "pending"
	Reason    string    `json:"reason,omitempty"` // rejection reason
	Timestamp time.Time `json:"timestamp"`
}

// TrackedRR wraps a dns.RR with lifecycle state for combiner confirmation tracking.
type TrackedRR struct {
	RR                 dns.RR
	State              RRState
	Reason             string // Rejection reason (empty unless rejected)
	DistributionID     string // Last distribution this RR was part of
	UpdatedAt          time.Time
	Confirmations      map[string]RRConfirmation // recipientID → per-recipient status
	ExpectedRecipients []string                  // Who must confirm before state transitions to accepted
}

// TrackedRRset holds a set of tracked RRs for a single RRtype.
type TrackedRRset struct {
	Tracked []TrackedRR
}

// ConfirmationDetail carries per-RR confirmation feedback from the combiner
// through to the SynchedDataEngine.
type ConfirmationDetail struct {
	DistributionID string
	Zone           ZoneName
	Source         string // Identifies the confirming peer (combiner ID or agent ID)
	Status         string // "ok", "partial", "error"
	Message        string
	AppliedRecords []string
	RemovedRecords []string // RR strings confirmed as removed by combiner
	RejectedItems  []RejectedItemInfo
	Truncated      bool
	Timestamp      time.Time
}

// RejectedItemInfo describes an RR rejected by the combiner.
type RejectedItemInfo struct {
	Record string
	Reason string
}

// TrackedRRInfo is the JSON-serializable form for dump output.
type TrackedRRInfo struct {
	RR             string                    `json:"rr"`
	State          string                    `json:"state"`
	KeyState       string                    `json:"key_state,omitempty"`
	Reason         string                    `json:"reason,omitempty"`
	DistributionID string                    `json:"distribution_id"`
	UpdatedAt      string                    `json:"updated_at"`
	Confirmations  map[string]RRConfirmation `json:"confirmations,omitempty"`
}

// --- from legacy_hsyncengine.go ---

type SyncRequest struct {
	Command      string
	ZoneName     ZoneName
	ZoneData     *ZoneData
	SyncStatus   *HsyncStatus
	OldDnskeys   *core.RRset
	NewDnskeys   *core.RRset
	DnskeyStatus *DnskeyStatus // Local DNSKEY adds/removes (Phase 5)
	Response     chan SyncResponse
}

type SyncResponse struct {
	Status   bool
	Error    bool
	ErrorMsg string
	Msg      string
}

type SyncStatus struct {
	Identity AgentId
	Agents   map[AgentId]*Agent
	Error    bool
	Response chan SyncStatus
}

// --- from legacy_combiner_chunk.go ---

// CombinerSyncRequest represents a sync request to the combiner.
// Uses the same data structure as CombinerPost.Data for transport neutrality.
type CombinerSyncRequest struct {
	SenderID       string                   // Identity of the sending agent
	DeliveredBy    string                   // Identity of the agent that delivered this to the combiner
	Zone           string                   // Zone being updated
	ZoneClass      string                   // "mp" (default) or "provider"
	SyncType       string                   // Type of sync: "NS", "DNSKEY", "CDS", "CSYNC", "GLUE"
	Records        map[string][]string      // RR strings grouped by owner name (same as CombinerPost.Data)
	Operations     []core.RROperation       // Explicit operations (takes precedence over Records)
	Publish        *core.PublishInstruction // KEY/CDS publication instruction
	Serial         uint32                   // Zone serial (optional)
	DistributionID string                   // Distribution ID for tracking
	Timestamp      time.Time                // When the request was created
}

// CombinerSyncResponse represents a confirmation from the combiner.
type CombinerSyncResponse struct {
	DistributionID string         // Echoed from request
	Zone           string         // Zone that was updated
	Nonce          string         // Echoed nonce from the incoming sync/update message
	Status         string         // "ok", "partial", "error"
	Message        string         // Human-readable message
	AppliedRecords []string       // RRs that were successfully applied (additions)
	RemovedRecords []string       // RRs that were successfully removed (deletions)
	RejectedItems  []RejectedItem // Items that were rejected with reasons
	Timestamp      time.Time      // When the response was created
	DataChanged    bool           // True when zone data was actually mutated (not idempotent re-apply)
}

// RejectedItem describes an RR that was rejected and why.
type RejectedItem struct {
	Record string // The RR string
	Reason string // Why it was rejected
}

// CombinerSyncRequestPlus includes a response channel for async processing.
type CombinerSyncRequestPlus struct {
	Request  *CombinerSyncRequest
	Response chan *CombinerSyncResponse
}

// CombinerState holds combiner-specific state that outlives individual CHUNK messages.
// Used by CLI commands (error journal queries) and in-process SendToCombiner.
// Transport routing is handled by the unified ChunkNotifyHandler.
type CombinerState struct {
	// ErrorJournal records errors during CHUNK NOTIFY processing for operational diagnostics.
	// Queried via "transaction errors" CLI commands. If nil, errors are only logged.
	ErrorJournal *ErrorJournal

	// ProtectedNamespaces: domain suffixes belonging to this provider.
	// NS records from remote agents whose targets fall within these namespaces are rejected.
	ProtectedNamespaces []string

	// chunkHandler is the underlying ChunkNotifyHandler (internal wiring).
	// Access is via SetRouter/SetGetPeerAddress/SetSecureWrapper.
	ChunkNotifyHandler *transport.ChunkNotifyHandler
}

// --- from legacy_combiner_utils.go ---

// Named presets for allowed RRtypes. Hardcoded for safety.
// "apex-combiner": manages DNSKEY, CDS, CSYNC, NS, KEY at the zone apex.
// "delegation-combiner": (future) manages NS, DS, GLUE at delegation points.
var AllowedRRtypePresets = map[string]map[uint16]bool{
	"apex-combiner": {
		dns.TypeDNSKEY: true,
		dns.TypeCDS:    true,
		dns.TypeCSYNC:  true,
		dns.TypeNS:     true,
		dns.TypeKEY:    true,
	},
	// "delegation-combiner": { dns.TypeNS: true, dns.TypeDS: true, ... },
}

// AllowedLocalRRtypes is the active preset. Default: "apex-combiner".
var AllowedLocalRRtypes = AllowedRRtypePresets["apex-combiner"]

// providerZoneRRtypes caches the parsed allowed-RRtype map for each provider zone.
// Populated during config parsing via RegisterProviderZoneRRtypes.
var providerZoneRRtypes = map[string]map[uint16]bool{}

// --- from legacy_hsync_utils.go ---

// DnskeyStatus holds the result of DNSKEY change detection (local keys only).
type DnskeyStatus struct {
	Time             time.Time
	ZoneName         string
	LocalAdds        []dns.RR // Local DNSKEYs added since last check
	LocalRemoves     []dns.RR // Local DNSKEYs removed since last check
	CurrentLocalKeys []dns.RR // Complete current set of local DNSKEYs (for replace operations)
}

// --- from legacy_db_combiner_edits.go ---

// PendingEditRecord represents a row in the CombinerPendingEdits table.
type PendingEditRecord struct {
	EditID         int                 `json:"edit_id"`
	Zone           string              `json:"zone"`
	SenderID       string              `json:"sender_id"`
	DeliveredBy    string              `json:"delivered_by"`
	DistributionID string              `json:"distribution_id"`
	Records        map[string][]string `json:"records"`
	ReceivedAt     time.Time           `json:"received_at"`
}

// ApprovedEditRecord represents a row in the CombinerApprovedEdits table.
type ApprovedEditRecord struct {
	EditID         int                 `json:"edit_id"`
	Zone           string              `json:"zone"`
	SenderID       string              `json:"sender_id"`
	DistributionID string              `json:"distribution_id"`
	Records        map[string][]string `json:"records"`
	ReceivedAt     time.Time           `json:"received_at"`
	ApprovedAt     time.Time           `json:"approved_at"`
}

// RejectedEditRecord represents a row in the CombinerRejectedEdits table.
type RejectedEditRecord struct {
	EditID         int                 `json:"edit_id"`
	Zone           string              `json:"zone"`
	SenderID       string              `json:"sender_id"`
	DistributionID string              `json:"distribution_id"`
	Records        map[string][]string `json:"records"`
	ReceivedAt     time.Time           `json:"received_at"`
	RejectedAt     time.Time           `json:"rejected_at"`
	Reason         string              `json:"reason"`
}

// --- from legacy_apihandler_combiner_distrib.go ---

// CombinerDistribPost represents a request to the combiner distrib API
type CombinerDistribPost struct {
	Command string `json:"command"` // "list", "purge"
	Force   bool   `json:"force,omitempty"`
}

// CombinerDistribResponse represents a response from the combiner distrib API
type CombinerDistribResponse struct {
	Time          time.Time              `json:"time"`
	Error         bool                   `json:"error,omitempty"`
	ErrorMsg      string                 `json:"error_msg,omitempty"`
	Msg           string                 `json:"msg,omitempty"`
	Summaries     []*DistributionSummary `json:"summaries,omitempty"`
	Distributions []string               `json:"distributions,omitempty"` // For backward compatibility
}

// AuthDistribPost is the request body for /auth/distrib.
type AuthDistribPost struct {
	Command string `json:"command"`
}
