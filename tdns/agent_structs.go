/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
	cmap "github.com/orcaman/concurrent-map/v2"
)

type AgentState uint8

const (
	AgentStateNeeded      AgentState = iota + 1 // Agent is required but we don't have complete information
	AgentStateKnown                             // We have complete information but haven't established communication
	AgentStateIntroduced                        // We got a nice reply to our HELLO
	AgentStateOperational                       // We got a nice reply to our (secure) BEAT
	AgentStateDegraded                          // Last successfull heartbeat (in eith direction) was more than 2x normal interval ago
	AgentStateInterrupted                       // Last successfull heartbeat (in eith direction) was more than 10x normal interval ago
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
	Addrs   []string
	Port    uint16
	BaseUri string
	UriRR   *dns.URI
	//	SvcbRR  *dns.SVCB
	Host   string    // the host part of the BaseUri
	KeyRR  *dns.KEY  // for DNS transport
	TlsaRR *dns.TLSA // for HTTPS transport
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
	S              cmap.ConcurrentMap[AgentId, *Agent]
	remoteAgents   map[ZoneName][]*Agent
	mu             sync.RWMutex    // protects remoteAgents
	LocalAgent     *LocalAgentConf // our own identity
	LocateInterval int             // seconds to wait between locating agents (until success)
}

type AgentBeatPost struct {
	MessageType    string
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
	MessageType  string
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
	Client       string
	Msg          string
	Error        bool
	ErrorMsg     string
}

// AgentMsg{Post,Response} are intended for agent-to-agent messaging
type AgentMsgPost struct {
	MessageType  string // "NOTIFY", ...
	MyIdentity   AgentId
	YourIdentity AgentId
	Addresses    []string
	Port         uint16
	TLSA         dns.TLSA
	Zone         ZoneName // An AgentMsgPost should always only refer to one zone.
	// Data	     map[AgentId]map[uint16]RRset
	RRs []string // cannot send more structured format, as dns.RR cannot be json marshalled.
	// Zones []string
	Time time.Time
}

type AgentMsgResponse struct {
	Status   string // ok | error | ...
	Time     time.Time
	Client   string
	Msg      string
	Zone     ZoneName
	Error    bool
	ErrorMsg string
}

// AgentMgmt{Post,Response} are used in the mgmt API
type AgentMgmtPost struct {
	Command     string `json:"command"`
	MessageType string
	Zone        ZoneName `json:"zone"`
	AgentId     AgentId  `json:"agent_id"`
	RRType      uint16
	RR          string
	RRs         []string
	Upstream    AgentId `json:"-"`
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
	Identity    AgentId
	Status      string
	Time        time.Time
	Agents      []*Agent
	HsyncRRs    []string
	AgentConfig LocalAgentConf
	Msg         string
	Error       bool
	ErrorMsg    string
}

type AgentMgmtPostPlus struct {
	AgentMgmtPost
	Response chan *AgentMgmtResponse
}

type AgentMsgReport struct {
	Transport    string
	MessageType  string
	Zone         ZoneName
	Identity     AgentId
	BeatInterval uint32
	Msg          interface{}
	Response     chan *SynchedDataResponse
}
