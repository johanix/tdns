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
	AgentStateError                             // We have tried to establish communication but failed
)

var AgentStateToString = map[AgentState]string{
	AgentStateNeeded:      "NEEDED",
	AgentStateKnown:       "KNOWN",
	AgentStateIntroduced:  "INTRODUCED",
	AgentStateOperational: "OPERATIONAL",
	AgentStateError:       "ERROR",
}

// Remote agent states: first occurence of a remote agent identity is when it appears in a
// HSYNC record for a zone where we also appear in the HSYNC RRset (i.e. we are both part of it).
// Then the remote agent becomes NEEDED. Data collection starts. When all data (URI, SVCB,
// TLSA, etc) has been collected (and verified) the state changes to KNOWN. At the tail end
// of LocateAgent(), when the state changes to KNOWN, a HELLO message is sent to the remote agent.
// If we get at positive response to that state changes to HELLOOK and we're ready to start
// sending heartbeats. After the first positive response to a heartbeat that we sent is received
// the state finally changes to OPERATIONAL.

type Agent struct {
	Identity    AgentId
	mu          sync.RWMutex
	InitialZone ZoneName
	ApiDetails  *AgentDetails
	DnsDetails  *AgentDetails
	ApiMethod   bool
	DnsMethod   bool
	Zones	    map[ZoneName]bool
	Api         *AgentApi
	State       AgentState // Agent states: needed, known, hello-done, operational, error
	LastState   time.Time  // When state last changed
	ErrorMsg    string     // Error message if state is error
}

type AgentDetails struct {
	Addrs   []string
	Port    uint16
	BaseUri string
	UriRR   *dns.URI
//	SvcbRR  *dns.SVCB
	Host    string    // the host part of the BaseUri
	KeyRR   *dns.KEY  // for DNS transport
	TlsaRR  *dns.TLSA // for HTTPS transport
	//	LastHB      time.Time
	Endpoint        string
	ContactInfo     string          // "none", "partial", "complete"
//	Zones           map[ZoneName]bool // zones we share with this agent
	State           AgentState      // "discovered", "contact_attempted", "connected", "failed"
	LatestError     string
	LatestErrorTime time.Time
	HelloTime       time.Time
	SentBeats       uint32
	ReceivedBeats   uint32
	LatestSBeat     time.Time
	LatestRBeat     time.Time
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

type xxxAgentMsg struct {
	MessageType string // "HELLO", "BEAT", or "FULLBEAT"
	Identity    string
	ZoneName    string
	Zone        string // in the /hello we only send one zone, the one that triggered the /hello
	SharedZones []string
	Time        time.Time
}

type AgentMsgPost struct {
	MessageType string // "HELLO", "BEAT", or "FULLBEAT"
	//	Name        string
	MyIdentity   AgentId
	YourIdentity AgentId
	Addresses    []string
	Port         uint16
	TLSA         dns.TLSA
	Zone         ZoneName // in the /hello we only send one zone, the one that triggered the /hello
	// Data	     map[AgentId]map[uint16]RRset
	Data	     ZoneUpdate
	Zones        []string
	Time         time.Time
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

// AgentPost/AgentResponse is used in the mgmt API
type AgentPost struct {
	Command string   `json:"command"`
	Zone    ZoneName `json:"zone"`
	AgentId AgentId   `json:"agent_id"`
}

type AgentResponse struct {
	Identity    AgentId
	Status      int
	Time        time.Time
	Agents      []*Agent
	HsyncRRs    []string
	AgentConfig LocalAgentConf
	Msg         string
	Error       bool
	ErrorMsg    string
}

type AgentMsgReport struct {
	Transport   string
	MessageType string
	Zone        ZoneName
	Identity    AgentId
	Msg         interface{}
	Response    chan *CombResponse
}
