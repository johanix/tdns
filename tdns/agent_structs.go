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

const (
	AgentStateNeeded      = "needed"      // Agent is required but we don't have complete information
	AgentStateKnown       = "known"       // We have complete information but haven't established communication
	AgentStateOperational = "operational" // We have established successful communication
	AgentStateError       = "error"       // We have tried to establish communication but failed
)

type Agent struct {
	Identity  string
	mu        sync.RWMutex
	Details   map[string]AgentDetails
	Methods   map[string]bool
	Api       *AgentApi
	State     string    // Agent state: needed, known, operational, error
	LastState time.Time // When state last changed
	ErrorMsg  string    // Error message if state is error
}

type AgentDetails struct {
	Addrs       []string
	Port        uint16
	BaseUri     string
	UriRR       *dns.URI
	Host        string
	KeyRR       *dns.KEY  // for DNS transport
	TlsaRR      *dns.TLSA // for HTTPS transport
	LastHB      time.Time
	Endpoint    string
	ContactInfo string          // "none", "partial", "complete"
	Zones       map[string]bool // zones we share with this agent
	State       string          // "discovered", "contact_attempted", "connected", "failed"
	LatestError string
	Heartbeats  uint32
	LatestBeat  time.Time
}

type AgentApi struct {
	Name       string
	Client     *http.Client
	BaseUrl    string
	ApiKey     string // TODO: to remove, but we still need it for a while
	Authmethod string
	Verbose    bool
	Debug      bool

	// normal TDNS API client, we're using most of the tdns API client,
	ApiClient *ApiClient
}

type AgentRegistry struct {
	S              cmap.ConcurrentMap[string, *Agent]
	remoteAgents   map[string][]*Agent
	mu             sync.RWMutex // protects remoteAgents
	LocalIdentity  string       // our own identity
	LocateInterval int          // seconds to wait between locating agents (until success)
}

type AgentBeatPost struct {
	MessageType string
	Identity    string
	Zones       []string // Zones that we share with the remote agent
	Time        time.Time
}

type AgentBeatResponse struct {
	Status   string // ok | error | ...
	Time     time.Time
	Client   string
	Msg      string
	Error    bool
	ErrorMsg string
}
type AgentBeatReport struct {
	Time time.Time
	Beat AgentBeatPost
}

type AgentHelloPost struct {
	MessageType string
	Name        string
	Identity    string
	Addresses   []string
	Port        uint16
	TLSA        dns.TLSA
	Zone        string // in the /hello we only send one zone, the one that triggered the /hello
}

type AgentHelloResponse struct {
	Status   string // ok | error | ...
	Time     time.Time
	Client   string
	Msg      string
	Error    bool
	ErrorMsg string
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
	Identity  string
	Addresses []string
	Port      uint16
	TLSA      dns.TLSA
	Zone      string // in the /hello we only send one zone, the one that triggered the /hello
	Zones     []string
	Time      time.Time
}

type AgentMsgResponse struct {
	Status   string // ok | error | ...
	Time     time.Time
	Client   string
	Msg      string
	Error    bool
	ErrorMsg string
}

// AgentPost/AgentResponse is used in the mgmt API
type AgentPost struct {
	Command string `json:"command"`
	Zone    string `json:"zone"`
	AgentId string `json:"agent_id"`
}

type AgentResponse struct {
	Identity string
	Status   int
	Time     time.Time
	Agents   []*Agent
	HsyncRRs []string
	Msg      string
	Error    bool
	ErrorMsg string
}

// XXX: Do we use this?
type AgentMsgReport struct {
	Msg   *AgentMsgPost
	Agent *Agent
}
