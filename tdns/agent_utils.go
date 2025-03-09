/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/miekg/dns"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/spf13/viper"
)

// Agent state constants
const (
	AgentStateNeeded      = "needed"      // Agent is required but we don't have complete information
	AgentStateKnown       = "known"       // We have complete information but haven't established communication
	AgentStateOperational = "operational" // We have established successful communication
)

type Agent struct {
	Identity  string
	Details   map[string]AgentDetails
	Methods   map[string]bool
	Api       *ApiClient
	State     string    // Agent state: needed, known, operational
	LastState time.Time // When state last changed
}

type AgentDetails struct {
	Addrs     []string
	Port      uint16
	BaseUri   string
	UriRR     *dns.URI
	KeyRR     *dns.KEY  // for DNS transport
	TlsaRR    *dns.TLSA // for HTTPS transport
	LastHB    time.Time
	Endpoint  string
	Zones     map[string]bool // zones we share with this agent
	State     string          // "discovered", "contact_attempted", "connected", "failed"
	LastError string
}

type AgentRegistry struct {
	S             cmap.ConcurrentMap[string, *Agent]
	remoteAgents  map[string][]*Agent
	mu            sync.RWMutex // protects remoteAgents
	LocalIdentity string       // our own identity
}

func (ar *AgentRegistry) AddZoneToAgent(identity, zone string) {
	agent, exists := ar.S.Get(identity)
	if !exists {
		return
	}

	// Add zone to both transports
	for transport := range agent.Details {
		details := agent.Details[transport]
		if details.Zones == nil {
			details.Zones = make(map[string]bool)
		}
		details.Zones[zone] = true
		agent.Details[transport] = details
	}

	// Update remoteAgents map
	ar.AddRemoteAgent(zone, agent)
	ar.S.Set(identity, agent)
}

func (ar *AgentRegistry) GetAgentsForZone(zone string) []*Agent {
	var agents []*Agent
	for _, agent := range ar.S.Items() {
		// Check any transport method - they should all have the same zone info
		if details, exists := agent.Details["dns"]; exists && details.Zones[zone] {
			agents = append(agents, agent)
		}
	}
	return agents
}

func NewAgentRegistry(identity string) *AgentRegistry {
	if identity == "" {
		log.Printf("NewAgentRegistry: error: identity is empty")
		return nil
	}
	return &AgentRegistry{
		S:             cmap.New[*Agent](),
		remoteAgents:  make(map[string][]*Agent),
		LocalIdentity: identity,
	}
}

// LocateAgent is completely asynchronous with no return values
func (ar *AgentRegistry) LocateAgent(identity string, zonename string) {
	log.Printf("LocateAgent: looking up agent %s", identity)

	// Skip if this is our own identity
	if ar.LocalIdentity != "" && identity == ar.LocalIdentity {
		log.Printf("LocateAgent: skipping self-identification for %s", identity)
		return
	}

	go func() {
		log.Printf("LocateAgent: looking up agent %s for zone %s", identity, zonename)

		// Check if we already know this agent and it's operational
		agent, exists := ar.S.Get(identity)
		if exists && agent.State == AgentStateOperational &&
			agent.Details["dns"].LastHB.After(time.Now().Add(-1*time.Hour)) {
			// Add zone if provided
			if zonename != "" {
				ar.AddZoneToAgent(identity, zonename)
			}
			return
		}

		// Initialize agent if needed
		if !exists {
			agent = &Agent{
				Identity:  identity,
				Details:   map[string]AgentDetails{},
				Methods:   map[string]bool{},
				State:     AgentStateNeeded,
				LastState: time.Now(),
			}
			// Initialize Zones map for each transport
			for _, transport := range []string{"dns", "api"} {
				details := AgentDetails{
					Zones: make(map[string]bool),
					State: AgentStateNeeded,
				}
				agent.Details[transport] = details
			}
			ar.S.Set(identity, agent)
		}

		// Do agent lookup
		resolverAddress := viper.GetString("resolver.address")
		resolvers := []string{resolverAddress}
		timeout := 2 * time.Second
		retries := 3

		// Look up URIs for both transports
		for _, transport := range []string{"dns", "api"} {
			details := agent.Details[transport]
			var targetName string

			// Only look up URI if we don't have it
			if details.UriRR == nil {
				svcname := fmt.Sprintf("_%s._tcp.%s", transport, identity)
				if transport == "api" {
					svcname = fmt.Sprintf("_https._tcp.%s", identity)
				}
				svcname = dns.Fqdn(svcname)

				rrset, err := RecursiveDNSQueryWithServers(svcname, dns.TypeURI, timeout, retries, resolvers)
				if err != nil {
					log.Printf("LocateAgent: error response to URI query for %s transport: %v", transport, err)
					continue // Try the next transport instead of failing
				}

				// Process URI response
				if len(rrset.RRs) > 0 {
					if u, ok := rrset.RRs[0].(*dns.URI); ok {
						details.UriRR = u
					}
				}
			}

			// Only proceed with SVCB if we have URI
			if details.UriRR != nil && len(details.Addrs) == 0 {
				uristr := details.UriRR.Target
				parsedUri, err := url.Parse(uristr)
				if err != nil {
					log.Printf("LocateAgent: failed to parse URI target %q: %v", uristr, err)
					continue
				}

				targetName, _, err = net.SplitHostPort(parsedUri.Host)
				if err != nil {
					targetName = parsedUri.Host
				}

				rrset, err := RecursiveDNSQueryWithServers(dns.Fqdn(targetName), dns.TypeSVCB, timeout, retries, resolvers)
				if err != nil {
					log.Printf("LocateAgent: error response to SVCB query: %v", err)
					continue // Try the next transport
				}

				// Process SVCB response
				if len(rrset.RRs) > 0 {
					if svcb, ok := rrset.RRs[0].(*dns.SVCB); ok {
						// Process SVCB record (addresses and port)
						for _, kv := range svcb.Value {
							switch kv.Key() {
							case dns.SVCB_IPV4HINT:
								ipv4Hints := kv.(*dns.SVCBIPv4Hint)
								for _, ip := range ipv4Hints.Hint {
									details.Addrs = append(details.Addrs, ip.String())
								}
							case dns.SVCB_IPV6HINT:
								ipv6Hints := kv.(*dns.SVCBIPv6Hint)
								for _, ip := range ipv6Hints.Hint {
									details.Addrs = append(details.Addrs, ip.String())
								}
							case dns.SVCB_PORT:
								port := kv.(*dns.SVCBPort)
								details.Port = uint16(port.Port)
							}
						}
					}
				}
			}

			// Only proceed with KEY/TLSA if we have addresses and a target name
			if len(details.Addrs) > 0 && targetName != "" {
				if transport == "dns" && details.KeyRR == nil {
					// Look up KEY
					rrset, err := RecursiveDNSQueryWithServers(dns.Fqdn(targetName), dns.TypeKEY, timeout, retries, resolvers)
					if err != nil {
						log.Printf("LocateAgent: error response to KEY query: %v", err)
						continue
					}

					for _, rr := range rrset.RRs {
						if k, ok := rr.(*dns.KEY); ok {
							details.KeyRR = k
							agent.Methods["dns"] = true
							break
						}
					}
				} else if transport == "api" && details.TlsaRR == nil {
					// Look up TLSA
					tlsaName := fmt.Sprintf("_%d._tcp.%s", details.Port, targetName)
					rrset, err := RecursiveDNSQueryWithServers(dns.Fqdn(tlsaName), dns.TypeTLSA, timeout, retries, resolvers)
					if err != nil {
						log.Printf("LocateAgent: error response to TLSA query: %v", err)
						continue
					}

					for _, rr := range rrset.RRs {
						if t, ok := rr.(*dns.TLSA); ok {
							details.TlsaRR = t
							agent.Methods["api"] = true
							break
						}
					}
				}
			}

			agent.Details[transport] = details
		}

		// Update agent state based on available methods
		if agent.Methods["dns"] || agent.Methods["api"] {
			agent.State = AgentStateKnown
			agent.LastState = time.Now()

			// If we're in known state and have a zone, try to send hello
			if zonename != "" {
				ar.AddZoneToAgent(identity, zonename)
				// Try to send hello
				go func() {
					err := agent.SendBeat("HELLO")
					if err != nil {
						log.Printf("LocateAgent: error sending HELLO to %s: %v", identity, err)
						return
					}

					// Update state after successful hello
					agent.State = AgentStateOperational
					agent.LastState = time.Now()
					ar.S.Set(identity, agent)
				}()
			}
		}

		ar.S.Set(identity, agent)
	}()
}

// Create a new synchronous function for code that needs immediate results
func (ar *AgentRegistry) GetAgentInfo(identity string) (*Agent, error) {
	// Skip if this is our own identity
	if ar.LocalIdentity != "" && identity == ar.LocalIdentity {
		return nil, fmt.Errorf("cannot get info for self as remote agent")
	}

	// Check if we already know this agent
	agent, exists := ar.S.Get(identity)
	if !exists {
		return nil, fmt.Errorf("agent %s not found", identity)
	}

	return agent, nil
}

// CleanCopy returns a copy of the Agent without any sensitive data
func (a *Agent) CleanCopy() *Agent {
	copy := &Agent{
		Identity: a.Identity,
		Details:  make(map[string]AgentDetails),
		Methods:  make(map[string]bool),
	}

	for transport, details := range a.Details {
		copyDetails := AgentDetails{
			LastHB:    details.LastHB,
			Endpoint:  details.Endpoint,
			State:     details.State,
			LastError: details.LastError,
			Zones:     make(map[string]bool),
		}
		for zone := range details.Zones {
			copyDetails.Zones[zone] = true
		}
		copy.Details[transport] = copyDetails
	}

	for method, enabled := range a.Methods {
		copy.Methods[method] = enabled
	}

	return copy
}

// IdentifyAgents looks for HSYNC records in a zone and identifies agents we need to sync with
func (ar *AgentRegistry) IdentifyAgents(zd *ZoneData, ourIdentity string) ([]*Agent, error) {
	var agents []*Agent

	rrset, err := zd.GetRRset(zd.ZoneName, TypeHSYNC)
	if err != nil {
		return nil, fmt.Errorf("error getting HSYNC records: %v", err)
	}

	// Look for HSYNC records where Target is NOT our identity
	for _, rr := range rrset.RRs {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync, ok := prr.Data.(*HSYNC); ok {
				if hsync.Target == ourIdentity {
					continue
				}
				// Found another agent, try to locate it
				ar.LocateAgent(hsync.Target, "")
			}
		}
	}

	return agents, nil
}

func AgentToString(a *Agent) string {
	if a == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s", a.Identity)
}

// AddRemoteAgent adds an agent to the list of remote agents for a zone
func (ar *AgentRegistry) AddRemoteAgent(zonename string, agent *Agent) {
	ar.mu.Lock()
	defer ar.mu.Unlock()
	if ar.remoteAgents[zonename] == nil {
		ar.remoteAgents[zonename] = make([]*Agent, 0)
	}
	ar.remoteAgents[zonename] = append(ar.remoteAgents[zonename], agent)
}

// RemoveRemoteAgent removes an agent from the list of remote agents for a zone
func (ar *AgentRegistry) RemoveRemoteAgent(zonename string, identity string) {
	ar.mu.Lock()
	defer ar.mu.Unlock()

	// Remove from remoteAgents
	agents := ar.remoteAgents[zonename]
	for i, a := range agents {
		if a.Identity == identity {
			ar.remoteAgents[zonename] = append(agents[:i], agents[i+1:]...)
			break
		}
	}

	// Clean up zone association in agent
	if agent, exists := ar.S.Get(identity); exists {
		for transport := range agent.Details {
			delete(agent.Details[transport].Zones, zonename)
		}
		ar.S.Set(identity, agent)
	}
}

func (ar *AgentRegistry) GetRemoteAgents(zonename string) []*Agent {
	ar.mu.RLock()
	defer ar.mu.RUnlock()

	// If we don't have any agents for this zone yet, try to find them
	if len(ar.remoteAgents[zonename]) == 0 {
		// Look up HSYNC records for the zone
		if zd, exists := Zones.Get(zonename); exists {
			if owner, err := zd.GetOwner(zonename); err == nil {
				hsyncRRset := owner.RRtypes.GetOnlyRRSet(TypeHSYNC)
				if len(hsyncRRset.RRs) > 0 {
					for _, rr := range hsyncRRset.RRs {
						if prr, ok := rr.(*dns.PrivateRR); ok {
							if hsync, ok := prr.Data.(*HSYNC); ok {
								// Skip if this is our own identity
								if hsync.Target == ar.LocalIdentity {
									continue
								}
								// Found an HSYNC record, try to locate the agent
								agent, err := ar.GetAgentInfo(hsync.Target)
								if err != nil {
									// Start async lookup
									ar.LocateAgent(hsync.Target, zonename)
									continue
								}
								ar.AddZoneToAgent(agent.Identity, zonename)
							}
						}
					}
				}
			}
		}
	}

	return ar.remoteAgents[zonename]
}

// CleanupZoneRelationships handles the complex cleanup when we're no longer involved in a zone's management
func (ar *AgentRegistry) CleanupZoneRelationships(zonename string) {
	// TODO: Implement cleanup:
	// 1. Remove zone from all agents that have it
	// 2. Remove all agents from remoteAgents[zonename]
	// 3. For any agent that no longer shares zones with us:
	//    - Send GOODBYE message
	//    - Remove from registry
	log.Printf("TODO: Implement cleanup for zone %s", zonename)
}
