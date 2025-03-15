/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/miekg/dns"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/spf13/viper"
)

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
		if details, exists := agent.Details["DNS"]; exists && details.Zones[zone] {
			agents = append(agents, agent)
		}
	}
	return agents
}

func (conf *Config) NewAgentRegistry() *AgentRegistry {
	if conf.Agent.Identity == "" {
		log.Printf("NewAgentRegistry: error: identity is empty")
		return nil
	}

	li := viper.GetInt("agent.remote.locateinterval")
	if li <= 10 {
		li = 10
	}
	if li > 300 {
		li = 300
	}

	return &AgentRegistry{
		S:              cmap.New[*Agent](),
		remoteAgents:   make(map[string][]*Agent),
		LocalAgent:     &conf.Agent,
		LocateInterval: li,
	}
}

// LocateAgent is completely asynchronous with no return values
func (ar *AgentRegistry) LocateAgent(remoteid string, zonename string) {
	log.Printf("LocateAgent: looking up agent %s", remoteid)

	// Skip if this is our own identity
	if ar.LocalAgent.Identity != "" && remoteid == ar.LocalAgent.Identity {
		log.Printf("LocateAgent: skipping self-identification for %s", remoteid)
		return
	}

	// Check if we already know this agent and it's operational
	agent, exists := ar.S.Get(remoteid)
	if exists {
		if zonename != "" {
			ar.AddZoneToAgent(remoteid, zonename)
		}

		// If the agent exists in the registry, then it is at least in the state "needed".
		// That implies that either there is already a LocateAgent() running, or one has
		// already completed. In neither case do we need a new LocateAgent(), so we just return.
		return
	}

	log.Printf("LocateAgent: looking up agent %s for zone %s", remoteid, zonename)

	// Initialize agent if needed
	agent = &Agent{
		Identity:  remoteid,
		Details:   map[string]AgentDetails{},
		Methods:   map[string]bool{},
		State:     AgentStateNeeded,
		LastState: time.Now(),
	}
	// Initialize Zones map for each transport
	for _, transport := range []string{"DNS", "API"} {
		details := AgentDetails{
			Zones:       make(map[string]bool),
			State:       AgentStateNeeded,
			ContactInfo: "none",
		}
		agent.Details[transport] = details
	}
	ar.S.Set(remoteid, agent)

	// lagent := agent.CleanCopy()
	tmp := SanitizeForJSON(agent)
	var lagent *Agent
	var ok bool
	if lagent, ok = tmp.(*Agent); !ok {
		log.Printf("LocateAgent: error: failed to assert tmp agent to *Agent")
		return
	}

	go func() {
		// Create a loop that continues until agent is known
		for {
			// Do agent lookup
			resolverAddress := viper.GetString("resolver.address")
			if Globals.Debug {
				log.Printf("LocateAgent: using debug resolver %s", resolverAddress)
			}
			resolvers := []string{resolverAddress}
			timeout := 2 * time.Second
			retries := 3

			// Look up URIs for both transports
			for _, transport := range []string{"DNS", "API"} {
				details := lagent.Details[transport]
				var targetName string

				// Only look up URI if we don't have it
				if details.UriRR == nil {
					svcname := fmt.Sprintf("_%s._tcp.%s", transport, remoteid)
					if transport == "API" {
						svcname = fmt.Sprintf("_https._tcp.%s", remoteid)
					}
					svcname = dns.Fqdn(svcname)

					rrset, err := RecursiveDNSQueryWithServers(svcname, dns.TypeURI, timeout, retries, resolvers)
					if err != nil {
						log.Printf("LocateAgent: error response to URI query for %s transport: %v", transport, err)
						continue // Try the next transport instead of failing
					}

					// Process URI response
					if rrset != nil && len(rrset.RRs) > 0 {
						for _, rr := range rrset.RRs {
							log.Printf("LocateAgent: URI record: %s", rr.String())
						}
					}
					// dump.P(rrset)
					if rrset != nil && len(rrset.RRs) > 0 {
						if u, ok := rrset.RRs[0].(*dns.URI); ok {
							details.UriRR = u

							details.BaseUri = details.UriRR.Target

							details.ContactInfo = "partial"
							agent.mu.Lock()
							agent.Details[transport] = details
							agent.mu.Unlock()
						}
					}
				}

				// Only proceed with SVCB if we have URI
				if details.UriRR != nil && len(details.Addrs) == 0 {
					parsedUri, err := url.Parse(details.BaseUri)
					if err != nil {
						log.Printf("LocateAgent: failed to parse URI target %q: %v", details.BaseUri, err)
						continue
					}

					targetName, _, err = net.SplitHostPort(parsedUri.Host)
					if err != nil {
						targetName = parsedUri.Host
					}
					details.Host = targetName

					rrset, err := RecursiveDNSQueryWithServers(dns.Fqdn(targetName), dns.TypeSVCB, timeout, retries, resolvers)
					if err != nil {
						log.Printf("LocateAgent: error response to SVCB query: %v", err)
						continue // Try the next transport
					}

					// Process SVCB response
					if rrset == nil {
						log.Printf("LocateAgent: response to %s SVCB contained zero RRs", targetName)
						continue
					}
					for _, rr := range rrset.RRs {
						log.Printf("LocateAgent: SVCB record: %s", rr.String())
					}

					if rrset != nil && len(rrset.RRs) > 0 {
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
							agent.mu.Lock()
							agent.Details[transport] = details
							agent.mu.Unlock()
						}
					}
				}

				// Only proceed with KEY/TLSA if we have addresses and a target name
				if len(details.Addrs) > 0 && targetName != "" {
					if transport == "DNS" && details.KeyRR == nil {
						// Look up KEY
						rrset, err := RecursiveDNSQueryWithServers(dns.Fqdn(targetName), dns.TypeKEY, timeout, retries, resolvers)
						if err != nil {
							log.Printf("LocateAgent: error response to KEY query: %v", err)
							continue
						}

						if rrset != nil {
							for _, rr := range rrset.RRs {
								log.Printf("LocateAgent: KEY record: %s", rr.String())
								if k, ok := rr.(*dns.KEY); ok {
									details.KeyRR = k
									lagent.Methods["DNS"] = true
									agent.mu.Lock()
									agent.Details[transport] = details
									agent.mu.Unlock()
									break
								}
							}
						}
					} else if transport == "API" && details.TlsaRR == nil {
						// Look up TLSA
						tlsaName := fmt.Sprintf("_%d._tcp.%s", details.Port, targetName)
						rrset, err := RecursiveDNSQueryWithServers(dns.Fqdn(tlsaName), dns.TypeTLSA, timeout, retries, resolvers)
						if err != nil {
							log.Printf("LocateAgent: error response to TLSA query: %v", err)
							continue
						}

						if rrset != nil {
							for _, rr := range rrset.RRs {
								log.Printf("LocateAgent: TLSA record: %s", rr.String())
								if t, ok := rr.(*dns.TLSA); ok {
									details.TlsaRR = t
									lagent.Methods["API"] = true
									agent.mu.Lock()
									agent.Details[transport] = details
									agent.mu.Unlock()
									break
								}
							}
						}
					}
				}

				lagent.Details[transport] = details
			}

			// Check if API transport details are complete
			details := lagent.Details["API"]
			if details.UriRR != nil && details.TlsaRR != nil && len(details.Addrs) > 0 {
				details.ContactInfo = "complete"
				details.State = AgentStateKnown
				lagent.Methods["API"] = true
				log.Printf("LocateAgent: API transport details for remote agent %s are complete", remoteid)
				lagent.Details["API"] = details
			}

			details = lagent.Details["DNS"]
			if details.UriRR != nil && details.KeyRR != nil && len(details.Addrs) > 0 {
				details.ContactInfo = "complete"
				details.State = AgentStateKnown
				lagent.Methods["DNS"] = true
				log.Printf("LocateAgent: DNS transport details for remote agent %s are complete", remoteid)
				lagent.Details["DNS"] = details
			}

			// Update agent state based on available methods
			if lagent.Details["DNS"].ContactInfo == "complete" || lagent.Details["API"].ContactInfo == "complete" {
				lagent.State = AgentStateKnown
				lagent.LastState = time.Now()

				err := lagent.NewAgentSyncApiClient(ar.LocalAgent)
				if err != nil {
					log.Printf("LocateAgent: error creating API client for remote agent %s: %v", remoteid, err)
					lagent.State = AgentStateError
					lagent.ErrorMsg = fmt.Sprintf("error creating API client: %v", err)
					lagent.LastState = time.Now()
				}
				lagent.Api.ApiClient.Debug = false // disable debug logging for API client

				if len(lagent.Details["API"].Addrs) > 0 {
					log.Printf("Remote agent %q has the API addresses %v", remoteid, lagent.Details["API"].Addrs)
					var tmp []string
					port := strconv.Itoa(int(lagent.Details["API"].Port))
					for _, addr := range lagent.Details["API"].Addrs {
						tmp = append(tmp, net.JoinHostPort(addr, port))
					}
					lagent.Api.ApiClient.Addresses = tmp
				}

				// Agent is now known, update and exit the loop
				ar.mu.Lock()
				ar.S.Set(remoteid, lagent)
				ar.mu.Unlock()
				log.Printf("LocateAgent: remote agent %s is now KNOWN, stopping retry loop", remoteid)

				// If we're in known state and have a zone, try to send hello
				if zonename != "" {
					ar.AddZoneToAgent(remoteid, zonename)

					// Try to send hello
					go func() {
						_, resp, err := lagent.SendApiHello(&AgentHelloPost{
							MessageType: "HELLO",
							MyIdentity:  ar.LocalAgent.Identity, // our identity
							Zone:        zonename,
						})
						if err != nil {
							log.Printf("LocateAgent: error sending HELLO to %s: %v", remoteid, err)
							return
						}

						var amr AgentHelloResponse
						err = json.Unmarshal(resp, &amr)
						if err != nil {
							log.Printf("LocateAgent: error unmarshalling HELLO response: %v", err)
							return
						}

						log.Printf("LocateAgent: HELLO to %s returned: %s", remoteid, amr.Msg)

						// Update state after successful hello
						ar.mu.Lock()
						details := lagent.Details["API"]
						if amr.Status == "ok" {
							lagent.State = AgentStateIntroduced
							details.LatestError = ""
						} else {
							details.LatestError = amr.ErrorMsg
							lagent.InitialZone = zonename // need to store this for future retries
						}
						lagent.Details["API"] = details
						lagent.LastState = time.Now()
						ar.S.Set(remoteid, lagent)
						ar.mu.Unlock()
					}()
				}
				return
			} else {
				// Agent is not yet known, update and sleep before retrying
				ar.S.Set(remoteid, agent)
				log.Printf("LocateAgent: remote agent %s is not operational, will retry in %d seconds", remoteid, ar.LocateInterval)
				time.Sleep(time.Duration(ar.LocateInterval) * time.Second)
				// Loop will continue
			}
		}
	}()
}

// Create a new synchronous function for code that needs immediate results
func (ar *AgentRegistry) GetAgentInfo(identity string) (*Agent, error) {
	// Skip if this is our own identity
	if ar.LocalAgent.Identity != "" && identity == ar.LocalAgent.Identity {
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
			// LastHB:      details.LastHB,
			Endpoint:    details.Endpoint,
			State:       details.State,
			LatestError: details.LatestError,
			// Heartbeats:  details.Heartbeats,
			Zones: make(map[string]bool),
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
				if hsync.Identity == ourIdentity {
					continue
				}
				// Found another agent, try to locate it
				ar.LocateAgent(hsync.Identity, "")
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

// GetRemoteAgents returns a list of remote agents for a zone. It does not
// check if the agents are operational, or try to get missing information.
func (ar *AgentRegistry) GetRemoteAgents(zonename string) ([]*Agent, error) {
	agents := []*Agent{}

	ar.mu.RLock()
	defer ar.mu.RUnlock()
	log.Printf("GetRemoteAgents: zone %s has %d remote agents", zonename, len(ar.remoteAgents[zonename]))

	zd, exists := Zones.Get(zonename)
	if !exists {
		log.Printf("GetRemoteAgents: zone %q is unknown", zonename)
		return nil, fmt.Errorf("zone %q is unknown", zonename)
	}

	apex, err := zd.GetOwner(zonename)
	if err != nil {
		log.Printf("GetRemoteAgents: error getting apex for zone %q: %v", zonename, err)
		return nil, fmt.Errorf("error getting apex for zone %q: %v", zonename, err)
	}

	hsyncRRset := apex.RRtypes.GetOnlyRRSet(TypeHSYNC)
	if len(hsyncRRset.RRs) == 0 {
		log.Printf("GetRemoteAgents: zone %q has no HSYNC RRset", zonename)
		return nil, fmt.Errorf("zone %q has no HSYNC RRset", zonename)
	}

	// Convert the RRs to strings for transmission
	hsyncStrs := make([]string, len(hsyncRRset.RRs))
	for i, rr := range hsyncRRset.RRs {
		hsyncStrs[i] = rr.String()
	}

	for _, rr := range hsyncRRset.RRs {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync, ok := prr.Data.(*HSYNC); ok {
				// Skip if this is our own identity
				if hsync.Identity == ar.LocalAgent.Identity {
					continue
				}
				// Found an HSYNC record, try to locate the agent
				agent, err := ar.GetAgentInfo(hsync.Identity)
				if err != nil {
					agent = &Agent{
						Identity:  hsync.Identity,
						State:     AgentStateError,
						ErrorMsg:  fmt.Sprintf("error getting agent info: %v", err),
						LastState: time.Now(),
					}
				}
				agents = append(agents, agent)
			}
		}
	}
	return agents, nil
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

// UpdateAgents updates the registry based on the HSYNC records in the request. It has already been
// split into "adds" and "removes" by zd.HsyncCHanged() so we can process them independently.
func (ar *AgentRegistry) UpdateAgents(ourId string, wannabe_agents map[string]*Agent,
	req SyncRequest, zonename string) error {

	// Handle new HSYNC records
	for _, rr := range req.SyncStatus.HsyncAdds {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync, ok := prr.Data.(*HSYNC); ok {
				log.Printf("UpdateAgents: Zone %s: analysing HSYNC: %q", zonename, hsync.String())

				if hsync.Identity == ourId {
					// We're the Target
					if hsync.Upstream == "." {
						// Special case: no upstream to sync with
						log.Printf("UpdateAgents: Zone %s: we are target but upstream is '.', no sync needed", zonename)
						continue
					}

					// Need to sync with Upstream - do this asynchronously
					ar.LocateAgent(hsync.Upstream, zonename)
				} else {
					log.Printf("UpdateAgents: Zone %s: HSYNC is for a remote agent, %q, analysing", zonename, hsync.Identity)
					// Not our target, locate agent asynchronously
					ar.LocateAgent(hsync.Identity, zonename)
				}
			}
		}
	}

	// Handle removed HSYNC records
	for _, rr := range req.SyncStatus.HsyncRemoves {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync, ok := prr.Data.(*HSYNC); ok {
				if hsync.Identity == ourId {
					// We're no longer involved in this zone's management
					ar.CleanupZoneRelationships(zonename)
				} else {
					// Remote agent was removed, update registry
					if agent, exists := ar.S.Get(hsync.Identity); exists {
						for transport := range agent.Details {
							if agent.Details[transport].Zones != nil {
								delete(agent.Details[transport].Zones, zonename)
							}
						}
						ar.RemoveRemoteAgent(zonename, hsync.Identity)
					}
				}
			}
		}
	}

	return nil
}
