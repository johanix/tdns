/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"slices"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

func (ar *AgentRegistry) AddZoneToAgent(identity AgentId, zone ZoneName) {
	agent, exists := ar.S.Get(identity)
	if !exists {
		return
	}

	if agent.Zones == nil {
		agent.Zones = make(map[ZoneName]bool)
	}
	agent.Zones[zone] = true

	// Update remoteAgents map
	ar.AddRemoteAgent(zone, agent)
	ar.S.Set(identity, agent)
}

func (ar *AgentRegistry) GetAgentsForZone(zone ZoneName) []*Agent {
	var agents []*Agent
	for _, agent := range ar.S.Items() {
		agent.mu.RLock()
		if _, exists := agent.Zones[zone]; exists {
			agents = append(agents, agent)
		}
		agent.mu.RUnlock()
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
		// S:              cmap.New[*Agent](),
		S:              NewStringer[AgentId, *Agent](),
		RemoteAgents:   make(map[ZoneName][]AgentId),
		LocalAgent:     &conf.Agent,
		LocateInterval: li,
		helloContexts:  make(map[AgentId]context.CancelFunc),
	}
}

// func (ar *AgentRegistry) MarshalJSON() ([]byte, error) {
// 	log.Printf("AgentRegistry: entering MarshalJSON, converting to regular map")
// 	regularS := make(map[AgentId]*Agent)
// 	// for entry := range ar.S.IterBuffered() {
// 	// 	regularS[k] = v
// 	// }
// 	regularS = ar.S.Items()

// 	log.Printf("AgentRegistry: MarshalJSON: json marshalling regular map")
// 	return json.Marshal(struct {
// 		S              map[AgentId]*Agent
// 		remoteAgents   map[ZoneName][]*Agent
// 		LocalAgent     LocalAgentConf
// 		LocateInterval int
// 	}{
// 		S:              regularS,
// 		remoteAgents:   ar.remoteAgents,
// 		LocalAgent:     *ar.LocalAgent,
// 		LocateInterval: ar.LocateInterval,
// 	})
// }

// LocateAgent is completely asynchronous with no return values
func (ar *AgentRegistry) LocateAgent(remoteid AgentId, zonename ZoneName, deferredTask *DeferredAgentTask) {
	log.Printf("LocateAgent: looking up agent %s", remoteid)

	// Skip if this is our own identity
	if ar.LocalAgent.Identity != "" && string(remoteid) == ar.LocalAgent.Identity {
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
		Identity: remoteid,
		// Details:   map[string]AgentDetails{},
		ApiDetails: &AgentDetails{},
		DnsDetails: &AgentDetails{},
		Zones:      make(map[ZoneName]bool),
		State:      AgentStateNeeded,
		LastState:  time.Now(),
	}

	agent.mu.Lock()
	agent.ApiDetails.State = AgentStateNeeded
	agent.DnsDetails.State = AgentStateNeeded
	agent.ApiDetails.ContactInfo = "none"
	agent.DnsDetails.ContactInfo = "none"
	agent.mu.Unlock()

	ar.S.Set(remoteid, agent)

	// lagent := agent.CleanCopy()
	//	tmp := SanitizeForJSON(agent)
	//	var lagent *Agent
	//	var ok bool
	//	if lagent, ok = tmp.(*Agent); !ok {
	//		log.Printf("LocateAgent: error: failed to assert tmp agent to *Agent")
	//		return
	//	}

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
			// for _, transport := range []string{"DNS", "API"} {
			//	details := lagent.Details[transport]
			// var targetName string

			// Only look up URI if we don't have it
			agent.mu.RLock()
			tmpniluri := agent.ApiDetails.UriRR == nil
			agent.mu.RUnlock()
			if tmpniluri {
				go func() {
					qname := string("_https._tcp." + remoteid)
					rrset, err := RecursiveDNSQueryWithServers(qname, dns.TypeURI, timeout, retries, resolvers)
					if err != nil {
						log.Printf("LocateAgent: error response to URI query for %s: %v", qname, err)
						return
					}

					if rrset == nil {
						log.Printf("LocateAgent: no URI record found for %s", qname)
						return
					}

					for _, rr := range rrset.RRs {
						if u, ok := rr.(*dns.URI); ok {
							log.Printf("LocateAgent: URI record: %s", u.String())
							agent.mu.Lock()
							agent.ApiDetails.UriRR = u
							agent.ApiDetails.BaseUri = u.Target
							agent.ApiDetails.ContactInfo = "partial"
							agent.mu.Unlock()
						}
					}
				}()
			}

			agent.mu.RLock()
			tmpniluri = agent.DnsDetails.UriRR == nil
			agent.mu.RUnlock()
			if tmpniluri {
				go func() {
					qname := string("_dns._tcp." + remoteid)
					rrset, err := RecursiveDNSQueryWithServers(qname, dns.TypeURI, timeout, retries, resolvers)
					if err != nil {
						log.Printf("LocateAgent: error response to URI query for %s: %v", qname, err)
						return
					}

					if rrset == nil {
						log.Printf("LocateAgent: no URI record found for %s", qname)
						return
					}

					for _, rr := range rrset.RRs {
						if u, ok := rr.(*dns.URI); ok {
							log.Printf("LocateAgent: URI record for %q:\n%s", agent.Identity, u.String())
							agent.mu.Lock()
							agent.DnsDetails.UriRR = u
							agent.DnsDetails.BaseUri = u.Target
							agent.DnsDetails.ContactInfo = "partial"
							agent.mu.Unlock()
						}
					}
				}()
			}

			// Only proceed with SVCB if we have URI
			agent.mu.RLock()
			tmpniluri = agent.ApiDetails.UriRR == nil
			tmpaddrs := agent.ApiDetails.Addrs
			agent.mu.RUnlock()
			if tmpniluri && len(tmpaddrs) == 0 {
				go func() {
					_, addrs, port, targetName, err := FetchSVCB(agent.ApiDetails.BaseUri, resolvers, timeout, retries)
					if err != nil {
						log.Printf("LocateAgent: error fetching SVCB for %s: %v", agent.ApiDetails.BaseUri, err)
						return
					}

					agent.mu.Lock()
					agent.ApiDetails.Addrs = addrs
					agent.ApiDetails.Port = port
					agent.ApiDetails.Host = targetName
					// agent.ApiDetails.SvcbRR = svcbrr // the svcb is hard to marshal into json
					agent.mu.Unlock()
				}()
			}

			agent.mu.RLock()
			tmpniluri = agent.DnsDetails.UriRR == nil
			tmpaddrs = agent.DnsDetails.Addrs
			agent.mu.RUnlock()
			if tmpniluri && len(tmpaddrs) == 0 {
				go func() {
					_, addrs, port, targetName, err := FetchSVCB(agent.DnsDetails.BaseUri, resolvers, timeout, retries)
					if err != nil {
						log.Printf("LocateAgent: error fetching SVCB for %s: %v", agent.DnsDetails.BaseUri, err)
						return
					}

					agent.mu.Lock()
					agent.DnsDetails.Addrs = addrs
					agent.DnsDetails.Port = port
					agent.DnsDetails.Host = targetName
					// agent.DnsDetails.SvcbRR = svcbrr // the svcb is hard to marshal into json
					agent.mu.Unlock()
				}()
			}

			// Only proceed with KEY if we have the target name
			agent.mu.RLock()
			tmpnilkey := agent.DnsDetails.KeyRR == nil
			tmphost := agent.DnsDetails.Host
			agent.mu.RUnlock()
			if tmpnilkey && tmphost != "" {
				go func() {
					// Look up KEY
					rrset, err := RecursiveDNSQueryWithServers(dns.Fqdn(tmphost), dns.TypeKEY, timeout, retries, resolvers)
					if err != nil {
						log.Printf("LocateAgent: error response to KEY query: %v", err)
						return
					}

					if rrset == nil {
						log.Printf("LocateAgent: no KEY record found for %s", tmphost)
						return
					}

					for _, rr := range rrset.RRs {
						if k, ok := rr.(*dns.KEY); ok {
							log.Printf("LocateAgent: KEY record for %q:\n%s", agent.Identity, k.String())
							agent.mu.Lock()
							agent.DnsDetails.KeyRR = k
							agent.DnsMethod = true
							agent.mu.Unlock()
						}
					}
				}()
			}

			// Only proceed with TLSA if we have the target name
			agent.mu.RLock()
			tmpniltlsa := agent.ApiDetails.TlsaRR == nil
			tmpport := agent.ApiDetails.Port
			tmphost = agent.ApiDetails.Host
			agent.mu.RUnlock()
			if tmpniltlsa && tmphost != "" {
				go func() {
					// Look up TLSA
					tlsaName := fmt.Sprintf("_%d._tcp.%s", tmpport, tmphost)
					rrset, err := RecursiveDNSQueryWithServers(dns.Fqdn(tlsaName), dns.TypeTLSA, timeout, retries, resolvers)
					if err != nil {
						log.Printf("LocateAgent: error response to TLSA query: %v", err)
						return
					}

					if rrset == nil {
						log.Printf("LocateAgent: no TLSA record found for %s", tlsaName)
						return
					}

					for _, rr := range rrset.RRs {
						if t, ok := rr.(*dns.TLSA); ok {
							log.Printf("LocateAgent: TLSA record for %q:\n%s", agent.Identity, t.String())
							agent.mu.Lock()
							agent.ApiDetails.TlsaRR = t
							agent.ApiMethod = true
							agent.mu.Unlock()
						}
					}
				}()
			}

			// Check if API transport details are complete
			agent.mu.Lock()
			// tmpurirrr = agent.ApiDetails.UriRR
			//tmptlsarr = agent.ApiDetails.TlsaRR
			tmpaddrs = agent.ApiDetails.Addrs

			if agent.ApiDetails.UriRR != nil && agent.ApiDetails.TlsaRR != nil && len(agent.ApiDetails.Addrs) > 0 {
				agent.ApiDetails.ContactInfo = "complete"
				agent.ApiDetails.State = AgentStateKnown
				agent.ApiMethod = true
				log.Printf("LocateAgent: API transport details for remote agent %s are complete", remoteid)
			}

			if agent.DnsDetails.UriRR != nil && agent.DnsDetails.KeyRR != nil && len(agent.DnsDetails.Addrs) > 0 {
				agent.DnsDetails.ContactInfo = "complete"
				agent.DnsDetails.State = AgentStateKnown
				agent.DnsMethod = true
				log.Printf("LocateAgent: DNS transport details for remote agent %s are complete", remoteid)
			}
			agent.mu.Unlock()

			// Update agent state based on available methods
			agent.mu.RLock()
			tmpstate := agent.ApiDetails.State
			agent.mu.RUnlock()
			if tmpstate == AgentStateKnown {
				agent.mu.Lock()
				agent.State = AgentStateKnown
				agent.LastState = time.Now()
				agent.mu.Unlock()

				err := agent.NewAgentSyncApiClient(ar.LocalAgent)
				if err != nil {
					log.Printf("LocateAgent: error creating API client for remote agent %s: %v", remoteid, err)
					agent.mu.Lock()
					agent.State = AgentStateError
					agent.ErrorMsg = fmt.Sprintf("error creating API client: %v", err)
					agent.LastState = time.Now()
					agent.mu.Unlock()
				}
				agent.Api.ApiClient.Debug = false // disable debug logging for API client

				// Agent is now known, update and exit the loop
				ar.S.Set(remoteid, agent)
				log.Printf("LocateAgent: remote agent %s is now KNOWN, stopping retry loop", remoteid)

				// If we're in known state and have a zone, try to send hello
				if zonename != "" {
					ar.AddZoneToAgent(remoteid, zonename)

					// Create a new context for this hello retrier
					ctx, cancel := context.WithCancel(context.Background())

					// Store the cancel function
					ar.mu.Lock()
					if existingCancel, exists := ar.helloContexts[remoteid]; exists {
						existingCancel() // Cancel any existing hello retrier
					}
					ar.helloContexts[remoteid] = cancel
					ar.mu.Unlock()

					// Start the hello retrier with the new context
					go ar.HelloRetrierNG(ctx, agent)
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

func FetchSVCB(baseurl string, resolvers []string, timeout time.Duration,
	retries int) (*dns.SVCB, []string, uint16, string, error) {
	parsedUri, err := url.Parse(baseurl)
	if err != nil {
		log.Printf("LocateAgent: failed to parse URI target %q: %v", baseurl, err)
		return nil, nil, 0, "", err
	}

	targetName, _, err := net.SplitHostPort(parsedUri.Host)
	if err != nil {
		targetName = parsedUri.Host
	}

	rrset, err := RecursiveDNSQueryWithServers(dns.Fqdn(targetName), dns.TypeSVCB, timeout, retries, resolvers)
	if err != nil {
		log.Printf("LocateAgent: error response to SVCB query: %v", err)
		return nil, nil, 0, "", err
	}

	// Process SVCB response
	if rrset == nil {
		log.Printf("LocateAgent: response to %s SVCB contained zero RRs", targetName)
		return nil, nil, 0, "", fmt.Errorf("response to %s SVCB contained zero RRs", targetName)
	}

	var addrs []string
	var port uint16
	var svcbrr *dns.SVCB

	if len(rrset.RRs) == 0 {
		return nil, nil, 0, "", fmt.Errorf("response to %s SVCB contained zero RRs", targetName)
	}

	for _, rr := range rrset.RRs {
		if svcb, ok := rr.(*dns.SVCB); ok {
			log.Printf("LocateAgent: SVCB record for %q:\n%s", targetName, svcb.String())
			svcbrr = svcb
			// Process SVCB record (addresses and port)
			for _, kv := range svcb.Value {
				switch kv.Key() {
				case dns.SVCB_IPV4HINT:
					ipv4Hints := kv.(*dns.SVCBIPv4Hint)
					for _, ip := range ipv4Hints.Hint {
						addrs = append(addrs, ip.String())
					}
				case dns.SVCB_IPV6HINT:
					ipv6Hints := kv.(*dns.SVCBIPv6Hint)
					for _, ip := range ipv6Hints.Hint {
						addrs = append(addrs, ip.String())
					}
				case dns.SVCB_PORT:
					tmpPort := kv.(*dns.SVCBPort)
					port = uint16(tmpPort.Port)
				}
			}
		}
	}
	return svcbrr, addrs, port, targetName, nil
}

// Create a new synchronous function for code that needs immediate results
func (ar *AgentRegistry) GetAgentInfo(identity AgentId) (*Agent, error) {
	// Skip if this is our own identity
	if ar.LocalAgent.Identity != "" && string(identity) == ar.LocalAgent.Identity {
		return nil, fmt.Errorf("cannot get info for self as remote agent")
	}

	// Check if we already know this agent
	agent, exists := ar.S.Get(identity)
	if !exists {
		return nil, fmt.Errorf("agent %s not found", identity)
	}

	return agent, nil
}

// IdentifyAgents looks for HSYNC records in a zone and identifies agents we need to sync with
func (ar *AgentRegistry) xxxIdentifyAgents(zd *ZoneData, ourIdentity AgentId) ([]*Agent, error) {
	var agents []*Agent

	rrset, err := zd.GetRRset(zd.ZoneName, TypeHSYNC)
	if err != nil {
		return nil, fmt.Errorf("error getting HSYNC records: %v", err)
	}

	// Look for HSYNC records where Target is NOT our identity
	for _, rr := range rrset.RRs {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync, ok := prr.Data.(*HSYNC); ok {
				if hsync.Identity == string(ourIdentity) {
					continue
				}
				// Found another agent, try to locate it
				ar.LocateAgent(AgentId(hsync.Identity), "", nil)
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
func (ar *AgentRegistry) AddRemoteAgent(zonename ZoneName, agent *Agent) {
	ar.mu.Lock()
	defer ar.mu.Unlock()
	if ar.RemoteAgents[zonename] == nil {
		ar.RemoteAgents[zonename] = make([]AgentId, 0)
	}
	if !slices.Contains(ar.RemoteAgents[zonename], agent.Identity) {
		ar.RemoteAgents[zonename] = append(ar.RemoteAgents[zonename], agent.Identity)
	}
}

// RemoveRemoteAgent removes an agent from the list of remote agents for a zone
func (ar *AgentRegistry) RemoveRemoteAgent(zonename ZoneName, identity AgentId) {
	ar.mu.Lock()
	defer ar.mu.Unlock()

	// Remove from remoteAgents
	agentids := ar.RemoteAgents[zonename]
	for i, a := range agentids {
		if a == identity {
			ar.RemoteAgents[zonename] = append(agentids[:i], agentids[i+1:]...)
			break
		}
	}

	// Clean up zone association in agent
	if agent, exists := ar.S.Get(identity); exists {
		delete(agent.Zones, zonename)
		ar.S.Set(identity, agent)
	}
}

type ZoneAgentData struct {
	ZoneName      ZoneName
	Agents        []*Agent
	MyUpstream    AgentId
	MyDownstreams []AgentId
}

// GetRemoteAgents returns a list of remote agents for a zone. It does not
// check if the agents are operational, or try to get missing information.
// func (ar *AgentRegistry) GetRemoteAgents(zonename ZoneName) ([]*Agent, error) {
func (ar *AgentRegistry) GetZoneAgentData(zonename ZoneName) (*ZoneAgentData, error) {
	var zad = &ZoneAgentData{
		ZoneName: zonename,
	}

	agents := []*Agent{}

	ar.mu.RLock()
	defer ar.mu.RUnlock()
	log.Printf("GetZoneAgentData: zone %s has %d remote agents", zonename, len(ar.RemoteAgents[zonename]))

	zd, exists := Zones.Get(string(zonename))
	if !exists {
		log.Printf("GetZoneAgentData: zone %q is unknown", zonename)
		return nil, fmt.Errorf("zone %q is unknown", zonename)
	}

	apex, err := zd.GetOwner(string(zonename))
	if err != nil {
		log.Printf("GetZoneAgentData: error getting apex for zone %q: %v", zonename, err)
		return nil, fmt.Errorf("error getting apex for zone %q: %v", zonename, err)
	}

	hsyncRRset := apex.RRtypes.GetOnlyRRSet(TypeHSYNC)
	if len(hsyncRRset.RRs) == 0 {
		log.Printf("GetZoneAgentData: zone %q has no HSYNC RRset", zonename)
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
					zad.MyUpstream = AgentId(hsync.Upstream)
					continue // don't add ourselves to the list of agents
				} else if hsync.Upstream == ar.LocalAgent.Identity {
					zad.MyDownstreams = append(zad.MyDownstreams, AgentId(hsync.Identity))
				}
				// Found an HSYNC record, try to locate the agent
				agent, err := ar.GetAgentInfo(AgentId(hsync.Identity))
				if err != nil {
					agent = &Agent{
						Identity:  AgentId(hsync.Identity),
						State:     AgentStateError,
						ErrorMsg:  fmt.Sprintf("error getting agent info: %v", err),
						LastState: time.Now(),
					}
				}
				agents = append(agents, agent)
			}
		}
	}

	zad.Agents = agents
	return zad, nil
}

// CleanupZoneRelationships handles the complex cleanup when we're no longer involved in a zone's management
func (ar *AgentRegistry) CleanupZoneRelationships(zonename ZoneName) {
	// TODO: Implement cleanup:
	// 1. Remove zone from all agents that have it
	// 2. Remove all agents from remoteAgents[zonename]
	// 3. For any agent that no longer shares zones with us:
	//    - Send GOODBYE message
	//    - Remove from registry
	log.Printf("TODO: Implement cleanup for zone %s", zonename)
}

// UpdateAgents updates the registry based on the HSYNC records in the request. It has been
// split into "adds" and "removes" by zd.HsyncCHanged() so we can process them independently.

// XXX: This is likely not sufficient, we must also be able to deal with HSYNC RRs that simply
// "change" (i.e. the same identity, but now roles). ADD+REMOVE doesn't deal with that.
func (ar *AgentRegistry) UpdateAgents(ourId AgentId, req SyncRequest, zonename ZoneName, synchedDataUpdateQ chan *SynchedDataUpdate) error {

	var updatedIdentities = map[AgentId]bool{}
	// Handle new HSYNC records
	for _, rr := range req.SyncStatus.HsyncAdds {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync, ok := prr.Data.(*HSYNC); ok {
				log.Printf("UpdateAgents: Zone %s: analysing HSYNC: %q", zonename, hsync.String())

				updatedIdentities[AgentId(hsync.Identity)] = true
				if AgentId(hsync.Identity) == ourId {
					// We're the Target
					if hsync.Upstream == "." {
						// Special case: no upstream to sync with
						log.Printf("UpdateAgents: Zone %s: we are target but upstream is '.', no sync needed", zonename)
						continue
					}

					// Need to sync with Upstream - do this asynchronously
					ar.LocateAgent(AgentId(hsync.Upstream), zonename,
						&DeferredAgentTask{
							Precondition: func() bool {
								if agent, exists := ar.S.Get(AgentId(hsync.Upstream)); exists {
									return agent.ApiDetails.State == AgentStateOperational
								}
								return false
							},
							Action: func() (bool, error) {
								log.Printf("UpdateAgents: Executing deferred action (waited for agent %q to be operational): Zone %q: sending RFI for upstream data from %q", hsync.Upstream, zonename, hsync.Upstream)
								amp := AgentMgmtPost{
									MessageType: AgentMsgRfi,
									RfiType:     "UPSTREAM",
									Zone:        zonename,
									Upstream:    AgentId(hsync.Upstream),
								}

								ar.CommandHandler(&AgentMgmtPostPlus{amp, nil}, synchedDataUpdateQ)
								return true, nil // cannot do much else
							},
							Desc: fmt.Sprintf("RFI for upstream data from %q", hsync.Upstream),
						})
				} else if AgentId(hsync.Upstream) == ourId {
					// Need to sync with Upstream - do this asynchronously
					ar.LocateAgent(AgentId(hsync.Identity), zonename,
						&DeferredAgentTask{
							// XXX: This is not complete, as there is no check for the Precondition
							// XXX: some sort of periodic check is needed to ensure that the agent is still
							// operational.
							Precondition: func() bool {
								if agent, exists := ar.S.Get(AgentId(hsync.Identity)); exists {
									return agent.State == AgentStateOperational
								}
								return false
							},
							Action: func() (bool, error) {
								log.Printf("UpdateAgents: Executing deferred action (waited for agent %q to be operational): Zone %q: sending RFI for downstream data from %q", hsync.Identity, zonename, hsync.Identity)
								amp := AgentMgmtPost{
									MessageType: AgentMsgRfi,
									RfiType:     "DOWNSTREAM",
									Zone:        zonename,
									Downstream:  AgentId(hsync.Identity),
								}

								ar.CommandHandler(&AgentMgmtPostPlus{amp, nil}, synchedDataUpdateQ)
								return true, nil // cannot do much else
							},
							Desc: fmt.Sprintf("RFI for downstream data from %q", hsync.Identity),
						})

				} else {
					log.Printf("UpdateAgents: Zone %s: HSYNC is for a remote agent, %q, analysing", zonename, hsync.Identity)
					// Not our target, locate agent asynchronously
					ar.LocateAgent(AgentId(hsync.Identity), zonename, nil)
				}
			}
		}
	}

	// Handle removed HSYNC records
	for _, rr := range req.SyncStatus.HsyncRemoves {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync, ok := prr.Data.(*HSYNC); ok {
				if updatedIdentities[AgentId(hsync.Identity)] {
					// Don't remove an agent that's still in the HSYNC RRset; it has only changed
					log.Printf("UpdateAgents: Zone %q: not removing agent %q, HSYNC RR changed", zonename, hsync.Identity)
					continue
				}
				if AgentId(hsync.Identity) == ourId {
					// We're no longer involved in this zone's management
					log.Printf("UpdateAgents: Zone %q: we (%q) are no longer part of the HSYNC RRset, cleaning up", zonename, hsync.Identity)
					ar.CleanupZoneRelationships(zonename)
				} else {
					// Remote agent was removed, update registry
					log.Printf("UpdateAgents: Zone %q: agent %q is no longer part of HSYNC RRset, cleaning up", zonename, hsync.Identity)
					if agent, exists := ar.S.Get(AgentId(hsync.Identity)); exists {
						delete(agent.Zones, zonename)
						ar.RemoveRemoteAgent(zonename, AgentId(hsync.Identity))
					}
				}
			}
		}
	}

	return nil
}

// XXX: The DeferredAgentTask functions are not yet fully thought out (and not in use yet).
func (agent *Agent) AddDeferredAgentTask(task *DeferredAgentTask) {
	agent.DeferredTasks = append(agent.DeferredTasks, *task)
}

func (agent *Agent) CreateOperationalAgentTask(action func() (bool, error), desc string) *DeferredAgentTask {
	return &DeferredAgentTask{
		Precondition: func() bool {
			return agent.State == AgentStateOperational
		},
		Action: action,
		Desc:   desc,
	}
}

func (agent *Agent) CreateAgentUpstreamRFI() *DeferredAgentTask {
	return &DeferredAgentTask{
		Desc: "Create Upstream RFI",
		Precondition: func() bool {
			return agent.State == AgentStateOperational
		},
		Action: func() (bool, error) {
			log.Printf("CreateAgentUpstreamRFI: Sending RFI to upstream agent %q (NYI)", agent.Identity)
			return true, nil
		},
	}
}

func (agent *Agent) MarshalJSON() ([]byte, error) {
	// Create a temporary struct without non-JSON-friendly fields
	type AgentJSON struct {
		Identity    AgentId
		InitialZone ZoneName
		ApiMethod   bool
		DnsMethod   bool
		Zones       map[ZoneName]bool
		State       AgentState
		LastState   time.Time
		ErrorMsg    string
	}

	aj := AgentJSON{
		Identity:    agent.Identity,
		InitialZone: agent.InitialZone,
		ApiMethod:   agent.ApiMethod,
		DnsMethod:   agent.DnsMethod,
		Zones:       agent.Zones,
		State:       agent.State,
		LastState:   agent.LastState,
		ErrorMsg:    agent.ErrorMsg,
	}

	log.Printf("Using local agent.MarshalJSON() function for agent %q: %+v", agent.Identity, aj)
	return json.Marshal(aj)
}
