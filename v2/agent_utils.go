/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"slices"
	"time"

	"github.com/johanix/tdns/v2/agent/transport"
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

var lgAgent = Logger("agent")

func (ar *AgentRegistry) AddZoneToAgent(identity AgentId, zone ZoneName) {
	agent, exists := ar.S.Get(identity)
	if !exists {
		return
	}

	agent.mu.Lock()
	defer agent.mu.Unlock()

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

// RecomputeSharedZonesAndSyncState updates an agent's shared zones and transitions between
// OPERATIONAL and LEGACY states based on zone count.
// This should be called after HSYNC changes to keep agent state synchronized with zone membership.
func (ar *AgentRegistry) RecomputeSharedZonesAndSyncState(agent *Agent) {
	agent.mu.Lock()
	defer agent.mu.Unlock()

	zoneCount := len(agent.Zones)
	oldState := agent.State

	// State transitions based on zone count
	if zoneCount == 0 && (oldState == AgentStateOperational || oldState == AgentStateIntroduced) {
		// Transition to LEGACY when zones go to zero
		agent.State = AgentStateLegacy
		agent.LastState = time.Now()
		lgAgent.Info("agent transitioned to LEGACY (no shared zones)",
			"agent", agent.Identity, "from", AgentStateToString[oldState])
	} else if zoneCount > 0 && oldState == AgentStateLegacy {
		// Transition back to OPERATIONAL when zones are re-added
		agent.State = AgentStateOperational
		agent.LastState = time.Now()
		lgAgent.Info("agent transitioned LEGACY to OPERATIONAL",
			"agent", agent.Identity, "zones", zoneCount)
	}

	// Sync zones to peer in PeerRegistry (updates cached SharedZones)
	if ar.TransportManager != nil {
		peer := ar.TransportManager.PeerRegistry.GetOrCreate(string(agent.Identity))

		// Clear existing shared zones
		peer.SharedZones = make(map[string]*transport.ZoneRelation)

		// Re-add all zones from agent
		for zone := range agent.Zones {
			peer.AddSharedZone(string(zone), "", "")
		}

		lgAgent.Debug("synced zones to peer", "zones", zoneCount, "peer", agent.Identity)
	}
}

func (conf *Config) NewAgentRegistry() *AgentRegistry {
	if conf.Agent.Identity == "" {
		lgAgent.Error("identity is empty")
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
		S:              core.NewStringer[AgentId, *Agent](),
		RemoteAgents:   make(map[ZoneName][]AgentId),
		LocalAgent:     conf.Agent,
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
//
// DEPRECATED: This function has critical concurrency issues (see docs/locateagent-review-findings.md).
// It will be replaced by the refactored discovery mechanism using common helpers from
// agent_discovery_common.go. Keep this implementation for backward compatibility until
// the migration is complete.
func (ar *AgentRegistry) LocateAgent(remoteid AgentId, zonename ZoneName, deferredTask *DeferredAgentTask) {
	lgAgent.Debug("looking up agent", "agent", remoteid)

	// Skip if this is our own identity
	if ar.LocalAgent.Identity != "" && string(remoteid) == ar.LocalAgent.Identity {
		lgAgent.Debug("skipping self-identification", "agent", remoteid)
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

	lgAgent.Debug("looking up agent for zone", "agent", remoteid, "zone", zonename)

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
			lgAgent.Debug("using resolver", "address", resolverAddress)
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
						lgAgent.Error("URI query failed", "qname", qname, "err", err)
						return
					}

					if rrset == nil {
						lgAgent.Debug("no URI record found", "qname", qname)
						return
					}

					for _, rr := range rrset.RRs {
						if u, ok := rr.(*dns.URI); ok {
							lgAgent.Debug("URI record found", "record", u.String())
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
						lgAgent.Error("URI query failed", "qname", qname, "err", err)
						return
					}

					if rrset == nil {
						lgAgent.Debug("no URI record found", "qname", qname)
						return
					}

					for _, rr := range rrset.RRs {
						if u, ok := rr.(*dns.URI); ok {
							lgAgent.Debug("URI record found", "agent", agent.Identity, "record", u.String())
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
						lgAgent.Error("SVCB fetch failed", "baseuri", agent.ApiDetails.BaseUri, "err", err)
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
						lgAgent.Error("SVCB fetch failed", "baseuri", agent.DnsDetails.BaseUri, "err", err)
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
			// TODO: Migrate to JWK lookup using lookupAgentJWK() from agent_discovery_common.go
			// This is a legacy fallback mechanism - new code should use JWK records
			agent.mu.RLock()
			tmpnilkey := agent.DnsDetails.KeyRR == nil
			tmphost := agent.DnsDetails.Host
			agent.mu.RUnlock()
			if tmpnilkey && tmphost != "" {
				go func() {
					// Look up KEY (legacy)
					rrset, err := RecursiveDNSQueryWithServers(dns.Fqdn(tmphost), dns.TypeKEY, timeout, retries, resolvers)
					if err != nil {
						lgAgent.Error("KEY query failed", "err", err)
						return
					}

					if rrset == nil {
						lgAgent.Debug("no KEY record found", "host", tmphost)
						return
					}

					for _, rr := range rrset.RRs {
						if k, ok := rr.(*dns.KEY); ok {
							lgAgent.Debug("KEY record found", "agent", agent.Identity, "record", k.String())
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
						lgAgent.Error("TLSA query failed", "err", err)
						return
					}

					if rrset == nil {
						lgAgent.Debug("no TLSA record found", "name", tlsaName)
						return
					}

					for _, rr := range rrset.RRs {
						if t, ok := rr.(*dns.TLSA); ok {
							lgAgent.Debug("TLSA record found", "agent", agent.Identity, "record", t.String())
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

			if agent.ApiDetails.UriRR != nil && agent.ApiDetails.TlsaRR != nil && len(agent.ApiDetails.Addrs) > 0 {
				agent.ApiDetails.ContactInfo = "complete"
				agent.ApiDetails.State = AgentStateKnown
				agent.ApiMethod = true
				lgAgent.Info("API transport details complete", "agent", remoteid)
			}

			if agent.DnsDetails.UriRR != nil && agent.DnsDetails.KeyRR != nil && len(agent.DnsDetails.Addrs) > 0 {
				agent.DnsDetails.ContactInfo = "complete"
				agent.DnsDetails.State = AgentStateKnown
				agent.DnsMethod = true
				lgAgent.Info("DNS transport details complete", "agent", remoteid)
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
					lgAgent.Error("failed to create API client", "agent", remoteid, "err", err)
					agent.mu.Lock()
					agent.State = AgentStateError
					agent.ErrorMsg = fmt.Sprintf("error creating API client: %v", err)
					agent.LastState = time.Now()
					agent.mu.Unlock()
				} else if agent.Api != nil {
					agent.Api.ApiClient.Debug = false // disable debug logging for API client
				}

				// Agent is now known, update and exit the loop
				ar.S.Set(remoteid, agent)
				lgAgent.Info("remote agent is now KNOWN, stopping retry loop", "agent", remoteid)

				if ar.TransportManager != nil {
					ar.TransportManager.OnAgentDiscoveryComplete(agent)
				}

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
				lgAgent.Debug("remote agent not operational, will retry", "agent", remoteid, "interval", ar.LocateInterval)
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
		lgAgent.Error("failed to parse URI target", "url", baseurl, "err", err)
		return nil, nil, 0, "", err
	}

	targetName, _, err := net.SplitHostPort(parsedUri.Host)
	if err != nil {
		targetName = parsedUri.Host
	}

	rrset, err := RecursiveDNSQueryWithServers(dns.Fqdn(targetName), dns.TypeSVCB, timeout, retries, resolvers)
	if err != nil {
		lgAgent.Error("SVCB query failed", "err", err)
		return nil, nil, 0, "", err
	}

	// Process SVCB response
	if rrset == nil {
		lgAgent.Warn("SVCB response contained zero RRs", "target", targetName)
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
			lgAgent.Debug("SVCB record found", "target", targetName, "record", svcb.String())
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

// MarkAgentAsNeeded creates a placeholder agent in NEEDED state.
// The agent will be discovered asynchronously by DiscoveryRetrierNG in HsyncEngine.
// This is the new recommended pattern for agent discovery triggered by HSYNC updates.
//
// Parameters:
//   - remoteid: The agent identity to mark as needed
//   - zonename: Optional zone name to associate with the agent
//   - deferredTask: Optional task to execute when agent becomes OPERATIONAL
func (ar *AgentRegistry) MarkAgentAsNeeded(remoteid AgentId, zonename ZoneName, deferredTask *DeferredAgentTask) {
	// Skip self-identification
	if ar.LocalAgent.Identity != "" && string(remoteid) == ar.LocalAgent.Identity {
		lgAgent.Debug("skipping self-identification", "agent", remoteid)
		return
	}

	// Check if agent already exists
	agent, exists := ar.S.Get(remoteid)
	if exists {
		// Already discovered - just associate zone
		if zonename != "" {
			ar.AddZoneToAgent(remoteid, zonename)
		}
		if deferredTask != nil {
			agent.DeferredTasks = append(agent.DeferredTasks, *deferredTask)
			ar.S.Set(remoteid, agent)
		}
		lgAgent.Debug("agent already exists", "agent", remoteid,
			"apiState", AgentStateToString[agent.ApiDetails.State],
			"dnsState", AgentStateToString[agent.DnsDetails.State])
		return
	}

	// Create placeholder agent in NEEDED state
	agent = &Agent{
		Identity:   remoteid,
		ApiDetails: &AgentDetails{State: AgentStateNeeded},
		DnsDetails: &AgentDetails{State: AgentStateNeeded},
		Zones:      make(map[ZoneName]bool),
		State:      AgentStateNeeded,
		LastState:  time.Now(),
	}

	// Mark both transports as needing discovery (will be refined during discovery)
	agent.ApiMethod = true
	agent.DnsMethod = true

	if zonename != "" {
		agent.Zones[zonename] = true
	}

	if deferredTask != nil {
		agent.DeferredTasks = append(agent.DeferredTasks, *deferredTask)
	}

	ar.S.Set(remoteid, agent)
	lgAgent.Info("marked agent as NEEDED", "agent", remoteid, "zone", zonename)

	// Trigger immediate discovery instead of waiting for DiscoveryRetrierNG tick
	if imr := Conf.Internal.ImrEngine; imr != nil {
		lgAgent.Debug("triggering immediate discovery", "agent", remoteid)
		go ar.attemptDiscovery(agent, imr, true, true)
	} else {
		lgAgent.Debug("IMR not ready, will be discovered by DiscoveryRetrierNG", "agent", remoteid)
	}
}

// attemptDiscovery performs a single discovery attempt for an agent.
// Called by DiscoveryRetrierNG for agents in NEEDED state.
// discoverAPI and discoverDNS control which transports are discovered,
// avoiding wasteful DNS lookups for transports already past NEEDED.
// On success, transitions agent from NEEDED → KNOWN and starts HelloRetrierNG.
// On failure, agent remains in NEEDED state for retry next interval.
func (ar *AgentRegistry) attemptDiscovery(agent *Agent, imr *Imr, discoverAPI, discoverDNS bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	lgAgent.Debug("attempting discovery", "agent", agent.Identity, "api", discoverAPI, "dns", discoverDNS)

	result := &AgentDiscoveryResult{Identity: string(agent.Identity)}

	if discoverAPI {
		DiscoverAgentAPI(ctx, imr, string(agent.Identity), result)
	}
	if discoverDNS {
		DiscoverAgentDNS(ctx, imr, string(agent.Identity), result)
	}

	// Check if we got anything useful from the transports we discovered
	if result.APIUri == "" && result.DNSUri == "" {
		agent.mu.Lock()
		agent.ApiDetails.LatestError = "no contact endpoints found"
		agent.ApiDetails.LatestErrorTime = time.Now()
		agent.mu.Unlock()
		lgAgent.Warn("discovery failed, will retry", "agent", agent.Identity, "reason", "no contact endpoints found")
		return
	}

	// Register discovered agent
	if ar.TransportManager != nil {
		err := ar.TransportManager.RegisterDiscoveredAgent(result)
		if err != nil {
			agent.mu.Lock()
			agent.ApiDetails.LatestError = err.Error()
			agent.ApiDetails.LatestErrorTime = time.Now()
			agent.mu.Unlock()
			lgAgent.Warn("registration failed, will retry", "agent", agent.Identity, "err", err)
			return
		}
	}

	// SUCCESS: Discovery complete. Contact info updated.
	lgAgent.Info("discovery successful", "agent", agent.Identity,
		"apiState", AgentStateToString[agent.ApiDetails.State],
		"dnsState", AgentStateToString[agent.DnsDetails.State])

	// Two-stage check:
	// 1. Did discovery produce any useful result? (any transport at KNOWN or beyond)
	// 2. Does any transport actually need Hello? (exactly at KNOWN state)
	//
	// On re-discovery, a transport may already be OPERATIONAL (preserved by
	// RegisterDiscoveredAgent). That's fine — it means Hello already succeeded.
	// We only start HelloRetrierNG if a transport is exactly at KNOWN.
	agent.mu.RLock()
	apiUseful := agent.ApiMethod && agent.ApiDetails.State >= AgentStateKnown
	dnsUseful := agent.DnsMethod && agent.DnsDetails.State >= AgentStateKnown
	apiNeedsHello := agent.ApiMethod && agent.ApiDetails.State == AgentStateKnown
	dnsNeedsHello := agent.DnsMethod && agent.DnsDetails.State == AgentStateKnown
	agent.mu.RUnlock()

	if !apiUseful && !dnsUseful {
		lgAgent.Debug("no transports at KNOWN or beyond, skipping HelloRetrierNG", "agent", agent.Identity)
		return
	}

	if !apiNeedsHello && !dnsNeedsHello {
		lgAgent.Debug("already past KNOWN state, no Hello needed", "agent", agent.Identity,
			"apiState", AgentStateToString[agent.ApiDetails.State],
			"dnsState", AgentStateToString[agent.DnsDetails.State])
		return
	}

	// Cancel any existing HelloRetrierNG for this agent before starting a new one
	ar.mu.Lock()
	if existingCancel, exists := ar.helloContexts[agent.Identity]; exists {
		lgAgent.Debug("cancelling existing Hello retry loop", "agent", agent.Identity)
		existingCancel()
	}
	ar.mu.Unlock()

	helloCtx, helloCancel := context.WithCancel(context.Background())
	ar.mu.Lock()
	ar.helloContexts[agent.Identity] = helloCancel
	ar.mu.Unlock()
	go ar.HelloRetrierNG(helloCtx, agent)
	lgAgent.Debug("started Hello retry loop", "agent", agent.Identity)
}

// DiscoverAgentAsync marks an agent as NEEDED for discovery by DiscoveryRetrierNG.
//
// DEPRECATED: This function is now a thin wrapper around MarkAgentAsNeeded() for backward compatibility.
// New code should call MarkAgentAsNeeded() directly instead.
//
// The old immediate discovery behavior has been replaced with a retry-based approach:
// - Agents are marked as NEEDED
// - DiscoveryRetrierNG continuously retries discovery until success
// - Eliminates IMR race conditions and handles transient failures
// - Provides infinite retry with backoff (consistent with Hello/Beat mechanisms)
//
// Parameters:
//   - remoteid: The agent identity to discover
//   - zonename: Optional zone name to associate with the agent
//   - deferredTask: Optional task to execute when agent becomes operational
func (ar *AgentRegistry) DiscoverAgentAsync(remoteid AgentId, zonename ZoneName, deferredTask *DeferredAgentTask) {
	lgAgent.Debug("deprecated wrapper, marking agent as NEEDED", "agent", remoteid)

	// Skip if this is our own identity
	if ar.LocalAgent.Identity != "" && string(remoteid) == ar.LocalAgent.Identity {
		lgAgent.Debug("skipping self-identification", "agent", remoteid)
		return
	}

	// Delegate to new unified discovery path
	ar.MarkAgentAsNeeded(remoteid, zonename, deferredTask)
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

func AgentToString(a *Agent) string {
	if a == nil {
		return "<nil>"
	}
	return string(a.Identity)
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
	lgAgent.Debug("getting zone agent data", "zone", zonename, "remoteAgents", len(ar.RemoteAgents[zonename]))

	zd, exists := Zones.Get(string(zonename))
	if !exists {
		lgAgent.Warn("zone is unknown", "zone", zonename)
		return nil, fmt.Errorf("zone %q is unknown", zonename)
	}

	apex, err := zd.GetOwner(string(zonename))
	if err != nil {
		lgAgent.Error("error getting apex", "zone", zonename, "err", err)
		return nil, fmt.Errorf("error getting apex for zone %q: %v", zonename, err)
	}

	hsyncRRset := apex.RRtypes.GetOnlyRRSet(core.TypeHSYNC3)
	if len(hsyncRRset.RRs) == 0 {
		lgAgent.Warn("zone has no HSYNC3 RRset", "zone", zonename)
		return nil, fmt.Errorf("zone %q has no HSYNC3 RRset", zonename)
	}

	// Convert the RRs to strings for transmission
	hsyncStrs := make([]string, len(hsyncRRset.RRs))
	for i, rr := range hsyncRRset.RRs {
		hsyncStrs[i] = rr.String()
	}

	// Build label→Identity map so we can resolve Upstream labels to FQDNs
	labelToIdentity := map[string]string{}
	for _, rr := range hsyncRRset.RRs {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if h3, ok := prr.Data.(*core.HSYNC3); ok {
				labelToIdentity[h3.Label] = h3.Identity
			}
		}
	}

	for _, rr := range hsyncRRset.RRs {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync3, ok := prr.Data.(*core.HSYNC3); ok {
				// Skip if this is our own identity
				if hsync3.Identity == ar.LocalAgent.Identity {
					zad.MyUpstream = AgentId(labelToIdentity[hsync3.Upstream])
					continue // don't add ourselves to the list of agents
				} else if labelToIdentity[hsync3.Upstream] == ar.LocalAgent.Identity {
					zad.MyDownstreams = append(zad.MyDownstreams, AgentId(hsync3.Identity))
				}
				// Found an HSYNC3 record, try to locate the agent
				agent, err := ar.GetAgentInfo(AgentId(hsync3.Identity))
				if err != nil {
					agent = &Agent{
						Identity:  AgentId(hsync3.Identity),
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
	lgAgent.Warn("TODO: cleanup not yet implemented", "zone", zonename)
}

// UpdateAgents updates the registry based on the HSYNC3 records in the request. It has been
// split into "adds" and "removes" by zd.HsyncCHanged() so we can process them independently.

// XXX: This is likely not sufficient, we must also be able to deal with HSYNC3 RRs that simply
// "change" (i.e. the same identity, but now roles). ADD+REMOVE doesn't deal with that.
func (ar *AgentRegistry) UpdateAgents(ourId AgentId, req SyncRequest, zonename ZoneName, synchedDataUpdateQ chan *SynchedDataUpdate) error {

	var updatedIdentities = map[AgentId]bool{}  // Tracks modified agents (both add and remove)
	var affectedIdentities = map[AgentId]bool{} // Tracks ALL agents that need zone recomputation

	// Build label→Identity map from HsyncAdds so we can resolve Upstream labels to FQDNs
	labelToIdentity := map[string]string{}
	for _, rr := range req.SyncStatus.HsyncAdds {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if h3, ok := prr.Data.(*core.HSYNC3); ok {
				labelToIdentity[h3.Label] = h3.Identity
			}
		}
	}

	lgAgent.Debug("UpdateAgents: identity resolution", "zone", zonename, "ourId", ourId, "labelToIdentity", labelToIdentity, "hsyncAdds", len(req.SyncStatus.HsyncAdds))

	// First pass: Check if WE are in this zone's HSYNC3 RRset
	// Only process remote agents if we're also involved in this zone
	weAreInHSYNC := false
	for _, rr := range req.SyncStatus.HsyncAdds {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync3, ok := prr.Data.(*core.HSYNC3); ok {
				if AgentId(hsync3.Identity) == ourId || AgentId(labelToIdentity[hsync3.Upstream]) == ourId {
					weAreInHSYNC = true
					break
				}
			}
		}
	}

	if !weAreInHSYNC {
		lgAgent.Debug("we are not in HSYNC3 RRset, ignoring remote agents", "zone", zonename)
		return nil
	}

	// Handle new HSYNC3 records
	for _, rr := range req.SyncStatus.HsyncAdds {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync3, ok := prr.Data.(*core.HSYNC3); ok {
				lgAgent.Debug("analysing HSYNC3", "zone", zonename, "hsync3", hsync3.String())

				updatedIdentities[AgentId(hsync3.Identity)] = true
				affectedIdentities[AgentId(hsync3.Identity)] = true
				upstreamIdentity := AgentId(labelToIdentity[hsync3.Upstream])
				if AgentId(hsync3.Identity) == ourId {
					// We're the Target
					if hsync3.Upstream == "." {
						// Special case: no upstream to sync with
						lgAgent.Debug("we are target but upstream is '.', no sync needed", "zone", zonename)
						continue
					}

					// Need to sync with Upstream - mark as needed for discovery
					ar.MarkAgentAsNeeded(upstreamIdentity, zonename,
						&DeferredAgentTask{
							Precondition: func() bool {
								if agent, exists := ar.S.Get(upstreamIdentity); exists {
									return agent.ApiDetails.State == AgentStateOperational
								}
								return false
							},
							Action: func() (bool, error) {
								lgAgent.Info("executing deferred RFI for upstream data", "upstream", hsync3.Upstream, "zone", zonename)
								amp := AgentMgmtPost{
									MessageType: AgentMsgRfi,
									RfiType:     "CONFIG",
									RfiSubtype:  "upstream",
									Zone:        zonename,
									Upstream:    upstreamIdentity,
								}

								ar.CommandHandler(&AgentMgmtPostPlus{amp, nil}, synchedDataUpdateQ)
								return true, nil // cannot do much else
							},
							Desc: fmt.Sprintf("RFI for upstream data from %q", hsync3.Upstream),
						})
				} else if upstreamIdentity == ourId {
					// Need to sync with downstream agents - mark as needed for discovery
					ar.MarkAgentAsNeeded(AgentId(hsync3.Identity), zonename,
						&DeferredAgentTask{
							// XXX: This is not complete, as there is no check for the Precondition
							// XXX: some sort of periodic check is needed to ensure that the agent is still
							// operational.
							Precondition: func() bool {
								if agent, exists := ar.S.Get(AgentId(hsync3.Identity)); exists {
									return agent.State == AgentStateOperational
								}
								return false
							},
							Action: func() (bool, error) {
								lgAgent.Info("executing deferred RFI for downstream data", "downstream", hsync3.Identity, "zone", zonename)
								amp := AgentMgmtPost{
									MessageType: AgentMsgRfi,
									RfiType:     "CONFIG",
									RfiSubtype:  "downstream",
									Zone:        zonename,
									Downstream:  AgentId(hsync3.Identity),
								}

								ar.CommandHandler(&AgentMgmtPostPlus{amp, nil}, synchedDataUpdateQ)
								return true, nil // cannot do much else
							},
							Desc: fmt.Sprintf("RFI for downstream data from %q", hsync3.Identity),
						})

				} else {
					lgAgent.Debug("HSYNC3 is for a remote agent, analysing", "zone", zonename, "agent", hsync3.Identity)
					// Not our target, mark as needed for discovery
					ar.MarkAgentAsNeeded(AgentId(hsync3.Identity), zonename, nil)
				}
			}
		}
	}

	// Handle removed HSYNC3 records
	for _, rr := range req.SyncStatus.HsyncRemoves {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync3, ok := prr.Data.(*core.HSYNC3); ok {
				affectedIdentities[AgentId(hsync3.Identity)] = true
				if updatedIdentities[AgentId(hsync3.Identity)] {
					// Don't remove an agent that's still in the HSYNC3 RRset; it has only changed
					lgAgent.Debug("not removing agent, HSYNC3 RR changed", "zone", zonename, "agent", hsync3.Identity)
					continue
				}
				if AgentId(hsync3.Identity) == ourId {
					// We're no longer involved in this zone's management
					lgAgent.Info("we are no longer part of the HSYNC3 RRset, cleaning up", "zone", zonename, "identity", hsync3.Identity)
					ar.CleanupZoneRelationships(zonename)
				} else {
					// Remote agent was removed, update registry
					lgAgent.Info("agent no longer in HSYNC3 RRset, cleaning up", "zone", zonename, "agent", hsync3.Identity)
					if agent, exists := ar.S.Get(AgentId(hsync3.Identity)); exists {
						agent.mu.Lock()
						delete(agent.Zones, zonename)
						agent.mu.Unlock()
						ar.RemoveRemoteAgent(zonename, AgentId(hsync3.Identity))
					}
				}
			}
		}
	}

	// Recompute shared zones for all affected agents and handle OPERATIONAL ↔ LEGACY transitions
	for identity := range affectedIdentities {
		if agent, exists := ar.S.Get(identity); exists && identity != ourId {
			ar.RecomputeSharedZonesAndSyncState(agent)
		}
	}

	// Trigger leader election if HSYNC3 RRset changed and we have a leader election manager.
	// Only count operational peers — an election with non-operational peers is pointless
	// (messages won't reach them, leading to split elections where both agents win).
	if len(updatedIdentities) > 0 && ar.LeaderElectionManager != nil {
		zad, err := ar.GetZoneAgentData(zonename)
		if err == nil {
			operationalPeers := 0
			for _, agent := range zad.Agents {
				if agent.Identity != AgentId(ar.LocalAgent.Identity) && agent.IsAnyTransportOperational() {
					operationalPeers++
				}
			}
			if operationalPeers > 0 {
				ar.LeaderElectionManager.StartElection(zonename, operationalPeers)
			} else {
				lgAgent.Debug("deferring leader election, no operational peers yet", "zone", zonename)
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
			lgAgent.Info("sending RFI to upstream agent (NYI)", "agent", agent.Identity)
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

	lgAgent.Debug("using local agent MarshalJSON", "agent", agent.Identity)
	return json.Marshal(aj)
}
