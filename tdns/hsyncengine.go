package tdns

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/miekg/dns"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/spf13/viper"
)

type SyncRequest struct {
	Command    string
	ZoneName   string
	ZoneData   *ZoneData
	SyncStatus *HsyncStatus
	OldDnskeys *RRset
	NewDnskeys *RRset
	Response   chan SyncResponse
}

type SyncResponse struct {
	Status   bool
	Error    bool
	ErrorMsg string
	Msg      string
}

type AgentBeatReport struct {
	Beat  *AgentBeat
	Agent *Agent
}

type AgentBeat struct {
	MessageType string // "HELLO", "BEAT", or "FULLBEAT"
	Identity    string
	Timestamp   time.Time
}

type SyncStatus struct {
	Identity string
	Agents   map[string]*Agent
	Error    bool
	Response chan SyncStatus
}

type Agents struct {
	S cmap.ConcurrentMap[string, *Agent]
}

// Define task struct for deferred operations
type DeferredTask struct {
	Action      string
	Target      string
	ZoneName    string
	RetryCount  int
	MaxRetries  int
	LastAttempt time.Time
}

func HsyncEngine(conf *Config, stopch chan struct{}) {
	ourId := conf.Agent.Identity

	registry := conf.Internal.Registry
	registry.LocalIdentity = ourId // Make sure registry knows our identity

	// wannabe_agents is a map of agents that we have received
	// a HELLO message from, but have not yet verified
	wannabe_agents := make(map[string]*Agent)

	// syncedZones maps zone names to the agents that share them with us
	syncedZones := map[string][]*Agent{}

	var syncitem SyncRequest
	syncQ := conf.Internal.SyncQ

	var beatReport AgentBeatReport
	beatQ := make(chan AgentBeatReport, 10)
	conf.Internal.HeartbeatQ = beatQ

	conf.Internal.SyncStatusQ = make(chan SyncStatus, 10)

	if !viper.GetBool("syncengine.active") {
		log.Printf("HsyncEngine is NOT active. No detection of communication with other agents will be done.")
		for range syncQ {
			syncitem = <-syncQ
			log.Printf("HsyncEngine: NOT active, but received a sync request: %+v", syncitem)
			continue
		}
	}

	// Configure intervals
	helloEvalInterval := configureInterval("syncengine.intervals.helloeval", 300, 1800)
	heartbeatInterval := configureInterval("syncengine.intervals.heartbeat", 15, 1800)
	fullHeartbeatInterval := configureInterval("syncengine.intervals.fullheartbeat", 60, 3600)

	log.Printf("Starting HsyncEngine (heartbeat will run once every %d seconds)", heartbeatInterval)

	HelloEvalTicker := time.NewTicker(time.Duration(helloEvalInterval) * time.Second)
	HBticker := time.NewTicker(time.Duration(heartbeatInterval) * time.Second)
	fullHBticker := time.NewTicker(time.Duration(fullHeartbeatInterval) * time.Second)

	// Add ticker for incomplete agent checks
	incompleteAgentTicker := time.NewTicker(30 * time.Second)

	for {
		select {
		case syncitem = <-syncQ:
			registry.HandleSyncRequest(ourId, wannabe_agents, syncitem)

		case beatReport = <-beatQ:
			registry.HandleBeatReport(beatReport, wannabe_agents)

		case <-HBticker.C:
			registry.SendHeartbeats()

		case <-fullHBticker.C:
			registry.SendFullHeartbeats()

		case <-HelloEvalTicker.C:
			registry.EvaluateHellos(wannabe_agents, syncedZones)

		case req := <-conf.Internal.SyncStatusQ:
			registry.HandleStatusRequest(req)

		case <-stopch:
			log.Printf("HsyncEngine shutting down")
			// stop all tickers
			HelloEvalTicker.Stop()
			HBticker.Stop()
			fullHBticker.Stop()
			incompleteAgentTicker.Stop()
			return
		}
	}
}

func configureInterval(key string, min, max int) int {
	interval := viper.GetInt(key)
	if interval > max {
		interval = max
	}
	if interval < min {
		interval = min
	}
	viper.Set(key, interval)
	return interval
}

func (ar *AgentRegistry) HandleSyncRequest(ourId string, wannabe_agents map[string]*Agent, req SyncRequest) {
	log.Printf("*** handleSyncRequest: enter (zone %q)", req.ZoneName)
	switch req.Command {
	case "HSYNC-UPDATE":
		log.Printf("HsyncEngine: Zone %s HSYNC RRset has changed. Updating sync group.", req.ZoneName)
		// Run UpdateAgents without waiting for completion
		go func() {
			err := ar.UpdateAgents(ourId, wannabe_agents, req, req.ZoneName)
			if err != nil {
				log.Printf("HsyncEngine: Error updating agents: %v", err)
			}
			// Send response if needed
			if req.Response != nil {
				req.Response <- SyncResponse{
					Status: err == nil,
					Error:  err != nil,
					ErrorMsg: func() string {
						if err != nil {
							return err.Error()
						}
						return ""
					}(),
					Msg: "Agent updates processed",
				}
			}
		}()

	case "SYNC-DNSKEY-RRSET":
		log.Printf("HsyncEngine: Zone %s DNSKEY RRset has changed. Should send NOTIFY(DNSKEY) to other agents.",
			req.ZoneName)

		if req.NewDnskeys != nil {
			for _, rr := range req.NewDnskeys.RRs {
				// process the record
				_ = rr // TODO: process the record
			}
		}

	default:
		log.Printf("HsyncEngine: Unknown command: %s", req.Command)
	}
}

func (ar *AgentRegistry) HandleBeatReport(report AgentBeatReport, wannabe_agents map[string]*Agent) {
	log.Printf("HsyncEngine: Received heartbeat from %s", report.Beat.Identity)

	switch report.Beat.MessageType {
	case "HELLO":
		log.Printf("HsyncEngine: Received initial hello from %s", report.Beat.Identity)
		// Store in wannabe_agents until we verify it shares zones with us
		wannabe_agents[report.Beat.Identity] = report.Agent

	case "BEAT":
		log.Printf("HsyncEngine: Received heartbeat from %s", report.Beat.Identity)
		if agent, exists := ar.S.Get(report.Beat.Identity); exists {
			for transport := range report.Agent.Details {
				newDetails := agent.Details[transport]
				newDetails.LastHB = time.Now()
				agent.Details[transport] = newDetails
			}
		}

	case "FULLBEAT":
		log.Printf("HsyncEngine: Received full heartbeat from %s", report.Beat.Identity)
		if agent, exists := ar.S.Get(report.Beat.Identity); exists {
			for transport, details := range report.Agent.Details {
				newDetails := details
				newDetails.LastHB = time.Now()
				agent.Details[transport] = newDetails
			}
		}
	}
}

func (ar *AgentRegistry) SendHeartbeats() {
	log.Printf("HsyncEngine: Sending heartbeats to known agents")
	for _, agent := range ar.S.Items() {
		err := agent.SendBeat("BEAT")
		if err != nil {
			log.Printf("HsyncEngine: Error sending heartbeat to %s: %v", agent.Identity, err)
		}
	}
}

func (ar *AgentRegistry) SendFullHeartbeats() {
	log.Printf("HsyncEngine: Sending full heartbeats to known agents")
	for _, agent := range ar.S.Items() {
		err := agent.SendBeat("FULLBEAT")
		if err != nil {
			log.Printf("HsyncEngine: Error sending full heartbeat to %s: %v", agent.Identity, err)
		}
	}
}

func (ar *AgentRegistry) EvaluateHellos(wannabe_agents map[string]*Agent, syncedZones map[string][]*Agent) {
	log.Printf("HsyncEngine: Evaluating agents that claim to share zones with us")

	for identity, wannabe := range wannabe_agents {
		// Check if this agent appears in any of our synced zones
		found := false
		for zonename, zoneAgents := range syncedZones {
			for _, agent := range zoneAgents {
				if agent.Identity == identity {
					found = true
					ar.S.Set(identity, wannabe)
					delete(wannabe_agents, identity)
					log.Printf("HsyncEngine: Confirmed agent %s shares zone %s with us", identity, zonename)
					break
				}
			}
			if found {
				break
			}
		}

		if !found {
			log.Printf("HsyncEngine: Agent %s does not share any zones with us", identity)
		}
	}
}

func (ar *AgentRegistry) HandleStatusRequest(req SyncStatus) {
	log.Printf("HsyncEngine: Received STATUS request")
	if req.Response == nil {
		log.Printf("HsyncEngine: STATUS request has no response channel")
		return
	}

	// Get current agents without waiting for any pending operations
	agents := map[string]*Agent{}
	for _, agent := range ar.S.Items() {
		// Make a clean copy of the agent for the response
		copy := *agent // Shallow copy
		agents[agent.Identity] = &copy
	}

	// Send the response immediately with a timeout to avoid blocking
	select {
	case req.Response <- SyncStatus{
		Agents:   agents,
		Identity: ar.LocalIdentity,
		Error:    false,
	}:
	case <-time.After(1 * time.Second): // Don't block forever
		log.Printf("HsyncEngine: STATUS response timed out")
	}
}

func (agent *Agent) SendBeat(beatType string) error {
	beat := &AgentBeat{
		MessageType: beatType,
		Identity:    agent.Identity,
		Timestamp:   time.Now(),
	}

	// Try API first, fall back to DNS if needed
	if agent.Methods["api"] {
		err := agent.sendBeatHTTPS(beat)
		if err == nil {
			return nil
		}
		log.Printf("API beat to %s failed: %v, trying DNS", agent.Identity, err)
	}

	if agent.Methods["dns"] {
		return agent.sendBeatDNS(beat)
	}

	return fmt.Errorf("no valid transport method available for agent %s", agent.Identity)
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

				if hsync.Target == ourId {
					// We're the Target
					if hsync.Upstream == "." {
						// Special case: no upstream to sync with
						log.Printf("UpdateAgents: Zone %s: we are target but upstream is '.', no sync needed", zonename)
						continue
					}

					// Need to sync with Upstream - do this asynchronously
					ar.LocateAgent(hsync.Upstream, zonename)
				} else {
					log.Printf("UpdateAgents: Zone %s: HSYNC is for a remote agent, %q, analysing", zonename, hsync.Target)
					// Not our target, locate agent asynchronously
					ar.LocateAgent(hsync.Target, zonename)
				}
			}
		}
	}

	// Handle removed HSYNC records
	for _, rr := range req.SyncStatus.HsyncRemoves {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync, ok := prr.Data.(*HSYNC); ok {
				if hsync.Target == ourId {
					// We're no longer involved in this zone's management
					ar.CleanupZoneRelationships(zonename)
				} else {
					// Remote agent was removed, update registry
					if agent, exists := ar.S.Get(hsync.Target); exists {
						for transport := range agent.Details {
							if agent.Details[transport].Zones != nil {
								delete(agent.Details[transport].Zones, zonename)
							}
						}
						ar.RemoveRemoteAgent(zonename, hsync.Target)
					}
				}
			}
		}
	}

	return nil
}

// Helper methods for SendBeat
func (agent *Agent) sendBeatHTTPS(beat *AgentBeat) error {
	if agent.Api == nil {
		return fmt.Errorf("no API client configured for agent %s", agent.Identity)
	}

	status, _, err := agent.Api.RequestNG("POST", "/beat", beat, false)
	if err != nil {
		return fmt.Errorf("HTTPS beat failed: %v", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("HTTPS beat returned status %d", status)
	}

	return nil
}

func (agent *Agent) sendBeatDNS(beat *AgentBeat) error {
	// TODO: Implement DNS-based heartbeat
	// This would involve creating a signed DNS message
	// containing the heartbeat information
	return fmt.Errorf("DNS transport not yet implemented")
}

// ... additional helper functions ...
