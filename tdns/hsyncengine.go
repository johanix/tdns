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
	Agents   map[string]*Agent
	Error    bool
	Response chan SyncStatus
}

type Agents struct {
	S cmap.ConcurrentMap[string, *Agent]
}

func HsyncEngine(conf *Config, stopch chan struct{}) {
	ourId := conf.Agent.Identity

	registry := conf.Internal.Registry

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
		log.Printf("HSyncEngine is NOT active. No detection of communication with other agents will be done.")
		for range syncQ {
			log.Printf("HSyncEngine: NOT active, but received a sync request: %+v", syncitem)
			continue
		}
	}

	// Configure intervals
	helloEvalInterval := configureInterval("syncengine.intervals.helloeval", 300, 1800)
	heartbeatInterval := configureInterval("syncengine.intervals.heartbeat", 15, 1800)
	fullHeartbeatInterval := configureInterval("syncengine.intervals.fullheartbeat", 60, 3600)

	log.Printf("Starting HSyncEngine (heartbeat will run once every %d seconds)", heartbeatInterval)

	HelloEvalTicker := time.NewTicker(time.Duration(helloEvalInterval) * time.Second)
	HBticker := time.NewTicker(time.Duration(heartbeatInterval) * time.Second)
	fullHBticker := time.NewTicker(time.Duration(fullHeartbeatInterval) * time.Second)

	for {
		select {
		case syncitem = <-syncQ:
			handleSyncRequest(registry, ourId, wannabe_agents, syncitem)

		case beatReport = <-beatQ:
			handleBeatReport(beatReport, registry, wannabe_agents)

		case <-HBticker.C:
			sendHeartbeats(registry)

		case <-fullHBticker.C:
			sendFullHeartbeats(registry)

		case <-HelloEvalTicker.C:
			evaluateHellos(registry, wannabe_agents, syncedZones)

		case req := <-conf.Internal.SyncStatusQ:
			handleStatusRequest(req, registry)

		case <-stopch:
			HBticker.Stop()
			fullHBticker.Stop()
			HelloEvalTicker.Stop()
			log.Println("HSyncEngine: stop signal received.")
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

func handleSyncRequest(registry *AgentRegistry, ourId string, wannabe_agents map[string]*Agent, req SyncRequest) {
	switch req.Command {
	case "HSYNC-UPDATE":
		log.Printf("HSyncEngine: Zone %s HSYNC RRset has changed. Updating sync group.", req.ZoneName)
		err := registry.UpdateAgents(ourId, wannabe_agents, req, req.ZoneName)
		if err != nil {
			log.Printf("HSyncEngine: Error updating agents: %v", err)
		}

	case "SYNC-DNSKEY-RRSET":
		log.Printf("HSyncEngine: Zone %s DNSKEY RRset has changed. Should send NOTIFY(DNSKEY) to other agents.",
			req.ZoneName)

		if req.NewDnskeys != nil {
			for _, rr := range req.NewDnskeys.RRs {
				// process the record
				_ = rr // TODO: process the record
			}
		}

	default:
		log.Printf("HSyncEngine: Unknown command: %s", req.Command)
	}
}

func handleBeatReport(report AgentBeatReport, registry *AgentRegistry, wannabe_agents map[string]*Agent) {
	log.Printf("HSyncEngine: Received heartbeat from %s", report.Beat.Identity)

	switch report.Beat.MessageType {
	case "HELLO":
		log.Printf("HSyncEngine: Received initial hello from %s", report.Beat.Identity)
		// Store in wannabe_agents until we verify it shares zones with us
		wannabe_agents[report.Beat.Identity] = report.Agent

	case "BEAT":
		log.Printf("HSyncEngine: Received heartbeat from %s", report.Beat.Identity)
		if agent, exists := registry.S.Get(report.Beat.Identity); exists {
			for transport := range report.Agent.Details {
				newDetails := agent.Details[transport]
				newDetails.LastHB = time.Now()
				agent.Details[transport] = newDetails
			}
		}

	case "FULLBEAT":
		log.Printf("HSyncEngine: Received full heartbeat from %s", report.Beat.Identity)
		if agent, exists := registry.S.Get(report.Beat.Identity); exists {
			for transport, details := range report.Agent.Details {
				newDetails := details
				newDetails.LastHB = time.Now()
				agent.Details[transport] = newDetails
			}
		}
	}
}

func sendHeartbeats(registry *AgentRegistry) {
	log.Printf("HSyncEngine: Sending heartbeats to known agents")
	for _, agent := range registry.S.Items() {
		err := agent.SendBeat("BEAT")
		if err != nil {
			log.Printf("HSyncEngine: Error sending heartbeat to %s: %v", agent.Identity, err)
		}
	}
}

func sendFullHeartbeats(registry *AgentRegistry) {
	log.Printf("HSyncEngine: Sending full heartbeats to known agents")
	for _, agent := range registry.S.Items() {
		err := agent.SendBeat("FULLBEAT")
		if err != nil {
			log.Printf("HSyncEngine: Error sending full heartbeat to %s: %v", agent.Identity, err)
		}
	}
}

func evaluateHellos(registry *AgentRegistry, wannabe_agents map[string]*Agent, syncedZones map[string][]*Agent) {
	log.Printf("HSyncEngine: Evaluating agents that claim to share zones with us")

	for identity, wannabe := range wannabe_agents {
		// Check if this agent appears in any of our synced zones
		found := false
		for zonename, zoneAgents := range syncedZones {
			for _, agent := range zoneAgents {
				if agent.Identity == identity {
					found = true
					registry.S.Set(identity, wannabe)
					delete(wannabe_agents, identity)
					log.Printf("HSyncEngine: Confirmed agent %s shares zone %s with us", identity, zonename)
					break
				}
			}
			if found {
				break
			}
		}

		if !found {
			log.Printf("HSyncEngine: Agent %s does not share any zones with us", identity)
		}
	}
}

func handleStatusRequest(req SyncStatus, registry *AgentRegistry) {
	log.Printf("HSyncEngine: Received STATUS request")
	if req.Response == nil {
		log.Printf("HSyncEngine: STATUS request has no response channel")
		return
	}

	cleaned := map[string]*Agent{}
	for _, agent := range registry.S.Items() {
		cleaned[agent.Identity] = agent.CleanCopy()
	}

	select {
	case req.Response <- SyncStatus{
		Agents: cleaned,
		Error:  false,
	}:
	case <-time.After(5 * time.Second):
		log.Printf("HSyncEngine: STATUS response timed out")
	}
}

func (agent *Agent) SendBeat(beatType string) error {
	beat := &AgentBeat{
		MessageType: beatType,
		Identity:    agent.Identity,
		Timestamp:   time.Now(),
	}

	// Try HTTPS first, fall back to DNS if needed
	if agent.Methods["https"] {
		err := agent.sendBeatHTTPS(beat)
		if err == nil {
			return nil
		}
		log.Printf("HTTPS beat to %s failed: %v, trying DNS", agent.Identity, err)
	}

	if agent.Methods["dns"] {
		return agent.sendBeatDNS(beat)
	}

	return fmt.Errorf("no valid transport method available for agent %s", agent.Identity)
}

func (ar *AgentRegistry) UpdateAgents(ourId string, wannabe_agents map[string]*Agent,
	req SyncRequest, zonename string) error {

	// Handle new HSYNC records
	for _, rr := range req.SyncStatus.HsyncAdds {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync, ok := prr.Data.(*HSYNC); ok {
				if hsync.Target == ourId {
					// We're the Target
					if hsync.Upstream == "." {
						// Special case: no upstream to sync with
						log.Printf("UpdateAgents: Zone %s: we are target but upstream is '.', no sync needed", zonename)
						continue
					}

					// Need to sync with Upstream
					new, agent, err := ar.LocateAgent(hsync.Upstream)
					if err != nil {
						log.Printf("UpdateAgents: Error locating agent %s: %v", hsync.Upstream, err)
						continue
					}

					if new {
						// Send HELLO to new agent
						err = agent.SendBeat("HELLO")
						if err != nil {
							log.Printf("UpdateAgents: Error sending HELLO to %s: %v", hsync.Upstream, err)
							continue
						}
					}

					ar.AddRemoteAgent(zonename, agent)
					ar.AddZoneToAgent(agent.Identity, zonename)

				} else {
					// Not our target, but register the agent in our registry
					_, agent, err := ar.LocateAgent(hsync.Target)
					if err != nil {
						log.Printf("UpdateAgents: Error locating remote agent %s: %v", hsync.Target, err)
						continue
					}
					ar.AddRemoteAgent(zonename, agent)
					ar.AddZoneToAgent(agent.Identity, zonename)
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
					// Schedule a cleanup of our relationships for this zone
					go ar.CleanupZoneRelationships(zonename)
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
