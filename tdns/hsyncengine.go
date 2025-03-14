package tdns

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

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

type SyncStatus struct {
	Identity string
	Agents   map[string]*Agent
	Error    bool
	Response chan SyncStatus
}

// type Agents struct {
//	S cmap.ConcurrentMap[string, *Agent]
//}

// Define task struct for deferred operations
type DeferredTask struct {
	Action      string
	Target      string
	ZoneName    string
	RetryCount  int
	MaxRetries  int
	LastAttempt time.Time
}

func HsyncEngine(conf *Config, helloQ <-chan AgentMsgReport, heartbeatQ <-chan AgentMsgReport, stopch chan struct{}) {
	ourId := conf.Agent.Identity

	registry := conf.Internal.Registry
	registry.LocalAgent.Identity = ourId // Make sure registry knows our identity

	// wannabe_agents is a map of agents that we have received
	// a HELLO message from, but have not yet verified
	wannabe_agents := make(map[string]*Agent)

	// syncedZones maps zone names to the agents that share them with us
	syncedZones := map[string][]*Agent{}

	var syncitem SyncRequest
	syncQ := conf.Internal.SyncQ

	var msgReport AgentMsgReport
	//msgQ := make(chan AgentMsgReport, 10)
	// conf.Internal.HeartbeatQ = msgQ

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
	// fullHeartbeatInterval := configureInterval("syncengine.intervals.fullheartbeat", 60, 3600)

	log.Printf("Starting HsyncEngine (heartbeat will run once every %d seconds)", heartbeatInterval)

	HelloEvalTicker := time.NewTicker(time.Duration(helloEvalInterval) * time.Second)
	HBticker := time.NewTicker(time.Duration(heartbeatInterval) * time.Second)
	// XXX: Unclear whether we need a separate "full" heartbeat
	// fullHBticker := time.NewTicker(time.Duration(fullHeartbeatInterval) * time.Second)

	// Add ticker for incomplete agent checks
	incompleteAgentTicker := time.NewTicker(30 * time.Second)

	for {
		select {
		case syncitem = <-syncQ:
			registry.SyncRequestHandler(ourId, wannabe_agents, syncitem)

		case msgReport = <-helloQ:
			registry.HelloHandler(msgReport, wannabe_agents)

		case msgReport = <-heartbeatQ:
			registry.HeartbeatHandler(msgReport, wannabe_agents)

		case <-HBticker.C:
			registry.SendHeartbeats()

		// case <-fullHBticker.C:
		// 	registry.SendFullHeartbeats()

		case <-HelloEvalTicker.C:
			registry.EvaluateHellos(wannabe_agents, syncedZones)

		case req := <-conf.Internal.SyncStatusQ:
			registry.HandleStatusRequest(req)

		case <-stopch:
			log.Printf("HsyncEngine shutting down")
			// stop all tickers
			HelloEvalTicker.Stop()
			HBticker.Stop()
			//fullHBticker.Stop()
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

func (ar *AgentRegistry) SyncRequestHandler(ourId string, wannabe_agents map[string]*Agent, req SyncRequest) {
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

func (ar *AgentRegistry) HelloHandler(report AgentMsgReport, wannabe_agents map[string]*Agent) {
	// log.Printf("HelloHandler: Received HELLO from %s", report.Msg.Identity)

	switch report.Msg.MessageType {
	case "HELLO":
		log.Printf("HelloHandler: Received initial HELLO from %s", report.Msg.Identity)
		// Store in wannabe_agents until we verify it shares zones with us
		// wannabe_agents[report.Msg.Identity] = report.Agent

	default:
		log.Printf("HelloHandler: Unknown message type: %s", report.Msg.MessageType)
	}
}

func (ar *AgentRegistry) HeartbeatHandler(report AgentMsgReport, wannabe_agents map[string]*Agent) {
	// log.Printf("HeartbeatHandler: Received %s from %s", report.Msg.MessageType, report.Msg.Identity)

	switch report.Msg.MessageType {
	case "BEAT":
		log.Printf("HeartbeatHandler: Received BEAT from %s", report.Msg.Identity)
		if agent, exists := ar.S.Get(report.Msg.Identity); exists {
			//dump.P(report)
			newDetails := agent.Details[report.Transport]
			newDetails.LatestRBeat = time.Now()
			newDetails.ReceivedBeats++
			agent.Details[report.Transport] = newDetails
		}

	case "FULLBEAT":
		log.Printf("HeartbeatHandler: Received FULLBEAT from %s", report.Msg.Identity)
		if agent, exists := ar.S.Get(report.Msg.Identity); exists {
			newDetails := agent.Details[report.Transport]
			newDetails.LatestRBeat = time.Now()
			newDetails.ReceivedBeats++
			agent.Details[report.Transport] = newDetails
		}

	default:
		log.Printf("HeartbeatHandler: Unknown message type: %s", report.Msg.MessageType)
	}
}

func (ar *AgentRegistry) SendHeartbeats() {
	log.Printf("HsyncEngine: Sending heartbeats to known agents")
	for _, agent := range ar.S.Items() {
		switch agent.State {
		case AgentStateHelloOK, AgentStateOperational:
			log.Printf("HsyncEngine: Sending heartbeat to %s", agent.Identity)
		default:
			log.Printf("HsyncEngine: Skipping heartbeat to %s (state %s)", agent.Identity, AgentStateToString[agent.State])
			continue
		}
		status, resp, err := agent.SendApiMsg(&AgentMsgPost{
			MessageType: "BEAT",
			Identity:    ar.LocalAgent.Identity,
			Zone:        "",
		})
		details := agent.Details["api"]
		switch {
		case err != nil:
			log.Printf("HsyncEngine: Error sending heartbeat to %s: %v", agent.Identity, err)
			details.LatestError = err.Error()

		case status != http.StatusOK:
			log.Printf("HsyncEngine: Heartbeat to %s returned status %d", agent.Identity, status)
			details.LatestError = fmt.Sprintf("status %d", status)

		default:
			var amr AgentMsgResponse
			err = json.Unmarshal(resp, &amr)
			if err != nil {
				log.Printf("HsyncEngine: Error unmarshalling heartbeat response: %v", err)
				details.LatestError = err.Error()
			}
			if amr.Status == "ok" {
				details.State = AgentStateOperational
				details.LatestSBeat = time.Now()
				details.LatestError = ""
				details.SentBeats++
			}
		}
		agent.Details["api"] = details
	}
}

// func (ar *AgentRegistry) SendFullHeartbeats() {
// 	log.Printf("HsyncEngine: Sending full heartbeats to known agents")
// 	for _, agent := range ar.S.Items() {
// 		status, resp, err := agent.SendApiMsg(&AgentMsgPost{
// 			MessageType: "FULLBEAT",
// 			Identity:    agent.Identity,
//			Zone:        "",
//		})
//		if err != nil {
//			log.Printf("HsyncEngine: Error sending full heartbeat to %s: %v", agent.Identity, err)
//		}
//		if status != http.StatusOK {
// 			log.Printf("HsyncEngine: Full heartbeat to %s returned status %d", agent.Identity, status)
// 		}
// 	}
// }

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
		Identity: ar.LocalAgent.Identity,
		Error:    false,
	}:
	case <-time.After(1 * time.Second): // Don't block forever
		log.Printf("HsyncEngine: STATUS response timed out")
	}
}

func (agent *Agent) SendMsg(msgType, zone string) ([]byte, error) {
	msg := &AgentMsgPost{
		MessageType: msgType,
		Identity:    agent.Identity,
		Zone:        zone,
		Time:        time.Now(),
	}

	// Try API first, fall back to DNS if needed
	if agent.Methods["api"] {
		status, resp, err := agent.SendApiMsg(msg)
		if err == nil && status == http.StatusOK {
			return resp, nil
		}
		log.Printf("API beat to %q failed: status: %d, error: %v, trying DNS", agent.Identity, status, err)
	}

	if agent.Methods["dns"] {
		_, resp, err := agent.SendDnsMsg(msg)
		if err == nil {
			return resp, nil
		}
		log.Printf("DNS beat to %s failed: %v", agent.Identity, err)
	}

	return nil, fmt.Errorf("no valid transport method available for agent %s", agent.Identity)
}

// Helper methods for SendBeat
func (agent *Agent) SendApiMsg(msg *AgentMsgPost) (int, []byte, error) {
	if agent.Api == nil {
		return 0, nil, fmt.Errorf("no API client configured for agent %s", agent.Identity)
	}

	status, resp, err := agent.Api.ApiClient.RequestNG("POST", "/beat", msg, false)
	if err != nil {
		return 0, nil, fmt.Errorf("HTTPS beat failed: %v", err)
	}
	if status != http.StatusOK {
		return 0, nil, fmt.Errorf("HTTPS beat returned status %d (%s)", status, http.StatusText(status))
	}

	return status, resp, nil
}

func (agent *Agent) SendApiHello(msg *AgentMsgPost) (int, []byte, error) {
	if agent.Api == nil {
		return 0, nil, fmt.Errorf("no API client configured for agent %s", agent.Identity)
	}

	status, resp, err := agent.Api.ApiClient.RequestNG("POST", "/hello", msg, false)
	if err != nil {
		return 0, nil, fmt.Errorf("API hello failed: %v", err)
	}
	if status != http.StatusOK {
		return 0, nil, fmt.Errorf("API hello returned status %d (%s)", status, http.StatusText(status))
	}

	return status, resp, nil
}

func (agent *Agent) SendDnsMsg(msg *AgentMsgPost) (int, []byte, error) {
	// TODO: Implement DNS-based heartbeat
	// This would involve creating a signed DNS message
	// containing the heartbeat information
	return 0, nil, fmt.Errorf("DNS transport not yet implemented")
}
