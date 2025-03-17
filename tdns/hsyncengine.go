package tdns

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/viper"
)

type SyncRequest struct {
	Command    string
	ZoneName   ZoneName
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
	Identity AgentId
	Agents   map[AgentId]*Agent
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

func HsyncEngine(conf *Config, agentQs AgentQs, stopch chan struct{}) {
	ourId := AgentId(conf.Agent.Identity)

	helloQ := agentQs.Hello
	heartbeatQ := agentQs.Beat
	msgQ := agentQs.Msg
	commandQ := agentQs.Command
	debugCommandQ := agentQs.DebugCommand
	combinerUpdateQ := agentQs.CombinerUpdate
	registry := conf.Internal.Registry
	registry.LocalAgent.Identity = string(ourId) // Make sure registry knows our identity

	// wannabe_agents is a map of agents that we have received
	// a HELLO message from, but have not yet verified
	wannabe_agents := make(map[AgentId]*Agent)

	// syncedZones maps zone names to the agents that share them with us
	syncedZones := map[ZoneName][]*Agent{}

	var syncitem SyncRequest
	syncQ := conf.Internal.SyncQ

	var msgReport *AgentMsgReport
	var mgmtPost *AgentMgmtPostPlus
	// var debugPost *AgentDebugPost
	// msgQ := make(chan AgentMsgReport, 10)
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
	helloEvalInterval := configureInterval("syncengine.intervals.helloeval", 15, 1800)
	helloRetryInterval := configureInterval("syncengine.intervals.helloretry", 15, 1800)
	// heartbeatInterval := configureInterval("syncengine.intervals.heartbeat", 15, 1800)
	heartbeatInterval := configureInterval("agent.remote.beatinterval", 15, 1800)
	// fullHeartbeatInterval := configureInterval("syncengine.intervals.fullheartbeat", 60, 3600)

	log.Printf("*** HsyncEngine starting (heartbeat will run once every %d seconds) ***", heartbeatInterval)

	HelloEvalTicker := time.NewTicker(time.Duration(helloEvalInterval) * time.Second)
	HBticker := time.NewTicker(time.Duration(heartbeatInterval) * time.Second)
	HelloRetryTicker := time.NewTicker(time.Duration(helloRetryInterval) * time.Second)
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

		case msgReport = <-msgQ:
			registry.MsgHandler(msgReport, combinerUpdateQ)

		case mgmtPost = <-commandQ:
			registry.CommandHandler(mgmtPost)

		// debug stuff arrive on separate channel, but use the same format and handler
		case mgmtPost = <-debugCommandQ:
			registry.CommandHandler(mgmtPost)

		case <-HelloRetryTicker.C:
			registry.HelloRetrier()

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

func (ar *AgentRegistry) SyncRequestHandler(ourId AgentId, wannabe_agents map[AgentId]*Agent, req SyncRequest) {
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

func (ar *AgentRegistry) HelloHandler(report *AgentMsgReport, wannabe_agents map[AgentId]*Agent) {
	log.Printf("HelloHandler: Received HELLO from %s", report.Identity)

	switch report.MessageType {
	case "HELLO":
		log.Printf("HelloHandler: Received initial HELLO from %s", report.Identity)
		// Store in wannabe_agents until we verify it shares zones with us
		// wannabe_agents[report.Msg.Identity] = report.Agent

	default:
		log.Printf("HelloHandler: Unknown message type: %s", report.MessageType)
	}
}

func (ar *AgentRegistry) HeartbeatHandler(report *AgentMsgReport, wannabe_agents map[AgentId]*Agent) {
	// log.Printf("HeartbeatHandler: Received %s from %s", report.Msg.MessageType, report.Msg.Identity)

	switch report.MessageType {
	case "BEAT":
		log.Printf("HeartbeatHandler: Received BEAT from %s", report.Identity)
		if agent, exists := ar.S.Get(report.Identity); exists {
			agent.ApiDetails.LatestRBeat = time.Now()
			agent.ApiDetails.ReceivedBeats++
		}

	case "FULLBEAT":
		log.Printf("HeartbeatHandler: Received FULLBEAT from %s", report.Identity)
		if agent, exists := ar.S.Get(report.Identity); exists {
			agent.ApiDetails.LatestRBeat = time.Now()
			agent.ApiDetails.ReceivedBeats++
		}

	default:
		log.Printf("HeartbeatHandler: Unknown message type: %s", report.MessageType)
	}
}

// Handler for messages received from other agents
func (ar *AgentRegistry) MsgHandler(report *AgentMsgReport, combinerUpdateQ chan *CombUpdate) {
	log.Printf("MsgHandler: Received message from %s: %+v", report.Identity, report.Msg)

	var resp = CombResponse{
		Time: time.Now(),
		Msg:  "Message received",
	}

	defer func() {
		if report.Response != nil {
			select {
			case report.Response <- &resp:
			default:
				log.Printf("MsgHandler: Response channel blocked, skipping response")
			}
		}
	}()

	switch report.MessageType {
	case "NOTIFY", "UPDATE", "MSG":
		if amp, ok := report.Msg.(*AgentMsgPost); ok {
			log.Printf("MsgHandler: Contained AgentMsgPost struct from %s: %+v", amp.MyIdentity, amp)

			var zu = &ZoneUpdate{
				Zone:   report.Zone,
				RRsets: map[uint16]RRset{},
			}
			for _, rrstr := range amp.RRs {
				rr, err := dns.NewRR(rrstr)
				if err != nil {
					log.Printf("MsgHandler: Error parsing RR %q: %v", rrstr, err)
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Error parsing RR %q: %v", rrstr, err)
					return
				}
				var rrset RRset
				var ok bool
				rrtype := rr.Header().Rrtype
				if rrset, ok = zu.RRsets[rrtype]; !ok {
					rrset = RRset{}
				}
				rrset.RRs = append(rrset.RRs, rr)
				zu.RRsets[rrtype] = rrset
				log.Printf("MsgHandler: RR: %s", rr)
			}

			var cresp = make(chan *CombResponse, 1)
			combinerUpdateQ <- &CombUpdate{
				Zone:     amp.Zone,
				AgentId:  amp.MyIdentity,
				Update:   zu,
				Response: cresp,
			}
			select {
			case r := <-cresp:
				if r.Error {
					log.Printf("MsgHandler: Error processing update from %s: %s", amp.MyIdentity, r.ErrorMsg)
					resp.Error = true
					resp.ErrorMsg = r.ErrorMsg
				}
			case <-time.After(2 * time.Second):
				log.Printf("MsgHandler: No response from CombinerUpdaterreceived for update from %s after waiting 2 seconds", amp.MyIdentity)
			}
		}
	}
}

// Handler for local commands from CLI or other components in the same organization
func (ar *AgentRegistry) CommandHandler(msg *AgentMgmtPostPlus) {

	log.Printf("CommandHandler: Received mgmt command: %+v", msg)
	resp := AgentMgmtResponse{
		Time: time.Now(),
		Msg:  "Command received",
	}

	defer func() {
		if msg.Response != nil {
			select {
			case msg.Response <- &resp:
			default:
				log.Printf("CommandHandler: Response channel blocked, skipping response")
			}
		}
	}()

	// Extract zone from message
	if msg.Zone == "" {
		log.Printf("CommandHandler: No zone specified in mgmt command")
		resp.Error = true
		resp.ErrorMsg = "No zone specified in mgmt command"
		return
	}

	for _, rrstr := range msg.RRs {
		rr, err := dns.NewRR(rrstr)
		if err != nil {
			log.Printf("CommandHandler: Error parsing RR: %s", err)
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error parsing RR: %s", err)
			return
		}
		log.Printf("CommandHandler: RR: %s", rr)
	}

	// Find remote agents for this zone
	agents, err := ar.GetRemoteAgents(msg.Zone)
	if err != nil {
		log.Printf("CommandHandler: Error getting remote agents for zone %s: %v", msg.Zone, err)
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("Error getting remote agents for zone %s: %v", msg.Zone, err)
		return
	}
	if len(agents) == 0 {
		log.Printf("CommandHandler: No remote agents found for zone %s", msg.Zone)
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("No remote agents found for zone %s", msg.Zone)
		return
	}

	var errstrs []string

	// Send message to each agent
	for _, agent := range agents {
		status, resp, err := agent.SendApiMsg(&AgentMsgPost{
			MessageType:  msg.MessageType,
			MyIdentity:   AgentId(ar.LocalAgent.Identity),
			YourIdentity: agent.Identity,
			Zone:         msg.Zone,
			RRs:          msg.RRs, // ZoneUpdate
			Time:         time.Now(),
		})

		if err != nil {
			log.Printf("CommandHandler: Error sending message to agent %s: %v", agent.Identity, err)
			errstrs = append(errstrs, fmt.Sprintf("Error sending message to agent %s: %v", agent.Identity, err))
			continue
		}

		if status != http.StatusOK {
			log.Printf("CommandHandler: Message to agent %s returned status %d (%s)", agent.Identity, status, http.StatusText(status))
			errstrs = append(errstrs, fmt.Sprintf("Message to agent %s returned status %d (%s)", agent.Identity, status, http.StatusText(status)))
			continue
		}

		var amr AgentMsgResponse
		err = json.Unmarshal(resp, &amr)
		if err != nil {
			log.Printf("CommandHandler: Error unmarshalling message response: %v", err)
			errstrs = append(errstrs, fmt.Sprintf("Error unmarshalling message response: %v", err))
			continue
		}
		if amr.Status == "ok" {
			log.Printf("CommandHandler: Message to agent %s for zone %s returned status OK: %s", agent.Identity, msg.Zone, amr.Msg)
		} else {
			log.Printf("CommandHandler: Message to agent %s for zone %s returned status %d: %s, ErrorMsg: %s", agent.Identity, msg.Zone, status, amr.Msg, amr.ErrorMsg)
			errstrs = append(errstrs, fmt.Sprintf("Message to agent %s for zone %s returned status %d: %s, ErrorMsg: %s", agent.Identity, msg.Zone, status, amr.Msg, amr.ErrorMsg))
		}
	}
	if len(errstrs) > 0 {
		resp.Error = true
		resp.ErrorMsg = strings.Join(errstrs, "\n")
	}
}

func (ar *AgentRegistry) SendHeartbeats() {
	log.Printf("HsyncEngine: Sending heartbeats to INTRODUCED or OPERATIONAL agents")
	for _, a := range ar.S.Items() {
		switch a.ApiDetails.State {
		case AgentStateIntroduced, AgentStateOperational:
			log.Printf("HsyncEngine: Sending heartbeat to %s", a.Identity)
		default:
			log.Printf("HsyncEngine: Not sending heartbeat to %s (state %s < INTRODUCED)", a.Identity, AgentStateToString[a.State])
			continue
		}

		go func(a *Agent) {
			agent := a
			status, resp, err := agent.SendApiBeat(&AgentBeatPost{
				MessageType:    "BEAT",
				MyIdentity:     AgentId(ar.LocalAgent.Identity),
				YourIdentity:   agent.Identity,
				MyBeatInterval: ar.LocalAgent.Remote.BeatInterval,
				// Zone:        "",
			})
			agent.mu.Lock()
			switch {
			case err != nil:
				log.Printf("HsyncEngine: Error sending heartbeat to %s: %v", agent.Identity, err)
				if agent.ApiDetails.LatestError == "" {
					agent.ApiDetails.LatestError = err.Error()
					agent.ApiDetails.LatestErrorTime = time.Now()
				}

			case status != http.StatusOK:
				log.Printf("HsyncEngine: Heartbeat to %s returned status %d", agent.Identity, status)
				if agent.ApiDetails.LatestError == "" {
					agent.ApiDetails.LatestError = fmt.Sprintf("status %d", status)
					agent.ApiDetails.LatestErrorTime = time.Now()
				}

			default:
				var abr AgentBeatResponse
				err = json.Unmarshal(resp, &abr)
				if err != nil {
					log.Printf("HsyncEngine: Error unmarshalling heartbeat response: %v", err)
					if agent.ApiDetails.LatestError == "" {
						agent.ApiDetails.LatestError = err.Error()
					}
				}
				if abr.Status == "ok" {
					agent.ApiDetails.State = AgentStateOperational
					agent.ApiDetails.LatestSBeat = time.Now()
					agent.ApiDetails.LatestError = ""
					agent.ApiDetails.SentBeats++
				}
			}
			ar.S.Set(agent.Identity, agent)
			agent.mu.Unlock()
		}(a)
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

func (ar *AgentRegistry) HelloRetrier() {
	var known_agents []AgentId
	for _, agent := range ar.S.Items() {
		switch agent.ApiDetails.State {
		case AgentStateKnown:
			known_agents = append(known_agents, agent.Identity)
			go ar.SingleHello(agent)
			// log.Printf("HsyncEngine: Retrying HELLO to %s (state %s)", agent.Identity, AgentStateToString[agent.ApiDetails.State])
		default:
			// log.Printf("HsyncEngine: Not retrying HELLO to %s (state %s != KNOWN)", agent.Identity, AgentStateToString[agent.ApiDetails.State])
			continue
		}
	}
	if len(known_agents) > 0 {
		log.Printf("HsyncEngine: Retried HELLO to %d remote agents in state KNOWN: %v", len(known_agents), known_agents)
	} else {
		log.Printf("HsyncEngine: No remote agents in state KNOWN to retry HELLO to")
	}
}

func (ar *AgentRegistry) SingleHello(agent *Agent) {
	log.Printf("HsyncEngine: Sending HELLO to %s (initial zone %q)", agent.Identity, agent.InitialZone)
	status, resp, err := agent.SendApiHello(&AgentHelloPost{
		MessageType:  "HELLO",
		MyIdentity:   AgentId(ar.LocalAgent.Identity),
		YourIdentity: agent.Identity,
		Zone:         agent.InitialZone,
	})
	agent.mu.Lock()
	switch {
	case err != nil:
		log.Printf("HsyncEngine: Error sending HELLO to %s: %v", agent.Identity, err)
		agent.ApiDetails.LatestError = err.Error()

	case status != http.StatusOK:
		log.Printf("HsyncEngine: HELLO to %s returned status %d", agent.Identity, status)
		agent.ApiDetails.LatestError = fmt.Sprintf("status %d", status)

	default:
		var ahr AgentHelloResponse
		err = json.Unmarshal(resp, &ahr)
		if err != nil {
			log.Printf("HsyncEngine: Error unmarshalling HELLO response: %v", err)
			agent.ApiDetails.LatestError = err.Error()
		}
		log.Printf("HsyncEngine: Our HELLO to %s returned: %s", agent.Identity, ahr.Msg)
		if ahr.Status == "ok" {
			agent.ApiDetails.State = AgentStateIntroduced
			agent.ApiDetails.LatestError = ""
		}
	}
	ar.S.Set(agent.Identity, agent)
	agent.mu.Unlock()
}

func (ar *AgentRegistry) EvaluateHellos(wannabe_agents map[AgentId]*Agent, syncedZones map[ZoneName][]*Agent) {
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

// XXX: Not used at the moment.
func (ar *AgentRegistry) HandleStatusRequest(req SyncStatus) {
	log.Printf("HsyncEngine: Received STATUS request")
	if req.Response == nil {
		log.Printf("HsyncEngine: STATUS request has no response channel")
		return
	}

	// Get current agents without waiting for any pending operations
	agents := map[AgentId]*Agent{}
	for _, agent := range ar.S.Items() {
		// Make a clean copy of the agent for the response
		sanitized := SanitizeForJSON(*agent) // Shallow copy
		if foo, ok := sanitized.(*Agent); ok {
			agents[agent.Identity] = foo
		} else {
			log.Printf("HsyncEngine: Failed to sanitize agent %s for JSON", agent.Identity)
		}
	}

	// Send the response immediately with a timeout to avoid blocking
	select {
	case req.Response <- SyncStatus{
		Agents:   agents,
		Identity: AgentId(ar.LocalAgent.Identity),
		Error:    false,
	}:
	case <-time.After(1 * time.Second): // Don't block forever
		log.Printf("HsyncEngine: STATUS response timed out")
	}
}

// XXX: This is fairly useless.
func (agent *Agent) xxxSendMsg(msgType string, zone ZoneName) ([]byte, error) {
	msg := &AgentMsgPost{
		MessageType: msgType,
		MyIdentity:  agent.Identity,
		Zone:        zone,
		Time:        time.Now(),
	}

	// Try API first, fall back to DNS if needed
	if agent.ApiMethod {
		status, resp, err := agent.SendApiMsg(msg)
		if err == nil && status == http.StatusOK {
			return resp, nil
		}
		log.Printf("API beat to %q failed: status: %d, error: %v, trying DNS", agent.Identity, status, err)
	}

	if agent.DnsMethod {
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

	status, resp, err := agent.Api.ApiClient.RequestNG("POST", "/msg", msg, false)
	if err != nil {
		return 0, nil, fmt.Errorf("API msg failed: %v", err)
	}
	if status != http.StatusOK {
		return 0, nil, fmt.Errorf("API msg returned status %d (%s)", status, http.StatusText(status))
	}

	return status, resp, nil
}

func (agent *Agent) SendApiBeat(msg *AgentBeatPost) (int, []byte, error) {
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

func (agent *Agent) SendApiHello(msg *AgentHelloPost) (int, []byte, error) {
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
