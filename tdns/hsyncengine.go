package tdns

import (
	"context"
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

// Define task struct for deferred operations
type DeferredTask struct {
	Action      string
	Target      string
	ZoneName    string
	RetryCount  int
	MaxRetries  int
	LastAttempt time.Time
}

func HsyncEngine(ctx context.Context, conf *Config, agentQs *AgentQs, stopch chan struct{}) {
	ourId := AgentId(conf.Agent.Identity)

	helloQ := agentQs.Hello
	heartbeatQ := agentQs.Beat
	msgQ := agentQs.Msg
	commandQ := agentQs.Command
	debugCommandQ := agentQs.DebugCommand
	synchedDataUpdateQ := agentQs.SynchedDataUpdate
	registry := conf.Internal.AgentRegistry
	registry.LocalAgent.Identity = string(ourId) // Make sure registry knows our identity

	var syncitem SyncRequest
	syncQ := conf.Internal.SyncQ

	var msgReport *AgentMsgReport
	var mgmtPost *AgentMgmtPostPlus
	var msgPost *AgentMsgPostPlus
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
	heartbeatInterval := configureInterval("agent.remote.beatinterval", 15, 1800)

	log.Printf("*** HsyncEngine starting (heartbeat will run once every %d seconds) ***", heartbeatInterval)

	HBticker := time.NewTicker(time.Duration(heartbeatInterval) * time.Second)

	for {
		select {
		case <-ctx.Done():
			log.Printf("HsyncEngine: context cancelled")
			HBticker.Stop()
			return
		case syncitem = <-syncQ:
			registry.SyncRequestHandler(ourId, syncitem, synchedDataUpdateQ)

		case msgReport = <-helloQ:
			registry.HelloHandler(msgReport)

		case msgReport = <-heartbeatQ:
			registry.HeartbeatHandler(msgReport)

		case msgPost = <-msgQ:
			registry.MsgHandler(msgPost, synchedDataUpdateQ)

		case mgmtPost = <-commandQ:
			registry.CommandHandler(mgmtPost, synchedDataUpdateQ)

		// debug stuff arrive on separate channel, but use the same format and handler
		case mgmtPost = <-debugCommandQ:
			registry.CommandHandler(mgmtPost, synchedDataUpdateQ)

		case <-HBticker.C:
			registry.SendHeartbeats()

		case req := <-conf.Internal.SyncStatusQ:
			registry.HandleStatusRequest(req)

		case <-stopch:
			log.Printf("HsyncEngine shutting down")
			// stop all tickers
			HBticker.Stop()
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

func (ar *AgentRegistry) SyncRequestHandler(ourId AgentId, req SyncRequest, synchedDataUpdateQ chan *SynchedDataUpdate) {
	log.Printf("*** handleSyncRequest: enter (zone %q)", req.ZoneName)
	switch req.Command {
	case "HSYNC-UPDATE":
		log.Printf("HsyncEngine: Zone %s HSYNC RRset has changed. Updating agents.", req.ZoneName)
		// Run UpdateAgents without waiting for completion
		go func() {
			err := ar.UpdateAgents(ourId, req, req.ZoneName, synchedDataUpdateQ)
			if err != nil {
				log.Printf("HsyncEngine: Error updating agents for zone %q: %v", req.ZoneName, err)
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

// Handler for messages received from other agents
func (ar *AgentRegistry) MsgHandler(ampp *AgentMsgPostPlus, synchedDataUpdateQ chan *SynchedDataUpdate) {
	log.Printf("MsgHandler: Received %q message from %s: %+v", AgentMsgToString[ampp.MessageType], ampp.MyIdentity, ampp)

	// var resp = SynchedDataResponse{
	var resp = AgentMsgResponse{
		Time:        time.Now(),
		Status:      "ok",
		Msg:         "Message received",
		RfiResponse: map[AgentId]*RfiData{},
	}

	defer func() {
		if ampp.Response != nil {
			select {
			case ampp.Response <- &resp:
				// log.Printf("MsgHandler: Response %+v sent to API handler", resp, ampp.MyIdentity)
			default:
				log.Printf("MsgHandler: Response channel blocked, skipping response")
			}
		}
	}()

	// Check if the zone exists (i.e. we have this zone under management)
	_, exists := Zones.Get(string(ampp.Zone))
	if !exists {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("MsgHandler for %s: Unknown zone: %s", ar.LocalAgent.Identity, ampp.Zone)
		resp.Msg = fmt.Sprintf("MsgHandler for %s: Unknown zone: %s", ar.LocalAgent.Identity, ampp.Zone)
		return
	}

	// Check if we are present in the zone HSYNC RRset (i.e. we have an agent role in this zone)
	zad, err := ar.GetZoneAgentData(ampp.Zone)
	if err != nil {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("MsgHandler for %s: Zone %s does not have a HSYNC RRset", ar.LocalAgent.Identity, ampp.Zone)
		resp.Msg = fmt.Sprintf("MsgHandler for %s: Zone %s does not have a HSYNC RRset", ar.LocalAgent.Identity, ampp.Zone)
		return
	}

	switch ampp.MessageType {
	case AgentMsgNotify:
		// if amp, ok := ampp.Msg.(*AgentMsgPost); ok {
		//	log.Printf("MsgHandler: Contained AgentMsgPost struct from %s: %+v", amp.MyIdentity, amp)

		var zu = &ZoneUpdate{
			Zone:   ampp.Zone,
			RRsets: map[uint16]RRset{},
		}
		for _, rrstr := range ampp.RRs {
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

		// var cresp = make(chan *SynchedDataResponse, 1)
		var cresp = make(chan *AgentMsgResponse, 1)
		synchedDataUpdateQ <- &SynchedDataUpdate{
			Zone:       ampp.Zone,
			AgentId:    ampp.MyIdentity,
			UpdateType: "remote",
			Update:     zu,
			Response:   cresp,
		}
		select {
		case r := <-cresp:
			if r.Error {
				log.Printf("MsgHandler: Error processing update from %s: %s", ampp.MyIdentity, r.ErrorMsg)
				resp.Error = true
				resp.ErrorMsg = r.ErrorMsg
			}
		case <-time.After(3 * time.Second):
			log.Printf("MsgHandler: No response from SynchedDataEngine received for update from %s after waiting 3 seconds", ampp.MyIdentity)
		}

	case AgentMsgRfi:
		// Process the RFI
		log.Printf("MsgHandler: Received RFI request from %s", ampp.MyIdentity)

		switch ampp.RfiType {
		case "UPSTREAM":
			// This is the case where a remote agent has us as upstream. Need to (a) verify that this is correct, (b) verify that we have
			// data for xfr.outgoing, (c) send the data to the remote agent.
			found := false
			for _, aid := range zad.MyDownstreams {
				if aid == ampp.MyIdentity {
					found = true
					break
				}
			}
			if !found {
				resp.Error = true
				resp.Msg = fmt.Sprintf("%s: RFI UPSTREAM request received, but remote agent %q is not a downstream agent", ar.LocalAgent.Identity, ampp.MyIdentity)
				resp.ErrorMsg = resp.Msg
				return
			}
			log.Printf("MsgHandler: RFI UPSTREAM request received from %q, which is a downstream agent (i.e. legitimate request)", ampp.MyIdentity)

			if len(ar.LocalAgent.Xfr.Outgoing.Addresses) == 0 {
				resp.Error = true
				resp.Msg = fmt.Sprintf("%s: RFI UPSTREAM request received, but local agent %q has no config for outgoing zone transfers", ar.LocalAgent.Identity, ar.LocalAgent.Identity)
				resp.ErrorMsg = resp.Msg
				return
			}

			// log.Printf("MsgHandler: Sending RFI UPSTREAM response to %q", ampp.MyIdentity)

			resp.RfiResponse[AgentId(ar.LocalAgent.Identity)] = &RfiData{
				ZoneXfrSrcs: ar.LocalAgent.Xfr.Outgoing.Addresses,
				ZoneXfrAuth: ar.LocalAgent.Xfr.Outgoing.Auth,
			}
			// log.Printf("MsgHandler: RFI UPSTREAM response %+v sent to %q", resp.RfiResponse, ampp.MyIdentity)

		case "DOWNSTREAM":
			// This is the case where a remote agent has us as downstream. Need to (a) verify that this is correct, (b) verify that we have
			// data for xfr.incoming, (c) send the data to the remote agent.
			if zad.MyUpstream != ampp.MyIdentity {
				resp.Error = true
				resp.Msg = fmt.Sprintf("%s: RFI DOWNSTREAM request received, but remote agent %q is not our upstream agent", ar.LocalAgent.Identity, ampp.MyIdentity)
				resp.ErrorMsg = resp.Msg
				return
			}

			log.Printf("MsgHandler: RFI DOWNSTREAM request received from %q, which is our upstream agent (i.e. legitimate request)", ampp.MyIdentity)

			if len(ar.LocalAgent.Xfr.Incoming.Addresses) == 0 {
				resp.Error = true
				resp.Msg = fmt.Sprintf("%s: RFI DOWNSTREAM request received, but local agent %q has no config for incoming zone transfers", ar.LocalAgent.Identity, ar.LocalAgent.Identity)
				resp.ErrorMsg = resp.Msg
				return
			}

			// log.Printf("MsgHandler: Sending RFI DOWNSTREAM response to %q", ampp.MyIdentity)

			resp.RfiResponse[AgentId(ar.LocalAgent.Identity)] = &RfiData{
				ZoneXfrDsts: ar.LocalAgent.Xfr.Incoming.Addresses,
				ZoneXfrAuth: ar.LocalAgent.Xfr.Incoming.Auth,
			}
			// log.Printf("MsgHandler: RFI DOWNSTREAM response %+v sent to %q", resp.RfiResponse, ampp.MyIdentity)

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("MsgHandler for %s: Unknown RFI type: %s", ar.LocalAgent.Identity, ampp.RfiType)
			resp.Msg = fmt.Sprintf("MsgHandler for %s: Unknown RFI type: %s", ar.LocalAgent.Identity, ampp.RfiType)
		}

	default:
		log.Printf("MsgHandler: Unknown message type: %+v", ampp.MessageType)
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("MsgHandler for %s: Unknown message type: %+v", ar.LocalAgent.Identity, ampp.MessageType)
		resp.Msg = fmt.Sprintf("MsgHandler for %s: Unknown message type: %+v", ar.LocalAgent.Identity, ampp.MessageType)
	}
}

// Handler for local commands from CLI or other components in the same organization
func (ar *AgentRegistry) CommandHandler(msg *AgentMgmtPostPlus, synchedDataUpdateQ chan *SynchedDataUpdate) {

	log.Printf("CommandHandler: Received mgmt command: %+v", msg)
	resp := AgentMgmtResponse{
		Identity:    AgentId(ar.LocalAgent.Identity), // Our identity, sent back to the originator (typically a CLI command)
		Time:        time.Now(),
		Msg:         "Command received",
		RfiResponse: map[AgentId]*RfiData{},
	}

	defer func() {
		if resp.ErrorMsg != "" {
			log.Printf("CommandHandler: Error: %s", resp.ErrorMsg)
		}
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
		resp.Error = true
		resp.ErrorMsg = "No zone specified in mgmt command"
		// log.Printf("CommandHandler: No zone specified in mgmt command")
		return
	}

	for _, rrstr := range msg.RRs {
		rr, err := dns.NewRR(rrstr)
		if err != nil {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Error parsing RR: %s", err)
			// log.Printf("CommandHandler: Error parsing RR: %s", err)
			return
		}
		log.Printf("CommandHandler: RR: %s", rr)
	}

	// Find remote agents for this zone
	// zad, err := ar.GetZoneAgentData(msg.Zone)
	// if err != nil {
	// 	resp.Error = true
	// 	resp.ErrorMsg = fmt.Sprintf("Error getting zone agent data for zone %s: %v", msg.Zone, err)
	// 	// log.Printf("CommandHandler: Error getting remote agents for zone %s: %v", msg.Zone, err)
	// 	return
	// }
	// if len(zad.Agents) == 0 {
	// 	resp.Error = true
	// 	resp.ErrorMsg = fmt.Sprintf("No remote agents found for zone %s", msg.Zone)
	// 	// log.Printf("CommandHandler: No remote agents found for zone %s", msg.Zone)
	// 	return
	// }

	// XXX: This is not quite clear: if one remote agent is unavailable for some reason,
	//      should we skip the command or not? Or should we send the command to the other agents?
	//      In most cases all agents must be operational, but for cases like UPSTREAM-RFI
	//      only the upstream agent has to be operational.
	// var notOperationalAgents = map[AgentId]bool{}
	// for _, agent := range zad.Agents {
	// 	if agent.ApiDetails.State != AgentStateOperational {
	// 		notOperationalAgents[agent.Identity] = true
	// 	}
	// }

	zad, notOperationalAgents, err := ar.RemoteOperationalAgents(msg.Zone)
	if err != nil {
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("Error getting remote operational agents for zone %s: %v", msg.Zone, err)
		return
	}

	var errstrs []string

	switch msg.Command { // msg.MessageType {

	case "send-notify":
		log.Printf("CommandHandler: Sending %q message to %d agents", AgentMsgToString[msg.MessageType], len(zad.Agents))
		// If any remote agent is not operational, we can't send the message
		if len(notOperationalAgents) > 0 {
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Agents %v are not operational, ignoring command for now", notOperationalAgents)
			// log.Printf("CommandHandler: %s", resp.ErrorMsg)
			return
		}

		// Send message to each agent
		for _, agent := range zad.Agents {
			amr, err := agent.SendApiMsg(&AgentMsgPost{
				MessageType:  AgentMsgNotify,
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

			resp.Msg = amr.Msg
			resp.Error = amr.Error
			resp.ErrorMsg = amr.ErrorMsg
		}
		if len(errstrs) > 0 {
			resp.Error = true
			resp.ErrorMsg = strings.Join(errstrs, "\n")
		}

	case "send-rfi":
		log.Printf("CommandHandler: Sending %s RFI message to %d agents", msg.RfiType, len(zad.Agents))
		switch msg.RfiType {
		case "UPSTREAM":
			if notOperationalAgents[zad.MyUpstream] {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("zone %q: Upstream agent %s is not operational, ignoring command for now", msg.Zone, zad.MyUpstream)
				// log.Printf("CommandHandler: %s", resp.ErrorMsg)
				return
			}

			agent, exists := ar.S.Get(zad.MyUpstream)
			if !exists {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("zone %q: %s agent %q not found", msg.Zone, msg.RfiType, zad.MyUpstream)
				// log.Printf("CommandHandler: %s", resp.ErrorMsg)
				return
			}

			// Send the RFI to the upstream agent
			amr, err := agent.SendApiMsg(&AgentMsgPost{
				MessageType:  AgentMsgRfi,
				MyIdentity:   AgentId(ar.LocalAgent.Identity),
				YourIdentity: agent.Identity,
				Zone:         msg.Zone,
				RfiType:      msg.RfiType,
			})

			if err != nil {
				resp.Error = true
				resp.ErrorMsg = fmt.Sprintf("Error sending RFI(%s) message to agent %s: %v", msg.RfiType, agent.Identity, err)
				// log.Printf("CommandHandler: %s", resp.ErrorMsg)
				return
			}

			if rfiresp, ok := amr.RfiResponse[agent.Identity]; ok {
				log.Printf("CommandHandler: UPSTREAM RFI message to agent %q for zone %q returned status OK: %s", agent.Identity, msg.Zone, amr.Msg)
				resp.RfiResponse[agent.Identity] = rfiresp
				resp.Status = "ok"
				resp.Msg = fmt.Sprintf("RFI(%s) message to agent %s for zone %s returned status OK: %s", msg.RfiType, agent.Identity, msg.Zone, amr.Msg)
				return
			}

			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("zone %q: UPSTREAM RFI message to agent %q returned strange response: %v",
				msg.Zone, msg.RfiType, amr.RfiResponse)
			return

		case "DOWNSTREAM":
			for _, aid := range zad.MyDownstreams {
				// Send the RFI to the upstream agent
				log.Printf("CommandHandler: Sending DOWNSTREAM RFI message to agent %q", aid)
				if notOperationalAgents[aid] {
					resp.RfiResponse[aid] = &RfiData{
						Status:   "error",
						Error:    true,
						ErrorMsg: fmt.Sprintf("zone %q: Downstream agent %q is not operational, ignoring command for now", msg.Zone, aid),
					}
					// log.Printf("CommandHandler: %s", resp.ErrorMsg)
					continue
				}

				agent, exists := ar.S.Get(aid)
				if !exists {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("zone %q: DOWNSTREAM RFI message to agent %q: Agent not found", msg.Zone, aid)
					// log.Printf("CommandHandler: %s", resp.ErrorMsg)
					resp.RfiResponse[aid] = &RfiData{
						Status:   "error",
						Error:    true,
						ErrorMsg: fmt.Sprintf("zone %q: Downstream agent %q not found, ignoring command for now", msg.Zone, aid),
					}
					continue
				}

				// Send the RFI to the upstream agent
				amr, err := agent.SendApiMsg(&AgentMsgPost{
					MessageType:  AgentMsgRfi,
					MyIdentity:   AgentId(ar.LocalAgent.Identity),
					YourIdentity: agent.Identity,
					Zone:         msg.Zone,
					RfiType:      msg.RfiType,
				})

				if err != nil {
					resp.Error = true
					resp.ErrorMsg = fmt.Sprintf("Error sending DOWNSTREAM RFI message to agent %q: %v", aid, err)
					// log.Printf("CommandHandler: %s", resp.ErrorMsg)
					return
				}

				if rfiresp, ok := amr.RfiResponse[aid]; ok {
					resp.RfiResponse[aid] = rfiresp
					continue
				}

				resp.RfiResponse[aid] = &RfiData{
					Error:    true,
					ErrorMsg: fmt.Sprintf("DOWNSTREAM RFI message to agent %q for zone %q returned strange response: %v", aid, msg.Zone, amr.RfiResponse),
				}
			}

		default:
			resp.Error = true
			resp.ErrorMsg = fmt.Sprintf("Unknown RFI type: %q", msg.RfiType)
			return
		}

	case "update-local-zonedata":
		// Update the local zone data for the zone
		var zu = &ZoneUpdate{
			Zone:   msg.Zone,
			RRsets: map[uint16]RRset{},
		}
		for _, rrstr := range msg.RRs {
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

		// var cresp = make(chan *SynchedDataResponse, 1)
		var cresp = make(chan *AgentMsgResponse, 1)
		synchedDataUpdateQ <- &SynchedDataUpdate{
			Zone:       msg.Zone,
			AgentId:    AgentId(ar.LocalAgent.Identity),
			UpdateType: "local",
			Update:     zu,
			Response:   cresp,
		}
		select {
		case r := <-cresp:
			if r.Error {
				log.Printf("MsgHandler: Error processing local update: %s", r.ErrorMsg)
				resp.Error = true
				resp.ErrorMsg = r.ErrorMsg
			}
			resp.Msg = r.Msg
		case <-time.After(2 * time.Second):
			log.Printf("MsgHandler: No response from SynchedDataEngine received for local update after waiting 2 seconds")
		}

	default:
		resp.Error = true
		resp.ErrorMsg = fmt.Sprintf("Unknown message type: %+v", msg.MessageType)
	}
}

func (ar *AgentRegistry) RemoteOperationalAgents(zone ZoneName) (*ZoneAgentData, map[AgentId]bool, error) {
	// Find remote agents for this zone
	zad, err := ar.GetZoneAgentData(zone)
	if err != nil {
		return nil, nil, fmt.Errorf("Error getting zone agent data for zone %s: %v", zone, err)
	}
	if len(zad.Agents) == 0 {
		return nil, nil, fmt.Errorf("No remote agents found for zone %s", zone)
	}

	// XXX: This is not quite clear: if one remote agent is unavailable for some reason,
	// should we skip the command or not? Or should we send the command to the other agents?
	// In most cases all agents must be operational, but for cases like UPSTREAM-RFI
	// only the upstream agent has to be operational.
	//
	// The question is what to do if one or more agents are not operational. One alternative is
	// to queue the update and resend when all remote agents are back. Another alternative is
	// put a "dirty" flag on the local data for the tuple <zone, agent> and send the update
	// when the agent comes back online.
	//
	// The second alternative seems more attractive.
	//
	// We return the ZAD struct including the list of all remote agents and a map of non-operational agents.
	var notOperationalAgents = map[AgentId]bool{}
	for _, agent := range zad.Agents {
		if agent.ApiDetails.State != AgentStateOperational {
			notOperationalAgents[agent.Identity] = true
		}
	}
	return zad, notOperationalAgents, nil
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
		saneAgent := SanitizeForJSON(*agent) // Shallow copy
		if foo, ok := saneAgent.(*Agent); ok {
			agents[agent.Identity] = foo
		} else {
			log.Printf("HsyncEngine: Failed to sanitize agent %s for JSON", agent.Identity)
		}
	}

	// var saneAr *AgentRegistry
	// if foo, ok := SanitizeForJSON(*ar).(*AgentRegistry); ok {
	// 	saneAr = foo
	// }

	// Send the response immediately with a timeout to avoid blocking
	select {
	case req.Response <- SyncStatus{
		Agents: agents,
		// AgentRegistry: saneAr,
		Identity: AgentId(ar.LocalAgent.Identity),
		Error:    false,
	}:
	case <-time.After(1 * time.Second): // Don't block forever
		log.Printf("HsyncEngine: STATUS response timed out")
	}
}

// Helper methods for SendBeat
func (agent *Agent) SendApiMsg(msg *AgentMsgPost) (*AgentMsgResponse, error) {
	if agent.Api == nil {
		return nil, fmt.Errorf("no API client configured for agent %q", agent.Identity)
	}

	status, resp, err := agent.Api.ApiClient.RequestNG("POST", "/msg", msg, false)
	if err != nil {
		return nil, fmt.Errorf("API msg failed: %v", err)
	}

	if status != http.StatusOK {
		return nil, fmt.Errorf("API msg returned status %d (%s)", status, http.StatusText(status))
	}

	// log.Printf("SendApiMsg: response: %s", string(resp))

	var amr AgentMsgResponse
	err = json.Unmarshal(resp, &amr)
	if err != nil {
		return nil, fmt.Errorf("Error unmarshalling message response: %v", err)
	}

	//	if amr.Status == "ok" {
	//		log.Printf("SendApiMsg: message to agent %q for zone %q returned status OK: %s", agent.Identity, msg.Zone, amr.Msg)
	//	} else {
	//		return nil, fmt.Errorf("SendApiMsg: message to agent %q for zone %q returned status %d: %s, ErrorMsg: %q. Full response: %+v", agent.Identity, msg.Zone, status, amr.Msg, amr.ErrorMsg, amr)
	//	}
	return &amr, nil
}

func (agent *Agent) SendDnsMsg(msg *AgentMsgPost) (int, []byte, error) {
	// TODO: Implement DNS-based heartbeat
	// This would involve creating a signed DNS message
	// containing the heartbeat information
	return 0, nil, fmt.Errorf("DNS transport not yet implemented")
}
