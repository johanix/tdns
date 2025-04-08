package tdns

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

func (ar *AgentRegistry) HelloHandler(report *AgentMsgReport) {
	// log.Printf("HelloHandler: Received HELLO from %s", report.Identity)

	switch report.MessageType {
	case AgentMsgHello:
		if Globals.Debug {
			log.Printf("HelloHandler: Received initial HELLO from %s", report.Identity)
		}
		// Store in wannabe_agents until we verify it shares zones with us
		// wannabe_agents[report.Msg.Identity] = report.Agent

	default:
		log.Printf("HelloHandler: Unknown message type: %s", AgentMsgToString[report.MessageType])
	}
}

func (ar *AgentRegistry) HelloRetrier() {
	var known_agents []AgentId
	for _, agent := range ar.S.Items() {
		switch agent.ApiDetails.State {
		case AgentStateKnown:
			known_agents = append(known_agents, agent.Identity)
			go ar.SingleHello(agent, agent.InitialZone)
			// log.Printf("HsyncEngine: Retrying HELLO to %s (state %s)", agent.Identity, AgentStateToString[agent.ApiDetails.State])
		default:
			// log.Printf("HsyncEngine: Not retrying HELLO to %s (state %s != KNOWN)", agent.Identity, AgentStateToString[agent.ApiDetails.State])
			continue
		}
	}
	if len(known_agents) > 0 {
		log.Printf("HsyncEngine: Retried HELLO to %d remote agents in state KNOWN: %v", len(known_agents), known_agents)
	} else {
		if Globals.Debug {
			log.Printf("HsyncEngine: No remote agents in state KNOWN to retry HELLO to")
		}
	}
}

func (ar *AgentRegistry) HelloRetrierNG(agent *Agent) {
	helloRetryInterval := configureInterval("syncengine.intervals.helloretry", 15, 1800)
	go func(agent *Agent) {
		if agent.ApiDetails.State != AgentStateKnown {
			log.Printf("HelloRetrierNG: agent %q is not in state KNOWN, stopping", agent.Identity)
			return
		}
		for {
			log.Printf("HelloRetrierNG: with agent %q we share the zones: %v", agent.Identity, agent.Zones)
			for zone := range agent.Zones {
				log.Printf("HelloRetrierNG: trying HELLO with agent %q with zone: %q", agent.Identity, zone)
				switch agent.ApiDetails.State {
				case AgentStateKnown:
					ar.SingleHello(agent, zone)

					// log.Printf("HsyncEngine: Retrying HELLO to %s (state %s)", agent.Identity, AgentStateToString[agent.ApiDetails.State])
				default:
					// log.Printf("HsyncEngine: Not retrying HELLO to %s (state %s != KNOWN)", agent.Identity, AgentStateToString[agent.ApiDetails.State])
					break
				}
				if agent.ApiDetails.State == AgentStateKnown {
					time.Sleep(time.Duration(helloRetryInterval) * time.Second)
				} else {
					log.Printf("HelloRetrierNG: agent %q no longer in state KNOWN (now %s), stopping", agent.Identity, AgentStateToString[agent.ApiDetails.State])
					return
				}
			}
		}
	}(agent)
	log.Printf("HelloRetrierNG: started HelloRetrierNG for agent %q", agent.Identity)
}

func (ar *AgentRegistry) SingleHello(agent *Agent, zone ZoneName) {
	log.Printf("SingleHello: Sending HELLO to %s (zone %q)", agent.Identity, zone)
	ahr, err := agent.SendApiHello(&AgentHelloPost{
		MessageType:  AgentMsgHello,
		MyIdentity:   AgentId(ar.LocalAgent.Identity),
		YourIdentity: agent.Identity,
		Zone:         zone,
	})
	agent.mu.Lock()
	switch {
	case err != nil:
		log.Printf("SingleHello: Error sending HELLO to %q: %v", agent.Identity, err)
		agent.ApiDetails.LatestError = err.Error()

		//	case status != http.StatusOK:
		//		log.Printf("HsyncEngine: HELLO to %s returned status %d", agent.Identity, status)
		//		agent.ApiDetails.LatestError = fmt.Sprintf("status %d", status)

	case ahr.Error:
		log.Printf("SingleHello: Our HELLO to %q returned error: %s", agent.Identity, ahr.ErrorMsg)
		agent.ApiDetails.LatestError = ahr.ErrorMsg
		agent.ApiDetails.LatestErrorTime = time.Now()

	default:
		log.Printf("SingleHello: Our HELLO to %q returned: %s", agent.Identity, ahr.Msg)
		// if ahr.Status == "ok" {
		agent.ApiDetails.State = AgentStateIntroduced
		agent.ApiDetails.LatestError = ""
		// }
	}
	ar.S.Set(agent.Identity, agent)
	agent.mu.Unlock()
}

func (ar *AgentRegistry) EvaluateHello(ahp *AgentHelloPost) (bool, string, error) {
	log.Printf("EvaluateHello: Evaluating agent %q that claims to share the zone %q with us", ahp.MyIdentity, ahp.Zone)

	// Now let's check if we need to know this agent
	if ahp.Zone == "" {
		log.Printf("EvaluateHello: Error: No zone specified in HELLO message")
		return false, "Error: No zone specified in HELLO message", nil
	}

	// Check if we have this zone
	zd, exists := Zones.Get(string(ahp.Zone))
	if !exists {
		log.Printf("EvaluateHello: Error: We don't know about zone %q. This could be a timing issue, so try again in a bit", ahp.Zone)
		return false, fmt.Sprintf("Error: We don't know about zone %q. This could be a timing issue, so try again in a bit", ahp.Zone), nil
	}

	// Check if zone has HSYNC RRset
	hsyncRR, err := zd.GetRRset(zd.ZoneName, TypeHSYNC)
	if err != nil {
		log.Printf("EvaluateHello: Error: Error trying to retrieve HSYNC RRset for zone %q: %v", ahp.Zone, err)
		return false, fmt.Sprintf("Error trying to retrieve HSYNC RRset for zone %q: %v", ahp.Zone, err), nil
	}
	if hsyncRR == nil {
		log.Printf("EvaluateHello: Error: Zone %q has no HSYNC RRset", ahp.Zone)
		return false, fmt.Sprintf("Error: Zone %q has no HSYNC RRset", ahp.Zone), nil
	}

	// Check if both our identity and remote agent are in HSYNC RRset
	foundMe := false
	foundYou := false
	for _, rr := range hsyncRR.RRs {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync, ok := prr.Data.(*HSYNC); ok {
				if hsync.Identity == ar.LocalAgent.Identity {
					foundMe = true
				}
				if AgentId(hsync.Identity) == ahp.MyIdentity {
					foundYou = true
				}
			}
		}
	}

	if !foundMe || !foundYou {
		log.Printf("EvaluateHello: Error: Zone %q HSYNC RRset does not include both our identities", ahp.Zone)
		log.Printf("EvaluateHello: HSYNC RRset: %+v", hsyncRR)
		log.Printf("EvaluateHello: your identity: %s, my identity: %s", ahp.MyIdentity, ar.LocalAgent.Identity)
		return false, fmt.Sprintf("Error: Zone %q HSYNC RRset does not include both our identities", ahp.Zone), nil
	}

	return true, "", nil
}

func (agent *Agent) SendApiHello(msg *AgentHelloPost) (*AgentHelloResponse, error) {
	if agent.Api == nil {
		return nil, fmt.Errorf("no API client configured for agent %s", agent.Identity)
	}

	status, resp, err := agent.Api.ApiClient.RequestNG("POST", "/hello", msg, false)
	if err != nil {
		return nil, fmt.Errorf("API hello failed: %v", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("API hello returned status %d (%s)", status, http.StatusText(status))
	}

	var ahr AgentHelloResponse
	err = json.Unmarshal(resp, &ahr)
	if err != nil {
		return nil, fmt.Errorf("Error unmarshalling HELLO response: %v", err)
	}

	return &ahr, nil
}
