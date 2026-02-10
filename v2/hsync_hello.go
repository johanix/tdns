package tdns

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func (ar *AgentRegistry) sharedZonesForAgent(agent *Agent) []string {
	zones := make([]string, 0, len(agent.Zones))
	for z := range agent.Zones {
		zones = append(zones, string(z))
	}
	return zones
}

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

// HelloRetrierNG manages Hello retries for an agent.
// UPDATED: Now handles both API and DNS transports independently.
// Continues retrying while EITHER transport is in KNOWN state.
func (ar *AgentRegistry) HelloRetrierNG(ctx context.Context, agent *Agent) {
	helloRetryInterval := configureInterval("agent.syncengine.intervals.helloretry", 15, 1800)
	go func(agent *Agent) {
		ticker := time.NewTicker(time.Duration(helloRetryInterval) * time.Second)
		defer ticker.Stop()

		// Check if ANY transport needs Hello retries
		apiNeedsRetry := agent.ApiMethod && agent.ApiDetails.State == AgentStateKnown
		dnsNeedsRetry := agent.DnsMethod && agent.DnsDetails.State == AgentStateKnown

		if !apiNeedsRetry && !dnsNeedsRetry {
			log.Printf("HelloRetrierNG: agent %q has no transports in state KNOWN (API: %s, DNS: %s), stopping",
				agent.Identity, AgentStateToString[agent.ApiDetails.State], AgentStateToString[agent.DnsDetails.State])
			return
		}

		log.Printf("HelloRetrierNG: started for agent %q (API: %s, DNS: %s)",
			agent.Identity, AgentStateToString[agent.ApiDetails.State], AgentStateToString[agent.DnsDetails.State])

		// Send immediate Hello, then wait for ticker for retries
		sendHello := true

		for {
			if !sendHello {
				select {
				case <-ctx.Done():
					log.Printf("HelloRetrierNG: context done, stopping")
					return
				case <-ticker.C:
					sendHello = true
				}
			}

			// Check current state of both transports
			agent.mu.RLock()
			apiState := agent.ApiDetails.State
			dnsState := agent.DnsDetails.State
			apiMethod := agent.ApiMethod
			dnsMethod := agent.DnsMethod
			agent.mu.RUnlock()

			apiNeedsRetry = apiMethod && apiState == AgentStateKnown
			dnsNeedsRetry = dnsMethod && dnsState == AgentStateKnown

			if !apiNeedsRetry && !dnsNeedsRetry {
				log.Printf("HelloRetrierNG: agent %q no longer in state KNOWN (API: %s, DNS: %s), stopping",
					agent.Identity, AgentStateToString[apiState], AgentStateToString[dnsState])
				return
			}

			log.Printf("HelloRetrierNG: with agent %q we share the zones: %v", agent.Identity, agent.Zones)

			// Send ONE Hello per retry interval with all shared zones
			// Old behavior sent one Hello PER ZONE which caused message bursts
			if apiNeedsRetry || dnsNeedsRetry {
				if len(agent.Zones) > 0 {
					// Pick first zone for the Hello message zone field (for backward compat with receivers)
					// But SendHelloWithFallback uses sharedZonesForAgent() which includes ALL zones
					var firstZone ZoneName
					for zone := range agent.Zones {
						firstZone = zone
						break
					}
					log.Printf("HelloRetrierNG: trying HELLO with agent %q with %d shared zone(s), using %q as primary zone (API needs: %v, DNS needs: %v)",
						agent.Identity, len(agent.Zones), firstZone, apiNeedsRetry, dnsNeedsRetry)
					ar.SingleHello(agent, firstZone)
				} else {
					// Config-based agent with no shared zones - send Hello anyway
					log.Printf("HelloRetrierNG: trying HELLO with agent %q (no shared zones, config-based agent, API needs: %v, DNS needs: %v)",
						agent.Identity, apiNeedsRetry, dnsNeedsRetry)
					ar.SingleHello(agent, "")
				}
			}

			// Reset flag to wait for next ticker
			sendHello = false
		}
	}(agent)
	log.Printf("HelloRetrierNG: started HelloRetrierNG for agent %q", agent.Identity)
}

func (ar *AgentRegistry) SingleHello(agent *Agent, zone ZoneName) {
	log.Printf("SingleHello: Sending HELLO to %s (zone %q)", agent.Identity, zone)

	// Use TransportManager for independent multi-transport handling
	if ar.TransportManager != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		sharedZones := ar.sharedZonesForAgent(agent)
		// SendHelloWithFallback now handles both transports independently
		// and updates ApiDetails.State and DnsDetails.State separately
		_, err := ar.TransportManager.SendHelloWithFallback(ctx, agent, sharedZones)
		if err != nil {
			log.Printf("SingleHello: TransportManager HELLO to %q failed on all transports: %v", agent.Identity, err)
		} else {
			log.Printf("SingleHello: Our HELLO to %q accepted on at least one transport", agent.Identity)
		}
		ar.S.Set(agent.Identity, agent)
		return
	}

	// Fallback: API-only (legacy mode without TransportManager)
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

	case ahr.Error:
		log.Printf("SingleHello: Our HELLO to %q returned error: %s", agent.Identity, ahr.ErrorMsg)
		agent.ApiDetails.LatestError = ahr.ErrorMsg
		agent.ApiDetails.LatestErrorTime = time.Now()

	default:
		log.Printf("SingleHello: Our HELLO to %q returned: %s", agent.Identity, ahr.Msg)
		agent.ApiDetails.State = AgentStateIntroduced
		agent.ApiDetails.LatestError = ""
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
	hsyncRR, err := zd.GetRRset(zd.ZoneName, core.TypeHSYNC)
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
			if hsync, ok := prr.Data.(*core.HSYNC); ok {
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
		return nil, fmt.Errorf("error unmarshalling HELLO response: %v", err)
	}

	return &ahr, nil
}
