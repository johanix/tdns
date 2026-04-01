package tdns

import (
	"context"
	"encoding/json"
	"fmt"
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
		lgAgent.Debug("received initial HELLO", "from", report.Identity)
		// Store in wannabe_agents until we verify it shares zones with us
		// wannabe_agents[report.Msg.Identity] = report.Agent

	default:
		lgAgent.Warn("unknown message type in HelloHandler", "type", AgentMsgToString[report.MessageType])
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
		lgAgent.Debug("retried HELLO to KNOWN agents", "count", len(known_agents), "agents", known_agents)
	} else {
		lgAgent.Debug("no remote agents in state KNOWN to retry HELLO to")
	}
}

// HelloRetrierNG manages Hello retries for an agent.
// Handles both API and DNS transports independently.
// Continues retrying while EITHER transport is in KNOWN state.
//
// Fast-start: configurable number of immediate attempts with configurable spacing.
// If all fail, falls back to the normal helloretry ticker.
// On HELLO success (INTRODUCED), triggers fast beat attempts.
func (ar *AgentRegistry) HelloRetrierNG(ctx context.Context, agent *Agent) {
	helloRetryInterval := configureInterval("agent.syncengine.intervals.helloretry", 15, 1800)
	fastAttempts := configureInterval("agent.syncengine.intervals.hello_fast_attempts", 3, 20)
	fastIntervalSec := configureInterval("agent.syncengine.intervals.hello_fast_interval", 1, 30)
	go func(agent *Agent) {
		// Check if ANY transport needs Hello retries
		if !ar.agentNeedsHello(agent) {
			lgAgent.Debug("no transports in state KNOWN, stopping HelloRetrierNG",
				"agent", agent.Identity, "apiState", AgentStateToString[agent.ApiDetails.State],
				"dnsState", AgentStateToString[agent.DnsDetails.State])
			return
		}

		lgAgent.Info("HelloRetrierNG started", "agent", agent.Identity,
			"fastAttempts", fastAttempts, "fastInterval", fastIntervalSec,
			"apiState", AgentStateToString[agent.ApiDetails.State],
			"dnsState", AgentStateToString[agent.DnsDetails.State])

		// Phase 1: Fast attempts — configurable count and spacing
		fastInterval := time.Duration(fastIntervalSec) * time.Second

		for attempt := 1; attempt <= fastAttempts; attempt++ {
			if attempt > 1 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(fastInterval):
				}
			}

			if !ar.agentNeedsHello(agent) {
				lgAgent.Info("HELLO succeeded (fast attempt)", "agent", agent.Identity,
					"attempt", attempt, "maxAttempts", fastAttempts)
				// HELLO succeeded — trigger fast beat attempts
				ar.FastBeatAttempts(ctx, agent)
				return
			}

			lgAgent.Debug("fast HELLO attempt", "attempt", attempt, "maxAttempts", fastAttempts, "agent", agent.Identity)
			ar.sendHelloToAgent(agent)
		}

		// Check if fast phase succeeded
		if !ar.agentNeedsHello(agent) {
			lgAgent.Info("HELLO succeeded after fast attempts", "agent", agent.Identity)
			ar.FastBeatAttempts(ctx, agent)
			return
		}

		// Phase 2: Fall back to normal ticker
		lgAgent.Debug("fast attempts exhausted, falling back to ticker",
			"agent", agent.Identity, "interval", helloRetryInterval)

		ticker := time.NewTicker(time.Duration(helloRetryInterval) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				lgAgent.Debug("HelloRetrierNG context done, stopping")
				return
			case <-ticker.C:
			}

			if !ar.agentNeedsHello(agent) {
				lgAgent.Info("agent no longer in state KNOWN, stopping HelloRetrierNG", "agent", agent.Identity)
				ar.FastBeatAttempts(ctx, agent)
				return
			}

			lgAgent.Debug("ticker retry HELLO", "agent", agent.Identity)
			ar.sendHelloToAgent(agent)
		}
	}(agent)
	lgAgent.Debug("launched HelloRetrierNG goroutine", "agent", agent.Identity)
}

// agentNeedsHello returns true if any transport is still in KNOWN state.
func (ar *AgentRegistry) agentNeedsHello(agent *Agent) bool {
	agent.Mu.RLock()
	defer agent.Mu.RUnlock()
	apiNeeds := agent.ApiMethod && agent.ApiDetails.State == AgentStateKnown
	dnsNeeds := agent.DnsMethod && agent.DnsDetails.State == AgentStateKnown
	return apiNeeds || dnsNeeds
}

// sendHelloToAgent sends a single HELLO to an agent using all shared zones.
func (ar *AgentRegistry) sendHelloToAgent(agent *Agent) {
	if len(agent.Zones) > 0 {
		var firstZone ZoneName
		for zone := range agent.Zones {
			firstZone = zone
			break
		}
		ar.SingleHello(agent, firstZone)
	} else {
		ar.SingleHello(agent, "")
	}
}

// FastBeatAttempts sends up to 3 beats with 5s spacing after HELLO succeeds.
// If any beat succeeds (agent becomes OPERATIONAL), returns immediately.
// If all 3 fail, returns — the normal heartbeat ticker will take over.
func (ar *AgentRegistry) FastBeatAttempts(ctx context.Context, agent *Agent) {
	const fastAttempts = 3
	const fastInterval = 5 * time.Second

	// Check if any transport is INTRODUCED (needs beat to reach OPERATIONAL)
	needsBeat := func() bool {
		agent.Mu.RLock()
		defer agent.Mu.RUnlock()
		apiIntro := agent.ApiMethod && agent.ApiDetails.State == AgentStateIntroduced
		dnsIntro := agent.DnsMethod && agent.DnsDetails.State == AgentStateIntroduced
		return apiIntro || dnsIntro
	}

	if !needsBeat() {
		return
	}

	lgAgent.Debug("starting fast beat attempts", "agent", agent.Identity)

	for attempt := 1; attempt <= fastAttempts; attempt++ {
		if attempt > 1 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(fastInterval):
			}
		}

		if !needsBeat() {
			lgAgent.Info("agent reached OPERATIONAL (fast beat)", "agent", agent.Identity,
				"attempt", attempt, "maxAttempts", fastAttempts)
			return
		}

		lgAgent.Debug("fast beat attempt", "attempt", attempt, "maxAttempts", fastAttempts, "agent", agent.Identity)

		if ar.MPTransport != nil {
			beatCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			agent.Mu.RLock()
			sequence := uint64(agent.ApiDetails.SentBeats)
			agent.Mu.RUnlock()
			beatResp, err := ar.MPTransport.SendBeatWithFallback(beatCtx, agent, sequence)
			cancel()

			if err == nil && beatResp != nil && beatResp.Ack {
				agent.Mu.Lock()
				agent.ApiDetails.State = AgentStateOperational
				agent.ApiDetails.LatestSBeat = time.Now()
				agent.ApiDetails.SentBeats++
				agent.ApiDetails.LatestError = ""
				tasks := agent.DeferredTasks
				agent.DeferredTasks = nil
				ar.S.Set(agent.Identity, agent)
				agent.Mu.Unlock()

				if len(tasks) > 0 {
					lgAgent.Info("executing deferred tasks after fast beat", "agent", agent.Identity, "count", len(tasks))
					var remaining []DeferredAgentTask
					for _, task := range tasks {
						if task.Precondition() {
							ok, taskErr := task.Action()
							if taskErr != nil {
								lgAgent.Error("deferred task failed", "task", task.Desc, "err", taskErr)
								remaining = append(remaining, task)
							} else if !ok {
								remaining = append(remaining, task)
							} else {
								lgAgent.Info("deferred task executed", "task", task.Desc)
							}
						} else {
							remaining = append(remaining, task)
						}
					}
					if len(remaining) > 0 {
						agent.Mu.Lock()
						agent.DeferredTasks = append(agent.DeferredTasks, remaining...)
						agent.Mu.Unlock()
					}
				}
				lgAgent.Info("agent reached OPERATIONAL", "agent", agent.Identity)
				return
			}
		}
	}

	// Check final state
	if !needsBeat() {
		lgAgent.Info("agent reached OPERATIONAL after fast attempts", "agent", agent.Identity)
	} else {
		lgAgent.Debug("fast beat attempts exhausted, heartbeat ticker will take over", "agent", agent.Identity)
	}
}

func (ar *AgentRegistry) SingleHello(agent *Agent, zone ZoneName) {
	lgAgent.Debug("sending HELLO", "agent", agent.Identity, "zone", zone)

	// Use TransportManager for independent multi-transport handling
	if ar.MPTransport != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
		defer cancel()
		sharedZones := ar.sharedZonesForAgent(agent)
		// SendHelloWithFallback now handles both transports independently
		// and updates ApiDetails.State and DnsDetails.State separately
		_, err := ar.MPTransport.SendHelloWithFallback(ctx, agent, sharedZones)
		if err != nil {
			lgAgent.Warn("HELLO failed on all transports", "agent", agent.Identity, "err", err)
		} else {
			lgAgent.Info("HELLO accepted on at least one transport", "agent", agent.Identity)
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
	agent.Mu.Lock()
	switch {
	case err != nil:
		lgAgent.Error("error sending HELLO", "agent", agent.Identity, "err", err)
		agent.ApiDetails.LatestError = err.Error()

	case ahr.Error:
		lgAgent.Warn("HELLO returned error", "agent", agent.Identity, "error", ahr.ErrorMsg)
		agent.ApiDetails.LatestError = ahr.ErrorMsg
		agent.ApiDetails.LatestErrorTime = time.Now()

	default:
		lgAgent.Info("HELLO accepted", "agent", agent.Identity, "msg", ahr.Msg)
		// Only transition to INTRODUCED if not already OPERATIONAL or better
		// This prevents Hello messages from downgrading state (e.g., after retry)
		if agent.ApiDetails.State < AgentStateIntroduced {
			agent.ApiDetails.State = AgentStateIntroduced
			lgAgent.Info("agent API state updated to INTRODUCED", "agent", agent.Identity)
		}
		agent.ApiDetails.LatestError = ""
	}
	ar.S.Set(agent.Identity, agent)
	agent.Mu.Unlock()
}

func (ar *AgentRegistry) EvaluateHello(ahp *AgentHelloPost) (bool, string, error) {
	lgAgent.Debug("evaluating HELLO", "agent", ahp.MyIdentity, "zone", ahp.Zone)

	// Now let's check if we need to know this agent
	if ahp.Zone == "" {
		lgAgent.Warn("no zone specified in HELLO message")
		return false, "Error: No zone specified in HELLO message", nil
	}

	// Check if we have this zone
	zd, exists := Zones.Get(string(ahp.Zone))
	if !exists {
		lgAgent.Warn("unknown zone in HELLO, may be a timing issue", "zone", ahp.Zone)
		return false, fmt.Sprintf("Error: We don't know about zone %q. This could be a timing issue, so try again in a bit", ahp.Zone), nil
	}

	// Check if zone has HSYNC3 RRset
	hsyncRR, err := zd.GetRRset(zd.ZoneName, core.TypeHSYNC3)
	if err != nil {
		lgAgent.Error("error retrieving HSYNC3 RRset", "zone", ahp.Zone, "err", err)
		return false, fmt.Sprintf("Error trying to retrieve HSYNC3 RRset for zone %q: %v", ahp.Zone, err), nil
	}
	if hsyncRR == nil {
		lgAgent.Warn("zone has no HSYNC3 RRset", "zone", ahp.Zone)
		return false, fmt.Sprintf("Error: Zone %q has no HSYNC3 RRset", ahp.Zone), nil
	}

	// Check if both our identity and remote agent are in HSYNC3 RRset
	foundMe := false
	foundYou := false
	for _, rr := range hsyncRR.RRs {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync3, ok := prr.Data.(*core.HSYNC3); ok {
				if hsync3.Identity == ar.LocalAgent.Identity {
					foundMe = true
				}
				if AgentId(hsync3.Identity) == ahp.MyIdentity {
					foundYou = true
				}
			}
		}
	}

	if !foundMe || !foundYou {
		lgAgent.Warn("HSYNC3 RRset does not include both identities",
			"zone", ahp.Zone, "yourIdentity", ahp.MyIdentity, "myIdentity", ar.LocalAgent.Identity)
		return false, fmt.Sprintf("Error: Zone %q HSYNC3 RRset does not include both our identities", ahp.Zone), nil
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
