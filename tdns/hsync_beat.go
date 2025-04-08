package tdns

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

func (ar *AgentRegistry) HeartbeatHandler(report *AgentMsgReport) {
	// log.Printf("HeartbeatHandler: Received %s from %s", report.Msg.MessageType, report.Msg.Identity)

	switch report.MessageType {
	case AgentMsgBeat:
		if Globals.Debug {
			log.Printf("HeartbeatHandler: Received BEAT from %s", report.Identity)
		}
		if agent, exists := ar.S.Get(report.Identity); exists {
			agent.ApiDetails.LatestRBeat = time.Now()
			agent.ApiDetails.ReceivedBeats++
			agent.ApiDetails.BeatInterval = report.BeatInterval
		}

		//	case "FULLBEAT":
		//		if Globals.Debug {
		//			log.Printf("HeartbeatHandler: Received FULLBEAT from %s", report.Identity)
		//		}
		//		if agent, exists := ar.S.Get(report.Identity); exists {
		//			agent.ApiDetails.LatestRBeat = time.Now()
		//			agent.ApiDetails.ReceivedBeats++
		//		}

	default:
		log.Printf("HeartbeatHandler: Unknown message type: %s", AgentMsgToString[report.MessageType])
	}
}

func (ar *AgentRegistry) SendHeartbeats() {
	// log.Printf("HsyncEngine: Sending heartbeats to INTRODUCED or OPERATIONAL agents")
	for _, a := range ar.S.Items() {
		switch a.ApiDetails.State {
		case AgentStateIntroduced, AgentStateOperational:
			if Globals.Debug {
				log.Printf("HsyncEngine: Sending heartbeat to %s", a.Identity)
			}
		case AgentStateDegraded, AgentStateInterrupted:
			log.Printf("HsyncEngine: Sending heartbeat to degraded/interrupted agent %s", a.Identity)
		default:
			if Globals.Debug {
				log.Printf("HsyncEngine: Not sending heartbeat to %s (state %s < INTRODUCED)", a.Identity, AgentStateToString[a.State])
			}
			continue
		}

		go func(a *Agent) {
			agent := a
			abr, err := agent.SendApiBeat(&AgentBeatPost{
				MessageType:    AgentMsgBeat,
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

			//			case status != http.StatusOK:
			//				log.Printf("HsyncEngine: Error: heartbeat to %s returned status %d", agent.Identity, status)
			//				if agent.ApiDetails.LatestError == "" {
			//					agent.ApiDetails.LatestError = fmt.Sprintf("status %d", status)
			//					agent.ApiDetails.LatestErrorTime = time.Now()
			//				}

			case abr.Error:
				agent.ApiDetails.LatestError = abr.ErrorMsg
				agent.ApiDetails.LatestErrorTime = time.Now()

			default:
				//				if abr.Status == "ok" {
				agent.ApiDetails.State = AgentStateOperational
				agent.ApiDetails.LatestSBeat = time.Now()
				agent.ApiDetails.LatestError = ""
				agent.ApiDetails.SentBeats++
				if len(agent.DeferredTasks) > 0 {
					log.Printf("HsyncEngine: Agent %s has %d deferred tasks, sending them now", agent.Identity, len(agent.DeferredTasks))
					var remainingTasks []DeferredAgentTask
					for _, task := range agent.DeferredTasks {
						if task.Precondition() {
							ok, err := task.Action()
							if err != nil {
								log.Printf("HsyncEngine: Error executing deferred task %s: %v", task.Desc, err)
								remainingTasks = append(remainingTasks, task)
							} else if ok {
								log.Printf("HsyncEngine: Deferred task %s executed successfully", task.Desc)
							} else {
								remainingTasks = append(remainingTasks, task)
							}
						} else {
							remainingTasks = append(remainingTasks, task)
						}
					}
					agent.DeferredTasks = remainingTasks
				}
				//				}
			}
			agent.CheckState(ar.LocalAgent.Remote.BeatInterval)
			ar.S.Set(agent.Identity, agent)
			agent.mu.Unlock()
		}(a)
	}
}

func (agent *Agent) CheckState(ourBeatInterval uint32) {
	timeSinceLastReceivedBeat := time.Since(agent.ApiDetails.LatestRBeat)
	timeSinceLastSentBeat := time.Since(agent.ApiDetails.LatestSBeat)
	remoteBeatInterval := time.Duration(agent.ApiDetails.BeatInterval) * time.Second
	localBeatInterval := time.Duration(ourBeatInterval) * time.Second

	switch agent.ApiDetails.State {
	case AgentStateOperational, AgentStateDegraded, AgentStateInterrupted:
		// proceed
	default:
		return
	}

	if timeSinceLastReceivedBeat > 10*remoteBeatInterval || timeSinceLastSentBeat > 10*localBeatInterval {
		agent.ApiDetails.State = AgentStateInterrupted
	} else if timeSinceLastReceivedBeat > 2*remoteBeatInterval || timeSinceLastSentBeat > 2*localBeatInterval {
		agent.ApiDetails.State = AgentStateDegraded
	} else {
		agent.ApiDetails.State = AgentStateOperational
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

func (agent *Agent) SendApiBeat(msg *AgentBeatPost) (*AgentBeatResponse, error) {
	if agent.Api == nil {
		return nil, fmt.Errorf("no API client configured for agent %s", agent.Identity)
	}

	// Create a context with a 2-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Use the context with the RequestNG function
	status, resp, err := agent.Api.ApiClient.RequestNGWithContext(ctx, "POST", "/beat", msg, false)
	if err != nil {
		return nil, fmt.Errorf("HTTPS beat failed: %v", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("HTTPS beat returned status %d (%s)", status, http.StatusText(status))
	}

	var abr AgentBeatResponse
	err = json.Unmarshal(resp, &abr)
	if err != nil {
		return nil, fmt.Errorf("Error unmarshalling BEAT response: %v", err)
	}

	return &abr, nil
}
