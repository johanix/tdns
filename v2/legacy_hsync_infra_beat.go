/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"context"
	"time"
)

const defaultInfraBeatInterval = 600 * time.Second // 10 minutes

// StartInfraBeatLoop sends periodic beats from the agent to infrastructure peers
// (combiner and signer). Runs at a lower frequency than the agent↔agent beat loop
// (default 10 minutes, vs 15–1800s for agent peers).
//
// Combiner and signer are excluded from SendHeartbeats() via IsInfraPeer=true.
// This loop handles them exclusively.
func (ar *AgentRegistry) StartInfraBeatLoop(ctx context.Context) {
	interval := defaultInfraBeatInterval

	lgAgent.Info("starting infra beat loop", "interval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Send an initial beat immediately so we don't wait a full interval on startup.
	ar.sendInfraBeats(ctx)

	for {
		select {
		case <-ctx.Done():
			lgAgent.Info("infra beat loop stopped")
			return
		case <-ticker.C:
			ar.sendInfraBeats(ctx)
		}
	}
}

// sendInfraBeats iterates AgentRegistry and sends a beat to every infra peer
// (combiner, signer) that has at least one transport ready.
func (ar *AgentRegistry) sendInfraBeats(parentCtx context.Context) {
	if ar.MPTransport == nil {
		return
	}

	for _, a := range ar.S.Items() {
		if !a.IsInfraPeer {
			continue
		}

		a.Mu.RLock()
		dnsState := a.DnsDetails.State
		apiState := a.ApiDetails.State
		a.Mu.RUnlock()

		dnsReady := dnsState == AgentStateOperational || dnsState == AgentStateIntroduced ||
			dnsState == AgentStateLegacy || dnsState == AgentStateDegraded || dnsState == AgentStateInterrupted
		apiReady := apiState == AgentStateOperational || apiState == AgentStateIntroduced ||
			apiState == AgentStateLegacy || apiState == AgentStateDegraded || apiState == AgentStateInterrupted

		if !dnsReady && !apiReady {
			lgAgent.Debug("infra peer not ready for beat, skipping", "peer", a.Identity,
				"dnsState", AgentStateToString[dnsState], "apiState", AgentStateToString[apiState])
			continue
		}

		go func(agent *Agent, dnsReady, apiReady bool) {
			ctx, cancel := context.WithTimeout(parentCtx, 15*time.Second)
			defer cancel()

			agent.Mu.RLock()
			var sequence uint64
			if agent.DnsDetails.SentBeats > 0 {
				sequence = uint64(agent.DnsDetails.SentBeats)
			}
			agent.Mu.RUnlock()

			resp, err := ar.MPTransport.SendBeatWithFallback(ctx, agent, sequence)
			if err != nil {
				lgAgent.Warn("infra beat failed", "peer", agent.Identity, "err", err)
				return
			}

			// SendBeatWithFallback already updates per-transport received-side
			// counters (ReceivedBeats, LatestRBeat, State) inside itself. Here we
			// only track sent-side counters, conditional on which transport was
			// actually attempted so an API-only beat doesn't corrupt DnsDetails.
			agent.Mu.Lock()
			if resp != nil && resp.Ack {
				lgAgent.Debug("infra beat acknowledged", "peer", agent.Identity, "state", resp.State)
				now := time.Now()
				if dnsReady {
					agent.DnsDetails.SentBeats++
					agent.DnsDetails.LatestSBeat = now
					agent.DnsDetails.LatestError = ""
				}
				if apiReady {
					agent.ApiDetails.SentBeats++
					agent.ApiDetails.LatestSBeat = now
					agent.ApiDetails.LatestError = ""
				}
			}
			agent.Mu.Unlock()
		}(a, dnsReady, apiReady)
	}
}
