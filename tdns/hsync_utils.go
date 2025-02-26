package tdns

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

// Add this function to process HSYNC records and update zone relationships
func (ar *AgentRegistry) ProcessHsyncRecords(zone string, hsyncRRs []dns.RR, ourId string) error {
	for _, rr := range hsyncRRs {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync, ok := prr.Data.(*HSYNC); ok {
				// If we're either Target or Upstream, we need to track this relationship
				if hsync.Target == ourId || hsync.Upstream == ourId {
					otherAgent := hsync.Target
					if hsync.Target == ourId {
						otherAgent = hsync.Upstream
					}

					ar.AddZoneToAgent(otherAgent, zone)

					// If we're the Target, we should initiate contact
					if hsync.Target == ourId {
						_, agent, err := ar.LocateAgent(hsync.Upstream)
						if err != nil {
							return fmt.Errorf("failed to locate agent %s: %v", hsync.Upstream, err)
						}

						if err := agent.SendBeat("HELLO"); err != nil {
							log.Printf("Warning: failed to send HELLO to %s: %v", hsync.Upstream, err)
						}
					}
				}
			}
		}
	}
	return nil
}
