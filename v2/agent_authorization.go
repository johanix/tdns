/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Agent authorization checks for secure agent introduction.
 * Prevents discovery amplification attacks by requiring authorization before discovery.
 */

package tdns

import (
	"fmt"
	"log"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// IsAgentAuthorized checks if an agent is authorized to communicate with us.
// Authorization can come from two sources:
//
// 1. Explicit authorization: Agent is in our agent.authorized_peers config list
// 2. Implicit authorization: Agent is in HSYNC RRset for a shared zone
//
// This function is used to prevent discovery amplification attacks:
// we only accept Hello from agents we're configured to work with OR
// agents that appear in HSYNC RRsets for zones we serve.
//
// Parameters:
//   - senderID: Identity of the agent attempting to communicate
//   - zone: Optional zone name for HSYNC membership check (empty string skips HSYNC check)
//
// Returns:
//   - authorized: true if agent is authorized
//   - reason: human-readable explanation of authorization decision
func (tm *TransportManager) IsAgentAuthorized(senderID string, zone string) (bool, string) {
	// Check 1: Explicit authorization via config
	if tm.isInAuthorizedPeers(senderID) {
		return true, "authorized via config (agent.authorized_peers)"
	}

	// Check 2: Implicit authorization via HSYNC membership
	if zone != "" {
		authorized, reason := tm.isInHSYNC(senderID, zone)
		if authorized {
			return true, fmt.Sprintf("authorized via HSYNC membership for zone %s", zone)
		}
		log.Printf("IsAgentAuthorized: Sender %s not in HSYNC for zone %s: %s",
			senderID, zone, reason)
	}

	// Not authorized via either path
	return false, fmt.Sprintf("not authorized (not in config or HSYNC for zone %q)", zone)
}

// isInAuthorizedPeers checks if senderID is in our agent.authorized_peers config.
// This represents explicit authorization - we've configured this agent as a trusted peer.
func (tm *TransportManager) isInAuthorizedPeers(senderID string) bool {
	if Conf.Agent == nil {
		return false
	}

	// Normalize senderID to FQDN for comparison
	senderFQDN := dns.Fqdn(senderID)

	// Check authorized_peers list
	for _, authorizedID := range Conf.Agent.AuthorizedPeers {
		// Normalize config entry to FQDN for comparison
		authorizedFQDN := dns.Fqdn(authorizedID)
		if authorizedFQDN == senderFQDN {
			log.Printf("IsAgentAuthorized: Agent %s found in agent.authorized_peers config", senderID)
			return true
		}
	}

	return false
}

// isInHSYNC checks if senderID is in the HSYNC RRset for the specified zone.
// This represents implicit authorization - we're both listed in the same HSYNC RRset,
// indicating operational need to communicate for this zone.
//
// This mirrors the logic in EvaluateHello() from hsync_hello.go:160-211.
func (tm *TransportManager) isInHSYNC(senderID string, zone string) (bool, string) {
	// Check if we have this zone
	zd, exists := Zones.Get(zone)
	if !exists {
		return false, fmt.Sprintf("we don't know about zone %q", zone)
	}

	// Check if zone has HSYNC RRset
	hsyncRR, err := zd.GetRRset(zd.ZoneName, core.TypeHSYNC)
	if err != nil {
		return false, fmt.Sprintf("error retrieving HSYNC RRset: %v", err)
	}
	if hsyncRR == nil {
		return false, fmt.Sprintf("zone %q has no HSYNC RRset", zone)
	}

	// Check if both our identity and sender are in HSYNC RRset
	foundMe := false
	foundSender := false
	for _, rr := range hsyncRR.RRs {
		if prr, ok := rr.(*dns.PrivateRR); ok {
			if hsync, ok := prr.Data.(*core.HSYNC); ok {
				if hsync.Identity == tm.LocalID {
					foundMe = true
				}
				if hsync.Identity == senderID {
					foundSender = true
				}
			}
		}
	}

	if !foundMe {
		return false, fmt.Sprintf("our identity %q not in HSYNC RRset for zone %s", tm.LocalID, zone)
	}
	if !foundSender {
		return false, fmt.Sprintf("sender %q not in HSYNC RRset for zone %s", senderID, zone)
	}

	log.Printf("IsAgentAuthorized: Both %s and %s found in HSYNC for zone %s", tm.LocalID, senderID, zone)
	return true, ""
}
