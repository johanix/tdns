/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Agent authorization checks for secure agent introduction.
 * Prevents discovery amplification attacks by requiring authorization before discovery.
 */

package tdns

import (
	"fmt"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// IsPeerAuthorized checks if a peer is authorized to communicate with us.
// Authorization can come from three sources:
//
// 1. Configured peers: Provided via AuthorizedPeers callback (role-specific)
// 2. LEGACY state: Established relationship with zero shared zones
// 3. HSYNC membership: Both peers listed in HSYNC RRset for a shared zone
//
// This function is role-agnostic. Each role injects its own AuthorizedPeers
// callback at TransportManager creation time.
//
// Parameters:
//   - senderID: Identity of the agent attempting to communicate
//   - zone: Optional zone name for HSYNC membership check (empty string skips HSYNC check)
//
// Returns:
//   - authorized: true if agent is authorized
//   - reason: human-readable explanation of authorization decision
func (tm *TransportManager) IsPeerAuthorized(senderID string, zone string) (bool, string) {
	// Check 1: Authorization via role-specific configured peers
	// The AuthorizedPeers callback is injected at config time by each role.
	if tm.isAuthorizedPeer(senderID) {
		return true, "authorized via configured peer"
	}

	// Check 2: LEGACY state agents (established relationship, zero zones)
	// These agents were previously in HSYNC but all shared zones have been removed
	// We still allow beat messages to maintain the relationship
	if tm.agentRegistry != nil {
		if agent, exists := tm.agentRegistry.S.Get(AgentId(senderID)); exists {
			if agent.State == AgentStateLegacy {
				return true, "authorized via LEGACY state (established relationship, zero shared zones)"
			}
		}
	}

	// Check 3: Implicit authorization via HSYNC membership
	if zone != "" {
		// Specific zone provided - check HSYNC for that zone
		authorized, reason := tm.isInHSYNC(senderID, zone)
		if authorized {
			return true, fmt.Sprintf("authorized via HSYNC membership for zone %s", zone)
		}
		lgAgent.Debug("sender not in HSYNC", "sender", senderID, "zone", zone, "reason", reason)
	} else {
		// No specific zone - check if sender is in HSYNC for ANY zone we share
		// This is used for zone-agnostic operations like heartbeats
		authorized, foundZone := tm.isInHSYNCAnyZone(senderID)
		if authorized {
			return true, fmt.Sprintf("authorized via HSYNC membership for zone %s", foundZone)
		}
	}

	// Not authorized via either path
	return false, fmt.Sprintf("not authorized (not in config or HSYNC for zone %q)", zone)
}

// isAuthorizedPeer checks if senderID is in the role-specific authorized peers list.
// The list is provided via the AuthorizedPeers callback in TransportManagerConfig.
// This replaces the former isConfiguredPeer + isInAuthorizedPeers methods which
// hardcoded role-specific Conf checks. Now any role (agent, combiner, signer, kdc, krs)
// provides its own callback returning the list of authorized peer identities.
func (tm *TransportManager) isAuthorizedPeer(senderID string) bool {
	if tm.authorizedPeers == nil {
		return false
	}
	senderFQDN := dns.Fqdn(senderID)
	for _, peerID := range tm.authorizedPeers() {
		if dns.Fqdn(peerID) == senderFQDN {
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

	lgAgent.Debug("both identities found in HSYNC", "local", tm.LocalID, "sender", senderID, "zone", zone)
	return true, ""
}

// isInHSYNCAnyZone checks if senderID is in the HSYNC RRset for ANY zone we share.
// This is used for zone-agnostic authorization (e.g., heartbeats, general peer communication).
// Returns true and the first matching zone name if found.
func (tm *TransportManager) isInHSYNCAnyZone(senderID string) (bool, string) {
	// Iterate through all zones we know about
	for _, zoneName := range Zones.Keys() {
		zd, exists := Zones.Get(zoneName)
		if !exists {
			continue
		}

		// Check if zone has HSYNC RRset
		hsyncRR, err := zd.GetRRset(zd.ZoneName, core.TypeHSYNC)
		if err != nil || hsyncRR == nil {
			continue // No HSYNC for this zone, try next
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

		// If we found both in this zone's HSYNC, authorize
		if foundMe && foundSender {
			lgAgent.Debug("both identities found in HSYNC (any-zone check)",
				"local", tm.LocalID, "sender", senderID, "zone", zoneName)
			return true, zoneName
		}
	}

	// Not found in any shared HSYNC
	return false, ""
}
