/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Generic NOTIFY pattern helpers for correlation ID handling
 * Extracted from tdns-nm/tnm for shared use by KDC, KRS, and agents
 */

package core

import (
	"fmt"
	"strings"
)

// BuildNotifyQNAME constructs a NOTIFY QNAME from a correlation ID and zone.
//
// The correlation ID is prepended as a label to the zone, following the pattern:
// <correlationID>.<zone>
//
// This pattern is used by:
//   - KDC: correlationID = distribution ID (e.g., "a1b2.kdc.example.com.")
//   - Agents: correlationID = sync operation ID (e.g., "sync123.agent.example.com.")
//
// The zone is ensured to be a fully-qualified domain name (FQDN) with trailing dot.
//
// Parameters:
//   - correlationID: The unique identifier for this operation (distribution, sync, etc.)
//   - zone: The base zone name (will be made FQDN if not already)
//
// Returns:
//   - The constructed NOTIFY QNAME as FQDN
//
// Example:
//   BuildNotifyQNAME("a1b2", "kdc.example.com") -> "a1b2.kdc.example.com."
func BuildNotifyQNAME(correlationID, zone string) string {
	// Ensure zone is FQDN
	zoneFQDN := zone
	if !strings.HasSuffix(zoneFQDN, ".") {
		zoneFQDN += "."
	}

	return correlationID + "." + zoneFQDN
}

// ExtractCorrelationIDFromQNAME extracts a correlation ID from a NOTIFY QNAME.
//
// Given a QNAME like "a1b2.kdc.example.com." and a zone "kdc.example.com.",
// this function returns "a1b2".
//
// The function validates that the QNAME ends with the zone and returns an error
// if it doesn't.
//
// Parameters:
//   - qname: The NOTIFY QNAME to extract from (FQDN)
//   - zone: The base zone name (will be made FQDN if not already)
//
// Returns:
//   - The correlation ID (without trailing dots), or an error if:
//     - QNAME doesn't end with zone
//     - QNAME equals zone (no correlation ID present)
//     - Zone is empty
//
// Example:
//   ExtractCorrelationIDFromQNAME("a1b2.kdc.example.com.", "kdc.example.com.") -> "a1b2", nil
func ExtractCorrelationIDFromQNAME(qname, zone string) (string, error) {
	if zone == "" {
		return "", fmt.Errorf("zone cannot be empty")
	}

	// Ensure both QNAME and zone are FQDN
	qnameFQDN := qname
	if !strings.HasSuffix(qnameFQDN, ".") {
		qnameFQDN += "."
	}

	zoneFQDN := zone
	if !strings.HasSuffix(zoneFQDN, ".") {
		zoneFQDN += "."
	}

	// Check if QNAME ends with zone
	if !strings.HasSuffix(qnameFQDN, zoneFQDN) {
		return "", fmt.Errorf("QNAME %s does not end with zone %s", qnameFQDN, zoneFQDN)
	}

	// Check if QNAME equals zone (no correlation ID)
	if qnameFQDN == zoneFQDN {
		return "", fmt.Errorf("QNAME equals zone (no correlation ID present)")
	}

	// Extract correlation ID (everything before the zone)
	correlationID := strings.TrimSuffix(qnameFQDN, zoneFQDN)
	correlationID = strings.TrimSuffix(correlationID, ".") // Remove trailing dot

	return correlationID, nil
}
