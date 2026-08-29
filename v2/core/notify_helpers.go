/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Generic NOTIFY pattern helpers for distribution ID handling
 * Extracted from tdns-nm/tnm for shared use by KDC, KRS, and agents
 */

package core

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// BuildNotifyQNAME constructs a NOTIFY QNAME from a distribution ID and zone.
//
// The distribution ID is prepended as a label to the zone, following the pattern:
// <distributionID>.<zone>
//
// This pattern is used by:
//   - KDC: distributionID = distribution ID (e.g., "a1b2.kdc.example.com.")
//   - Agents: distributionID = sync operation ID (e.g., "sync123.agent.example.com.")
//
// The zone is ensured to be a fully-qualified domain name (FQDN) with trailing dot.
//
// Parameters:
//   - distributionID: The unique identifier for this operation (distribution, sync, etc.)
//   - zone: The base zone name (will be made FQDN if not already)
//
// Returns:
//   - The constructed NOTIFY QNAME as FQDN
//
// Example:
//
//	BuildNotifyQNAME("a1b2", "kdc.example.com") -> "a1b2.kdc.example.com."
func BuildNotifyQNAME(distributionID, zone string) string {
	// Ensure zone is FQDN
	zoneFQDN := zone
	if !strings.HasSuffix(zoneFQDN, ".") {
		zoneFQDN += "."
	}

	return distributionID + "." + zoneFQDN
}

// ExtractDistributionIDFromQNAME extracts a distribution ID from a NOTIFY QNAME.
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
//   - The distribution ID (without trailing dots), or an error if:
//   - QNAME doesn't end with zone
//   - QNAME equals zone (no distribution ID present)
//   - Zone is empty
//
// Example:
//
//	ExtractDistributionIDFromQNAME("a1b2.kdc.example.com.", "kdc.example.com.") -> "a1b2", nil
func ExtractDistributionIDFromQNAME(qname, zone string) (string, error) {
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

	// Inside the zone, as a DNS name. strings.HasSuffix got this wrong twice:
	// it is case-sensitive, so a1b2.KDC.example.com. was rejected outright; and
	// it knows nothing about label boundaries, so evila1b2kdc.example.com. --
	// a name in a DIFFERENT zone -- passed, and the trim below then handed back
	// "evila1b2" as though it were a distribution ID from this one.
	if !dns.IsSubDomain(zoneFQDN, qnameFQDN) {
		return "", fmt.Errorf("QNAME %s is not inside zone %s", qnameFQDN, zoneFQDN)
	}

	// Check if QNAME equals zone (no distribution ID)
	if EqualNames(qnameFQDN, zoneFQDN) {
		return "", fmt.Errorf("QNAME equals zone (no distribution ID present)")
	}

	// Extract distribution ID (everything before the zone). Sliced by length,
	// not trimmed: TrimSuffix compares bytes, so it would strip nothing from a
	// qname whose zone part is spelled in another case than the zone -- exactly
	// what the fold above just accepted.
	distributionID := qnameFQDN[:len(qnameFQDN)-len(zoneFQDN)]
	distributionID = strings.TrimSuffix(distributionID, ".") // Remove trailing dot

	return distributionID, nil
}
