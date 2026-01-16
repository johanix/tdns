/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * DNS RRtypes for HPKE-based key distribution
 */

package hpke

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Experimental RRtype codes (to be replaced with IANA assignments)
const (
	TypeKMCTRL = 65010 // 0xFDF2 - Key Management Control (legacy)
	TypeKMREQ  = 65011 // 0xFDF3 - Key Management Request (legacy)
	TypeKMPKG  = 65012 // 0xFDF4 - Key Management Package (legacy)
)

// ParseQnameForKMREQ extracts distribution ID and zone from KMREQ QNAME
// Format: <distribution-id>.<zone>.<control-zone>
// The control zone is needed to correctly extract multi-label zones
func ParseQnameForKMREQ(qname string, controlZone string) (distributionID, zone string, err error) {
	// Remove trailing dot if present
	if len(qname) > 0 && qname[len(qname)-1] == '.' {
		qname = qname[:len(qname)-1]
	}

	labels := dns.SplitDomainName(qname)
	if len(labels) < 3 {
		return "", "", fmt.Errorf("invalid KMREQ QNAME format: %s (need at least distribution-id.zone.control-zone)", qname)
	}

	// Distribution ID is the first label
	distributionID = labels[0]

	// Validate distribution ID is hex
	if _, err := hex.DecodeString(distributionID); err != nil {
		return "", "", fmt.Errorf("invalid distribution ID in QNAME: %s (must be hex)", distributionID)
	}

	// Extract control zone labels (remove trailing dot if present)
	controlZoneClean := controlZone
	if len(controlZoneClean) > 0 && controlZoneClean[len(controlZoneClean)-1] == '.' {
		controlZoneClean = controlZoneClean[:len(controlZoneClean)-1]
	}
	controlLabels := dns.SplitDomainName(controlZoneClean)

	if len(controlLabels) == 0 {
		return "", "", fmt.Errorf("invalid control zone: %s", controlZone)
	}

	// The zone is everything between the distribution ID and the control zone
	// QNAME format: <distribution-id>.<zone-labels>.<control-zone-labels>
	// We need at least: distribution-id (1) + zone (1+) + control-zone (1+) = 3+ labels
	if len(labels) < len(controlLabels)+2 {
		return "", "", fmt.Errorf("invalid KMREQ QNAME format: %s (too few labels)", qname)
	}

	// Check that the last N labels match the control zone
	controlStartIdx := len(labels) - len(controlLabels)
	for i := 0; i < len(controlLabels); i++ {
		if labels[controlStartIdx+i] != controlLabels[i] {
			return "", "", fmt.Errorf("QNAME %s does not end with control zone %s", qname, controlZone)
		}
	}

	// Zone is everything between distribution ID (index 0) and control zone
	// Zone labels are from index 1 to controlStartIdx-1
	if controlStartIdx <= 1 {
		return "", "", fmt.Errorf("invalid KMREQ QNAME format: %s (no zone labels found)", qname)
	}

	zoneLabels := labels[1:controlStartIdx]
	zone = strings.Join(zoneLabels, ".")

	// Ensure zone is FQDN
	zone = dns.Fqdn(zone)

	return distributionID, zone, nil
}

// BuildKMREQQname constructs a QNAME for a KMREQ query
// All inputs are expected to be FQDN (dot-terminated), but we handle both cases
// Format: <distribution-id>.<zone>.<control-zone>
func BuildKMREQQname(distributionID, zone, controlZone string) string {
	// Strip trailing dots to avoid ".." in the QNAME
	zoneClean := zone
	if len(zoneClean) > 0 && zoneClean[len(zoneClean)-1] == '.' {
		zoneClean = zoneClean[:len(zoneClean)-1]
	}

	controlZoneClean := controlZone
	if len(controlZoneClean) > 0 && controlZoneClean[len(controlZoneClean)-1] == '.' {
		controlZoneClean = controlZoneClean[:len(controlZoneClean)-1]
	}

	// Build QNAME: <distribution-id>.<zone>.<control-zone>.
	// Always ensure the result is FQDN (ends with ".")
	return fmt.Sprintf("%s.%s.%s.", distributionID, zoneClean, controlZoneClean)
}
