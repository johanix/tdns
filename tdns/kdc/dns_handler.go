/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * DNS query handler for tdns-kdc
 * Handles KMREQ, KMCTRL, and other queries
 */

package kdc

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/johanix/tdns/tdns/core"
	"github.com/johanix/tdns/tdns/hpke"
	"github.com/miekg/dns"
)

// KdcQueryRequest represents a DNS query request for KDC
// This mirrors DnsQueryRequest from tdns package to avoid circular imports
type KdcQueryRequest struct {
	ResponseWriter dns.ResponseWriter
	Msg            *dns.Msg
	Qname          string
	Qtype          uint16
	Options        interface{} // *edns0.MsgOptions (avoiding import)
}

// HandleKdcQuery processes DNS queries for the KDC
// This function is called by QueryHandler when DnsQueryQ is non-nil
func HandleKdcQuery(ctx context.Context, dqr *KdcQueryRequest, kdcDB *KdcDB, conf *KdcConf) error {
	msg := dqr.Msg
	qname := dqr.Qname
	qtype := dqr.Qtype
	w := dqr.ResponseWriter

	log.Printf("KDC: Received query for %s %s from %s", qname, dns.TypeToString[qtype], w.RemoteAddr())
	log.Printf("KDC: Message details - ID: %d, Opcode: %s, Question count: %d, Additional count: %d", 
		msg.MsgHdr.Id, dns.OpcodeToString[msg.Opcode], len(msg.Question), len(msg.Extra))

	// Check for SIG(0) signature in Additional section (but don't enforce initially)
	sig0Validated := false
	sig0SignerName := ""
	sig0KeyID := uint16(0)
	if len(msg.Extra) > 0 {
		for _, rr := range msg.Extra {
			if sig, ok := rr.(*dns.SIG); ok {
				sig0SignerName = sig.RRSIG.SignerName
				sig0KeyID = sig.RRSIG.KeyTag
				log.Printf("KDC: Query has SIG(0) signature from %s (keyid %d)", sig0SignerName, sig0KeyID)

				// TODO: Verify SIG(0) signature against trusted keys
				// For now, we just log it but don't enforce
				// sig0Validated = verifySig0Signature(msg, sig)
				sig0Validated = false // Not enforced initially
				if sig0Validated {
					log.Printf("KDC: SIG(0) signature validated successfully")
				} else {
					log.Printf("KDC: SIG(0) signature not validated (not enforced)")
				}
				break // Only check first SIG RR
			}
		}
	}

	// Create response message
	m := new(dns.Msg)
	m.SetReply(msg)
	m.Authoritative = true

	log.Printf("KDC: Processing query type %s (%d) for %s", dns.TypeToString[qtype], qtype, qname)
	switch qtype {
	case hpke.TypeKMREQ:
		log.Printf("KDC: Handling KMREQ query")
		err := handleKMREQQuery(ctx, m, msg, qname, w, kdcDB, conf, sig0SignerName, sig0KeyID)
		if err != nil {
			log.Printf("KDC: Error handling KMREQ: %v", err)
		} else {
			log.Printf("KDC: KMREQ query handled successfully")
		}
		return err

	case hpke.TypeKMCTRL:
		log.Printf("KDC: Handling KMCTRL query")
		err := handleKMCTRLQuery(ctx, m, msg, qname, w, kdcDB, conf)
		if err != nil {
			log.Printf("KDC: Error handling KMCTRL: %v", err)
		} else {
			log.Printf("KDC: KMCTRL query handled successfully")
		}
		return err

	case core.TypeJSONMANIFEST:
		log.Printf("KDC: Handling JSONMANIFEST query")
		err := handleJSONMANIFESTQuery(ctx, m, msg, qname, w, kdcDB, conf)
		if err != nil {
			log.Printf("KDC: Error handling JSONMANIFEST: %v", err)
		} else {
			log.Printf("KDC: JSONMANIFEST query handled successfully")
		}
		// Don't return error - we've already sent the response (success or error)
		return nil

	case core.TypeJSONCHUNK:
		log.Printf("KDC: Handling JSONCHUNK query")
		err := handleJSONCHUNKQuery(ctx, m, msg, qname, w, kdcDB, conf)
		if err != nil {
			log.Printf("KDC: Error handling JSONCHUNK: %v", err)
		} else {
			log.Printf("KDC: JSONCHUNK query handled successfully")
		}
		return err

	default:
		// For other query types, return NOTIMP or REFUSED
		log.Printf("KDC: Unsupported query type %s (%d) for %s", dns.TypeToString[qtype], qtype, qname)
		m.SetRcode(msg, dns.RcodeNotImplemented)
		err := w.WriteMsg(m)
		if err != nil {
			log.Printf("KDC: Error writing response: %v", err)
		}
		return err
	}
}

// handleKMREQQuery processes KMREQ queries
// KMREQ format: QNAME = <distribution-id>.<zone>.<control-zone>
// Ephemeral public key may be in EDNS(0) option or encoded in question
func handleKMREQQuery(ctx context.Context, m *dns.Msg, msg *dns.Msg, qname string, w dns.ResponseWriter, kdcDB *KdcDB, conf *KdcConf, sig0SignerName string, sig0KeyID uint16) error {
	log.Printf("KDC: Processing KMREQ query for %s", qname)

	// Parse QNAME to extract distribution ID and zone
	distributionID, zone, err := hpke.ParseQnameForKMREQ(qname, conf.ControlZone)
	if err != nil {
		log.Printf("KDC: Error parsing KMREQ QNAME %s: %v", qname, err)
		m.SetRcode(msg, dns.RcodeFormatError)
		return w.WriteMsg(m)
	}

	log.Printf("KDC: KMREQ distribution-id=%s, zone=%s", distributionID, zone)

	// Extract ephemeral public key from EDNS(0) option or question
	// TODO: EDNS(0) support for ephemeral key is not yet implemented
	// For now, we'll generate a dummy key for testing, but this should be replaced with actual EDNS(0) extraction
	ephemeralPubKey, err := extractEphemeralPubKey(msg)
	if err != nil {
		log.Printf("KDC: Warning: Ephemeral public key extraction not yet implemented (EDNS(0) support pending). Using placeholder for testing.")
		log.Printf("KDC: Error extracting ephemeral public key: %v", err)
		// For now, generate a dummy key to allow testing to proceed
		// TODO: Remove this once EDNS(0) support is implemented
		ephemeralPubKey = make([]byte, 32)
		// Fill with zeros as placeholder (not secure, but allows testing)
		log.Printf("KDC: Using placeholder ephemeral key (all zeros) for testing")
	}

	if len(ephemeralPubKey) != 32 {
		log.Printf("KDC: Invalid ephemeral public key length: %d (expected 32)", len(ephemeralPubKey))
		m.SetRcode(msg, dns.RcodeFormatError)
		err := w.WriteMsg(m)
		if err != nil {
			log.Printf("KDC: Error writing FORMATERROR response: %v", err)
		}
		return err
	}

	// Log whether we're using a placeholder key
	allZeros := true
	if ephemeralPubKey != nil && len(ephemeralPubKey) == 32 {
		for _, b := range ephemeralPubKey {
			if b != 0 {
				allZeros = false
				break
			}
		}
	}
	if allZeros {
		log.Printf("KDC: Using ephemeral public key (32 bytes) - PLACEHOLDER (all zeros - EDNS(0) not implemented)")
	} else {
		log.Printf("KDC: Using ephemeral public key (32 bytes) - extracted from query")
	}

	// Find the zone
	zoneObj, err := kdcDB.GetZone(zone)
	if err != nil {
		log.Printf("KDC: Zone %s not found: %v", zone, err)
		m.SetRcode(msg, dns.RcodeNameError)
		err := w.WriteMsg(m)
		if err != nil {
			log.Printf("KDC: Error writing NXDOMAIN response: %v", err)
		}
		return err
	}

	if !zoneObj.Active {
		log.Printf("KDC: Zone %s is not active", zone)
		m.SetRcode(msg, dns.RcodeRefused)
		err := w.WriteMsg(m)
		if err != nil {
			log.Printf("KDC: Error writing REFUSED response: %v", err)
		}
		return err
	}

	// Find node by SIG(0) signer name (if provided) or use default node selection
	// For now, we'll get all nodes and encrypt for each
	// TODO: Implement proper node identification from SIG(0) signature
	var nodes []*Node
	if sig0SignerName != "" {
		// Try to find node by signer name (future: map signer name to node)
		log.Printf("KDC: SIG(0) signer: %s (not yet used for node identification)", sig0SignerName)
	}

	// Get all online nodes
	nodes, err = kdcDB.GetActiveNodes()
	if err != nil {
		log.Printf("KDC: Error getting active nodes: %v", err)
		m.SetRcode(msg, dns.RcodeServerFailure)
		err := w.WriteMsg(m)
		if err != nil {
			log.Printf("KDC: Error writing SERVFAIL response: %v", err)
		}
		return err
	}

	if len(nodes) == 0 {
		log.Printf("KDC: No online nodes found")
		m.SetRcode(msg, dns.RcodeServerFailure)
		err := w.WriteMsg(m)
		if err != nil {
			log.Printf("KDC: Error writing SERVFAIL response: %v", err)
		}
		return err
	}

	// Get ZSK keys for the zone that are in "published" or "active" state
	keys, err := kdcDB.GetDNSSECKeysForZone(zone)
	if err != nil {
		log.Printf("KDC: Error getting keys for zone %s: %v", zone, err)
		m.SetRcode(msg, dns.RcodeServerFailure)
		return w.WriteMsg(m)
	}

	// Filter to ZSK keys that are published or active
	var zskKeys []*DNSSECKey
	for _, key := range keys {
		if key.KeyType == KeyTypeZSK && (key.State == KeyStatePublished || key.State == KeyStateActive) {
			zskKeys = append(zskKeys, key)
		}
	}

	if len(zskKeys) == 0 {
		log.Printf("KDC: No ZSK keys found for zone %s", zone)
		m.SetRcode(msg, dns.RcodeNameError)
		err := w.WriteMsg(m)
		if err != nil {
			log.Printf("KDC: Error writing NXDOMAIN response: %v", err)
		}
		return err
	}

	// Encrypt keys for each node and create KMPKG records
	// For now, we'll encrypt for the first node (or use a default node selection)
	// TODO: Implement proper node selection based on SIG(0) signature
	// Use first online node for now
	node := nodes[0]
	log.Printf("KDC: Encrypting keys for node %s (%s)", node.ID, node.Name)

	// Encrypt each ZSK key
	for _, key := range zskKeys {
		// Encrypt using HPKE with node's long-term public key and ephemeral public key
		// Note: HPKE Base mode uses ephemeral key internally, but we need to use the provided one
		// For now, we'll use the standard EncryptKeyForNode which generates its own ephemeral
		// TODO: Modify encryption to use provided ephemeral key
		encryptedKey, _, distributionID, err := kdcDB.EncryptKeyForNode(key, node)
		if err != nil {
			log.Printf("KDC: Error encrypting key %s for node %s: %v", key.ID, node.ID, err)
			continue
		}
		
		// TODO: Use distributionID
		_ = distributionID

		// Create KMPKG record
		kmpkg := &hpke.KMPKG{
			EncryptedData: encryptedKey,
			Sequence:      0,
			Total:         1,
		}

		// Convert to DNS RR
		kmpkgRR := &dns.PrivateRR{
			Hdr: dns.RR_Header{
				Name:   qname,
				Rrtype: hpke.TypeKMPKG,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Data: kmpkg,
		}

		m.Answer = append(m.Answer, kmpkgRR)
		log.Printf("KDC: Added KMPKG record for key %s (keyid %d)", key.ID, key.KeyID)
	}

	// Add SOA record in Authority section (if we have a control zone)
	if conf.ControlZone != "" {
		soaRR, err := dns.NewRR(fmt.Sprintf("%s. SOA %s. hostmaster.%s. %d 3600 1800 604800 300", conf.ControlZone, conf.ControlZone, conf.ControlZone, time.Now().Unix()))
		if err == nil {
			m.Ns = append(m.Ns, soaRR)
		}
	}

	m.SetRcode(msg, dns.RcodeSuccess)
	log.Printf("KDC: Sending KMREQ response with %d answer RRs, %d authority RRs", len(m.Answer), len(m.Ns))
	err = w.WriteMsg(m)
	if err != nil {
		log.Printf("KDC: Error writing KMREQ response: %v", err)
	} else {
		log.Printf("KDC: KMREQ response sent successfully")
	}
	return err
}

// handleKMCTRLQuery processes KMCTRL queries for control zone information
// The qname should be the control zone name (e.g., "kdc.example.com.")
func handleKMCTRLQuery(ctx context.Context, m *dns.Msg, msg *dns.Msg, qname string, w dns.ResponseWriter, kdcDB *KdcDB, conf *KdcConf) error {
	log.Printf("KDC: Processing KMCTRL query for %s (control zone: %s)", qname, conf.ControlZone)
	
	// Normalize qname to FQDN for comparison
	qnameFQDN := dns.Fqdn(qname)
	controlZoneFQDN := dns.Fqdn(conf.ControlZone)
	
	// Check if query is for the control zone (informational only - we process all KMCTRL queries)
	if qnameFQDN != controlZoneFQDN {
		log.Printf("KDC: KMCTRL query qname %s does not match control zone %s (still processing)", qnameFQDN, controlZoneFQDN)
	}

	// Get all zones
	zones, err := kdcDB.GetAllZones()
	if err != nil {
		log.Printf("KDC: Error getting zones: %v", err)
		m.SetRcode(msg, dns.RcodeServerFailure)
		return w.WriteMsg(m)
	}

	log.Printf("KDC: Found %d zones", len(zones))

	// For each zone, get published/active ZSK keys and create KMCTRL records
	for _, zone := range zones {
		if !zone.Active {
			log.Printf("KDC: Skipping inactive zone %s", zone.Name)
			continue
		}

		log.Printf("KDC: Processing active zone %s", zone.Name)

		keys, err := kdcDB.GetDNSSECKeysForZone(zone.Name)
		if err != nil {
			log.Printf("KDC: Error getting keys for zone %s: %v", zone.Name, err)
			continue
		}

		log.Printf("KDC: Found %d keys for zone %s", len(keys), zone.Name)

		for _, key := range keys {
			// KMCTRL shows only keys that are currently being distributed (distributed state)
			if key.KeyType == KeyTypeZSK && key.State == KeyStateDistributed {
				log.Printf("KDC: Processing ZSK key %s (keytag %d, state %s) for zone %s", key.ID, key.KeyID, key.State, zone.Name)

				// Get or create a stable distribution ID for this key
				distributionID, err := kdcDB.GetOrCreateDistributionID(zone.Name, key)
				if err != nil {
					log.Printf("KDC: Error getting distribution ID for key %s: %v", key.ID, err)
					continue
				}

				log.Printf("KDC: Using distribution ID %s for key %s (keytag %d)", distributionID, key.ID, key.KeyID)

				kmctrl := &hpke.KMCTRL{
					DistributionID: distributionID,
					KeyID:          key.KeyID,
					State:          hpke.KeyState(key.State),
					Timestamp:      uint64(time.Now().Unix()),
					Zone:           zone.Name,
				}

				// Convert to DNS RR
				kmctrlRR := &dns.PrivateRR{
					Hdr: dns.RR_Header{
						Name:   qname,
						Rrtype: hpke.TypeKMCTRL,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Data: kmctrl,
				}

				m.Answer = append(m.Answer, kmctrlRR)
				log.Printf("KDC: Added KMCTRL record for zone %s, key %d (keytag), distribution ID %s, state %s", zone.Name, key.KeyID, distributionID, key.State)
			} else {
				log.Printf("KDC: Skipping key %s (type %s, state %s) - not a distributed ZSK", key.ID, key.KeyType, key.State)
			}
		}
	}

	log.Printf("KDC: KMCTRL query result: %d answer RRs", len(m.Answer))
	if len(m.Answer) == 0 {
		log.Printf("KDC: No KMCTRL records returned - this means there are no ZSK keys in 'distributed' state")
		log.Printf("KDC: (KMCTRL only shows keys that are currently being distributed, not standby keys)")
	}

	// Add SOA record in Authority section
	if conf.ControlZone != "" {
		soaRR, err := dns.NewRR(fmt.Sprintf("%s. SOA %s. hostmaster.%s. %d 3600 1800 604800 300", conf.ControlZone, conf.ControlZone, conf.ControlZone, time.Now().Unix()))
		if err == nil {
			m.Ns = append(m.Ns, soaRR)
		}
	}

	m.SetRcode(msg, dns.RcodeSuccess)
	return w.WriteMsg(m)
}

// extractEphemeralPubKey extracts the ephemeral public key from a DNS message
// It checks EDNS(0) options first, then falls back to the question section
func extractEphemeralPubKey(msg *dns.Msg) ([]byte, error) {
	// TODO: Check EDNS(0) options for ephemeral public key
	// For now, check if there's a KMREQ RR in the question section
	if len(msg.Question) > 0 {
		q := msg.Question[0]
		if q.Qtype == hpke.TypeKMREQ {
			// The ephemeral key might be encoded in the QNAME or we need to extract it differently
			// For now, return an error indicating we need EDNS(0) support
			return nil, fmt.Errorf("ephemeral public key extraction from EDNS(0) not yet implemented")
		}
	}

	return nil, fmt.Errorf("no ephemeral public key found in query")
}

// ParseQnameForJSONMANIFEST extracts nodeid and distributionID from JSONMANIFEST QNAME
// Format: <nodeid><distributionID>.<controlzone>
// Node ID is an FQDN (with trailing dot), so distributionID is concatenated directly after it
func ParseQnameForJSONMANIFEST(qname string, controlZone string) (nodeID, distributionID string, err error) {
	// Remove trailing dot if present
	if len(qname) > 0 && qname[len(qname)-1] == '.' {
		qname = qname[:len(qname)-1]
	}

	// Extract control zone labels
	controlZoneClean := controlZone
	if len(controlZoneClean) > 0 && controlZoneClean[len(controlZoneClean)-1] == '.' {
		controlZoneClean = controlZoneClean[:len(controlZoneClean)-1]
	}
	controlLabels := dns.SplitDomainName(controlZoneClean)

	if len(controlLabels) == 0 {
		return "", "", fmt.Errorf("invalid control zone: %s", controlZone)
	}

	// Check that QNAME ends with control zone
	if !strings.HasSuffix(qname, "."+controlZoneClean) && !strings.HasSuffix(qname, controlZoneClean) {
		return "", "", fmt.Errorf("QNAME %s does not end with control zone %s", qname, controlZone)
	}

	// Remove control zone suffix to get <nodeid><distributionID>
	prefix := qname[:len(qname)-len(controlZoneClean)-1] // -1 for the dot before control zone

	// Find where distribution ID starts (it's hex, so we need to find the boundary)
	// Distribution ID is typically 4 hex characters, but could be longer
	// We'll try to find a valid hex string at the end of the prefix
	// Start from the end and work backwards to find the longest valid hex string
	maxDistIDLen := len(prefix)
	if maxDistIDLen > 8 {
		maxDistIDLen = 8 // Reasonable max for distribution ID
	}

	found := false
	for distIDLen := 4; distIDLen <= maxDistIDLen && distIDLen <= len(prefix); distIDLen++ {
		candidateDistID := prefix[len(prefix)-distIDLen:]
		if _, err := hex.DecodeString(candidateDistID); err == nil {
			// Valid hex string found
			distributionID = candidateDistID
			nodeID = prefix[:len(prefix)-distIDLen]
			// Ensure node ID is FQDN
			if !strings.HasSuffix(nodeID, ".") {
				nodeID = nodeID + "."
			}
			found = true
			break
		}
	}

	if !found {
		return "", "", fmt.Errorf("invalid JSONMANIFEST QNAME format: %s (could not find valid distribution ID)", qname)
	}

	return nodeID, distributionID, nil
}

// ParseQnameForJSONCHUNK extracts chunkid, nodeid, and distributionID from JSONCHUNK QNAME
// Format: <chunkid>.<nodeid><distributionID>.<controlzone>
// Node ID is an FQDN (with trailing dot), so distributionID is concatenated directly after it
func ParseQnameForJSONCHUNK(qname string, controlZone string) (chunkID uint16, nodeID, distributionID string, err error) {
	// Remove trailing dot if present
	if len(qname) > 0 && qname[len(qname)-1] == '.' {
		qname = qname[:len(qname)-1]
	}

	labels := dns.SplitDomainName(qname)
	if len(labels) < 3 {
		return 0, "", "", fmt.Errorf("invalid JSONCHUNK QNAME format: %s (need at least chunkid.nodeid+distID.controlzone)", qname)
	}

	// Parse chunk ID (first label)
	chunkIDUint, err := strconv.ParseUint(labels[0], 10, 16)
	if err != nil {
		return 0, "", "", fmt.Errorf("invalid chunk ID in QNAME: %s (must be uint16)", labels[0])
	}
	chunkID = uint16(chunkIDUint)

	// Extract control zone labels
	controlZoneClean := controlZone
	if len(controlZoneClean) > 0 && controlZoneClean[len(controlZoneClean)-1] == '.' {
		controlZoneClean = controlZoneClean[:len(controlZoneClean)-1]
	}
	controlLabels := dns.SplitDomainName(controlZoneClean)

	if len(controlLabels) == 0 {
		return 0, "", "", fmt.Errorf("invalid control zone: %s", controlZone)
	}

	// Check that the last N labels match the control zone
	controlStartIdx := len(labels) - len(controlLabels)
	if controlStartIdx < 2 {
		return 0, "", "", fmt.Errorf("invalid JSONCHUNK QNAME format: %s (too few labels)", qname)
	}

	for i := 0; i < len(controlLabels); i++ {
		if labels[controlStartIdx+i] != controlLabels[i] {
			return 0, "", "", fmt.Errorf("QNAME %s does not end with control zone %s", qname, controlZone)
		}
	}

	// After removing control zone, we have: <chunkid>.<nodeid><distributionID>
	// Labels from index 1 to controlStartIdx-1 contain <nodeid><distributionID>
	// We need to combine them and find where distribution ID starts
	if controlStartIdx-1 < 1 {
		return 0, "", "", fmt.Errorf("invalid JSONCHUNK QNAME format: %s (missing node ID and distribution ID)", qname)
	}
	prefixLabels := labels[1:controlStartIdx]
	prefix := strings.Join(prefixLabels, ".")

	// Find where distribution ID starts (it's hex, so we need to find the boundary)
	// Distribution ID is typically 4 hex characters, but could be longer
	maxDistIDLen := len(prefix)
	if maxDistIDLen > 8 {
		maxDistIDLen = 8 // Reasonable max for distribution ID
	}

	found := false
	for distIDLen := 4; distIDLen <= maxDistIDLen && distIDLen <= len(prefix); distIDLen++ {
		candidateDistID := prefix[len(prefix)-distIDLen:]
		if _, err := hex.DecodeString(candidateDistID); err == nil {
			// Valid hex string found
			distributionID = candidateDistID
			nodeID = prefix[:len(prefix)-distIDLen]
			// Ensure node ID is FQDN
			if !strings.HasSuffix(nodeID, ".") {
				nodeID = nodeID + "."
			}
			found = true
			break
		}
	}

	if !found {
		return 0, "", "", fmt.Errorf("invalid JSONCHUNK QNAME format: %s (could not find valid distribution ID in %s)", qname, prefix)
	}

	return chunkID, nodeID, distributionID, nil
}

// handleJSONMANIFESTQuery processes JSONMANIFEST queries
// QNAME format: <nodeid>.<distributionID>.<controlzone>
func handleJSONMANIFESTQuery(ctx context.Context, m *dns.Msg, msg *dns.Msg, qname string, w dns.ResponseWriter, kdcDB *KdcDB, conf *KdcConf) error {
	log.Printf("KDC: Processing JSONMANIFEST query for %s", qname)

	// Parse QNAME to extract node ID and distribution ID
	nodeID, distributionID, err := ParseQnameForJSONMANIFEST(qname, conf.ControlZone)
	if err != nil {
		log.Printf("KDC: Error parsing JSONMANIFEST QNAME %s: %v", qname, err)
		m.SetRcode(msg, dns.RcodeFormatError)
		if writeErr := w.WriteMsg(m); writeErr != nil {
			return writeErr
		}
		return fmt.Errorf("failed to parse QNAME: %v", err)
	}

	log.Printf("KDC: JSONMANIFEST node-id=%s, distribution-id=%s", nodeID, distributionID)

	// Get manifest data for this node and distribution
	manifest, err := kdcDB.GetManifestForNode(nodeID, distributionID, conf)
	if err != nil {
		log.Printf("KDC: Error getting manifest for node %s, distribution %s: %v", nodeID, distributionID, err)
		m.SetRcode(msg, dns.RcodeServerFailure)
		if writeErr := w.WriteMsg(m); writeErr != nil {
			return writeErr
		}
		return fmt.Errorf("failed to get manifest: %v", err)
	}

	if manifest == nil {
		log.Printf("KDC: No manifest found for node %s, distribution %s", nodeID, distributionID)
		m.SetRcode(msg, dns.RcodeNameError)
		if writeErr := w.WriteMsg(m); writeErr != nil {
			return writeErr
		}
		return fmt.Errorf("no manifest found for node %s, distribution %s", nodeID, distributionID)
	}

	// Create JSONMANIFEST RR
	manifestRR := &dns.PrivateRR{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: core.TypeJSONMANIFEST,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Data: manifest,
	}

	m.Answer = append(m.Answer, manifestRR)
	m.SetRcode(msg, dns.RcodeSuccess)

	content := "unknown"
	if manifest.Metadata != nil {
		if c, ok := manifest.Metadata["content"].(string); ok {
			content = c
		}
	}
	log.Printf("KDC: Sending JSONMANIFEST response with content=%s, chunk_count=%d", content, manifest.ChunkCount)
	return w.WriteMsg(m)
}

// handleJSONCHUNKQuery processes JSONCHUNK queries
// QNAME format: <chunkid>.<nodeid>.<distributionID>.<controlzone>
func handleJSONCHUNKQuery(ctx context.Context, m *dns.Msg, msg *dns.Msg, qname string, w dns.ResponseWriter, kdcDB *KdcDB, conf *KdcConf) error {
	log.Printf("KDC: Processing JSONCHUNK query for %s", qname)

	// Parse QNAME to extract chunk ID, node ID, and distribution ID
	chunkID, nodeID, distributionID, err := ParseQnameForJSONCHUNK(qname, conf.ControlZone)
	if err != nil {
		log.Printf("KDC: Error parsing JSONCHUNK QNAME %s: %v", qname, err)
		m.SetRcode(msg, dns.RcodeFormatError)
		return w.WriteMsg(m)
	}

	log.Printf("KDC: JSONCHUNK chunk-id=%d, node-id=%s, distribution-id=%s", chunkID, nodeID, distributionID)

	// Get chunk data for this node, distribution, and chunk ID
	chunk, err := kdcDB.GetChunkForNode(nodeID, distributionID, chunkID, conf)
	if err != nil {
		log.Printf("KDC: Error getting chunk %d for node %s, distribution %s: %v", chunkID, nodeID, distributionID, err)
		m.SetRcode(msg, dns.RcodeServerFailure)
		return w.WriteMsg(m)
	}

	if chunk == nil {
		log.Printf("KDC: No chunk %d found for node %s, distribution %s", chunkID, nodeID, distributionID)
		m.SetRcode(msg, dns.RcodeNameError)
		return w.WriteMsg(m)
	}

	// Create JSONCHUNK RR
	chunkRR := &dns.PrivateRR{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: core.TypeJSONCHUNK,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Data: chunk,
	}

	m.Answer = append(m.Answer, chunkRR)
	m.SetRcode(msg, dns.RcodeSuccess)

	log.Printf("KDC: Sending JSONCHUNK response with sequence=%d, total=%d, data_len=%d", chunk.Sequence, chunk.Total, len(chunk.Data))
	return w.WriteMsg(m)
}

// handleConfirmationNotify handles NOTIFY(JSONMANIFEST) messages from KRS confirming receipt of keys
// The NOTIFY QNAME format is: <distributionID>.<controlzone>
func handleConfirmationNotify(ctx context.Context, msg *dns.Msg, qname string, qtype uint16, w dns.ResponseWriter, kdcDB *KdcDB, conf *KdcConf) error {
	// Only handle JSONMANIFEST NOTIFYs as confirmations
	if qtype != core.TypeJSONMANIFEST {
		log.Printf("KDC: Ignoring NOTIFY for non-JSONMANIFEST type %s", dns.TypeToString[qtype])
		return nil
	}

	// Extract distributionID from QNAME: <distributionID>.<controlzone>
	controlZoneFQDN := conf.ControlZone
	if !strings.HasSuffix(controlZoneFQDN, ".") {
		controlZoneFQDN += "."
	}

	if !strings.HasSuffix(qname, controlZoneFQDN) {
		log.Printf("KDC: NOTIFY QNAME %s does not match control zone %s", qname, controlZoneFQDN)
		return fmt.Errorf("invalid NOTIFY QNAME format")
	}

	// Extract distributionID (everything before the control zone)
	prefix := strings.TrimSuffix(qname, controlZoneFQDN)
	if strings.HasSuffix(prefix, ".") {
		prefix = strings.TrimSuffix(prefix, ".")
	}
	
	// Get the last label (distributionID)
	labels := strings.Split(prefix, ".")
	distributionID := labels[len(labels)-1]

	log.Printf("KDC: Processing confirmation NOTIFY for distribution %s from %s", distributionID, w.RemoteAddr())

	// Extract node ID from remote address or from NOTIFY message
	// For now, we'll need to identify the node by matching the remote address
	// or by extracting from SIG(0) if present (future)
	// TODO: Extract node ID from SIG(0) signature or from message metadata
	
	// Get distribution records to find which zone/key this is for
	records, err := kdcDB.GetDistributionRecordsForDistributionID(distributionID)
	if err != nil {
		return fmt.Errorf("failed to get distribution records: %v", err)
	}

	if len(records) == 0 {
		log.Printf("KDC: No distribution records found for distribution %s", distributionID)
		return fmt.Errorf("no distribution records found for distribution %s", distributionID)
	}

	// Use the first record to get zone and key info (all records for same distribution have same zone/key)
	record := records[0]
	zoneID := record.ZoneID
	keyID := record.KeyID

	// For now, we'll identify the node by matching remote address to node notify addresses
	// This is a temporary solution - in the future, we'll use SIG(0) to identify the node
	remoteAddr := w.RemoteAddr().String()
	// Extract IP:port (remove protocol prefix if present)
	parts := strings.Split(remoteAddr, ":")
	if len(parts) < 2 {
		return fmt.Errorf("invalid remote address format: %s", remoteAddr)
	}
	remoteIP := strings.TrimPrefix(parts[0], "[") // Handle IPv6
	remoteIP = strings.TrimSuffix(remoteIP, "]")

	// Find node by matching remote IP to notify address
	allNodes, err := kdcDB.GetAllNodes()
	if err != nil {
		return fmt.Errorf("failed to get nodes: %v", err)
	}

	var confirmedNodeID string
	for _, node := range allNodes {
		if node.NotifyAddress != "" {
			// Extract IP from notify address (format: "IP:port")
			nodeParts := strings.Split(node.NotifyAddress, ":")
			if len(nodeParts) >= 1 {
				nodeIP := nodeParts[0]
				if nodeIP == remoteIP {
					confirmedNodeID = node.ID
					break
				}
			}
		}
	}

	if confirmedNodeID == "" {
		log.Printf("KDC: Warning: Could not identify node from remote address %s, using first node from distribution records", remoteAddr)
		// Fallback: use the node ID from the first distribution record if available
		if record.NodeID != "" {
			confirmedNodeID = record.NodeID
		} else {
			// If no node ID in record, we can't confirm - this shouldn't happen
			return fmt.Errorf("could not identify confirming node")
		}
	}

	log.Printf("KDC: Recording confirmation for distribution %s, zone %s, key %s, node %s", 
		distributionID, zoneID, keyID, confirmedNodeID)

	// Record the confirmation
	if err := kdcDB.AddDistributionConfirmation(distributionID, zoneID, keyID, confirmedNodeID); err != nil {
		return fmt.Errorf("failed to record confirmation: %v", err)
	}

	// Check if all nodes have confirmed
	allConfirmed, err := kdcDB.CheckAllNodesConfirmed(distributionID, zoneID)
	if err != nil {
		log.Printf("KDC: Error checking if all nodes confirmed: %v", err)
		// Don't fail - we've recorded the confirmation
	} else if allConfirmed {
		log.Printf("KDC: All nodes have confirmed distribution %s, transitioning key %s state from 'distributed' to 'edgesigner'", 
			distributionID, keyID)
		
		// Transition key state from 'distributed' to 'edgesigner'
		if err := kdcDB.UpdateKeyState(zoneID, keyID, KeyStateEdgeSigner); err != nil {
			log.Printf("KDC: Error transitioning key state: %v", err)
			// Don't fail - the confirmation was recorded
		} else {
			log.Printf("KDC: Successfully transitioned key %s to 'edgesigner' state", keyID)
		}
	} else {
		// Get list of confirmed nodes for logging
		confirmedNodes, _ := kdcDB.GetDistributionConfirmations(distributionID)
		activeNodes, _ := kdcDB.GetActiveNodes()
		var targetCount int
		for _, node := range activeNodes {
			if node.NotifyAddress != "" {
				targetCount++
			}
		}
		log.Printf("KDC: Distribution %s: %d/%d nodes confirmed (need all %d)", 
			distributionID, len(confirmedNodes), targetCount, targetCount)
	}

	return nil
}

