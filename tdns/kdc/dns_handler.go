/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * DNS query handler for tdns-kdc
 * Handles KMREQ, KMCTRL, and other queries
 */

package kdc

import (
	"context"
	"fmt"
	"log"
	"time"

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

