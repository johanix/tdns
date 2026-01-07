/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KMREQ query functionality for tdns-krs
 */

package krs

import (
	"fmt"
	"log"

	"github.com/johanix/tdns/v0.x/tdns/hpke"
	"github.com/miekg/dns"
)

// QueryKMREQ sends a KMREQ query to the KDC to request a key
// distributionID: The distribution ID from KMCTRL record
// zoneID: The zone name
func QueryKMREQ(krsDB *KrsDB, conf *KrsConf, distributionID, zoneID string) error {
	// Get node config
	nodeConfig, err := krsDB.GetNodeConfig()
	if err != nil {
		return fmt.Errorf("failed to get node config: %v", err)
	}

	// Generate ephemeral HPKE keypair
	ephemeralPubKey, ephemeralPrivKey, err := hpke.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate ephemeral keypair: %v", err)
	}

	// ephemeralPrivKey will be needed later for decryption, but not used in query construction
	_ = ephemeralPrivKey

	if nodeConfig.KdcAddress == "" {
		return fmt.Errorf("KDC address not configured")
	}

	// Build QNAME: <distribution-id>.<zone>.<control-zone>
	qname := hpke.BuildKMREQQname(distributionID, zoneID, conf.ControlZone)

	// Create KMREQ query
	msg := new(dns.Msg)
	msg.SetQuestion(qname, hpke.TypeKMREQ)
	msg.RecursionDesired = false // No recursion for KMREQ

	// TODO: Add EDNS(0) option with ephemeral public key
	// For now, we'll encode it in the query somehow (future: use EDNS(0))
	_ = ephemeralPubKey // Will be used in EDNS(0) option when implemented

	log.Printf("KRS: Sending KMREQ query for distribution %s, zone %s to %s", distributionID, zoneID, nodeConfig.KdcAddress)
	log.Printf("KRS: KMREQ query details: QNAME=%s, QTYPE=KMREQ, ID=%d", qname, hpke.TypeKMREQ, msg.MsgHdr.Id)

	// Send query to KDC
	resp, err := dns.Exchange(msg, nodeConfig.KdcAddress)
	if err != nil {
		log.Printf("KRS: Error sending KMREQ query to %s: %v", nodeConfig.KdcAddress, err)
		return fmt.Errorf("failed to send KMREQ query to %s: %v", nodeConfig.KdcAddress, err)
	}

	log.Printf("KRS: Received KMREQ response: RCODE=%s (%d), ID=%d, Answer count=%d, Additional count=%d",
		dns.RcodeToString[resp.Rcode], resp.Rcode, resp.MsgHdr.Id, len(resp.Answer), len(resp.Extra))

	if resp.Rcode != dns.RcodeSuccess {
		log.Printf("KRS: KMREQ query returned non-success RCODE: %s", dns.RcodeToString[resp.Rcode])
		return fmt.Errorf("KMREQ query returned rcode %s", dns.RcodeToString[resp.Rcode])
	}

	// Log response details
	if len(resp.Answer) > 0 {
		log.Printf("KRS: KMREQ response contains %d answer RR(s)", len(resp.Answer))
		for i, rr := range resp.Answer {
			log.Printf("KRS: Answer[%d]: %s %s", i, dns.TypeToString[rr.Header().Rrtype], rr.Header().Name)
		}
	} else {
		log.Printf("KRS: KMREQ response has no answer RRs")
	}

	// TODO: Parse KMPKG records from response and decrypt
	// This will be implemented in decrypt.go
	log.Printf("KRS: KMREQ query completed successfully (decryption not yet implemented)")

	return nil
}

// QueryKMCTRL queries the control zone for KMCTRL records
func QueryKMCTRL(krsDB *KrsDB, conf *KrsConf) ([]*hpke.KMCTRL, error) {
	nodeConfig, err := krsDB.GetNodeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get node config: %v", err)
	}

	if nodeConfig.KdcAddress == "" {
		return nil, fmt.Errorf("KDC address not configured")
	}

	// Create a DNS query for KMCTRL records in the control zone
	msg := new(dns.Msg)
	msg.SetQuestion(conf.ControlZone, hpke.TypeKMCTRL)
	msg.RecursionDesired = false

	log.Printf("KRS: Querying KMCTRL records from control zone %s at %s", conf.ControlZone, nodeConfig.KdcAddress)

	// Send query to KDC
	resp, err := dns.Exchange(msg, nodeConfig.KdcAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to send KMCTRL query to %s: %v", nodeConfig.KdcAddress, err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("KMCTRL query returned rcode %s", dns.RcodeToString[resp.Rcode])
	}

	// Parse KMCTRL records from response
	var kmctrlRecords []*hpke.KMCTRL
	for _, rr := range resp.Answer {
		if privRR, ok := rr.(*dns.PrivateRR); ok && privRR.Hdr.Rrtype == hpke.TypeKMCTRL {
			if kmctrl, ok := privRR.Data.(*hpke.KMCTRL); ok {
				log.Printf("KRS: Parsed KMCTRL record: distribution=%s, keyid=%d, state=%s, zone=%s",
					kmctrl.DistributionID, kmctrl.KeyID, kmctrl.State, kmctrl.Zone)
				kmctrlRecords = append(kmctrlRecords, kmctrl)
			} else {
				log.Printf("KRS: Warning: KMCTRL record has unexpected data type: %T", privRR.Data)
			}
		}
	}

	log.Printf("KRS: Successfully retrieved %d KMCTRL record(s)", len(kmctrlRecords))
	return kmctrlRecords, nil
}

// ProcessKMCTRL processes KMCTRL records and triggers KMREQ queries for new keys
func ProcessKMCTRL(krsDB *KrsDB, conf *KrsConf, kmctrlRecords []*hpke.KMCTRL) error {
	for _, kmctrl := range kmctrlRecords {
		// Check if we already have this key
		existingKey, err := krsDB.GetReceivedKey(kmctrl.DistributionID)
		if err == nil && existingKey != nil {
			log.Printf("KRS: Already have key for distribution %s (zone %s), skipping", kmctrl.DistributionID, kmctrl.Zone)
			continue
		}

		// Use zone from KMCTRL record
		if kmctrl.Zone == "" {
			log.Printf("KRS: KMCTRL record for distribution %s has no zone name, skipping", kmctrl.DistributionID)
			continue
		}

		log.Printf("KRS: Processing KMCTRL record: distribution=%s, zone=%s, keyid=%d, state=%s",
			kmctrl.DistributionID, kmctrl.Zone, kmctrl.KeyID, kmctrl.State)

		// Trigger KMREQ query
		if err := QueryKMREQ(krsDB, conf, kmctrl.DistributionID, kmctrl.Zone); err != nil {
			log.Printf("KRS: Failed to query KMREQ for distribution %s (zone %s): %v", kmctrl.DistributionID, kmctrl.Zone, err)
			continue
		}
	}

	return nil
}

