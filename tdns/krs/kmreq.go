/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * KMREQ query functionality for tdns-krs
 */

package krs

import (
	"fmt"
	"log"

	"github.com/johanix/tdns/tdns/hpke"
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

	// Build QNAME: <distribution-id>.<zone>.<control-zone>
	qname := hpke.BuildKMREQQname(distributionID, zoneID, conf.ControlZone)

	// Create KMREQ query
	msg := new(dns.Msg)
	msg.SetQuestion(qname, hpke.TypeKMREQ)
	msg.RecursionDesired = false // No recursion for KMREQ

	// TODO: Add EDNS(0) option with ephemeral public key
	// For now, we'll encode it in the query somehow (future: use EDNS(0))
	_ = ephemeralPubKey // Will be used in EDNS(0) option when implemented

	// TODO: Send query to KDC
	// msg will be used when we implement the actual DNS query
	_ = msg

	// TODO: Send query to KDC
	// For now, this is a placeholder
	log.Printf("KRS: Would send KMREQ query for distribution %s, zone %s to %s", distributionID, zoneID, nodeConfig.KdcAddress)

	// TODO: Receive KMPKG response and decrypt
	// This will be implemented in decrypt.go

	return nil
}

// QueryKMCTRL queries the control zone for KMCTRL records
func QueryKMCTRL(krsDB *KrsDB, conf *KrsConf) ([]*hpke.KMCTRL, error) {
	nodeConfig, err := krsDB.GetNodeConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get node config: %v", err)
	}

	// Create a DNS query for KMCTRL records in the control zone
	msg := new(dns.Msg)
	msg.SetQuestion(conf.ControlZone, hpke.TypeKMCTRL)
	msg.RecursionDesired = false

	// TODO: Send query to KDC at nodeConfig.KdcAddress
	// For now, this is a placeholder
	log.Printf("KRS: Would query KMCTRL records from control zone %s at %s", conf.ControlZone, nodeConfig.KdcAddress)

	// TODO: Parse response and return KMCTRL records
	return nil, fmt.Errorf("KMCTRL query not yet implemented")
}

// ProcessKMCTRL processes KMCTRL records and triggers KMREQ queries for new keys
func ProcessKMCTRL(krsDB *KrsDB, conf *KrsConf, kmctrlRecords []*hpke.KMCTRL) error {
	for _, kmctrl := range kmctrlRecords {
		// Check if we already have this key
		existingKey, err := krsDB.GetReceivedKey(kmctrl.DistributionID)
		if err == nil && existingKey != nil {
			log.Printf("KRS: Already have key for distribution %s, skipping", kmctrl.DistributionID)
			continue
		}

		// Extract zone from distribution ID or KMCTRL record
		// TODO: This needs to be determined from the KMCTRL record or query context
		zoneID := "" // Placeholder

		// Trigger KMREQ query
		if err := QueryKMREQ(krsDB, conf, kmctrl.DistributionID, zoneID); err != nil {
			log.Printf("KRS: Failed to query KMREQ for distribution %s: %v", kmctrl.DistributionID, err)
			continue
		}
	}

	return nil
}

