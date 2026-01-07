/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * NOTIFY sending functionality for KDC
 */

package kdc

import (
	"fmt"
	"log"
	"strings"

	"github.com/johanix/tdns/v0.x/tdns/core"
	"github.com/johanix/tdns/v0.x/tdns/hpke"
	"github.com/miekg/dns"
)

// SendNotifyToNodes sends NOTIFY messages to all active nodes for a zone
// controlZone is the zone name to query for KMCTRL records (e.g., "kdc.example.com.")
func (kdc *KdcDB) SendNotifyToNodes(zoneName, controlZone string) error {
	// Get all active nodes
	nodes, err := kdc.GetActiveNodes()
	if err != nil {
		return fmt.Errorf("failed to get active nodes: %v", err)
	}

	if len(nodes) == 0 {
		log.Printf("KDC: No active nodes found, skipping NOTIFY")
		return nil
	}

	// Filter nodes that have notify addresses configured
	var targets []string
	for _, node := range nodes {
		if node.NotifyAddress != "" {
			targets = append(targets, node.NotifyAddress)
			log.Printf("KDC: Will send NOTIFY for zone %s to node %s at %s", zoneName, node.ID, node.NotifyAddress)
		} else {
			log.Printf("KDC: Skipping node %s (no notify_address configured)", node.ID)
		}
	}

	if len(targets) == 0 {
		log.Printf("KDC: No nodes with notify_address configured, skipping NOTIFY")
		return nil
	}

	// Send NOTIFY for KMCTRL query type (custom RRtype)
	// The NOTIFY will indicate that nodes should query for KMCTRL records
	notifyType := uint16(hpke.TypeKMCTRL) // Use KMCTRL RRtype (65010)

	successCount := 0
	for _, dst := range targets {
		typeStr := dns.TypeToString[notifyType]
		if typeStr == "" {
			typeStr = fmt.Sprintf("KMCTRL(%d)", notifyType)
		}
		log.Printf("KDC: Sending NOTIFY(%s) for zone %s to %s", typeStr, controlZone, dst)

		m := new(dns.Msg)
		m.SetNotify(controlZone)
		m.Question = []dns.Question{
			{Name: controlZone, Qtype: notifyType, Qclass: dns.ClassINET},
		}

		res, err := dns.Exchange(m, dst)
		if err != nil {
			log.Printf("KDC: Error sending NOTIFY to %s: %v", dst, err)
			continue
		}

		if res.Rcode != dns.RcodeSuccess {
			log.Printf("KDC: NOTIFY to %s returned rcode %s", dst, dns.RcodeToString[res.Rcode])
		} else {
			log.Printf("KDC: NOTIFY to %s succeeded", dst)
			successCount++
		}
	}

	if successCount == 0 {
		return fmt.Errorf("failed to send NOTIFY to any node")
	}

	log.Printf("KDC: Successfully sent NOTIFY to %d/%d nodes", successCount, len(targets))
	return nil
}

// SendNotifyWithDistributionID sends NOTIFY messages to all active nodes for a distribution event
// distributionID is the distribution identifier (e.g., "a1b2")
// controlZone is the control zone name (e.g., "kdc.example.com.")
// The NOTIFY QNAME will be <distributionID>.<controlzone> (e.g., "a1b2.kdc.example.com.")
func (kdc *KdcDB) SendNotifyWithDistributionID(distributionID, controlZone string) error {
	// Get all active nodes
	nodes, err := kdc.GetActiveNodes()
	if err != nil {
		return fmt.Errorf("failed to get active nodes: %v", err)
	}

	if len(nodes) == 0 {
		log.Printf("KDC: No active nodes found, skipping NOTIFY")
		return nil
	}

	// Filter nodes that have notify addresses configured
	var targets []string
	for _, node := range nodes {
		if node.NotifyAddress != "" {
			targets = append(targets, node.NotifyAddress)
			log.Printf("KDC: Will send NOTIFY for distribution %s to node %s at %s", distributionID, node.ID, node.NotifyAddress)
		} else {
			log.Printf("KDC: Skipping node %s (no notify_address configured)", node.ID)
		}
	}

	if len(targets) == 0 {
		log.Printf("KDC: No nodes with notify_address configured, skipping NOTIFY")
		return nil
	}

	// Construct NOTIFY QNAME: <distributionID>.<controlzone>
	// Ensure controlZone is FQDN
	controlZoneFQDN := controlZone
	if !strings.HasSuffix(controlZoneFQDN, ".") {
		controlZoneFQDN += "."
	}
	notifyQname := distributionID + "." + controlZoneFQDN

	// Send NOTIFY for JSONMANIFEST query type
	notifyType := uint16(core.TypeJSONMANIFEST) // Use JSONMANIFEST RRtype (65013)

	successCount := 0
	for _, dst := range targets {
		typeStr := dns.TypeToString[notifyType]
		if typeStr == "" {
			typeStr = fmt.Sprintf("JSONMANIFEST(%d)", notifyType)
		}
		log.Printf("KDC: Sending NOTIFY(%s) for distribution %s (QNAME: %s) to %s", typeStr, distributionID, notifyQname, dst)

		m := new(dns.Msg)
		m.SetNotify(notifyQname)
		m.Question = []dns.Question{
			{Name: notifyQname, Qtype: notifyType, Qclass: dns.ClassINET},
		}

		res, err := dns.Exchange(m, dst)
		if err != nil {
			log.Printf("KDC: Error sending NOTIFY to %s: %v", dst, err)
			continue
		}

		if res.Rcode != dns.RcodeSuccess {
			log.Printf("KDC: NOTIFY to %s returned rcode %s", dst, dns.RcodeToString[res.Rcode])
		} else {
			log.Printf("KDC: NOTIFY to %s succeeded", dst)
			successCount++
		}
	}

	if successCount == 0 {
		return fmt.Errorf("failed to send NOTIFY to any node")
	}

	log.Printf("KDC: Successfully sent NOTIFY to %d/%d nodes", successCount, len(targets))
	return nil
}

