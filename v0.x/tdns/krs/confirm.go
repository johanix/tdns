/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * Confirmation sending functionality for KRS
 */

package krs

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/johanix/tdns/v0.x/tdns/core"
	"github.com/miekg/dns"
)

// SendConfirmationToKDC sends a NOTIFY(JSONMANIFEST) back to KDC to confirm receipt of keys
// distributionID: The distribution ID that was received
// controlZone: The control zone name (e.g., "kdc.example.com.")
// kdcAddress: The KDC server address (IP:port)
func SendConfirmationToKDC(distributionID, controlZone, kdcAddress string) error {
	// Construct NOTIFY QNAME: <distributionID>.<controlzone>
	// Ensure controlZone is FQDN
	controlZoneFQDN := controlZone
	if !strings.HasSuffix(controlZoneFQDN, ".") {
		controlZoneFQDN += "."
	}
	notifyQname := distributionID + "." + controlZoneFQDN

	// Send NOTIFY for JSONMANIFEST query type
	notifyType := uint16(core.TypeJSONMANIFEST) // Use JSONMANIFEST RRtype (65013)

	typeStr := dns.TypeToString[notifyType]
	if typeStr == "" {
		typeStr = fmt.Sprintf("JSONMANIFEST(%d)", notifyType)
	}
	log.Printf("KRS: Sending confirmation NOTIFY(%s) for distribution %s (QNAME: %s) to %s", typeStr, distributionID, notifyQname, kdcAddress)

	m := new(dns.Msg)
	m.SetNotify(notifyQname)
	m.Question = []dns.Question{
		{Name: notifyQname, Qtype: notifyType, Qclass: dns.ClassINET},
	}

	// Create a DNS client with a reasonable timeout for NOTIFY
	client := &dns.Client{
		Timeout: 5 * time.Second, // 5 second timeout for NOTIFY
		Net:     "udp",
	}

	res, _, err := client.Exchange(m, kdcAddress)
	if err != nil {
		log.Printf("KRS: Error sending confirmation NOTIFY to %s: %v", kdcAddress, err)
		return fmt.Errorf("failed to send confirmation NOTIFY to %s: %v", kdcAddress, err)
	}

	if res == nil {
		log.Printf("KRS: Confirmation NOTIFY to %s returned nil response", kdcAddress)
		return fmt.Errorf("confirmation NOTIFY returned nil response")
	}

	if res.Rcode != dns.RcodeSuccess {
		log.Printf("KRS: Confirmation NOTIFY to %s returned rcode %s", kdcAddress, dns.RcodeToString[res.Rcode])
		return fmt.Errorf("confirmation NOTIFY returned rcode %s", dns.RcodeToString[res.Rcode])
	}

	log.Printf("KRS: Confirmation NOTIFY to %s succeeded", kdcAddress)
	return nil
}

