/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * NOTIFY handler for tdns-kdc
 * Handles confirmation NOTIFYs from KRS nodes
 */

package kdc

import (
	"context"
	"log"

	"github.com/johanix/tdns/v0.x/tdns/core"
	"github.com/miekg/dns"
)

// HandleKdcNotify processes NOTIFY messages for the KDC
// This function is called by the NOTIFY handler engine when DnsNotifyQ is non-nil
func HandleKdcNotify(ctx context.Context, msg *dns.Msg, qname string, w dns.ResponseWriter, kdcDB *KdcDB, conf *KdcConf) error {

	log.Printf("KDC: Received NOTIFY message for %s from %s", qname, w.RemoteAddr())
	log.Printf("KDC: NOTIFY details - ID: %d, Opcode: %s, Question count: %d", 
		msg.MsgHdr.Id, dns.OpcodeToString[msg.Opcode], len(msg.Question))

	// Extract QTYPE from question
	var qtype uint16
	if len(msg.Question) > 0 {
		qtype = msg.Question[0].Qtype
	} else {
		log.Printf("KDC: NOTIFY has no question section, ignoring")
		m := new(dns.Msg)
		m.SetReply(msg)
		m.SetRcode(msg, dns.RcodeFormatError)
		return w.WriteMsg(m)
	}

	// Only handle JSONMANIFEST NOTIFYs as confirmations
	if qtype != core.TypeJSONMANIFEST {
		log.Printf("KDC: Ignoring NOTIFY for non-JSONMANIFEST type %s", dns.TypeToString[qtype])
		// Send minimal ACK response
		m := new(dns.Msg)
		m.SetReply(msg)
		m.Authoritative = true
		return w.WriteMsg(m)
	}

	// Handle confirmation NOTIFY
	err := handleConfirmationNotify(ctx, msg, qname, qtype, w, kdcDB, conf)
	if err != nil {
		log.Printf("KDC: Error handling confirmation NOTIFY: %v", err)
	} else {
		log.Printf("KDC: Confirmation NOTIFY handled successfully")
	}

	// Send minimal ACK response
	m := new(dns.Msg)
	m.SetReply(msg)
	m.Authoritative = true
	if err := w.WriteMsg(m); err != nil {
		log.Printf("KDC: Error writing NOTIFY response: %v", err)
		return err
	}

	return err
}

