/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	"log"
	"strings"

	"github.com/miekg/dns"
	"github.com/johanix/tdns/tdns"
)

type UpdatePolicy struct {
	Type    string // only "selfsub" known at the moment
	RRtypes map[uint16]bool
	Verbose bool
	Debug   bool
}

func UpdateResponder(w dns.ResponseWriter, r *dns.Msg, qname string,
     		       policy UpdatePolicy, updateq chan UpdateRequest) error {

	m := new(dns.Msg)
	m.SetReply(r)

	// This is a DDNS update, then the Query Section becomes the Zone Section
        zone := qname
	
	// Let's see if we can find the zone
	zd := tdns.FindZone(qname)
	if zd == nil {
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return nil // didn't find any zone for that qname
	}

	rcode, signername, err := zd.ValidateUpdate(r)
	if err != nil {
		log.Printf("Error from ValidateUpdate(): %v", err)
		return err
	}

	// send response
	m = m.SetRcode(m, int(rcode))
	w.WriteMsg(m)

	if rcode != dns.RcodeSuccess {
		log.Printf("Error verifying DDNS update. Ignoring contents.")
	}

	ok, err := policy.ApproveUpdate(zone, signername, r)
	if err != nil {
		log.Printf("Error from ApproveUpdate: %v. Ignoring update.", err)
		return err
	}

	if !ok {
		log.Printf("DnsEngine: ApproveUpdate rejected the update. Ignored.")
		return nil
	}
	log.Printf("DnsEngine: Update validated and approved. Queued for zone update.")

	// send into suitable channel for pending updates
	updateq <- UpdateRequest{Cmd: "UPDATE", ZoneName: zone, Actions: r.Ns}
	return nil
}

func (policy *UpdatePolicy) ApproveUpdate(zone, signername string, r *dns.Msg) (bool, error) {
	log.Printf("Analysing update using policy type %s with allowed RR types %v",
		policy.Type, policy.RRtypes)

	for i := 0; i <= len(r.Ns)-1; i++ {
		rr := r.Ns[i]

		if !policy.RRtypes[rr.Header().Rrtype] {
			log.Printf("ApproveUpdate: update rejected (unapproved RR type: %s)",
				dns.TypeToString[rr.Header().Rrtype])
			return false, nil
		}

		switch policy.Type {
		case "selfsub":
			if !strings.HasSuffix(rr.Header().Name, signername) {
				log.Printf("ApproveUpdate: update rejected (owner name %s outside selfsub %s tree)",
					rr.Header().Name, signername)
				return false, nil
			}

		case "self":
			if rr.Header().Name != signername {
				log.Printf("ApproveUpdate: update rejected (owner name %s different from signer name %s in violation of \"self\" policy)",
					rr.Header().Name, signername)
				return false, nil
			}
		default:
			log.Printf("ApproveUpdate: unknown policy type: \"%s\"", policy.Type)
			return false, nil
		}

		if rr.Header().Class == dns.ClassNONE {
			log.Printf("ApproveUpdate: Remove RR: %s", rr.String())
		} else if rr.Header().Class == dns.ClassANY {
			log.Printf("ApproveUpdate: Remove RRset: %s", rr.String())
		} else {
			log.Printf("ApproveUpdate: Add RR: %s", rr.String())
		}
	}
	return true, nil
}