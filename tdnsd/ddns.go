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
	Type	  string // only "selfsub" known at the moment
	RRtypes	  map[uint16]bool
	KeyUpload string	// only "unvalidated" is used
	Verbose   bool
	Debug     bool
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
		log.Printf("Error verifying DDNS update. Most likely ignoring contents.")
		// Let's not return here, this could be an unvalidated key upload.
//		return nil
	}

	// rcode from validation is input to ApproveUpdate only to enable
	// the possibility of upload of unvalidated keys
	ok, err := policy.ApproveUpdate(zone, signername, rcode, r)
	if err != nil {
		log.Printf("Error from ApproveUpdate: %v. Ignoring update.", err)
		return err
	}

	if !ok {
		log.Printf("DnsEngine: ApproveUpdate rejected the update. Ignored.")
		return nil
	}

	if rcode == dns.RcodeSuccess {
	   log.Printf("DnsEngine: Update validated and approved. Queued for zone update.")
	} else {
	   log.Printf("DnsEngine: Update NOT validated BUT still approved. Queued for zone update.")
	}

	// send into suitable channel for pending updates
	updateq <- UpdateRequest{
			Cmd:		"UPDATE",
			ZoneName: 	zone,
			Actions: 	r.Ns,
			Validated:	rcode == dns.RcodeSuccess,
		   }
	return nil
}

func (policy *UpdatePolicy) ApproveUpdate(zone, signername string, rcode uint8,
     	     		    			r *dns.Msg) (bool, error) {
	un := ""
	if rcode != dns.RcodeSuccess {
	   un = "un"
	}
	log.Printf("Analysing %svalidated update using policy type %s with allowed RR types %v",
		un, policy.Type, policy.RRtypes)

	for i := 0; i <= len(r.Ns)-1; i++ {
		rr := r.Ns[i]
		rrname := rr.Header().Name
		rrtype := rr.Header().Rrtype
		rrclass := rr.Header().Class

		// Requirement for unvalidated key upload:
		// 1. Policy has keyupload=unvalidated"
		// 2. Single RR in Update section, which is a KEY
		// 3. Class is not NONE or ANY (i.e. not a removal, but an add)
		// 4. Name of key must be == existing delegation
		log.Printf("AppUpdate: rrtype=%s keyupload=%s class=%s len(r.Ns)=%d",
				       dns.TypeToString[rrtype], policy.KeyUpload, 
				       dns.ClassToString[rrclass], len(r.Ns))
				       
		if rrtype == dns.TypeKEY && policy.KeyUpload == "unvalidated" && 
		   rrclass != dns.ClassNONE && rrclass != dns.ClassANY &&
		   len(r.Ns) == 1 {
		   zd := tdns.FindZone(zone)
		   if zd == nil {
		      log.Printf("ApproveUpdate: update rejected (parent zone of %s not known)", rrname)
		      return false, nil
		   }
		   if zd.IsChildDelegation(rrname) {
		      log.Printf("ApproveUpdate: update approved (unvalidated KEY upload)")
		      continue
		   } else {
			log.Printf("ApproveUpdate: update rejected (KEY ADD, but %s is not a child of %s)",
				rrname, zone)
		      return false, nil
		   }
		}
		
		// Past the unvalidated key upload; from here update MUST be validated
		if rcode != dns.RcodeSuccess {
			log.Printf("ApproveUpdate: update rejected (signature did not validate)")
		   	return false, nil 
		}

		if !policy.RRtypes[rrtype] {
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
			log.Printf("ApproveUpdate: unknown policy type: \"%s\"", 
						   policy.Type)
			return false, nil
		}

		switch rrclass {
		case dns.ClassNONE:
			log.Printf("ApproveUpdate: Remove RR: %s", rr.String())
		case dns.ClassANY:
			log.Printf("ApproveUpdate: Remove RRset: %s", rr.String())
		default:
			log.Printf("ApproveUpdate: Add RR: %s", rr.String())
		}
	}
	return true, nil
}

