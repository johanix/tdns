/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package main

import (
	"log"
	"strings"
	"sync"

	"github.com/gookit/goutil/dump"
	"github.com/johanix/tdns/tdns"
	"github.com/miekg/dns"
)

type UpdatePolicy struct {
	Type      string // only "selfsub" known at the moment
	RRtypes   map[uint16]bool
	KeyUpload string // only "unvalidated" is used
	Verbose   bool
	Debug     bool
}

type DnsHandlerRequest struct {
	ResponseWriter dns.ResponseWriter
	Msg            *dns.Msg
	Qname          string
}

func DnsUpdateResponderEngine(conf *Config) error {
	dnsupdateq := conf.Internal.DnsUpdateQ
	updateq := conf.Internal.UpdateQ

	//        keydir := viper.GetString("ddns.keydirectory")
	//        keymap, err := tdns.ReadPubKeys(keydir)
	//        if err != nil {
	//                log.Fatalf("Error from ReadPublicKeys(%s): %v", keydir, err)
	//        }

	//	polviper := viper.Sub("parentsync.receivers.update")
	//	if polviper == nil {
	//		log.Fatalf("Error: missing config for parentsync.receivers.update")
	//	}

	//	policy := UpdatePolicy{
	//		Type:      polviper.GetString("policy.type"),
	//		RRtypes:   map[uint16]bool{},
	//		KeyUpload: polviper.GetString("policy.keyupload"),
	//		Verbose:   *conf.Service.Verbose,
	//		Debug:     *conf.Service.Debug,
	//	}

	//	switch policy.Type {
	//	case "selfsub", "self":
	//		// all ok, we know these
	//	default:
	//		log.Fatalf("Error: unknown update policy type: \"%s\". Terminating.", policy.Type)
	//	}

	//	var rrtypes []string
	//	for _, rrstr := range polviper.GetStringSlice("policy.rrtypes") {
	//		if rrt, ok := dns.StringToType[rrstr]; ok {
	//			policy.RRtypes[rrt] = true
	//			rrtypes = append(rrtypes, rrstr)
	//		} else {
	//			log.Printf("Unknown RR type: \"%s\". Ignoring.", rrstr)
	//		}
	//	}

	//	if len(policy.RRtypes) == 0 {
	//		log.Fatalf("Error: zero valid RRtypes listed in policy.")
	//	}
	//	log.Printf("DnsUpdateResponderEngine: using update policy \"%s\" with RRtypes: %v", policy.Type, rrtypes)

	log.Printf("*** DnsUpdateResponderEngine: starting")

	var dhr tdns.DnsHandlerRequest

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for {
			select {
			case dhr = <-dnsupdateq:
				tdns.UpdateResponder(&dhr, updateq)
			}
		}
	}()
	wg.Wait()

	log.Println("DnsUpdateResponderEngine: terminating")
	return nil
}

// func UpdateResponder(w dns.ResponseWriter, r *dns.Msg, qname string,
//
//	policy UpdatePolicy, updateq chan UpdateRequest) error {
func xxxUpdateResponder(dhr *DnsHandlerRequest, policy UpdatePolicy, updateq chan tdns.UpdateRequest) error {
	w := dhr.ResponseWriter
	r := dhr.Msg
	qname := dhr.Qname

	m := new(dns.Msg)
	m.SetReply(r)

	log.Printf("UpdateResponder: Received UPDATE for zone '%s' with %d RRs in the update section",
		qname, len(r.Ns))
	// This is a DNS UPDATE, so the Query Section becomes the Zone Section
	zone := qname

	// 1. Is qname inside or below a zone that we're auth for?
	// Let's see if we can find the zone
	zd, _ := tdns.FindZone(qname)
	if zd == nil {
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return nil // didn't find any zone for that qname
	}

	dump.P(zd.Options)
	dump.P(zd.UpdatePolicy)

	// 2. Is qname a zone cut for a child zone?
	// cdd, v4glue, v6glue := zd.FindDelegation(qname, true)

	isdel := zd.IsChildDelegation(qname)
	if isdel {
		zd.Logger.Printf("UpdateResponder: zone %s: qname %s is the name of an existing child zone",
			zd.ZoneName, qname)
		if !zd.Options["allowchildupdates"] {
			zd.Logger.Printf("UpdateResponder: zone %s does not allow child updates like %s. Ignoring update.",
				zd.ZoneName, qname)
			m.SetRcode(r, dns.RcodeRefused)
			w.WriteMsg(m)
			return nil
		}
	} else if zd.NameExists(qname) {
		zd.Logger.Printf("UpdateResponder: qname %s is in auth zone %s", qname, zd.ZoneName)
		if !zd.Options["allowupdates"] {
			zd.Logger.Printf("UpdateResponder: zone %s does not allow updates to auth data %s. Ignoring update.",
				zd.ZoneName, qname)
			m.SetRcode(r, dns.RcodeRefused)
			w.WriteMsg(m)
			return nil
		}
	}

	// Now we know that the update is for the zd.ZoneName zone, whether it is a child delegation update
	// or an update of auth data. In both cases we zone update policy allows it.

	rcode, signername, err := zd.ValidateUpdate(r)
	if err != nil {
		zd.Logger.Printf("Error from ValidateUpdate(): %v", err)
		m.SetRcode(m, dns.RcodeServerFailure)
		// XXX: Here it would be nice to also return an extended error code, but let's save that for later.
		w.WriteMsg(m)
		return err
	}

	// send response
	m = m.SetRcode(m, int(rcode))
	w.WriteMsg(m)

	if rcode != dns.RcodeSuccess {
		zd.Logger.Printf("Error verifying DDNS update. Most likely ignoring contents.")
		// Let's not return here, this could be an unvalidated key upload.
		//		return nil
	}

	// rcode from validation is input to ApproveUpdate only to enable
	// the possibility of upload of unvalidated keys
	ok, err := policy.xxxApproveUpdate(zone, signername, rcode, isdel, r)
	if err != nil {
		zd.Logger.Printf("Error from ApproveUpdate: %v. Ignoring update.", err)
		return err
	}

	if !ok {
		zd.Logger.Printf("DnsEngine: ApproveUpdate rejected the update. Ignored.")
		return nil
	}

	if rcode == dns.RcodeSuccess {
		zd.Logger.Printf("DnsEngine: Update validated and approved. Queued for zone update.")
	} else {
		zd.Logger.Printf("DnsEngine: Update NOT validated BUT still approved. Queued for zone update.")
	}

	// send into suitable channel for pending updates
	// XXX: This should be separated into updates to auth data in the zone and updates to child data.
	updateq <- tdns.UpdateRequest{
		Cmd:       "UPDATE",
		ZoneName:  zone,
		Actions:   r.Ns,
		Validated: rcode == dns.RcodeSuccess,
	}
	return nil
}

func (policy *UpdatePolicy) xxxApproveUpdate(zone, signername string, rcode uint8, isdel bool,
	r *dns.Msg) (bool, error) {

	switch isdel {
	case true:
		return policy.xxxApproveChildUpdate(zone, signername, rcode, r)
	default:
		return policy.xxxApproveAuthUpdate(zone, signername, rcode, r)
	}
}

// Child updates are either validated updates for child delegation data,
// or unvalidated key upload requests.
func (policy *UpdatePolicy) xxxApproveChildUpdate(zone, signername string, rcode uint8,
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
			rrclass != dns.ClassNONE && rrclass != dns.ClassANY && len(r.Ns) == 1 {
			// XXX: We've already done both FindZone() and IsChildDelegation() above.
			// This will get fixed when policy.Approval() becomes zd.Approval()
			zd, _ := tdns.FindZone(zone)
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

// Updates to auth data must be validated.
func (policy *UpdatePolicy) xxxApproveAuthUpdate(zone, signername string, rcode uint8,
	r *dns.Msg) (bool, error) {

	if rcode != dns.RcodeSuccess {
		log.Printf("ApproveUpdate: update rejected (signature did not validate)")
		return false, nil
	}

	log.Printf("Analysing validated update using policy type %s with allowed RR types %v",
		policy.Type, policy.RRtypes)

	for i := 0; i <= len(r.Ns)-1; i++ {
		rr := r.Ns[i]
		rrtype := rr.Header().Rrtype
		rrclass := rr.Header().Class

		log.Printf("AppUpdate: rrtype=%s class=%s len(r.Ns)=%d",
			dns.TypeToString[rrtype], dns.ClassToString[rrclass], len(r.Ns))

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
