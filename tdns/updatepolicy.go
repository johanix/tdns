/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"log"
	"strings"

	"github.com/miekg/dns"
)

type DnsHandlerRequest struct {
	ResponseWriter dns.ResponseWriter
	Msg            *dns.Msg
	Qname          string
}

func UpdateResponder(dhr *DnsHandlerRequest, updateq chan UpdateRequest) error {
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
	zd, _ := FindZone(qname)
	if zd == nil {
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return nil // didn't find any zone for that qname
	}

	// dump.P(zd.Options)
	// dump.P(zd.UpdatePolicy)

	// 2. Is qname a zone cut for a child zone?
	// cdd, v4glue, v6glue := zd.FindDelegation(qname, true)

	isdel := zd.IsChildDelegation(qname)
	if isdel {
		zd.Logger.Printf("UpdateResponder: zone %s: qname %s is the name of an existing child zone",
			zd.ZoneName, qname)
		if !zd.Options["allow-child-updates"] || zd.Options["frozen"] {
			zd.Logger.Printf("UpdateResponder: zone %s does not allow child updates like %s. Ignoring update.",
				zd.ZoneName, qname)
			m.SetRcode(r, dns.RcodeRefused)
			w.WriteMsg(m)
			return nil
		}
	} else if zd.NameExists(qname) {
		zd.Logger.Printf("UpdateResponder: qname %s is in auth zone %s", qname, zd.ZoneName)
		if !zd.Options["allow-updates"] || zd.Options["frozen"] {
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
	ok, err := zd.ApproveUpdate(zone, signername, rcode, isdel, r)
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

	cmd := "ZONE-UPDATE"
	if isdel {
		cmd = "CHILD-UPDATE"
	}
	// send into suitable channel for pending updates
	// XXX: This should be separated into updates to auth data in the zone and updates to child data.
	updateq <- UpdateRequest{
		Cmd:       cmd,
		ZoneName:  zone,
		Actions:   r.Ns,
		Validated: rcode == dns.RcodeSuccess,
	}
	return nil
}

func (zd *ZoneData) ApproveUpdate(zone, signername string, rcode uint8, isdel bool,
	r *dns.Msg) (bool, error) {

	switch isdel {
	case true:
		return zd.ApproveChildUpdate(zone, signername, rcode, r)
	default:
		return zd.ApproveAuthUpdate(zone, signername, rcode, r)
	}
}

// Child updates are either validated updates for child delegation data,
// or unvalidated key upload requests.
func (zd *ZoneData) ApproveChildUpdate(zone, signername string, rcode uint8,
	r *dns.Msg) (bool, error) {
	un := ""
	if rcode != dns.RcodeSuccess {
		un = "un"
	}
	log.Printf("Analysing %svalidated update using policy type %s with allowed RR types %v",
		un, zd.UpdatePolicy.Child.Type, zd.UpdatePolicy.Child.RRtypes)

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
		log.Printf("AppUpdate: rrtype=%s keybootstrap=%s class=%s len(r.Ns)=%d",
			dns.TypeToString[rrtype], zd.UpdatePolicy.Child.KeyBootstrap,
			dns.ClassToString[rrclass], len(r.Ns))

		if rrtype == dns.TypeKEY && zd.UpdatePolicy.Child.KeyBootstrap == "unvalidated" &&
			rrclass != dns.ClassNONE && rrclass != dns.ClassANY && len(r.Ns) == 1 {
			// XXX: We've already done both FindZone() and IsChildDelegation() above.
			// This will get fixed when policy.Approval() becomes zd.Approval()
			zd, _ := FindZone(zone)
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

		if !zd.UpdatePolicy.Child.RRtypes[rrtype] {
			log.Printf("ApproveUpdate: update rejected (unapproved RR type: %s)",
				dns.TypeToString[rr.Header().Rrtype])
			return false, nil
		}

		switch zd.UpdatePolicy.Child.Type {
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
				zd.UpdatePolicy.Child.Type)
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
func (zd *ZoneData) ApproveAuthUpdate(zone, signername string, rcode uint8,
	r *dns.Msg) (bool, error) {

	if rcode != dns.RcodeSuccess {
		log.Printf("ApproveUpdate: update rejected (signature did not validate)")
		return false, nil
	}

	var rrtypes []string
	for rrt, _ := range zd.UpdatePolicy.Zone.RRtypes {
		rrtypes = append(rrtypes, dns.TypeToString[rrt])
	}
	log.Printf("Analysing validated update using policy type %s with allowed RR types: %s",
		zd.UpdatePolicy.Zone.Type, strings.Join(rrtypes, ", "))

	for i := 0; i <= len(r.Ns)-1; i++ {
		rr := r.Ns[i]
		rrtype := rr.Header().Rrtype
		rrclass := rr.Header().Class

		log.Printf("AppUpdate: rrtype=%s class=%s len(r.Ns)=%d",
			dns.TypeToString[rrtype], dns.ClassToString[rrclass], len(r.Ns))

		if !zd.UpdatePolicy.Zone.RRtypes[rrtype] {
			log.Printf("ApproveUpdate: update rejected (unapproved RR type: %s)",
				dns.TypeToString[rr.Header().Rrtype])
			return false, nil
		}

		switch zd.UpdatePolicy.Zone.Type {
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

		case "none":
			log.Printf("ApproveUpdate: update rejected (policy type \"none\" disallows all updates)")
			return false, nil
		default:
			log.Printf("ApproveUpdate: unknown policy type: \"%s\"",
				zd.UpdatePolicy.Zone.Type)
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
