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

	if len(r.Ns) == 1 {
		qname = r.Ns[0].Header().Name // If there is only one RR in the update, we will use that name as the qname
	}
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

	if zd.Options["frozen"] {
		zd.Logger.Printf("UpdateResponder: zone %s is frozen (i.e. updates not possible). Ignoring update.",
			zd.ZoneName, qname)
		m.SetRcode(r, dns.RcodeRefused)
		w.WriteMsg(m)
		return nil
	}

	isdel := false

	// 1. Is qname the apex of this zone?
	if qname == zd.ZoneName {
		zd.Logger.Printf("UpdateResponder: zone %s: qname %s is the apex of this zone",
			zd.ZoneName, qname)
		if !zd.Options["allow-updates"] || zd.Options["frozen"] {
			zd.Logger.Printf("UpdateResponder: zone %s does not allow updates to auth data %s. Ignoring update.",
				zd.ZoneName, qname)
			m.SetRcode(r, dns.RcodeRefused)
			w.WriteMsg(m)
			return nil
		}
		// 2. Is qname a zone cut for a child zone?
	} else if zd.IsChildDelegation(qname) {
		isdel = true
		zd.Logger.Printf("UpdateResponder: zone %s: qname %s is the name of an existing child zone",
			zd.ZoneName, qname)
		if !zd.Options["allow-child-updates"] || zd.Options["frozen"] {
			zd.Logger.Printf("UpdateResponder: zone %s does not allow child updates like %s. Ignoring update.",
				zd.ZoneName, qname)
			m.SetRcode(r, dns.RcodeRefused)
			w.WriteMsg(m)
			return nil
		}
		// 3. Does qname exist in auth zone?
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
	// or an update of auth data. In both cases we should validate the update and then see
	// if the update policy allows the update.

	// XXX: Note that the validation process may find that the update is signed by a previously
	// unknown key. If so that key will be looked up and if possible (according to policy) be
	// validated and trusted.

	// XXX: Also note that if the SIG(0) key is present in a zone that we are authoritative for (i.e.
	// this is an update to auth data) then the update will validate and the SIG(0) key will be
	// trusted. We always trust SIG(0) keys in the zone we are authoritative for.
	rcode, validated, trusted, signername, err := zd.ValidateAndTrustUpdate(r)
	if err != nil {
		zd.Logger.Printf("Error from ValidateAndTrustUpdate(): %v", err)
		m.SetRcode(m, dns.RcodeServerFailure)
		// XXX: Here it would be nice to also return an extended error code, but let's save that for later.
		w.WriteMsg(m)
		return err
	}

	log.Printf("UpdateResponder: isdel=%v ValidateAndTrustUpdate returned rcode=%d, validated=%t, trusted=%t, signername=%s",
		isdel, rcode, validated, trusted, signername)
	// send response
	m = m.SetRcode(m, int(rcode))
	w.WriteMsg(m)

	if rcode != dns.RcodeSuccess {
		zd.Logger.Printf("Error verifying DNS UPDATE. Most likely ignoring contents.")
		// Let's not return here, this could be an unvalidated key upload.
		//		return nil
	}

	if !validated {
		zd.Logger.Printf("DnsEngine: Update NOT validated. Ignored.")
		return nil
	}

	// rcode from validation is input to ApproveUpdate only to enable
	// the possibility of upload of unvalidated keys
	approved, updatezone, err := zd.ApproveUpdate(zone, signername, rcode, validated, trusted, isdel, r)
	if err != nil {
		zd.Logger.Printf("Error from ApproveUpdate: %v. Ignoring update.", err)
		return err
	}

	if !approved {
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
	if !updatezone {
		cmd = "TRUSTSTORE-UPDATE"
	}

	log.Printf("UpdateResponder: cmd=%s zone=%s validated=%v trusted=%v", cmd, zone, validated, trusted)

	// send into suitable channel for pending updates
	// XXX: This should be separated into updates to auth data in the zone and updates to child data.
	updateq <- UpdateRequest{
		Cmd:       cmd,
		ZoneName:  zone,
		Actions:   r.Ns,
		Validated: validated,
		Trusted:   trusted,
	}
	return nil
}

// Returns approved, updatezone, error
func (zd *ZoneData) ApproveUpdate(zone, signername string, rcode uint8, validated, trusted, isdel bool,
	r *dns.Msg) (bool, bool, error) {

	switch isdel {
	case true:
		return zd.ApproveChildUpdate(zone, signername, rcode, validated, trusted, r)
	default:
		return zd.ApproveAuthUpdate(zone, signername, rcode, validated, trusted, r)
	}
}

// Child updates are either validated updates for child delegation data,
// or unvalidated key upload requests.
// Returns approved, updatezone, error
func (zd *ZoneData) ApproveChildUpdate(zone, signername string, rcode uint8, validated, trusted bool,
	r *dns.Msg) (bool, bool, error) {
	un := ""
	if rcode != dns.RcodeSuccess || !validated {
		un = "un"
	}
	log.Printf("Analysing %svalidated update using policy type %s with allowed RR types %v",
		un, zd.UpdatePolicy.Child.Type, zd.UpdatePolicy.Child.RRtypes)

	unvalidatedKeyUpload := false
	for i := 0; i <= len(r.Ns)-1; i++ {
		rr := r.Ns[i]
		// rrname := rr.Header().Name
		rrtype := rr.Header().Rrtype
		rrclass := rr.Header().Class

		// Requirement for unvalidated key upload:
		// 1. Policy has keyupload=unvalidated"
		// 2. Single RR in Update section, which is a KEY
		// 3. Class is not NONE or ANY (i.e. not a removal, but an add)
		// 4. Name of key must be == existing delegation
		log.Printf("ApproveChildUpdate: rrtype=%s keybootstrap=%s class=%s len(r.Ns)=%d",
			dns.TypeToString[rrtype], zd.UpdatePolicy.Child.KeyBootstrap,
			dns.ClassToString[rrclass], len(r.Ns))

		if !trusted {
			// If the update is not trusted (i.e. validated against a trusted key) it should be
			// rejected, except in the special case of unvalidated key uploads.

			if rrtype != dns.TypeKEY {
				log.Printf("ApproveChildUpdate: update of %s RRset rejected (signed by an untrusted key)",
					dns.TypeToString[rrtype])
				return false, false, nil
			}

			if rrclass == dns.ClassNONE || rrclass == dns.ClassANY {
				log.Printf("ApproveChildUpdate: update of KEY RRset rejected (delete operation signed by untrusted key)",
					dns.TypeToString[rrtype])
				return false, false, nil
			}

			if len(r.Ns) != 1 {
				log.Printf("ApproveChildUpdate: update of KEY RRset rejected (only a single KEY record allowed to be added by untrusted key)")
				return false, false, nil
			}

			// This is the special case that we allow for unvalidated key uploads.
			if zd.UpdatePolicy.Child.KeyUpload == "unvalidated" { // exactly one SIG(0) key
				for _, bootstrap := range zd.UpdatePolicy.Child.KeyBootstrap {
					if bootstrap == "strict-manual" {
						log.Printf("ApproveChildUpdate: keybootstrap=strict-manual prohibits unvalidated KEY upload")
						return false, false, nil
					}
				}
				// XXX: I think we should require that this KEY upload is self-signed.
				log.Printf("ApproveChildUpdate: update approved (unvalidated KEY upload)")
				unvalidatedKeyUpload = true
			}
		}

		// Past the unvalidated key upload; from here update MUST be validated
		if (rcode != dns.RcodeSuccess || !validated) && !unvalidatedKeyUpload {
			log.Printf("ApproveUpdate: update rejected (signature did not validate)")
			return false, false, nil
		}

		if !trusted && !unvalidatedKeyUpload {
			log.Printf("ApproveUpdate: update rejected (signature validated but key not trusted)")
			return false, false, nil
		}

		if !zd.UpdatePolicy.Child.RRtypes[rrtype] {
			log.Printf("ApproveUpdate: update rejected (unapproved RR type: %s)",
				dns.TypeToString[rr.Header().Rrtype])
			return false, false, nil
		}

		switch zd.UpdatePolicy.Child.Type {
		case "selfsub":
			if !strings.HasSuffix(rr.Header().Name, signername) {
				log.Printf("ApproveUpdate: update rejected (owner name %s outside selfsub %s tree)",
					rr.Header().Name, signername)
				return false, false, nil
			}

		case "self":
			if rr.Header().Name != signername {
				log.Printf("ApproveUpdate: update rejected (owner name %s different from signer name %s in violation of \"self\" policy)",
					rr.Header().Name, signername)
				return false, false, nil
			}
		default:
			log.Printf("ApproveUpdate: unknown policy type: \"%s\"",
				zd.UpdatePolicy.Child.Type)
			return false, false, nil
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
	updateZone := !unvalidatedKeyUpload

	return true, updateZone, nil
}

// Updates to auth data must be validated.
func (zd *ZoneData) ApproveAuthUpdate(zone, signername string, rcode uint8, validated, trusted bool,
	r *dns.Msg) (bool, bool, error) {

	if rcode != dns.RcodeSuccess || !validated {
		log.Printf("ApproveUpdate: update rejected (signature did not validate)")
		return false, false, nil
	}

	if !trusted {
		log.Printf("ApproveUpdate: update rejected (signature validated but key not trusted)")
		return false, false, nil
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

		log.Printf("ApproveAuthUpdate: rrtype=%s class=%s len(r.Ns)=%d",
			dns.TypeToString[rrtype], dns.ClassToString[rrclass], len(r.Ns))

		if !zd.UpdatePolicy.Zone.RRtypes[rrtype] {
			log.Printf("ApproveAuthUpdate: update rejected (unapproved RR type: %s)",
				dns.TypeToString[rr.Header().Rrtype])
			return false, false, nil
		}

		switch zd.UpdatePolicy.Zone.Type {
		case "selfsub":
			if !strings.HasSuffix(rr.Header().Name, signername) {
				log.Printf("ApproveAuthUpdate: update rejected (owner name %s outside selfsub %s tree)",
					rr.Header().Name, signername)
				return false, false, nil
			}

		case "self":
			if rr.Header().Name != signername {
				log.Printf("ApproveUpdate: update rejected (owner name %s different from signer name %s in violation of \"self\" policy)",
					rr.Header().Name, signername)
				return false, false, nil
			}

		case "none":
			log.Printf("ApproveUpdate: update rejected (policy type \"none\" disallows all updates)")
			return false, false, nil
		default:
			log.Printf("ApproveUpdate: unknown policy type: \"%s\"",
				zd.UpdatePolicy.Zone.Type)
			return false, false, nil
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
	return true, true, nil
}
