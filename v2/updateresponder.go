/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"strings"

	// "github.com/gookit/goutil/dump"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

type DnsHandlerRequest struct {
	ResponseWriter dns.ResponseWriter
	Msg            *dns.Msg
	Qname          string
}

type DnsUpdateRequest struct {
	ResponseWriter dns.ResponseWriter
	Msg            *dns.Msg
	Qname          string
	Options        *edns0.MsgOptions
	Status         *UpdateStatus
}

type DnsNotifyRequest struct {
	ResponseWriter dns.ResponseWriter
	Msg            *dns.Msg
	Qname          string
	Options        *edns0.MsgOptions
	Status         *NotifyStatus
}

type DnsQueryRequest struct {
	ResponseWriter dns.ResponseWriter
	Msg            *dns.Msg
	Qname          string
	Qtype          uint16
	Options        *edns0.MsgOptions
}

func UpdateHandler(ctx context.Context, conf *Config) error {
	dnsupdateq := conf.Internal.DnsUpdateQ
	updateq := conf.Internal.UpdateQ

	lgHandler.Info("DnsUpdateResponderEngine starting")

	//	var wg sync.WaitGroup
	//	wg.Add(1)
	//    go func() {
	//		defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			lgHandler.Info("DnsUpdateResponderEngine: context cancelled")
			return nil
		case dhr, ok := <-dnsupdateq:
			if !ok {
				lgHandler.Info("DnsUpdateResponderEngine: dnsupdateq closed")
				return nil
			}
			err := UpdateResponder(&dhr, updateq)
			if err != nil {
				lgHandler.Error("error from UpdateResponder", "err", err)
			}
		}
	}
}

func UpdateResponder(dur *DnsUpdateRequest, updateq chan UpdateRequest) error {
	w := dur.ResponseWriter
	r := dur.Msg
	qname := dur.Qname

	m := new(dns.Msg)
	m.SetReply(r)
	var opt *dns.OPT

	lgHandler.Info("received UPDATE", "zone", qname, "updateRRs", len(r.Ns), "additionalRRs", len(r.Extra))

	if len(r.Ns) > 0 {
		lgHandler.Debug("update section RRs", "count", len(r.Ns))
		//		for _, rr := range r.Ns {
		//			log.Printf("UpdateResponder: Update RR: %s", rr.String())
		//		}
		lgHandler.Debug("update contents", "updates", SprintUpdates(r.Ns))
	}
	if len(r.Extra) > 0 {
		lgHandler.Debug("additional section RRs", "count", len(r.Extra))
		for _, rr := range r.Extra {
			lgHandler.Debug("additional RR", "rr", rr.String())
			if rr.Header().Rrtype == dns.TypeOPT {
				opt = new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
			}
		}
	}

	// example of how to populate an OPT RR. This is a DNS Cookie, we're interested in the EDE.
	//	o := new(dns.OPT)
	// o.Hdr.Name = "."
	// o.Hdr.Rrtype = dns.TypeOPT
	// e := new(dns.EDNS0_COOKIE)
	// e.Code = dns.EDNS0COOKIE
	// e.Cookie = "24a5ac.."
	// o.Option = append(o.Option, e)

	// This is a DNS UPDATE, so the Query Section becomes the Zone Section
	zone := qname

	if len(r.Ns) == 1 {
		qname = r.Ns[0].Header().Name // If there is only one RR in the update, we will use that name as the qname
	}
	// 1. Is qname inside or below a zone that we're auth for?
	// Let's see if we can find the zone
	zd, _ := FindZone(qname)
	if zd == nil {
		lgHandler.Warn("zone not found", "qname", qname)
		m.SetRcode(r, dns.RcodeRefused)
		edns0.AttachEDEToResponse(m, edns0.EDEZoneNotFound)
		w.WriteMsg(m)
		return nil // didn't find any zone for that qname
	}

	if zd.Error {
		lgHandler.Error("zone in error state", "qname", qname, "errorType", ErrorTypeToString[zd.ErrorType], "errorMsg", zd.ErrorMsg)
		m.SetRcode(r, dns.RcodeServerFailure)
		edns0.AttachEDEToResponse(m, edns0.EDEZoneNotFound)
		w.WriteMsg(m)
		return nil // didn't find any zone for that qname
	}

	// dump.P(zd.Options)
	// dump.P(zd.UpdatePolicy)

	if zd.Options[OptFrozen] {
		lgHandler.Warn("zone is frozen, ignoring update", "zone", zd.ZoneName, "owner", qname)
		m.SetRcode(r, dns.RcodeRefused)
		edns0.AttachEDEToResponse(m, edns0.EDEZoneFrozen)
		w.WriteMsg(m)
		return nil
	}

	// isdel := false

	lgHandler.Debug("setting update type", "zone", zd.ZoneName, "qname", qname)
	// 1. Is qname the apex of this zone?
	if qname == zd.ZoneName {
		// Per RFC 2136 the QNAME is the zone being updated. Check whether all RRs in the
		// update section target a single existing child delegation (at or below the delegation
		// point). If so, this is a child delegation sync, not a zone update.
		childDel := ""
		isChildUpdate := len(r.Ns) > 0
		for _, rr := range r.Ns {
			ownerName := rr.Header().Name
			rrtype := rr.Header().Rrtype

			if rrtype == dns.TypeNS || rrtype == dns.TypeDS {
				// NS and DS must be at a child delegation point
				if !zd.IsChildDelegation(ownerName) {
					isChildUpdate = false
					break
				}
				if childDel == "" {
					childDel = ownerName
				} else if childDel != ownerName {
					isChildUpdate = false
					break
				}
			} else {
				// Glue (A, AAAA, etc.) must be below an existing child delegation.
				// Walk up the labels to find the delegation point.
				found := false
				labels := dns.SplitDomainName(ownerName)
				for i := 1; i < len(labels); i++ {
					ancestor := dns.Fqdn(strings.Join(labels[i:], "."))
					if ancestor == zd.ZoneName {
						break
					}
					if zd.IsChildDelegation(ancestor) {
						if childDel == "" {
							childDel = ancestor
						} else if childDel != ancestor {
							isChildUpdate = false
							break
						}
						found = true
						break
					}
				}
				if !found {
					isChildUpdate = false
					break
				}
			}
		}

		if isChildUpdate && childDel != "" {
			lgHandler.Info("update targets child delegation", "child", childDel)
			dur.Status.Type = "CHILD-UPDATE"
			if !zd.Options[OptAllowChildUpdates] {
				lgHandler.Warn("zone does not allow child updates, ignoring", "zone", zd.ZoneName, "child", childDel)
				m.SetRcode(r, dns.RcodeRefused)
				w.WriteMsg(m)
				return nil
			}
		} else {
			dur.Status.Type = "ZONE-UPDATE"
			zd.Logger.Printf("UpdateResponder: zone %s: qname %s is the apex of this zone",
				zd.ZoneName, qname)
			if !zd.Options[OptAllowUpdates] {
				lgHandler.Warn("zone does not allow updates to auth data, ignoring", "zone", zd.ZoneName, "qname", qname)
				m.SetRcode(r, dns.RcodeRefused)
				edns0.AttachEDEToResponse(m, edns0.EDEZoneUpdatesNotAllowed)
				w.WriteMsg(m)
				return nil
			}
		}
		// 2. Is qname a zone cut for a child zone? If so, we classify this as a CHILD-UPDATE
		// even though it may be a KEY update and hence really a TRUSTSTORE-UPDATE. But we don't know that until
		// we have validated the contents of update.
	} else if zd.IsChildDelegation(qname) {
		zd.Logger.Printf("UpdateResponder: zone %s: qname %s is the name of an existing child zone",
			zd.ZoneName, qname)
		// There are two cases here: update of child delegation data or update of a KEY RR.
		switch {
		case len(r.Ns) == 1 && r.Ns[0].Header().Rrtype == dns.TypeKEY:
			dur.Status.Type = "TRUSTSTORE-UPDATE"
			// XXX: Do we want a separate option for child trust updates? Or is it sufficient with an
			// update policy that allows KEY updates (or not?)
			// For now we just allow it here and catch it in ApproveUpdate()

		default:
			dur.Status.Type = "CHILD-UPDATE"
			if !zd.Options[OptAllowChildUpdates] {
				lgHandler.Warn("zone does not allow child updates, ignoring", "zone", zd.ZoneName, "qname", qname)
				m.SetRcode(r, dns.RcodeRefused)
				w.WriteMsg(m)
				return nil
			}
		}

		// 3. Does qname exist in auth zone?
		// XXX: It doesn't have to exist!
	} else {
		dur.Status.Type = "ZONE-UPDATE"
		zd.Logger.Printf("UpdateResponder: qname %s is in auth zone %s", qname, zd.ZoneName)
		if !zd.Options[OptAllowUpdates] {
			lgHandler.Warn("zone does not allow updates to auth data, ignoring", "zone", zd.ZoneName, "qname", qname)
			m.SetRcode(r, dns.RcodeRefused)
			edns0.AttachEDEToResponse(m, edns0.EDEZoneUpdatesNotAllowed)
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

	err := zd.ValidateUpdate(r, dur.Status)
	if err != nil {
		zd.Logger.Printf("Error from ValidateUpdate(): %v", err)
		m.SetRcode(m, dns.RcodeServerFailure)
		edns0.AttachEDEToResponse(m, edns0.EDESig0KeyNotKnown)
		w.WriteMsg(m)
		return err
	}

	// Now we have the update validated by one or more keys, but we don't yet know if any of these keys
	// are trusted.

	err = zd.TrustUpdate(r, dur.Status)
	if err != nil {
		zd.Logger.Printf("Error from TrustUpdate(): %v", err)
		m.SetRcode(m, int(dur.Status.ValidationRcode))
		edns0.AttachEDEToResponse(m, edns0.EDESig0KeyKnownButNotTrusted)
		w.WriteMsg(m)
		return err
	}

	//	log.Printf("UpdateResponder: isdel=%v ValidateAndTrustUpdate returned rcode=%d, validated=%t, trusted=%t, signername=%s",
	//		isdel, rcode, validated, trusted, signername)
	lgHandler.Info("update status", "type", dur.Status.Type, "rcode", dur.Status.ValidationRcode, "validated", dur.Status.Validated, "trusted", dur.Status.ValidatedByTrustedKey, "signer", dur.Status.SignerName)
	// send response
	m = m.SetRcode(m, int(dur.Status.ValidationRcode))
	w.WriteMsg(m)

	if dur.Status.ValidationRcode != dns.RcodeSuccess {
		lgHandler.Error("error verifying DNS UPDATE, most likely ignoring contents")
		// Let's not return here, this could be an unvalidated key upload.
	}

	// dump.P(dur.Status.Type)

	// rcode from validation is input to ApproveUpdate only to enable the possibility of upload of unvalidated keys
	approved, updatezone, err := zd.ApproveUpdate(zone, dur.Status, r)
	// err := zd.ApproveUpdate(zone, r, dur.Status)
	dur.Status.Approved = approved
	// XXX: FIXME:
	// dur.Status.UpdateZone = updatezone
	if !updatezone {
		dur.Status.Type = "TRUSTSTORE-UPDATE"
	}
	if err != nil {
		lgHandler.Error("error from ApproveUpdate, ignoring update", "err", err)
		return err
	}

	// dump.P(dur.Status.Type)

	if !dur.Status.Approved {
		lgHandler.Warn("ApproveUpdate rejected the update, ignored")
		return nil
	}

	if dur.Status.ValidationRcode == dns.RcodeSuccess {
		zd.Logger.Printf("DnsEngine: Update validated and approved. Queued for zone update.")
	} else {
		zd.Logger.Printf("DnsEngine: Update NOT validated BUT still approved. Queued for zone update.")
	}

	// dump.P(dur.Status)
	lgHandler.Info("update queued for zone update", "cmd", dur.Status.Type, "zone", zone, "validated", dur.Status.Validated, "trusted", dur.Status.ValidatedByTrustedKey)

	// send into suitable channel for pending updates
	// XXX: This should be separated into updates to auth data in the zone and updates to child data.
	updateq <- UpdateRequest{
		Cmd:       dur.Status.Type,
		ZoneName:  zone,
		Actions:   r.Ns,
		Validated: dur.Status.Validated,
		Trusted:   dur.Status.ValidatedByTrustedKey,
		Status:    dur.Status,
	}
	return nil
}

// Returns approved, updatezone, error
func (zd *ZoneData) ApproveUpdate(zone string, us *UpdateStatus, r *dns.Msg) (bool, bool, error) {
	// dump.P(us)
	switch us.Type {
	case "CHILD-UPDATE":
		return zd.ApproveChildUpdate(zone, us, r)
	case "ZONE-UPDATE":
		return zd.ApproveAuthUpdate(zone, us, r)
	case "TRUSTSTORE-UPDATE":
		// XXX: Perhaps there should be a separate function for approval of truststore updates?
		// XXX: Then the ApproveChildUpdate() could be simplified.
		return zd.ApproveTrustUpdate(zone, us, r)
	default:
		return false, false, fmt.Errorf("ApproveUpdate: unknown update type: %s", us.Type)
	}
}

// Child updates are either validated updates for child delegation data,
// or unvalidated key upload requests.
// Returns approved, updatezone, error
func (zd *ZoneData) ApproveChildUpdate(zone string, us *UpdateStatus, r *dns.Msg) (bool, bool, error) {
	un := ""
	if us.ValidationRcode != dns.RcodeSuccess || !us.Validated {
		un = "un"
	}
	lgHandler.Info("analysing child update", "validated", un == "", "policyType", zd.UpdatePolicy.Child.Type, "allowedRRtypes", zd.UpdatePolicy.Child.RRtypes)

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
		lgHandler.Debug("ApproveChildUpdate checking RR", "rrtype", dns.TypeToString[rrtype], "keyBootstrap", zd.UpdatePolicy.Child.KeyBootstrap, "class", dns.ClassToString[rrclass], "updateRRs", len(r.Ns))

		if !us.ValidatedByTrustedKey {
			// If the update is not trusted (i.e. validated against a trusted key) it should be
			// rejected, except in the special case of unvalidated key uploads.

			if rrtype != dns.TypeKEY {
				us.Approved = false
				lgHandler.Warn("child update rejected: signed by untrusted key", "rrtype", dns.TypeToString[rrtype])
				return false, false, nil
			}

			if rrclass == dns.ClassNONE || rrclass == dns.ClassANY {
				us.Approved = false
				lgHandler.Warn("child update rejected: KEY delete signed by untrusted key")
				return false, false, nil
			}

			if len(r.Ns) != 1 {
				us.Approved = false
				lgHandler.Warn("child update rejected: only a single KEY record allowed from untrusted key")
				return false, false, nil
			}

			// This is the special case that we allow for unvalidated key uploads.
			if zd.UpdatePolicy.Child.KeyUpload == "unvalidated" { // exactly one SIG(0) key
				for _, bootstrap := range zd.UpdatePolicy.Child.KeyBootstrap {
					if bootstrap == "strict-manual" {
						us.Approved = false
						lgHandler.Warn("keybootstrap=strict-manual prohibits unvalidated KEY upload")
						return false, false, nil
					}
				}
				// XXX: I think we should require that this KEY upload is self-signed.
				lgHandler.Info("child update approved: unvalidated KEY upload")
				unvalidatedKeyUpload = true
			}
		}

		// Past the unvalidated key upload; from here update MUST be validated
		if (us.ValidationRcode != dns.RcodeSuccess || !us.Validated) && !unvalidatedKeyUpload {
			us.Approved = false
			lgHandler.Warn("update rejected: signature did not validate")
			return false, false, nil
		}

		if !us.ValidatedByTrustedKey && !unvalidatedKeyUpload {
			us.Approved = false
			lgHandler.Warn("update rejected: signature validated but key not trusted")
			return false, false, nil
		}

		if !zd.UpdatePolicy.Child.RRtypes[rrtype] {
			us.Approved = false
			lgHandler.Warn("update rejected: unapproved RR type", "rrtype", dns.TypeToString[rr.Header().Rrtype])
			return false, false, nil
		}

		switch zd.UpdatePolicy.Child.Type {
		case "selfsub":
			if !strings.HasSuffix(rr.Header().Name, us.SignerName) {
				us.Approved = false
				lgHandler.Warn("update rejected: owner name outside selfsub tree", "owner", rr.Header().Name, "signer", us.SignerName)
				return false, false, nil
			}

		case "self":
			if rr.Header().Name != us.SignerName {
				us.Approved = false
				lgHandler.Warn("update rejected: owner name differs from signer name violating self policy", "owner", rr.Header().Name, "signer", us.SignerName)
				return false, false, nil
			}
		default:
			us.Approved = false
			lgHandler.Warn("unknown policy type", "policyType", zd.UpdatePolicy.Child.Type)
			return false, false, nil
		}

		switch rrclass {
		case dns.ClassNONE:
			lgHandler.Debug("remove RR", "rr", rr.String())
		case dns.ClassANY:
			lgHandler.Debug("remove RRset", "rr", rr.String())
		default:
			lgHandler.Debug("add RR", "rr", rr.String())
		}
	}
	us.Approved = true
	lgHandler.Info("child update approved")
	updateZone := !unvalidatedKeyUpload

	return true, updateZone, nil
}

// Updates to auth data must be validated.
func (zd *ZoneData) ApproveAuthUpdate(zone string, us *UpdateStatus, r *dns.Msg) (bool, bool, error) {

	if us.ValidationRcode != dns.RcodeSuccess || !us.Validated {
		us.Approved = false
		lgHandler.Warn("auth update rejected: signature did not validate")
		return false, false, nil
	}

	if !us.ValidatedByTrustedKey {
		us.Approved = false
		lgHandler.Warn("auth update rejected: signature validated but key not trusted")
		return false, false, nil
	}

	var rrtypes []string
	for rrt := range zd.UpdatePolicy.Zone.RRtypes {
		rrtypes = append(rrtypes, dns.TypeToString[rrt])
	}
	lgHandler.Info("analysing auth update", "policyType", zd.UpdatePolicy.Zone.Type, "allowedRRtypes", strings.Join(rrtypes, ", "))

	for i := 0; i <= len(r.Ns)-1; i++ {
		rr := r.Ns[i]
		rrtype := rr.Header().Rrtype
		rrclass := rr.Header().Class

		lgHandler.Debug("ApproveAuthUpdate checking RR", "rrtype", dns.TypeToString[rrtype], "class", dns.ClassToString[rrclass], "updateRRs", len(r.Ns))

		if !zd.UpdatePolicy.Zone.RRtypes[rrtype] {
			us.Approved = false
			lgHandler.Warn("auth update rejected: unapproved RR type", "rrtype", dns.TypeToString[rr.Header().Rrtype])
			return false, false, nil
		}

		switch zd.UpdatePolicy.Zone.Type {
		case "selfsub":
			if !strings.HasSuffix(rr.Header().Name, us.SignerName) {
				us.Approved = false
				lgHandler.Warn("auth update rejected: owner name outside selfsub tree", "owner", rr.Header().Name, "signer", us.SignerName)
				return false, false, nil
			}

		case "self":
			if rr.Header().Name != us.SignerName {
				us.Approved = false
				lgHandler.Warn("auth update rejected: owner name differs from signer name violating self policy", "owner", rr.Header().Name, "signer", us.SignerName)
				return false, false, nil
			}

		case "none":
			us.Approved = false
			lgHandler.Warn("auth update rejected: policy type none disallows all updates")
			return false, false, nil

		default:
			us.Approved = false
			lgHandler.Warn("unknown policy type", "policyType", zd.UpdatePolicy.Zone.Type)
			return false, false, nil
		}

		switch rrclass {
		case dns.ClassNONE:
			lgHandler.Debug("remove RR", "rr", rr.String())
		case dns.ClassANY:
			lgHandler.Debug("remove RRset", "rr", rr.String())
		default:
			lgHandler.Debug("add RR", "rr", rr.String())
		}
	}
	us.Approved = true
	lgHandler.Info("auth update approved")
	return true, true, nil
}

// Trust updates are either validated updates (signed by already trusted key) or unvalidated
// (selfsigned initial uploads of key). In both cases the update section must only contain a
// single KEY RR.
// Returns approved, updatezone, error
func (zd *ZoneData) ApproveTrustUpdate(zone string, us *UpdateStatus, r *dns.Msg) (bool, bool, error) {
	lgHandler.Info("approving trust update", "zone", zone)
	un := ""
	if us.ValidationRcode != dns.RcodeSuccess || !us.Validated {
		un = "un"
	}
	lgHandler.Info("analysing trust update", "validated", un == "", "policyType", zd.UpdatePolicy.Child.Type, "allowedRRtypes", zd.UpdatePolicy.Child.RRtypes)

	unvalidatedKeyUpload := false

	if len(r.Ns) != 1 {
		us.Approved = false
		lgHandler.Warn("trust update rejected: only a single KEY record allowed")
		return false, false, nil
	}

	rr := r.Ns[0]
	// rrname := rr.Header().Name
	rrtype := rr.Header().Rrtype
	rrclass := rr.Header().Class

	// Requirement for unvalidated key upload:
	// 1. Policy has keyupload=unvalidated"
	// 2. Single RR in Update section, which is a KEY
	// 3. Class is not NONE or ANY (i.e. not a removal, but an add)
	// 4. Name of key must be == existing delegation
	lgHandler.Debug("ApproveTrustUpdate checking RR", "rrtype", dns.TypeToString[rrtype], "keyBootstrap", zd.UpdatePolicy.Child.KeyBootstrap, "class", dns.ClassToString[rrclass], "updateRRs", len(r.Ns))

	if !us.ValidatedByTrustedKey {
		// If the update is not trusted (i.e. validated against a trusted key) it should be
		// rejected, except in the special case of unvalidated key uploads.

		if rrtype != dns.TypeKEY {
			lgHandler.Warn("trust update rejected: must be for a KEY RR", "rrtype", dns.TypeToString[rrtype])
			return false, false, nil
		}

		if rrclass == dns.ClassNONE || rrclass == dns.ClassANY {
			us.Approved = false
			lgHandler.Warn("trust update rejected: KEY delete signed by untrusted key")
			return false, false, nil
		}

		//		if len(r.Ns) != 1 {
		//			us.Approved = false
		//			us.Log("ApproveChildUpdate: update of KEY RRset rejected (only a single KEY record allowed to be added by untrusted key)")
		//			return false, false, nil
		//		}

		// This is the special case that we allow for unvalidated key uploads.
		if zd.UpdatePolicy.Child.KeyUpload == "unvalidated" { // exactly one SIG(0) key
			for _, bootstrap := range zd.UpdatePolicy.Child.KeyBootstrap {
				if bootstrap == "strict-manual" {
					us.Approved = false
					lgHandler.Warn("keybootstrap=strict-manual prohibits unvalidated KEY upload")
					return false, false, nil
				}
			}
			// XXX: I think we should require that this KEY upload is self-signed.
			lgHandler.Info("trust update approved: unvalidated KEY upload")
			unvalidatedKeyUpload = true
			us.Approved = true
			return true, false, nil
		}
	}

	// Past the unvalidated key upload; from here update MUST be validated
	if (us.ValidationRcode != dns.RcodeSuccess || !us.Validated) && !unvalidatedKeyUpload {
		us.Approved = false
		lgHandler.Warn("trust update rejected: signature did not validate")
		return false, false, nil
	}

	if !us.ValidatedByTrustedKey && !unvalidatedKeyUpload {
		us.Approved = false
		lgHandler.Warn("trust update rejected: signature validated but key not trusted")
		return false, false, nil
	}

	if !zd.UpdatePolicy.Child.RRtypes[rrtype] {
		us.Approved = false
		lgHandler.Warn("trust update rejected: unapproved RR type", "rrtype", dns.TypeToString[rr.Header().Rrtype])
		return false, false, nil
	}

	switch zd.UpdatePolicy.Child.Type {
	case "selfsub":
		if !strings.HasSuffix(rr.Header().Name, us.SignerName) {
			us.Approved = false
			lgHandler.Warn("trust update rejected: owner name outside selfsub tree", "owner", rr.Header().Name, "signer", us.SignerName)
			return false, false, nil
		}

	case "self":
		if rr.Header().Name != us.SignerName {
			us.Approved = false
			lgHandler.Warn("trust update rejected: owner name differs from signer name violating self policy", "owner", rr.Header().Name, "signer", us.SignerName)
			return false, false, nil
		}
	default:
		us.Approved = false
		lgHandler.Warn("unknown policy type", "policyType", zd.UpdatePolicy.Child.Type)
		return false, false, nil
	}

	switch rrclass {
	case dns.ClassNONE:
		lgHandler.Debug("remove RR", "rr", rr.String())
	case dns.ClassANY:
		lgHandler.Debug("remove RRset", "rr", rr.String())
	default:
		lgHandler.Debug("add RR", "rr", rr.String())
	}

	us.Approved = true
	lgHandler.Info("trust update approved")

	return true, false, nil
}
