/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"strings"
	"time"

	// "github.com/gookit/goutil/dump"
	core "github.com/johanix/tdns/v2/core"
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

// applyValidationFailure stamps the response with the rcode and EDE that
// ValidateUpdate / TrustUpdate recorded for a rejected SIG(0) UPDATE, rather
// than a hardcoded guess at the reason. Every rejection path in
// UpdateResponder must use this so they cannot drift apart again — there are
// three (ValidateUpdate, TrustUpdate, ApproveUpdate), and the ApproveUpdate one
// was originally missed.
//
// us.ValidationRcode is authoritative: ValidateUpdate fails closed by
// defaulting it to BADSIG on entry, and TrustUpdate defends the same way, so
// an error return always carries a non-success rcode. The EDE is attached only
// when one was actually selected — an EDE of 0 is "none recorded", not a
// meaningful extended error.
func applyValidationFailure(m *dns.Msg, us *UpdateStatus) {
	rcode := int(us.ValidationRcode)
	if rcode == dns.RcodeSuccess {
		// A validation error must never answer NOERROR. ValidateUpdate
		// defaults ValidationRcode to BADSIG on entry, and TrustUpdate
		// defends the same way, precisely so this cannot happen — fail
		// closed if some future path forgets to set it. (Carried over from
		// PR #307, which guarded only the ValidateUpdate branch inline;
		// living in the shared helper it now covers TrustUpdate too.)
		lgHandler.Error("SIG(0) UPDATE rejected but ValidationRcode was left at NOERROR; failing closed with SERVFAIL")
		rcode = dns.RcodeServerFailure
	}
	m.SetRcode(m, rcode)
	if us.RejectionEDE != 0 {
		edns0.AttachEDEToResponse(m, us.RejectionEDE)
	}
	// BADSIG(16)/BADKEY(17)/BADTIME(18) are extended rcodes: the header field
	// is 4 bits, and Pack() refuses Rcode > 0xF unless an OPT RR is present
	// to carry the upper bits (ErrExtendedRcode). Every path that records
	// such an rcode today also records an EDE, and AttachEDEToResponse
	// creates the OPT — but that is an invariant of the current callers, not
	// of this helper. Guarantee it here: without the OPT the rejection would
	// fail to pack inside WriteMsg, whose error both rejection paths discard,
	// and the child would see a TIMEOUT instead of a rejection.
	//
	// Test the local rcode that was actually stamped onto m, not
	// us.ValidationRcode: the fail-closed branch above can substitute a
	// different value, and the OPT requirement is dictated by whatever will be
	// packed. (They coincide today — the only substitution is Success→SERVFAIL,
	// neither of which is extended — but coupling the guard to the packed value
	// keeps it correct if that ever changes.)
	if rcode > 0xF && m.IsEdns0() == nil {
		m.SetEdns0(4096, false)
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
	zd := FindZone(qname)
	if zd == nil {
		lgHandler.Warn("zone not found", "qname", qname)
		m.SetRcode(r, dns.RcodeRefused)
		edns0.AttachEDEToResponse(m, edns0.EDEZoneNotFound)
		w.WriteMsg(m)
		return nil // didn't find any zone for that qname
	}

	// Refuse UPDATE on a service-impacting error, or when the zone holds
	// no published data to update. Same predicate as the query path in
	// defaultqueryhandlers.go, deliberately: an UPDATE that the query
	// path would answer for must not be refused here, and vice versa.
	// RefreshError alone does not qualify -- a zone with data is still
	// authoritative for its current contents.
	if zd.HasServiceImpactingError() {
		lgHandler.Error("zone in error state", "qname", qname, "errorType", ErrorTypeToString[zd.ErrorType], "errorMsg", zd.ErrorMsg)
		m.SetRcode(r, dns.RcodeServerFailure)
		edns0.AttachEDEToResponse(m, edns0.EDEZoneNotFound)
		w.WriteMsg(m)
		return nil // didn't find any zone for that qname
	}
	if !zd.HasPublishedData() {
		lgHandler.Error("zone holds no published data", "qname", qname, "zone", zd.ZoneName)
		m.SetRcode(r, dns.RcodeServerFailure)
		edns0.AttachEDEToResponse(m, edns0.EDEZoneNotFound)
		w.WriteMsg(m)
		return nil // didn't find any zone for that qname
	}
	// And the same expire guard as the query path: a zone we may no longer
	// answer for is not one we may accept updates to either.
	if zd.HasExpired() {
		lgHandler.Error("zone has passed SOA EXPIRE since its last confirmed refresh",
			"qname", qname, "zone", zd.ZoneName, "lastRefresh", zd.lastRefresh())
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
		return nil
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

	// 0. Is this key material for a child rather than delegation data? That is
	// decided by what the update section CONTAINS, so it is asked before the
	// QNAME-shaped questions below: the bootstrap ceremony arrives with the
	// RFC 2136 QNAME (the parent zone) while a bare KEY upload arrives with
	// the child's own name, and the two are the same request.
	if child, ok := zd.classifyTruststoreUpdate(r.Ns); ok {
		lgHandler.Info("update carries child key material", "child", child)
		dur.Status.Type = "TRUSTSTORE-UPDATE"
		// Deliberately not gated on allow-child-updates: a truststore update
		// writes no zone content at all. ApproveTrustUpdate is its gate.
	} else if core.EqualNames(qname, zd.ZoneName) {
		// Per RFC 2136 the QNAME is the zone being updated, so the apex here
		// says nothing about what is being changed. The update section does.
		isChildUpdate, childDel := zd.classifyDelegationUpdate(r.Ns)

		if isChildUpdate && childDel != "" {
			lgHandler.Info("update targets child delegation", "child", childDel)
			dur.Status.Type = "CHILD-UPDATE"
			if !zd.Options[OptAllowChildUpdates] {
				lgHandler.Warn("zone does not allow child updates, ignoring", "zone", zd.ZoneName, "child", childDel)
				m.SetRcode(r, dns.RcodeRefused)
				edns0.AttachEDEToResponse(m, edns0.EDEZoneUpdatesNotAllowed)
				w.WriteMsg(m)
				return nil
			}
		} else {
			dur.Status.Type = "ZONE-UPDATE"
			// Name the owner that could not be placed, not the QNAME. The
			// QNAME is SUPPOSED to be the apex here (RFC 2136: it is the zone
			// being updated), so reporting that says nothing about why this
			// was not a child update -- and reads as "the name you tried to
			// update was the apex", which is usually false.
			unplaced := qname
			if len(r.Ns) > 0 {
				unplaced = r.Ns[0].Header().Name
			}
			zd.Logger.Printf("UpdateResponder: zone %s: no child delegation covers owner %s; treating as ZONE-UPDATE",
				zd.ZoneName, unplaced)
			if !zd.Options[OptAllowUpdates] {
				lgHandler.Warn("zone does not allow updates to auth data, ignoring", "zone", zd.ZoneName, "qname", qname)
				m.SetRcode(r, dns.RcodeRefused)
				edns0.AttachEDEToResponse(m, edns0.EDEZoneUpdatesNotAllowed)
				w.WriteMsg(m)
				return nil
			}
		}
		// 2. Is qname a zone cut for a child zone? Then this is delegation
		// data for that child. The KEY case that used to be split out here is
		// gone: step 0 above answers it for every message shape, rather than
		// only for an update section holding exactly one record.
	} else if zd.IsChildDelegation(qname) {
		zd.Logger.Printf("UpdateResponder: zone %s: qname %s is the name of an existing child zone",
			zd.ZoneName, qname)
		dur.Status.Type = "CHILD-UPDATE"
		if !zd.Options[OptAllowChildUpdates] {
			lgHandler.Warn("zone does not allow child updates, ignoring", "zone", zd.ZoneName, "qname", qname)
			m.SetRcode(r, dns.RcodeRefused)
			edns0.AttachEDEToResponse(m, edns0.EDEZoneUpdatesNotAllowed)
			w.WriteMsg(m)
			return nil
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

	// applyValidationFailure is deliberately shared by all three rejection
	// paths below: ValidateUpdate, TrustUpdate, and ApproveUpdate. They
	// previously each hardcoded
	// their own rcode + EDE, and correcting only one of them is exactly how
	// they drifted apart: the TrustUpdate path was fixed to relay the recorded
	// values while the ValidateUpdate path kept answering SERVFAIL + "key not
	// known" for what is actually FORMERR + a format error — mislabelling a
	// malformed request as a server-side fault and directing the child at
	// bootstrapping a key, which does not fix a malformed message.
	err := zd.ValidateUpdate(r, dur.Status)
	if err != nil {
		zd.Logger.Printf("Error from ValidateUpdate(): %v", err)
		applyValidationFailure(m, dur.Status)
		w.WriteMsg(m)
		return err
	}

	// Now we have the update validated by one or more keys, but we don't yet know if any of these keys
	// are trusted.

	err = zd.TrustUpdate(r, dur.Status)
	if err != nil {
		zd.Logger.Printf("Error from TrustUpdate(): %v", err)
		applyValidationFailure(m, dur.Status)
		w.WriteMsg(m)
		return err
	}

	//	log.Printf("UpdateResponder: isdel=%v ValidateAndTrustUpdate returned rcode=%d, validated=%t, trusted=%t, signername=%s",
	//		isdel, rcode, validated, trusted, signername)
	lgHandler.Info("update status", "type", dur.Status.Type, "rcode", dur.Status.ValidationRcode, "validated", dur.Status.Validated, "trusted", dur.Status.ValidatedByTrustedKey, "signer", dur.Status.SignerName)

	if dur.Status.ValidationRcode != dns.RcodeSuccess {
		lgHandler.Error("error verifying DNS UPDATE, most likely ignoring contents")
		// Don't return here — this might be an unvalidated key upload
		// that ApproveUpdate accepts despite the validation failure.
		// The final rcode and EDE are decided after ApproveUpdate
		// returns (see below).
	}

	// rcode from validation is input to ApproveUpdate only to enable the possibility of upload of unvalidated keys
	approved, updatezone, err := zd.ApproveUpdate(zone, dur.Status, r)
	dur.Status.Approved = approved
	if !updatezone {
		dur.Status.Type = "TRUSTSTORE-UPDATE"
	}
	if err != nil {
		lgHandler.Error("error from ApproveUpdate, ignoring update", "err", err)
		// Even on internal error, send a response with the validation
		// rcode + EDE so the child sees something coherent. This is the
		// third rejection path and it needs the same two guards as the
		// other two: ApproveUpdate only errors on an unknown update type,
		// which it reaches with validation having SUCCEEDED — so relaying
		// ValidationRcode raw would answer NOERROR for an update that was
		// never applied.
		applyValidationFailure(m, dur.Status)
		w.WriteMsg(m)
		return err
	}

	// Decide the final wire rcode + EDE based on the combined
	// validation + approval outcome, then write the response.
	// Rollover-overhaul phase 11 moved this from before ApproveUpdate
	// to after it: the previous order made policy-rejected updates
	// look like NOERROR-but-don't-publish to the child, which the
	// rollover engine had no way to distinguish from a true publish-
	// pipeline failure on the parent side.
	finalRcode := int(dur.Status.ValidationRcode)
	if !dur.Status.Approved && dur.Status.ValidationRcode == dns.RcodeSuccess {
		// Validation succeeded but approval rejected — REFUSED is the
		// right wire rcode (NOERROR would be a wire-protocol lie).
		finalRcode = dns.RcodeRefused
	}
	if dur.Status.RejectionEDE != 0 {
		edns0.AttachEDEToResponse(m, dur.Status.RejectionEDE)
	}

	// A rejected update is answered immediately: there is nothing to wait for.
	// An approved one is NOT answered here -- see below, where the response is
	// sent only after the update has actually been applied.
	if !dur.Status.Approved {
		m = m.SetRcode(m, finalRcode)
		w.WriteMsg(m)
		lgHandler.Warn("ApproveUpdate rejected the update, ignored")
		for _, rr := range r.Ns {
			switch rr.Header().Class {
			case dns.ClassINET:
				lgHandler.Warn(fmt.Sprintf("REJECTED[ADD]: %s", rr.String()))
			case dns.ClassNONE:
				lgHandler.Warn(fmt.Sprintf("REJECTED[DEL]: %s", rr.String()))
			case dns.ClassANY:
				lgHandler.Warn(fmt.Sprintf("REJECTED[DEL-rrset]: %s %s",
					rr.Header().Name, dns.TypeToString[rr.Header().Rrtype]))
			}
		}
		return nil
	}

	if dur.Status.ValidationRcode == dns.RcodeSuccess {
		zd.Logger.Printf("DnsEngine: Update validated and approved. Queued for zone update.")
	} else {
		zd.Logger.Printf("DnsEngine: Update NOT validated BUT still approved. Queued for zone update.")
	}

	// dump.P(dur.Status)
	lgHandler.Info("update queued for zone update", "cmd", dur.Status.Type, "zone", zone, "validated", dur.Status.Validated, "trusted", dur.Status.ValidatedByTrustedKey)

	// RFC 2136 §3.4.2.5: a NOERROR response means the requested update HAS been
	// made. Answering as soon as the request was queued makes that a statement
	// of intent rather than of fact -- the client is told the change is safe
	// while it is still a message on a channel, and a crash or a refusal in the
	// updater loses it silently after the client was told otherwise.
	//
	// So: hand the request over with a reply channel and answer only once the
	// update has been applied, persisted and published. Buffered, so the
	// updater's non-blocking send always lands even if the wait below has
	// already timed out.
	respch := make(chan ZoneUpdateResult, 1)

	// XXX: This should be separated into updates to auth data in the zone and updates to child data.
	updateq <- UpdateRequest{
		Cmd:       dur.Status.Type,
		ZoneName:  zone,
		Actions:   r.Ns,
		Validated: dur.Status.Validated,
		Trusted:   dur.Status.ValidatedByTrustedKey,
		Status:    dur.Status,
		Resp:      respch,
	}

	select {
	case res := <-respch:
		if res.Err != nil {
			// The update was refused or could not be made durable. SERVFAIL is
			// the honest answer: the client learns to retry or escalate,
			// instead of believing a change that was never made.
			lgHandler.Error("update was not applied; answering SERVFAIL",
				"zone", zone, "error", res.Err)
			m.SetRcode(m, dns.RcodeServerFailure)
			edns0.AttachEDEToResponse(m, edns0.EDEZoneUpdateNotApplied)
		} else {
			m.SetRcode(m, finalRcode)
		}

	case <-time.After(UpdateApplyTimeout):
		// The updater is a single goroutine serving every zone, so a slow or
		// wedged apply shows up here. Do NOT answer NOERROR on a timeout: the
		// update may yet be applied, but we no longer know, and the whole point
		// of this wait is to stop claiming otherwise. SERVFAIL is retryable and
		// an RFC 2136 update is idempotent, so a retry that arrives after a
		// late apply is harmless.
		lgHandler.Error("timed out waiting for the update to be applied; answering SERVFAIL",
			"zone", zone, "timeout", UpdateApplyTimeout)
		m.SetRcode(m, dns.RcodeServerFailure)
		edns0.AttachEDEToResponse(m, edns0.EDEZoneUpdateApplyTimeout)
	}
	w.WriteMsg(m)

	return nil
}

// UpdateApplyTimeout bounds how long an UPDATE responder waits for the
// ZoneUpdater to apply, persist and publish a change before giving up and
// answering SERVFAIL. Generous: the wait covers a database write and, on a
// signed zone, re-signing the affected RRsets.
const UpdateApplyTimeout = 10 * time.Second

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

	// A CHILD-UPDATE carries delegation data. Key material is a truststore
	// matter, and step 0 of UpdateResponder classified every KEY-only update
	// as one -- so a KEY arriving HERE is in a message that MIXES the two.
	// Those go to different stores, and one wire rcode cannot honestly report
	// "the delegation half landed, the key half did not", so the message is
	// refused whole and the child is told which record made it unacceptable.
	//
	// Before this, a mixed message published the child's KEY into the parent
	// zone along with its NS and DS.
	for _, rr := range r.Ns {
		if rr.Header().Rrtype == dns.TypeKEY {
			us.Approved = false
			us.RejectionEDE = edns0.EDEZoneUpdateRRtypeNotAllowed
			lgHandler.Warn("child update rejected: KEY records must be sent on their own, not mixed with delegation data",
				"zone", zd.ZoneName, "owner", rr.Header().Name)
			return false, false, nil
		}
	}

	// With key material refused above, the unvalidated-KEY-upload allowance
	// below is reached only to be declined: an untrusted signer asking to
	// change delegation data is refused on the first record. The allowance
	// itself now lives in ApproveTrustUpdate, which is where a KEY upload is
	// classified to.
	unvalidatedKeyUpload := false
	for i := 0; i <= len(r.Ns)-1; i++ {
		rr := r.Ns[i]
		// rrname := rr.Header().Name
		rrtype := rr.Header().Rrtype
		rrclass := rr.Header().Class

		// Requirement for unvalidated key upload:
		// 1. Bound delegationpolicy has allow-unvalidated-upload: true
		// 2. Single RR in Update section, which is a KEY
		// 3. Class is not NONE or ANY (i.e. not a removal, but an add)
		// 4. Name of key must be == existing delegation
		lgHandler.Debug("ApproveChildUpdate checking RR", "rrtype", dns.TypeToString[rrtype], "delegationpolicy", zd.boundDelegationPolicy().Name, "class", dns.ClassToString[rrclass], "updateRRs", len(r.Ns))

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
			if zoneAllowsUnvalidatedUpload(zd) {
				lgHandler.Info("child update approved: unvalidated KEY upload")
				unvalidatedKeyUpload = true
			}
		}

		// Past the unvalidated key upload; from here update MUST be validated
		if (us.ValidationRcode != dns.RcodeSuccess || !us.Validated) && !unvalidatedKeyUpload {
			us.Approved = false
			if us.RejectionEDE == 0 {
				us.RejectionEDE = edns0.EDESig0BadSignature
			}
			lgHandler.Warn("update rejected: signature did not validate")
			return false, false, nil
		}

		if !us.ValidatedByTrustedKey && !unvalidatedKeyUpload {
			us.Approved = false
			us.RejectionEDE = edns0.EDESig0KeyKnownButNotTrusted
			lgHandler.Warn("update rejected: signature validated but key not trusted")
			return false, false, nil
		}

		// The policy itself, shared with ApproveAuthUpdate and with the
		// DSYNC API handler. Called here rather than after the loop so the
		// interleaving with the SIG(0) checks above is unchanged: an update
		// whose first record fails policy and whose second fails validation
		// still reports the policy failure.
		if ok, ede := evalUpdatePolicyRR(zd.UpdatePolicy.Child, us.SignerName, rr, "update"); !ok {
			us.Approved = false
			us.RejectionEDE = ede
			return false, false, nil
		}
	}
	us.Approved = true
	lgHandler.Info("child update approved")
	updateZone := !unvalidatedKeyUpload

	// Coherence: the policy above decided whether this child MAY change these
	// RRtypes. Whether the delegation that results still works is a separate
	// question, and the parent answers it on every channel -- the DSYNC API
	// handler applies the same check.
	//
	// A refusal here is permanent, so it must not answer SERVFAIL. Returning an
	// error alone did: applyValidationFailure reads us.ValidationRcode, which
	// is still NOERROR because the signature validated perfectly well, and its
	// fail-closed branch substitutes SERVFAIL. A child's rollover engine
	// categorises that as a transport softfail and retries a hard no for as
	// long as it is configured to, which is why the rcode is set explicitly
	// alongside an EDE that names the reason.
	if cerr := zd.CheckDelegationCoherenceForUpdate(r.Ns,
		imrDnskeyFetcher(Conf.Internal.ImrEngine)); cerr != nil {
		lgHandler.Warn("child update refused as incoherent",
			"zone", zd.ZoneName, "err", cerr)
		us.ValidationRcode = dns.RcodeRefused
		us.RejectionEDE = edns0.EDEZoneUpdatesNotAllowed
		return false, false, cerr
	}

	// The NS/glue half of the same question (RFC 7477 via the CSYNC rules):
	// the delegation that results must be the one the child's nameservers
	// serve. Same refusal shape as the DS check above, for the same reason.
	ctx, cancel := context.WithTimeout(context.Background(), delegationCheckTimeout)
	defer cancel()
	if cerr := zd.CheckDelegationNSCoherenceForUpdate(ctx, r.Ns,
		Conf.Internal.Scanner.childNameserverAsker(nil)); cerr != nil {
		lgHandler.Warn("child update refused as incoherent",
			"zone", zd.ZoneName, "err", cerr)
		us.ValidationRcode = dns.RcodeRefused
		us.RejectionEDE = edns0.EDEZoneUpdatesNotAllowed
		return false, false, cerr
	}

	return true, updateZone, nil
}

// Updates to auth data must be validated.
func (zd *ZoneData) ApproveAuthUpdate(zone string, us *UpdateStatus, r *dns.Msg) (bool, bool, error) {

	if us.ValidationRcode != dns.RcodeSuccess || !us.Validated {
		us.Approved = false
		// Don't overwrite a more specific RejectionEDE set during
		// validation (e.g. EDESig0BadTime) — fall back only if no
		// validation EDE was recorded.
		if us.RejectionEDE == 0 {
			us.RejectionEDE = edns0.EDESig0BadSignature
		}
		lgHandler.Warn("auth update rejected: signature did not validate")
		return false, false, nil
	}

	if !us.ValidatedByTrustedKey {
		us.Approved = false
		us.RejectionEDE = edns0.EDESig0KeyKnownButNotTrusted
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

		if ok, ede := evalUpdatePolicyRR(zd.UpdatePolicy.Zone, us.SignerName, rr, "auth update"); !ok {
			us.Approved = false
			us.RejectionEDE = ede
			return false, false, nil
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

	// A trust update is either a single KEY RR, or the self-signed bootstrap
	// ceremony "DEL <child> ANY KEY" + "ADD <child> KEY" (draft §"Bootstrapping
	// the Child's Key"). For the ceremony we approve/inspect the ADD KEY; the
	// accompanying DEL-ANY-KEY is DEFERRED by the apply path (it must not evict
	// an already-trusted key until the new key validates). A bare untrusted
	// DEL-ANY-KEY (no ADD) is not a ceremony and remains refused below.
	addKey, _, isCeremony := bootstrapCeremony(r.Ns)
	if len(r.Ns) != 1 && !isCeremony {
		us.Approved = false
		lgHandler.Warn("trust update rejected: only a single KEY record or a bootstrap DEL+ADD ceremony allowed", "rrs", len(r.Ns))
		return false, false, nil
	}

	rr := r.Ns[0]
	if isCeremony {
		rr = addKey // operate on the ADD KEY; the DEL is handled by the apply path
	}
	// rrname := rr.Header().Name
	rrtype := rr.Header().Rrtype
	rrclass := rr.Header().Class

	// Requirement for unvalidated key upload:
	// 1. Bound delegationpolicy has allow-unvalidated-upload: true
	// 2. Single RR in Update section, which is a KEY
	// 3. Class is not NONE or ANY (i.e. not a removal, but an add)
	// 4. Name of key must be == existing delegation
	lgHandler.Debug("ApproveTrustUpdate checking RR", "rrtype", dns.TypeToString[rrtype], "delegationpolicy", zd.boundDelegationPolicy().Name, "class", dns.ClassToString[rrclass], "updateRRs", len(r.Ns))

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
		if zoneAllowsUnvalidatedUpload(zd) {
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
		// AUTHORISATION CHECK -- dns.IsSubDomain, not strings.HasSuffix.
		// HasSuffix is true for evilchild.example. against child.example.,
		// because it compares bytes and knows nothing about label boundaries:
		// a signer authorised for one name could update names under a
		// DIFFERENT name that merely ends with it. It is also case-sensitive,
		// which denied legitimate updates. IsSubDomain gets both right, and is
		// true for the signer name itself, which selfsub has always allowed.
		if !dns.IsSubDomain(us.SignerName, rr.Header().Name) {
			us.Approved = false
			lgHandler.Warn("trust update rejected: owner name outside selfsub tree", "owner", rr.Header().Name, "signer", us.SignerName)
			return false, false, nil
		}

	case "self":
		if !core.EqualNames(rr.Header().Name, us.SignerName) {
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

// firstKeyRR returns the first KEY record in an update section, or nil. The
// record rather than a bool, so the caller can name the owner it refused.
func firstKeyRR(rrs []dns.RR) dns.RR {
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeKEY {
			return rr
		}
	}
	return nil
}

// classifyTruststoreUpdate reports whether an update section is key material
// for one child rather than delegation data, and for which child.
//
// A KEY at a child's name is never parent zone content. The name is below a
// zone cut, so the parent cannot serve the record; publishing it anyway puts
// KEY into the NSEC/NSEC3 type bitmap of a delegation the parent does not
// control, and hands the parent's signer an RRset at a cut to sign. The record
// belongs in the truststore, which is what the child is asking for by sending
// it: this is the SIG(0) bootstrap of
// draft-ietf-dnsop-delegation-mgmt-via-ddns-02 §"Bootstrapping the Child's
// Key".
//
// THE REGRESSION. ValidateUpdate also recognises a self-signed KEY upload and
// rewrites us.Type to TRUSTSTORE-UPDATE -- but only on the paths where the
// signing key was NOT already in the truststore. So the first bootstrap was
// routed to the truststore and every re-send of the identical ceremony was
// classified as a delegation update and published into the parent zone, where
// it stayed. Deciding it here, from what the message contains rather than from
// where its key happened to be found, gives the same answer on the first send
// and on the hundredth.
//
// The shapes this covers are the ADD-KEY upload, the DEL-ANY-KEY + ADD-KEY
// ceremony, and the removal of a key the child no longer uses -- all classes,
// because "which store does this belong in" does not depend on whether the
// record is being added or removed. What the truststore then accepts is
// ApproveTrustUpdate's decision, not this one.
func (zd *ZoneData) classifyTruststoreUpdate(rrs []dns.RR) (string, bool) {
	if len(rrs) == 0 {
		return "", false
	}
	owner := ""
	for _, rr := range rrs {
		if rr.Header().Rrtype != dns.TypeKEY {
			return "", false
		}
		name := rr.Header().Name
		if owner == "" {
			owner = name
			continue
		}
		if !core.EqualNames(owner, name) {
			// Key material for two children in one message. The truststore
			// applier authorises per child, exactly as classifyDelegationUpdate
			// does for delegations, so this is not split -- it is not a
			// truststore update, and the delegation classifier will refuse it
			// in turn.
			return "", false
		}
	}
	if !zd.IsChildDelegation(owner) {
		// A KEY anywhere else in the zone -- at the apex above all -- is the
		// zone's own data, judged by updatepolicy.zone like any other RRset.
		return "", false
	}
	return owner, true
}

// classifyDelegationUpdate reports whether every RR in an update section
// targets a single existing child delegation, and which one.
//
// Extracted from UpdateResponder so it can be tested directly: the bug this
// guards against (a KEY at a child's apex classified as a ZONE-UPDATE and
// refused) survived because the only coverage went through the full responder,
// where a message, a policy and a ResponseWriter all have to be right before
// the classification is even reached.
//
// Three shapes count as a child update:
//   - NS or DS AT the delegation point
//   - anything else AT the delegation point (a child publishing at its own
//     apex; the SIG(0) bootstrap KEY is the case that matters)
//   - glue BELOW the delegation point
//
// All RRs must land on the SAME child; an update spanning two delegations is
// not a child update.
func (zd *ZoneData) classifyDelegationUpdate(rrs []dns.RR) (bool, string) {
	childDel := ""
	isChildUpdate := len(rrs) > 0
	for _, rr := range rrs {
		ownerName := rr.Header().Name
		rrtype := rr.Header().Rrtype

		switch {
		case rrtype == dns.TypeNS || rrtype == dns.TypeDS:
			// NS and DS must be AT a child delegation point.
			if !zd.IsChildDelegation(ownerName) {
				return false, childDel
			}
			if childDel == "" {
				childDel = ownerName
			} else if !core.EqualNames(childDel, ownerName) {
				return false, childDel
			}

		case zd.IsChildDelegation(ownerName):
			// AT the delegation point, and not NS or DS: a child publishing
			// something at its own apex. Step 2 in UpdateResponder still
			// describes this ("it may be a KEY update and hence really a
			// TRUSTSTORE-UPDATE"), but step 2 is no longer reached for these
			// messages, because the child now sends the RFC 2136 QNAME (the
			// zone) rather than its own name.
			//
			// Without this case the ancestor walk below starts one label ABOVE
			// the owner, immediately hits the zone apex, and a child bootstrap
			// is classified as a ZONE-UPDATE -- refused by updatepolicy.zone,
			// which is normally "none".
			if childDel == "" {
				childDel = ownerName
			} else if !core.EqualNames(childDel, ownerName) {
				return false, childDel
			}

		default:
			// Glue (A, AAAA, ...) BELOW an existing child delegation. The
			// owner itself was handled above, so start one label up.
			found := false
			labels := dns.SplitDomainName(ownerName)
			for i := 1; i < len(labels); i++ {
				ancestor := dns.Fqdn(strings.Join(labels[i:], "."))
				if core.EqualNames(ancestor, zd.ZoneName) {
					break
				}
				if zd.IsChildDelegation(ancestor) {
					if childDel == "" {
						childDel = ancestor
					} else if !core.EqualNames(childDel, ancestor) {
						return false, childDel
					}
					found = true
					break
				}
			}
			if !found {
				return false, childDel
			}
		}
	}
	return isChildUpdate, childDel
}
