/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"context"
	"fmt"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// AuthzTsig is UpdateAuthz.Mech for an UPDATE authorized by a TSIG key.
const AuthzTsig = "tsig"

// UpdateAuthz says how a DNS UPDATE that did not come through the SIG(0) path
// was authorized, and carries what the applier needs to ask again per record:
// the principal and the grants it was judged against. The grants are the
// zone's at the moment the responder approved the update, so a reload between
// the responder and the applier cannot change the answer halfway.
type UpdateAuthz struct {
	Mech   string // AuthzTsig
	Key    string // canonical TSIG key name
	Grants []TsigGrant
}

// isTsig reports whether the update was authorized by a TSIG key. Nil-safe.
func (a *UpdateAuthz) isTsig() bool { return a != nil && a.Mech == AuthzTsig }

// typeAllowed is the applier's per-record type check. Internal and API
// requests are not subject to update policy; a TSIG request is subject to its
// grants; anything else (SIG(0)) to updatepolicy.zone's type list, exactly as
// before Authz existed.
func (ur *UpdateRequest) typeAllowed(zd *ZoneData, owner string, rrtype uint16) bool {
	if ur.InternalUpdate || ur.PreAuthorized {
		return true
	}
	if ur.Authz.isTsig() {
		return tsigGrantsAllow(ur.Authz.Grants, ur.Authz.Key, owner, rrtype)
	}
	_, ok := zd.UpdatePolicy.Zone.RRtypes[rrtype]
	return ok
}

// zoneUpdatesAdmitted is the admission switch for an update to the zone's own
// data, by mechanism: allow-tsig-updates for TSIG, allow-updates for SIG(0).
func zoneUpdatesAdmitted(zd *ZoneData, viaTsig bool) bool {
	if viaTsig {
		return zd.Options[OptAllowTsigUpdates]
	}
	return zd.Options[OptAllowUpdates]
}

// hasSigRR reports whether an additional section carries a SIG RR (SIG(0)).
func hasSigRR(extra []dns.RR) bool {
	for _, rr := range extra {
		if _, ok := rr.(*dns.SIG); ok {
			return true
		}
	}
	return false
}

// respondTsigUpdate authorizes and answers an UPDATE that carries a TSIG and
// no SIG(0). It replaces ValidateUpdate, TrustUpdate and ApproveUpdate for that
// message; what follows approval -- the ZoneUpdater, the delta journal, the
// answer once the change is published -- is the same as for SIG(0).
//
// m is the reply UpdateResponder prepared. Every answer goes out through w,
// which on Do53 and DoT TSIG-signs it (tsigSignResponseWriter), refusals
// included.
func (zd *ZoneData) respondTsigUpdate(ctx context.Context, w dns.ResponseWriter, m, r *dns.Msg,
	dur *DnsUpdateRequest, updateq chan UpdateRequest) error {

	us := dur.Status
	key := canonicalFqdn(r.IsTsig().Hdr.Name)
	refuse := func(ede uint16, text string) error {
		us.Approved = false
		us.RejectionEDE = ede
		m.SetRcode(r, dns.RcodeRefused)
		if text != "" {
			edns0.AttachEDEToResponseWithText(m, ede, text, false)
		} else {
			edns0.AttachEDEToResponse(m, ede)
		}
		w.WriteMsg(m)
		return nil
	}

	// On Do53 and DoT a TSIG that did not verify never gets this far:
	// TsigSigningHandler has answered NOTAUTH with the TSIG error. DoH and DoQ
	// cannot verify a TSIG at all and say so here; a TSIG that has not been
	// verified authorizes nothing.
	if err := w.TsigStatus(); err != nil {
		lgHandler.Warn("TSIG update refused: the TSIG was not verified", "zone", zd.ZoneName, "key", key, "err", err)
		return refuse(dns.ExtendedErrorCodeOther,
			fmt.Sprintf("TSIG for key %q cannot be verified on this transport", key))
	}

	// Only the zone's own data. Delegation data for a child and a child's key
	// material cross an administrative boundary and stay SIG(0).
	if us.Type != "ZONE-UPDATE" {
		lgHandler.Warn("TSIG update refused: not an update of the zone's own data",
			"zone", zd.ZoneName, "key", key, "type", us.Type)
		return refuse(edns0.EDEZoneUpdatesNotAllowed,
			"delegation data and child keys can only be updated with SIG(0)")
	}
	// The classification above is not enough on its own: a zone section that
	// names a name inside the zone skips the delegation classifier, and an
	// update that mixes zone data with a child's records, or spans two
	// children, is classified as ZONE-UPDATE. So every record is checked.
	for _, rr := range r.Ns {
		if zd.tsigTouchesDelegation(rr) {
			lgHandler.Warn("TSIG update refused: it carries delegation data",
				"zone", zd.ZoneName, "key", key, "owner", rr.Header().Name,
				"rrtype", dns.TypeToString[rr.Header().Rrtype])
			return refuse(edns0.EDEZoneUpdatesNotAllowed,
				"delegation data and child keys can only be updated with SIG(0)")
		}
	}

	us.SignerName = key
	us.SignatureType = "tsig"
	us.Validated = true
	us.ValidationRcode = dns.RcodeSuccess

	grants := zd.UpdatePolicy.TsigGrants
	for _, rr := range r.Ns {
		if ok, ede := evalTsigGrants(grants, key, rr); !ok {
			lgHandler.Warn("TSIG update refused by the zone's grants",
				"zone", zd.ZoneName, "key", key, "owner", rr.Header().Name,
				"rrtype", dns.TypeToString[rr.Header().Rrtype], "class", dns.ClassToString[rr.Header().Class],
				"reason", edns0.EDECodeToString[ede])
			return refuse(ede, "")
		}
	}
	us.Approved = true
	lgHandler.Info("TSIG update approved", "zone", zd.ZoneName, "key", key, "updateRRs", len(r.Ns))

	req := UpdateRequest{
		Cmd:       "ZONE-UPDATE",
		ZoneName:  zd.ZoneName,
		Actions:   r.Ns,
		Validated: true,
		Status:    us,
		Authz:     &UpdateAuthz{Mech: AuthzTsig, Key: key, Grants: grants},
	}
	// The same two ways out as the SIG(0) path: a zone that syncs its own
	// delegation applies under its delegation lock, on a goroutine of its own.
	if zd.syncsOwnDelegation() {
		go zd.answerOwnDelegationUpdate(ctx, w, m, req, updateq, dns.RcodeSuccess)
		return nil
	}
	return answerWhenApplied(ctx, w, m, req, updateq, dns.RcodeSuccess)
}

// tsigTouchesDelegation reports whether one update record is delegation data,
// which TSIG may not change: an NS or DS anywhere below the apex (an NS there
// makes a zone cut, and a DS belongs only at one), or any record at or below
// an existing delegation point (the cut itself, its glue, a child's KEY). The
// apex is the zone's own.
func (zd *ZoneData) tsigTouchesDelegation(rr dns.RR) bool {
	owner := rr.Header().Name
	if core.EqualNames(owner, zd.ZoneName) {
		return false
	}
	if t := rr.Header().Rrtype; t == dns.TypeNS || t == dns.TypeDS {
		return true
	}
	labels := dns.SplitDomainName(owner)
	for i := range labels {
		ancestor := dns.Fqdn(strings.Join(labels[i:], "."))
		if core.EqualNames(ancestor, zd.ZoneName) {
			break
		}
		if zd.IsChildDelegation(ancestor) {
			return true
		}
	}
	return false
}
