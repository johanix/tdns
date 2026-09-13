/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"time"

	"github.com/johanix/tdns/v2/cache"
	edns0 "github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// answerDisposition is what a positive answer's validation verdict means for
// the response.
//
// Decided in ONE place, for an answer just fetched and for one served from the
// cache. They used to be decided separately and disagreed: a fresh answer whose
// verdict was Insecure or Indeterminate was SERVFAIL, the same entry from the
// cache was NOERROR. Every name in an unsigned zone, or in a signed zone with no
// DS, failed on the first ask and worked on the second. And a fresh bogus answer
// was served to a client without the DO bit, while the cached copy of it was
// refused.
type answerDisposition int

const (
	answerServe       answerDisposition = iota // served, AD clear
	answerServeSecure                          // served, AD if the client can take it (adWanted)
	answerServfail                             // SERVFAIL, carrying the returned EDE
)

// dispositionFor maps a verdict onto a response.
//
//   - Secure is served, with AD when the client asked for DNSSEC.
//   - With CD set the client does its own validation: anything else is served,
//     never with AD.
//   - Bogus, or an entry already carrying an EDE, is SERVFAIL -- whether or not
//     the client set DO. A validating resolver protects the clients that do not
//     validate for themselves, and that is most of them.
//   - Indeterminate means the chain could not be followed. For a signed RRset,
//     on a resolver that has trust anchors, that is a failure (EDE 5); it is
//     not the same as the zone being unsigned. Without trust anchors nothing
//     can be secure and Indeterminate is the ordinary state, so it is served.
//   - Insecure, and an RRset nothing was able to judge, is served without AD.
func (imr *Imr) dispositionFor(state cache.ValidationState, edeCode uint16, signed bool, msgoptions *edns0.MsgOptions) (answerDisposition, uint16) {
	if state == cache.ValidationStateSecure && edeCode == 0 {
		return answerServeSecure, 0
	}
	if msgoptions != nil && msgoptions.CD {
		return answerServe, 0
	}
	switch {
	case edeCode != 0:
		return answerServfail, edeCode
	case state == cache.ValidationStateBogus:
		return answerServfail, edns0.EDEDNSSECBogus
	case state == cache.ValidationStateIndeterminate && signed && imr.hasTrustAnchors():
		return answerServfail, edns0.EDEDNSSECIndeterminate
	}
	return answerServe, 0
}

// adWanted reports whether a secure answer to r may carry AD: only if the client
// set DO, or set AD in the query to say it understands the bit (RFC 6840 §5.7,
// §5.8). The cached path used to set it for everyone.
func adWanted(r *dns.Msg, msgoptions *edns0.MsgOptions) bool {
	return (msgoptions != nil && msgoptions.DO) || (r != nil && r.AuthenticatedData)
}

// negativeAD reports whether a denial served from entry c may carry AD: only a
// Secure proof, and only to a client that can take the bit.
//
// Denials do not go through dispositionFor. A bogus one never reaches the cache
// (handleNegative refuses it), the only EDE a cached denial carries is served
// beside it rather than instead of it, and ValidateNegativeResponse still
// returns Indeterminate for every NSEC3 proof -- SERVFAIL for a signed,
// Indeterminate denial would fail every NXDOMAIN from an NSEC3-signed zone.
func negativeAD(c *cache.CachedRRset, r *dns.Msg, msgoptions *edns0.MsgOptions) bool {
	return c != nil && c.State == cache.ValidationStateSecure && adWanted(r, msgoptions)
}

// verdictReusable reports whether a cached verdict can be served as it stands.
// Indeterminate and "no verdict" cannot: they mean the chain was not available
// when the entry was made, and the only way to find out whether it is now is to
// validate again.
func verdictReusable(state cache.ValidationState) bool {
	switch state {
	case cache.ValidationStateSecure, cache.ValidationStateInsecure, cache.ValidationStateBogus:
		return true
	}
	return false
}

// serveCachedPositive answers r from a cached positive entry under the same
// rule as a fresh answer: a verdict that says "could not tell yet" is asked
// again, a failing one is SERVFAIL with its EDE, and AD goes only to a client
// that can take it.
//
// Every cache branch that serves positive data comes through here: the ordinary
// answer, a DS served from the parent's referral, and indirect data (referral,
// glue, hint) served without upgrading. The last two used to set AD from the
// entry's state for every client, and served a bogus entry as NOERROR.
func (imr *Imr) serveCachedPositive(ctx context.Context, w dns.ResponseWriter, r, m *dns.Msg, qname string, qtype uint16, crrset *cache.CachedRRset, msgoptions *edns0.MsgOptions) {
	state := crrset.State
	signed := crrset.RRset != nil && len(crrset.RRset.RRSIGs) > 0
	if !verdictReusable(state) && signed && !msgoptions.CD && imr.Cache != nil {
		if v, err := imr.Cache.ValidateRRsetWithParentZone(ctx, crrset.RRset, imr.IterativeDNSQueryFetcher(), imr.ParentZone); err == nil {
			state = v
		}
	}
	disp, ede := imr.dispositionFor(state, crrset.EDECode, signed, msgoptions)
	if disp == answerServfail {
		lgImr.Debug("ImrResponder: returning SERVFAIL for cached data that did not validate",
			"qname", qname, "qtype", dns.TypeToString[qtype], "edeCode", ede,
			"state", cache.ValidationStateToString[state], "context", cache.CacheContextToString[crrset.Context])
		m.Answer = nil
		m.Ns = nil
		m.SetRcode(r, dns.RcodeServerFailure)
		if r.IsEdns0() != nil {
			if crrset.EDECode != 0 && crrset.EDEText != "" {
				edns0.AttachEDEToResponseWithText(m, crrset.EDECode, crrset.EDEText, msgoptions.DO)
			} else {
				edns0.AttachEDEToResponse(m, ede)
			}
		}
		w.WriteMsg(m)
		return
	}
	m.SetRcode(r, dns.RcodeSuccess)
	m.Answer = crrset.ServeAnswer(time.Now(), msgoptions.DO)
	m.AuthenticatedData = disp == answerServeSecure && adWanted(r, msgoptions)
	setPrivacyStatus(m, msgoptions, edns0.PrivacyCached)
	w.WriteMsg(m)
}

// hasTrustAnchors reports whether this resolver holds any trust anchor, i.e.
// whether a signed answer could ever be Secure here.
func (imr *Imr) hasTrustAnchors() bool {
	if imr == nil || imr.Cache == nil || imr.Cache.DnskeyCache == nil {
		return false
	}
	for _, v := range imr.Cache.DnskeyCache.Map.Items() {
		if v.TrustAnchor {
			return true
		}
	}
	return false
}
