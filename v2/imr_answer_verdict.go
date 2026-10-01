/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"

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
// Secure proof, and only to a client that can take the bit. A proof through an
// NSEC3 Opt-Out span, or over the NSEC3 iteration limit, is Insecure, and
// gets none.
//
// Denials do not go through dispositionFor: the only EDE a cached denial
// carries (27, or 9 on a DNSKEY denial) is served beside it rather than
// instead of it. Which denials are SERVFAIL is denialServfail's.
func negativeAD(c *cache.CachedRRset, r *dns.Msg, msgoptions *edns0.MsgOptions) bool {
	return c != nil && c.State == cache.ValidationStateSecure && adWanted(r, msgoptions)
}

// denialServfail reports whether a denial cached as c is answered SERVFAIL
// rather than served, and with which EDE. Denials follow dispositionFor's
// rule for positive answers:
//
//   - Bogus: SERVFAIL, EDE 6.
//   - Indeterminate, signed, from a zone at or below a trust anchor: SERVFAIL,
//     EDE 5. The chain could not be followed, which is not the same as the
//     zone being unsigned.
//   - With CD the client validates for itself, and every denial is served.
//
// Everything else is served: Secure, Insecure (an unsigned zone, an insecure
// delegation, an NSEC3 Opt-Out span or iteration count), an unsigned
// Indeterminate one, and a signed one from a zone no trust anchor is above --
// outside an island of security, or on a resolver without trust anchors --
// whose chain has nothing to lead to.
//
// A bogus denial used to be served, without AD. handleNegative refuses a
// denial only when validation fails with an error, and a stripped denial from
// a zone known to be signed is not an error but a verdict: it was cached as
// Bogus, and the name was gone for every client that does not validate for
// itself. And an Indeterminate one was served because every NSEC3 proof
// validated Indeterminate; they are validated now.
func (imr *Imr) denialServfail(c *cache.CachedRRset, msgoptions *edns0.MsgOptions) (bool, uint16) {
	if c == nil || (msgoptions != nil && msgoptions.CD) {
		return false, 0
	}
	switch {
	case c.State == cache.ValidationStateBogus:
		return true, edns0.EDEDNSSECBogus
	case c.State == cache.ValidationStateIndeterminate && denialSigned(c) && imr.denialUnderTrustAnchor(c):
		return true, edns0.EDEDNSSECIndeterminate
	}
	return false, 0
}

// denialUnderTrustAnchor reports whether a trust anchor is at or above the
// zone a cached denial comes from, its SOA's owner.
func (imr *Imr) denialUnderTrustAnchor(c *cache.CachedRRset) bool {
	return imr.Cache != nil && c.RRset != nil && imr.Cache.UnderTrustAnchor(c.RRset.Name)
}

// denialSigned reports whether a cached denial arrived with signatures: on
// its SOA, or anywhere in its proof.
func denialSigned(c *cache.CachedRRset) bool {
	if c.RRset != nil && len(c.RRset.RRSIGs) > 0 {
		return true
	}
	for _, set := range c.NegAuthority {
		if set != nil && len(set.RRSIGs) > 0 {
			return true
		}
	}
	return false
}

// writeDenialServfail answers r with a SERVFAIL carrying ede, as a failing
// answer is answered (dispositionFor).
func writeDenialServfail(w dns.ResponseWriter, r, m *dns.Msg, ede uint16) {
	m.Answer, m.Ns = nil, nil
	m.SetRcode(r, dns.RcodeServerFailure)
	if r.IsEdns0() != nil {
		edns0.AttachEDEToResponse(m, ede)
	}
	w.WriteMsg(m)
}

// revalidateDenial validates a cached denial held Indeterminate again as it is
// served, as serveCachedPositive does a positive entry, and returns the entry
// with the new verdict. Indeterminate says the chain could not be followed
// when the denial was cached -- a DNSKEY fetch that failed, a zone not judged
// yet -- and denialServfail answers it SERVFAIL; held as it was, a moment's
// gap would fail the name for the whole negative TTL.
//
// The verdict and EDE are updated in the cache without extending the entry's
// life. Only Indeterminate, and only a signed denial: State None marks a DNSKEY
// denial handleNegative did not validate, and it stays as it is. With CD the
// client validates for itself.
func (imr *Imr) revalidateDenial(ctx context.Context, c *cache.CachedRRset, msgoptions *edns0.MsgOptions) *cache.CachedRRset {
	if c == nil || c.State != cache.ValidationStateIndeterminate || !denialSigned(c) ||
		(msgoptions != nil && msgoptions.CD) || imr.Cache == nil || len(c.NegAuthority) == 0 {
		return c
	}
	v, err := imr.Cache.ValidateDenial(ctx, c.Name, c.RRtype, c.Rcode, c.NegAuthority, imr.IterativeDNSQueryFetcher())
	if err != nil && v.State != cache.ValidationStateIndeterminate {
		// handleNegative does not take a denial that fails to validate this
		// way; one already cached is Bogus.
		v = cache.DenialVerdict{State: cache.ValidationStateBogus, Rcode: c.Rcode}
	}
	if v.State == cache.ValidationStateNone || v.State == c.State {
		return c
	}
	// Stored only if c is still the entry cached; the answer being built is
	// made from c either way.
	imr.Cache.SetVerdict(c, v.State, v.EDECode, v.EDEText)
	updated := *c
	updated.State, updated.EDECode, updated.EDEText = v.State, v.EDECode, v.EDEText
	return &updated
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
	m.Answer = crrset.ServeAnswer(cache.Now(), msgoptions.DO)
	m.AuthenticatedData = disp == answerServeSecure && adWanted(r, msgoptions)
	setPrivacyStatus(m, msgoptions, edns0.PrivacyCached)
	w.WriteMsg(m)
}

// hasTrustAnchors reports whether this resolver holds any trust anchor, i.e.
// whether a signed answer could ever be Secure here. A configured anchor counts
// from the moment it is loaded: a DS anchor has no key in the DNSKEY cache
// until its zone's DNSKEY RRset has been fetched and matched it, and until then
// the resolver used to serve what it could not validate as if it had no anchor.
func (imr *Imr) hasTrustAnchors() bool {
	if imr == nil || imr.Cache == nil {
		return false
	}
	if imr.Cache.HasTrustAnchors() {
		return true
	}
	if imr.Cache.DnskeyCache == nil {
		return false
	}
	for _, v := range imr.Cache.DnskeyCache.Map.Items() {
		if v.TrustAnchor {
			return true
		}
	}
	return false
}
