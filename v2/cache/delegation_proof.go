/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"log"
	"slices"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// dsProofKey marks a context as inside ReferralChildState's questions to the
// parent side.
type dsProofKey struct{}

// ReferralChildState is the ZoneMap state for child, delegated by a referral
// with no DS that validated, and whether there is a state to enter at all.
//
// The closest zone above the child that decides (judgedZone) settles it:
//
//   - None: the verdict referrals always gave, Insecure with a trust anchor and
//     Indeterminate without.
//   - Insecure or Indeterminate: nothing below it has a chain of trust either,
//     and the child takes its state.
//   - Secure: the parent signs its delegations, so a child without a DS must be
//     proven insecure (RFC 4035 section 5.2, RFC 6840 section 4.4). The proof is
//     the referral's own NSEC or NSEC3 at the cut, or, when it carries none, the
//     parent side's answer to the DS question, asked for each name from the
//     parent down to the child as unsignedRRsetState asks it. A DS that
//     validates makes the child Secure, a proof of no DS Insecure, and a proof
//     over the NSEC3 iteration limit (NSEC3MaxIterations) Indeterminate.
//   - Bogus, or a Secure parent that proves nothing: the child is not entered,
//     and its data is judged when it arrives (unsignedRRsetState).
//
// This used to be Insecure whenever the resolver held any trust anchor. An
// attacker who stripped the DS and its RRSIG from the first referral to a
// signed zone had the zone entered as Insecure, and every answer from it,
// stripped or altered, validated Insecure from then on.
//
// A stub or forward zone at or above the child, below the zone that decides,
// keeps the old verdict: its servers are the operator's, and the public tree
// does not speak for it.
func (rrcache *RRsetCacheT) ReferralChildState(ctx context.Context, child string, authority []dns.RR, fetcher RRsetFetcher) (ValidationState, bool) {
	child = dns.Fqdn(child)
	if child == "." {
		return ValidationStateNone, false
	}
	legacy := ValidationStateIndeterminate
	if rrcache.anyTrustAnchor() {
		legacy = ValidationStateInsecure
	}
	var parentName string
	var parent *Zone
	for n := child; parent == nil; n = parentOf(n) {
		if !core.EqualNames(n, child) {
			if zone, ok := rrcache.ZoneMap.Get(n); ok && rrcache.judgedZone(n, zone) {
				parentName, parent = n, zone
				break
			}
		}
		if n == "." || (rrcache.ConfiguredZone != nil && rrcache.ConfiguredZone(n)) {
			return legacy, true
		}
	}
	switch state := parent.GetState(); state {
	case ValidationStateSecure:
	case ValidationStateInsecure, ValidationStateIndeterminate:
		return state, true
	default:
		return ValidationStateNone, false
	}

	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Value(dsProofKey{}) != nil {
		// A DS question asked for another referral was itself answered with a
		// referral. What the cache holds is all there is to go on: asking again
		// from here is how two lying servers would keep the resolver asking.
		fetcher = nil
	} else {
		ctx = context.WithValue(ctx, dsProofKey{}, true)
	}

	switch rrcache.cutProof(ctx, child, rrsetsOf(authority), fetcher) {
	case evidenceInsecureCut:
		return ValidationStateInsecure, true
	case evidenceUnjudged:
		return ValidationStateIndeterminate, true
	}
	for _, n := range rrcache.proofNames(parentName, child) {
		if n == "." {
			continue // the root has no parent side to ask
		}
		switch ev := rrcache.delegationEvidence(ctx, n, fetcher); ev {
		case evidenceSecureCut, evidenceNoCut:
			if core.EqualNames(n, child) {
				if ev == evidenceSecureCut {
					return ValidationStateSecure, true
				}
				break // the parent denies the cut it has just referred to
			}
			continue
		case evidenceInsecureCut:
			if !core.EqualNames(n, child) {
				rrcache.markZoneInsecure(n)
			}
			return ValidationStateInsecure, true
		case evidenceUnjudged:
			return ValidationStateIndeterminate, true
		default:
			if rrcache.Verbose {
				log.Printf("ReferralChildState: the DS question at %q below secure zone %q got %s; %q not entered",
					n, parentName, evidenceToString[ev], child)
			}
		}
		return ValidationStateNone, false
	}
	return ValidationStateNone, false
}

// judgedZone reports whether zone, the ZoneMap entry for name, decides for the
// names below it. An entry made before its zone was judged does not. Nor does
// one held Indeterminate below a zone held Secure: the chain from that zone is
// there to follow, and a step in it that could not be followed -- a DS question
// that went unanswered, a key signed by one the parent does not have -- is as
// easily an attacker's doing as a missing signature. The validator enters a zone
// as Indeterminate on such a step, and the unsigned data below it was served.
func (rrcache *RRsetCacheT) judgedZone(name string, zone *Zone) bool {
	if zone == nil {
		return false
	}
	switch zone.GetState() {
	case ValidationStateSecure, ValidationStateInsecure, ValidationStateBogus:
		return true
	case ValidationStateIndeterminate:
		return !rrcache.parentSideSecure(name)
	}
	return false
}

// cutProof reads what the NSEC or NSEC3 records in sets, from a referral or a
// denial, prove about a zone cut at name. Only records signed by a zone above
// name count, and only once they validate: a delegation is the parent's to
// prove.
//
//   - evidenceInsecureCut: an NSEC at name whose bitmap has NS and neither DS
//     nor SOA (RFC 4035 section 5.2, RFC 6840 section 4.4), or an NSEC3 proof
//     of the same (nsec3CutProof).
//   - evidenceNoCut: an NSEC at name, or an NSEC3 proof, that shows no insecure
//     delegation at name.
//   - evidenceUnjudged: NSEC3 records over the iteration limit and nothing
//     else, or an NSEC3 proof that ran out of hashes (nsec3HashBudget).
//   - evidenceNone: nothing in sets proves anything about name.
func (rrcache *RRsetCacheT) cutProof(ctx context.Context, name string, sets []*core.RRset, fetcher RRsetFetcher) cutEvidence {
	for _, set := range sets {
		if set == nil || set.RRtype != dns.TypeNSEC || !core.EqualNames(set.Name, name) {
			continue
		}
		proof := signedFromAbove(set, name)
		if proof == nil {
			continue
		}
		if state, err := rrcache.ValidateRRset(ctx, proof, fetcher); err != nil || state != ValidationStateSecure {
			continue
		}
		for _, rr := range proof.RRs {
			if nsec, ok := rr.(*dns.NSEC); ok && insecureDelegationBitmap(nsec.TypeBitMap) {
				return evidenceInsecureCut
			}
		}
		return evidenceNoCut
	}
	return rrcache.nsec3CutProof(ctx, name, sets, fetcher)
}

// nsec3CutProof is cutProof for a parent signed with NSEC3 (RFC 5155 section
// 8.9). An NSEC3 matching name with NS and neither DS nor SOA proves an
// insecure delegation, and so does a closest encloser proof (section 8.3) whose
// NSEC3 covering the next closer name has Opt-Out set: an unsigned delegation
// may sit in an Opt-Out span with no NSEC3 of its own (section 6). A matching
// NSEC3 without that bitmap, or a covering one without Opt-Out, proves there is
// no insecure delegation at name.
//
// Only NSEC3 records owned directly below the zone that signed them, a zone
// above name, count, and only those that validate. Which records count, and how
// names are hashed and compared, is nsec3.go's: records with an unknown hash
// algorithm or unknown flags are ignored (sections 8.1 and 8.2), cover is
// strict, and hashes compare as octets. Records over the iteration limit are
// set aside, and a proof that needs them, or runs out of hashes, is unjudged.
func (rrcache *RRsetCacheT) nsec3CutProof(ctx context.Context, name string, sets []*core.RRset, fetcher RRsetFetcher) cutEvidence {
	var zone string
	var proven []*dns.NSEC3
	overLimit := false
	maxIter := NSEC3MaxIterations()
	for _, set := range sets {
		if set == nil || set.RRtype != dns.TypeNSEC3 || len(set.RRs) == 0 {
			continue
		}
		setZone := parentOf(dns.Fqdn(set.Name))
		if !dns.IsSubDomain(setZone, name) || core.EqualNames(setZone, name) {
			continue
		}
		if zone != "" && !core.EqualNames(setZone, zone) {
			continue
		}
		proof := signedBy(set, setZone)
		if proof == nil {
			continue
		}
		if state, err := rrcache.ValidateRRset(ctx, proof, fetcher); err != nil || state != ValidationStateSecure {
			continue
		}
		for _, rr := range proof.RRs {
			n, ok := rr.(*dns.NSEC3)
			if !ok {
				continue
			}
			switch _, use := nsec3Usable(setZone, n, maxIter); use {
			case nsec3Counts:
				zone = setZone
				proven = append(proven, n)
			case nsec3OverTheLimit:
				overLimit = true
			}
		}
	}
	unproven := evidenceNone
	if overLimit {
		unproven = evidenceUnjudged
	}
	if len(proven) == 0 {
		return unproven
	}
	p := newNSEC3Proof(zone, proven, maxIter)
	if rec := p.matching(name); rec != nil {
		if insecureDelegationBitmap(rec.rr.TypeBitMap) {
			return evidenceInsecureCut
		}
		return evidenceNoCut
	}
	if p.spent {
		return evidenceUnjudged
	}
	nextCloser := name
	for ce := parentOf(name); dns.IsSubDomain(zone, ce); ce = parentOf(ce) {
		if rec := p.matching(ce); rec != nil {
			// The closest encloser is no DNAME and no delegation: one that is
			// would be speaking for names the zone does not hold (section 8.3).
			if rec.has(dns.TypeDNAME) || rec.delegation() {
				return evidenceNone
			}
			if cover := p.covering(nextCloser); cover != nil {
				if cover.optOut() {
					return evidenceInsecureCut
				}
				return evidenceNoCut
			}
			if p.spent {
				return evidenceUnjudged
			}
			return unproven
		}
		if p.spent {
			return evidenceUnjudged
		}
		if core.EqualNames(ce, zone) {
			break
		}
		nextCloser = ce
	}
	return unproven
}

// insecureDelegationBitmap reports whether the type bitmap of an NSEC or NSEC3
// at a name, from the zone above it, is a delegation with no DS: NS set, DS
// clear, and SOA clear -- the SOA is the child's apex answering, not the parent.
func insecureDelegationBitmap(bitmap []uint16) bool {
	return slices.Contains(bitmap, dns.TypeNS) &&
		!slices.Contains(bitmap, dns.TypeDS) && !slices.Contains(bitmap, dns.TypeSOA)
}

// signedBy returns set carrying only the signatures made by zone, or nil if
// there are none.
func signedBy(set *core.RRset, zone string) *core.RRset {
	var sigs []dns.RR
	for _, rr := range set.RRSIGs {
		if sig, ok := rr.(*dns.RRSIG); ok && core.EqualNames(sig.SignerName, zone) {
			sigs = append(sigs, rr)
		}
	}
	if len(sigs) == 0 {
		return nil
	}
	return &core.RRset{Name: set.Name, Class: set.Class, RRtype: set.RRtype, RRs: set.RRs, RRSIGs: sigs}
}

// rrsetsOf groups a message section into RRsets, each with the RRSIGs covering
// it. The records are copies: validation caps TTLs in place.
func rrsetsOf(rrs []dns.RR) []*core.RRset {
	var sets []*core.RRset
	setFor := func(name string, rrtype uint16) *core.RRset {
		for _, s := range sets {
			if s.RRtype == rrtype && core.EqualNames(s.Name, name) {
				return s
			}
		}
		s := &core.RRset{Name: name, Class: dns.ClassINET, RRtype: rrtype}
		sets = append(sets, s)
		return s
	}
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		if sig, ok := rr.(*dns.RRSIG); ok {
			s := setFor(sig.Hdr.Name, sig.TypeCovered)
			s.RRSIGs = append(s.RRSIGs, dns.Copy(rr))
			continue
		}
		s := setFor(rr.Header().Name, rr.Header().Rrtype)
		s.RRs = append(s.RRs, dns.Copy(rr))
	}
	return sets
}

// anyTrustAnchor reports whether the resolver holds a trust anchor for any zone.
func (rrcache *RRsetCacheT) anyTrustAnchor() bool {
	if rrcache.DnskeyCache == nil {
		return false
	}
	for item := range rrcache.DnskeyCache.Map.IterBuffered() {
		if item.Val.TrustAnchor {
			return true
		}
	}
	return false
}
