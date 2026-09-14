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

// unsignedRRsetState is the verdict for an RRset that arrived with no RRSIGs.
//
// The zone the RRset belongs to decides it. A zone the resolver holds as
// Insecure or Indeterminate lends the RRset its state. A zone it holds as Secure
// signs what it serves, so unsigned data from it had its signatures stripped on
// the way and is Bogus -- the rule ValidateNegativeResponse already applies to a
// denial. This used to return Insecure, and the responder served the data,
// without AD, to every client that does not validate for itself.
//
// But the closest zone in ZoneMap is only the closest zone the resolver knows.
// A child delegated insecurely from it, on the same servers, sends no referral
// and so has no entry of its own, and its data looks exactly like the secure
// parent's with the signatures gone. So before the verdict falls to Bogus the
// parent side is asked for the DS at each name from the secure zone down to the
// owner (delegationEvidence), and a proven insecure delegation on the way makes
// the data Insecure.
func (rrcache *RRsetCacheT) unsignedRRsetState(ctx context.Context, rrset *core.RRset, fetcher RRsetFetcher) ValidationState {
	// A DS is the parent's data: its zone is the one holding the owner's parent.
	name := dns.Fqdn(rrset.Name)
	if rrset.RRtype == dns.TypeDS {
		name = parentOf(name)
	}
	zoneName, zone := rrcache.closestKnownZone(name)
	if zone == nil {
		// No zone found - return indeterminate without flagging an error
		// This can happen during priming before zone state is established
		if rrcache.Verbose {
			log.Printf("ValidateRRset: no zone found for %s %s; returning indeterminate", rrset.Name, dns.TypeToString[rrset.RRtype])
		}
		return ValidationStateIndeterminate
	}
	// closestKnownZone passes over entries that do not decide (judgedZone), so
	// the state is a verdict, and any verdict but Secure is the data's too: a
	// zone held Bogus serves nothing, signed or not.
	if state := zone.GetState(); state != ValidationStateSecure {
		return state
	}
	return rrcache.belowSecureZone(ctx, zoneName, name, rrset.Name+" "+dns.TypeToString[rrset.RRtype], fetcher)
}

// unsignedDenialState is the verdict for a denial from zone, its SOA owner, whose
// signatures prove nothing: it has none, or its proof validated Insecure.
//
// This used to be Bogus only when zone had a ZoneMap entry of its own held
// Secure. A signed child of a secure zone has none when its parent's servers
// serve it too, so the resolver never saw a referral, or when the DS question
// for its referral went unanswered (ReferralChildState). Its NXDOMAIN and NODATA
// answers, stripped of their RRSIGs and NSEC records on the way, validated
// Insecure.
//
// A denial is data from zone, and is judged as unsigned data is: below the
// closest zone held Secure it is Bogus unless the parent side proves an insecure
// delegation on the way down to zone (belowSecureZone). Outside a zone held
// Secure it is Insecure, as it always was.
//
// A denial of the DS at zone's own apex is the child speaking for its parent's
// data, and is judged from the zone above, as an unsigned DS is. That also keeps
// the DS questions asked for a DS denial strictly above the name denied, so the
// denials those questions draw cannot lead back to it.
func (rrcache *RRsetCacheT) unsignedDenialState(ctx context.Context, zone, qname string, qtype uint16, fetcher RRsetFetcher) ValidationState {
	name := dns.Fqdn(zone)
	if qtype == dns.TypeDS && core.EqualNames(name, qname) {
		name = parentOf(name)
	}
	zoneName, z := rrcache.closestKnownZone(name)
	if z == nil || z.GetState() != ValidationStateSecure {
		return ValidationStateInsecure
	}
	return rrcache.belowSecureZone(ctx, zoneName, name, "the denial of "+qname+" "+dns.TypeToString[qtype], fetcher)
}

// belowSecureZone is the verdict for unsigned data at name, in or below the zone
// zoneName held Secure: Insecure if the way down from zoneName passes a proven
// insecure delegation or a stub or forward zone, Indeterminate if it passes a
// proof that cannot be judged, and Bogus otherwise. what names the data in the
// log.
func (rrcache *RRsetCacheT) belowSecureZone(ctx context.Context, zoneName, name, what string, fetcher RRsetFetcher) ValidationState {
	for _, n := range rrcache.proofNames(zoneName, name) {
		// A stub or forward zone is reached through servers the operator named,
		// and the public tree does not speak for it: its unsigned data is served
		// as it always was.
		if !core.EqualNames(n, zoneName) && rrcache.ConfiguredZone != nil && rrcache.ConfiguredZone(n) {
			return ValidationStateInsecure
		}
		ev := rrcache.delegationEvidence(ctx, n, fetcher)
		switch ev {
		case evidenceSecureCut, evidenceNoCut:
			continue
		case evidenceInsecureCut:
			rrcache.markZoneInsecure(n)
			if rrcache.Verbose {
				log.Printf("ValidateRRset: %q is an insecure delegation; %s is insecure", n, what)
			}
			return ValidationStateInsecure
		case evidenceUnjudged:
			// Nothing below a name that could not be judged can be judged
			// either: a proof further down would chain through it.
			return ValidationStateIndeterminate
		}
		if rrcache.Verbose {
			log.Printf("ValidateRRset: %s is unsigned below secure zone %q, and the DS question at %q got %s; bogus",
				what, zoneName, n, evidenceToString[ev])
		}
		return ValidationStateBogus
	}
	if rrcache.Verbose {
		log.Printf("ValidateRRset: %s is unsigned in secure zone %q; bogus", what, zoneName)
	}
	return ValidationStateBogus
}

// closestKnownZone is the ZoneMap entry at name or nearest above it that decides
// for the names below it (judgedZone). The root is not looked up, as it was not
// before: unsigned data that no zone below the root claims stays Indeterminate.
func (rrcache *RRsetCacheT) closestKnownZone(name string) (string, *Zone) {
	for n := dns.Fqdn(name); n != "."; n = parentOf(n) {
		if zone, ok := rrcache.ZoneMap.Get(n); ok && rrcache.judgedZone(n, zone) {
			return n, zone
		}
	}
	return "", nil
}

// proofNames lists, top down, the names whose DS decides whether unsigned data
// at name is legitimate below the secure zone zoneName: every name below the
// zone down to name, and first the zone itself, whose DS may have been removed
// since it was found Secure -- unless a trust anchor vouches for the zone, which
// no DS removal undoes.
func (rrcache *RRsetCacheT) proofNames(zoneName, name string) []string {
	var names []string
	for n := name; !core.EqualNames(n, zoneName) && n != "."; n = parentOf(n) {
		names = append(names, n)
	}
	if !rrcache.hasTrustAnchor(zoneName) {
		names = append(names, zoneName)
	}
	slices.Reverse(names)
	return names
}

// hasTrustAnchor reports whether a configured trust anchor vouches for zone.
func (rrcache *RRsetCacheT) hasTrustAnchor(zone string) bool {
	if rrcache.DnskeyCache == nil {
		return false
	}
	for item := range rrcache.DnskeyCache.Map.IterBuffered() {
		if item.Val.TrustAnchor && core.EqualNames(item.Val.Name, zone) {
			return true
		}
	}
	return false
}

func (rrcache *RRsetCacheT) markZoneInsecure(name string) {
	if rrcache.ZoneMap.SetIfAbsent(name, &Zone{ZoneName: name, State: ValidationStateInsecure}) {
		return
	}
	if zone, ok := rrcache.ZoneMap.Get(name); ok {
		zone.SetState(ValidationStateInsecure)
	}
}

// cutEvidence is what the parent side says about a zone cut at a name.
type cutEvidence int

const (
	evidenceNone        cutEvidence = iota // no answer to the DS question
	evidenceSecureCut                      // a DS that validated: a signed zone starts here
	evidenceInsecureCut                    // a validated proof of a delegation with no DS
	evidenceNoCut                          // a validated denial at a name that is no delegation
	evidenceUnjudged                       // an answer this validator cannot judge
	evidenceBogus                          // an answer that had to validate, and did not
)

var evidenceToString = map[cutEvidence]string{
	evidenceNone:        "no answer",
	evidenceSecureCut:   "a secure DS",
	evidenceInsecureCut: "an insecure delegation",
	evidenceNoCut:       "no delegation",
	evidenceUnjudged:    "an answer that cannot be judged",
	evidenceBogus:       "a bogus answer",
}

// delegationEvidence reads what the resolver holds for the DS at name, asking
// the parent side first when it holds nothing:
//
//   - A DS that validates: a signed zone starts at name.
//   - A denial that validates, with an NSEC owned by name and signed from above
//     it whose bitmap has NS and neither DS nor SOA: an insecure delegation (RFC
//     4035 section 5.2). Any other validated denial -- name is ordinary data,
//     an empty non-terminal, or does not exist -- means no delegation at name.
//   - An NSEC3 denial is read the same way (nsec3CutProof): a matching NSEC3, or
//     an Opt-Out span covering name, proves an insecure delegation.
//   - A proof over maxNSEC3Iterations cannot be judged, nor can a DS that
//     validated Insecure or Indeterminate when the zone above name is not held
//     Secure either.
//   - Everything else is bogus. The parent side of name lies inside the signed
//     tree, so its answer is signed: an unsigned denial is a stripped one, or
//     the child's own, which proves nothing about the parent side (RFC 6840
//     section 4.4). A signed answer whose chain cannot be followed below a
//     Secure zone counts the same -- a signature by a key the zone does not
//     have validates Indeterminate -- and so does a DS that validated Insecure
//     there, a verdict an RRSIG earns unverified by naming a signer held
//     Insecure. And so does no answer at all, because whoever can strip the
//     signatures can as easily drop the question.
func (rrcache *RRsetCacheT) delegationEvidence(ctx context.Context, name string, fetcher RRsetFetcher) cutEvidence {
	crr := rrcache.Get(name, dns.TypeDS)
	if crr == nil && ctx != nil && fetcher != nil {
		// The fetch caches what it gets, answer or denial, with its verdict.
		_, servers, err := rrcache.FindClosestKnownZoneFor(name, dns.TypeDS)
		if err == nil && len(servers) == 0 {
			servers, _ = rrcache.ServerMapCopy(".")
		}
		if err == nil && len(servers) > 0 {
			if _, err := fetcher(ctx, name, dns.TypeDS, servers); err != nil && rrcache.Verbose {
				log.Printf("ValidateRRset: DS query for %q failed: %v", name, err)
			}
			crr = rrcache.Get(name, dns.TypeDS)
		}
	}
	if crr == nil {
		return evidenceNone
	}
	switch crr.Context {
	case ContextNoErrNoAns, ContextNXDOMAIN:
		return rrcache.denialEvidence(ctx, name, crr, fetcher)
	case ContextAnswer, ContextReferral, ContextPriming:
	default:
		return evidenceNone
	}
	if crr.RRset == nil || len(crr.RRset.RRs) == 0 {
		return evidenceNone
	}
	state := crr.State
	if state != ValidationStateSecure && state != ValidationStateBogus {
		state, _ = rrcache.ValidateRRset(ctx, crr.RRset, fetcher)
	}
	switch state {
	case ValidationStateSecure:
		return evidenceSecureCut
	case ValidationStateInsecure, ValidationStateIndeterminate:
		if !rrcache.parentSideSecure(name) {
			return evidenceUnjudged
		}
	}
	return evidenceBogus
}

// denialEvidence is delegationEvidence for a cached denial of the DS at name,
// and its proof decides (cutProof). A denial that validated Secure with no
// proof about name in it shows that name is no delegation: ordinary data, an
// empty non-terminal, or no name at all. One that validated Indeterminate --
// every NSEC3 denial does, as does a chain that could not be followed -- and
// holds no proof that validates is bogus below a Secure zone: an NSEC3 denial
// that proves nothing about name, or a signature made with a key the zone does
// not have, is not a reason to serve unsigned data.
func (rrcache *RRsetCacheT) denialEvidence(ctx context.Context, name string, crr *CachedRRset, fetcher RRsetFetcher) cutEvidence {
	switch crr.State {
	case ValidationStateSecure, ValidationStateIndeterminate:
	case ValidationStateBogus, ValidationStateInsecure:
		return evidenceBogus
	default:
		return evidenceNone
	}
	if ev := rrcache.cutProof(ctx, name, crr.NegAuthority, fetcher); ev != evidenceNone {
		return ev
	}
	switch {
	case crr.State == ValidationStateSecure:
		return evidenceNoCut
	case !rrcache.parentSideSecure(name):
		return evidenceUnjudged
	}
	return evidenceBogus
}

// parentSideSecure reports whether the closest zone above name that decides
// (judgedZone) is held Secure. What that zone says about name is signed, and a
// signature whose chain cannot be followed there is an attacker's as easily as a
// missing one.
//
// Only zones held Secure, Insecure or Bogus are looked at, the root included. One
// held Indeterminate, or with no state, cannot change the answer: judgedZone
// counts it only when nothing above it is Secure, and then it is not Secure
// either. Asking judgedZone about each zone instead made the two call each other:
// over again for every zone above, doubling the work with each label, and for
// ever at the root, which is its own parent -- a root held Indeterminate
// overflowed the stack.
func (rrcache *RRsetCacheT) parentSideSecure(name string) bool {
	for n := dns.Fqdn(name); n != "."; {
		n = parentOf(n)
		if zone, ok := rrcache.ZoneMap.Get(n); ok && zone != nil {
			switch zone.GetState() {
			case ValidationStateSecure:
				return true
			case ValidationStateInsecure, ValidationStateBogus:
				return false
			}
		}
	}
	return false
}

// signedFromAbove returns set carrying only the signatures made by a zone above
// name, or nil if there are none. A delegation is the parent's to prove: an NSEC
// at name signed by name's own zone is the child's apex speaking, and one signed
// by a zone that does not enclose name speaks for nothing there.
func signedFromAbove(set *core.RRset, name string) *core.RRset {
	var sigs []dns.RR
	for _, rr := range set.RRSIGs {
		sig, ok := rr.(*dns.RRSIG)
		if ok && dns.IsSubDomain(sig.SignerName, name) && !core.EqualNames(sig.SignerName, name) {
			sigs = append(sigs, rr)
		}
	}
	if len(sigs) == 0 {
		return nil
	}
	return &core.RRset{Name: set.Name, Class: set.Class, RRtype: set.RRtype, RRs: set.RRs, RRSIGs: sigs}
}
