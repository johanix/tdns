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
	switch state := zone.GetState(); state {
	case ValidationStateSecure:
	case ValidationStateIndeterminate, ValidationStateInsecure:
		return state
	default:
		return ValidationStateInsecure
	}

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
				log.Printf("ValidateRRset: %q is an insecure delegation; %s %s is insecure", n, rrset.Name, dns.TypeToString[rrset.RRtype])
			}
			return ValidationStateInsecure
		case evidenceUnjudged:
			// Nothing below a name that could not be judged can be judged
			// either: a proof further down would chain through it.
			return ValidationStateIndeterminate
		}
		if rrcache.Verbose {
			log.Printf("ValidateRRset: %s %s has no RRSIGs below secure zone %q, and the DS question at %q got %s; bogus",
				rrset.Name, dns.TypeToString[rrset.RRtype], zoneName, n, evidenceToString[ev])
		}
		return ValidationStateBogus
	}
	if rrcache.Verbose {
		log.Printf("ValidateRRset: %s %s has no RRSIGs in secure zone %q; bogus", rrset.Name, dns.TypeToString[rrset.RRtype], zoneName)
	}
	return ValidationStateBogus
}

// closestKnownZone is the ZoneMap entry at name or nearest above it. The root is
// not looked up, as it was not before: unsigned data that no zone below the root
// claims stays Indeterminate.
func (rrcache *RRsetCacheT) closestKnownZone(name string) (string, *Zone) {
	for n := dns.Fqdn(name); n != "."; n = parentOf(n) {
		if zone, ok := rrcache.ZoneMap.Get(n); ok && zone != nil {
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
//   - An answer that validated Indeterminate -- an NSEC3 denial, which
//     ValidateNegativeResponse does not check yet, or a chain that could not be
//     followed -- cannot be judged.
//   - Everything else is bogus. The parent side of name lies inside the signed
//     tree, so its answer is signed: an unsigned denial is a stripped one, or
//     the child's own, which proves nothing about the parent side (RFC 6840
//     section 4.4). And no answer at all counts the same, because whoever can
//     strip the signatures can as easily drop the question.
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
	case ValidationStateIndeterminate, ValidationStateInsecure:
		return evidenceUnjudged
	}
	return evidenceBogus
}

func (rrcache *RRsetCacheT) denialEvidence(ctx context.Context, name string, crr *CachedRRset, fetcher RRsetFetcher) cutEvidence {
	switch crr.State {
	case ValidationStateSecure:
	case ValidationStateIndeterminate:
		return evidenceUnjudged
	case ValidationStateBogus, ValidationStateInsecure:
		return evidenceBogus
	default:
		return evidenceNone
	}
	for _, set := range crr.NegAuthority {
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
			nsec, ok := rr.(*dns.NSEC)
			if ok && slices.Contains(nsec.TypeBitMap, dns.TypeNS) &&
				!slices.Contains(nsec.TypeBitMap, dns.TypeDS) && !slices.Contains(nsec.TypeBitMap, dns.TypeSOA) {
				return evidenceInsecureCut
			}
		}
	}
	return evidenceNoCut
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
