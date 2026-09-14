/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"slices"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// maxNSEC3Iterations is the most NSEC3 hash iterations a proof is computed for.
// RFC 9276 section 3.2 lets a validator stop at a limit of its choosing; a proof
// above it is not judged. 150 was the limit validators shared when RFC 9276 was
// written.
const maxNSEC3Iterations = 150

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
//   - evidenceUnjudged: NSEC3 records over maxNSEC3Iterations and nothing else.
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
// above name, count, and only those that validate. Records with an unknown hash
// algorithm or unknown flags are ignored (sections 8.1 and 8.2): HashName has no
// hash for them, and Cover would compare the empty string.
func (rrcache *RRsetCacheT) nsec3CutProof(ctx context.Context, name string, sets []*core.RRset, fetcher RRsetFetcher) cutEvidence {
	var zone string
	var proven []*dns.NSEC3
	overLimit := false
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
			switch n, ok := rr.(*dns.NSEC3); {
			case !ok || n.Hash != dns.SHA1 || n.Flags > 1:
			case n.Iterations > maxNSEC3Iterations:
				overLimit = true
			default:
				zone = setZone
				proven = append(proven, n)
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
	matching := func(n string) *dns.NSEC3 {
		for _, rr := range proven {
			if rr.Match(n) {
				return rr
			}
		}
		return nil
	}
	if rr := matching(name); rr != nil {
		if insecureDelegationBitmap(rr.TypeBitMap) {
			return evidenceInsecureCut
		}
		return evidenceNoCut
	}
	nextCloser := name
	for ce := parentOf(name); dns.IsSubDomain(zone, ce); ce = parentOf(ce) {
		if rr := matching(ce); rr != nil {
			// The closest encloser is no DNAME and no delegation: one that is
			// would be speaking for names the zone does not hold (section 8.3).
			if slices.Contains(rr.TypeBitMap, dns.TypeDNAME) ||
				(slices.Contains(rr.TypeBitMap, dns.TypeNS) && !slices.Contains(rr.TypeBitMap, dns.TypeSOA)) {
				return evidenceNone
			}
			for _, cover := range proven {
				if cover.Cover(nextCloser) {
					if cover.Flags&1 == 1 {
						return evidenceInsecureCut
					}
					return evidenceNoCut
				}
			}
			return unproven
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
