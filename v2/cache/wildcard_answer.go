/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"context"
	"fmt"
	"log"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Answers synthesized from a wildcard.
//
// An RRSIG whose Labels field is below its owner's label count, a leading "*"
// label not counted, was made over the wildcard at the owner's last Labels
// labels (RFC 4034 section 3.1.3, RFC 4035 section 5.3.2): an expansion
// signature. When the signature that validates an RRset is one, the RRset is
// validated together with the proof that its owner does not exist in the
// zone, nor anything between it and the wildcard (RFC 4035 section 5.3.4 for
// NSEC, RFC 5155 section 8.8 for NSEC3). The proof comes from the authority
// section of the response, and is kept with the cached answer
// (CachedRRset.WildcardProof).

// AnswerVerdict is what ValidateAnswer makes of a positive RRset.
type AnswerVerdict struct {
	State   ValidationState
	EDECode uint16 // 27 when the wildcard proof needs NSEC3 records over the iteration limit
	EDEText string
	// Proof is set when the RRset carries an expansion signature: the NSEC and
	// NSEC3 RRsets of the authority section that the signer's zone signed.
	Proof []*core.RRset
}

// ValidateAnswer validates a positive RRset together with the authority
// section it arrived with. An RRset without an expansion signature, and a
// DNSKEY RRset, is validated as ValidateRRsetWithParentZone validates it.
// One with an expansion signature is validated afresh: a verdict cached for
// the same RRset is not reused, as the authority section is new.
func (rrcache *RRsetCacheT) ValidateAnswer(ctx context.Context, rrset *core.RRset, authority []*core.RRset,
	fetcher RRsetFetcher) (AnswerVerdict, error) {
	if rrcache == nil || rrset == nil || rrset.RRtype == dns.TypeDNSKEY || !hasExpansionSignature(rrset) {
		state, err := rrcache.ValidateRRsetWithParentZone(ctx, rrset, fetcher, nil)
		return AnswerVerdict{State: state}, err
	}
	return rrcache.validateExpansion(ctx, rrset, authority, fetcher)
}

// validateWithKeptProof is ValidateRRsetWithParentZone for an RRset with an
// expansion signature: its authority section is the proof kept on the cache
// entry that holds the same RRs and RRSIGs. A verdict cached for that RRset is
// reused, as for any other: it was reached with the proof.
func (rrcache *RRsetCacheT) validateWithKeptProof(ctx context.Context, rrset *core.RRset, fetcher RRsetFetcher) (ValidationState, error) {
	// Read before reusableVerdict, whose Get drops an expired entry: one
	// stored with TTL 0 holds the proof of the answer its query just fetched.
	kept := rrcache.keptProof(rrset)
	if state, ok := rrcache.reusableVerdict(rrset); ok {
		return state, nil
	}
	v, err := rrcache.validateExpansion(ctx, rrset, kept, fetcher)
	return v.State, err
}

// keptProof returns the proof kept on the cache entry for rrset, if that
// entry holds the same RRs and RRSIGs, expired or not.
func (rrcache *RRsetCacheT) keptProof(rrset *core.RRset) []*core.RRset {
	c := rrcache.Peek(rrset.Name, rrset.RRtype)
	if c == nil || c.RRset == nil || len(c.WildcardProof) == 0 {
		return nil
	}
	if differ, _, _ := c.RRset.RRsetDiffer(rrset, log.Default(), false, false); differ || c.RRset.RRSIGsDiffer(rrset) {
		return nil
	}
	return c.WildcardProof
}

// validateExpansion validates rrset, which carries an expansion signature,
// with authority. Signatures over the owner itself are tried first: one that
// validates makes the RRset the owner's own, and no proof is needed. An
// expansion signature that validates needs the proof (WildcardAnswerProof).
// A verdict other than Secure stands as it is: a zone held Insecure or
// Indeterminate has nothing to check a proof against.
//
// Data from a zone the server this resolver runs in is authoritative for
// (AnsweredLocally) is the server's own, and is not held to the proof.
func (rrcache *RRsetCacheT) validateExpansion(ctx context.Context, rrset *core.RRset, authority []*core.RRset,
	fetcher RRsetFetcher) (AnswerVerdict, error) {
	owner := answerOwner(rrset)
	own, exp := splitExpansionSignatures(rrset)
	v := AnswerVerdict{Proof: wildcardProofSets(authority, signersOf(exp))}
	if rrcache.Verbose {
		log.Printf("ValidateAnswer: %s %s carries %d expansion signature(s); %d proof RRset(s) in the authority section",
			owner, dns.TypeToString[rrset.RRtype], len(exp), len(v.Proof))
	}
	state, sig, err := rrcache.validateSignatures(ctx, rrset, append(own, exp...), rrcache.DnskeyCache, fetcher)
	v.State = state
	if err != nil || state != ValidationStateSecure || sig == nil {
		return v, err
	}
	if !ExpansionSignature(sig, owner) {
		v.Proof = nil
		return v, nil
	}
	if rrcache.AnsweredLocally != nil && rrcache.AnsweredLocally(owner, rrset.RRtype) {
		return v, nil
	}
	v.State, v.EDECode = rrcache.WildcardAnswerProof(ctx, sig.SignerName, owner, sig.Labels, v.Proof, fetcher)
	if v.EDECode == edeUnsupportedNSEC3Iterations {
		v.EDEText = fmt.Sprintf("NSEC3 iterations above the limit of %d", NSEC3MaxIterations())
	}
	if rrcache.Verbose {
		log.Printf("ValidateAnswer: %s %s synthesized from *.%s in %s: %s",
			owner, dns.TypeToString[rrset.RRtype], lastLabels(dns.SplitDomainName(owner), int(sig.Labels)),
			sig.SignerName, ValidationStateToString[v.State])
	}
	return v, nil
}

// WildcardAnswerProof reports what the NSEC or NSEC3 RRsets in proof show
// about an answer for qname that zone synthesised from a wildcard: that qname
// does not exist, and nothing between it and the wildcard's closest encloser
// does (RFC 4035 section 5.3.4, RFC 5155 section 8.8). labels is the Labels
// field of the RRSIG that validated the answer.
//
// Only NSEC RRsets owned at or below zone, and NSEC3 RRsets owned directly
// below it, count, validated with zone's signatures alone; one that does not
// validate Secure decides the verdict. An NSEC that proves it: Secure.
// Otherwise the NSEC3 verdict: Secure, Insecure through an Opt-Out span
// (section 9.2), Insecure with EDE 27 over the iteration limit (RFC 9276).
// No proof: Bogus. The EDE code is 0 unless 27.
func (rrcache *RRsetCacheT) WildcardAnswerProof(ctx context.Context, zone, qname string, labels uint8,
	proof []*core.RRset, fetcher RRsetFetcher) (ValidationState, uint16) {
	if ctx == nil {
		ctx = context.Background()
	}
	zone = dns.Fqdn(zone)
	qname = dns.CanonicalName(qname)
	var nsecs []*dns.NSEC
	var nsec3s []*dns.NSEC3
	for _, set := range proof {
		if set == nil || !proofOwnedIn(set, zone) {
			continue
		}
		zs := signedBy(set, zone)
		if zs == nil {
			continue
		}
		if state, err := rrcache.ValidateRRset(ctx, zs, fetcher); err != nil || state != ValidationStateSecure {
			if err != nil {
				return ValidationStateIndeterminate, 0
			}
			return state, 0
		}
		for _, rr := range zs.RRs {
			switch r := rr.(type) {
			case *dns.NSEC:
				nsecs = append(nsecs, r)
			case *dns.NSEC3:
				nsec3s = append(nsec3s, r)
			}
		}
	}
	return ProveWildcardAnswer(zone, qname, labels, nsecs, nsec3s)
}

// ProveWildcardAnswer reads what nsecs and nsec3s, records of zone whose
// signatures by zone the caller has verified, prove about an answer for qname
// that zone synthesized from a wildcard; labels is the Labels field of the
// RRSIG that verified the answer. It is the reading WildcardAnswerProof makes
// of the records that validate, for a caller that checks signatures with keys
// of its own, not the cache's: the chain walk of dog +sigchase. It looks at no
// signatures, cache or network.
//
// An NSEC that proves it (nsecWildcardAnswer): Secure. Otherwise the NSEC3
// verdict: Secure, Insecure through an Opt-Out span (RFC 5155 section 9.2),
// Insecure with EDE 27 over the iteration limit (RFC 9276). No proof: Bogus.
// The EDE code is 0 unless 27.
func ProveWildcardAnswer(zone, qname string, labels uint8, nsecs []*dns.NSEC, nsec3s []*dns.NSEC3) (ValidationState, uint16) {
	zone = dns.Fqdn(zone)
	qname = dns.CanonicalName(qname)
	if nsecWildcardAnswer(qname, labels, zone, nsecs) {
		return ValidationStateSecure, 0
	}
	if len(nsec3s) > 0 {
		v := newNSEC3Proof(zone, nsec3s, NSEC3MaxIterations()).wildcardAnswer(qname, labels)
		if v == nsec3OverLimit {
			return v.state(), edeUnsupportedNSEC3Iterations
		}
		return v.state(), 0
	}
	return ValidationStateBogus, 0
}

// nsecWildcardAnswer reports whether an NSEC in nsecs proves that qname does
// not exist in zone, and nothing between it and the wildcard's closest
// encloser, qname's last labels labels (RFC 4035 section 5.3.4). The NSEC:
//
//   - covers qname;
//   - proves that closest encloser: a longer one means a name between it and
//     qname exists, and the wildcard does not apply;
//   - has a next name that does not lie below qname, which would make qname
//     an empty non-terminal, a name that exists;
//   - has neither DNAME nor NS without SOA when its owner is an ancestor of
//     qname: the names below such an owner are not the zone's.
func nsecWildcardAnswer(qname string, labels uint8, zone string, nsecs []*dns.NSEC) bool {
	ql := dns.SplitDomainName(qname)
	if int(labels) >= len(ql) {
		return false
	}
	ce := lastLabels(ql, int(labels))
	for _, nsec := range nsecs {
		if !nsecCoversName(qname, nsec) || dns.IsSubDomain(qname, nsec.NextDomain) {
			continue
		}
		if canonicalNameCompare(closestEncloser(qname, nsec, zone), ce) != 0 {
			continue
		}
		if dns.IsSubDomain(nsec.Hdr.Name, qname) {
			bm := nsec.TypeBitMap
			if typeInList(dns.TypeDNAME, bm) || (typeInList(dns.TypeNS, bm) && !typeInList(dns.TypeSOA, bm)) {
				continue
			}
		}
		return true
	}
	return false
}

// typeInList reports whether t is in bitmap, sorted or not.
func typeInList(t uint16, bitmap []uint16) bool {
	for _, b := range bitmap {
		if b == t {
			return true
		}
	}
	return false
}

// proofOwnedIn reports whether an NSEC or NSEC3 RRset can be zone's: an NSEC
// owned at or below zone, an NSEC3 owned directly below it.
func proofOwnedIn(set *core.RRset, zone string) bool {
	switch set.RRtype {
	case dns.TypeNSEC:
		return dns.IsSubDomain(zone, dns.Fqdn(set.Name))
	case dns.TypeNSEC3:
		return core.EqualNames(parentOf(dns.Fqdn(set.Name)), zone)
	}
	return false
}

// wildcardProofSets returns the NSEC and NSEC3 RRsets of authority that may be
// one of zones' proof (proofOwnedIn), each with that zone's RRSIGs only.
func wildcardProofSets(authority []*core.RRset, zones []string) []*core.RRset {
	var out []*core.RRset
	for _, set := range authority {
		if set == nil || (set.RRtype != dns.TypeNSEC && set.RRtype != dns.TypeNSEC3) {
			continue
		}
		for _, zone := range zones {
			if !proofOwnedIn(set, zone) {
				continue
			}
			if zs := signedBy(set, zone); zs != nil {
				out = append(out, zs)
				break
			}
		}
	}
	return out
}

// answerOwner is the owner of rrset's records: the name its RRSIGs were made
// over, and the one a wildcard proof proves absent.
func answerOwner(rrset *core.RRset) string {
	if len(rrset.RRs) > 0 {
		return dns.Fqdn(rrset.RRs[0].Header().Name)
	}
	return dns.Fqdn(rrset.Name)
}

// ownerLabels is the label count of owner that an RRSIG Labels field is
// compared with: a leading "*" label is not counted (RFC 4034 section 3.1.3).
func ownerLabels(owner string) int {
	labels := dns.SplitDomainName(owner)
	if len(labels) > 0 && labels[0] == "*" {
		return len(labels) - 1
	}
	return len(labels)
}

// ExpansionSignature reports whether sig, over records owned by owner, was
// made over a wildcard: its Labels field is below owner's label count, a
// leading "*" label not counted (RFC 4034 section 3.1.3, RFC 4035 section
// 5.3.2). The chain walk of dog +sigchase asks it too, so that the two cannot
// tell expansions apart differently.
func ExpansionSignature(sig *dns.RRSIG, owner string) bool {
	return int(sig.Labels) < ownerLabels(owner)
}

// splitExpansionSignatures parts rrset's RRSIGs: those over its records that
// are expansion signatures, and the rest, in their order.
func splitExpansionSignatures(rrset *core.RRset) (rest, expansion []dns.RR) {
	owner := answerOwner(rrset)
	for _, rr := range rrset.RRSIGs {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == rrset.RRtype &&
			core.EqualNames(dns.Fqdn(sig.Hdr.Name), owner) && ExpansionSignature(sig, owner) {
			expansion = append(expansion, rr)
			continue
		}
		rest = append(rest, rr)
	}
	return rest, expansion
}

// hasExpansionSignature reports whether an RRSIG over rrset was made over a
// wildcard. Its callers do not ask it of a DNSKEY RRset, which is validated
// against the DS (ValidateDNSKEYs) and sits at a zone apex.
func hasExpansionSignature(rrset *core.RRset) bool {
	_, exp := splitExpansionSignatures(rrset)
	return len(exp) > 0
}

// signersOf is the Signer's Names of sigs, each once.
func signersOf(sigs []dns.RR) []string {
	var out []string
	for _, rr := range sigs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		signer := dns.Fqdn(sig.SignerName)
		if !core.EqualNamesContains(out, signer) {
			out = append(out, signer)
		}
	}
	return out
}
