/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Delegation coherence: the parent will not publish a delegation it can see is
// broken.
//
// The parent's update policy answers whether a principal MAY change an RRtype
// at a name. It says nothing about whether the delegation that results still
// works, so a principal fully authorised to manage a child's DS can hand the
// parent a DS set matching no key the child publishes, and every validating
// resolver then declares the whole child zone bogus.
//
// RFC 7344 §4.1 states the property for the CDS channel -- "Continuity: MUST
// NOT break the current delegation if applied to DS RRset" -- and the parent's
// CDS scanner enforces it. The property is not channel-specific: a child
// asserting a DS change over DNS UPDATE or the DSYNC API can break its
// delegation exactly as thoroughly. This applies it on those channels too.
//
// It is the PARENT doing the checking, on every channel, which is the whole
// point. A check performed by the requesting client is not a check, and a
// client cannot know a given parent's local requirements anyway.

// dnskeyFetcher returns the DNSKEY RRset the child currently publishes.
//
// Injected rather than called directly so the rule below can be tested without
// a network, and so the parent can choose how it looks the child up.
type dnskeyFetcher func(child string) ([]dns.RR, error)

// dsAfterActions applies the DS-affecting records of an RFC 2136 update to the
// parent's current DS RRset for child, and reports the result.
//
// touched is false when the update says nothing about the child's DS. That is
// the common case -- an NS or glue change -- and it matters because it is what
// keeps the coherence check, and the lookup it needs, off updates that cannot
// affect the chain of trust.
func dsAfterActions(child string, currentDS, actions []dns.RR) (result []dns.RR, touched bool) {
	child = dns.Fqdn(child)
	result = append(result, currentDS...)

	for _, rr := range actions {
		h := rr.Header()
		if !dns.IsSubDomain(child, h.Name) || !dns.IsSubDomain(h.Name, child) {
			continue // not at the child's apex
		}

		switch h.Class {
		case dns.ClassANY:
			// Delete an entire RRset. TypeANY deletes every RRset at the name,
			// which includes the DS.
			if h.Rrtype == dns.TypeDS || h.Rrtype == dns.TypeANY {
				result = nil
				touched = true
			}
		case dns.ClassNONE:
			// Delete one record.
			if h.Rrtype != dns.TypeDS {
				continue
			}
			touched = true
			var kept []dns.RR
			for _, cur := range result {
				if sameRecord(cur, rr) {
					continue
				}
				kept = append(kept, cur)
			}
			result = kept
		default:
			// Add.
			if h.Rrtype != dns.TypeDS {
				continue
			}
			touched = true
			dup := false
			for _, cur := range result {
				if sameRecord(cur, rr) {
					dup = true
					break
				}
			}
			if !dup {
				result = append(result, dns.Copy(rr))
			}
		}
	}
	return result, touched
}


// sameRecord reports whether two records are the same owner, type and rdata,
// ignoring class and TTL.
//
// Both have to be normalised before comparing. An RFC 2136 delete-RR carries
// CLASS=NONE and TTL=0 while the record it removes is CLASS=IN with a real TTL,
// and dns.IsDuplicate compares the header as it stands -- so comparing them
// directly never matches, and a deletion silently removes nothing. That failure
// is invisible in the result: the record simply stays.
func sameRecord(a, b dns.RR) bool {
	na, nb := dns.Copy(a), dns.Copy(b)
	na.Header().Class, nb.Header().Class = dns.ClassINET, dns.ClassINET
	na.Header().Ttl, nb.Header().Ttl = 0, 0
	return dns.IsDuplicate(na, nb)
}


// sameDSSet reports whether two DS RRsets hold the same records, order aside.
func sameDSSet(a, b []dns.RR) bool {
	if len(a) != len(b) {
		return false
	}
	used := make([]bool, len(b))
	for _, x := range a {
		found := false
		for i, y := range b {
			if used[i] {
				continue
			}
			if sameRecord(x, y) {
				used[i] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// childrenWithDSChanges returns the delegations an update touches the DS of.
//
// The owner name of a DS record IS the delegation it belongs to, so there is no
// arithmetic to get wrong here and multi-label children work by construction --
// which an earlier version of this code, trimming names to one label below the
// apex, did not: a DS for foo.bar.example. of example. was silently skipped.
//
// TypeANY at a name counts, because deleting every RRset at a delegation takes
// its DS with it.
func childrenWithDSChanges(parent string, actions []dns.RR) []string {
	parent = dns.Fqdn(parent)
	seen := map[string]bool{}
	var out []string
	for _, rr := range actions {
		h := rr.Header()
		if h.Rrtype != dns.TypeDS && h.Rrtype != dns.TypeANY {
			continue
		}
		name := dns.Fqdn(h.Name)
		if !dns.IsSubDomain(parent, name) || strings.EqualFold(name, parent) {
			continue
		}
		key := strings.ToLower(name)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, name)
	}
	return out
}

// CheckDelegationCoherenceForUpdate applies the coherence rule to every
// delegation whose DS the update touches.
func (zd *ZoneData) CheckDelegationCoherenceForUpdate(actions []dns.RR, fetch dnskeyFetcher) error {
	for _, child := range childrenWithDSChanges(zd.ZoneName, actions) {
		if err := CheckDelegationCoherence(child, zd.currentChildDS(child), actions, fetch); err != nil {
			return err
		}
	}
	return nil
}

// CheckDelegationCoherence reports whether applying actions would leave child's
// delegation unvalidatable, and refuses it if so.
//
// The rule is RFC 7344's Continuity, and it is deliberately "at least one",
// not "all": a multi-DS KSK rollover legitimately places a DS for a key whose
// DNSKEY is not published yet, and requiring every DS to match a published key
// would reject exactly the procedure the rollover engine implements. What must
// hold is that SOME DS in the resulting set still resolves to a key the child
// publishes, so the chain of trust survives the change.
//
// An empty resulting DS set is allowed. Going insecure is a legitimate thing to
// ask for, it is what the RFC 8078 delete sentinel expresses, and it leaves the
// child working rather than bogus.
//
// A failed DNSKEY lookup refuses the update. That is the uncomfortable half of
// making the check mandatory: it means a child that cannot be reached cannot
// change its own DS. The alternative is worse -- accepting on lookup failure
// turns the check into a formality that anything can bypass by being
// unreachable at the right moment -- and the cost is bounded by the fact that
// this runs only for updates that actually change the DS.
func CheckDelegationCoherence(child string, currentDS, actions []dns.RR, fetch dnskeyFetcher) error {
	child = dns.Fqdn(child)

	resulting, mentioned := dsAfterActions(child, currentDS, actions)
	if !mentioned {
		return nil
	}
	// Mentioning DS is not changing it. A no-op DS delete alongside an NS edit,
	// or a re-send of the DS already published, leaves the parent exactly where
	// it was -- and making that depend on the child being reachable would add a
	// failure mode to a request that changes nothing.
	if sameDSSet(currentDS, resulting) {
		return nil
	}
	if len(resulting) == 0 {
		lgHandler.Info("delegation coherence: update clears the DS RRset; the child becomes insecure",
			"child", child)
		return nil
	}
	if fetch == nil {
		return fmt.Errorf("cannot verify that %s would still validate: no way to look up its DNSKEYs", child)
	}

	keys, err := fetch(child)
	if err != nil {
		return fmt.Errorf("cannot verify that %s would still validate: DNSKEY lookup failed: %w", child, err)
	}

	for _, dsrr := range resulting {
		ds, ok := dsrr.(*dns.DS)
		if !ok {
			continue
		}
		for _, keyrr := range keys {
			dk, ok := keyrr.(*dns.DNSKEY)
			if !ok {
				continue
			}
			// Deliberately not filtered on the SEP bit. SEP is advisory and
			// validators ignore it, so a DS hashing a flags-256 CSK is a
			// perfectly usable entry point. Requiring SEP here would refuse a
			// working delegation on the strength of a hint.
			if dk.Flags&dns.ZONE == 0 {
				continue
			}
			computed := dk.ToDS(ds.DigestType)
			if computed == nil {
				continue
			}
			if computed.KeyTag == ds.KeyTag &&
				computed.Algorithm == ds.Algorithm &&
				equalFoldASCII(computed.Digest, ds.Digest) {
				return nil
			}
		}
	}

	return fmt.Errorf(
		"the resulting DS RRset for %s matches none of the %d DNSKEY(s) it publishes;"+
			" applying it would make the whole child zone bogus", child, len(keys))
}

// equalFoldASCII compares two hex digests without allocating. DS digests are
// hex and case-insensitive.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// imrDnskeyFetcher looks the child's DNSKEY RRset up through the iterative
// resolver, which is the parent's normal way of asking a question about a zone
// it is not authoritative for.
//
// Returns nil when there is no resolver, so the caller reports "no way to look
// up its DNSKEYs" rather than an unexplained refusal.
func imrDnskeyFetcher(imr *Imr) dnskeyFetcher {
	if imr == nil {
		return nil
	}
	return func(child string) ([]dns.RR, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := imr.ImrQuery(ctx, dns.Fqdn(child), dns.TypeDNSKEY, dns.ClassINET, nil)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.RRset == nil {
			return nil, fmt.Errorf("no DNSKEY RRset returned for %s", child)
		}
		if resp.Error {
			return nil, fmt.Errorf("DNSKEY lookup for %s failed: %s", child, resp.ErrorMsg)
		}
		// The answer has to be authenticated. This check exists to stop the
		// parent publishing a DS that nothing can validate, and an unvalidated
		// DNSKEY answer is exactly what an attacker would supply to make a
		// bogus DS look fine -- the check would then certify the breakage
		// rather than prevent it.
		//
		// A child that is currently insecure cannot produce a validated DNSKEY
		// answer, but it does not need to: this fetch only runs when the
		// resulting DS set is non-empty, and a DS whose child is insecure is
		// the state being refused anyway.
		if !resp.Validated {
			return nil, fmt.Errorf("DNSKEY RRset for %s did not DNSSEC-validate", child)
		}
		return resp.RRset.RRs, nil
	}
}

// currentChildDS returns the DS RRset the parent currently publishes for child.
// The parent is authoritative for it, so this is a local read.
func (zd *ZoneData) currentChildDS(child string) []dns.RR {
	owner, err := zd.GetOwner(dns.Fqdn(child))
	if err != nil || owner == nil || owner.RRtypes == nil {
		return nil
	}
	return owner.RRtypes.GetOnlyRRSet(dns.TypeDS).RRs
}
