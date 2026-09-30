/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"time"

	cache "github.com/johanix/tdns/v2/cache"
	core "github.com/johanix/tdns/v2/core"
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

// dnskeyFetcher returns the DNSKEY RRset the child currently publishes, with
// its RRSIGs, and the resolver's verdict on it: cache.ValidationStateSecure
// when it DNSSEC-validated, the zero value when validation was not attempted.
//
// The two travel together because only the caller can decide what an
// unvalidated answer means: for a child that already has a DS it must be
// authenticated some other way, and for a child that has none it is the normal
// state of affairs. A fetcher that decided on its own could only get one of
// those right. The RRSIGs are what the other way checks (signedByPublishedDS).
//
// Injected rather than called directly so the rule below can be tested without
// a network, and so the parent can choose how it looks the child up.
type dnskeyFetcher func(child string) (dnskeys *core.RRset, state cache.ValidationState, err error)

// dsAfterActions applies the DS-affecting records of an RFC 2136 update to the
// parent's current DS RRset for child, and reports the result.
//
// touched is false when the update says nothing about the child's DS. That is
// the common case -- an NS or glue change -- and it matters because it is what
// keeps the coherence check, and the lookup it needs, off updates that cannot
// affect the chain of trust.
func dsAfterActions(child string, currentDS, actions []dns.RR) (result []dns.RR, touched bool) {
	return rrsetAfterActions(child, dns.TypeDS, currentDS, actions)
}

// rrsetAfterActions applies the records of an RFC 2136 update that address
// (owner, rrtype) to current, and reports the result and whether the update
// mentioned that RRset at all. Shared by the DS coherence check above and the
// NS/glue one (delegation_csync_update.go); the semantics are RFC 2136 §2.5:
// class ANY deletes the RRset (or, with type ANY, every RRset at the name),
// class NONE deletes one record, anything else adds one.
func rrsetAfterActions(owner string, rrtype uint16, current, actions []dns.RR) (result []dns.RR, touched bool) {
	owner = dns.Fqdn(owner)
	result = append(result, current...)

	for _, rr := range actions {
		h := rr.Header()
		if !core.EqualNames(dns.Fqdn(h.Name), owner) {
			continue
		}

		switch h.Class {
		case dns.ClassANY:
			if h.Rrtype == rrtype || h.Rrtype == dns.TypeANY {
				result = nil
				touched = true
			}
		case dns.ClassNONE:
			if h.Rrtype != rrtype {
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
			if h.Rrtype != rrtype {
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

// sameRRsetContent reports whether two RRsets hold the same records, order
// aside. Nothing in it is DS-specific (sameRecord zeroes the TTL and compares
// wire content), and the NS half of the acceptance rules needs the same test,
// so it is named for what it does.
func sameRRsetContent(a, b []dns.RR) bool {
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
		if !dns.IsSubDomain(parent, name) || core.EqualNames(name, parent) {
			continue
		}
		key := core.CanonicalizeName(name)
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
// ErrDelegationUnverifiable marks a coherence failure the parent could not
// DECIDE, as opposed to one it decided against.
//
// The two are different answers to the child and want different reactions. "The
// delegation you asked for is not what your nameservers serve" is the child's
// to fix and will not improve by waiting. "I could not ask your nameservers" --
// one refused the connection, or a parent-side precondition was missing -- says
// nothing about the update at all, and is worth retrying.
//
// Both used to arrive as EDE 518, "Zone does not allow DNS UPDATE", on a zone
// that had just approved the update (#571).
var ErrDelegationUnverifiable = errors.New("the delegation could not be verified")

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
	if sameRRsetContent(currentDS, resulting) {
		return nil
	}
	if len(resulting) == 0 {
		lgHandler.Info("delegation coherence: update clears the DS RRset; the child becomes insecure",
			"child", child)
		return nil
	}
	if fetch == nil {
		return fmt.Errorf("cannot verify that %s would still validate: %w: %w", child, errNoDnskeyFetcher, ErrDelegationUnverifiable)
	}

	dnskeys, state, err := fetch(child)
	if err != nil {
		return fmt.Errorf("cannot verify that %s would still validate: DNSKEY lookup failed: %w: %w", child, err, ErrDelegationUnverifiable)
	}
	var keys []dns.RR
	if dnskeys != nil {
		keys = dnskeys.RRs
	}

	// An unvalidated DNSKEY answer is only meaningful when there is something to
	// validate against.
	//
	// If the parent already publishes a DS, the answer must be authenticated
	// through it: an unauthenticated one is exactly what an attacker would
	// supply to make a bogus DS look fine. The resolver's Secure does that, but
	// only for a parent inside the resolver's chain of trust, and a DS does not
	// put the parent there. At a parent that is unsigned, or that no trust
	// anchor of its resolver covers, the child is never Secure however correct
	// its keys, and every DS change after the first was refused for good
	// (#838). So on any verdict short of Secure the parent takes the step a
	// validator takes at this delegation point itself, with the DS it
	// publishes and is the authority for: the DNSKEY RRset must be signed,
	// within the signature's validity period, by a key matching that DS
	// (signedByPublishedDS). The conclusion holds for this check only; nothing
	// is cached.
	//
	// That includes Bogus. The check is made on the RRset in hand, so a forged
	// or altered one, or one whose signatures have expired, fails it whatever
	// the resolver said. An RRset that passes it and is still Bogus to the
	// resolver is a disagreement about the chain rather than the keys -- the
	// resolver holding an older copy of this parent's DS RRset, or a break
	// above this parent -- which the child cannot fix and this change does not
	// touch. It is logged.
	//
	// If the parent publishes no DS, the child is insecure -- and demanding a
	// validated answer would make it permanently so. That is RFC 8078
	// bootstrap: the child has keys, no DS chains to them yet, and adding the
	// first DS is what creates the chain. Requiring validation here refuses the
	// one update that would fix it, so an authorised child could go insecure and
	// never come back via UPDATE or the API.
	//
	// This is the distinction an earlier version of this function got wrong, and
	// argued for in a comment: "currently insecure" is not "would be bogus".
	// What still protects the bootstrap case is everything else -- the update is
	// authenticated and authorised, and the DS must match a key the child
	// actually publishes. It is the same carve-out the CDS scanner makes for
	// onboarding when no DS exists.
	if len(currentDS) > 0 && state != cache.ValidationStateSecure {
		if err := signedByPublishedDS(dnskeys, currentDS); err != nil {
			return fmt.Errorf(
				"the DNSKEY RRset for %s did not DNSSEC-validate (resolver: %s), and it is not"+
					" signed by a key matching the DS this parent publishes (%v): with a DS in"+
					" place, an unvalidated answer cannot authorise changing it",
				child, validationStateName(state), err)
		}
		if state == cache.ValidationStateBogus {
			lgHandler.Warn("delegation coherence: the resolver holds the child's DNSKEY RRset bogus,"+
				" but a key matching the DS this parent publishes signs it; the parent's DS decides",
				"child", child)
		} else {
			lgHandler.Info("delegation coherence: DNSKEY RRset authenticated by the DS this parent publishes",
				"child", child, "resolver", validationStateName(state))
		}
	}

	for _, dsrr := range resulting {
		ds, ok := dsrr.(*dns.DS)
		if !ok {
			continue
		}
		for _, keyrr := range keys {
			if dk, ok := keyrr.(*dns.DNSKEY); ok && dsMatchesKey(ds, dk) {
				return nil
			}
		}
	}

	return fmt.Errorf(
		"the resulting DS RRset for %s matches none of the %d DNSKEY(s) it publishes;"+
			" applying it would make the whole child zone bogus", child, len(keys))
}

// dsMatchesKey reports whether ds is the DS of dk: key tag, algorithm and
// digest.
//
// Deliberately not filtered on the SEP bit. SEP is advisory and validators
// ignore it, so a DS hashing a flags-256 CSK is a perfectly usable entry point.
// Requiring SEP here would refuse a working delegation on the strength of a
// hint.
func dsMatchesKey(ds *dns.DS, dk *dns.DNSKEY) bool {
	if dk.Flags&dns.ZONE == 0 {
		return false
	}
	computed := dk.ToDS(ds.DigestType)
	return computed != nil &&
		computed.KeyTag == ds.KeyTag &&
		computed.Algorithm == ds.Algorithm &&
		equalFoldASCII(computed.Digest, ds.Digest)
}

// signedByPublishedDS returns nil when the DNSKEY RRset dnskeys is signed by
// one of its own keys that matches a DS in currentDS, with a signature that
// verifies and is within its validity period; otherwise why not. That is the
// step a validator takes at the delegation point (RFC 4035 §5.2), taken with
// the DS this parent publishes rather than one a resolver learned. It only
// reads dnskeys: what it concludes goes no further than the caller.
func signedByPublishedDS(dnskeys *core.RRset, currentDS []dns.RR) error {
	if dnskeys == nil || len(dnskeys.RRs) == 0 {
		return errors.New("there is no DNSKEY RRset")
	}
	var entry []*dns.DNSKEY
	for _, keyrr := range dnskeys.RRs {
		dk, ok := keyrr.(*dns.DNSKEY)
		if !ok {
			continue
		}
		for _, dsrr := range currentDS {
			if ds, ok := dsrr.(*dns.DS); ok && dsMatchesKey(ds, dk) {
				entry = append(entry, dk)
				break
			}
		}
	}
	if len(entry) == 0 {
		return fmt.Errorf("none of its %d DNSKEY(s) matches that DS", len(dnskeys.RRs))
	}
	_, err := signedByOneOf(dnskeys, entry, time.Now().UTC())
	return err
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

// coherenceDnskeyFetcher is the fetcher the coherence check gets on a server
// built from conf.
//
// Three cases, because they call for three different answers. A running
// resolver is asked. A server without one gets nil, and the check refuses as
// unverifiable: that will not change by asking again. A daemon whose resolver
// has not started yet -- still priming, or retrying a failed priming -- gets a
// fetcher that fails with ErrNoImrEngine, which the callers answer as "try
// again" rather than as a verdict on the delegation.
func coherenceDnskeyFetcher(conf *Config) dnskeyFetcher {
	// ImrEngine may be read only once readiness is published. No readiness
	// signal at all means no engine goroutine that could still bring a resolver
	// up (a CLI, a test): whatever the field holds is all there will be.
	r := conf.Internal.ImrReady
	if r == nil || r.Published() {
		return imrDnskeyFetcher(conf.Internal.ImrEngine)
	}
	if conf.Imr.Active != nil && !*conf.Imr.Active {
		return nil
	}
	return func(child string) (*core.RRset, cache.ValidationState, error) {
		return nil, 0, fmt.Errorf("this server's resolver is not running yet: %w", ErrNoImrEngine)
	}
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
	return func(child string) (*core.RRset, cache.ValidationState, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := imr.ImrQuery(ctx, dns.Fqdn(child), dns.TypeDNSKEY, dns.ClassINET, nil)
		if err != nil {
			return nil, 0, err
		}
		if resp == nil || resp.RRset == nil {
			return nil, 0, fmt.Errorf("no DNSKEY RRset returned for %s", child)
		}
		if resp.Error {
			return nil, 0, fmt.Errorf("DNSKEY lookup for %s failed: %s", child, resp.ErrorMsg)
		}
		// Report the verdict; do not decide what it means. Only the caller
		// knows whether the child already has a DS, which is what separates an
		// attack from an ordinary bootstrap. The RRset may be the resolver's
		// cached one, so the caller only reads it.
		return resp.RRset, resp.ValidationState, nil
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
