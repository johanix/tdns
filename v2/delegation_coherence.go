/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
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

// dnskeyCopy is the DNSKEY RRset one nameserver of the child serves, with its
// RRSIGs, and what is known about how it validated.
//
// A child that is signed by more than one provider has a DNSKEY RRset per
// nameserver, not one: every nameserver serves the keys of all the signers, and
// each signs the RRset with its own signer's key only. Whether a delegation
// works is a property of every one of those copies, so the check is given all of
// them (#925).
type dnskeyCopy struct {
	// Server is the nameserver the copy came from. Empty where it is not known.
	Server string

	// RRset is the copy. Nil when Err is set.
	RRset *core.RRset

	// State is the resolver's verdict on the copy: cache.ValidationStateSecure
	// when it DNSSEC-validated, the zero value when validation was not
	// attempted. Only a Secure verdict is used, to authenticate a copy; the
	// check does not rely on it to judge what a DS change leaves behind, because
	// the verdict is about the DS RRset the resolver saw, which is not the one
	// the change produces.
	State cache.ValidationState

	// Err is why Server gave no copy: it could not be reached, or it gave no
	// answer.
	Err error
}

// dnskeyFetcher returns the DNSKEY RRset each of nameservers serves for child,
// one dnskeyCopy per nameserver asked, a nameserver that gave no copy included
// (dnskeyCopy.Err). An error means no copy could be had at all.
//
// The copies and their verdicts travel together because only the caller can
// decide what an unvalidated answer means: for a child that already has a DS it
// must be authenticated some other way, and for a child that has none it is the
// normal state of affairs. A fetcher that decided on its own could only get one
// of those right. The RRSIGs are what the other way checks (signedByPublishedDS).
//
// nameservers is the child's NS RRset: the delegation the update leaves. A
// fetcher that is not able to ask a particular nameserver ignores it.
//
// Injected rather than called directly so the rule below can be tested without
// a network, and so the parent can choose how it looks the child up.
type dnskeyFetcher func(child string, nameservers []dns.RR) (copies []dnskeyCopy, err error)

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
// ignoring class and TTL, and the case of a DS digest.
//
// Both have to be normalised before comparing. An RFC 2136 delete-RR carries
// CLASS=NONE and TTL=0 while the record it removes is CLASS=IN with a real TTL,
// and dns.IsDuplicate compares the header as it stands -- so comparing them
// directly never matches, and a deletion silently removes nothing. That failure
// is invisible in the result: the record simply stays.
//
// A digest is hex and means the same in either case, but dns.IsDuplicate
// compares the text. A record unpacked from a message carries lowercase hex,
// and one parsed from a zone file the case it was written in, so a withdrawal
// received from a child did not match the DS the parent publishes, and the
// check took it for a change that changes nothing (#925).
func sameRecord(a, b dns.RR) bool {
	na, nb := dns.Copy(a), dns.Copy(b)
	na.Header().Class, nb.Header().Class = dns.ClassINET, dns.ClassINET
	na.Header().Ttl, nb.Header().Ttl = 0, 0
	foldDigest(na)
	foldDigest(nb)
	return dns.IsDuplicate(na, nb)
}

// foldDigest lowercases the digest of a DS or CDS, in place.
func foldDigest(rr dns.RR) {
	switch r := rr.(type) {
	case *dns.DS:
		r.Digest = strings.ToLower(r.Digest)
	case *dns.CDS:
		r.Digest = strings.ToLower(r.Digest)
	}
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

// CheckDelegationCoherenceForUpdate applies the coherence rule to every
// delegation whose DS the update touches.
//
// The DS the parent publishes for the child is what the rule measures against,
// so a parent that cannot read it has not checked anything and refuses. It must
// not go on as if there were no DS: "no DS" is the bootstrap case, which accepts
// an unvalidated DNSKEY answer, and for a child that has a DS that answer is
// exactly the one the rule exists to refuse (#848). The DS set the update would
// leave is also computed from the current one, so it would be wrong as well.
func (zd *ZoneData) CheckDelegationCoherenceForUpdate(actions []dns.RR, fetch dnskeyFetcher) error {
	for _, child := range childrenWithDSChanges(zd.ZoneName, actions) {
		currentDS, err := zd.currentChildDS(child)
		if err != nil {
			return fmt.Errorf("cannot verify that %s would still validate: cannot read the DS this parent publishes for it: %w: %w",
				child, err, ErrDelegationUnverifiable)
		}
		if err := CheckDelegationCoherence(child, zd.childNameserversAfter(child, actions),
			currentDS, actions, fetch); err != nil {
			return err
		}
	}
	return nil
}

// childNameserversAfter returns the NS RRset the parent publishes for child once
// actions are applied: the nameservers a resolver is sent to after the change,
// and so the ones whose DNSKEY RRsets a DS change has to hold for. The current
// RRset when the update says nothing about NS, which is the usual case for a
// DS change.
func (zd *ZoneData) childNameserversAfter(child string, actions []dns.RR) []dns.RR {
	current := zd.currentChildNS(child)
	if after, touched := rrsetAfterActions(child, dns.TypeNS, current, actions); touched && len(after) > 0 {
		return after
	}
	return current
}

// CheckDelegationCoherence reports whether applying actions would leave child's
// delegation unvalidatable, and refuses it if so. nameservers is the child's NS
// RRset after the change; fetch is asked for the DNSKEY RRset each of them
// serves.
//
// The rule is RFC 7344's Continuity, and it is deliberately "at least one",
// not "all", for which key matches: a multi-DS KSK rollover legitimately places
// a DS for a key whose DNSKEY is not published yet, and requiring every DS to
// match a published key would reject exactly the procedure the rollover engine
// implements. What must hold is that SOME DS in the resulting set still resolves
// to a key the child publishes, so the chain of trust survives the change.
//
// It is "every" for which nameserver, when the change takes a DS away. A child
// that several providers sign has a DNSKEY RRset per nameserver, and each
// provider's nameservers serve it signed by that provider's key only. Taking one
// provider's DS away leaves the DS RRset matching a key the child publishes, and
// every resolver that asks that provider's nameservers gets an RRset no DS
// vouches for. So a DS is withdrawn only if, at every nameserver of the
// delegation, the DNSKEY RRset is signed by a key matching the DS RRset that
// results (#925). A nameserver that cannot be asked leaves that open, so the
// change is refused as unverifiable rather than accepted on the copies that
// could be had.
//
// A change that only adds DS records cannot make any copy bogus: whatever
// validated through the DS the parent publishes still does. It is judged as
// before, on a copy the DS the parent publishes authenticates. That is any one
// copy, not every one: the copy a resolver happens to be given may be the one
// the DS being added is for, and signed by nothing the parent publishes a DS
// for yet. Refusing the repair for that reason is the other half of #925.
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
func CheckDelegationCoherence(child string, nameservers, currentDS, actions []dns.RR, fetch dnskeyFetcher) error {
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

	all, err := fetch(child, nameservers)
	if err != nil {
		return fmt.Errorf("cannot verify that %s would still validate: DNSKEY lookup failed: %w: %w", child, err, ErrDelegationUnverifiable)
	}
	var copies, silent []dnskeyCopy // the copies there are; the nameservers that gave none
	for _, c := range all {
		switch {
		case c.Err != nil:
			silent = append(silent, c)
		case c.RRset == nil:
			// An answer with no RRset is an empty one: the nameserver serves no keys.
			c.RRset = &core.RRset{Name: child, Class: dns.ClassINET, RRtype: dns.TypeDNSKEY}
			copies = append(copies, c)
		default:
			copies = append(copies, c)
		}
	}
	if len(copies) == 0 {
		var errs []error
		for _, c := range silent {
			errs = append(errs, fmt.Errorf("%s: %w", c.server(), c.Err))
		}
		if len(errs) == 0 {
			errs = append(errs, errors.New("no nameserver gave a DNSKEY RRset"))
		}
		return fmt.Errorf("cannot verify that %s would still validate: DNSKEY lookup failed: %w: %w",
			child, errors.Join(errs...), ErrDelegationUnverifiable)
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
	// One authenticated copy is enough, and only the keys of authenticated
	// copies count below. The copies come from different nameservers, and a
	// delegation that is already broken at one of them (a DS withdrawn too
	// early, #925) is the case the child needs to repair; the others carry
	// the same keys, and they are authenticated.
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
	authenticated := copies
	if len(currentDS) > 0 {
		authenticated = nil
		var why []string
		var firstErr error
		viaDS := 0
		for _, c := range copies {
			if c.State == cache.ValidationStateSecure {
				authenticated = append(authenticated, c)
				continue
			}
			if err := signedByPublishedDS(c.RRset, currentDS); err != nil {
				why = append(why, fmt.Sprintf("%s (resolver: %s): %v", c.server(), validationStateName(c.State), err))
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			authenticated = append(authenticated, c)
			viaDS++
			if c.State == cache.ValidationStateBogus {
				lgHandler.Warn("delegation coherence: the resolver holds the child's DNSKEY RRset bogus,"+
					" but a key matching the DS this parent publishes signs it; the parent's DS decides",
					"child", child, "server", c.Server)
			}
		}
		if len(authenticated) == 0 {
			if len(copies) == 1 {
				return fmt.Errorf(
					"the DNSKEY RRset for %s did not DNSSEC-validate (resolver: %s), and it is not"+
						" signed by a key matching the DS this parent publishes (%v): with a DS in"+
						" place, an unvalidated answer cannot authorise changing it",
					child, validationStateName(copies[0].State), firstErr)
			}
			return fmt.Errorf(
				"the DNSKEY RRsets for %s, as its %d nameservers serve them, did not DNSSEC-validate,"+
					" and they are not signed by a key matching the DS this parent publishes (%s): with a DS in"+
					" place, an unvalidated answer cannot authorise changing it",
				child, len(copies), strings.Join(why, "; "))
		}
		if viaDS > 0 {
			lgHandler.Info("delegation coherence: DNSKEY RRset authenticated by the DS this parent publishes",
				"child", child, "copies", viaDS)
		}
	}

	keys := distinctDNSKEYs(authenticated)
	matched := false
	for _, dsrr := range resulting {
		ds, ok := dsrr.(*dns.DS)
		if !ok {
			continue
		}
		for _, dk := range keys {
			if dsMatchesKey(ds, dk) {
				matched = true
				break
			}
		}
	}
	if !matched {
		return fmt.Errorf(
			"the resulting DS RRset for %s matches none of the %d DNSKEY(s) it publishes;"+
				" applying it would make the whole child zone bogus", child, len(keys))
	}

	// A DS that goes away is what can leave a copy with no key to vouch for it,
	// so every nameserver's copy is held against the DS RRset that results. The
	// verdict on a copy that DS RRset has not been tried against says nothing.
	if !dsWithdrawn(currentDS, resulting) {
		return nil
	}
	for _, c := range copies {
		if err := signedByPublishedDS(c.RRset, resulting); err != nil {
			return fmt.Errorf(
				"the resulting DS RRset for %s would not validate the DNSKEY RRset %s serves (%v);"+
					" applying it would make %s bogus for every resolver that asks it",
				child, c.server(), err, child)
		}
	}
	if len(silent) > 0 {
		c := silent[0]
		return fmt.Errorf(
			"cannot verify that %s would still validate: %s gave no DNSKEY RRset (%v), and the DS being"+
				" withdrawn may be the one that vouches for what it serves: %w",
			child, c.server(), c.Err, ErrDelegationUnverifiable)
	}
	return nil
}

// dsWithdrawn reports whether resulting leaves out a DS record that current has.
func dsWithdrawn(current, resulting []dns.RR) bool {
	for _, cur := range current {
		kept := false
		for _, res := range resulting {
			if sameRecord(cur, res) {
				kept = true
				break
			}
		}
		if !kept {
			return true
		}
	}
	return false
}

// distinctDNSKEYs returns the DNSKEY records the copies hold, each once.
func distinctDNSKEYs(copies []dnskeyCopy) []*dns.DNSKEY {
	var keys []*dns.DNSKEY
	for _, c := range copies {
		for _, rr := range c.RRset.RRs {
			dk, ok := rr.(*dns.DNSKEY)
			if !ok {
				continue
			}
			dup := false
			for _, have := range keys {
				if sameRecord(have, dk) {
					dup = true
					break
				}
			}
			if !dup {
				keys = append(keys, dk)
			}
		}
	}
	return keys
}

// server names the nameserver of a copy, for a refusal.
func (c dnskeyCopy) server() string {
	if c.Server == "" {
		return "a nameserver"
	}
	return "nameserver " + c.Server
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
// resolver and scanner are asked. A server without them gets nil, and the check
// refuses as unverifiable: that will not change by asking again. A daemon whose
// resolver has not started yet -- still priming, or retrying a failed priming --
// gets a fetcher that fails with ErrNoImrEngine, which the callers answer as "try
// again" rather than as a verdict on the delegation.
func coherenceDnskeyFetcher(conf *Config) dnskeyFetcher {
	// ImrEngine may be read only once readiness is published. No readiness
	// signal at all means no engine goroutine that could still bring a resolver
	// up (a CLI, a test): whatever the field holds is all there will be.
	r := conf.Internal.ImrReady
	if r == nil || r.Published() {
		return nameserversDnskeyFetcher(conf.Internal.GetScanner())
	}
	if conf.Imr.Active != nil && !*conf.Imr.Active {
		return nil
	}
	return func(string, []dns.RR) ([]dnskeyCopy, error) {
		return nil, fmt.Errorf("this server's resolver is not running yet: %w", ErrNoImrEngine)
	}
}

// nameserversDnskeyFetcher asks every nameserver of the child for its DNSKEY
// RRset, which is the way the parent learns what the child serves for the CDS
// and CSYNC scans and for the NS half of the coherence check too. Each is asked
// directly and none is answered from a cache.
//
// The parent's resolver would give one answer, from one nameserver and possibly
// from its cache, and a child that several providers sign has a different one
// at each nameserver (#925). The resolver's verdict is not taken either: it is
// reached through the DS RRset the resolver holds, which a change in progress
// may have just made out of date. The parent is the authority for that DS
// RRset, and the check measures every copy against its own.
//
// Returns nil when there is no scanner, so the caller reports "no way to look
// up its DNSKEYs" rather than an unexplained refusal.
func nameserversDnskeyFetcher(scanner *Scanner) dnskeyFetcher {
	if scanner == nil {
		return nil
	}
	return func(child string, nameservers []dns.RR) ([]dnskeyCopy, error) {
		if len(nameservers) == 0 {
			return nil, fmt.Errorf("the parent publishes no nameserver for %s to ask", child)
		}
		lg := scanner.Log["CDS"]
		if lg == nil {
			lg = log.Default()
		}
		ctx, cancel := context.WithTimeout(context.Background(), delegationCheckTimeout)
		defer cancel()

		answers, err := scanner.askChildServers(ctx, child, dns.TypeDNSKEY,
			&core.RRset{Name: child, Class: dns.ClassINET, RRtype: dns.TypeNS, RRs: nameservers}, lg)
		if err != nil {
			return nil, err
		}
		copies := make([]dnskeyCopy, 0, len(answers))
		for _, a := range answers {
			copies = append(copies, dnskeyCopy{Server: a.NS, RRset: a.RRset})
		}
		return withSilentServers(copies, nameservers), nil
	}
}

// withSilentServers adds, for each of nameservers that has no copy among
// copies, an entry that says so. The scanner leaves a nameserver that gave no
// answer out of what it returns.
func withSilentServers(copies []dnskeyCopy, nameservers []dns.RR) []dnskeyCopy {
	for _, rr := range nameservers {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		answered := false
		for _, c := range copies {
			if core.EqualNames(c.Server, ns.Ns) {
				answered = true
				break
			}
		}
		if !answered {
			copies = append(copies, dnskeyCopy{Server: ns.Ns, Err: errors.New("it gave no answer")})
		}
	}
	return copies
}

// currentChildDS returns the DS RRset the parent currently publishes for child.
// The parent is authoritative for it, so this is a local read.
//
// A child with no owner in the zone, or no DS at its owner, has no DS: nil and
// no error. A parent that cannot read its own zone returns an error instead,
// because to the caller nil means "no DS" (#848). A zone store with no owner
// index can never answer, which errParentDSUnreadable marks; a zone that is not
// Ready yet can once it is, and keeps ErrZoneNotReady.
func (zd *ZoneData) currentChildDS(child string) ([]dns.RR, error) {
	if zd.ZoneStore != MapZone {
		return nil, fmt.Errorf("zone %s is a %s, which holds no owner index: %w",
			zd.ZoneName, ZoneStoreToString[zd.ZoneStore], errParentDSUnreadable)
	}
	owner, err := zd.GetOwner(dns.Fqdn(child))
	if err != nil {
		return nil, err
	}
	if owner == nil || owner.RRtypes == nil {
		return nil, nil
	}
	return owner.RRtypes.GetOnlyRRSet(dns.TypeDS).RRs, nil
}
