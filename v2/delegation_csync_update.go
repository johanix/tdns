/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The RFC 7477 rules applied to an ASSERTED change (D-3b, step 2).
//
// draft-ietf-dnsop-delegation-mgmt-via-ddns-02 §"Processing the UPDATE": a
// delegation change that arrives by DNS UPDATE (or the DSYNC API) is subjected
// to the same correctness tests a CSYNC scanner would have run, so the parent
// applies one policy however the change arrives. For DS that is
// CheckDelegationCoherence (delegation_coherence.go). This is the NS/glue
// half, built on the rules the scanner uses (delegation_csync.go).
//
// A scan COPIES the child's NS set and the addresses of its in-bailiwick
// nameservers. So a delegation the scanner would produce is one where the NS
// set is what the child's nameservers serve, in agreement, and the glue is
// what they serve for each in-bailiwick nameserver. That is what is checked,
// scoped to what the update touches -- the DS check's discipline: an update
// that changes the NS set must produce the served NS set; a nameserver the
// update adds, or whose glue it touches, must end up with the served glue; a
// nameserver the update removes must not leave glue behind; and an address
// record may only be added at an in-bailiwick nameserver of the resulting set.
// Glue the update does not touch, for nameservers it keeps, is not
// re-verified: stale glue elsewhere is the scanner's to fix, not a reason to
// refuse this child's change.

// childNameserverAsker builds, for one child, the fetcher that asks that
// child's nameservers. Which nameservers: the parent's current delegation, so
// the child has to have made its CURRENT servers serve the change before
// asking the parent to publish it (RFC 7477's child-first model); for a
// delegation that does not exist yet, the ones the update names.
type childNameserverAsker func(child string, nameservers []dns.RR) childRRsetFetcher

// childNameserverAsker is the production asker: the scanner's
// query-every-nameserver-and-compare, which is also what the CSYNC path uses.
// A nil scanner yields nil, and the check then refuses rather than guesses.
func (scanner *Scanner) childNameserverAsker(lg *log.Logger) childNameserverAsker {
	if scanner == nil {
		return nil
	}
	if lg == nil {
		lg = scanner.Log["CSYNC"]
	}
	if lg == nil {
		lg = log.Default()
	}
	return func(child string, nameservers []dns.RR) childRRsetFetcher {
		return scanner.childRRsetFetcher(&core.RRset{Name: child, RRtype: dns.TypeNS, RRs: nameservers}, lg)
	}
}

// delegationCheckTimeout bounds one update's worth of asking the child's
// nameservers: an NS query plus up to two address queries per in-bailiwick
// nameserver, each to every nameserver.
const delegationCheckTimeout = 30 * time.Second

// CheckDelegationNSCoherenceForUpdate applies the NS/glue rule to every
// delegation the update touches. It reads the parent's current delegation
// from its own zone data, which is what the responder itself updates.
func (zd *ZoneData) CheckDelegationNSCoherenceForUpdate(ctx context.Context, actions []dns.RR, ask childNameserverAsker) error {
	children, orphans := zd.delegationsTouched(actions)
	if len(orphans) > 0 {
		return fmt.Errorf("address records at %s belong to no delegation of %s: not glue",
			strings.Join(orphans, ", "), zd.ZoneName)
	}
	for _, child := range children {
		currentNS := zd.currentChildNS(child)
		resultingNS, _ := rrsetAfterActions(child, dns.TypeNS, currentNS, actions)
		toAsk := currentNS
		if len(toAsk) == 0 {
			toAsk = resultingNS
		}
		var fetch childRRsetFetcher
		if ask != nil && len(toAsk) > 0 {
			fetch = ask(child, toAsk)
		}
		if err := CheckDelegationNSCoherence(ctx, child, currentNS, zd.currentGlueLookup(), actions, fetch); err != nil {
			return err
		}
	}
	return nil
}

// delegationsTouched returns the delegations whose NS or glue the update
// mentions. An NS record's owner IS its delegation. An address record's
// delegation is the closest enclosing name that is an existing child cut or
// an NS owner in this same update; one with neither is an orphan -- there is
// no delegation it could be glue for.
func (zd *ZoneData) delegationsTouched(actions []dns.RR) (children, orphans []string) {
	parent := dns.Fqdn(zd.ZoneName)
	nsOwners := map[string]bool{}
	seen := map[string]bool{}
	add := func(name string) {
		key := core.CanonicalizeName(name)
		if !seen[key] {
			seen[key] = true
			children = append(children, name)
		}
	}

	for _, rr := range actions {
		h := rr.Header()
		name := dns.Fqdn(h.Name)
		if !dns.IsSubDomain(parent, name) || core.EqualNames(name, parent) {
			continue
		}
		switch {
		case h.Rrtype == dns.TypeNS:
			nsOwners[core.CanonicalizeName(name)] = true
			add(name)
		case h.Class == dns.ClassANY && h.Rrtype == dns.TypeANY && zd.IsChildDelegation(name):
			// Deleting every RRset at a delegation point takes its NS with it.
			add(name)
		}
	}

	for _, rr := range actions {
		h := rr.Header()
		// Address records, and a name-wide delete, which takes the addresses
		// with it.
		//
		// The ANY case is easy to miss and expensive to miss. "CLASS=ANY
		// TYPE=ANY at ns1.child.example." is not an NS action, and it is not
		// ANY at a delegation cut (the loop above catches that), and it is not
		// typed A/AAAA -- so without this it matches nothing, no child is
		// discovered, and the whole NS/glue check is SKIPPED for an update
		// that strips every address off an in-bailiwick nameserver while
		// leaving the NS in place. That is the exact state the glue rules
		// exist to refuse.
		glueTouch := h.Rrtype == dns.TypeA || h.Rrtype == dns.TypeAAAA ||
			(h.Class == dns.ClassANY && h.Rrtype == dns.TypeANY)
		if !glueTouch {
			continue
		}
		name := dns.Fqdn(h.Name)
		if !dns.IsSubDomain(parent, name) || core.EqualNames(name, parent) {
			continue
		}
		labels := dns.SplitDomainName(name)
		found := ""
		for i := 0; i < len(labels); i++ {
			cand := dns.Fqdn(strings.Join(labels[i:], "."))
			if core.EqualNames(cand, parent) {
				break
			}
			if nsOwners[core.CanonicalizeName(cand)] || zd.IsChildDelegation(cand) {
				found = cand
				break
			}
		}
		switch {
		case found != "":
			add(found)
		case h.Class == dns.ClassINET:
			orphans = append(orphans, name)
		}
	}
	return children, orphans
}

// currentChildNS returns the NS RRset the parent publishes for child now.
func (zd *ZoneData) currentChildNS(child string) []dns.RR {
	owner, err := zd.GetOwner(dns.Fqdn(child))
	if err != nil || owner == nil || owner.RRtypes == nil {
		return nil
	}
	return owner.RRtypes.GetOnlyRRSet(dns.TypeNS).RRs
}

// currentGlueLookup reads glue from the parent's zone data, in the shape the
// scanner's delegation-backend lookup has.
func (zd *ZoneData) currentGlueLookup() currentGlueLookup {
	return func(owner string, qtype uint16) ([]dns.RR, bool) {
		od, err := zd.GetOwner(dns.Fqdn(owner))
		if err != nil || od == nil || od.RRtypes == nil {
			return nil, false
		}
		rrset, ok := od.RRtypes.Get(qtype)
		if !ok {
			return nil, false
		}
		return rrset.RRs, true
	}
}

var discardLog = log.New(io.Discard, "", 0)

// CheckDelegationNSCoherence reports whether applying actions to child's
// delegation would leave it different from what the child's nameservers serve,
// and refuses it if so. See the file comment for the rule and its scoping.
//
// fetch may be nil only when the update touches neither NS nor glue for the
// child; otherwise a nil fetch is "no way to ask", and refuses.
func CheckDelegationNSCoherence(ctx context.Context, child string, currentNS []dns.RR, currentGlue currentGlueLookup,
	actions []dns.RR, fetch childRRsetFetcher) error {

	child = dns.Fqdn(child)
	resultingNS, nsTouched := rrsetAfterActions(child, dns.TypeNS, currentNS, actions)
	glueTouched := glueOwnersTouched(child, actions)
	if !nsTouched && len(glueTouched) == 0 {
		return nil
	}

	// Mentioning the NS RRset is not changing it. A duplicate NS add, or a
	// delete of something that was not there, leaves the parent's delegation
	// exactly where it was -- and making that depend on the child being
	// reachable and in agreement would add a failure mode to a request that
	// changes nothing. Same reasoning, and the same helper, as the DS half in
	// CheckDelegationCoherence.
	//
	// The gate has to be here rather than only at the query below: further
	// down, a nil fetcher is a refusal, so a no-op NS edit on a server with no
	// scanner would be refused for being unverifiable when there is nothing to
	// verify.
	nsChanged := nsTouched && !sameRRsetContent(currentNS, resultingNS)
	if !nsChanged && len(glueTouched) == 0 {
		return nil
	}

	if len(resultingNS) == 0 {
		return fmt.Errorf("the update would leave %s with no NS records; an empty NS RRset is rejected (RFC 7477 §3.2.1)", child)
	}

	inBailiwick := inBailiwickNSNames(child, resultingNS)
	inBailiwickSet := canonicalNameSet(inBailiwick)

	// An address record may only be ADDED at an in-bailiwick nameserver of the
	// resulting set: anything else is not glue.
	for _, rr := range actions {
		h := rr.Header()
		if h.Class != dns.ClassINET || (h.Rrtype != dns.TypeA && h.Rrtype != dns.TypeAAAA) {
			continue
		}
		name := dns.Fqdn(h.Name)
		if !dns.IsSubDomain(child, name) {
			continue // another delegation's business
		}
		if core.EqualNames(name, child) {
			return fmt.Errorf("%s at %s is not glue: address records at the delegation point itself belong to the child zone",
				dns.TypeToString[h.Rrtype], name)
		}
		if !inBailiwickSet[core.CanonicalizeName(name)] {
			return fmt.Errorf("%s at %s is not glue for %s: %s is not a nameserver of the resulting NS RRset",
				dns.TypeToString[h.Rrtype], name, child, name)
		}
	}

	// A nameserver the update removes must not leave its glue behind.
	for _, ns := range inBailiwickNSNames(child, currentNS) {
		if inBailiwickSet[core.CanonicalizeName(dns.Fqdn(ns))] {
			continue
		}
		for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
			cur, _ := currentGlue(ns, t)
			if left, _ := rrsetAfterActions(ns, t, cur, actions); len(left) > 0 {
				return fmt.Errorf("the update removes nameserver %s from %s but leaves its %s glue; delete the %s records at %s too",
					ns, child, dns.TypeToString[t], dns.TypeToString[t], ns)
			}
		}
	}

	if fetch == nil {
		return fmt.Errorf("cannot verify the delegation for %s: no way to ask its nameservers what they serve", child)
	}

	// The NS set must be what the child serves, as agreed by its nameservers.
	if nsChanged {
		served, inSync, err := fetch(ctx, child, dns.TypeNS)
		if err != nil {
			return fmt.Errorf("cannot verify the NS RRset for %s: %w", child, err)
		}
		if !inSync {
			return fmt.Errorf("the nameservers of %s do not agree on its NS RRset; retry once they are in sync", child)
		}
		if changed, extra, missing := core.RRsetDiffer(child, resultingNS, served, dns.TypeNS, discardLog, false, false); changed {
			return fmt.Errorf("the resulting NS RRset for %s is not what its nameservers serve: %d record(s) not served, %d served but absent; a scan would publish the served set",
				child, len(extra), len(missing))
		}
	}

	// Glue: for every in-bailiwick nameserver the update adds to the NS set,
	// and every one whose glue it touches, the resulting glue must be what the
	// child serves, per type.
	currentSet := canonicalNameSet(inBailiwickNSNames(child, currentNS))
	for _, ns := range inBailiwick {
		key := core.CanonicalizeName(dns.Fqdn(ns))
		if currentSet[key] && !glueTouched[key] {
			continue
		}
		for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
			cur, _ := currentGlue(ns, t)
			resulting, _ := rrsetAfterActions(ns, t, cur, actions)
			served, inSync, err := fetch(ctx, ns, t)
			if err != nil {
				return fmt.Errorf("cannot verify the %s glue for %s: %w", dns.TypeToString[t], ns, err)
			}
			if !inSync {
				return fmt.Errorf("the nameservers of %s do not agree on the %s records of %s; retry once they are in sync", child, dns.TypeToString[t], ns)
			}
			if changed, extra, missing := core.RRsetDiffer(ns, resulting, served, t, discardLog, false, false); changed {
				return fmt.Errorf("the resulting %s glue for %s is not what %s's nameservers serve: %d record(s) not served, %d served but absent",
					dns.TypeToString[t], ns, child, len(extra), len(missing))
			}
		}
	}
	return nil
}

// glueOwnersTouched returns the canonical owner names at or below child at
// which the update mentions an A or AAAA record, in any class (a type-ANY
// delete counts). The delegation point itself is included so that an address
// record added there reaches the rule that refuses it.
func glueOwnersTouched(child string, actions []dns.RR) map[string]bool {
	out := map[string]bool{}
	for _, rr := range actions {
		h := rr.Header()
		if h.Rrtype != dns.TypeA && h.Rrtype != dns.TypeAAAA && !(h.Class == dns.ClassANY && h.Rrtype == dns.TypeANY) {
			continue
		}
		name := dns.Fqdn(h.Name)
		if !dns.IsSubDomain(child, name) {
			continue
		}
		out[core.CanonicalizeName(name)] = true
	}
	return out
}
