/*
 * Copyright (c) Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"strings"

	"github.com/johanix/tdns/v2/edns0"
	"github.com/miekg/dns"
)

// evalUpdatePolicyRR decides whether one update policy permits one record to be
// changed by one principal. It is the whole of what an update policy means.
//
// Extracted from ApproveChildUpdate and ApproveAuthUpdate, which had two copies
// of it, and about to gain a third caller: the DSYNC API scheme
// (docs/2026-08-11-dsync-api-scheme.md §6.3) authenticates over HTTP Basic and
// then applies this same policy, substituting the authenticated principal for
// the SIG(0) signer name. Two transports enforcing subtly different policies
// from two copies of this logic is the failure this consolidation exists to
// prevent -- the second copy had already drifted to the point of using a
// different log prefix, which is harmless, but nothing structural stopped it
// drifting somewhere that mattered.
//
// principal is who is asking: the SIG(0) signer name on the DDNS path, the
// authenticated username on the API path. It is a domain name either way,
// which is what makes self/selfsub mean the same thing on both.
//
// Every update policy in tdns is enforced here -- child and zone, all
// transports. See nameWithinPrincipal below, which carries a security fix that
// therefore applies to all of them, not only to the API scheme this branch
// adds.
//
// label prefixes the log lines ("update", "auth update") and exists only so
// the messages read as they always have.
//
// Returns (approved, EDE). The EDE is 0 when approved.
func evalUpdatePolicyRR(policy UpdatePolicyDetail, principal string, rr dns.RR, label string) (bool, uint16) {
	owner := rr.Header().Name
	rrtype := rr.Header().Rrtype

	if !policy.RRtypes[rrtype] {
		lgHandler.Warn(label+" rejected: unapproved RR type", "rrtype", dns.TypeToString[rrtype])
		return false, edns0.EDEZoneUpdateRRtypeNotAllowed
	}

	switch policy.Type {
	case "selfsub":
		if !nameWithinPrincipal(principal, owner, true) {
			lgHandler.Warn(label+" rejected: owner name outside selfsub tree",
				"owner", owner, "principal", principal)
			return false, edns0.EDEZoneUpdateOwnerOutsidePolicy
		}

	case "self":
		if !nameWithinPrincipal(principal, owner, false) {
			lgHandler.Warn(label+" rejected: owner name differs from principal violating self policy",
				"owner", owner, "principal", principal)
			return false, edns0.EDEZoneUpdateOwnerOutsidePolicy
		}

	default:
		// "none", "" and anything unrecognised. Both former copies landed
		// here with the same EDE: the child one via its default case, the
		// zone one via an explicit "none" case plus a default that did the
		// same thing.
		lgHandler.Warn(label+" rejected: policy type disallows all updates", "policyType", policy.Type)
		return false, edns0.EDEZoneUpdatesNotAllowed
	}

	switch rr.Header().Class {
	case dns.ClassNONE:
		lgHandler.Debug("remove RR", "rr", rr.String())
	case dns.ClassANY:
		lgHandler.Debug("remove RRset", "rr", rr.String())
	default:
		lgHandler.Debug("add RR", "rr", rr.String())
	}

	return true, 0
}

// nameWithinPrincipal answers whether owner is inside the principal's tree
// (sub=true, the selfsub policy) or is the principal itself (sub=false, self).
//
// SCOPE, because this arrived on the DSYNC-API branch and is not about the
// DSYNC API: this function decides self/selfsub for EVERY update policy tdns
// has. updatepolicy.child and updatepolicy.zone, on every transport --
// RFC 2136 UPDATE over SIG(0) as it works today, the API scheme once it
// exists. A zone with a self or selfsub policy was affected whether or not it
// ever enables the API scheme, and whether or not it is a delegation parent.
// The fix rode along in this branch only because extracting the evaluator is
// what made the bug visible; nothing about it is specific to the new scheme.
//
// Both are comparisons of DNS names, which means label-aligned and
// case-insensitive. That has to be done deliberately, because doing it with
// string operations very nearly works and is wrong in both directions:
//
//	strings.HasSuffix("evilchild1.example.", "child1.example.") == true
//	"CHILD1.example." != "child1.example."
//
// The first grants the holder of child1.example.'s key authority over a
// differently-named sibling delegation. The second refuses a legitimate update
// over letter case, in a protocol where case carries no meaning.
func nameWithinPrincipal(principal, owner string, sub bool) bool {
	p := strings.TrimSpace(principal)
	o := strings.TrimSpace(owner)
	if p == "" || o == "" {
		return false
	}
	p = dns.CanonicalName(dns.Fqdn(p))
	o = dns.CanonicalName(dns.Fqdn(o))

	// The root as a principal would put every name inside its tree. Nothing
	// legitimate sets that, so it is refused rather than honoured.
	if p == "." {
		return false
	}
	if sub {
		return dns.IsSubDomain(p, o)
	}
	return p == o
}

// ApproveActionsForPrincipal runs a set of records past a policy on behalf of a
// principal, stopping at the first refusal.
//
// It does NOT confine owner names to zd.ZoneName. The receiver is carried for
// call-site symmetry and for the error context, and this method evaluates only
// the policy it is handed against the actions it is handed. Bailiwick is the
// caller's job -- dsyncApiBuildActions rejects owners outside the child before
// it gets here -- so a future caller that skips that step gets no zone
// confinement from this method, whatever the receiver suggests.
//
// This is the entry point for callers that have no DNS message and no SIG(0)
// status to consult -- the DSYNC API handler. The DDNS path does not use it:
// it has per-record validation state of its own to interleave, and calls
// evalUpdatePolicyRR directly so the order in which reasons are reported does
// not change.
func (zd *ZoneData) ApproveActionsForPrincipal(policy UpdatePolicyDetail, principal string, actions []dns.RR, label string) (bool, uint16) {
	if strings.TrimSpace(principal) == "" {
		lgHandler.Warn(label + " rejected: no principal")
		return false, edns0.EDEZoneUpdatesNotAllowed
	}
	for _, rr := range actions {
		if ok, ede := evalUpdatePolicyRR(policy, principal, rr, label); !ok {
			return false, ede
		}
	}
	return true, 0
}
