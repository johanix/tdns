/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package cache

import (
	"strings"

	core "github.com/johanix/tdns/v2/core"
)

// The validation state of a transport signal: the state of each RRset it was
// read from, on every path a signal arrives by (the Additional section of a
// referral, of the server's own response, and a direct lookup of _dns.<ns>).
// docs/2026-11-14-transport-signal-alternative-endpoint.md, section 4, gives
// the rules (R1-R5). Nothing acts on the state yet: every record a resolver
// honours has TargetName ".", which needs no validation (R4). It is recorded,
// logged and shown, so that the step that honours a TargetName has it.

// SignalStateUnknown is the zero ValidationState: the RRset's state was not
// decided where it was read, because no RRSIG came with it or the keys were
// not at hand. It stays unknown until the verifying lookup. It is not in
// ValidationStateToString; SignalStateString names it.
const SignalStateUnknown ValidationState = 0

// Where a transport signal arrived. ReceivedSignal.Via holds one of them.
const (
	SignalViaReferral = "referral" // a parent's referral, for the child's nameserver
	SignalViaResponse = "response" // the Additional section of the server's own response
	SignalViaLookup   = "lookup"   // the answer to a lookup of _dns.<ns>
)

// SignalHop is one RRset on the path a transport signal was read from, and
// its validation state.
type SignalHop struct {
	Owner string
	State ValidationState // Secure, Insecure, Bogus or SignalStateUnknown
}

// SignalState is s as a signal records it: Secure, Insecure and Bogus as they
// are, anything else unknown. None and Indeterminate say only that no verdict
// was reached.
func SignalState(s ValidationState) ValidationState {
	switch s {
	case ValidationStateSecure, ValidationStateInsecure, ValidationStateBogus:
		return s
	}
	return SignalStateUnknown
}

// SignalStateString names a signal's state, "unknown" included.
func SignalStateString(s ValidationState) string {
	if s = SignalState(s); s == SignalStateUnknown {
		return "unknown"
	}
	return ValidationStateToString[s]
}

// SignalPathState is the state of a whole path, which a target needs to be
// Secure (R5): Secure only when every hop is. Otherwise Bogus when a hop is,
// then Insecure, which no later lookup turns Secure, then unknown. An empty
// path is unknown.
func SignalPathState(path []SignalHop) ValidationState {
	if len(path) == 0 {
		return SignalStateUnknown
	}
	var bogus, insecure, unknown bool
	for _, hop := range path {
		switch SignalState(hop.State) {
		case ValidationStateBogus:
			bogus = true
		case ValidationStateInsecure:
			insecure = true
		case SignalStateUnknown:
			unknown = true
		}
	}
	switch {
	case bogus:
		return ValidationStateBogus
	case insecure:
		return ValidationStateInsecure
	case unknown:
		return SignalStateUnknown
	}
	return ValidationStateSecure
}

// FormatSignalPath renders a path as "owner state -> owner state". Empty for
// an empty path.
func FormatSignalPath(path []SignalHop) string {
	parts := make([]string, 0, len(path))
	for _, hop := range path {
		parts = append(parts, hop.Owner+" "+SignalStateString(hop.State))
	}
	return strings.Join(parts, " -> ")
}

// SignalRRsetState decides in place the validation state of a transport-signal
// RRset read from an Additional section: with the RRSIGs that came with it and
// the keys the cache already holds. Nothing is fetched, so it is cheap enough
// for every response that carries a signal. A verdict the cache holds for the
// same RRs and RRSIGs is reused.
//
// Without an RRSIG, or when the signer's keys are not at hand, the state is
// SignalStateUnknown until the verifying lookup. So is an RRset synthesized
// from a wildcard, whose proof the lookup judges. Once the lookup has run, an
// RRset equal to the copy it validated is Secure, RRSIG or not: an equal
// harvest is the copy that was validated (equalToSecureCopy). rrset is
// validated as given; pass a copy, since a verdict caps the RRs' TTLs at the
// signature expiration.
func (rrcache *RRsetCacheT) SignalRRsetState(rrset *core.RRset) ValidationState {
	if rrcache == nil || rrset == nil || len(rrset.RRs) == 0 {
		return SignalStateUnknown
	}
	state := rrcache.signalRRsetVerdict(rrset)
	if state == SignalStateUnknown && rrcache.equalToSecureCopy(rrset) {
		return ValidationStateSecure
	}
	return state
}

// signalRRsetVerdict is SignalRRsetState from rrset's own RRSIGs alone.
func (rrcache *RRsetCacheT) signalRRsetVerdict(rrset *core.RRset) ValidationState {
	if len(rrset.RRSIGs) == 0 || hasExpansionSignature(rrset) {
		return SignalStateUnknown
	}
	if state, ok := rrcache.reusableVerdict(rrset); ok {
		return SignalState(state)
	}
	// No context and no fetcher: validateRRsetWithRRSIG then neither rechecks
	// an insecure zone nor fetches a missing DNSKEY. A missing key is a chain
	// gap, Indeterminate, which is unknown here.
	//lint:ignore SA1012 a nil context is what keeps validateRRsetWithRRSIG from fetching
	state, _, err := rrcache.validateSignatures(nil, rrset, rrset.RRSIGs, rrcache.DnskeyCache, nil)
	if err != nil {
		return SignalStateUnknown
	}
	return SignalState(state)
}

// equalToSecureCopy reports whether the cache holds a live Secure copy of
// rrset: the same owner, type and RRs, whatever RRSIGs came with either. A
// replay of that RRset carries nothing the validated copy did not.
func (rrcache *RRsetCacheT) equalToSecureCopy(rrset *core.RRset) bool {
	cached := rrcache.Get(rrset.Name, rrset.RRtype)
	if cached == nil || cached.State != ValidationStateSecure || cached.RRset == nil || len(cached.RRset.RRs) == 0 {
		return false
	}
	differ, _, _ := cached.RRset.RRsetDiffer(rrset, rrcache.DebugLog(), false, false)
	return !differ
}
