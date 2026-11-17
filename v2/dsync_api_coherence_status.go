/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"errors"
	"net/http"
)

// errNoDnskeyFetcher is the coherence check's "this server has no way to look
// the child's DNSKEYs up at all": no resolver, by configuration. Unlike every
// other way the check can fail to run, asking again changes nothing.
var errNoDnskeyFetcher = errors.New("no way to look up its DNSKEYs")

// errParentDSUnreadable is the other permanent one: the parent's zone store
// holds no owner index, so it cannot read the DS it publishes for the child,
// and never will. A parent that is merely not Ready yet will, and is retryable.
var errParentDSUnreadable = errors.New("the zone store cannot be read by owner name")

// dsyncApiCoherenceStatus is the HTTP status for a DS change the coherence
// check refused.
//
// The two refusals mean opposite things to a client, and the UPDATE path
// already tells them apart with its EDE (delegationCoherenceEDE):
//
//   - incoherent: the check ran and the resulting DS set would not validate.
//     That is the child's to fix; 409.
//   - unverifiable: the check could not run -- the child's DNSKEY lookup
//     failed, typically because a zone that has just started is not yet at its
//     nameservers, or this server's resolver has not come up. That says nothing
//     about the update and is exactly what a retry fixes; 503, which is what
//     §7.3 gives to a parent that cannot serve the request right now, and what
//     a DSYNC API client already classifies as transient.
//
// Both used to be 409, so a child's first DS after a cold start was refused
// with the status a client reads as final.
//
// The exceptions are a server with no resolver at all, and a parent whose zone
// store cannot be read by owner name: unverifiable, but for good, so they stay
// 409 rather than inviting retries that cannot succeed.
func dsyncApiCoherenceStatus(cerr error) int {
	if errors.Is(cerr, ErrDelegationUnverifiable) &&
		!errors.Is(cerr, errNoDnskeyFetcher) && !errors.Is(cerr, errParentDSUnreadable) {
		return http.StatusServiceUnavailable
	}
	return http.StatusConflict
}
