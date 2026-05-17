/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cache

import (
	"fmt"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// RecordZoneAddressFailureForRcode records a zone-specific failure for the
// given (address, transport) tuple based on a DNS response code.
// REFUSED / NOTAUTH / SERVFAIL signal lame delegation and get the policy's
// LameDelegation backoff. NOTIMP is kept at a longer fixed 6h since it
// indicates the server speaks DNS but lacks features we need. Other rcodes
// follow the standard exponential schedule. Thread-safe.
func (z *Zone) RecordZoneAddressFailureForRcode(addr string, t core.Transport, rcode uint8, debug bool) {
	if z == nil {
		return
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.AddressBackoffs == nil {
		z.AddressBackoffs = make(map[AddrXport]*AddressBackoff)
	}
	key := AddrXport{Addr: addr, Transport: t}
	backoff, exists := z.AddressBackoffs[key]

	var backoffDuration time.Duration
	var errMsg string
	switch rcode {
	case dns.RcodeRefused, dns.RcodeNotAuth, dns.RcodeServerFailure:
		backoffDuration = applyJitter(GetBackoffPolicy().LameDelegation)
		if debug {
			errMsg = fmt.Sprintf("rcode=%d: lame delegation", rcode)
		}
	case dns.RcodeNotImplemented:
		backoffDuration = 6 * time.Hour
		if debug {
			errMsg = "rcode=NOTIMP; backoff=6h"
		}
	default:
		var count uint8
		if exists {
			count = backoff.FailureCount
		}
		backoffDuration = applyJitter(exponentialBackoff(count))
		if debug {
			errMsg = fmt.Sprintf("rcode=%d", rcode)
		}
	}

	if !exists {
		z.AddressBackoffs[key] = &AddressBackoff{
			NextTry:      time.Now().Add(backoffDuration),
			FailureCount: 1,
			LastError:    errMsg,
		}
		return
	}
	backoff.NextTry = time.Now().Add(backoffDuration)
	if debug {
		backoff.LastError = errMsg
	}
	if backoff.FailureCount < 255 {
		backoff.FailureCount++
	}
}

// IsZoneAddrXportAvailable returns true if the (address, transport) tuple is
// not in zone-specific backoff (or its backoff has expired). Thread-safe.
func (z *Zone) IsZoneAddrXportAvailable(addr string, t core.Transport) bool {
	if z == nil {
		return true // No zone-specific restrictions
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.AddressBackoffs == nil {
		return true
	}
	backoff, exists := z.AddressBackoffs[AddrXport{Addr: addr, Transport: t}]
	if !exists {
		return true
	}
	return time.Now().After(backoff.NextTry)
}

// SnapshotAddressBackoffs returns a copy of the zone's (address, transport)
// backoff map containing only entries whose NextTry is still in the future.
// Mirrors AuthServer.SnapshotAddressBackoffs. Thread-safe.
func (z *Zone) SnapshotAddressBackoffs(now time.Time) map[AddrXport]*AddressBackoff {
	if z == nil {
		return nil
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	if len(z.AddressBackoffs) == 0 {
		return nil
	}
	snap := make(map[AddrXport]*AddressBackoff)
	for key, backoff := range z.AddressBackoffs {
		if backoff.NextTry.After(now) {
			snap[key] = &AddressBackoff{
				NextTry:      backoff.NextTry,
				FailureCount: backoff.FailureCount,
				LastError:    backoff.LastError,
			}
		}
	}
	if len(snap) == 0 {
		return nil
	}
	return snap
}

// RecordZoneAddressSuccess clears any zone-specific backoff for the given
// (address, transport) tuple. Thread-safe.
func (z *Zone) RecordZoneAddressSuccess(addr string, t core.Transport) {
	if z == nil {
		return
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.AddressBackoffs != nil {
		delete(z.AddressBackoffs, AddrXport{Addr: addr, Transport: t})
	}
}
