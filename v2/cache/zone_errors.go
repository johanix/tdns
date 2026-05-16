/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cache

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// RecordZoneAddressFailureForRcode records a zone-specific failure
// for the given address based on a DNS response code. REFUSED /
// NOTAUTH / SERVFAIL signal lame delegation and get the policy's
// LameDelegation backoff. NOTIMP is kept at a longer fixed 6h since
// it indicates the server speaks DNS but lacks features we need.
// Other rcodes follow the standard exponential schedule.
// Thread-safe: acquires mu lock.
func (z *Zone) RecordZoneAddressFailureForRcode(addr string, rcode uint8, debug bool) {
	if z == nil {
		return
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.AddressBackoffs == nil {
		z.AddressBackoffs = make(map[string]*AddressBackoff)
	}
	backoff, exists := z.AddressBackoffs[addr]

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
		z.AddressBackoffs[addr] = &AddressBackoff{
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

// IsZoneAddressAvailable returns true if the given address is not in zone-specific backoff or backoff has expired.
// Thread-safe: acquires mu lock.
func (z *Zone) IsZoneAddressAvailable(addr string) bool {
	if z == nil {
		return true // No zone-specific restrictions
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.AddressBackoffs == nil {
		return true // No backoffs recorded, address is available
	}
	backoff, exists := z.AddressBackoffs[addr]
	if !exists {
		return true // No backoff for this address
	}
	// Check if backoff has expired
	return time.Now().After(backoff.NextTry)
}

// RecordZoneAddressSuccess clears any zone-specific backoff for the given address.
// Thread-safe: acquires mu lock.
func (z *Zone) RecordZoneAddressSuccess(addr string) {
	if z == nil {
		return
	}
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.AddressBackoffs != nil {
		delete(z.AddressBackoffs, addr)
		// If map is empty, we could nil it out, but keeping it is fine for efficiency
	}
}
