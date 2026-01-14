/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package cache

import (
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// RecordZoneAddressFailureForRcode records a zone-specific failure for the given address based on a DNS response code.
// REFUSED/NOTAUTH/NOTIMP responses (lame delegations) get 1 hour backoff immediately as they're unlikely to resolve soon.
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

	// Determine backoff duration based on rcode
	var backoffDuration time.Duration
	var errMsg string
	switch rcode {
	case dns.RcodeRefused, dns.RcodeNotAuth: // lame delegation
		backoffDuration = 1 * time.Hour
		if debug {
			errMsg = fmt.Sprintf("rcode=%d: lame delegation; backoff=1h", rcode)
		}
	case dns.RcodeServerFailure:
		// SERVFAIL might be temporary, but for zone-specific failures, treat as persistent
		backoffDuration = 1 * time.Hour
		if debug {
			errMsg = fmt.Sprintf("rcode=SERVFAIL; backoff=1h")
		}
	case dns.RcodeNotImplemented:
		backoffDuration = 6 * time.Hour
		if debug {
			errMsg = fmt.Sprintf("rcode=NOTIMP; backoff=6h")
		}
	default:
		// For other rcodes, use default behavior (2 min first, 1 hour subsequent)
		if !exists {
			backoffDuration = 2 * time.Minute
		} else {
			backoffDuration = 1 * time.Hour
		}
		if debug {
			errMsg = fmt.Sprintf("rcode=%d", rcode)
		}
	}

	if !exists {
		// First failure
		z.AddressBackoffs[addr] = &AddressBackoff{
			NextTry:      time.Now().Add(backoffDuration),
			FailureCount: 1,
			LastError:    errMsg,
		}
		return
	}
	// Subsequent failure
	backoff.NextTry = time.Now().Add(backoffDuration)
	if debug {
		backoff.LastError = errMsg
	}
	if backoff.FailureCount < 255 { // Prevent overflow
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
