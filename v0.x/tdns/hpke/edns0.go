/*
 * Copyright (c) 2025 Johan Stenstam, johani@johani.org
 *
 * EDNS(0) option for HPKE ephemeral public key exchange
 */

package hpke

import (
	"fmt"

	"github.com/miekg/dns"
)

// EDNS0 option code for HPKE ephemeral public key
// TBD: Replace with actual IANA assigned code
const (
	EDNS0_HPKE_EPHEMERAL_OPTION_CODE = 65010
)

// EphemeralPublicKeyOption represents an EDNS(0) option containing an HPKE ephemeral public key
type EphemeralPublicKeyOption struct {
	PublicKey []byte // X25519 public key (32 bytes)
}

// AddHPKEEphemeralOption adds an HPKE ephemeral public key EDNS(0) option to an existing OPT RR
func AddHPKEEphemeralOption(opt *dns.OPT, pubKey []byte) error {
	if opt == nil {
		return fmt.Errorf("OPT RR is nil")
	}

	if len(pubKey) != 32 {
		return fmt.Errorf("HPKE ephemeral public key must be 32 bytes (got %d)", len(pubKey))
	}

	// Create the EDNS0 option
	option := &dns.EDNS0_LOCAL{
		Code: EDNS0_HPKE_EPHEMERAL_OPTION_CODE,
		Data: pubKey,
	}

	// Add the option to the OPT RR
	opt.Option = append(opt.Option, option)

	return nil
}

// ExtractHPKEEphemeralOption extracts the HPKE ephemeral public key EDNS(0) option from an OPT RR
// Returns the public key and true if found, or nil and false if not found
func ExtractHPKEEphemeralOption(opt *dns.OPT) ([]byte, bool) {
	if opt == nil {
		return nil, false
	}

	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_HPKE_EPHEMERAL_OPTION_CODE {
				if len(localOpt.Data) == 32 {
					// Return a copy
					pubKey := make([]byte, 32)
					copy(pubKey, localOpt.Data)
					return pubKey, true
				}
			}
		}
	}

	return nil, false
}

// HasHPKEEphemeralOption checks if an OPT RR contains an HPKE ephemeral public key option
func HasHPKEEphemeralOption(opt *dns.OPT) bool {
	_, found := ExtractHPKEEphemeralOption(opt)
	return found
}

// RemoveHPKEEphemeralOption removes the HPKE ephemeral public key EDNS(0) option from an OPT RR
func RemoveHPKEEphemeralOption(opt *dns.OPT) {
	if opt == nil {
		return
	}

	var newOptions []dns.EDNS0
	for _, option := range opt.Option {
		if localOpt, ok := option.(*dns.EDNS0_LOCAL); ok {
			if localOpt.Code == EDNS0_HPKE_EPHEMERAL_OPTION_CODE {
				continue // Skip this option
			}
		}
		newOptions = append(newOptions, option)
	}

	opt.Option = newOptions
}
