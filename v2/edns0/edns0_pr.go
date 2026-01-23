/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package edns0

import (
	"fmt"

	"github.com/miekg/dns"
)

// PR (Privacy Requested) flag bit - bit 13 in OPT header TTL
const (
	EDNS0_PR_FLAG_BIT = 13 // Privacy Requested flag bit position
)

// SetPRFlag sets the PR (Privacy Requested) flag in an OPT RR
func SetPRFlag(opt *dns.OPT) error {
	if opt == nil {
		return fmt.Errorf("OPT RR is nil")
	}
	opt.Hdr.Ttl |= (1 << EDNS0_PR_FLAG_BIT)
	return nil
}

// ClearPRFlag clears the PR (Privacy Requested) flag in an OPT RR
func ClearPRFlag(opt *dns.OPT) {
	if opt == nil {
		return
	}
	opt.Hdr.Ttl &^= (1 << EDNS0_PR_FLAG_BIT)
}

// HasPRFlag checks if the PR (Privacy Requested) flag is set in an OPT RR
func HasPRFlag(opt *dns.OPT) bool {
	if opt == nil {
		return false
	}
	return (opt.Hdr.Ttl & (1 << EDNS0_PR_FLAG_BIT)) != 0
}

// SetPRFlagInMessage sets the PR flag in a DNS message's OPT RR (creates OPT if needed)
func SetPRFlagInMessage(msg *dns.Msg) error {
	if msg == nil {
		return fmt.Errorf("message is nil")
	}
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(4096, false)
		opt = msg.IsEdns0()
	}
	return SetPRFlag(opt)
}
