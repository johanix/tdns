/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package core

import (
	"github.com/miekg/dns"
)

type RRset struct {
	Name   string
	Class  uint16
	RRtype uint16
	RRs    []dns.RR
	RRSIGs []dns.RR

	// UnclampedTTL is the operator-configured TTL captured the first
	// time SignRRset clamps this RRset under K-step rollover clamping
	// (§5.2 of the automated KSK rollover design). Sentinel 0 means
	// "never clamped." Reset only on whole-RRset replacement (inbound
	// zone transfer / zone reload), which naturally zeroes the field.
	UnclampedTTL uint32 `json:"-"`
}

// String-based versions of RRset for JSON marshaling
type RRsetString struct {
	Name   string   `json:"name"`
	RRtype uint16   `json:"rrtype"`
	RRs    []string `json:"rrs"`
	RRSIGs []string `json:"rrsigs,omitempty"`
}
