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
}

// String-based versions of RRset for JSON marshaling
type RRsetString struct {
	Name   string   `json:"name"`
	RRtype uint16   `json:"rrtype"`
	RRs    []string `json:"rrs"`
	RRSIGs []string `json:"rrsigs,omitempty"`
}
