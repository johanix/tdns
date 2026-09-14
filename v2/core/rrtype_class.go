/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package core

import "github.com/miekg/dns"

// IsMetaType reports whether t is a Q-TYPE or Meta-TYPE (RFC 6895 section
// 3.1): OPT, and 128-255, which holds NXNAME, TKEY, TSIG, IXFR, AXFR, MAILB,
// MAILA and ANY. No zone holds an RRset of such a type.
func IsMetaType(t uint16) bool {
	return t == dns.TypeOPT || (t >= 128 && t <= 255)
}

// IsReservedType reports whether t lies in a range RFC 6895 section 3.1
// reserves: 0, 61440-65279 and 65535.
func IsReservedType(t uint16) bool {
	return t == 0 || (t >= 61440 && t <= 65279) || t == 65535
}
