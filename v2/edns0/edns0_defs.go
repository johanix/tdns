/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package edns0

// Local EDNS(0) options that are defined in TDNS.
//
// EVERY tdns-local option code MUST be declared here and nowhere else. Codes
// declared next to their implementation drift into collisions that the compiler
// cannot see: PROVIDERSYNC was defined as 65002 in edns0_providersync.go while
// KEYSTATE held the same 65002 here, so a ProviderSync option would have been
// parsed as a KeyState option (both are dns.EDNS0_LOCAL, dispatched purely on
// Code). Keep them adjacent so the next addition is an obvious next number, and
// see TestLocalOptionCodesAreUnique.
const (
	EDNS0_OOTS_OPTION_CODE          = 65001 // experimental OOTS EDNS option (-03; IANA TBD)
	EDNS0_KEYSTATE_OPTION_CODE      = 65002
	EDNS0_REPORT_OPTION_CODE        = 65003
	EDNS0_CHUNK_OPTION_CODE         = 65004 // CHUNK EDNS(0) option for payload
	EDNS0_CHUNK_QUERY_ENDPOINT_CODE = 65005 // CHUNK query endpoint: where receiver should send CHUNK query (host:port)
	EDNS0_PROVIDERSYNC_OPTION_CODE  = 65006 // provider-synchronization option (moved off 65002, which KEYSTATE holds)
)

// Standard EDNS(0) option codes (RFC9567)
const (
	EDNS0_ER_OPTION_CODE = 18 // RFC9567: DNS Error Reporting option code
)
