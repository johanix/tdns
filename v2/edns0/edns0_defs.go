/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package edns0

// Local EDNS(0) options that are defined in TDNS.
//
// EVERY local option code belongs in this block, and nowhere else. The one that
// was declared in its own file -- PROVIDERSYNC, formerly in
// edns0_providersync.go -- ended up sharing 65002 with KEYSTATE, because
// nothing adding to this table could see it. Two options with one code are
// indistinguishable on the wire: a receiver reads whichever it happens to look
// for and parses the other one's payload as though it were its own.
//
// TestLocalOptionCodesAreUnique enforces the property; keeping the declarations
// together is what lets it.
const (
	EDNS0_OOTS_OPTION_CODE          = 65001 // experimental OOTS EDNS option (-03; IANA TBD)
	EDNS0_KEYSTATE_OPTION_CODE      = 65002
	EDNS0_REPORT_OPTION_CODE        = 65003
	EDNS0_CHUNK_OPTION_CODE         = 65004 // CHUNK EDNS(0) option for payload
	EDNS0_CHUNK_QUERY_ENDPOINT_CODE = 65005 // CHUNK query endpoint: where receiver should send CHUNK query (host:port)
	EDNS0_PROVIDERSYNC_OPTION_CODE  = 65006 // provider synchronisation; IANA TBD (moved off 65002, which KEYSTATE holds)
	EDNS0_PRIVACY_OPTION_CODE       = 65007 // privacy request/status, one octet; replaces the former PR flag bit

	// localOptionCodeFirst / localOptionCodeLast bound the private-use range
	// these are drawn from (RFC 6891 §9). Anything outside it is squatting on
	// space IANA may hand to someone else.
	localOptionCodeFirst = 65001
	localOptionCodeLast  = 65534
)

// Standard EDNS(0) option codes (RFC9567)
const (
	EDNS0_ER_OPTION_CODE = 18 // RFC9567: DNS Error Reporting option code
)
