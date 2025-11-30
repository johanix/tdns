/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package edns0

// Local EDNS(0) options that are defined in TDNS
const (
	EDNS0_OTS_OPTION_CODE      = 65001 // TBD: Replace with actual IANA assigned code
	EDNS0_KEYSTATE_OPTION_CODE = 65002
	EDNS0_REPORT_OPTION_CODE   = 65003
)

// Standard EDNS(0) option codes (RFC9567)
const (
	EDNS0_ER_OPTION_CODE = 18 // RFC9567: DNS Error Reporting option code
)
