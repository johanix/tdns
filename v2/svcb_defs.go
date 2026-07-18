/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

// Private-use SVCB key codes for TDNS.
// RFC 9460 reserves 65280–65534 for local assignments.
// Transport signaling uses the registered oots key (dns.SVCB_OOTS = 12).
const (
	SvcbTLSAKey      uint16 = 65281
	SvcbBootstrapKey uint16 = 65282 // "bootstrap" SvcParamKey per draft-ietf-dnsop-delegation-mgmt-via-ddns-01
)
