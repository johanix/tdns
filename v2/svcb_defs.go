/*
 * Copyright (c) 2025 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

// Private-use SVCB key codes for TDNS.
// RFC 9460 reserves 65280–65534 for local assignments.
const (
	SvcbTransportKey uint16 = 65280
	SvcbTLSAKey      uint16 = 65281
	SvcbBootstrapKey uint16 = 65282 // "bootstrap" SvcParamKey per draft-ietf-dnsop-delegation-mgmt-via-ddns-01
)
