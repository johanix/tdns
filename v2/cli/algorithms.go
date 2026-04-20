/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import "strings"

// SupportedSig0Algorithms lists the DNSSEC algorithm names tdns
// accepts for SIG(0) key generation and transaction signing.
var SupportedSig0Algorithms = []string{
	"RSASHA256",
	"RSASHA512",
	"ECDSAP256SHA256",
	"ECDSAP384SHA384",
	"ED25519",
	"MLDSA44",
}

// SupportedDnssecAlgorithms lists the DNSSEC algorithm names tdns
// accepts for zone signing (RRSIG). MLDSA44 is deliberately omitted:
// it is supported only for SIG(0) transaction signatures, not zone
// signing.
var SupportedDnssecAlgorithms = []string{
	"RSASHA256",
	"RSASHA512",
	"ECDSAP256SHA256",
	"ECDSAP384SHA384",
	"ED25519",
}

func sig0AlgorithmsHelp(prefix string) string {
	return prefix + ". Supported: " + strings.Join(SupportedSig0Algorithms, ", ")
}

func dnssecAlgorithmsHelp(prefix string) string {
	return prefix + ". Supported: " + strings.Join(SupportedDnssecAlgorithms, ", ")
}
