/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import "strings"

// SupportedSig0Algorithms lists the DNSSEC algorithm names tdns
// accepts for SIG(0) key generation and transaction signing.
//
// The PQ entries assume the corresponding dnssec-algorithms/<alg>
// subpackage is blank-imported by the binary (agentv2, authv2,
// imrv2 do so; cliv2 does not, but it forwards key generation to
// other tdns binaries via the API). The full set is listed here
// regardless of which binary loaded this file, since the help text
// is informational about what the deployment as a whole can do.
var SupportedSig0Algorithms = []string{
	"RSASHA256",
	"RSASHA512",
	"ECDSAP256SHA256",
	"ECDSAP384SHA384",
	"ED25519",
	"MLDSA44",
	"SLHDSA128S",
	"FALCON512",
	"MAYO1",
	"SNOVA24_5_4",
}

// SupportedDnssecAlgorithms lists the DNSSEC algorithm names tdns
// accepts for zone signing (RRSIG). The PQ algorithms are
// deliberately omitted: their signature sizes (2.4 kB to 7.8 kB)
// make routine zone signing operationally unattractive, and the
// primary use case in this repo is SIG(0) transaction signing
// rather than RRSIG.
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
