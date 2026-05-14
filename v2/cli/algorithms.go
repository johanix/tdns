/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"slices"
	"strings"
)

// isKnownAlgorithm reports whether name (already upper-cased)
// matches an algorithm tdns accepts on the CLI. Checked against
// the union of SupportedSig0Algorithms and SupportedDnssecAlgorithms.
//
// Decoupled from dns.StringToAlgorithm so cliv2 — which deliberately
// does not blank-import the PQ algorithm subpackages from
// dnssec-algorithms — can still validate PQ algorithm names that
// the server-side binaries (agentv2/authv2/imrv2) accept.
func isKnownAlgorithm(name string) bool {
	return slices.Contains(SupportedSig0Algorithms, name) ||
		slices.Contains(SupportedDnssecAlgorithms, name)
}

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
// accepts for zone signing (RRSIG). PQ algorithms are listed for
// experimental use; their signature sizes (250 B for SNOVA up to
// 7.8 kB for SLH-DSA-128s) range from "works in DNS UDP responses"
// to "TCP-only territory" and routine zone signing with the larger
// ones is operationally awkward.
var SupportedDnssecAlgorithms = []string{
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

func sig0AlgorithmsHelp(prefix string) string {
	return prefix + ". Supported: " + strings.Join(SupportedSig0Algorithms, ", ")
}

func dnssecAlgorithmsHelp(prefix string) string {
	return prefix + ". Supported: " + strings.Join(SupportedDnssecAlgorithms, ", ")
}
