/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"strings"

	algregistry "github.com/johanix/tdns/v2/algorithms"
)

// isKnownAlgorithm reports whether name (already upper-cased)
// matches an algorithm registered with the tdns/v2/algorithms
// runtime registry. Used by the CLI's --algorithm argument
// validator.
func isKnownAlgorithm(name string) bool {
	_, ok := algregistry.AlgorithmNumber(name)
	return ok
}

// AlgorithmNumber returns the DNSSEC algorithm number for name and
// true if registered, or 0 and false otherwise. The caller is
// expected to upper-case the input.
func AlgorithmNumber(name string) (uint8, bool) {
	return algregistry.AlgorithmNumber(name)
}

// MustAlgorithmNumber is the AlgorithmNumber variant for call sites
// that have already validated name (typically via prepargs's
// "algorithm" stage). Returns 0 for unknown names.
func MustAlgorithmNumber(name string) uint8 {
	num, _ := algregistry.AlgorithmNumber(name)
	return num
}

func sig0AlgorithmsHelp(prefix string) string {
	return prefix + ". Supported: " + strings.Join(algregistry.SupportedSIG0(), ", ")
}

func dnssecAlgorithmsHelp(prefix string) string {
	return prefix + ". Supported: " + strings.Join(algregistry.SupportedDNSSEC(), ", ")
}
