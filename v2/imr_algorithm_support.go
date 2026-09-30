/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	algorithms "github.com/johanix/tdns/v2/algorithms"
	cache "github.com/johanix/tdns/v2/cache"
	"github.com/miekg/dns"
)

// The validator treats a delegation whose DS RRset names no algorithm the
// resolver can verify as insecure (cache/ds_usable.go). This is the answer it
// asks, installed for every binary and test that has the resolver. An
// algorithm an application registers later (algs.list) counts from then on.
func init() {
	cache.SetAlgorithmSupported(dnssecAlgorithmVerifiable)
}

// dnssecAlgorithmVerifiable reports whether the resolver can verify signatures
// made with algorithm alg: one with a real implementation in the algorithms
// registry, or RSASHA1 or RSASHA1-NSEC3-SHA1. The registry leaves those two
// out because tdns does not sign with them (RFC 9905 retires both for
// signing); the dns library verifies them itself, and the resolver still
// validates them. RFC 9905 also asks resolver operators to treat them as
// unsupported. Whether to do so is a decision of its own.
func dnssecAlgorithmVerifiable(alg uint8) bool {
	switch alg {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1:
		return true
	}
	_, real := algorithms.CapsReal(alg)
	return real
}
