/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"sync/atomic"

	"github.com/miekg/dns"
)

// A DS the resolver can use names an algorithm it can verify signatures with,
// and a digest type it can compute. RFC 4035 section 5.2: when no DS in an
// authenticated DS RRset is one the resolver supports, there is no supported
// authentication path from the parent to the child, and the child is treated
// as if the parent had proven it has no DS -- insecure. A DS with a digest type
// the resolver cannot compute counts the same (RFC 6840 section 5.2).
//
// The DS RRsets this applies to are the parent's. A trust anchor is the
// operator's, and one that matches no key stays an error.

// algorithmSupported answers whether the resolver can verify signatures made
// with an algorithm. The cache does not know the algorithms registry; the
// resolver installs the answer (SetAlgorithmSupported). Without one, every
// algorithm counts as supported.
var algorithmSupported atomic.Pointer[func(alg uint8) bool]

// SetAlgorithmSupported installs the answer to "can signatures made with
// algorithm alg be verified". nil removes it.
func SetAlgorithmSupported(f func(alg uint8) bool) {
	if f == nil {
		algorithmSupported.Store(nil)
		return
	}
	algorithmSupported.Store(&f)
}

// AlgorithmSupported reports whether signatures made with alg can be verified.
func AlgorithmSupported(alg uint8) bool {
	if f := algorithmSupported.Load(); f != nil {
		return (*f)(alg)
	}
	return true
}

// DSUsable reports whether ds names an algorithm the resolver can verify and a
// digest type it can compute. The chain walk (dog +sigchase) asks it too, so
// that it treats a DS RRset as the resolver does.
func DSUsable(ds *dns.DS) bool {
	switch ds.DigestType {
	case dns.SHA1, dns.SHA256, dns.SHA384:
	default:
		return false
	}
	return AlgorithmSupported(ds.Algorithm)
}

// dsUsable is DSUsable, under the name the cache's own callers use.
func dsUsable(ds *dns.DS) bool { return DSUsable(ds) }

// noUsableDS reports whether rrs holds DS records and none of them is usable.
func noUsableDS(rrs []dns.RR) bool {
	seen := false
	for _, rr := range rrs {
		ds, ok := rr.(*dns.DS)
		if !ok {
			continue
		}
		if dsUsable(ds) {
			return false
		}
		seen = true
	}
	return seen
}

// parentDSWithNoUsableDS reports whether crr is a DS RRset from the parent that
// validated Secure and in which no DS is usable: an insecure cut.
func parentDSWithNoUsableDS(crr *CachedRRset) bool {
	if crr == nil || crr.RRset == nil || crr.State != ValidationStateSecure {
		return false
	}
	switch crr.Context {
	case ContextAnswer, ContextReferral:
	default:
		return false // a trust anchor's DS (ContextPriming), or no DS at all
	}
	return noUsableDS(crr.RRset.RRs)
}
