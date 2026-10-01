/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"slices"

	"github.com/miekg/dns"
)

// NSEC proofs of no data for a name that owns no NSEC of its own among the
// records of a denial. A name that owns one is read by ValidateNegativeResponse
// itself (RFC 9824 compact denial, and plain no data).

// nsecNoData reports whether nsecs prove that qname, in zone, has no qtype:
//
//   - qname is an empty non-terminal: an NSEC covers qname, and its next name
//     lies below qname. qname has a descendant and no records of its own.
//   - qname is answered by a wildcard that has no qtype (RFC 4035 sections
//     3.1.3.4 and 5.4): an NSEC covers qname, and the NSEC owned by the
//     wildcard at the closest encloser that cover proves has neither qtype nor
//     CNAME in its bitmap. A wildcard is not a delegation: NS without SOA there
//     proves nothing. One NSEC may be both.
//
// Every NSEC in nsecs has validated Secure. Neither proof is a name error:
// the first shows that qname exists, the second that a wildcard answers for
// it.
func nsecNoData(qname string, qtype uint16, zone string, nsecs []*dns.NSEC) bool {
	var cover *dns.NSEC
	for _, nsec := range nsecs {
		if !nsecCoversName(qname, nsec) {
			continue
		}
		if nsecNextBelow(qname, nsec) {
			return true
		}
		if cover == nil {
			cover = nsec
		}
	}
	if cover == nil {
		return false
	}
	wildcard := wildcardAt(closestEncloser(qname, cover, zone))
	for _, nsec := range nsecs {
		if canonicalNameCompare(nsec.Hdr.Name, wildcard) != 0 {
			continue
		}
		bm := nsec.TypeBitMap
		delegation := slices.Contains(bm, dns.TypeNS) && !slices.Contains(bm, dns.TypeSOA)
		return !slices.Contains(bm, qtype) && !slices.Contains(bm, dns.TypeCNAME) && !delegation
	}
	return false
}

// nsecNextBelow reports whether the next name of nsec, an NSEC that covers
// name, lies below name. Covering name, its next name is not name itself. It
// shows that name has a descendant: name is an empty non-terminal, and exists.
func nsecNextBelow(name string, nsec *dns.NSEC) bool {
	return nsec != nil && dns.IsSubDomain(name, nsec.NextDomain)
}
