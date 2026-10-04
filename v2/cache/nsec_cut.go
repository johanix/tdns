/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// NSEC records at a point below which their zone holds no names: a zone cut
// seen from the zone above (NS without SOA), and a DNAME. In canonical order
// such an NSEC covers every name below its owner, but it is no proof about
// any of them (RFC 4035 section 5.4, RFC 6840 section 4.1): below a cut they
// are the child zone's names, below a DNAME they are redirected.

// delegationBitmap reports whether an NSEC or NSEC3 type bitmap is that of a
// zone cut seen from the zone above: NS set, SOA clear.
func delegationBitmap(bitmap []uint16) bool {
	return typeInList(dns.TypeNS, bitmap) && !typeInList(dns.TypeSOA, bitmap)
}

// nsecAboveCut reports whether nsec is owned by a proper ancestor of name and
// marks its owner as a zone cut or a DNAME: an NSEC that must not be read as
// a proof about name.
func nsecAboveCut(name string, nsec *dns.NSEC) bool {
	if nsec == nil || !dns.IsSubDomain(nsec.Hdr.Name, name) || core.EqualNames(nsec.Hdr.Name, name) {
		return false
	}
	return typeInList(dns.TypeDNAME, nsec.TypeBitMap) || delegationBitmap(nsec.TypeBitMap)
}

// cutDenial is the verdict on a denial for a name below a zone cut or a DNAME
// that nsec, an NSEC at that point, is the only proof of. Its zone holds no
// names there, so it proves nothing about the name, and the answer should
// have been a referral or a DNAME. Below a cut without DS -- an insecure
// delegation the zone above has proven, RFC 4035 section 5.2 -- nothing can be
// Secure, and the denial is Insecure, as for NSEC3 (nsec3Proof.closestEncloser).
// Below a cut with DS, or a DNAME, it is Bogus.
func cutDenial(nsec *dns.NSEC) ValidationState {
	if insecureDelegationBitmap(nsec.TypeBitMap) && !typeInList(dns.TypeDNAME, nsec.TypeBitMap) {
		return ValidationStateInsecure
	}
	return ValidationStateBogus
}
