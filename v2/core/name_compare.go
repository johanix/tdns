/*
 * DNS name comparison.
 *
 * EqualNames began as miekg/dns's unexported equal() (labels.go), lifted and
 * exported -- its own comment there invites this: "might be lifted into API
 * function." It has since learnt to read escapes, which equal() does not.
 */

package core

import "strings"

// EqualNames reports whether two domain names are the same name: the same
// octets, compared case-insensitively as DNS requires, however they are
// written.
//
// USE THIS RATHER THAN strings.EqualFold FOR ANYTHING THAT IS A DOMAIN NAME.
// strings.EqualFold applies Unicode simple case-folding; RFC 4343 folds only
// US-ASCII A-Z. The difference is not theoretical:
//
//	strings.EqualFold("K.example.", "k.example.")  // true  -- KELVIN SIGN
//	strings.EqualFold("ſ.example.", "s.example.")  // true  -- LATIN LONG S
//	EqualNames(...)                                     // false, both
//
// A domain name is a string of octets, and those octet sequences are not the
// ASCII letter they happen to fold to in Unicode. Treating them as equal makes
// a server answer for a name it is not authoritative for.
//
// Allocation-free, so it is cheap enough to use on every comparison.
// dns.CanonicalName(a) == dns.CanonicalName(b) is correct about case -- it is
// ASCII-only too -- but allocates twice per call and does not read escapes.
//
// NOT a substitute for canonicalising a map key. A lookup keyed by name still
// needs a canonical key, because a hash table cannot consult a function; this
// is for the places that genuinely compare two names. Use CanonicalizeName to
// build that key -- NOT dns.CanonicalName, which folds case by the same rule
// but rewrites any octet that is not valid UTF-8 into U+FFFD, so two distinct
// names can collide on one key. See the discussion in tdns#415.
//
// Escapes are read: \097 and a are one octet, as are \255 and a raw 0xff, and
// a\.b is one label where a.b is two. EqualNames(a, b) holds exactly when
// CanonicalizeName gives a and b the same key, so a comparison and a lookup
// cannot disagree about whether two names are one.
//
// No trailing-dot normalisation: "example.com" and "example.com." are
// different strings and this reports them different. Callers holding
// possibly-relative names should pass both through dns.Fqdn first.
func EqualNames(a, b string) bool {
	if len(a) == len(b) && equalFolded(a, b) {
		return true
	}
	// Two spellings of one name differ in length, or in more than case, only
	// through an escape. With no backslash on either side the bytes decided.
	if strings.IndexByte(a, '\\') < 0 && strings.IndexByte(b, '\\') < 0 {
		return false
	}
	return equalOctets(a, b)
}

// equalFolded compares two strings of one length byte by byte, with US-ASCII
// A-Z folded.
func equalFolded(a, b string) bool {
	// Backwards, as miekg does: domain names share their left-hand labels far
	// more often than their right-hand ones, so a mismatch is usually found
	// sooner from the end.
	for i := len(a) - 1; i >= 0; i-- {
		ai := a[i]
		bi := b[i]
		if ai >= 'A' && ai <= 'Z' {
			ai |= 'a' - 'A'
		}
		if bi >= 'A' && bi <= 'Z' {
			bi |= 'a' - 'A'
		}
		if ai != bi {
			return false
		}
	}
	return true
}

// equalOctets compares two names octet by octet with escapes decoded and
// US-ASCII A-Z folded: what comparing their CanonicalizeName keys compares,
// without building either key.
func equalOctets(a, b string) bool {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		ca, na := nameOctet(a, i)
		cb, nb := nameOctet(b, j)
		// A raw dot separates labels; a dot inside a label is escaped.
		if (na == 1 && ca == '.') != (nb == 1 && cb == '.') {
			return false
		}
		if ca >= 'A' && ca <= 'Z' {
			ca |= 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb |= 'a' - 'A'
		}
		if ca != cb {
			return false
		}
		i, j = i+na, j+nb
	}
	return i == len(a) && j == len(b)
}

// EqualNamesContains reports whether names contains name, compared as DNS
// names.
//
// The tdns-side counterpart to the strings.EqualFold loops scattered around the
// tree, and correct where those are not.
func EqualNamesContains(names []string, name string) bool {
	for _, n := range names {
		if EqualNames(n, name) {
			return true
		}
	}
	return false
}
