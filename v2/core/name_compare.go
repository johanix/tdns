/*
 * Case-insensitive DNS name comparison.
 *
 * EqualNames is miekg/dns's unexported equal() (labels.go), lifted and
 * exported. Its own comment there invites this: "might be lifted into API
 * function."
 */

package core

// EqualNames reports whether two domain names are the same name, comparing
// case-insensitively as DNS requires.
//
// USE THIS RATHER THAN strings.EqualFold FOR ANYTHING THAT IS A DOMAIN NAME.
// strings.EqualFold applies Unicode simple case-folding; RFC 4343 folds only
// US-ASCII A-Z. The difference is not theoretical:
//
//	strings.EqualFold("K.example.", "k.example.")  // true  -- KELVIN SIGN
//	strings.EqualFold("ſ.example.", "s.example.")  // true  -- LATIN LONG S
//	EqualNames(...)                                     // false, both
//
// A domain name is a string of octets, and those octet sequences are not the
// ASCII letter they happen to fold to in Unicode. Treating them as equal makes
// a server answer for a name it is not authoritative for.
//
// Byte-wise and allocation-free, so it is cheap enough to use on every
// comparison. dns.CanonicalName(a) == dns.CanonicalName(b) is equally correct
// -- it is ASCII-only too -- but allocates twice per call.
//
// NOT a substitute for canonicalising a map key. A lookup keyed by name still
// needs a canonical key, because a hash table cannot consult a function; this
// is for the places that genuinely compare two names. Use CanonicalizeName to
// build that key -- NOT dns.CanonicalName, which folds case by the same rule
// but rewrites any octet that is not valid UTF-8 into U+FFFD, so two distinct
// names can collide on one key. See the discussion in tdns#415.
//
// Names are compared exactly as given: no trailing-dot normalisation, no
// escape processing. "example.com" and "example.com." are different strings and
// this reports them different. Callers holding possibly-relative names should
// pass both through dns.Fqdn first.
func EqualNames(a, b string) bool {
	la := len(a)
	if la != len(b) {
		return false
	}

	// Backwards, as miekg does: domain names share their left-hand labels far
	// more often than their right-hand ones, so a mismatch is usually found
	// sooner from the end.
	for i := la - 1; i >= 0; i-- {
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
