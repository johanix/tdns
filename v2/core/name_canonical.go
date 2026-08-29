/*
 * Canonical form of a DNS name, for use as a lookup key.
 *
 * The counterpart to EqualNames: that one answers "are these the same name?"
 * without allocating; this one produces the key a hash table can be indexed by,
 * because a map cannot consult a function.
 */

package core

// CanonicalizeName returns name with US-ASCII A-Z lowercased and every other
// octet left exactly as it was.
//
// USE THIS, NOT dns.CanonicalName, TO BUILD A MAP KEY FROM A DOMAIN NAME.
// dns.CanonicalName folds by the same ASCII-only rule (RFC 4034 §6.2) and is
// correct about case, but it is built on strings.Map, which decodes UTF-8. A
// name carrying an octet that is not valid UTF-8 comes back with that octet
// replaced by U+FFFD:
//
//	dns.CanonicalName("ns\xff1.example.")  // "ns�1.example." -- 15 bytes for 13
//
// Two names differing only in such an octet then canonicalise to the same key
// and collide, and neither can be retrieved by its own bytes. Names unpacked
// from the wire cannot hit this, because miekg escapes non-printable octets to
// \DDD before they ever reach a Go string; names read from zone files and YAML
// arrive as written and can.
//
// Returns name itself when it is already canonical, which is the common case,
// so a lookup on an already-lowercase name allocates nothing.
//
// Does NOT append a trailing dot. A possibly-relative name should go through
// dns.Fqdn first; doing it here would silently turn a caller's relative name
// into a different name than the one they passed.
func CanonicalizeName(name string) string {
	// Two passes so the common case -- already canonical -- returns the
	// original string and allocates nothing.
	i := 0
	for ; i < len(name); i++ {
		if c := name[i]; c >= 'A' && c <= 'Z' {
			break
		}
	}
	if i == len(name) {
		return name
	}

	buf := make([]byte, len(name))
	copy(buf, name[:i])
	for ; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c |= 'a' - 'A'
		}
		buf[i] = c
	}
	return string(buf)
}
