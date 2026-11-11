/*
 * Canonical form of a DNS name, for use as a lookup key.
 *
 * The counterpart to EqualNames: that one answers "are these the same name?"
 * without allocating; this one produces the key a hash table can be indexed by,
 * because a map cannot consult a function.
 */

package core

import "strings"

// CanonicalizeName returns the spelling of name that every spelling of it
// shares: US-ASCII A-Z lowercased, presentation escapes decoded, and every
// octet otherwise left as it was.
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
// and collide, and neither can be retrieved by its own bytes.
//
// ONE NAME, ONE KEY, HOWEVER ITS OCTETS ARE WRITTEN. Presentation form spells
// an octet several ways -- a as a, \a or \097; 0xff raw or as \255 -- and names
// arrive in all of them: the zone parser hands over what the zone file wrote,
// and miekg writes a name it unpacks from the wire its own way (\255, never a
// raw 0xff). Keyed by spelling, a name stored one way is missed by a lookup
// that spells it another. So escapes are decoded and their octets written raw,
// except the two that would change the name's shape: a dot inside a label
// stays \. and a backslash stays \\.
//
// Raw rather than re-escaped, so that a string with no backslash in it
// canonicalises exactly as it did before escapes were decoded. Usernames,
// certificate identities and TSIG key names go through here on their way into
// the database, and none of them moves unless it was written with an escape.
//
// Returns name itself when it is already canonical, which is the common case,
// so a lookup on an already-canonical name allocates nothing.
//
// Does NOT append a trailing dot. A possibly-relative name should go through
// dns.Fqdn first; doing it here would silently turn a caller's relative name
// into a different name than the one they passed.
func CanonicalizeName(name string) string {
	// The common case -- no upper case and no escape -- is canonical as it
	// stands.
	i := 0
	for ; i < len(name); i++ {
		if c := name[i]; (c >= 'A' && c <= 'Z') || c == '\\' {
			break
		}
	}
	if i == len(name) {
		return name
	}

	// Upper case and no escape, which is every mixed-case query name off the
	// wire: fold byte for byte into a copy of the same length.
	if strings.IndexByte(name[i:], '\\') < 0 {
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
	return canonicalizeEscaped(name, i)
}

// canonicalizeEscaped finishes CanonicalizeName for a name with an escape in
// it, from name[i] on; everything before i is canonical as written.
//
// Each octet is written in its canonical spelling, and the copy starts only
// where that first differs from name: a canonical name that escapes a dot or a
// backslash allocates nothing.
func canonicalizeEscaped(name string, i int) string {
	var b strings.Builder
	copying := false
	for i < len(name) {
		start := i
		c, n := nameOctet(name, i)
		i += n

		var spelled [2]byte
		width := 1
		switch {
		case n == 1 && c == '.':
			spelled[0] = '.' // a label separator
		case c == '.' || c == '\\':
			spelled[0], spelled[1], width = '\\', c, 2
		case c >= 'A' && c <= 'Z':
			spelled[0] = c + 'a' - 'A'
		default:
			spelled[0] = c
		}

		if !copying {
			if name[start:i] == string(spelled[:width]) {
				continue
			}
			b.Grow(len(name) + 1)
			b.WriteString(name[:start])
			copying = true
		}
		b.Write(spelled[:width])
	}
	if !copying {
		return name
	}
	return b.String()
}

// nameOctet decodes the octet that starts at name[i] -- \DDD, \X, or a byte
// standing for itself -- and returns it with the number of bytes that spell
// it. A backslash that ends the string stands for itself. A raw '.' comes back
// as '.' in one byte, which is how a caller tells a label separator from an
// escaped dot.
func nameOctet(name string, i int) (byte, int) {
	c, n := nextByte(name, i)
	if n == 0 {
		return '\\', 1
	}
	return c, n
}
