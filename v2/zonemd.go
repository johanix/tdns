/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// ZONEMD (RFC 8976) message digest over zone data.
//
// Used here as a DETECTOR, not as a published record: it answers "is the zone
// file still the one the delta journal was computed against?" A byte hash of
// the file would answer a different and less useful question -- reordering
// records, editing comments, reflowing whitespace or changing $TTL style all
// alter the bytes and none of them alter the zone. The zone file is meant to
// stay human-authored and revision-control friendly, and a detector that fires
// on formatting makes it neither.
//
// Implemented to the RFC rather than as a private digest, for two reasons: it
// is specified and testable (Appendix A gives vectors, and TestZoneDigest*
// below checks against them), and publishing ZONEMD later becomes nearly free
// once the computation exists.

// ZONEMD scheme and hash algorithm codepoints (RFC 8976 §5).
const (
	ZonemdSchemeSimple = uint8(1)

	ZonemdAlgSHA384 = uint8(1)
	ZonemdAlgSHA512 = uint8(2)
)

// zonemdHasher returns the hash for an RFC 8976 algorithm codepoint.
func zonemdHasher(alg uint8) (hash.Hash, error) {
	switch alg {
	case ZonemdAlgSHA384:
		return sha512.New384(), nil
	case ZonemdAlgSHA512:
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("ZONEMD: unsupported hash algorithm %d", alg)
	}
}

// canonicalOwnerLess reports whether name a sorts before b in DNS canonical
// order (RFC 4034 §6.1): compare labels from the RIGHT, each as a
// case-insensitive octet string, with a shorter name sorting first when it is
// a suffix of the longer.
//
// Not a plain string comparison. For a zone `clean.example.` holding `alpha`,
// `bravo` and `ns` beneath it, a lexicographic sort puts the apex in the
// MIDDLE -- alpha, bravo, clean.example., ns -- because it compares from the
// left and the apex is a suffix, not a prefix. Canonical order puts the apex
// first, where the NSEC chain needs it.
//
// For a bulk sort use canonicalSortKey instead: this allocates on every
// comparison, which an O(n log n) sort over a large zone feels.
func canonicalOwnerLess(a, b string) bool {
	al := dns.SplitDomainName(strings.ToLower(dns.Fqdn(a)))
	bl := dns.SplitDomainName(strings.ToLower(dns.Fqdn(b)))

	for i, j := len(al)-1, len(bl)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if c := strings.Compare(al[i], bl[j]); c != 0 {
			return c < 0
		}
	}
	// One is a suffix of the other; the shorter (fewer labels) sorts first.
	return len(al) < len(bl)
}

// canonicalSortKey renders a name as a byte string whose plain bytewise order
// IS canonical name order, so a bulk sort can compare precomputed keys with
// bytes.Compare instead of re-splitting both names on every comparison.
//
// canonicalOwnerLess costs two Fqdn calls, two ToLower calls and two
// SplitDomainName allocations per comparison, and it is called O(n log n)
// times -- by the NSEC chain sort on every publish of a signed zone, and by
// the digest sort on every publish of a zonemd zone. Over a large zone that is
// the dominant cost of both.
//
// The encoding: labels lowercased and emitted right-to-left, each terminated
// by 0x00 0x00, with any 0x00 INSIDE a label escaped to 0x00 0x01. The escape
// is what makes the order exact rather than merely usual. A label may legally
// contain a zero octet, and without the escape such a label would collide with
// the separator and sort as though it were two labels -- a name ordering that
// is wrong in a way no test zone would ever show, and that would put the NSEC
// chain in an order no validator accepts.
//
// The terminator gives the "shorter name first" rule for free: `example.` is
// "example\x00\x00", `a.example.` is "example\x00\x00a\x00\x00", and a prefix
// sorts before what extends it.
func canonicalSortKey(name string) []byte {
	labels := dns.SplitDomainName(strings.ToLower(dns.Fqdn(name)))
	// One byte per character plus a two-byte terminator per label, which is
	// exact for the overwhelmingly common case of no zero octets.
	key := make([]byte, 0, len(name)+2*len(labels)+2)
	for i := len(labels) - 1; i >= 0; i-- {
		for j := 0; j < len(labels[i]); j++ {
			if c := labels[i][j]; c == 0x00 {
				key = append(key, 0x00, 0x01)
			} else {
				key = append(key, c)
			}
		}
		key = append(key, 0x00, 0x00)
	}
	return key
}

// canonicalRRWire renders one RR in RFC 4034 §6.2 canonical form: the owner
// name lowercased and fully expanded, no name compression, and -- for the
// types RFC 4034 lists -- domain names inside the RDATA lowercased too.
//
// The RDATA lowercasing is the part it would be tempting to skip. It only
// changes the result for a zone that spells, say, an NS target in mixed case,
// which no generator does and every hand-edited zone eventually might. Skipping
// it would produce a digest that agrees with the RFC's test vectors (they are
// all lowercase) while disagreeing with every other implementation on real
// zones -- passing tests and being wrong.
//
// HINFO is deliberately absent: RFC 4034 §6.2 lists it twice by mistake, and
// RFC 6840 §5.1 records that it holds no domain names and is not subject to
// case conversion.
func canonicalRRWire(rr dns.RR) ([]byte, int, error) {
	r := dns.Copy(rr)
	r.Header().Name = dns.CanonicalName(r.Header().Name)

	switch x := r.(type) {
	case *dns.NS:
		x.Ns = dns.CanonicalName(x.Ns)
	case *dns.MD:
		x.Md = dns.CanonicalName(x.Md)
	case *dns.MF:
		x.Mf = dns.CanonicalName(x.Mf)
	case *dns.CNAME:
		x.Target = dns.CanonicalName(x.Target)
	case *dns.SOA:
		x.Ns = dns.CanonicalName(x.Ns)
		x.Mbox = dns.CanonicalName(x.Mbox)
	case *dns.MB:
		x.Mb = dns.CanonicalName(x.Mb)
	case *dns.MG:
		x.Mg = dns.CanonicalName(x.Mg)
	case *dns.MR:
		x.Mr = dns.CanonicalName(x.Mr)
	case *dns.PTR:
		x.Ptr = dns.CanonicalName(x.Ptr)
	case *dns.MINFO:
		x.Rmail = dns.CanonicalName(x.Rmail)
		x.Email = dns.CanonicalName(x.Email)
	case *dns.MX:
		x.Mx = dns.CanonicalName(x.Mx)
	case *dns.RP:
		x.Mbox = dns.CanonicalName(x.Mbox)
		x.Txt = dns.CanonicalName(x.Txt)
	case *dns.AFSDB:
		x.Hostname = dns.CanonicalName(x.Hostname)
	case *dns.RT:
		x.Host = dns.CanonicalName(x.Host)
	case *dns.SIG:
		x.SignerName = dns.CanonicalName(x.SignerName)
	case *dns.PX:
		x.Map822 = dns.CanonicalName(x.Map822)
		x.Mapx400 = dns.CanonicalName(x.Mapx400)
	case *dns.NAPTR:
		x.Replacement = dns.CanonicalName(x.Replacement)
	case *dns.KX:
		x.Exchanger = dns.CanonicalName(x.Exchanger)
	case *dns.SRV:
		x.Target = dns.CanonicalName(x.Target)
	case *dns.DNAME:
		x.Target = dns.CanonicalName(x.Target)
	case *dns.RRSIG:
		x.SignerName = dns.CanonicalName(x.SignerName)
	case *dns.NSEC:
		x.NextDomain = dns.CanonicalName(x.NextDomain)
	}

	buf := make([]byte, dns.Len(r)+1)
	off, err := dns.PackRR(r, buf, 0, nil, false)
	if err != nil {
		return nil, 0, fmt.Errorf("ZONEMD: packing %s: %v", rr.Header().Name, err)
	}
	return buf[:off], rdataOffset(buf[:off]), nil
}

// rdataOffset returns the index at which the RDATA begins in an uncompressed
// wire-format RR: past the owner name, then the fixed TYPE, CLASS, TTL and
// RDLENGTH fields.
//
// Name compression is disabled for canonical form (RFC 4034 §6.2), so the name
// is a plain sequence of length-prefixed labels ending in a zero octet and can
// be walked without a message to resolve pointers against.
func rdataOffset(wire []byte) int {
	i := 0
	for i < len(wire) {
		l := int(wire[i])
		if l == 0 {
			i++
			break
		}
		i += 1 + l
	}
	// TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
	if i+10 > len(wire) {
		return len(wire)
	}
	return i + 10
}

// ZoneDigest computes the RFC 8976 digest over rrs for the given apex.
//
// Exclusions, per §3.3.1: the apex ZONEMD RRset and the RRSIGs covering it are
// omitted (a digest cannot cover itself), and duplicate RRs count once.
//
// Only the SIMPLE scheme is implemented. It is the only one defined, and the
// registry exists for a scheme that has not been specified.
func ZoneDigest(apex string, rrs []dns.RR, scheme, alg uint8) ([]byte, error) {
	if scheme != ZonemdSchemeSimple {
		return nil, fmt.Errorf("ZONEMD: unsupported scheme %d (only SIMPLE=%d is defined)",
			scheme, ZonemdSchemeSimple)
	}
	h, err := zonemdHasher(alg)
	if err != nil {
		return nil, err
	}
	apex = dns.CanonicalName(apex)

	type entry struct {
		wire  []byte
		rdata []byte
		key   []byte
		typ   uint16
	}
	var entries []entry

	// One key per OWNER, not per RR: a zone has several records at most names
	// and the key depends only on the name.
	keyCache := make(map[string][]byte)
	keyFor := func(name string) []byte {
		if k, ok := keyCache[name]; ok {
			return k
		}
		k := canonicalSortKey(name)
		keyCache[name] = k
		return k
	}

	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		hdr := rr.Header()
		atApex := dns.CanonicalName(hdr.Name) == apex

		// Out-of-zone data is excluded (§3.3.1). A loaded zone should not carry
		// any, but a zone FILE can -- nothing stops an operator writing an
		// absolute name from another zone into it, and this digest is computed
		// over files. Including it would make the digest depend on records the
		// zone does not own. RFC 8976's own Appendix A.2 vector carries a
		// `foo.test.` record for exactly this reason.
		if !dns.IsSubDomain(apex, dns.CanonicalName(hdr.Name)) {
			continue
		}

		// The digest cannot cover itself -- but only the APEX ZONEMD RRset is
		// excluded. A ZONEMD at any other owner is ordinary zone data and is
		// digested like anything else (A.2 has one, to catch implementations
		// that exclude by type alone).
		if atApex && hdr.Rrtype == dns.TypeZONEMD {
			continue
		}
		if atApex && hdr.Rrtype == dns.TypeRRSIG {
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeZONEMD {
				continue
			}
		}

		wire, rdoff, err := canonicalRRWire(rr)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry{wire: wire, rdata: wire[rdoff:],
			key: keyFor(hdr.Name), typ: hdr.Rrtype})
	}

	sort.SliceStable(entries, func(i, j int) bool {
		if c := bytes.Compare(entries[i].key, entries[j].key); c != 0 {
			return c < 0
		}
		if entries[i].typ != entries[j].typ {
			return entries[i].typ < entries[j].typ
		}
		// RDATA, not the whole wire. The two differ for records that share an
		// owner and a type but not a TTL -- which in a signed zone is every
		// apex with an RRSIG over its NSEC (TTL from the SOA minimum) beside
		// RRSIGs over everything else (TTL from the records they cover).
		// Comparing the whole wire reaches the TTL field first and decides
		// there, producing an order RFC 4034 §6.3 does not describe and a
		// digest no other implementation reproduces.
		//
		// Not the wire minus the TTL either: RDLENGTH precedes the RDATA, so
		// that comparison sorts a shorter RDATA first unconditionally, where
		// §6.3 wants a left-justified octet comparison in which a shorter
		// RDATA sorts first only when it is a PREFIX of the longer.
		return bytes.Compare(entries[i].rdata, entries[j].rdata) < 0
	})

	// Duplicates count once (§3.3.1). After the sort they are adjacent, so this
	// is a scan rather than a set.
	var prev []byte
	for _, e := range entries {
		if prev != nil && bytes.Equal(prev, e.wire) {
			continue
		}
		h.Write(e.wire)
		prev = e.wire
	}

	return h.Sum(nil), nil
}

// ZoneDigestHex is ZoneDigest rendered as lowercase hex, which is how the
// digest is stored and compared in ZoneFileState.
func ZoneDigestHex(apex string, rrs []dns.RR, scheme, alg uint8) (string, error) {
	d, err := ZoneDigest(apex, rrs, scheme, alg)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(d), nil
}
