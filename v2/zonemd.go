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

	core "github.com/johanix/tdns/v2/core"
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
	// core.CanonicalizeName, NOT strings.ToLower. RFC 4034 6.1 orders names as
	// OCTET strings with US-ASCII A-Z folded and nothing else; strings.ToLower
	// folds by Unicode, and gets this wrong twice over. See canonicalSortKey.
	al := dns.SplitDomainName(core.CanonicalizeName(dns.Fqdn(a)))
	bl := dns.SplitDomainName(core.CanonicalizeName(dns.Fqdn(b)))

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
	// core.CanonicalizeName, NOT strings.ToLower. This key IS the canonical
	// order: it decides the NSEC chain and the order records are fed to the
	// ZONEMD digest, so getting it wrong produces a chain no validator accepts
	// and a digest that matches no other implementation. RFC 4034 6.1 folds
	// US-ASCII A-Z and leaves every other octet alone. strings.ToLower breaks
	// that in two separate ways:
	//
	//   U+212A KELVIN SIGN folds onto "k", so \u212a.example. and k.example. --
	//   two different names -- produce the SAME key and occupy one position.
	//
	//   A byte that is not valid UTF-8 is rewritten to U+FFFD, so ns\xff1. is
	//   ordered by three bytes it does not contain.
	//
	// The comment below is right that this is "wrong in a way no test zone
	// would ever show"; it was describing the zero-octet case and the folding
	// had the same property.
	labels := dns.SplitDomainName(core.CanonicalizeName(dns.Fqdn(name)))
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
// core.CanonicalizeName, not dns.CanonicalName, for the same reason the sort
// key above uses it: these are the BYTES THAT GO INTO THE HASH. §6.2 folds
// US-ASCII A-Z and leaves every other octet alone, and dns.CanonicalName
// rewrites anything that is not valid UTF-8 into U+FFFD -- so a name carrying
// a raw octet would be hashed as three bytes it does not contain, and the
// digest would disagree with every other implementation on exactly the zones
// the paragraph above is about.
//
// HINFO is deliberately absent: RFC 4034 §6.2 lists it twice by mistake, and
// RFC 6840 §5.1 records that it holds no domain names and is not subject to
// case conversion.
func canonicalRRWire(rr dns.RR) ([]byte, int, error) {
	r := dns.Copy(rr)
	r.Header().Name = core.CanonicalizeName(r.Header().Name)

	switch x := r.(type) {
	case *dns.NS:
		x.Ns = core.CanonicalizeName(x.Ns)
	case *dns.MD:
		x.Md = core.CanonicalizeName(x.Md)
	case *dns.MF:
		x.Mf = core.CanonicalizeName(x.Mf)
	case *dns.CNAME:
		x.Target = core.CanonicalizeName(x.Target)
	case *dns.SOA:
		x.Ns = core.CanonicalizeName(x.Ns)
		x.Mbox = core.CanonicalizeName(x.Mbox)
	case *dns.MB:
		x.Mb = core.CanonicalizeName(x.Mb)
	case *dns.MG:
		x.Mg = core.CanonicalizeName(x.Mg)
	case *dns.MR:
		x.Mr = core.CanonicalizeName(x.Mr)
	case *dns.PTR:
		x.Ptr = core.CanonicalizeName(x.Ptr)
	case *dns.MINFO:
		x.Rmail = core.CanonicalizeName(x.Rmail)
		x.Email = core.CanonicalizeName(x.Email)
	case *dns.MX:
		x.Mx = core.CanonicalizeName(x.Mx)
	case *dns.RP:
		x.Mbox = core.CanonicalizeName(x.Mbox)
		x.Txt = core.CanonicalizeName(x.Txt)
	case *dns.AFSDB:
		x.Hostname = core.CanonicalizeName(x.Hostname)
	case *dns.RT:
		x.Host = core.CanonicalizeName(x.Host)
	case *dns.SIG:
		x.SignerName = core.CanonicalizeName(x.SignerName)
	case *dns.PX:
		x.Map822 = core.CanonicalizeName(x.Map822)
		x.Mapx400 = core.CanonicalizeName(x.Mapx400)
	case *dns.NAPTR:
		x.Replacement = core.CanonicalizeName(x.Replacement)
	case *dns.KX:
		x.Exchanger = core.CanonicalizeName(x.Exchanger)
	case *dns.SRV:
		x.Target = core.CanonicalizeName(x.Target)
	case *dns.DNAME:
		x.Target = core.CanonicalizeName(x.Target)
	case *dns.RRSIG:
		x.SignerName = core.CanonicalizeName(x.SignerName)
	case *dns.NSEC:
		x.NextDomain = core.CanonicalizeName(x.NextDomain)
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

// A zone's digest is the concatenation of its OWNERS' digests, in canonical
// owner order.
//
// That decomposition is not an implementation detail, it is what makes the
// digest cacheable. The RFC's ordering is (owner, type, RDATA), so every
// record at one owner name sorts into one contiguous run -- an owner's
// contribution to the hash is a single block of bytes that depends on nothing
// outside that owner. A publish that changes three names can therefore reuse
// the blocks of every name it did not touch. See zonemd_cache.go.
//
// The blocks do not depend on the hash algorithm either, so a zone publishing
// both SHA-384 and SHA-512 encodes once and hashes twice.

// digestBlock renders the records of ONE owner name into the bytes that owner
// contributes to the digest: each record in RFC 4034 §6.2 canonical form,
// ordered by type and then by canonical RDATA (§6.3), with duplicates counted
// once (RFC 8976 §3.3.1).
//
// Duplicate suppression is per-owner and that is complete: two records are
// duplicates only if their canonical wire forms are identical, and the wire
// form begins with the owner name, so duplicates always share an owner.
//
// apex governs the two exclusions, both of which apply only AT the apex: the
// ZONEMD RRset (a digest cannot cover itself) and the RRSIGs covering it. A
// ZONEMD at any other owner is ordinary zone data and is digested like
// anything else -- RFC 8976's Appendix A.2 has one, to catch implementations
// that exclude by type alone.
func digestBlock(apex string, rrs []dns.RR) ([]byte, error) {
	type entry struct {
		wire  []byte
		rdata []byte
		typ   uint16
	}
	var entries []entry
	var total int

	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		hdr := rr.Header()
		name := core.CanonicalizeName(hdr.Name)

		// Out-of-zone data is excluded (§3.3.1). A loaded zone should not carry
		// any, but a zone FILE can -- nothing stops an operator writing an
		// absolute name from another zone into it, and this digest is computed
		// over files. Including it would make the digest depend on records the
		// zone does not own. RFC 8976's own Appendix A.2 vector carries a
		// `foo.test.` record for exactly this reason.
		if !dns.IsSubDomain(apex, name) {
			continue
		}
		// The apex exclusion decides whether the ZONEMD RRset is fed to its own
		// digest, and a miss digests the record the digest is supposed to be.
		//
		// Every caller inside tdns passes a canonical apex, and name is folded
		// by the same function a few lines up, so == was correct as it stood.
		// EqualNames because ZoneDigest and ZoneDigestHex are EXPORTED: an
		// outside caller's apex is not covered by that invariant, and this is
		// not a place to find out.
		if core.EqualNames(name, apex) {
			if hdr.Rrtype == dns.TypeZONEMD {
				continue
			}
			if hdr.Rrtype == dns.TypeRRSIG {
				if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeZONEMD {
					continue
				}
			}
		}

		wire, rdoff, err := canonicalRRWire(rr)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry{wire: wire, rdata: wire[rdoff:], typ: hdr.Rrtype})
		total += len(wire)
	}
	if len(entries) == 0 {
		return nil, nil
	}

	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].typ != entries[j].typ {
			return entries[i].typ < entries[j].typ
		}
		// RDATA, not the whole wire. The two differ for records that share an
		// owner and a type but not a TTL -- which in a signed zone is every
		// apex with an RRSIG over its NSEC (TTL from the SOA minimum) beside
		// RRSIGs over everything else. Comparing the whole wire reaches the TTL
		// field first and decides there, producing an order RFC 4034 §6.3 does
		// not describe and a digest no other implementation reproduces.
		//
		// Not the wire minus the TTL either: RDLENGTH precedes the RDATA, so
		// that comparison sorts a shorter RDATA first unconditionally, where
		// §6.3 wants a left-justified octet comparison in which a shorter RDATA
		// sorts first only when it is a PREFIX of the longer.
		if c := bytes.Compare(entries[i].rdata, entries[j].rdata); c != 0 {
			return c < 0
		}
		// Equal RDATA at the same type: duplicates, which §3.3.1 counts once.
		// The whole wire decides between them, which with everything up to the
		// RDATA equal means the TTL decides -- so the LOWEST TTL sorts first
		// and is the one kept below.
		//
		// This is not a second ordering rule; it is what makes the choice
		// DETERMINISTIC. Without it the survivor would be whichever the caller
		// happened to hand over first, and the digest of a zone read from a
		// file could differ from the digest of the same zone walked from a
		// snapshot. Keeping the lowest also agrees with dnspython, which
		// collapses such a pair to one rdata at the lower TTL whatever order
		// it reads them in, and with RFC 2181 §5.2 on a malformed RRset.
		return bytes.Compare(entries[i].wire, entries[j].wire) < 0
	})

	// Duplicates count once (§3.3.1). A duplicate is owner, class, type and
	// RDATA -- NOT the TTL: two records differing only in TTL are one record
	// in a malformed RRset (RFC 2181 §5.2), and miekg's own IsDuplicate
	// ignores the TTL for the same reason. Comparing whole wire records here
	// would hash both and disagree with every implementation that stores an
	// RRset's TTL once, dnspython included.
	//
	// The sort put them adjacent with the lowest TTL first, so this is a scan
	// and the survivor is the low-TTL copy.
	block := make([]byte, 0, total)
	var prevRdata []byte
	var prevTyp uint16
	first := true
	for _, e := range entries {
		if !first && e.typ == prevTyp && bytes.Equal(prevRdata, e.rdata) {
			continue
		}
		block = append(block, e.wire...)
		prevRdata, prevTyp, first = e.rdata, e.typ, false
	}
	return block, nil
}

// groupByOwner buckets a flat record list by canonical owner name.
func groupByOwner(rrs []dns.RR) map[string][]dns.RR {
	out := make(map[string][]dns.RR)
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		// A MAP KEY. dns.CanonicalName sends every non-UTF-8 octet to U+FFFD,
		// so ns\xfe1. and ns\xff1. -- two owners -- merged into one bucket and
		// were digested as a single owner's records.
		name := core.CanonicalizeName(rr.Header().Name)
		out[name] = append(out[name], rr)
	}
	return out
}

// canonicalOwnerOrder sorts owner names into RFC 4034 §6.1 canonical order.
//
// Sorts (key, name) pairs rather than looking each key up in a map. The map
// spelling is the obvious one and costs about six allocations per name to the
// pair slice's one -- which for a zone with a million owners is the difference
// between the sort being noticeable and being the whole cost. Every publish of
// every signed zone pays this ordering for the NSEC chain, so it is worth the
// extra four lines.
func canonicalOwnerOrder(names []string) {
	type keyed struct {
		key  []byte
		name string
	}
	tmp := make([]keyed, len(names))
	for i, n := range names {
		tmp[i] = keyed{canonicalSortKey(n), n}
	}
	sort.Slice(tmp, func(i, j int) bool {
		return bytes.Compare(tmp[i].key, tmp[j].key) < 0
	})
	for i := range tmp {
		names[i] = tmp[i].name
	}
}

// ZoneDigest computes the RFC 8976 digest over rrs for the given apex.
//
// Exclusions, per §3.3.1: the apex ZONEMD RRset and the RRSIGs covering it are
// omitted (a digest cannot cover itself), and duplicate RRs count once.
//
// Only the SIMPLE scheme is implemented. It is the only one defined, and the
// registry exists for a scheme that has not been specified.
//
// This is the uncached path, over a flat record list: what a zone file parse,
// an AXFR and every verification hand it. The publish path goes through
// zonemd_cache.go instead, and the two share digestBlock so they cannot
// disagree about what a digest is.
func ZoneDigest(apex string, rrs []dns.RR, scheme, alg uint8) ([]byte, error) {
	h, err := zonemdHasherForScheme(scheme, alg)
	if err != nil {
		return nil, err
	}
	// Folded by the function digestBlock compares against, or the apex-ZONEMD
	// exclusion in there is comparing two different foldings of the same name.
	apex = core.CanonicalizeName(apex)

	byOwner := groupByOwner(rrs)
	names := make([]string, 0, len(byOwner))
	for name := range byOwner {
		names = append(names, name)
	}
	canonicalOwnerOrder(names)

	for _, name := range names {
		block, berr := digestBlock(apex, byOwner[name])
		if berr != nil {
			return nil, berr
		}
		h.Write(block)
	}
	return h.Sum(nil), nil
}

// zonemdHasherForScheme resolves the hash for a (scheme, algorithm) pair,
// rejecting a scheme that is not SIMPLE.
func zonemdHasherForScheme(scheme, alg uint8) (hash.Hash, error) {
	if scheme != ZonemdSchemeSimple {
		return nil, fmt.Errorf("ZONEMD: unsupported scheme %d (only SIMPLE=%d is defined)",
			scheme, ZonemdSchemeSimple)
	}
	return zonemdHasher(alg)
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
