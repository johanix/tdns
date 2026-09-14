/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The proof that goes with a signed wildcard answer.
 *
 * An RRSIG over a wildcard expansion says, through its Labels field, which
 * wildcard produced the answer. It cannot say that the wildcard was the right
 * one to use: that the name asked for does not exist, so nothing closer to it
 * could have answered. RFC 4035 section 3.1.3.3 has the server prove that with
 * an NSEC covering the name, and a validator that does not get one treats the
 * answer as bogus (RFC 4035 section 5.3.4).
 */

package tdns

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// addWildcardProof adds to AUTHORITY the NSEC proving that qname, answered
// from wildcard, does not exist.
//
// A zone with an NSEC chain proves it with the chain's own record, the one
// that covers qname, served with the signature it already carries. That
// works on a secondary too, which holds no key. A black-lies zone has no
// chain; it gets an NSEC covering only the next closer name, synthesised and
// signed for this response as its denials are.
//
// The error is from signing that NSEC. A zone that must be signed and cannot
// sign the proof is broken, and the caller answers SERVFAIL, as for a denial
// it cannot sign. When no truthful cover can be built at all (see
// coverNextCloser) the answer goes out without one.
func (zd *ZoneData) addWildcardProof(m *dns.Msg, snap *zoneSnapshot, apex *OwnerData, qname, wildcard string,
	signFunc func(core.RRset, string) (core.RRset, error)) error {
	if !zd.Options[OptBlackLies] {
		if nsec, ok := nsecCoveringFrom(snap, qname); ok && len(nsec.RRSIGs) > 0 {
			m.Ns = append(m.Ns, nsec.RRs...)
			m.Ns = append(m.Ns, nsec.RRSIGs...)
			return nil
		}
	}

	var ttl uint32 = 3600
	if soaRR, ok := apex.RRtypes.Get(dns.TypeSOA); ok && len(soaRR.RRs) > 0 {
		if soa, ok := soaRR.RRs[0].(*dns.SOA); ok {
			ttl = soa.Minttl
		}
	}
	ce := "."
	if wildcard != "*." {
		ce = strings.TrimPrefix(wildcard, "*.")
	}
	nsec := coverNextCloser(snap, qname, ce, ttl)
	if nsec == nil {
		lgHandler.Warn("no NSEC can be built to prove this wildcard answer; serving it without one",
			"zone", zd.ZoneName, "qname", qname, "wildcard", wildcard)
		return nil
	}
	signed, err := signFunc(core.RRset{RRs: []dns.RR{nsec}}, zd.ZoneName)
	if err != nil {
		lgHandler.Error("failed to sign the NSEC proving a wildcard answer; serving SERVFAIL",
			"zone", zd.ZoneName, "qname", qname, "err", err)
		return err
	}
	if len(signed.RRSIGs) == 0 {
		return nil // an unsigned NSEC proves nothing
	}
	m.Ns = append(m.Ns, nsec)
	m.Ns = append(m.Ns, signed.RRSIGs...)
	return nil
}

type nsecIndexEntry struct {
	key  []byte
	name string
}

// nsecOwners returns the owners in s that carry a stored NSEC, sorted by
// canonicalSortKey, the order the signer builds the chain in.
func (s *zoneSnapshot) nsecOwners() []nsecIndexEntry {
	s.nsecOnce.Do(func() {
		for name, od := range s.Data {
			if od != nil && len(od.NSEC.RRs) > 0 {
				s.nsecIndex = append(s.nsecIndex, nsecIndexEntry{canonicalSortKey(name), name})
			}
		}
		sort.Slice(s.nsecIndex, func(i, j int) bool {
			return bytes.Compare(s.nsecIndex[i].key, s.nsecIndex[j].key) < 0
		})
	})
	return s.nsecIndex
}

// nsecCoveringFrom returns the stored NSEC that covers qname, a name the zone
// does not hold: the chain's record whose owner is the last before qname,
// provided its next name comes after qname or wraps round to the apex.
func nsecCoveringFrom(snap *zoneSnapshot, qname string) (core.RRset, bool) {
	if snap == nil {
		return core.RRset{}, false
	}
	idx := snap.nsecOwners()
	key := canonicalSortKey(qname)
	i := sort.Search(len(idx), func(i int) bool { return bytes.Compare(idx[i].key, key) >= 0 })
	if i == 0 || (i < len(idx) && bytes.Equal(idx[i].key, key)) {
		return core.RRset{}, false
	}
	od := snap.Data[idx[i-1].name]
	if od == nil || len(od.NSEC.RRs) == 0 {
		return core.RRset{}, false
	}
	nsec, ok := od.NSEC.RRs[0].(*dns.NSEC)
	if !ok {
		return core.RRset{}, false
	}
	next := canonicalSortKey(nsec.NextDomain)
	if bytes.Compare(key, next) < 0 || bytes.Compare(next, idx[i-1].key) <= 0 {
		return od.NSEC, true
	}
	return core.RRset{}, false
}

// coverNextCloser synthesises an NSEC that covers the next closer name -- ce
// with the next label of qname in front -- and nothing that exists (RFC 4470).
// nil if there is no such NSEC to be had, which takes a zone built to defeat
// it.
//
// The next name is the first name after the next closer name's whole subtree:
// its label with a \000 appended. Not \000.<next closer>, the successor
// RFC 4470 describes, which lies inside the subtree. A validator takes the
// closest encloser from whichever of the NSEC's two names shares more labels
// with qname (Unbound's nsec_closest_encloser), so a next name below the next
// closer name makes the next closer name the closest encloser. That no longer
// matches the wildcard, and the proof is rejected.
//
// The owner is the largest name under ce that sorts before the next closer
// name and has no children: its label with the last octet lowered, padded out
// with \255 octets. Only that owner's descendants could lie between it and the
// next closer name, and they exist only if the owner does, which one lookup
// settles. When the next closer name's label is the single octet \000 nothing
// sorts between it and ce, and the owner is ce itself, with ce's own types.
func coverNextCloser(snap *zoneSnapshot, qname, ce string, ttl uint32) *dns.NSEC {
	qname, ce = core.CanonicalizeName(dns.Fqdn(qname)), core.CanonicalizeName(dns.Fqdn(ce))
	if !dns.IsSubDomain(ce, qname) || dns.CountLabel(ce) >= dns.CountLabel(qname) {
		return nil // ce is not a proper ancestor of qname, so there is no next closer name
	}
	nc := nextCloserName(qname, ce)
	labels, wire, err := nameLabels(nc)
	if err != nil || len(labels) == 0 {
		return nil
	}
	first := foldLabel(labels[0])
	// The longest label that still fits: a name is at most 255 octets on the
	// wire, and ce takes up what nc does less its first label.
	room := 254 - (wire - 1 - len(first))
	if room > 63 {
		room = 63
	}
	join := func(l []byte) string {
		if ce == "." {
			return labelString(l) + "."
		}
		return labelString(l) + "." + ce
	}

	var owner string
	types := []uint16{dns.TypeRRSIG, dns.TypeNSEC}
	if before := labelBefore(first, room); len(before) > 0 {
		owner = join(before)
		if nameExistsFrom(snap, owner) || isEmptyNonTerminal(snap, owner) {
			return nil
		}
	} else {
		owner = ce
		if od := getOwnerFrom(snap, ce); od != nil && od.RRtypes != nil {
			types = append(types, od.RRtypes.Keys()...)
		}
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	}
	after := labelAfter(first, room)
	if after == nil {
		return nil
	}
	next := join(after)
	if canonicalCompare(owner, nc) >= 0 || canonicalCompare(nc, next) >= 0 {
		return nil
	}
	return &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		NextDomain: next,
		TypeBitMap: types,
	}
}

// nextCloserName returns ce with the next label of qname in front of it.
func nextCloserName(qname, ce string) string {
	labels := dns.SplitDomainName(qname)
	return strings.Join(labels[len(labels)-dns.CountLabel(ce)-1:], ".") + "."
}

// labelBefore returns the largest label of at most room octets that sorts
// before l in canonical order, or an empty one when none does (l is \000).
// l must already be folded to lower case. Canonical order folds A-Z, so an
// octet lowered onto an upper-case letter would sort after l rather than
// before it; it goes one further, to '@'.
func labelBefore(l []byte, room int) []byte {
	last := l[len(l)-1]
	if last == 0 {
		// l less its final \000 sorts before l, with nothing between.
		return append([]byte(nil), l[:len(l)-1]...)
	}
	out := append([]byte(nil), l[:len(l)-1]...)
	c := last - 1
	if c >= 'A' && c <= 'Z' {
		c = 'A' - 1
	}
	out = append(out, c)
	for len(out) < room {
		out = append(out, 0xff)
	}
	return out
}

// labelAfter returns the smallest label of at most room octets that sorts
// after l and after every name beneath l: l with a \000 appended when there
// is room, and otherwise l with its last octet raised, carrying into the
// octet before it past \255. nil when no label follows (l is room octets of
// \255). l must already be folded to lower case, and a raised octet that lands
// on an upper-case letter goes on to '['.
func labelAfter(l []byte, room int) []byte {
	if len(l) < room {
		return append(append([]byte(nil), l...), 0)
	}
	out := append([]byte(nil), l...)
	for len(out) > 0 {
		c := out[len(out)-1]
		if c == 0xff {
			out = out[:len(out)-1]
			continue
		}
		c++
		if c >= 'A' && c <= 'Z' {
			c = 'Z' + 1
		}
		out[len(out)-1] = c
		return out
	}
	return nil
}

// nameLabels returns name's labels as raw octets, leftmost first, and its
// length on the wire.
func nameLabels(name string) ([][]byte, int, error) {
	buf := make([]byte, 256)
	off, err := dns.PackDomainName(dns.Fqdn(name), buf, 0, nil, false)
	if err != nil {
		return nil, 0, err
	}
	var labels [][]byte
	for i := 0; i < off && buf[i] != 0; i += 1 + int(buf[i]) {
		labels = append(labels, buf[i+1:i+1+int(buf[i])])
	}
	return labels, off, nil
}

// foldLabel returns l with US-ASCII A-Z lowered, the only folding canonical
// order does.
func foldLabel(l []byte) []byte {
	out := append([]byte(nil), l...)
	for i, c := range out {
		if c >= 'A' && c <= 'Z' {
			out[i] = c + 'a' - 'A'
		}
	}
	return out
}

// labelString renders a label's octets in presentation form.
func labelString(l []byte) string {
	var b strings.Builder
	for _, c := range l {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "\\%03d", c)
		}
	}
	return b.String()
}

// canonicalCompare orders two names in canonical order (RFC 4034 section
// 6.1) by their octets, as a validator does. canonicalSortKey works on the
// presentation form, where an octet written \255 compares as the four
// characters that spell it; the names coverNextCloser builds are made of such
// octets. A name that does not pack sorts first.
func canonicalCompare(a, b string) int {
	al, _, errA := nameLabels(a)
	bl, _, errB := nameLabels(b)
	if errA != nil || errB != nil {
		switch {
		case errA != nil && errB != nil:
			return 0
		case errA != nil:
			return -1
		default:
			return 1
		}
	}
	for i, j := len(al)-1, len(bl)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if c := bytes.Compare(foldLabel(al[i]), foldLabel(bl[j])); c != 0 {
			return c
		}
	}
	switch {
	case len(al) < len(bl):
		return -1
	case len(al) > len(bl):
		return 1
	}
	return 0
}
