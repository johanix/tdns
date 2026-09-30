/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cache

import (
	"bytes"
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"slices"
	"strings"
	"sync/atomic"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// NSEC3 proofs (RFC 5155 section 8), over records that have already
// validated. Nothing here looks at the cache or the network: the callers
// (ValidateDenial, nsec3CutProof, NSEC3WildcardProof) validate the records and
// pick the zone, and hand the NSEC3 records to newNSEC3Proof.

// DefaultNSEC3MaxIterations is the most NSEC3 hash iterations a proof is
// computed for unless configured otherwise. RFC 9276 section 3.2 lets a
// validator stop at a limit of its choosing; 150 was the limit validators
// shared when RFC 9276 was written.
const DefaultNSEC3MaxIterations = 150

var nsec3MaxIterations atomic.Uint32

func init() { nsec3MaxIterations.Store(DefaultNSEC3MaxIterations) }

// SetNSEC3MaxIterations sets the iteration limit (imrengine.tuning
// nsec3-max-iterations). Records above it are set aside after their
// signatures validate: a denial that needs them is Insecure (RFC 9276), and a
// zone cut they would prove is unjudged.
func SetNSEC3MaxIterations(n uint16) { nsec3MaxIterations.Store(uint32(n)) }

// NSEC3MaxIterations returns the iteration limit.
func NSEC3MaxIterations() uint16 { return uint16(nsec3MaxIterations.Load()) }

// nsec3HashBudget is the most hash computations one proof may make. At the
// default iteration limit that is about 1.5 ms of SHA-1, and it covers a
// qname 127 labels deep under two parameter sets. A proof that runs out is
// not judged (nsec3OverBudget).
const nsec3HashBudget = 256

// edeUnsupportedNSEC3Iterations is RFC 9276's EDE for a proof set aside for
// its iteration count: "Unsupported NSEC3 Iterations Value" (RFC 8914
// registry, code 27).
const edeUnsupportedNSEC3Iterations = 27

const nsec3HashLen = 20 // SHA-1

var base32hexNoPad = base32.HexEncoding.WithPadding(base32.NoPadding)

// nsec3Verdict is what an NSEC3 proof shows.
type nsec3Verdict int

const (
	nsec3Unproven           nsec3Verdict = iota // the records do not make the proof: Bogus
	nsec3Proven                                 // Secure
	nsec3OptOut                                 // made through an Opt-Out span: Insecure (RFC 5155 section 9.2)
	nsec3InsecureDelegation                     // the name is at or below a proven insecure delegation: Insecure
	nsec3OverLimit                              // needs records over the iteration limit: Insecure, EDE 27
	nsec3OverBudget                             // ran out of nsec3HashBudget: Indeterminate
)

var nsec3VerdictToString = map[nsec3Verdict]string{
	nsec3Unproven:           "unproven",
	nsec3Proven:             "proven",
	nsec3OptOut:             "proven through Opt-Out",
	nsec3InsecureDelegation: "insecure delegation",
	nsec3OverLimit:          "over the iteration limit",
	nsec3OverBudget:         "over the hash budget",
}

// state is the validation state a verdict gives the data it is about.
func (v nsec3Verdict) state() ValidationState {
	switch v {
	case nsec3Proven:
		return ValidationStateSecure
	case nsec3OptOut, nsec3InsecureDelegation, nsec3OverLimit:
		return ValidationStateInsecure
	case nsec3OverBudget:
		return ValidationStateIndeterminate
	}
	return ValidationStateBogus
}

// nsec3Params is one NSEC3 hash parameter set.
type nsec3Params struct {
	alg        uint8
	iterations uint16
	salt       string // the salt's octets
}

// nsec3Record is an NSEC3 record that counts toward a proof, with its owner
// hash and next hashed owner decoded.
type nsec3Record struct {
	rr     *dns.NSEC3
	owner  []byte
	next   []byte
	params nsec3Params
}

func (r *nsec3Record) optOut() bool { return r.rr.Flags&1 == 1 }

func (r *nsec3Record) has(t uint16) bool { return slices.Contains(r.rr.TypeBitMap, t) }

// delegation reports whether the record's name is a zone cut seen from the
// zone above: NS set, SOA clear.
func (r *nsec3Record) delegation() bool { return r.has(dns.TypeNS) && !r.has(dns.TypeSOA) }

// nsec3Proof is the NSEC3 records of one response that count toward a proof
// about names in zone, and the work done with them.
type nsec3Proof struct {
	zone     string
	records  []nsec3Record
	setAside bool // records over the iteration limit were left out
	memo     map[string][]byte
	budget   int
	hashes   int  // hash computations made
	spent    bool // a hash was needed and the budget had run out
}

// newNSEC3Proof keeps the records in rrs that count toward a proof about
// names in zone (nsec3Usable). Records over maxIter iterations are set aside,
// and the proof remembers that. The caller has validated every record in rrs
// with a signature by zone.
func newNSEC3Proof(zone string, rrs []*dns.NSEC3, maxIter uint16) *nsec3Proof {
	p := &nsec3Proof{zone: dns.Fqdn(zone), memo: map[string][]byte{}, budget: nsec3HashBudget}
	for _, rr := range rrs {
		switch rec, use := nsec3Usable(p.zone, rr, maxIter); use {
		case nsec3Counts:
			p.records = append(p.records, rec)
		case nsec3OverTheLimit:
			p.setAside = true
		}
	}
	return p
}

// nsec3Use is whether an NSEC3 record counts toward a proof.
type nsec3Use int

const (
	nsec3Ignored      nsec3Use = iota // RFC 5155 sections 8.1 and 8.2, or malformed
	nsec3Counts                       // counts
	nsec3OverTheLimit                 // would count, but is over the iteration limit
)

// nsec3Usable reports whether rr counts toward a proof about names in zone
// (RFC 5155 sections 8.1 and 8.2): owned directly below zone, hash algorithm
// SHA-1, flags 0 or 1, a 20-octet hash, and an owner label and next hashed
// owner that decode as base32hex to it. Other records are ignored. One over
// maxIter iterations is set aside (RFC 9276).
func nsec3Usable(zone string, rr *dns.NSEC3, maxIter uint16) (nsec3Record, nsec3Use) {
	if rr == nil || rr.Hash != dns.SHA1 || rr.Flags > 1 || rr.HashLength != nsec3HashLen {
		return nsec3Record{}, nsec3Ignored
	}
	labels := dns.SplitDomainName(rr.Hdr.Name)
	if len(labels) == 0 || !core.EqualNames(parentOf(dns.Fqdn(rr.Hdr.Name)), zone) {
		return nsec3Record{}, nsec3Ignored
	}
	owner, ok := decodeNSEC3Hash(labels[0])
	if !ok {
		return nsec3Record{}, nsec3Ignored
	}
	next, ok := decodeNSEC3Hash(rr.NextDomain)
	if !ok {
		return nsec3Record{}, nsec3Ignored
	}
	salt, err := hex.DecodeString(rr.Salt)
	if err != nil {
		return nsec3Record{}, nsec3Ignored
	}
	if rr.Iterations > maxIter {
		return nsec3Record{}, nsec3OverTheLimit
	}
	return nsec3Record{rr: rr, owner: owner, next: next,
		params: nsec3Params{alg: rr.Hash, iterations: rr.Iterations, salt: string(salt)}}, nsec3Counts
}

// decodeNSEC3Hash decodes a base32hex hash of nsec3HashLen octets, in either
// case.
func decodeNSEC3Hash(s string) ([]byte, bool) {
	b, err := base32hexNoPad.DecodeString(strings.ToUpper(s))
	if err != nil || len(b) != nsec3HashLen {
		return nil, false
	}
	return b, true
}

// nsec3Hash is H(name) under params (RFC 5155 section 5): SHA-1 over the
// name's canonical wire form and the salt, then params.iterations more rounds
// over the digest and the salt. The canonical form folds US-ASCII upper case
// and nothing else (RFC 4034 section 6.2). Every octet of a packed name that
// is an upper-case letter is one: length octets are at most 63.
func nsec3Hash(wire []byte, params nsec3Params) []byte {
	h := sha1.New()
	h.Write(wire)
	h.Write([]byte(params.salt))
	d := h.Sum(nil)
	for i := uint16(0); i < params.iterations; i++ {
		h.Reset()
		h.Write(d)
		h.Write([]byte(params.salt))
		d = h.Sum(d[:0])
	}
	return d
}

// canonicalWire is name in canonical wire form, or false if it does not pack.
func canonicalWire(name string) ([]byte, bool) {
	buf := make([]byte, 256)
	off, err := dns.PackDomainName(dns.Fqdn(name), buf, 0, nil, false)
	if err != nil {
		return nil, false
	}
	buf = buf[:off]
	for i, c := range buf {
		if c >= 'A' && c <= 'Z' {
			buf[i] = c + 'a' - 'A'
		}
	}
	return buf, true
}

// hash is H(name) under params, computed once per proof. It returns nil for
// a name that does not pack, and for one the budget has no room for, which it
// records in p.spent.
func (p *nsec3Proof) hash(name string, params nsec3Params) []byte {
	wire, ok := canonicalWire(name)
	if !ok {
		return nil
	}
	key := string(wire) + "\x00" + string([]byte{params.alg, byte(params.iterations >> 8), byte(params.iterations)}) + params.salt
	if h, ok := p.memo[key]; ok {
		return h
	}
	if p.budget <= 0 {
		p.spent = true
		return nil
	}
	p.budget--
	p.hashes++
	h := nsec3Hash(wire, params)
	p.memo[key] = h
	return h
}

// matching returns the record whose owner is the hash of name, or nil.
func (p *nsec3Proof) matching(name string) *nsec3Record {
	for i := range p.records {
		r := &p.records[i]
		if h := p.hash(name, r.params); h != nil && bytes.Equal(h, r.owner) {
			return r
		}
	}
	return nil
}

// covering returns a record whose interval holds the hash of name, strictly
// (see covers), or nil.
func (p *nsec3Proof) covering(name string) *nsec3Record {
	for i := range p.records {
		r := &p.records[i]
		if h := p.hash(name, r.params); h != nil && covers(r, h) {
			return r
		}
	}
	return nil
}

// covers reports whether h lies strictly between r's owner hash and its next
// hashed owner: the owner exists, so a record never covers its own owner. The
// last record of the chain wraps around (next <= owner), and a chain of one
// record (owner == next) covers every hash but its own.
func covers(r *nsec3Record, h []byte) bool {
	afterOwner := bytes.Compare(h, r.owner) > 0
	beforeNext := bytes.Compare(h, r.next) < 0
	switch c := bytes.Compare(r.owner, r.next); {
	case c == 0:
		return !bytes.Equal(h, r.owner)
	case c < 0:
		return afterOwner && beforeNext
	default:
		return afterOwner || beforeNext
	}
}

// finish turns a proof that did not hold into what the records set aside and
// the budget make of it: a proof that ran out of budget was not judged, and
// one that failed while records over the iteration limit were left out might
// have held with them (RFC 9276).
func (p *nsec3Proof) finish(v nsec3Verdict) nsec3Verdict {
	switch {
	case p.spent:
		return nsec3OverBudget
	case v == nsec3Unproven && p.setAside:
		return nsec3OverLimit
	}
	return v
}

// ceProof is a closest encloser proof (RFC 5155 section 8.3).
type ceProof struct {
	ce    string       // the closest encloser
	nc    string       // the next closer name; "" when ce is qname
	ncRec *nsec3Record // the record covering nc
}

// closestEncloser proves the closest encloser of qname, which is at or below
// p.zone (RFC 5155 section 8.3). It walks up from qname to the zone: the
// first name that a record matches is the closest encloser, and the name one
// label below it on the way to qname, the next closer name, must be covered.
//
// A closest encloser whose record has DNAME speaks for names the zone does
// not hold: Bogus. One with NS and not SOA is a zone cut, and qname lies below
// it: an insecure delegation without DS, Bogus with DS, where the answer
// should have been a referral.
//
// When qname itself is matched, the proof is qname, with no next closer name,
// and the caller decides what that means.
func (p *nsec3Proof) closestEncloser(qname string) (ceProof, nsec3Verdict) {
	nc := ""
	for n := dns.Fqdn(qname); ; n = parentOf(n) {
		if rec := p.matching(n); rec != nil {
			if nc == "" {
				return ceProof{ce: n}, nsec3Proven
			}
			switch {
			case rec.has(dns.TypeDNAME):
				return ceProof{}, nsec3Unproven
			case rec.delegation() && rec.has(dns.TypeDS):
				return ceProof{}, nsec3Unproven
			case rec.delegation():
				return ceProof{ce: n}, nsec3InsecureDelegation
			}
			ncRec := p.covering(nc)
			if ncRec == nil {
				return ceProof{}, nsec3Unproven
			}
			return ceProof{ce: n, nc: nc, ncRec: ncRec}, nsec3Proven
		}
		if p.spent || core.EqualNames(n, p.zone) || n == "." {
			return ceProof{}, nsec3Unproven
		}
		nc = n
	}
}

// inZone reports whether qname is at or below the proof's zone.
func (p *nsec3Proof) inZone(qname string) bool {
	return dns.IsSubDomain(p.zone, dns.Fqdn(qname))
}

// nameError proves that qname does not exist (RFC 5155 section 8.4): a
// closest encloser proof, with qname not matched, and a record covering the
// wildcard at the closest encloser. Through an Opt-Out span it is Insecure
// (section 9.2): an insecure delegation may hide in the span.
func (p *nsec3Proof) nameError(qname string) nsec3Verdict {
	if !p.inZone(qname) {
		return nsec3Unproven
	}
	ce, v := p.closestEncloser(qname)
	switch {
	case v != nsec3Proven:
		return p.finish(v)
	case ce.nc == "":
		// qname is matched: it exists.
		return p.finish(nsec3Unproven)
	}
	if p.covering(wildcardAt(ce.ce)) == nil {
		return p.finish(nsec3Unproven)
	}
	if ce.ncRec.optOut() {
		return nsec3OptOut
	}
	return nsec3Proven
}

// noData proves that qname has no qtype (RFC 5155 sections 8.5 to 8.7).
//
//  1. A record matching qname proves it, unless its bitmap has qtype or
//     CNAME. For a qtype other than DS, a match with NS and not SOA is a
//     delegation whose parent side answered for the child's data: an insecure
//     delegation without DS, Bogus with it. The match's own Opt-Out flag does
//     not matter: it describes the span after the record.
//  2. Otherwise a closest encloser proof is needed. At an insecure delegation
//     it is Insecure, except for DS, which the parent answers.
//  3. A record matching the wildcard at the closest encloser proves it too
//     (section 8.7), with neither qtype nor CNAME in its bitmap and not a
//     delegation.
//  4. Without such a record, a next closer name covered by an Opt-Out span
//     leaves qname possibly an insecure delegation in the span: Insecure. For
//     DS that is section 8.6; for other types the unsigned data below such a
//     delegation can reach the resolver by other paths.
//
// Steps 3 and 4 through Opt-Out are Insecure (section 9.2).
func (p *nsec3Proof) noData(qname string, qtype uint16) nsec3Verdict {
	if !p.inZone(qname) {
		return nsec3Unproven
	}
	if rec := p.matching(qname); rec != nil {
		switch {
		case rec.has(qtype) || rec.has(dns.TypeCNAME):
			return p.finish(nsec3Unproven)
		case qtype == dns.TypeDS:
			return nsec3Proven
		case rec.delegation() && rec.has(dns.TypeDS):
			return p.finish(nsec3Unproven)
		case rec.delegation():
			return nsec3InsecureDelegation
		}
		return nsec3Proven
	}
	if p.spent {
		return nsec3OverBudget
	}
	// qname is not matched, so a proof has a next closer name.
	ce, v := p.closestEncloser(qname)
	switch {
	case v == nsec3InsecureDelegation && qtype != dns.TypeDS:
		return v
	case v == nsec3InsecureDelegation:
		return p.finish(nsec3Unproven)
	case v != nsec3Proven || ce.nc == "":
		return p.finish(v)
	}
	if rec := p.matching(wildcardAt(ce.ce)); rec != nil {
		if rec.has(qtype) || rec.has(dns.TypeCNAME) || rec.delegation() {
			return p.finish(nsec3Unproven)
		}
		if ce.ncRec.optOut() {
			return nsec3OptOut
		}
		return nsec3Proven
	}
	if p.spent {
		return nsec3OverBudget
	}
	if ce.ncRec.optOut() {
		return nsec3OptOut
	}
	return p.finish(nsec3Unproven)
}

// wildcardAnswer proves that an answer for qname synthesised from a wildcard
// is the right one (RFC 5155 section 8.8). labels is the Labels field of the
// answer's RRSIG: the wildcard's closest encloser is qname's last labels
// labels, and a record must cover the next closer name, one label longer.
// Through an Opt-Out span it is Insecure (section 9.2).
func (p *nsec3Proof) wildcardAnswer(qname string, labels uint8) nsec3Verdict {
	qname = dns.Fqdn(qname)
	ql := dns.SplitDomainName(qname)
	if int(labels) >= len(ql) {
		return nsec3Unproven
	}
	ce := lastLabels(ql, int(labels))
	if !p.inZone(ce) {
		return nsec3Unproven
	}
	rec := p.covering(lastLabels(ql, int(labels)+1))
	if rec == nil {
		return p.finish(nsec3Unproven)
	}
	if rec.optOut() {
		return nsec3OptOut
	}
	return nsec3Proven
}

// lastLabels is the name made of the last n labels.
func lastLabels(labels []string, n int) string {
	if n <= 0 {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[len(labels)-n:], "."))
}
