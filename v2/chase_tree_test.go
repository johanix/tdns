/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// chaseTree is a namespace served from memory to the chaser, answering as a
// validating resolver asked with CD set does: answers with their RRSIGs,
// CNAMEs followed, wildcards expanded, and NSEC denials with the records that
// prove them. Each signed zone has one key, flags 257, that signs everything
// in it; its parent holds its NS and DS. An unsigned zone has neither key nor
// DS, and its parent proves the delegation unsigned with the NSEC at it.
//
// Responses are built for each question, and edits keyed by "qname/TYPE"
// change them on the way out: strip signatures, drop the proof, change a
// record after signing, or answer with another rcode.
type chaseTree struct {
	t     *testing.T
	zones map[string]*treeZone        // by apex, canonical form
	edits map[string][]func(*dns.Msg) // by "qname/TYPE", qname canonical
	fixed map[string]func() *dns.Msg  // responses scripted whole, by "qname/TYPE"
	asked []*dns.Msg                  // the questions, in order
}

type treeZone struct {
	tr   *chaseTree
	apex string
	key  *fwdSecKey                     // nil: unsigned
	data map[string]map[uint16][]dns.RR // owner (canonical) -> type -> records
}

const treeSOA = "%s 300 IN SOA ns.example.net. hostmaster.example.net. 1 7200 1800 604800 300"

// newChaseTree returns a tree holding the signed root zone.
func newChaseTree(t *testing.T) *chaseTree {
	t.Helper()
	tr := &chaseTree{t: t, zones: map[string]*treeZone{}, edits: map[string][]func(*dns.Msg){},
		fixed: map[string]func() *dns.Msg{}}
	tr.zone(".")
	return tr
}

// zone adds a signed zone at apex, delegated from the closest zone above it.
func (tr *chaseTree) zone(apex string) *treeZone { return tr.addZone(apex, true) }

// unsignedZone adds a zone at apex with no key, delegated without a DS.
func (tr *chaseTree) unsignedZone(apex string) *treeZone { return tr.addZone(apex, false) }

func (tr *chaseTree) addZone(apex string, signed bool) *treeZone {
	tr.t.Helper()
	apex = dns.Fqdn(apex)
	parent := tr.zoneAbove(apex)
	z := &treeZone{tr: tr, apex: apex, data: map[string]map[uint16][]dns.RR{}}
	tr.zones[core.CanonicalizeName(apex)] = z
	z.add(fmt.Sprintf(treeSOA, apex), apex+" 300 IN NS ns.example.net.")
	if signed {
		z.key = newFwdSecKey(tr.t, apex)
		z.put(z.key.dnskey)
	}
	if parent != nil {
		parent.add(apex + " 300 IN NS ns.example.net.")
		if signed {
			parent.put(z.key.dnskey.ToDS(dns.SHA256))
		}
	}
	return z
}

// zoneAbove returns the closest zone strictly above name, or nil.
func (tr *chaseTree) zoneAbove(name string) *treeZone {
	for n := dns.Fqdn(name); n != "."; {
		n = treeParent(n)
		if z, ok := tr.zones[core.CanonicalizeName(n)]; ok {
			return z
		}
	}
	return nil
}

// zoneFor returns the zone that answers for name and qtype: the closest zone
// at or above name, or for a DS at a zone apex, the zone above it.
func (tr *chaseTree) zoneFor(name string, qtype uint16) *treeZone {
	for n := dns.Fqdn(name); ; n = treeParent(n) {
		if z, ok := tr.zones[core.CanonicalizeName(n)]; ok {
			if qtype == dns.TypeDS && core.EqualNames(n, name) && n != "." {
				return tr.zoneAbove(n)
			}
			return z
		}
		if n == "." {
			return nil
		}
	}
}

// anchors returns the DS of the root's key, the trust anchor.
func (tr *chaseTree) anchors() []*dns.DS {
	return []*dns.DS{tr.zones["."].key.dnskey.ToDS(dns.SHA256)}
}

// chaser returns a Chaser asking the tree, anchored at the root.
func (tr *chaseTree) chaser() *Chaser { return NewChaser(tr, "192.0.2.1", tr.anchors()) }

// chase runs a chase for qname and qtype and fails the test on an error.
func (tr *chaseTree) chase(qname string, qtype uint16) *ChainResult {
	tr.t.Helper()
	res, err := tr.chaser().Chase(qname, qtype)
	if err != nil {
		tr.t.Fatalf("Chase(%s, %s): %v", qname, dns.TypeToString[qtype], err)
	}
	return res
}

// edit changes the response to qname and qtype on its way out.
func (tr *chaseTree) edit(qname string, qtype uint16, f func(*dns.Msg)) {
	k := treeKey(qname, qtype)
	tr.edits[k] = append(tr.edits[k], f)
}

// script answers qname and qtype with the message f builds, instead of the
// tree's own answer.
func (tr *chaseTree) script(qname string, qtype uint16, f func() *dns.Msg) {
	tr.fixed[treeKey(qname, qtype)] = f
}

func treeKey(qname string, qtype uint16) string {
	return core.CanonicalizeName(dns.Fqdn(qname)) + "/" + dns.TypeToString[qtype]
}

// askedFor reports whether the chaser asked about qname and qtype.
func (tr *chaseTree) askedFor(qname string, qtype uint16) bool {
	for _, m := range tr.asked {
		if q := m.Question[0]; q.Qtype == qtype && core.EqualNames(q.Name, qname) {
			return true
		}
	}
	return false
}

func (tr *chaseTree) TransportKind() core.Transport { return core.TransportDo53 }

func (tr *chaseTree) ExchangeWithResult(msg *dns.Msg, server string, debug bool) (*dns.Msg, time.Duration, core.ExchangeResult, error) {
	r, rtt, err := tr.Exchange(msg, server, debug)
	return r, rtt, core.ExchangeResult{WireTransport: core.TransportDo53}, err
}

func (tr *chaseTree) Exchange(msg *dns.Msg, _ string, _ bool) (*dns.Msg, time.Duration, error) {
	tr.asked = append(tr.asked, msg.Copy())
	q := msg.Question[0]
	k := treeKey(q.Name, q.Qtype)
	var resp *dns.Msg
	if f, ok := tr.fixed[k]; ok {
		resp = f()
	} else {
		resp = new(dns.Msg)
		tr.resolve(resp, q.Name, q.Qtype, 0)
	}
	resp.Id = msg.Id
	resp.Response = true
	resp.RecursionAvailable = true
	resp.CheckingDisabled = msg.CheckingDisabled
	resp.Question = []dns.Question{q}
	for _, f := range tr.edits[k] {
		f(resp)
	}
	return resp, 0, nil
}

// resolve adds the answer for name and qtype to m, following CNAMEs.
func (tr *chaseTree) resolve(m *dns.Msg, name string, qtype uint16, hops int) {
	name = dns.Fqdn(name)
	z := tr.zoneFor(name, qtype)
	if z == nil {
		m.Rcode = dns.RcodeServerFailure
		return
	}
	m.Rcode = dns.RcodeSuccess
	if rrs := z.get(name, qtype); len(rrs) > 0 {
		m.Answer = append(m.Answer, z.sign(rrs)...)
		return
	}
	if qtype != dns.TypeCNAME {
		if cn := z.get(name, dns.TypeCNAME); len(cn) > 0 {
			m.Answer = append(m.Answer, z.sign(cn)...)
			if hops < 10 {
				tr.resolve(m, cn[0].(*dns.CNAME).Target, qtype, hops+1)
			}
			return
		}
	}
	if wild := "*." + z.closestEncloser(name); !z.exists(name) && z.owns(wild) {
		cover := z.sign([]dns.RR{z.nsec(z.prev(name))})
		if rrs := z.get(wild, qtype); len(rrs) > 0 {
			// An answer synthesized from the wildcard, with the NSEC that
			// shows name does not exist.
			m.Answer = append(m.Answer, expand(z.sign(rrs), name)...)
			if z.key != nil {
				m.Ns = append(m.Ns, cover...)
			}
			return
		}
		// The wildcard has no qtype: no data, shown by the NSEC covering
		// name and the wildcard's own.
		m.Ns = append(m.Ns, z.sign(z.get(z.apex, dns.TypeSOA))...)
		if z.key != nil {
			m.Ns = append(append(m.Ns, cover...), z.sign([]dns.RR{z.nsec(wild)})...)
		}
		return
	}
	z.deny(m, name)
}

// expand renames the records and RRSIGs of a signed wildcard RRset to name,
// as a server answering from the wildcard does: the RRSIG keeps its Labels.
func expand(rrs []dns.RR, name string) []dns.RR {
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		c := dns.Copy(rr)
		c.Header().Name = name
		out = append(out, c)
	}
	return out
}

// deny adds the denial for name to m: the SOA and, in a signed zone, the NSEC
// at name, or for a name that does not exist the NSECs covering it and the
// wildcard at its closest encloser.
func (z *treeZone) deny(m *dns.Msg, name string) {
	m.Ns = append(m.Ns, z.sign(z.get(z.apex, dns.TypeSOA))...)
	if z.exists(name) {
		if z.key != nil {
			owner := name
			if !z.owns(name) {
				owner = z.prev(name) // an empty non-terminal: the NSEC covering it
			}
			m.Ns = append(m.Ns, z.sign([]dns.RR{z.nsec(owner)})...)
		}
		return
	}
	m.Rcode = dns.RcodeNameError
	if z.key == nil {
		return
	}
	cover := z.prev(name)
	m.Ns = append(m.Ns, z.sign([]dns.RR{z.nsec(cover)})...)
	if wc := z.prev("*." + z.closestEncloser(name)); !core.EqualNames(wc, cover) {
		m.Ns = append(m.Ns, z.sign([]dns.RR{z.nsec(wc)})...)
	}
}

// add puts records, in presentation format, in the zone.
func (z *treeZone) add(rrs ...string) *treeZone {
	z.tr.t.Helper()
	for _, s := range rrs {
		rr, err := dns.NewRR(s)
		if err != nil {
			z.tr.t.Fatalf("NewRR(%q): %v", s, err)
		}
		z.put(rr)
	}
	return z
}

func (z *treeZone) put(rr dns.RR) {
	owner := core.CanonicalizeName(rr.Header().Name)
	if z.data[owner] == nil {
		z.data[owner] = map[uint16][]dns.RR{}
	}
	z.data[owner][rr.Header().Rrtype] = append(z.data[owner][rr.Header().Rrtype], rr)
}

// get returns copies of the records of rrtype that name owns.
func (z *treeZone) get(name string, rrtype uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range z.data[core.CanonicalizeName(dns.Fqdn(name))][rrtype] {
		out = append(out, dns.Copy(rr))
	}
	return out
}

// sign returns rrs followed by their RRSIG, or rrs alone in an unsigned zone.
func (z *treeZone) sign(rrs []dns.RR) []dns.RR {
	if z.key == nil || len(rrs) == 0 {
		return rrs
	}
	return z.key.sign(z.tr.t, rrs...)
}

// owns reports whether name owns records in the zone.
func (z *treeZone) owns(name string) bool {
	return len(z.data[core.CanonicalizeName(dns.Fqdn(name))]) > 0
}

// exists reports whether name owns records in the zone or is an empty
// non-terminal above names that do.
func (z *treeZone) exists(name string) bool {
	if z.owns(name) {
		return true
	}
	for owner := range z.data {
		if dns.IsSubDomain(name, owner) {
			return true
		}
	}
	return false
}

// closestEncloser is the closest name above name that exists in the zone.
func (z *treeZone) closestEncloser(name string) string {
	for n := treeParent(dns.Fqdn(name)); ; n = treeParent(n) {
		if z.exists(n) || core.EqualNames(n, z.apex) || n == "." {
			return n
		}
	}
}

// owners returns the names that own records in the zone, in canonical order.
func (z *treeZone) owners() []string {
	var out []string
	for owner := range z.data {
		out = append(out, owner)
	}
	slices.SortFunc(out, treeCompare)
	return out
}

// prev returns the owner that is name or sorts last before it, wrapping
// around to the last owner.
func (z *treeZone) prev(name string) string {
	owners := z.owners()
	found := owners[len(owners)-1]
	for _, o := range owners {
		if treeCompare(o, name) > 0 {
			break
		}
		found = o
	}
	return found
}

// nsec is the NSEC at owner: the next owner, and owner's types with RRSIG and
// NSEC.
func (z *treeZone) nsec(owner string) *dns.NSEC {
	owners := z.owners()
	next := owners[0]
	for i, o := range owners {
		if core.EqualNames(o, owner) && i+1 < len(owners) {
			next = owners[i+1]
		}
	}
	types := []uint16{dns.TypeRRSIG, dns.TypeNSEC}
	for t := range z.data[core.CanonicalizeName(owner)] {
		types = append(types, t)
	}
	slices.Sort(types)
	return &dns.NSEC{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: next, TypeBitMap: slices.Compact(types)}
}

// treeCompare orders names canonically (RFC 4034 section 6.1), for the names
// these tests use.
func treeCompare(a, b string) int {
	al := dns.SplitDomainName(strings.ToLower(dns.Fqdn(a)))
	bl := dns.SplitDomainName(strings.ToLower(dns.Fqdn(b)))
	for i, j := len(al)-1, len(bl)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if c := strings.Compare(al[i], bl[j]); c != 0 {
			return c
		}
	}
	return len(al) - len(bl)
}

// treeParent is the name one label up; the root is its own.
func treeParent(name string) string {
	labels := dns.SplitDomainName(name)
	if len(labels) <= 1 {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[1:], "."))
}

// Edits.

// stripSigs removes the RRSIGs over covered from every section.
func stripSigs(covered uint16) func(*dns.Msg) {
	keep := func(rrs []dns.RR) []dns.RR {
		return slices.DeleteFunc(rrs, func(rr dns.RR) bool {
			sig, ok := rr.(*dns.RRSIG)
			return ok && sig.TypeCovered == covered
		})
	}
	return func(m *dns.Msg) { m.Answer, m.Ns = keep(m.Answer), keep(m.Ns) }
}

// dropProof removes the NSEC and NSEC3 records, and their RRSIGs, from the
// authority section.
func dropProof(m *dns.Msg) {
	m.Ns = slices.DeleteFunc(m.Ns, func(rr dns.RR) bool {
		if sig, ok := rr.(*dns.RRSIG); ok {
			return sig.TypeCovered == dns.TypeNSEC || sig.TypeCovered == dns.TypeNSEC3
		}
		t := rr.Header().Rrtype
		return t == dns.TypeNSEC || t == dns.TypeNSEC3
	})
}

// changeRR applies f to every record of rrtype in the response, after it was
// signed.
func changeRR(rrtype uint16, f func(dns.RR)) func(*dns.Msg) {
	return func(m *dns.Msg) {
		for _, sec := range [][]dns.RR{m.Answer, m.Ns} {
			for _, rr := range sec {
				if rr.Header().Rrtype == rrtype {
					f(rr)
				}
			}
		}
	}
}

// rcodeOnly answers with rcode and empty sections.
func rcodeOnly(rcode int) func(*dns.Msg) {
	return func(m *dns.Msg) { m.Rcode, m.Answer, m.Ns, m.Extra = rcode, nil, nil, nil }
}

// linkNamed returns the link for zone in links, or nil.
func linkNamed(links []ChainLink, zone string) *ChainLink {
	for i := range links {
		if core.EqualNames(links[i].Zone, zone) {
			return &links[i]
		}
	}
	return nil
}

// zonesOf lists the zones of links.
func zonesOf(links []ChainLink) []string {
	var out []string
	for _, l := range links {
		out = append(out, l.Zone)
	}
	return out
}

// hasNote reports whether one of notes contains s.
func hasNote(notes []string, s string) bool {
	for _, n := range notes {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}
