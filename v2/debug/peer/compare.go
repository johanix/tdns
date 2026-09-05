/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package peer

import (
	"fmt"
	"sort"
	"strings"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// CanonicalText is an RR's identity for every comparison in this package:
// its presentation form with the owner name ASCII-lowercased.
//
// The owner is canonicalised because tdns lowercases names at the index
// boundary (#415/#417), so an owner's case is not preserved end to end and
// comparing it would report a difference that is not one. RDATA is compared
// byte-exactly, INCLUDING any domain names in it — the rig authors its content
// in lowercase, so nothing legitimate differs there, and a case rewrite inside
// RDATA is a finding worth seeing rather than one worth normalising away.
//
// TTL is part of the identity. A zone that comes back with rewritten TTLs is a
// different zone, and this is the level at which to notice.
func CanonicalText(rr dns.RR) string {
	c := dns.Copy(rr)
	h := c.Header()
	h.Name = core.CanonicalizeName(h.Name)
	return c.String()
}

func equalName(a, b string) bool { return core.EqualNames(dns.Fqdn(a), dns.Fqdn(b)) }

// dnssecTypes are the record types a signer owns. They are excluded from
// content comparison (invariant N4): the SUT signs what it receives, so these
// MUST differ between upstream and downstream and their difference says
// nothing about whether the change was carried correctly.
var dnssecTypes = map[uint16]bool{
	dns.TypeRRSIG:      true,
	dns.TypeNSEC:       true,
	dns.TypeNSEC3:      true,
	dns.TypeNSEC3PARAM: true,
	dns.TypeDNSKEY:     true,
	dns.TypeCDS:        true,
	dns.TypeCDNSKEY:    true,
	dns.TypeZONEMD:     true,
}

func IsDNSSECType(t uint16) bool { return dnssecTypes[t] }

// StripDNSSEC drops every signer-owned record.
func StripDNSSEC(rrs []dns.RR) []dns.RR {
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if IsDNSSECType(rr.Header().Rrtype) {
			continue
		}
		out = append(out, rr)
	}
	return out
}

// ZoneDiff is the result of comparing two zone versions for content equality.
type ZoneDiff struct {
	OnlyInA []dns.RR
	OnlyInB []dns.RR
	// SOAMismatch is set when the apex SOAs differ in a field other than
	// SERIAL. A secondary rewrites the serial and nothing else, so any other
	// difference means the SOA did not pass through intact.
	SOAMismatch string
}

func (d ZoneDiff) Equal() bool {
	return len(d.OnlyInA) == 0 && len(d.OnlyInB) == 0 && d.SOAMismatch == ""
}

func (d ZoneDiff) String() string {
	if d.Equal() {
		return "zones are equal (modulo DNSSEC and SOA serial)"
	}
	var b strings.Builder
	if d.SOAMismatch != "" {
		fmt.Fprintf(&b, "SOA differs beyond SERIAL: %s\n", d.SOAMismatch)
	}
	for _, rr := range d.OnlyInA {
		fmt.Fprintf(&b, "  only upstream: %s\n", oneLine(rr))
	}
	for _, rr := range d.OnlyInB {
		fmt.Fprintf(&b, "  only downstream: %s\n", oneLine(rr))
	}
	return strings.TrimRight(b.String(), "\n")
}

// CompareContent decides invariant N4: with signer-owned records removed and
// the apex SOA compared on every field but SERIAL, are these the same zone?
//
// a is conventionally the upstream (what the rig authored) and b the zone the
// SUT serves; the OnlyInA/OnlyInB labels in the report follow that.
func CompareContent(a, b *Zone) ZoneDiff {
	ka := contentRRs(a)
	kb := contentRRs(b)
	var d ZoneDiff
	for k, rr := range ka {
		if _, ok := kb[k]; !ok {
			d.OnlyInA = append(d.OnlyInA, rr)
		}
	}
	for k, rr := range kb {
		if _, ok := ka[k]; !ok {
			d.OnlyInB = append(d.OnlyInB, rr)
		}
	}
	sortRRs(d.OnlyInA)
	sortRRs(d.OnlyInB)
	d.SOAMismatch = compareSOAModuloSerial(a, b)
	return d
}

// contentRRs is the zone reduced to what N4 compares: no signer-owned records,
// no apex SOA (handled separately, because its serial legitimately differs).
func contentRRs(z *Zone) map[string]dns.RR {
	out := make(map[string]dns.RR, len(z.rrs))
	for k, rr := range z.rrs {
		if IsDNSSECType(rr.Header().Rrtype) || isApexSOA(rr, z.Origin) {
			continue
		}
		out[k] = rr
	}
	return out
}

func compareSOAModuloSerial(a, b *Zone) string {
	sa, sb := a.SOA(), b.SOA()
	switch {
	case sa == nil && sb == nil:
		return "neither zone has an apex SOA"
	case sa == nil:
		return "upstream has no apex SOA"
	case sb == nil:
		return "downstream has no apex SOA"
	}
	na := dns.Copy(sa).(*dns.SOA)
	nb := dns.Copy(sb).(*dns.SOA)
	na.Serial, nb.Serial = 0, 0
	ta, tb := CanonicalText(na), CanonicalText(nb)
	if ta == tb {
		return ""
	}
	return fmt.Sprintf("upstream %q vs downstream %q (SERIAL zeroed for the comparison)",
		strings.Join(strings.Fields(ta), " "), strings.Join(strings.Fields(tb), " "))
}

// NetDelta collapses a round's deltas into the single net change they express.
//
// Applied in order, because a record added by one delta and removed by a later
// one nets to nothing and must not appear in either list. That case is not
// hypothetical here: an intermediate published state can carry content a
// subsequent one withdraws.
func NetDelta(deltas []Delta) (removed, added []dns.RR) {
	addedSet := map[string]dns.RR{}
	removedSet := map[string]dns.RR{}
	for _, d := range deltas {
		for _, rr := range d.Removed {
			k := CanonicalText(rr)
			if _, ok := addedSet[k]; ok {
				delete(addedSet, k)
				continue
			}
			removedSet[k] = rr
		}
		for _, rr := range d.Added {
			k := CanonicalText(rr)
			if _, ok := removedSet[k]; ok {
				delete(removedSet, k)
				continue
			}
			addedSet[k] = rr
		}
	}
	for _, rr := range removedSet {
		removed = append(removed, rr)
	}
	for _, rr := range addedSet {
		added = append(added, rr)
	}
	sortRRs(removed)
	sortRRs(added)
	return removed, added
}

// DeltaDiff is the result of checking a round's deltas against the change the
// rig authored (invariant N5).
type DeltaDiff struct {
	MissingAdds    []dns.RR // the change added it; the deltas did not carry it
	ExtraAdds      []dns.RR // the deltas carried an addition the change did not make
	MissingRemoves []dns.RR
	ExtraRemoves   []dns.RR
}

func (d DeltaDiff) Equal() bool {
	return len(d.MissingAdds) == 0 && len(d.ExtraAdds) == 0 &&
		len(d.MissingRemoves) == 0 && len(d.ExtraRemoves) == 0
}

func (d DeltaDiff) String() string {
	if d.Equal() {
		return "deltas express exactly the authored change"
	}
	var b strings.Builder
	for _, rr := range d.MissingAdds {
		fmt.Fprintf(&b, "  add not carried: %s\n", oneLine(rr))
	}
	for _, rr := range d.ExtraAdds {
		fmt.Fprintf(&b, "  unexpected add: %s\n", oneLine(rr))
	}
	for _, rr := range d.MissingRemoves {
		fmt.Fprintf(&b, "  removal not carried: %s\n", oneLine(rr))
	}
	for _, rr := range d.ExtraRemoves {
		fmt.Fprintf(&b, "  unexpected removal: %s\n", oneLine(rr))
	}
	return strings.TrimRight(b.String(), "\n")
}

// CompareDelta decides invariant N5: does the net of the deltas the SUT served,
// with signer-owned records removed, equal the change the rig authored?
func CompareDelta(c Change, deltas []Delta) DeltaDiff {
	netRemoved, netAdded := NetDelta(deltas)
	var d DeltaDiff
	d.MissingAdds, d.ExtraAdds = setDiff(c.Add, StripDNSSEC(netAdded))
	d.MissingRemoves, d.ExtraRemoves = setDiff(c.Remove, StripDNSSEC(netRemoved))
	return d
}

// setDiff returns what want has that got does not, and vice versa.
func setDiff(want, got []dns.RR) (missing, extra []dns.RR) {
	wantSet := map[string]dns.RR{}
	for _, rr := range want {
		wantSet[CanonicalText(rr)] = rr
	}
	gotSet := map[string]dns.RR{}
	for _, rr := range got {
		gotSet[CanonicalText(rr)] = rr
	}
	for k, rr := range wantSet {
		if _, ok := gotSet[k]; !ok {
			missing = append(missing, rr)
		}
	}
	for k, rr := range gotSet {
		if _, ok := wantSet[k]; !ok {
			extra = append(extra, rr)
		}
	}
	sortRRs(missing)
	sortRRs(extra)
	return missing, extra
}

// oneLine collapses an RR's tab-separated presentation form so a report line
// stays readable in a terminal.
func oneLine(rr dns.RR) string { return strings.Join(strings.Fields(rr.String()), " ") }

// SortedTexts is the canonical-text view of a set of RRs, for tests and for
// dumping a zone into a report.
func SortedTexts(rrs []dns.RR) []string {
	out := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		out = append(out, CanonicalText(rr))
	}
	sort.Strings(out)
	return out
}
