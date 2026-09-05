/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

// Package peer is the server side of the relay rig: the rig's own upstream
// primary and downstream secondary, plus the zone model they share.
//
// The rig authors every change itself, so this package is also the ground
// truth the checkers compare against. See
// docs/2026-09-05-notify-semantics-rig.md.
package peer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// Zone is one complete zone version, held as a set of RRs keyed by their
// canonical text. The key carries the TTL, so a TTL-only rewrite is a
// difference this model can see rather than one it silently absorbs.
type Zone struct {
	Origin string
	rrs    map[string]dns.RR
}

func NewZone(origin string) *Zone {
	return &Zone{Origin: dns.Fqdn(origin), rrs: map[string]dns.RR{}}
}

// ZoneFromRRs builds a zone from a transfer or a parsed zone file. Duplicate
// RRs collapse, which is what a receiving server does too.
func ZoneFromRRs(origin string, rrs []dns.RR) *Zone {
	z := NewZone(origin)
	for _, rr := range rrs {
		z.Add(rr)
	}
	return z
}

func (z *Zone) Add(rr dns.RR) {
	z.rrs[CanonicalText(rr)] = dns.Copy(rr)
}

// Remove drops rr and reports whether it was there. The rig removes only
// records it added, so a false return is a rig bug and callers treat it as one.
func (z *Zone) Remove(rr dns.RR) bool {
	k := CanonicalText(rr)
	if _, ok := z.rrs[k]; !ok {
		return false
	}
	delete(z.rrs, k)
	return true
}

func (z *Zone) Len() int { return len(z.rrs) }

func (z *Zone) Clone() *Zone {
	n := &Zone{Origin: z.Origin, rrs: make(map[string]dns.RR, len(z.rrs))}
	for k, rr := range z.rrs {
		n.rrs[k] = dns.Copy(rr)
	}
	return n
}

// RRs returns every RR in canonical-text order. Deterministic rather than
// DNSSEC-canonical: nothing here signs, and a stable order is what makes two
// runs comparable.
func (z *Zone) RRs() []dns.RR {
	keys := make([]string, 0, len(z.rrs))
	for k := range z.rrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]dns.RR, 0, len(keys))
	for _, k := range keys {
		out = append(out, z.rrs[k])
	}
	return out
}

// SOA returns the apex SOA, or nil. A zone without one is not servable and
// every caller that needs a serial checks for it.
func (z *Zone) SOA() *dns.SOA {
	for _, rr := range z.rrs {
		soa, ok := rr.(*dns.SOA)
		if ok && equalName(soa.Hdr.Name, z.Origin) {
			return soa
		}
	}
	return nil
}

func (z *Zone) Serial() uint32 {
	if soa := z.SOA(); soa != nil {
		return soa.Serial
	}
	return 0
}

// SetSerial rewrites the apex SOA serial. The SOA's canonical text is its map
// key, so the old entry has to go before the new one lands.
func (z *Zone) SetSerial(serial uint32) error {
	soa := z.SOA()
	if soa == nil {
		return fmt.Errorf("zone %s has no apex SOA", z.Origin)
	}
	delete(z.rrs, CanonicalText(soa))
	updated := dns.Copy(soa).(*dns.SOA)
	updated.Serial = serial
	z.rrs[CanonicalText(updated)] = updated
	return nil
}

// Change is one authored edit: what the rig removed and added upstream, and
// therefore exactly what must come out the far side (invariant N5).
type Change struct {
	Label  string
	Remove []dns.RR
	Add    []dns.RR
}

func (c Change) String() string {
	var b strings.Builder
	b.WriteString(c.Label)
	for _, rr := range c.Remove {
		fmt.Fprintf(&b, " -[%s]", strings.Join(strings.Fields(rr.String()), " "))
	}
	for _, rr := range c.Add {
		fmt.Fprintf(&b, " +[%s]", strings.Join(strings.Fields(rr.String()), " "))
	}
	return b.String()
}

// Delta is the difference between two consecutive versions, in the shape RFC
// 1995 puts on the wire. The apex SOA is NOT in Removed/Added: it is the
// framing, carried by From and To, and keeping it out is what lets a Delta be
// compared directly against a Change.
type Delta struct {
	From    uint32
	To      uint32
	Removed []dns.RR
	Added   []dns.RR
}

func (d Delta) Empty() bool { return len(d.Removed) == 0 && len(d.Added) == 0 }

// Diff computes the delta from one zone version to the next.
func Diff(from, to *Zone) Delta {
	d := Delta{From: from.Serial(), To: to.Serial()}
	fromKeys := map[string]dns.RR{}
	for k, rr := range from.rrs {
		fromKeys[k] = rr
	}
	for k, rr := range to.rrs {
		if _, ok := fromKeys[k]; ok {
			delete(fromKeys, k)
			continue
		}
		if isApexSOA(rr, to.Origin) {
			continue
		}
		d.Added = append(d.Added, rr)
	}
	for _, rr := range fromKeys {
		if isApexSOA(rr, from.Origin) {
			continue
		}
		d.Removed = append(d.Removed, rr)
	}
	sortRRs(d.Removed)
	sortRRs(d.Added)
	return d
}

// Version is one entry in the upstream's history: the zone as published, and
// the delta that produced it.
type Version struct {
	Serial uint32
	Zone   *Zone
	Delta  Delta // zero-valued for the seed version
	Change Change
}

// History is the upstream peer's ordered version list — the rig's ground
// truth. Capped so a long run does not grow without bound; the cap is also
// what makes the too-old-serial AXFR fallback reachable on purpose.
type History struct {
	Origin   string
	Cap      int
	versions []Version
}

func NewHistory(origin string, capacity int) *History {
	if capacity < 2 {
		capacity = 2
	}
	return &History{Origin: dns.Fqdn(origin), Cap: capacity}
}

// Seed installs the initial version. Any prior history is discarded.
func (h *History) Seed(z *Zone) error {
	if z.SOA() == nil {
		return fmt.Errorf("seed zone %s has no apex SOA", h.Origin)
	}
	h.versions = []Version{{Serial: z.Serial(), Zone: z.Clone(), Change: Change{Label: "seed"}}}
	return nil
}

func (h *History) Current() *Version {
	if len(h.versions) == 0 {
		return nil
	}
	return &h.versions[len(h.versions)-1]
}

func (h *History) Versions() []Version { return h.versions }

// Apply builds the next version from the current one and appends it. The
// serial advances by one; the caller does not choose it, because the whole
// point is to count how many times somebody else's serial advances per one of
// these.
func (h *History) Apply(c Change) (*Version, error) {
	cur := h.Current()
	if cur == nil {
		return nil, fmt.Errorf("history for %s is empty; Seed first", h.Origin)
	}
	next := cur.Zone.Clone()
	for _, rr := range c.Remove {
		if !next.Remove(rr) {
			return nil, fmt.Errorf("change %q removes an RR the zone does not hold: %s", c.Label, rr)
		}
	}
	for _, rr := range c.Add {
		next.Add(rr)
	}
	if err := next.SetSerial(cur.Serial + 1); err != nil {
		return nil, err
	}
	v := Version{
		Serial: next.Serial(),
		Zone:   next,
		Delta:  Diff(cur.Zone, next),
		Change: c,
	}
	h.versions = append(h.versions, v)
	if len(h.versions) > h.Cap {
		h.versions = h.versions[len(h.versions)-h.Cap:]
	}
	return &h.versions[len(h.versions)-1], nil
}

// DeltasSince returns the deltas carrying a client at `serial` up to current.
// ok is false when the serial is unknown or has aged out of the cap, which is
// the caller's signal to answer AXFR instead. A client already at the current
// serial gets ok=true and no deltas — the RFC 1995 "no changes" case.
func (h *History) DeltasSince(serial uint32) (deltas []Delta, ok bool) {
	for i, v := range h.versions {
		if v.Serial != serial {
			continue
		}
		for _, later := range h.versions[i+1:] {
			deltas = append(deltas, later.Delta)
		}
		return deltas, true
	}
	return nil, false
}

func isApexSOA(rr dns.RR, origin string) bool {
	soa, ok := rr.(*dns.SOA)
	return ok && equalName(soa.Hdr.Name, origin)
}

func sortRRs(rrs []dns.RR) {
	sort.Slice(rrs, func(i, j int) bool {
		return CanonicalText(rrs[i]) < CanonicalText(rrs[j])
	})
}
