/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package peer

import (
	"fmt"

	"github.com/miekg/dns"
)

// TransferKind is what a server actually answered, which for an IXFR request
// is not what was asked. Recording it is the point: every scenario converges
// just as well over AXFR, so a delta path that has quietly stopped working
// shows up as nothing but green unless the fallback is counted.
type TransferKind string

const (
	KindAXFR        TransferKind = "axfr"     // whole zone, as requested
	KindIXFR        TransferKind = "ixfr"     // incremental, as requested
	KindFallback    TransferKind = "fallback" // IXFR requested, whole zone answered
	KindUpToDate    TransferKind = "uptodate" // IXFR requested, single SOA answered
	KindUnparseable TransferKind = "bad"
)

// TransferResult is a parsed transfer stream.
type TransferResult struct {
	Kind   TransferKind
	Serial uint32  // the serial the stream's framing SOA carries
	Deltas []Delta // incremental answers only
	Zone   *Zone   // whole-zone answers only
}

// ParseTransfer decodes an AXFR or IXFR response stream.
//
// requestedIXFR distinguishes the two whole-zone cases: an AXFR that was asked
// for, and an AXFR that arrived because the server would not or could not
// answer incrementally. They are the same bytes and very different findings.
func ParseTransfer(origin string, rrs []dns.RR, requestedIXFR bool) (TransferResult, error) {
	res := TransferResult{Kind: KindUnparseable}
	if len(rrs) == 0 {
		return res, fmt.Errorf("transfer of %s carried no records", origin)
	}
	first, ok := rrs[0].(*dns.SOA)
	if !ok {
		return res, fmt.Errorf("transfer of %s does not open with an SOA", origin)
	}
	res.Serial = first.Serial

	if len(rrs) == 1 {
		if !requestedIXFR {
			return res, fmt.Errorf("AXFR of %s returned a bare SOA", origin)
		}
		res.Kind = KindUpToDate
		return res, nil
	}

	// Incremental iff a difference sequence follows the opening SOA. The one
	// ambiguous stream is a whole zone consisting of nothing but its apex SOA
	// ([SOA, SOA]) — not servable, and not something the rig ever authors, but
	// cheap to exclude rather than misparse.
	_, secondIsSOA := rrs[1].(*dns.SOA)
	if !secondIsSOA || len(rrs) == 2 {
		res.Kind = KindAXFR
		if requestedIXFR {
			res.Kind = KindFallback
		}
		res.Zone = ZoneFromRRs(origin, rrs)
		return res, nil
	}

	last, ok := rrs[len(rrs)-1].(*dns.SOA)
	if !ok {
		return res, fmt.Errorf("IXFR of %s does not close with an SOA", origin)
	}
	if last.Serial != first.Serial {
		return res, fmt.Errorf("IXFR of %s is framed by mismatched serials %d and %d",
			origin, first.Serial, last.Serial)
	}

	deltas, err := parseSequences(origin, rrs[1:len(rrs)-1])
	if err != nil {
		return res, err
	}
	res.Kind = KindIXFR
	res.Deltas = deltas
	return res, nil
}

// parseSequences reads the RFC 1995 §4 body: repeated (old SOA, deletions,
// new SOA, additions).
func parseSequences(origin string, body []dns.RR) ([]Delta, error) {
	var deltas []Delta
	i := 0
	for i < len(body) {
		from, ok := body[i].(*dns.SOA)
		if !ok {
			return nil, fmt.Errorf("IXFR of %s: difference sequence %d does not start with an SOA",
				origin, len(deltas)+1)
		}
		i++
		removed, i2 := runUntilSOA(body, i)
		if i2 >= len(body) {
			return nil, fmt.Errorf("IXFR of %s: difference sequence %d has no closing SOA",
				origin, len(deltas)+1)
		}
		to := body[i2].(*dns.SOA)
		i = i2 + 1
		added, i3 := runUntilSOA(body, i)
		i = i3
		deltas = append(deltas, Delta{
			From: from.Serial, To: to.Serial, Removed: removed, Added: added,
		})
	}
	return deltas, nil
}

// runUntilSOA collects records from i up to (not including) the next SOA.
func runUntilSOA(body []dns.RR, i int) ([]dns.RR, int) {
	var out []dns.RR
	for ; i < len(body); i++ {
		if _, ok := body[i].(*dns.SOA); ok {
			break
		}
		out = append(out, body[i])
	}
	return out, i
}
