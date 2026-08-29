/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 *
 * Inbound IXFR (RFC 1995), the client side: parse a difference sequence and
 * apply it to the copy we hold. Project C2, per
 * docs/2026-07-25-inbound-ixfr-plan.md.
 *
 * The one invariant everything here serves (§1 of that plan): AXFR fallback is
 * always available and IXFR-in is never a correctness dependency. Every doubt
 * -- a malformed stream, a non-contiguous serial, a delete that does not match,
 * an RRset left unsigned -- resolves to an error, and the caller re-pulls a
 * full zone. The worst case of a bug in this file is a wasteful transfer, never
 * a corrupt local zone.
 */
package tdns

import (
	"fmt"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// ixfrStep is one RFC 1995 difference sequence: everything that has to be
// removed from serial `from`, and everything added, to arrive at `to`.
type ixfrStep struct {
	from    uint32
	to      uint32
	removed []dns.RR
	added   []dns.RR
}

// parseIxfrDeltas turns the flat RR stream of an IXFR response into ordered
// difference sequences.
//
// The shape, matching #328's own outbound emission:
//
//	SOA(S)                                   leading, S = server's current serial
//	  SOA(from_1) del_1…  SOA(to_1) add_1…   difference sequence 1
//	  SOA(from_2) del_2…  SOA(to_2) add_2…   difference sequence 2 (from_2 == to_1)
//	  …
//	SOA(S)                                   trailing bookend, to_last == S
//
// Section-boundary SOAs are DELIMITERS, not members of the section they open.
// That is what RFC 1995 means, and it is why the caller has to replace the apex
// SOA itself once the steps are applied (see applyIxfrSteps): nothing in here
// ever puts an SOA into `removed` or `added`.
//
// Which SOA is which is decided positionally, not by serial: after a delete
// section's RRs, the next SOA opens the add section; after an add section's
// RRs, the next SOA either opens the following sequence or is the trailing
// bookend, and it is the bookend exactly when it is the last RR. Serials are
// then checked against that structure rather than used to derive it, so a
// primary that repeats a serial cannot make us mis-slice the stream.
//
// Any violation is an error. The caller re-pulls via AXFR.
func parseIxfrDeltas(zoneName string, rrs []dns.RR, clientSerial uint32) ([]ixfrStep, error) {
	// Two leading SOAs are what IsIxfr tests for, so a caller that classified
	// correctly cannot get here with fewer than three RRs. Checked anyway: this
	// function indexes both ends.
	if len(rrs) < 3 {
		return nil, fmt.Errorf("ixfr %s: %d RRs is too short to be a difference stream", zoneName, len(rrs))
	}
	first, ok := rrs[0].(*dns.SOA)
	if !ok {
		return nil, fmt.Errorf("ixfr %s: stream does not start with an SOA", zoneName)
	}
	last, ok := rrs[len(rrs)-1].(*dns.SOA)
	if !ok {
		return nil, fmt.Errorf("ixfr %s: stream does not end with an SOA", zoneName)
	}
	target := first.Serial
	if last.Serial != target {
		return nil, fmt.Errorf("ixfr %s: bookend serials disagree: leading %d, trailing %d",
			zoneName, target, last.Serial)
	}

	// Collect the run of non-SOA RRs starting at i, stopping at the next SOA.
	// The trailing bookend guarantees a terminator exists, so this cannot run
	// off the end.
	collect := func(i int) ([]dns.RR, int) {
		var out []dns.RR
		for i < len(rrs) {
			if _, isSOA := rrs[i].(*dns.SOA); isSOA {
				break
			}
			out = append(out, rrs[i])
			i++
		}
		return out, i
	}

	var steps []ixfrStep
	i := 1
	for i < len(rrs)-1 {
		fromSOA, ok := rrs[i].(*dns.SOA)
		if !ok {
			// Reachable only if the caller skipped classification: a stream
			// whose second RR is not an SOA is a full zone (RFC 1995 §4), and
			// IsIxfr exists to route it elsewhere.
			return nil, fmt.Errorf("ixfr %s: expected an SOA opening a delete section at RR %d, got %s",
				zoneName, i, dns.TypeToString[rrs[i].Header().Rrtype])
		}
		i++
		removed, next := collect(i)
		i = next

		// The add-section SOA cannot be the trailing bookend: something has to
		// close the stream after it. A delete section that runs straight into
		// the bookend is a truncated sequence.
		if i >= len(rrs)-1 {
			return nil, fmt.Errorf("ixfr %s: delete section for serial %d is not followed by an add section",
				zoneName, fromSOA.Serial)
		}
		toSOA, ok := rrs[i].(*dns.SOA)
		if !ok {
			return nil, fmt.Errorf("ixfr %s: expected an SOA opening an add section at RR %d, got %s",
				zoneName, i, dns.TypeToString[rrs[i].Header().Rrtype])
		}
		i++
		added, next := collect(i)
		i = next

		steps = append(steps, ixfrStep{
			from:    fromSOA.Serial,
			to:      toSOA.Serial,
			removed: removed,
			added:   added,
		})
	}

	if len(steps) == 0 {
		return nil, fmt.Errorf("ixfr %s: no difference sequences between the bookends", zoneName)
	}

	// The chain has to start where we are, be contiguous, and end where the
	// primary says it is. Any gap means we would be applying a delta to a base
	// it was not computed against, which is the one thing this must never do.
	if steps[0].from != clientSerial {
		return nil, fmt.Errorf("ixfr %s: first difference sequence starts at serial %d, we hold %d",
			zoneName, steps[0].from, clientSerial)
	}
	for k := 0; k+1 < len(steps); k++ {
		if steps[k].to != steps[k+1].from {
			return nil, fmt.Errorf("ixfr %s: non-contiguous difference sequences: %d→%d followed by %d→%d",
				zoneName, steps[k].from, steps[k].to, steps[k+1].from, steps[k+1].to)
		}
	}
	if final := steps[len(steps)-1].to; final != target {
		return nil, fmt.Errorf("ixfr %s: difference sequences end at serial %d, bookend says %d",
			zoneName, final, target)
	}

	// Out-of-bailiwick adds would land in the zone as names we are not
	// authoritative for. Deletes are not checked: one that names something
	// outside the zone cannot match anything we hold, and applyIxfrSteps
	// already treats a delete that matches nothing as a divergence.
	for _, st := range steps {
		for _, rr := range st.added {
			if !dns.IsSubDomain(zoneName, rr.Header().Name) {
				return nil, fmt.Errorf("ixfr %s: difference sequence %d→%d adds out-of-bailiwick name %s",
					zoneName, st.from, st.to, rr.Header().Name)
			}
		}
	}

	return steps, nil
}

// ixfrTargetSerial is the serial the parsed steps arrive at.
func ixfrTargetSerial(steps []ixfrStep) uint32 {
	if len(steps) == 0 {
		return 0
	}
	return steps[len(steps)-1].to
}

// countIxfrRRs reports how many records the steps move, for logging: a delta
// that turns out to be most of the zone is worth seeing in a log next to the
// AXFR it saved.
func countIxfrRRs(steps []ixfrStep) (removed, added int) {
	for _, st := range steps {
		removed += len(st.removed)
		added += len(st.added)
	}
	return removed, added
}

// rrsetHasSignatures reports whether an RRset carries any RRSIG.
func rrsetHasSignatures(rs core.RRset) bool { return len(rs.RRSIGs) > 0 }
