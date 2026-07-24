/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package tdns

// Outbound IXFR (RFC 1995), Project C: delta retention at the publish choke
// point plus incremental serving from the pinned snapshot.
//
// Invariants (docs/2026-07-02-ixfr-support.md):
//   - IXFR is never a correctness dependency: any doubt (unknown serial,
//     non-contiguous chain, same-serial content change, serial regression,
//     over-budget history, UDP) degrades to the full-transfer path or a
//     single-SOA answer. The worst case is a wasteful transfer, never a
//     wrong delta.
//   - Serving reads ONLY the pinned snapshot (snap.IxfrChain / snap.SOA /
//     snap.Data), so a concurrent publish cannot tear a response.
//   - Chain order is newest-last; contiguity holds by construction at append
//     time and is re-verified at serve time.
//   - No bare SOA RR ever appears inside a link's Removed/Added: the
//     bracketing FromSOA/ToSOA carry the SOA change, and client-side framing
//     counts SOA records to delimit difference sequences. Apex SOA RRSIGs are
//     ordinary diff content.

import (
	"net"
	"sort"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

const (
	// DefaultIxfrChainMaxBytes bounds the per-zone retained delta history
	// (estimated wire bytes) when ixfr-chain-max-bytes is unset.
	DefaultIxfrChainMaxBytes = 1 << 20 // 1 MiB
	// ixfrChainMaxLinks is a defensive secondary cap on chain length.
	ixfrChainMaxLinks = 512
)

// serialNewer reports whether serial a is newer than b in RFC 1982 serial
// arithmetic. Equal serials are not newer; the undefined half-way distance
// (2^31) reports not-newer in both directions, so callers degrade
// conservatively (single-SOA answer rather than a transfer).
func serialNewer(a, b uint32) bool {
	d := a - b
	return d != 0 && d < year68
}

// ixfrBudget returns the effective retention budget for the zone:
// 0/unset => default; negative => retention disabled.
func (zd *ZoneData) ixfrBudget() int {
	if zd.ixfrChainMaxBytes == 0 {
		return DefaultIxfrChainMaxBytes
	}
	return zd.ixfrChainMaxBytes
}

// updateIxfrChainLocked maintains zd.IxfrChain across one publish: called
// under zd.mu from publishWorkingSetLocked immediately before the snapshot is
// built, so the chain copied into the new snapshot always ends exactly at the
// new snapshot's serial. old is the currently-published snapshot; newSerial /
// newData describe the snapshot about to be built.
func (zd *ZoneData) updateIxfrChainLocked(old *zoneSnapshot, newSerial uint32, newData map[string]*OwnerData) {
	epochReset := zd.wsIxfrEpochReset
	zd.wsIxfrEpochReset = false

	budget := zd.ixfrBudget()
	if budget < 0 {
		zd.IxfrChain = nil // retention disabled for this zone
		return
	}
	if epochReset || old == nil || old.SOA == nil {
		// Wholesale replace (refresh/reload/AXFR-in) or no baseline: new
		// epoch. A replace has no meaningful delta; do not diff it.
		zd.IxfrChain = nil
		return
	}
	newSOA := soaFromApex(newSerial, apexFromSnapshotData(zd, newData))
	if newSOA == nil {
		// Callers refuse apex-less swaps before this point; belt and braces.
		zd.IxfrChain = nil
		return
	}

	removed, added, est := computeZoneDelta(zd.ZoneName, old.Data, newData)

	if newSerial == old.Serial {
		if len(removed) == 0 && len(added) == 0 {
			return // nothing changed (e.g. signalSynth-only publish): keep history
		}
		// Content changed under an unchanged serial: "serial N" is now
		// ambiguous, so any delta through this point could be wrong for some
		// downstream. Drop history; serve full transfers until it rebuilds.
		lg.Error("ixfr: zone content changed without a serial bump; resetting IXFR history",
			"zone", zd.ZoneName, "serial", newSerial)
		zd.IxfrChain = nil
		return
	}
	if !serialNewer(newSerial, old.Serial) {
		lg.Error("ixfr: outbound serial did not advance (RFC 1982); resetting IXFR history",
			"zone", zd.ZoneName, "old", old.Serial, "new", newSerial)
		zd.IxfrChain = nil
		return
	}

	// An empty delta still appends a link: a serial-only advance (e.g.
	// outbound_soa_serial=unixtime) is a legal empty difference sequence and
	// keeps the chain contiguous.
	link := Ixfr{
		FromSerial: old.Serial,
		ToSerial:   newSerial,
		FromSOA:    old.SOA, // snapshot-owned; immutable by the B invariant
		ToSOA:      newSOA,  // fresh copy from soaFromApex
		Removed:    removed,
		Added:      added,
		EstBytes:   est + estimateRRSize(old.SOA) + estimateRRSize(newSOA),
	}
	if link.EstBytes > budget {
		lg.Warn("ixfr: single delta exceeds ixfr-chain-max-bytes; resetting IXFR history",
			"zone", zd.ZoneName, "delta_bytes", link.EstBytes, "budget", budget)
		zd.IxfrChain = nil
		return
	}

	chain := append(zd.IxfrChain, link)
	total := 0
	for i := range chain {
		total += chain[i].EstBytes
	}
	start := 0
	for total > budget || len(chain)-start > ixfrChainMaxLinks {
		total -= chain[start].EstBytes
		start++
	}
	if start > 0 {
		// Fresh backing array so trimmed links do not linger via slice aliasing.
		chain = append([]Ixfr(nil), chain[start:]...)
	}
	zd.IxfrChain = chain
}

// computeZoneDelta returns the RR-level difference between two snapshot owner
// maps plus an estimated wire size. It leans on the copy-on-write publish
// discipline: an owner whose *OwnerData pointer is unchanged was not touched
// by any stager, so only changed owners are content-compared. The apex SOA
// RRs are excluded (the IXFR brackets carry the SOA change); apex SOA RRSIGs
// are included. Output is sorted by owner name then type for determinism.
func computeZoneDelta(zoneName string, oldData, newData map[string]*OwnerData) (removed, added []core.RRset, est int) {
	type ownerPair struct {
		name     string
		old, new *OwnerData
	}
	var pairs []ownerPair
	for name, nod := range newData {
		ood := oldData[name]
		if ood == nod {
			continue // COW: identical pointer == untouched owner
		}
		pairs = append(pairs, ownerPair{name, ood, nod})
	}
	for name, ood := range oldData {
		if _, ok := newData[name]; !ok {
			pairs = append(pairs, ownerPair{name, ood, nil})
		}
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].name < pairs[j].name })

	for _, p := range pairs {
		rem, add, sz := diffOwner(zoneName, p.name, p.old, p.new)
		removed = append(removed, rem...)
		added = append(added, add...)
		est += sz
	}
	return removed, added, est
}

func ownerTypes(od *OwnerData) []uint16 {
	if od == nil || od.RRtypes == nil {
		return nil
	}
	return od.RRtypes.Keys()
}

func ownerRRset(od *OwnerData, t uint16) core.RRset {
	if od == nil || od.RRtypes == nil {
		return core.RRset{}
	}
	return od.RRtypes.GetOnlyRRSet(t)
}

// diffOwner computes per-RRset removed/added RRs for one owner name. Either
// side may be nil (owner added or deleted).
func diffOwner(zoneName, name string, old, new *OwnerData) (removed, added []core.RRset, est int) {
	types := map[uint16]bool{}
	for _, t := range ownerTypes(old) {
		types[t] = true
	}
	for _, t := range ownerTypes(new) {
		types[t] = true
	}
	sorted := make([]uint16, 0, len(types))
	for t := range types {
		sorted = append(sorted, t)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	apexSOA := name == zoneName
	for _, t := range sorted {
		ors := ownerRRset(old, t)
		nrs := ownerRRset(new, t)
		if rrsetEqual(ors, nrs) {
			continue
		}
		remRRs, addRRs := rrDiff(ors.RRs, nrs.RRs)
		remSigs, addSigs := rrDiff(ors.RRSIGs, nrs.RRSIGs)
		if apexSOA && t == dns.TypeSOA {
			// The bracketing FromSOA/ToSOA carry the SOA change on the wire;
			// a bare SOA inside a diff section would break client framing.
			remRRs, addRRs = nil, nil
		}
		if len(remRRs) > 0 || len(remSigs) > 0 {
			rs := core.RRset{Name: name, Class: dns.ClassINET, RRtype: t, RRs: remRRs, RRSIGs: remSigs}
			removed = append(removed, rs)
			est += rrsetWireEstimate(rs)
		}
		if len(addRRs) > 0 || len(addSigs) > 0 {
			rs := core.RRset{Name: name, Class: dns.ClassINET, RRtype: t, RRs: addRRs, RRSIGs: addSigs}
			added = append(added, rs)
			est += rrsetWireEstimate(rs)
		}
	}
	return removed, added, est
}

// rrDiff returns the string-keyed set difference between two RR slices:
// RRs only in a (removed) and RRs only in b (added). A TTL or RDATA change
// therefore becomes delete-old + add-new, per RFC 1995.
func rrDiff(a, b []dns.RR) (onlyA, onlyB []dns.RR) {
	inA := make(map[string]bool, len(a))
	for _, rr := range a {
		inA[rr.String()] = true
	}
	inB := make(map[string]bool, len(b))
	for _, rr := range b {
		inB[rr.String()] = true
	}
	for _, rr := range a {
		if !inB[rr.String()] {
			onlyA = append(onlyA, rr)
		}
	}
	for _, rr := range b {
		if !inA[rr.String()] {
			onlyB = append(onlyB, rr)
		}
	}
	return onlyA, onlyB
}

func rrsetWireEstimate(rs core.RRset) int {
	sz := 0
	for _, rr := range rs.RRs {
		sz += estimateRRSize(rr)
	}
	for _, rr := range rs.RRSIGs {
		sz += estimateRRSize(rr)
	}
	return sz
}

// --- serving ---

// ixfrQuerySOA returns the SOA the client presented in the IXFR query's
// authority section (the serial it currently holds), or nil.
func ixfrQuerySOA(r *dns.Msg) *dns.SOA {
	if r == nil {
		return nil
	}
	for _, rr := range r.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}
	return nil
}

// ixfrDeltaSteps returns the contiguous run of chain links leading from
// clientSerial to the pinned snapshot's serial, or ok=false when no provable
// path exists (caller then serves a full transfer, RFC 1995 §4).
func ixfrDeltaSteps(snap *zoneSnapshot, clientSerial uint32) (steps []Ixfr, ok bool) {
	if snap == nil || len(snap.IxfrChain) == 0 {
		return nil, false
	}
	chain := snap.IxfrChain
	start := -1
	for i := range chain {
		if chain[i].FromSerial == clientSerial {
			start = i
			break
		}
	}
	if start < 0 {
		return nil, false
	}
	for i := start; i < len(chain); i++ {
		if chain[i].FromSOA == nil || chain[i].ToSOA == nil {
			return nil, false
		}
		if i > start && chain[i].FromSerial != chain[i-1].ToSerial {
			return nil, false
		}
	}
	if chain[len(chain)-1].ToSerial != snap.Serial {
		return nil, false
	}
	return chain[start:], true
}

func soaOnlyRRset(soa *dns.SOA) core.RRset {
	return core.RRset{
		Name:   soa.Hdr.Name,
		Class:  soa.Hdr.Class,
		RRtype: dns.TypeSOA,
		RRs:    []dns.RR{soa},
	}
}

func isUDPTransport(w dns.ResponseWriter) bool {
	if w == nil || w.RemoteAddr() == nil {
		return false
	}
	switch w.RemoteAddr().(type) {
	case *net.UDPAddr:
		return true
	}
	return false
}

// ixfrSingleSOAReply answers an IXFR query with a single SOA at the current
// serial: the up-to-date/client-ahead answer (RFC 1995 §2) and the
// retry-over-TCP signal for UDP (RFC 1995 §4). Signed like the request.
func (zd *ZoneData) ixfrSingleSOAReply(w dns.ResponseWriter, r *dns.Msg, soa *dns.SOA) (int, error) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = []dns.RR{soa}
	signResponseLikeRequest(w, r, m)
	if err := w.WriteMsg(m); err != nil {
		zd.Logger.Printf("ZoneTransferOut: %s: WriteMsg on IXFR single-SOA reply failed: %v",
			dns.Fqdn(zd.ZoneName), err)
		return 0, nil
	}
	return 1, nil
}

// emitIxfrDelta streams the RFC 1995 difference sequences through the shared
// transfer batcher: SOA(cur), then per step FromSOA / removed / ToSOA / added,
// then the trailing SOA(cur) via the same flush-before-trailing treatment as
// the full-transfer path.
func (zd *ZoneData) emitIxfrDelta(bs *batchState, currentSOA *dns.SOA, steps []Ixfr) (int, error) {
	if !appendRRset(bs, soaOnlyRRset(currentSOA)) {
		return 0, nil
	}
	for i := range steps {
		st := &steps[i]
		if !appendRRset(bs, soaOnlyRRset(st.FromSOA)) {
			return 0, nil
		}
		for _, rs := range st.Removed {
			if !appendRRset(bs, rs) {
				return 0, nil
			}
		}
		if !appendRRset(bs, soaOnlyRRset(st.ToSOA)) {
			return 0, nil
		}
		for _, rs := range st.Added {
			if !appendRRset(bs, rs) {
				return 0, nil
			}
		}
	}
	return zd.finishTransferWithTrailingSOA(bs, currentSOA)
}
