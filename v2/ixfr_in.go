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
	"context"
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

// signedKey identifies an RRset that carried signatures in the copy we started
// from, so applyIxfrSteps can tell "this delta legitimately removed the last
// RR" from "this delta silently stripped the signatures off an RRset that is
// still there".
type signedKey struct {
	owner  string
	rrtype uint16
}

// materializeForIxfr copies the published snapshot into a fresh owner map that
// the delta can be applied to, and reports which RRsets were signed.
//
// The copy is deep, and it must be. RRTypeStore.Get returns core.RRset by
// VALUE, so a store-to-store copy leaves the RRs/RRSIGs slices sharing backing
// arrays with the snapshot that is being served right now -- and removing an RR
// shifts elements inside that shared array. That is the Project B invariant
// snapshotMapFromData exists to protect: a published snapshot is immutable
// while it is published.
//
// OwnerData.NSEC is carried too. It is a field beside RRtypes rather than an
// entry inside it, so an RRtypes-only copy drops the denial chain -- and
// nothing would notice, because the apply would SUCCEED and there would be no
// error to fall back from. The zone would simply be served unsigned-for-denial
// and resolvers would call it bogus.
//
// Deliberately NOT cloneOwner: that reads and writes zd.workingSet, so calling
// it here would mutate the live secondary, and its own RRtypes copy is the
// shallow one described above.
func materializeForIxfr(snap *zoneSnapshot) (*core.NameMap[OwnerData], map[signedKey]bool) {
	out := core.NewNameMap[OwnerData]()
	signed := map[signedKey]bool{}
	if snap == nil {
		return out, signed
	}
	for name, src := range snap.Data {
		if src == nil {
			continue
		}
		nod := OwnerData{Name: src.Name, RRtypes: NewRRTypeStore()}
		for _, t := range src.RRtypes.Keys() {
			rs, ok := src.RRtypes.Get(t)
			if !ok {
				continue
			}
			if len(rs.RRSIGs) > 0 {
				signed[signedKey{owner: core.CanonicalizeName(src.Name), rrtype: t}] = true
			}
			nod.RRtypes.Set(t, cloneRRset(rs))
		}
		nod.NSEC = cloneRRset(src.NSEC)
		out.Set(name, nod)
	}
	return out, signed
}

// removeExact removes one RR from a slice by canonical-duplicate match,
// reporting whether it was found.
//
// Written here rather than reusing core.RRset.RemoveRR for two reasons, both of
// which would be silent: RemoveRR searches only the .RRs slice, so an RRSIG or
// NSEC delete would never match and would be read as divergence; and on a hit
// it clears the whole .RRSIGs list, which would strip an RRset's signatures as
// a side effect of removing one of its records.
func removeExact(rrs []dns.RR, victim dns.RR) ([]dns.RR, bool) {
	for i, rr := range rrs {
		if core.IsDuplicate(rr, victim) {
			return append(rrs[:i:i], rrs[i+1:]...), true
		}
	}
	return rrs, false
}

// applyIxfrSteps applies parsed difference sequences to a materialized copy.
//
// Routing mirrors SortFunc exactly, on the delete side as well as the add side:
// NSEC lands in OwnerData.NSEC, an RRSIG follows the type it covers (NSEC's
// signatures into OwnerData.NSEC.RRSIGs), and everything else into
// RRtypes[type]. Getting the delete side wrong does not corrupt anything -- it
// reads as "delete of a record we do not have" -- but it would abort every
// signed-zone IXFR to AXFR, which is the feature quietly doing nothing for the
// zones it matters most for.
//
// Any delete that does not match is a divergence signal: our base is not the
// base the delta was computed against. Abort, and let the caller re-pull.
func applyIxfrSteps(zoneName string, data *core.NameMap[OwnerData], signed map[signedKey]bool, steps []ixfrStep) error {
	for _, st := range steps {
		for _, rr := range st.removed {
			if err := applyIxfrRemove(data, rr); err != nil {
				return fmt.Errorf("ixfr %s: sequence %d→%d: %w", zoneName, st.from, st.to, err)
			}
		}
		for _, rr := range st.added {
			applyIxfrAdd(data, rr)
		}
		// Per step, not once at the end: a later step may legitimately delete
		// the last RR of an RRset this step left unsigned, and then there is
		// nothing to complain about any more. Checking as we go catches the
		// window the served zone would actually have been published in.
		if err := checkSignaturesIntact(zoneName, data, signed); err != nil {
			return fmt.Errorf("ixfr %s: sequence %d→%d: %w", zoneName, st.from, st.to, err)
		}
	}
	return nil
}

func applyIxfrRemove(data *core.NameMap[OwnerData], rr dns.RR) error {
	owner := rr.Header().Name
	nod, ok := data.Get(owner)
	if !ok {
		return fmt.Errorf("delete of %s: no such owner name in the copy we hold", rr.String())
	}

	switch v := rr.(type) {
	case *dns.NSEC:
		out, found := removeExact(nod.NSEC.RRs, rr)
		if !found {
			return fmt.Errorf("delete of %s: not present", rr.String())
		}
		nod.NSEC.RRs = out

	case *dns.RRSIG:
		if v.TypeCovered == dns.TypeNSEC {
			out, found := removeExact(nod.NSEC.RRSIGs, rr)
			if !found {
				return fmt.Errorf("delete of %s: not present", rr.String())
			}
			nod.NSEC.RRSIGs = out
			break
		}
		rs, ok := nod.RRtypes.Get(v.TypeCovered)
		if !ok {
			return fmt.Errorf("delete of %s: no %s RRset to remove a signature from",
				rr.String(), dns.TypeToString[v.TypeCovered])
		}
		out, found := removeExact(rs.RRSIGs, rr)
		if !found {
			return fmt.Errorf("delete of %s: not present", rr.String())
		}
		rs.RRSIGs = out
		nod.RRtypes.Set(v.TypeCovered, rs)

	default:
		rrtype := rr.Header().Rrtype
		rs, ok := nod.RRtypes.Get(rrtype)
		if !ok {
			return fmt.Errorf("delete of %s: no %s RRset at that name",
				rr.String(), dns.TypeToString[rrtype])
		}
		out, found := removeExact(rs.RRs, rr)
		if !found {
			return fmt.Errorf("delete of %s: not present", rr.String())
		}
		rs.RRs = out
		if len(rs.RRs) == 0 {
			// The RRset is gone, and so are the signatures over it. Dropping
			// the type is what keeps a name from lingering with nothing but
			// its own signatures.
			nod.RRtypes.Delete(rrtype)
		} else {
			nod.RRtypes.Set(rrtype, rs)
		}
	}

	// An owner with no RRsets and no denial record has stopped existing.
	if nod.RRtypes.Count() == 0 && len(nod.NSEC.RRs) == 0 {
		data.Remove(owner)
		return nil
	}
	data.Set(owner, nod)
	return nil
}

func applyIxfrAdd(data *core.NameMap[OwnerData], rr dns.RR) {
	owner := rr.Header().Name
	nod, ok := data.Get(owner)
	if !ok {
		nod = OwnerData{Name: owner, RRtypes: NewRRTypeStore()}
	}

	switch v := rr.(type) {
	case *dns.NSEC:
		nod.NSEC.Name, nod.NSEC.RRtype, nod.NSEC.Class = owner, dns.TypeNSEC, dns.ClassINET
		nod.NSEC.RRs = append(nod.NSEC.RRs, rr)

	case *dns.RRSIG:
		if v.TypeCovered == dns.TypeNSEC {
			nod.NSEC.Name, nod.NSEC.RRtype, nod.NSEC.Class = owner, dns.TypeNSEC, dns.ClassINET
			nod.NSEC.RRSIGs = append(nod.NSEC.RRSIGs, rr)
			break
		}
		rs := nod.RRtypes.GetOnlyRRSet(v.TypeCovered)
		rs.RRSIGs = append(rs.RRSIGs, rr)
		nod.RRtypes.Set(v.TypeCovered, rs)

	default:
		rrtype := rr.Header().Rrtype
		rs := nod.RRtypes.GetOnlyRRSet(rrtype)
		rs.Name, rs.RRtype, rs.Class = owner, rrtype, rr.Header().Class
		rs.RRs = append(rs.RRs, rr)
		nod.RRtypes.Set(rrtype, rs)
	}
	data.Set(owner, nod)
}

// checkSignaturesIntact refuses a delta that has left an RRset standing without
// the signatures it had.
//
// This is §1's rule applied to the one failure the invariant does NOT surface.
// A delete that does not match aborts to AXFR and self-heals loudly; an RRset
// silently stripped of its RRSIGs aborts nothing, publishes, and shows up as
// validation failures at other people's resolvers. Re-attaching signatures
// instead would be a second design -- it has to decide what to do when a delta
// legitimately removes the last one -- and is not this project.
func checkSignaturesIntact(zoneName string, data *core.NameMap[OwnerData], signed map[signedKey]bool) error {
	for key := range signed {
		nod, ok := data.Get(key.owner)
		if !ok {
			continue // the whole name went away; nothing is being served unsigned
		}
		rs, ok := nod.RRtypes.Get(key.rrtype)
		if !ok || len(rs.RRs) == 0 {
			continue // the RRset went away with its signatures
		}
		if len(rs.RRSIGs) == 0 {
			return fmt.Errorf("%s %s would be served unsigned: it had signatures before this delta and has none after",
				key.owner, dns.TypeToString[key.rrtype])
		}
	}
	return nil
}

// replaceApexSOA puts the serial the difference sequences arrived at into the
// zone's own apex SOA record.
//
// Not optional, and easy to miss: the parser treats section-boundary SOAs as
// delimiters (correctly, per RFC 1995), so nothing has touched the SOA RR
// sitting in the materialized copy -- it still carries the serial the snapshot
// was taken at. applyRefreshReplacementLocked publishes from this map, so
// without this the zone is served with the OLD SOA while CurrentSerial says the
// new one, which trips the serial-mirror drift check on the next publish and
// hands downstreams a SOA that disagrees with the IXFR brackets we are about to
// append to the outbound chain.
func replaceApexSOA(zoneName string, data *core.NameMap[OwnerData], bookend *dns.SOA) error {
	nod, ok := data.Get(zoneName)
	if !ok {
		return fmt.Errorf("ixfr %s: no apex in the copy after applying the delta", zoneName)
	}
	rs, ok := nod.RRtypes.Get(dns.TypeSOA)
	if !ok || len(rs.RRs) == 0 {
		return fmt.Errorf("ixfr %s: no apex SOA in the copy after applying the delta", zoneName)
	}
	soa := dns.Copy(bookend).(*dns.SOA)
	// Keep the owner spelling and TTL the zone already uses: the delta's
	// bookend is the primary's spelling of the apex, and only its RDATA is
	// being adopted here.
	soa.Hdr = *rs.RRs[0].Header()
	rs.RRs = []dns.RR{soa}
	nod.RRtypes.Set(dns.TypeSOA, rs)
	data.Set(zoneName, nod)
	return nil
}

// ixfrOutcome is the third thing an inbound transfer can be, alongside "failed"
// and "here is a zone".
//
// ZoneTransferIn cannot express it: it wipes zd.Data and returns
// (serial, error), so every non-error return means a zone body arrived and the
// caller decides whether to swap it. An up-to-date IXFR is neither an error nor
// a zone, and signalling it as a sentinel error would be worse than useless --
// FetchFromUpstream reads any error as "try the next primary" and would walk
// the whole list over a perfectly good answer.
type ixfrOutcome int

const (
	// ixfrUpToDate: the primary answered with a single SOA (RFC 1995 §2), so
	// our serial is current. Rare by construction -- the SOA probe already
	// filtered unchanged serials out, and `force` never asks for a delta -- so
	// this means the serial moved back, or changed between probe and request.
	ixfrUpToDate ixfrOutcome = iota
	// ixfrDelta: difference sequences, to be parsed and applied.
	ixfrDelta
	// ixfrFullZone: the primary answered our IXFR with an entire zone, which
	// RFC 1995 §4 explicitly allows. Apply it exactly as an AXFR.
	ixfrFullZone
)

func (o ixfrOutcome) String() string {
	switch o {
	case ixfrUpToDate:
		return "up-to-date"
	case ixfrDelta:
		return "delta"
	case ixfrFullZone:
		return "full-zone"
	}
	return "unknown"
}

// ixfrTransferIn sends an IXFR for the serial we hold and collects the reply as
// a flat RR slice, then classifies it.
//
// Collects rather than streams, and deliberately does NOT touch zd.Data: the
// difference between a delta and a full zone is not knowable until the second
// RR has been seen, and feeding a difference stream through SortFunc would
// silently corrupt the zone -- deleted records appended as additions, bracket
// SOAs dropped. The buffering is IXFR-only; AXFR keeps streaming.
func (zd *ZoneData) ixfrTransferIn(ctx context.Context, up PeerConf, serial uint32, conf *Config) (ixfrOutcome, []dns.RR, error) {
	msg := new(dns.Msg)
	// Root MNAME/RNAME: SetIxfr("", "") packs zero bytes for the empty names,
	// which the primary reads as malformed SOA rdata and FORMERRs. The primary
	// only looks at the serial anyway.
	msg.SetIxfr(zd.ZoneName, serial, ".", ".")

	answerChan, transfer, err := zd.openTransferStream(ctx, up, msg, conf)
	if err != nil {
		return ixfrUpToDate, nil, err
	}

	rrs, err := collectTransferEnvelopes(ctx, zd.ZoneName, up.Addr, answerChan, func() { _ = transfer.Close() })
	if err != nil {
		return ixfrUpToDate, nil, err
	}
	if len(rrs) == 0 {
		return ixfrUpToDate, nil, fmt.Errorf("ixfr %s from %s: empty response", zd.ZoneName, up.Addr)
	}

	// Classification, in the order the shapes can be told apart.
	if len(rrs) == 1 {
		if _, ok := rrs[0].(*dns.SOA); ok {
			return ixfrUpToDate, rrs, nil
		}
		return ixfrUpToDate, nil, fmt.Errorf("ixfr %s from %s: single non-SOA record in response",
			zd.ZoneName, up.Addr)
	}
	if IsIxfr(rrs) {
		return ixfrDelta, rrs, nil
	}
	return ixfrFullZone, rrs, nil
}

// collectTransferEnvelopes drains a transfer stream into a flat RR slice.
//
// Mirrors drainTransferEnvelopes' cancellation contract exactly, and for the
// same reason: dns.Transfer's reader sends on an UNBUFFERED channel, so simply
// stopping receiving parks it forever and leaks the goroutine and its socket.
// Close the connection first, then drain until the reader has sent its final
// envelope and closed.
func collectTransferEnvelopes(ctx context.Context, zoneName, upstream string,
	answerChan <-chan *dns.Envelope, abort func()) ([]dns.RR, error) {

	var out []dns.RR
	for {
		select {
		case <-ctx.Done():
			if abort != nil {
				abort()
			}
			if !drainRemainder(answerChan, transferDrainGrace) {
				lg.Warn("ixfr: transfer reader did not exit after cancellation; goroutine may be retained",
					"zone", zoneName, "upstream", upstream, "grace", transferDrainGrace)
			}
			return nil, fmt.Errorf("ixfr %s from %s: %w", zoneName, upstream, ctx.Err())

		case envelope, ok := <-answerChan:
			if !ok {
				return out, nil
			}
			if envelope.Error != nil {
				return nil, clarifyXfrError(zoneName, upstream, envelope.Error)
			}
			out = append(out, envelope.RR...)
		}
	}
}

// applyIxfrToScratch turns a collected difference stream into a ready-to-swap
// scratch zone, or refuses.
//
// Every refusal here is the caller's cue to re-pull a full zone from the SAME
// upstream: the primary answered, we simply could not use what it said.
func (zd *ZoneData) applyIxfrToScratch(newZd *ZoneData, rrs []dns.RR) error {
	snap := zd.publishedSnapshot()
	if snap == nil {
		// The attempt predicate checks this, so reaching here means the
		// snapshot went away mid-refresh. Not an error worth a stack trace --
		// just fall back.
		return fmt.Errorf("ixfr %s: no published snapshot to apply a delta onto", zd.ZoneName)
	}

	steps, err := parseIxfrDeltas(zd.ZoneName, rrs, zd.IncomingSerial)
	if err != nil {
		return err
	}

	data, signed := materializeForIxfr(snap)
	if err := applyIxfrSteps(zd.ZoneName, data, signed, steps); err != nil {
		return err
	}

	target := ixfrTargetSerial(steps)
	bookend, ok := rrs[len(rrs)-1].(*dns.SOA)
	if !ok {
		// parseIxfrDeltas already required this; belt and braces before we
		// dereference it.
		return fmt.Errorf("ixfr %s: stream does not end with an SOA", zd.ZoneName)
	}
	if err := replaceApexSOA(zd.ZoneName, data, bookend); err != nil {
		return err
	}

	newZd.Data = data
	newZd.IncomingSerial = target
	newZd.CurrentSerial = target
	// This replacement is a delta applied to what we already served, not a
	// whole zone that arrived. applyRefreshReplacementLocked uses that to keep
	// the outbound chain contiguous instead of resetting it (§5).
	newZd.ixfrDerived = true
	// The journal anchors to the file, not to whatever the serial becomes after
	// load-time signing, exactly as the AXFR path records it.
	newZd.fileSerial = target

	removed, added := countIxfrRRs(steps)
	lg.Info("ixfr: delta applied", "zone", zd.ZoneName, "from", steps[0].from,
		"to", target, "sequences", len(steps), "removed", removed, "added", added)
	return nil
}

// adoptFullZoneRRs applies an RFC 1995 §4 full-zone answer to an IXFR request,
// which is an ordinary AXFR body and goes through the ordinary AXFR routing.
func (zd *ZoneData) adoptFullZoneRRs(newZd *ZoneData, rrs []dns.RR) error {
	newZd.Data = core.NewNameMap[OwnerData]()
	firstSoaSeen := false
	for _, rr := range rrs {
		firstSoaSeen = newZd.SortFunc(rr, firstSoaSeen)
	}
	soa, err := newZd.transferredApexSOA("(ixfr full-zone answer)")
	if err != nil {
		return err
	}
	newZd.IncomingSerial = soa.Serial
	newZd.CurrentSerial = soa.Serial
	newZd.fileSerial = soa.Serial
	lg.Info("ixfr: primary answered with a full zone", "zone", zd.ZoneName,
		"serial", soa.Serial, "rrs", len(rrs))
	return nil
}

// requestIxfr reports whether this zone may ask for an incremental transfer.
//
// Default ON (F1). The default lives here rather than being materialised into
// zd.Options by the parser on purpose: asConfiguredOptions re-serializes the
// option set into the persisted zone config, so materialising would write
// `request-ixfr` into the config of every zone that never asked for it, and the
// operator's file would grow a setting they did not choose.
func (zd *ZoneData) requestIxfr() bool {
	if zd == nil {
		return false
	}
	// Explicit off wins over explicit on: the safe direction is the one that
	// only ever asks for a full transfer.
	if zd.Options[OptNoRequestIxfr] {
		return false
	}
	return true
}

// signsItsOwnContent reports whether this zone re-signs what it serves, so its
// served content is not a faithful mirror of what its primary sent.
//
// The distinction matters for onward relay (§5): a mirror can hand its own
// downstreams the same difference the chain records, while a re-signing
// secondary's records are its own and the two must not be conflated.
func (zd *ZoneData) signsItsOwnContent() bool {
	if zd == nil {
		return false
	}
	return zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning]
}
