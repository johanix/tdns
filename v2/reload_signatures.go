/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// Signatures across a reload (#1006, part D).
//
// A zone file carries no signatures of ours, so a reload of a zone that signs
// its own content used to sign every RRset afresh and rebuild the whole NSEC
// chain. Correct, but every RRSIG and every NSEC in the zone then changed under
// the new serial, so the IXFR link for the reload held the whole zone twice: it
// passed the IXFR budget and the downstream got a full transfer anyway. It also
// re-signed a zone of any size for a one-record edit.
//
// So the reloaded working set starts from what the published snapshot already
// holds wherever nothing changed: an RRset whose records are exactly the ones it
// had gets the signatures it had, and an owner still present keeps its NSEC.
// After that the reload looks to the signing pass and the restitch like any
// incremental change. The scoped signing pass stands down on an RRset that
// carries a valid signature by an active key, and signs the rest. The restitch
// repairs the chain around the names whose types changed, the names that came
// and went, and their predecessors.
//
// "Exactly" is the whole safety argument. A signature is carried only over the
// same set of RDATA at the same TTLs, compared as text. A changed RRset never
// keeps a signature over its old contents -- the defect signStagedScopeLocked
// warns about, which no later pass would repair before the signature expired.

// carrySignaturesLocked gives the reloaded working set the signatures and NSEC
// records the published snapshot holds for whatever did not change, and
// returns how many RRsets kept their signatures. Runs with zd.mu held, before
// the publish signs.
//
// The working set's stores are the parse's own (snapshotMapFromData shares them
// with a scratch zone nobody else holds), so they are written in place. What is
// taken from the snapshot is copied: its slices are shared with every reader.
func (zd *ZoneData) carrySignaturesLocked(old *zoneSnapshot) int {
	if old == nil {
		return 0
	}
	// NSEC TTLs follow the SOA's negative TTL. If that changed, every NSEC in
	// the zone has to be rewritten, and carrying them would keep the old TTL.
	carryNsec := negativeTTLOf(apexFromSnapshotData(zd, old.Data)) ==
		negativeTTLOf(apexFromSnapshotData(zd, zd.workingSet))

	carried := 0
	for name, nod := range zd.workingSet {
		ood := old.Data[name]
		if nod == nil || ood == nil || nod.RRtypes == nil || ood.RRtypes == nil {
			continue
		}
		for _, t := range nod.RRtypes.Keys() {
			nrs := nod.RRtypes.GetOnlyRRSet(t)
			if len(nrs.RRs) == 0 || len(nrs.RRSIGs) > 0 {
				continue
			}
			ors := ood.RRtypes.GetOnlyRRSet(t)
			if len(ors.RRSIGs) == 0 || !identicalRecords(ors.RRs, nrs.RRs) {
				continue
			}
			nrs.RRSIGs = append([]dns.RR(nil), ors.RRSIGs...)
			nod.RRtypes.Set(t, nrs) // mutator-ok: the reload's own parsed store, not yet published or shared
			carried++
		}
		if carryNsec && len(nod.NSEC.RRs) == 0 && len(ood.NSEC.RRs) > 0 {
			nod.NSEC = core.RRset{
				Name:   ood.NSEC.Name,
				Class:  ood.NSEC.Class,
				RRtype: ood.NSEC.RRtype,
				RRs:    append([]dns.RR(nil), ood.NSEC.RRs...),
				RRSIGs: append([]dns.RR(nil), ood.NSEC.RRSIGs...),
			}
		}
	}
	return carried
}

// identicalRecords reports whether two RR slices hold the same records, in any
// order, TTLs included: same count, and nothing in one that is not in the
// other. Not sameRecords (delsync_signals.go), which ignores TTLs: a signature
// covers the TTL, so a TTL change must not keep one.
func identicalRecords(a, b []dns.RR) bool {
	if len(a) != len(b) {
		return false
	}
	onlyA, onlyB := rrDiff(a, b)
	return len(onlyA) == 0 && len(onlyB) == 0
}

// negativeTTLOf is the negative-caching TTL an apex's SOA implies, or 0 when
// there is no SOA.
func negativeTTLOf(apex *OwnerData) uint32 {
	if apex == nil || apex.RRtypes == nil {
		return 0
	}
	soa := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	if len(soa.RRs) == 0 {
		return 0
	}
	if s, ok := soa.RRs[0].(*dns.SOA); ok {
		return negativeTTL(s)
	}
	return 0
}
