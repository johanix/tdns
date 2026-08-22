/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"sort"

	"github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// The NSEC chain has to be correct in the snapshot being published, not in a
// later one.
//
// Repairing it afterwards means a second publish at a second serial: every
// secondary sees two changes, and between them it serves -- and proves things
// with -- a chain that does not describe the zone. It cannot rebuild the chain
// itself, having no private key, so whatever it is handed is what it uses.
//
// So the repair runs inside the publish, before the snapshot swap, and it is
// incremental: an update touches a handful of names, and only their NSECs and
// their neighbours' need rewriting and re-signing. Re-signing the zone on every
// update would be correct and unusable.

// changedChainNames reports the owner names whose authoritative data differs
// between the published snapshot and the working set.
//
// The NSEC property is deliberately not part of the comparison. It is derived
// from these names, so including it would make the restitch respond to its own
// output.
func changedChainNames(old *zoneSnapshot, ws map[string]*OwnerData) []string {
	var out []string
	seen := map[string]bool{}

	var published map[string]*OwnerData
	if old != nil {
		published = old.Data
	}

	for name, wsOd := range ws {
		seen[name] = true
		pubOd := published[name]
		if pubOd == nil {
			out = append(out, name)
			continue
		}
		if len(ownerTypesChanged(pubOd, wsOd)) > 0 {
			out = append(out, name)
		}
	}
	for name := range published {
		if !seen[name] {
			out = append(out, name)
		}
	}
	return out
}

// zoneMaintainsItsOwnChain reports whether this zone's chain is ours to keep
// correct: we sign it, and we are not answering denial from synthesised
// records instead.
func (zd *ZoneData) zoneMaintainsItsOwnChain() bool {
	if zd == nil || zd.workingSet == nil || zd.KeyDB == nil {
		return false
	}
	if zd.Options[OptBlackLies] {
		// Compact denial: no stored chain is generated, so there is none to
		// keep in step.
		return false
	}
	if !zoneMayOriginateContent(zd) {
		return false
	}
	if zd.DnssecPolicy == nil {
		return false
	}
	return zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning]
}

// restitchNsecLocked repairs the NSEC chain around whatever this publish
// changed, and signs what it rewrites. Runs with zd.mu held.
//
// Three things can happen to a name:
//
//	it entered the chain   -> it needs an NSEC, and its predecessor must point at it
//	it left the chain      -> its NSEC goes, and its predecessor must point past it
//	its types changed      -> its own bitmap is rebuilt; the links are unaffected
//
// In every case the predecessor is rewritten too, which is why the affected set
// is the changed names plus their predecessors and never the whole zone.
func (zd *ZoneData) restitchNsecLocked() {
	if !zd.zoneMaintainsItsOwnChain() {
		return
	}

	changed := changedChainNames(zd.snapshot.Load(), zd.workingSet)
	if len(changed) == 0 {
		return
	}

	all := zd.workingOwnerNamesLocked()
	chain := zd.chainNamesLocked(all)
	if len(chain) == 0 {
		return
	}
	pos := make(map[string]int, len(chain))
	for i, n := range chain {
		pos[n] = i
	}

	// Resolved once, under the lock, and passed into SignRRset so it does not
	// reach EnsureActiveDnssecKeys itself -- that path re-locks zd.mu and
	// deadlocks. Same reasoning as the SOA re-sign alongside this.
	dak, err := zd.EnsureActiveDnssecKeys(zd.KeyDB, true)
	if err != nil {
		lgSigner.Error("publish: cannot resolve keys to restitch the NSEC chain;"+
			" the zone is being published with a chain that does not describe it",
			"zone", zd.ZoneName, "err", err)
		return
	}

	affected := map[string]bool{}
	for _, name := range changed {
		if _, stillIn := pos[name]; stillIn {
			affected[name] = true
		} else {
			// Gone from the chain: drop its NSEC so it stops asserting that it
			// exists. Its predecessor is picked up below and will point past it.
			zd.stageNsecDeleteLocked(name)
			// And if the NSEC was the only thing left, the owner itself goes.
			// Deleting the last RRset at a name removes the name from the zone;
			// leaving an entry behind holding nothing but the record that
			// proves it exists is the ghost this is here to prevent.
			if !ownerHasData(zd.stagedOwner(name)) {
				zd.stageOwnerDeleteLocked(name)
			}
		}
		if pred, ok := chainPredecessor(chain, name); ok {
			affected[pred] = true
		}
	}

	ttl := zd.nsecTTLLocked()
	rewritten := 0
	for name := range affected {
		i, ok := pos[name]
		if !ok {
			continue
		}
		next := chain[(i+1)%len(chain)]
		nsecrr, err := zd.nsecRRForLocked(name, next, ttl, dak)
		if err != nil || nsecrr == nil {
			if err != nil {
				lgSigner.Error("publish: could not build the NSEC record",
					"zone", zd.ZoneName, "name", name, "err", err)
			}
			continue
		}
		rs := core.RRset{RRs: []dns.RR{nsecrr}}
		if _, err := zd.SignRRset(&rs, zd.ZoneName, dak, true, nil); err != nil {
			// An unsigned NSEC is worse than a stale one: a validator rejects
			// the proof outright rather than merely disagreeing with it.
			lgSigner.Error("publish: could not sign the NSEC record; leaving the"+
				" previous one in place",
				"zone", zd.ZoneName, "name", name, "err", err)
			continue
		}
		zd.stageNsecLocked(name, rs)
		rewritten++
	}

	if rewritten > 0 {
		lgSigner.Debug("publish: restitched the NSEC chain",
			"zone", zd.ZoneName, "changed", len(changed), "rewritten", rewritten)
	}
}

// chainPredecessor returns the name immediately before target in the chain,
// whether or not target is itself in it -- a name that has just left still has
// a predecessor that needs to point past it.
//
// The chain is a cycle, so the predecessor of the first name is the last.
func chainPredecessor(chain []string, target string) (string, bool) {
	if len(chain) == 0 {
		return "", false
	}
	// First index whose name is >= target.
	i := sort.Search(len(chain), func(i int) bool {
		return !canonicalOwnerLess(chain[i], target)
	})
	if i == 0 {
		return chain[len(chain)-1], true
	}
	pred := chain[i-1]
	if pred == target {
		// target is in the chain at i-1 only if the search overshot; guard
		// against returning the name as its own predecessor.
		if i-2 < 0 {
			return chain[len(chain)-1], true
		}
		return chain[i-2], true
	}
	return pred, true
}

// withoutDerivedRecords drops the RRsets a journal must not carry.
//
// The delta computation is shared with the IXFR chain, which needs every
// record a secondary must see. The journal answers a different question --
// what did someone change about this zone -- and NSEC is not an answer to it:
// it is recomputed from the zone's shape on every publish.
func withoutDerivedRecords(rrsets []core.RRset) []core.RRset {
	out := rrsets[:0:0]
	for _, rs := range rrsets {
		if rs.RRtype == dns.TypeNSEC {
			continue
		}
		out = append(out, rs)
	}
	return out
}

// ownerHasData reports whether a name exists in the zone: it owns at least one
// actual record.
//
// Not RRtypes.Count(): deleting the last RR of an RRset can leave the type
// entry behind holding an empty RRset, so counting entries reports a name that
// owns nothing as though it were still in the zone -- and it then keeps its
// place in the chain, asserting its own existence with nothing to prove.
func ownerHasData(od *OwnerData) bool {
	if od == nil || od.RRtypes == nil {
		return false
	}
	for _, rrt := range od.RRtypes.Keys() {
		if len(od.RRtypes.GetOnlyRRSet(rrt).RRs) > 0 {
			return true
		}
	}
	return false
}
