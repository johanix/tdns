package tdns

import (
	"errors"
	"fmt"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

func (zd *ZoneData) ensureWorkingSet() {
	if zd.workingSet != nil {
		return
	}
	snap := zd.snapshot.Load()
	if snap == nil {
		zd.workingSet = snapshotMapFromData(zd.Data)
		return
	}
	zd.workingSet = make(map[string]*OwnerData, len(snap.Data))
	for k, v := range snap.Data {
		zd.workingSet[k] = v
	}
	if zd.wsSignalSynth == nil {
		zd.wsSignalSynth = cloneSignalSynth(snap.signalSynth)
	}
}

// cloneOwner returns a fresh, mutable copy of one owner in the working set.
//
// The working set is keyed canonically, like the snapshot it is built from, so
// an update naming an owner in a different case than the zone file used reaches
// the owner that is already there instead of creating a second one beside it.
// The owner's own Name keeps a spelling that was actually published: an
// existing owner keeps its own, and a name appearing here for the first time
// keeps the caller's.
func (zd *ZoneData) cloneOwner(name string) *OwnerData {
	key := core.CanonicalizeName(name)
	src := zd.workingSet[key]
	stored := name
	if src != nil {
		stored = src.Name
	}
	nod := &OwnerData{Name: stored, RRtypes: NewRRTypeStore()}
	if src != nil {
		for _, t := range src.RRtypes.Keys() {
			rs, _ := src.RRtypes.Get(t)
			nod.RRtypes.Set(t, rs)
		}
		// The NSEC property travels with the owner. Rebuilding an owner from
		// its RRtypes alone would drop the chain entry silently, and the name
		// would fall out of the chain on the next publish without anything
		// having asked for that.
		//
		// Deep-copied, because the published snapshot shares these records and
		// signing rewrites them: applyClampToRRset assigns Header().Ttl in
		// place, so a shared RR would have its TTL changed underneath a
		// snapshot that is being served right now.
		nod.NSEC = cloneRRset(src.NSEC)
	}
	zd.workingSet[key] = nod
	return nod
}

func (zd *ZoneData) stageRRset(name string, rs core.RRset) {
	zd.ensureWorkingSet()
	zd.cloneOwner(name).RRtypes.Set(rs.RRtype, cloneRRset(rs))
}

func (zd *ZoneData) stageDelete(name string, rrtype uint16) {
	zd.ensureWorkingSet()
	zd.cloneOwner(name).RRtypes.Delete(rrtype)
}

func (zd *ZoneData) stageOwnerReplace(name string, od *OwnerData) {
	zd.ensureWorkingSet()
	zd.workingSet[core.CanonicalizeName(name)] = od
}

func (zd *ZoneData) pendingChanges() *PendingChanges {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.workingSet == nil {
		return nil
	}
	snap := zd.snapshot.Load()
	publishedSerial := zd.CurrentSerial
	if snap != nil {
		publishedSerial = snap.Serial
	}
	pc := &PendingChanges{
		PublishedSerial: publishedSerial,
		PublishQueued:   zd.publishQueued,
	}
	published := map[string]*OwnerData{}
	if snap != nil {
		published = snap.Data
	}
	seen := map[string]bool{}
	for name, wsOd := range zd.workingSet {
		seen[name] = true
		pubOd := published[name]
		if pubOd == nil {
			pc.Added = append(pc.Added, name)
			continue
		}
		changed := ownerTypesChanged(pubOd, wsOd)
		if len(changed) > 0 {
			pc.Replaced = append(pc.Replaced, pendingOwnerChange{Owner: name, RRtypes: changed})
		}
	}
	for name, pubOd := range published {
		if seen[name] {
			continue
		}
		if pubOd == nil {
			continue
		}
		pc.Deleted = append(pc.Deleted, pendingOwnerChange{Owner: name, RRtypes: pubOd.RRtypes.Keys()})
	}
	if len(pc.Added) == 0 && len(pc.Replaced) == 0 && len(pc.Deleted) == 0 && !pc.PublishQueued {
		return nil
	}
	return pc
}

func ownerTypesChanged(a, b *OwnerData) []uint16 {
	if a == nil || b == nil {
		return nil
	}
	aTypes := map[uint16]bool{}
	for _, t := range a.RRtypes.Keys() {
		aTypes[t] = true
	}
	var changed []uint16
	for _, t := range b.RRtypes.Keys() {
		brs, ok := b.RRtypes.Get(t)
		if !ok {
			continue
		}
		ars, aok := a.RRtypes.Get(t)
		if !aok || !rrsetEqual(ars, brs) {
			changed = append(changed, t)
		}
		delete(aTypes, t)
	}
	for t := range aTypes {
		changed = append(changed, t)
	}
	return changed
}

func rrsetEqual(a, b core.RRset) bool {
	if len(a.RRs) != len(b.RRs) || len(a.RRSIGs) != len(b.RRSIGs) {
		return false
	}
	for i := range a.RRs {
		if a.RRs[i].String() != b.RRs[i].String() {
			return false
		}
	}
	for i := range a.RRSIGs {
		if a.RRSIGs[i].String() != b.RRSIGs[i].String() {
			return false
		}
	}
	return true
}

func (zd *ZoneData) stagedOwner(name string) *OwnerData {
	zd.ensureWorkingSet()
	return zd.workingSet[core.CanonicalizeName(name)]
}

func (zd *ZoneData) getOrCreateWorkingOwner(name string) *OwnerData {
	zd.ensureWorkingSet()
	if od := zd.workingSet[core.CanonicalizeName(name)]; od != nil {
		return od
	}
	return zd.cloneOwner(name)
}

func (zd *ZoneData) workingOwnerNamesLocked() []string {
	if zd.workingSet == nil {
		return nil
	}
	names := make([]string, 0, len(zd.workingSet))
	for name := range zd.workingSet {
		names = append(names, name)
	}
	// Canonical order (RFC 4034 §6.1), NOT lexicographic. The NSEC chain is
	// built by walking this slice and linking each name to the next, so the
	// order IS the chain: a lexicographic sort produces a chain that is a
	// permutation of the right names in the wrong sequence, which no validator
	// will accept and which no query against the signer will reveal, because
	// denial is answered by compact denial rather than from the chain.
	//
	// The two differ whenever a name is a SUFFIX of another rather than a
	// prefix, which for a zone is every name in it against the apex: a
	// lexicographic sort of `clean.example.` with `alpha` and `ns` beneath it
	// puts the apex in the middle.
	//
	// Sorted on precomputed keys rather than by comparing names pairwise.
	// canonicalOwnerLess allocates six times per comparison and this sort runs
	// on every publish of every signed zone, so the cost is O(n log n)
	// allocations where O(n) will do. canonicalSortKey's byte order IS
	// canonical order, so the result is identical.
	//
	// Shared with the digest, which needs the same order over the same names.
	canonicalOwnerOrder(names)
	return names
}

func (zd *ZoneData) requestPublish(urgent bool) {
	if urgent {
		_, _ = zd.publishSync()
		return
	}
	zd.startPublisher()
	zd.mu.Lock()
	zd.publishQueued = true
	zd.mu.Unlock()
	zd.wakePublisher()
}

// publishSync runs publish immediately under zd.mu (serial bump + snapshot swap).
func (zd *ZoneData) resignWorkingSetSOAIfSigned(sm *signingMaterial) {
	// sm carries the publish's role and policy gates already: it is nil for a
	// zone that does not sign, for one that must not originate content, and for
	// one whose keys cannot be resolved yet. One resolution per publish, made by
	// publishWorkingSetLocked. See signingMaterial.
	if sm == nil {
		return
	}
	if zd.workingSet == nil {
		return
	}
	apex := zd.workingSet[zd.ZoneName]
	if apex == nil {
		return
	}
	rs := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	if len(rs.RRs) == 0 {
		return
	}
	// SignRRset takes the pre-resolved keys so it does not reach its own
	// EnsureActiveDnssecKeys, which gets to PublishDnskeyRRs and re-locks zd.mu
	// (the 6e090a9 deadlock class).
	//
	// clamp stays nil here, as it always has: the K-step TTL clamp is for the
	// zone's authored records, and the apex SOA is rewritten on every publish
	// regardless.
	if _, err := zd.SignRRset(&rs, zd.ZoneName, sm.dak, true, nil); err != nil {
		lg.Error("publish: failed to re-sign SOA", "zone", zd.ZoneName, "err", err)
		return
	}
	zd.cloneOwner(zd.ZoneName).RRtypes.Set(dns.TypeSOA, cloneRRset(rs))
}

func (zd *ZoneData) publishSync() (BumperResponse, error) {
	resp := BumperResponse{Zone: zd.ZoneName}
	zd.mu.Lock()
	defer zd.mu.Unlock()
	resp.OldSerial = zd.CurrentSerial
	if zd.workingSet == nil {
		zd.ensureWorkingSet()
	}
	zd.publishLocked(zd.generation.Load())
	resp.NewSerial = zd.CurrentSerial
	return resp, nil
}

func (zd *ZoneData) stageRRsetLocked(name string, rs core.RRset) {
	// The store keys by RR type, but callers frequently build rs via
	// GetOnlyRRSet (which leaves rs.RRtype unset) or via signing helpers that
	// drop it. Derive the type from the RRs when rs.RRtype is 0 so the RRset is
	// never mis-keyed under type 0.
	rrtype := rs.RRtype
	if rrtype == 0 && len(rs.RRs) > 0 {
		rrtype = rs.RRs[0].Header().Rrtype
	}
	rs.RRtype = rrtype
	zd.ensureWorkingSet()
	zd.cloneOwner(name).RRtypes.Set(rrtype, cloneRRset(rs))
}

// stageNsecLocked sets an owner's NSEC property. Unlike stageRRsetLocked it
// cannot bring an owner into existence: an NSEC belongs to a name that has
// authoritative data, and staging one for a name with none would recreate the
// ghosts the property exists to prevent.
func (zd *ZoneData) stageNsecLocked(name string, rs core.RRset) {
	zd.ensureWorkingSet()
	od := zd.stagedOwner(name)
	if od == nil {
		return
	}
	rs.Name, rs.RRtype, rs.Class = name, dns.TypeNSEC, dns.ClassINET
	zd.cloneOwner(name).NSEC = cloneRRset(rs)
}

// stageNsecDeleteLocked drops an owner's NSEC property, for a name leaving the
// chain.
func (zd *ZoneData) stageNsecDeleteLocked(name string) {
	zd.ensureWorkingSet()
	if od := zd.stagedOwner(name); od == nil {
		return
	}
	zd.cloneOwner(name).NSEC = core.RRset{}
}

func (zd *ZoneData) stageDeleteLocked(name string, rrtype uint16) {
	zd.ensureWorkingSet()
	zd.cloneOwner(name).RRtypes.Delete(rrtype)
}

func (zd *ZoneData) stageOwnerReplaceLocked(name string, od *OwnerData) {
	zd.ensureWorkingSet()
	zd.workingSet[core.CanonicalizeName(name)] = od
}

func (zd *ZoneData) stageOwnerDeleteLocked(name string) {
	zd.ensureWorkingSet()
	delete(zd.workingSet, core.CanonicalizeName(name))
}

func (zd *ZoneData) publishLocked(gen uint64) {
	zd.publishWorkingSetLocked(gen, true)
}

// publishWorkingSetLocked stores the current working set. When bumpSerial is
// false the caller has already set zd.CurrentSerial (refresh flips, transport
// signal synthesis without a content serial change).
func (zd *ZoneData) publishWorkingSetLocked(gen uint64, bumpSerial bool) {
	if zd.workingSet == nil {
		zd.publishQueued = false
		zd.publishUrgent = false
		// The epoch-reset flag is staged together with a working set; with no
		// working set it is orphaned. Clear it so a dropped publish cannot
		// carry it into a later unrelated publish (which would needlessly
		// wipe the IXFR history).
		zd.wsIxfrEpochReset = false
		zd.wsNeedsFullSign, zd.wsSignOwners = false, nil
		// Same reasoning for the delta staging: wsPersistDelta says "the
		// working set about to be published carries a change worth
		// journalling". A dropped publish leaves it staged, and the NEXT
		// publish for this zone -- a refresh, a reload, a signalSynth-only
		// republish -- would then write a ZoneDelta row it does not own,
		// diffed against a working set no applier staged. Replay would later
		// apply that row as though it were an update. wsPersistErr is cleared
		// with it so a later applier cannot read a failure belonging to a
		// publish that never happened.
		zd.wsPersistDelta = false
		zd.wsPersistErr = nil
		return
	}
	if !zoneStillLive(zd, gen) {
		zd.workingSet = nil
		zd.wsSignalSynth = nil
		zd.publishQueued = false
		zd.publishUrgent = false
		zd.wsIxfrEpochReset = false
		zd.wsNeedsFullSign, zd.wsSignOwners = false, nil
		// Same reasoning for the delta staging: wsPersistDelta says "the
		// working set about to be published carries a change worth
		// journalling". A dropped publish leaves it staged, and the NEXT
		// publish for this zone -- a refresh, a reload, a signalSynth-only
		// republish -- would then write a ZoneDelta row it does not own,
		// diffed against a working set no applier staged. Replay would later
		// apply that row as though it were an update. wsPersistErr is cleared
		// with it so a later applier cannot read a failure belonging to a
		// publish that never happened.
		zd.wsPersistDelta = false
		zd.wsPersistErr = nil
		return
	}

	// Atomic-swap invariant: never store a snapshot without an apex. An
	// apex-less working set (e.g. an empty rebuild during reload) would yield a
	// snapshot with nil Apex/SOA; storing it would leave a Ready zone with no
	// servable SOA and crash readers (GetSOA -> nil). A zone with no apex SOA is
	// not servable, so refuse the swap and keep serving the current snapshot; a
	// later valid rebuild will publish correctly. Serial is not bumped here, so
	// the refused publish does not advance the zone's serial.
	if apexFromSnapshotData(zd, zd.workingSet) == nil {
		lg.Error("publish: refusing to swap in an apex-less snapshot; keeping current snapshot",
			"zone", zd.ZoneName)
		zd.workingSet = nil
		zd.wsSignalSynth = nil
		zd.publishQueued = false
		zd.publishUrgent = false
		zd.wsIxfrEpochReset = false
		zd.wsNeedsFullSign, zd.wsSignOwners = false, nil
		// A refused publish must not leave the delta staged; see above.
		zd.wsPersistDelta = false
		zd.wsPersistErr = nil
		return
	}

	prevSerial := zd.CurrentSerial
	serial := zd.CurrentSerial
	if bumpSerial {
		zd.CurrentSerial = nextOutboundSerial(zd)
		serial = zd.CurrentSerial
	}
	zd.setWorkingSetSOASerial(serial)

	// One resolution for the whole publish; every signing step below consumes
	// it. A real failure refuses the publish; "cannot sign yet" is nil and
	// every step stands down, so a brand-new zone publishes unsigned and stays
	// not Ready until the policy apply signs it.
	sm, kerr := zd.resolveSigningMaterialLocked()
	if kerr != nil {
		zd.refuseUnsignableWorkingSetLocked(prevSerial, kerr)
		return
	}

	zd.resignWorkingSetSOAIfSigned(sm)

	// Authored content, for a working set that arrived unsigned. This is the
	// same argument the NSEC restitch below makes for the chain, applied to the
	// data: signing in a LATER pass publishes a second serial and leaves a
	// window -- the length of a full signing pass -- in which this zone serves
	// its transferred RRsets with a signed SOA, a signed NSEC chain and no
	// RRSIGs on the answers themselves. A validator asking during that window
	// gets the worst combination available, and ZoneTransferOut's fail-closed
	// guard passes it, because that guard inspects the SOA.
	//
	// Refuse rather than publish unsigned: the previous snapshot is still good
	// and is still being served.
	if err := zd.signStagedScopeLocked(sm); err != nil {
		zd.refuseUnsignableWorkingSetLocked(prevSerial, err)
		return
	}
	// Cleared only on success. Clearing before the attempt would leave a
	// refused-but-still-staged working set marked as already signed, and the
	// next publish would put it on the wire unsigned -- the exact defect the
	// staged scope exists to prevent.
	zd.wsNeedsFullSign, zd.wsSignOwners = false, nil

	// Whether the apex carries a ZONEMD is settled BEFORE the restitch, so the
	// apex NSEC bitmap describes the record set this snapshot will hold. The
	// digest itself cannot be computed yet: it covers the NSEC records the
	// restitch is about to write. See zonemd_publish.go.
	zd.ensureZonemdPresenceLocked(sm)

	// The chain must describe the snapshot about to be published, so it is
	// repaired HERE -- before the delta is computed and before the swap, so
	// that secondaries receive the change together with the data that caused
	// it. Doing it in a later pass would publish a second serial and leave a
	// window in which the served chain contradicts the served zone.
	if err := zd.restitchNsecLocked(sm); err != nil {
		zd.refuseUnrepairableChainLocked(prevSerial, err)
		return
	}

	// And now the digest, over a working set that is finally complete. This is
	// the LAST step that may change zone content: everything below only reads
	// the working set. Writing the ZONEMD RDATA and its RRSIG here cannot
	// invalidate what was just computed, because ZoneDigest excludes both.
	//
	// A zone that cannot produce a digest is published WITHOUT one. The one
	// case that refuses the publish is a chain left claiming a ZONEMD the zone
	// no longer carries -- the same defect the restitch above refuses, reached
	// from the other side.
	if !zd.updateZonemdLocked(serial, prevSerial, sm) {
		return
	}

	data := zd.workingSet
	oldSnap := zd.snapshot.Load()

	// Phase 2: make the change DURABLE BEFORE making it VISIBLE.
	//
	// This runs ahead of updateIxfrChainLocked and the snapshot swap on
	// purpose. Once the snapshot is stored the content is being served and a
	// secondary can pull it via NOTIFY -> IXFR; if the process then died before
	// the row was written, that secondary would hold content the primary has
	// no record of and silently rolls back on restart. Durable-then-visible is
	// the only order in which a crash cannot desync a secondary, and it is what
	// F12 of the design specified.
	//
	// The difference is computed here rather than reused from
	// updateIxfrChainLocked: that function returns early on a zero retention
	// budget, on an epoch reset and on a missing baseline, none of which say
	// anything about whether a change should survive a restart. The two
	// histories answer different questions and must not share an early return.
	//
	// Yes, this is a database write under zd.mu. That is deliberate and it is
	// what BIND does with its journal. The earlier arrangement -- persisting
	// after the unlock -- was chosen to keep disk I/O off the zone lock, citing
	// this tree's deadlock history. That history is about paths which RE-ENTER
	// zone locking (signing, PublishDnskeyRRs); PersistZoneDelta is a leaf that
	// runs a few INSERTs in one transaction and calls nothing back. So the cost
	// here is latency, not deadlock, and latency is the cheaper thing to pay
	// for durability.
	if zd.wsPersistDelta {
		zd.wsPersistDelta = false
		// The kill-switch (journal: active: false). Checked HERE, at the single
		// point where a delta would be written, rather than at the two places
		// that set wsPersistDelta -- one gate cannot drift from the other, and a
		// future third setter is covered without being remembered.
		//
		// Only the WRITE side is gated. Replay is untouched: an operator who
		// disables the journal must not thereby discard the deltas already in
		// it, or the escape hatch becomes a second way to lose data.
		if !JournalActive() {
			lg.Debug("delta persistence is disabled (journal: active: false);"+
				" this change will NOT survive a restart",
				"zone", zd.ZoneName, "serial", serial)
		} else if oldSnap != nil && zd.KeyDB != nil {
			removed, added, _ := computeZoneDelta(zd.ZoneName, oldSnap.Data, data)
			// The journal carries authored data only. NSEC is derived -- this
			// publish just regenerated it -- and the same delta computation
			// feeds the IXFR chain, where secondaries DO need it.
			//
			// Journalling it would replay regenerated records onto a zone file
			// as though an operator had written them, and the zone-file
			// reconciliation would then report conflicts on records nobody
			// authored and offer .rejected artefacts full of them. It also
			// reinstates the ghosts the property model removes, by putting
			// NSEC back into an owner's RRtypes on replay.
			removed, added = zd.withoutDerivedRecords(removed), zd.withoutDerivedRecords(added)
			if len(removed) > 0 || len(added) > 0 {
				// What this delta chains FROM.
				//
				// NOT oldSnap.Serial, which is where the zone was last
				// published. A zone that re-signs or republishes during load
				// advances its published serial past the serial its FILE
				// carries -- on a signed zone, by several -- so the first
				// change after a load would be journalled as starting from a
				// serial the file has never had. The next load reads the file,
				// compares it against that base, finds a mismatch, and refuses
				// the entire journal: every change lost, and the operator told
				// their zone file had been edited. That is the shape of the
				// bug this replaces.
				//
				// The first delta of a journal anchors to the FILE; every
				// later one anchors to the journal's own tail. The chain is
				// then continuous by construction and starts where the next
				// load will actually begin.
				fromSerial := zd.fileSerial
				if last, have, lerr := zd.KeyDB.LastZoneDeltaSerial(zd.ZoneName); lerr != nil {
					// Refusing here rather than guessing: a wrong base is
					// silent data loss at the next restart, which is exactly
					// what this whole path exists to prevent.
					zd.wsPersistErr = lerr
					zd.CurrentSerial = prevSerial
					zd.workingSet = nil
					zd.wsSignalSynth = nil
					zd.publishQueued = false
					zd.publishUrgent = false
					zd.wsIxfrEpochReset = false
					zd.wsNeedsFullSign, zd.wsSignOwners = false, nil
					lg.Error("publish refused: could not determine the delta chain base",
						"zone", zd.ZoneName, "error", lerr)
					return
				} else if have {
					fromSerial = last
				}

				if err := zd.KeyDB.PersistZoneDelta(zd.ZoneName,
					fromSerial, serial, removed, added); err != nil {
					// Refuse the publish. The alternative is to serve a change
					// that is guaranteed to vanish at the next restart, which
					// is worse than not serving it: the operator gets an error
					// they can act on instead of silent data loss later.
					//
					// Unwind cleanly. Nothing else has been touched yet -- the
					// IXFR chain has not been updated and no snapshot has been
					// stored -- so dropping the working set and restoring the
					// serial leaves the zone exactly as it was, still serving
					// the previous snapshot.
					zd.wsPersistErr = err
					zd.CurrentSerial = prevSerial
					zd.workingSet = nil
					zd.wsSignalSynth = nil
					zd.publishQueued = false
					zd.publishUrgent = false
					zd.wsIxfrEpochReset = false
					zd.wsNeedsFullSign, zd.wsSignOwners = false, nil
					lg.Error("refusing to publish a zone change that could not be persisted;"+
						" the zone continues to serve its previous content",
						"zone", zd.ZoneName, "from_serial", oldSnap.Serial,
						"to_serial", serial, "error", err)
					return
				}
			}
		}
	}

	// Maintain the IXFR delta history BEFORE building the snapshot so the
	// chain copied into it ends exactly at this publish's serial (Project C).
	zd.updateIxfrChainLocked(oldSnap, serial, data)

	snap := zd.buildSnapshotLocked(serial, data, zd.wsSignalSynth)
	zd.snapshot.Store(snap)

	zd.workingSet = nil
	zd.wsSignalSynth = nil
	zd.publishQueued = false
	zd.publishUrgent = false
	zd.lastPublish = time.Now()

	// Persist only for a zone that may originate: a mirroring secondary's
	// serial is upstream's property, not ours to record and later restore.
	if zd.KeyDB != nil && zoneMayOriginateContent(zd) &&
		zd.EffectiveOutboundSoaSerial() == OutboundSoaSerialPersist {
		if err := zd.KeyDB.SaveOutgoingSerial(zd.ZoneName, zd.CurrentSerial); err != nil {
			lg.Error("publish: failed to persist outgoing serial", "zone", zd.ZoneName, "err", err)
		}
	}

	if loaded := zd.snapshot.Load(); loaded != nil && loaded.Serial != zd.CurrentSerial {
		lg.Error("publish: serial mirror drift", "zone", zd.ZoneName, "current", zd.CurrentSerial, "snapshot", loaded.Serial)
	}

	// Becoming servable is decided on the CONTENT half alone. The notify test
	// below ands that with Ready, which is right for notifying and circular
	// here: with Ready still false it would answer false for every zone, signed
	// or not, and nothing would ever be flipped or ever serve.
	//
	// This is also the only writer that runs after the policy apply.
	// applyRefreshReplacementLocked withholds Ready on a first load and
	// InstallInitialSnapshot runs BEFORE the apply, so without this a zone that
	// the apply publish signs correctly would stay invisible for good.
	if !zd.Ready && zd.snapshotContentIsServableLocked(snap) {
		zd.Ready = true
		zd.Status = ZoneStatusReady
	}

	zd.notifyIfServableLocked(snap)
}

// notifyIfServableLocked emits at most one NOTIFY for the version just
// published, and only if a downstream could actually take it.
//
// The predicate is deliberately ZoneTransferOut's own admission test. A NOTIFY
// about a version we would then REFUSE to transfer only burns the downstream's
// retry budget, and first load publishes exactly such a version: the load path
// publishes before InstallInitialSnapshot marks the zone Ready, and a downstream
// acting on that notification is refused on status.
//
// The hand-off is a NON-BLOCKING send to the Notifier, replacing the inline
// NotifyDownstreams loop that used to run here. That loop ran under zd.mu, at
// dns.Exchange's 2s per unreachable downstream, with no way to interrupt it --
// NotifyDownstreams uses dns.Exchange, not ExchangeContext, so no deadline or
// cancellation reaches it. A publish therefore held the zone's own lock across
// network I/O to every downstream, blocking every reader of that zone for as
// long as it took.
//
// A full queue drops and says so. NOTIFY is best-effort by design -- a
// downstream that misses one refreshes on its SOA timer -- and blocking a
// publish on a queue whose consumer is serial and 2s-per-target is how the stall
// comes back somewhere new. The send cannot block, which is what makes it safe
// to do while holding zd.mu.
func (zd *ZoneData) notifyIfServableLocked(snap *zoneSnapshot) {
	if len(zd.Notify) == 0 {
		return
	}
	if !zd.snapshotIsServableLocked(snap) {
		lg.Debug("publish: not notifying downstreams, this version is not servable yet",
			"zone", zd.ZoneName, "ready", zd.Ready)
		return
	}
	q := Conf.Internal.NotifyQ
	if q == nil {
		return
	}
	select {
	case q <- NotifyRequest{
		ZoneName: zd.ZoneName,
		ZoneData: zd,
		RRtype:   dns.TypeSOA,
		Targets:  peerAddrs(zd.Notify),
	}:
	default:
		lg.Warn("publish: NOTIFY queue is full, dropping a downstream notification;"+
			" the downstream picks this up on its own SOA timer instead",
			"zone", zd.ZoneName, "serial", snap.Serial, "downstreams", len(zd.Notify))
	}
}

// snapshotIsServableLocked reports whether a downstream could take this
// snapshot. The two gates are ZoneTransferOut's, for its reasons: the zone must
// be Ready, and a zone configured to be signed must not be offering an unsigned
// apex SOA. Keeping the predicates identical is the point -- what we notify
// about and what we will hand over have to be the same set of versions.
func (zd *ZoneData) snapshotIsServableLocked(snap *zoneSnapshot) bool {
	return zd.Ready && zd.snapshotContentIsServableLocked(snap)
}

// snapshotContentIsServableLocked is the CONTENT half of that test: would this
// snapshot be servable if the zone were Ready? A zone that does not sign its own
// content always qualifies; one that does must not offer an unsigned apex SOA.
//
// Separate from the test above because this one decides whether to SET Ready,
// and a predicate that reads Ready cannot do that -- it would answer false for
// every zone forever. Same content rule, no Ready in it.
func (zd *ZoneData) snapshotContentIsServableLocked(snap *zoneSnapshot) bool {
	if snap == nil {
		return false
	}
	if !zd.signsItsOwnContent() {
		return true
	}
	if snap.Apex == nil {
		return false
	}
	soa := snap.Apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	return len(soa.RRSIGs) > 0
}

// applyRefreshReplacementLocked swaps freshly loaded zone data in and publishes
// it.
//
// fromZoneFile says the replacement was read from this zone's own file rather
// than transferred from an upstream. It governs the serial floor in the default
// branch below and nothing else, because only a file-backed zone anchors its
// delta journal to the content it has just loaded.
func (zd *ZoneData) applyRefreshReplacementLocked(new_zd *ZoneData, dynamicRRs []*core.RRset,
	firstLoad, fromZoneFile bool) error {
	// The zone has just been re-read; whatever was replayed on top of the
	// PREVIOUS file no longer applies to this one, so a replay for the new file
	// is due again.
	zd.deltasReplayed = false
	// The file's serial travels with the data it came from. The parse happens
	// on a scratch ZoneData, so without this the live zone keeps a fileSerial
	// of 0 and the journal anchors to nothing.
	zd.fileSerial = new_zd.fileSerial
	zd.fileDigest = new_zd.fileDigest
	zd.IncomingSerial = new_zd.IncomingSerial
	switch {
	case firstLoad:
		zd.CurrentSerial = new_zd.CurrentSerial
		zd.FirstZoneLoad = false

	case !zoneMayOriginateContent(zd):
		// MUST-NOT-MODIFY: a tdns-auth secondary that did not originate this
		// content mirrors the upstream serial verbatim. The historical
		// unconditional ++ below made every such secondary drift +1 per
		// refresh, so two masters downstream of one signer (say BIND9 and
		// tdns-auth) advertised different serials for identical content and
		// edge nodes always fetched from the tdns one — silently collapsing a
		// redundant pair. This is the fix.
		prev := zd.CurrentSerial
		zd.CurrentSerial = new_zd.IncomingSerial
		// A secondary that had already inflated its serial (or was running in
		// persist/unixtime mode before the upgrade) steps BACKWARDS here, once.
		// Its own downstreams will then refuse to transfer until upstream
		// climbs past the old value — RFC 1982 serial arithmetic, so BIND/NSD
		// behave the same and a NOTIFY carrying a lower serial is ignored.
		// Shout, so the operator can force a retransfer on the downstreams
		// (`tdns-cli zone reload --force <zone>`) instead of discovering it as
		// mysteriously stale data.
		if prev != 0 && zd.CurrentSerial < prev {
			lg.Error("secondary SOA serial steps BACKWARDS to mirror upstream; downstreams will refuse to transfer until forced",
				"zone", zd.ZoneName, "old_serial", prev, "new_serial", zd.CurrentSerial,
				"action", "force a retransfer on each downstream (tdns-cli zone reload --force)")
		}

	default:
		// Strictly newer than what this server has already served -- and, when
		// the content came from this zone's own file, than the serial that file
		// carries.
		//
		// The served serial alone is the obvious choice, and for a reload it is
		// not enough. A reload adopts the new file as the journal's anchor
		// (zd.fileSerial, assigned above), so a file whose serial jumped ahead
		// of what is being served leaves that anchor ahead of the zone: the
		// next change is then a delta from the file's serial to a lower one,
		// PersistZoneDelta refuses it, and the zone accepts no further update
		// until it is restarted. That was the second half of #362, and it needs
		// no journal to happen -- with an empty journal the next delta anchors
		// to zd.fileSerial directly.
		//
		// Same floor MergeJournalOverNewFile applies, and for the same reason;
		// it just has to hold whether or not there is a journal to merge.
		//
		// A TRANSFERRED zone is excluded deliberately. Its serial is its own,
		// not upstream's -- an inline-signing secondary re-signs what it
		// receives and advances in its own space (see the MUST-NOT-MODIFY
		// design), and off tdns-auth the whole gate stands down. Nothing there
		// anchors a journal to the received serial, so there is nothing to
		// floor.
		next := zd.CurrentSerial
		if fromZoneFile && serialNewer(zd.fileSerial, next) {
			next = zd.fileSerial
		}
		zd.CurrentSerial = next + 1
		if zd.KeyDB != nil && zd.EffectiveOutboundSoaSerial() == OutboundSoaSerialPersist {
			if err := zd.KeyDB.SaveOutgoingSerial(zd.ZoneName, zd.CurrentSerial); err != nil {
				return fmt.Errorf("persist outgoing serial for zone %s: %w", zd.ZoneName, err)
			}
		}
	}
	zd.ApexLen = new_zd.ApexLen
	zd.ZoneStore = new_zd.ZoneStore
	zd.ZoneType = new_zd.ZoneType

	zd.workingSet = snapshotMapFromData(new_zd.Data)
	// A refresh replaces zone data wholesale; carry the synthesized-signal
	// fallback over from the current snapshot so it survives until the transport
	// postpass recomputes it. The stored _dns.<ns> owner RRsets are preserved
	// separately by CollectDynamicRRs -> repopulateWorkingSetLocked.
	if old := zd.snapshot.Load(); old != nil {
		zd.wsSignalSynth = cloneSignalSynth(old.signalSynth)
	} else {
		zd.wsSignalSynth = nil
	}
	zd.repopulateWorkingSetLocked(dynamicRRs)
	// A refresh normally replaces zone data wholesale, which is a new IXFR
	// epoch by definition: nothing links the previous snapshot to this one, so
	// any delta across the boundary could be wrong for some downstream.
	//
	// An inbound IXFR is the exception, and the reason §5 exists. Its content
	// IS the previous snapshot plus a difference sequence, so the boundary is
	// exactly the kind of step the chain is made of -- and a cascaded
	// secondary can go on serving deltas to ITS downstreams across a refresh
	// instead of forcing them all to AXFR.
	//
	// The link is not translated from the inbound format. updateIxfrChainLocked
	// already diffs the outgoing snapshot against the data about to be
	// published, so letting it run produces a link computed from what we
	// actually served and are about to serve. That is stronger than relaying
	// the primary's sequence verbatim: it cannot ship a delta that disagrees
	// with our own content, whatever the primary sent.
	//
	// Non-signing only, per §5. A signing secondary re-signs on publish, and
	// while the same diff would in principle capture that too, the interaction
	// between signing, NSEC chain regeneration and the chain update is not
	// something this project audited. Deferred to PR-2 deliberately rather
	// than assumed safe.
	zd.wsIxfrEpochReset = !(new_zd != nil && new_zd.ixfrDerived && !zd.signsItsOwnContent())
	// This content came from a file or from an upstream, so whatever RRSIGs it
	// carries are not ours. A zone that signs its own content must sign it
	// before it is published, not in a pass afterwards.
	//
	// Scoped, not wholesale, when the replacement is an applied IXFR delta:
	// materializeForIxfr deep-copied exactly the owners the delta reached and
	// SHARES the rest with the published snapshot, and a full pass would stage
	// -- and therefore cloneOwner -- every owner it walked, re-materialising the
	// whole zone for a two-record change. See wsSignOwners.
	switch {
	case !zd.signsItsOwnContent():
		zd.wsNeedsFullSign, zd.wsSignOwners = false, nil
	case new_zd != nil && new_zd.ixfrDerived && new_zd.ixfrTouched != nil:
		zd.wsNeedsFullSign, zd.wsSignOwners = false, new_zd.ixfrTouched
	default:
		zd.wsNeedsFullSign, zd.wsSignOwners = true, nil
	}
	zd.publishWorkingSetLocked(zd.generation.Load(), false)

	// Only advertise the zone as Ready once a snapshot actually exists. If the
	// publish was dropped (zone no longer live / generation guard), leaving
	// Ready=true with snapshot==nil would let a query dereference a nil apex
	// (M2). Gate Ready on a real published snapshot.
	if !firstLoad && zd.snapshotContentIsServableLocked(zd.snapshot.Load()) {
		zd.Ready = true
		zd.Status = ZoneStatusReady
	}
	return nil
}

// signingMaterial is one publish's signing context: the active keys and the TTL
// clamp, resolved ONCE at the top of publishWorkingSetLocked and handed to every
// step that signs.
//
// A nil *signingMaterial means "this publish cannot sign" -- either the zone
// does not sign its own content, or its keys cannot be resolved yet because the
// policy has not bound. Every signing step stands down on nil rather than
// deciding for itself.
//
// Resolving once is not just tidiness. Three helpers used to test
// zd.DnssecPolicy == nil independently -- the SOA re-sign, the NSEC restitch and
// the ZONEMD gate -- and each therefore skipped on a RESTART, where the policy
// is nil but the keys exist. A zone would then flip Ready with a signed apex SOA
// and no denial chain at all: signed positive answers, absent negative ones.
// One resolution, one answer, no way for the steps to disagree.
//
// It also fixes the shape problem in zonemdSignableLocked, which runs before the
// restitch (its answer decides whether the apex NSEC bitmap lists ZONEMD) and so
// cannot call EnsureActiveDnssecKeys itself -- that is not a predicate, it mints
// a zone's first keys as a side effect.
type signingMaterial struct {
	dak   *DnssecKeys
	clamp *ClampParams
}

// resolveSigningMaterialLocked resolves this publish's signing context.
//
// (nil, nil) means the publish cannot sign and that is ordinary: the zone does
// not sign its own content, must not originate it, or is a brand-new zone whose
// policy has not bound and whose keys therefore cannot be minted yet.
// (nil, err) means resolution genuinely failed and the publish must be refused.
//
// The distinction is ErrDnssecPolicyNotBound, and testing zd.DnssecPolicy == nil
// instead is the bug this replaces: a restart has a nil policy AND usable keys,
// so the pointer test skips signing on every process start, and after C5 nothing
// downstream signs it either.
func (zd *ZoneData) resolveSigningMaterialLocked() (*signingMaterial, error) {
	if !zd.signsItsOwnContent() || !zoneMayOriginateContent(zd) {
		return nil, nil
	}
	// No KeyDB, nothing to resolve from. Matches what zonemdSignableLocked has
	// always said (`DnssecPolicy != nil && KeyDB != nil`) and is load-bearing
	// rather than defensive: the KeyDB accessors do not guard their receiver all
	// the way down -- loadDnssecKeysFromDB dereferences it -- so reaching them
	// with nil is a SIGSEGV in the publish path. The old DnssecPolicy == nil
	// test happened to shield this; the corrected predicate does not, so the
	// guard has to be explicit.
	if zd.KeyDB == nil {
		return nil, nil
	}
	// zdLocked=true: we hold zd.mu, and the resolution must not re-enter it.
	dak, err := zd.EnsureActiveDnssecKeys(zd.KeyDB, true)
	switch {
	case errors.Is(err, ErrDnssecPolicyNotBound):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("resolving signing keys: %w", err)
	}
	var clamp *ClampParams
	if zd.DnssecPolicy != nil {
		if clamp, err = ClampParamsForZone(zd.KeyDB, zd.ZoneName, zd.DnssecPolicy, time.Now()); err != nil {
			return nil, fmt.Errorf("resolving the TTL clamp: %w", err)
		}
	}
	return &signingMaterial{dak: dak, clamp: clamp}, nil
}

// signStagedScopeLocked signs the scope applyRefreshReplacementLocked staged:
// every authored owner after an AXFR or a file reload, or just the owners an
// inbound IXFR touched. No staged scope means nothing to do.
func (zd *ZoneData) signStagedScopeLocked(sm *signingMaterial) error {
	if sm == nil || (!zd.wsNeedsFullSign && zd.wsSignOwners == nil) {
		return nil
	}
	// force=false: sign what is unsigned, which after a wholesale replacement is
	// everything, and after an IXFR is what the delta brought.
	// signNsec=false: restitchNsecLocked regenerates and signs the chain a few
	// lines below, so signing it here would be thrown away.
	_, _, err := zd.signWorkingSetLocked(sm.dak, sm.clamp, false, false, zd.wsSignOwners)
	return err
}

// refuseUnsignableWorkingSetLocked drops a publish whose content could not be
// signed, keeping the previous snapshot on the wire.
//
// DnssecError, which is service-impacting (enums.go): the zone renders as an
// ERROR and the query, NOTIFY and UPDATE handlers refuse. That is deliberate. A
// signed zone whose signing is broken IS broken, and saying so is better than
// quietly serving an ageing snapshot while the operator believes all is well.
// The last good version stays published either way -- refusing the swap is what
// guarantees that -- but the zone does not pretend to be healthy.
//
// Note the contrast with refuseUnrepairableChainLocked below, which records a
// warning for a structurally similar refusal. The severities genuinely differ:
// an unrepairable chain is a defect in derived data, an unsignable zone means
// this server can no longer produce the signatures its own configuration says
// it must.
func (zd *ZoneData) refuseUnsignableWorkingSetLocked(prevSerial uint32, err error) {
	zd.CurrentSerial = prevSerial
	lg.Error("publish: refusing to publish unsigned content for a zone that signs"+
		" its own; the previous snapshot is still being served and the change"+
		" remains staged", "zone", zd.ZoneName, "error", err)
	zd.setErrorLocked(DnssecError,
		"the refreshed zone could not be signed, so it was not published: %v", err)
}

// refuseUnrepairableChainLocked abandons a publish whose NSEC chain could not
// be repaired. Runs with zd.mu HELD, which is the whole reason it exists as a
// function: the obvious spelling of this -- zd.SetError -- takes zd.mu itself
// and deadlocks the publish it is trying to report on.
//
// Serving a zone whose chain does not describe it is the failure this path
// exists to prevent, and a secondary cannot repair it: having no private key,
// it answers denial from whatever chain it was handed. So the previous
// snapshot goes on being served, which is at least self-consistent, and the
// change stays staged in the working set for the next publish to retry.
//
// The serial is rolled back with it. It was advanced before the repair ran,
// and leaving it advanced would have publishSync report a serial to its caller
// that no snapshot carries and no secondary will ever be offered.
func (zd *ZoneData) refuseUnrepairableChainLocked(prevSerial uint32, err error) {
	zd.CurrentSerial = prevSerial
	lg.Error("publish: refusing to publish, because the NSEC chain could not be"+
		" repaired to describe this zone; the previous snapshot is still being"+
		" served and the change remains staged",
		"zone", zd.ZoneName, "error", err)
	zd.setErrorLocked(DnssecPolicyWarning,
		"the NSEC chain could not be repaired, so the zone was not published: %v", err)
}

func (zd *ZoneData) buildSnapshotLocked(serial uint32, data map[string]*OwnerData, signalSynth map[string]*core.RRset) *zoneSnapshot {
	apex := apexFromSnapshotData(zd, data)
	return &zoneSnapshot{
		Serial:      serial,
		SOA:         soaFromApex(serial, apex),
		Apex:        apex,
		Data:        data,
		signalSynth: cloneSignalSynth(signalSynth),
		IxfrChain:   copyIxfrChain(zd.IxfrChain),
	}
}

func (zd *ZoneData) setWorkingSetSOASerial(serial uint32) {
	if zd.workingSet == nil {
		return
	}
	apex := zd.workingSet[zd.ZoneName]
	if apex == nil {
		return
	}
	rs := cloneRRset(apex.RRtypes.GetOnlyRRSet(dns.TypeSOA))
	if len(rs.RRs) == 0 {
		return
	}
	soa, ok := rs.RRs[0].(*dns.SOA)
	if !ok {
		return
	}
	soa.Serial = serial
	// Stage into a cloned apex owner rather than writing through the shared
	// snapshot store — the previous in-place Set tore concurrent readers.
	zd.cloneOwner(zd.ZoneName).RRtypes.Set(dns.TypeSOA, rs)
}

func (zd *ZoneData) publishNow(gen uint64) {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	zd.publishLocked(gen)
}

// InstallInitialSnapshot builds the first published snapshot from the fully
// initialized zone data (after OnFirstLoad / SetupZoneSigning) and marks the
// zone genuinely servable. Discharges the Ready=true "lie".
func (zd *ZoneData) InstallInitialSnapshot() {
	zd.startPublisher()
	zd.mu.Lock()
	defer zd.mu.Unlock()

	data := snapshotMapFromData(zd.Data)
	if apexFromSnapshotData(zd, data) == nil {
		// zd.Data carries no apex. Two cases:
		//   1. The load path (initialLoadZone -> applyRefreshReplacementLocked)
		//      already published a valid snapshot and left zd.Data empty; here
		//      InstallInitialSnapshot's only job is to mark the zone Ready. Do NOT
		//      overwrite the good snapshot with an apex-less one — just flip Ready.
		//   2. There is also no valid snapshot: genuinely nothing to serve (e.g.
		//      an empty rebuild during reload). Refuse and leave the zone not
		//      Ready — marking a zone with a nil apex/SOA Ready is exactly what
		//      crashed readers (GetSOA -> nil).
		if cur := zd.snapshot.Load(); cur != nil && cur.SOA != nil {
			zd.markReadyIfServableLocked(cur)
			return
		}
		lg.Error("InstallInitialSnapshot: no apex in data and no valid snapshot; zone left not Ready", "zone", zd.ZoneName)
		return
	}
	// This is a re-baseline from zd.Data outside the publish path: a new
	// IXFR epoch by definition (no delta links the previous snapshot to it).
	zd.IxfrChain = nil
	snap := zd.buildSnapshotLocked(zd.CurrentSerial, data, nil)
	zd.snapshot.Store(snap)
	zd.markReadyIfServableLocked(snap)
}

// markReadyIfServableLocked flips a zone to Ready on a snapshot that qualifies,
// and notifies downstreams ONLY if this call is what flipped it.
//
// Both halves matter. A signing zone must not become Ready on a snapshot with an
// unsigned apex SOA -- Ready is what makes queries answerable (GetOwner) and
// transfers possible, so publishing an unsigned first snapshot is only safe
// while the flag is false.
//
// And the notify has to be conditional, because publishWorkingSetLocked flips
// Ready too. On a restart the refresh publish signs, flips and notifies before
// this ever runs; emitting again here would be a second NOTIFY for one serial.
// The case that still needs it is a first load whose policy sync BACKFILLS:
// that publish was pre-Ready and silent, the backfill re-signs nothing and
// publishes nothing, so without this the zone serves a new serial no downstream
// is told about.
func (zd *ZoneData) markReadyIfServableLocked(snap *zoneSnapshot) {
	if zd.Ready || !zd.snapshotContentIsServableLocked(snap) {
		return
	}
	zd.Ready = true
	zd.Status = ZoneStatusReady
	zd.notifyIfServableLocked(snap)
}

func (zd *ZoneData) startPublisher() {
	zd.publisherOnce.Do(func() {
		zd.publishWake = make(chan struct{}, 1)
		zd.publishStop = make(chan struct{})
		go zd.runPublisher()
	})
}

// stopPublisher terminates the per-zone publisher goroutine started by
// startPublisher. Safe to call at most once; a no-op if the publisher never
// started. Callers that remove or replace a zone should call this so the
// goroutine does not stay parked on publishWake forever.
func (zd *ZoneData) stopPublisher() {
	zd.publishStopOnce.Do(func() {
		if zd.publishStop != nil {
			close(zd.publishStop)
		}
	})
}

// stopZonePublisher stops the per-zone publisher goroutine for the zone
// currently registered under name (if any), so it does not leak when the zone is
// removed from the Zones registry.
func stopZonePublisher(name string) {
	if zd, ok := Zones.Get(name); ok && zd != nil {
		zd.stopPublisher()
	}
}

func (zd *ZoneData) wakePublisher() {
	select {
	case zd.publishWake <- struct{}{}:
	default:
	}
}

func (zd *ZoneData) runPublisher() {
	var timer *time.Timer
	var timerC <-chan time.Time
	for {
		select {
		case <-zd.publishStop:
			if timer != nil {
				timer.Stop()
			}
			return
		case <-zd.publishWake:
		case <-timerC:
		}
		if timer != nil {
			timer.Stop()
			timer = nil
			timerC = nil
		}

		for {
			zd.mu.Lock()
			if !zd.publishQueued {
				zd.mu.Unlock()
				break
			}
			urgent := zd.publishUrgent
			cadence := publishCadenceForZone(zd)
			since := time.Since(zd.lastPublish)
			if urgent || zd.lastPublish.IsZero() || since >= cadence {
				gen := zd.generation.Load()
				zd.publishLocked(gen)
				zd.mu.Unlock()
				continue
			}
			wait := cadence - since
			zd.mu.Unlock()
			timer = time.NewTimer(wait)
			timerC = timer.C
			break
		}
	}
}

// snapshotGeneration returns the live snapshot serial for tests.
func (zd *ZoneData) snapshotGeneration() uint32 {
	snap := zd.snapshot.Load()
	if snap == nil {
		return 0
	}
	return snap.Serial
}

func (zd *ZoneData) testPublishNow() {
	zd.publishNow(zd.generation.Load())
}
