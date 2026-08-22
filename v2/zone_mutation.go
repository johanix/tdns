package tdns

import (
	"fmt"
	"sort"
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

func (zd *ZoneData) cloneOwner(name string) *OwnerData {
	src := zd.workingSet[name]
	nod := &OwnerData{Name: name, RRtypes: NewRRTypeStore()}
	if src != nil {
		for _, t := range src.RRtypes.Keys() {
			rs, _ := src.RRtypes.Get(t)
			nod.RRtypes.Set(t, rs)
		}
		// The NSEC property travels with the owner. Rebuilding an owner from
		// its RRtypes alone would drop the chain entry silently, and the name
		// would fall out of the chain on the next publish without anything
		// having asked for that.
		nod.NSEC = src.NSEC
	}
	zd.workingSet[name] = nod
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
	zd.workingSet[name] = od
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
	return zd.workingSet[name]
}

func (zd *ZoneData) getOrCreateWorkingOwner(name string) *OwnerData {
	zd.ensureWorkingSet()
	if od := zd.workingSet[name]; od != nil {
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
	// The two differ whenever a label boundary falls inside a shared prefix:
	// "ns.example." sorts after "alpha.example." canonically but before
	// "clean.example." as a plain string.
	sort.Slice(names, func(i, j int) bool { return canonicalOwnerLess(names[i], names[j]) })
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
func (zd *ZoneData) resignWorkingSetSOAIfSigned() {
	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return
	}
	// Role gate (Fix E). SetupZoneSigning has one — "a non-primary signs only
	// with inline-signing" — but this path did not, and it runs inside
	// publishWorkingSetLocked, i.e. on EVERY publish including the refresh
	// path. Without this, a tdns-auth secondary carrying `online-signing`
	// re-signs the upstream SOA with locally generated keys (EnsureActiveDnssecKeys
	// below will mint them if absent) — signatures from a key that is not in the
	// zone's published DNSKEY RRset, i.e. BOGUS to every validator downstream.
	// `online-signing` is also normalized off for such a zone; this is the
	// defence in depth behind that.
	if !zoneMayOriginateContent(zd) {
		return
	}
	// A new zone's DNSSEC policy is bound post-Ready (PR-2 defers binding so a
	// restart cannot hide applied≠intent, blocking ①). Until it is bound there is
	// nothing to re-sign under, and EnsureActiveDnssecKeys below would deref a nil
	// zd.DnssecPolicy while generating the zone's first keys (SIGSEGV at
	// sign.go GenerateKeypair). Skip — SetupZoneSigning signs the zone after the
	// post-Ready sync binds the policy.
	if zd.DnssecPolicy == nil {
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
	// This runs UNDER zd.mu (called from publishWorkingSetLocked). Resolve the
	// active keys here with zdLocked=true and pass the non-nil dak into
	// SignRRset, so SignRRset does NOT fall into its own EnsureActiveDnssecKeys
	// call (which would reach PublishDnskeyRRs and re-lock zd.mu → self-deadlock,
	// the same class as the SignZone/UpdateSigValidityFloor deadlock in 6e090a9).
	dak, err := zd.EnsureActiveDnssecKeys(zd.KeyDB, true)
	if err != nil {
		lg.Error("publish: failed to ensure DNSSEC keys for SOA re-sign", "zone", zd.ZoneName, "err", err)
		return
	}
	if _, err := zd.SignRRset(&rs, zd.ZoneName, dak, true, nil); err != nil {
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
	zd.workingSet[name] = od
}

func (zd *ZoneData) stageOwnerDeleteLocked(name string) {
	zd.ensureWorkingSet()
	delete(zd.workingSet, name)
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

	zd.resignWorkingSetSOAIfSigned()

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

	_ = zd.NotifyDownstreams()
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
	zd.XfrType = new_zd.XfrType
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
	// A refresh replaces zone data wholesale: new IXFR epoch, no delta.
	zd.wsIxfrEpochReset = true
	zd.publishWorkingSetLocked(zd.generation.Load(), false)

	// Only advertise the zone as Ready once a snapshot actually exists. If the
	// publish was dropped (zone no longer live / generation guard), leaving
	// Ready=true with snapshot==nil would let a query dereference a nil apex
	// (M2). Gate Ready on a real published snapshot.
	if !firstLoad && zd.snapshot.Load() != nil {
		zd.Ready = true
		zd.Status = ZoneStatusReady
	}
	return nil
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
			zd.Ready = true
			zd.Status = ZoneStatusReady
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
	zd.Ready = true
	zd.Status = ZoneStatusReady
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
