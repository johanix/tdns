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
	sort.Strings(names)
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
		return
	}
	if !zoneStillLive(zd, gen) {
		zd.workingSet = nil
		zd.wsSignalSynth = nil
		zd.publishQueued = false
		zd.publishUrgent = false
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
		return
	}

	serial := zd.CurrentSerial
	if bumpSerial {
		zd.CurrentSerial = nextOutboundSerial(zd)
		serial = zd.CurrentSerial
	}
	zd.setWorkingSetSOASerial(serial)

	zd.resignWorkingSetSOAIfSigned()

	data := zd.workingSet
	snap := zd.buildSnapshotLocked(serial, data, zd.wsSignalSynth)
	zd.snapshot.Store(snap)

	zd.workingSet = nil
	zd.wsSignalSynth = nil
	zd.publishQueued = false
	zd.publishUrgent = false
	zd.lastPublish = time.Now()

	if zd.KeyDB != nil && zd.KeyDB.OutboundSoaSerial == OutboundSoaSerialPersist {
		if err := zd.KeyDB.SaveOutgoingSerial(zd.ZoneName, zd.CurrentSerial); err != nil {
			lg.Error("publish: failed to persist outgoing serial", "zone", zd.ZoneName, "err", err)
		}
	}

	if loaded := zd.snapshot.Load(); loaded != nil && loaded.Serial != zd.CurrentSerial {
		lg.Error("publish: serial mirror drift", "zone", zd.ZoneName, "current", zd.CurrentSerial, "snapshot", loaded.Serial)
	}

	_ = zd.NotifyDownstreams()
}

func (zd *ZoneData) applyRefreshReplacementLocked(new_zd *ZoneData, dynamicRRs []*core.RRset, firstLoad bool) error {
	zd.IncomingSerial = new_zd.IncomingSerial
	if firstLoad {
		zd.CurrentSerial = new_zd.CurrentSerial
		zd.FirstZoneLoad = false
	} else {
		zd.CurrentSerial++
		if zd.KeyDB != nil && zd.KeyDB.OutboundSoaSerial == OutboundSoaSerialPersist {
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
