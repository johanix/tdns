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
	if zd.wsTransportSignal == nil {
		zd.wsTransportSignal = cloneTransportSignal(snap.TransportSignal)
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
	if _, err := zd.SignRRset(&rs, zd.ZoneName, nil, true, nil); err != nil {
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
	zd.ensureWorkingSet()
	zd.cloneOwner(name).RRtypes.Set(rs.RRtype, cloneRRset(rs))
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
		zd.wsTransportSignal = nil
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

	transport := zd.wsTransportSignal
	if transport == nil {
		transport = zd.TransportSignal
	}

	data := zd.workingSet
	snap := zd.buildSnapshotLocked(serial, data, transport)
	zd.snapshot.Store(snap)

	zd.workingSet = nil
	zd.wsTransportSignal = nil
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
	zd.wsTransportSignal = nil
	zd.repopulateWorkingSetLocked(dynamicRRs)
	zd.publishWorkingSetLocked(zd.generation.Load(), false)

	if !firstLoad {
		zd.Ready = true
		zd.Status = ZoneStatusReady
	}
	return nil
}

func (zd *ZoneData) buildSnapshotLocked(serial uint32, data map[string]*OwnerData, transport *core.RRset) *ZoneSnapshot {
	apex := apexFromSnapshotData(zd, data)
	return &ZoneSnapshot{
		Serial:          serial,
		SOA:             soaFromApex(serial, apex),
		Apex:            apex,
		Data:            data,
		TransportSignal: cloneTransportSignal(transport),
		IxfrChain:       copyIxfrChain(zd.IxfrChain),
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
	rs := apex.RRtypes.GetOnlyRRSet(dns.TypeSOA)
	if len(rs.RRs) == 0 {
		return
	}
	soa := dns.Copy(rs.RRs[0]).(*dns.SOA)
	soa.Serial = serial
	rs.RRs[0] = soa
	apex.RRtypes.Set(dns.TypeSOA, rs)
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
	snap := zd.buildSnapshotLocked(zd.CurrentSerial, data, zd.TransportSignal)
	zd.snapshot.Store(snap)
	zd.Ready = true
	zd.Status = ZoneStatusReady
}

func (zd *ZoneData) startPublisher() {
	zd.publisherOnce.Do(func() {
		zd.publishWake = make(chan struct{}, 1)
		go zd.runPublisher()
	})
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
