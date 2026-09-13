/*
 * Copyright (c) Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdns

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/miekg/dns"
)

var lgDSEngine = Logger("dsengine")

// DSModel is how a zone's DS RRset at its parent is meant to change as its KSKs
// change.
//
// The DS engine asks the model which DS the parent should hold now. It cannot be
// a "make sure key K has a CDS" service: under multi-DS a key's DS goes to the
// parent before its DNSKEY is published, under double-signature only after the
// new key has signed alongside the old one, and a multi-provider zone's DS set
// includes keys this signer never held.
type DSModel uint8

const (
	// DSModelNone is a zone without automated KSK rollover. The parent's DS
	// follows the keystore's DS-bearing keys (DSIntentForZone).
	DSModelNone DSModel = iota
	// DSModelMultiDS keeps a pipeline of pre-published DS at the parent. The
	// target is the rollover engine's (loadTargetKSKsForRollover).
	DSModelMultiDS
	// DSModelDoubleSignature publishes the new DNSKEY and signs with both keys
	// before the DS is swapped. The policy parser accepts it; the rollover engine
	// does not implement it.
	DSModelDoubleSignature
	// DSModelMultiProvider is a zone whose DNSKEY RRset carries every provider's
	// keys, so its DS set is the SEP keys of that RRset.
	DSModelMultiProvider
)

func (m DSModel) String() string {
	switch m {
	case DSModelNone:
		return "none"
	case DSModelMultiDS:
		return "multi-ds"
	case DSModelDoubleSignature:
		return "double-signature"
	case DSModelMultiProvider:
		return "multi-provider"
	}
	return fmt.Sprintf("unknown(%d)", int(m))
}

// dsModelForZone reports a zone's DS model. multi-provider wins over the
// rollover method, as it does for the rollover engine, which skips such zones.
func dsModelForZone(zd *ZoneData) DSModel {
	if zd.Options[OptMultiProvider] {
		return DSModelMultiProvider
	}
	if zd.DnssecPolicy == nil {
		return DSModelNone
	}
	switch zd.DnssecPolicy.Rollover.Method {
	case RolloverMethodMultiDS:
		return DSModelMultiDS
	case RolloverMethodDoubleSignature:
		return DSModelDoubleSignature
	}
	return DSModelNone
}

var (
	// errDSEngineNotRunning: nothing is serving KeyDB.DSEngineQ.
	errDSEngineNotRunning = errors.New("the DS engine is not running")
	// errDSModelNotImplemented: the zone's DS model has no implementation here.
	errDSModelNotImplemented = errors.New("DS model not implemented")
)

const (
	dsEngineEnqueueTimeout = 5 * time.Second
	// dsEngineReplyTimeout bounds the wait for an answer. The engine serves one
	// request at a time and each may wait UpdateApplyTimeout on the zone updater,
	// so this leaves room for a couple queued ahead.
	dsEngineReplyTimeout = 3 * UpdateApplyTimeout
)

type dsEngineCmd uint8

const (
	// dsCmdPublishRolloverCDS: the rollover engine's NOTIFY push.
	dsCmdPublishRolloverCDS dsEngineCmd = iota + 1
	// dsCmdReleaseRolloverCDS: the rollover engine's cleanup triggers.
	dsCmdReleaseRolloverCDS
	// dsCmdEnsureCDS: delegation sync, before a NOTIFY(CDS).
	dsCmdEnsureCDS
)

// DSEngineRequest is one request to the DS engine. Requests are built inside
// tdns only; the type is exported because KeyDB.DSEngineQ is.
type DSEngineRequest struct {
	cmd      dsEngineCmd
	zd       *ZoneData
	snapshot *RolloverTargetKeySnapshot
	resp     chan dsEngineResult
	// ctx is cancelled when the requester stops waiting. The engine skips a
	// request whose requester has already given up; once it has started on one
	// it finishes under its own context, so a CDS publish is never separated from
	// the claim recorded with it by a requester that left in between.
	ctx context.Context
}

type dsEngineResult struct {
	// cds is the CDS RRset the zone now serves.
	cds []dns.RR
	// low, high and rangeKnown are the rollover index range recorded as the
	// rollover engine's claim on cds, when one was.
	low, high  int
	rangeKnown bool
	// deferred, when set, says why nothing was published although nothing
	// failed: the DS belongs to someone other than the requester.
	deferred string
	err      error
}

// DSEngine is the child side's single owner of what a zone asks its parent to
// hold as DS (docs/2026-09-13-ds-engine-design.md).
//
// In this first step it owns the CDS RRset. The KSK rollover engine asks it to
// publish and to release the rollover target's CDS; delegation sync asks it for
// the CDS a NOTIFY(CDS) points at; PublishDnskeyRRs marks zones that serve a CDS
// and have changed their KSKs, and the engine brings their CDS back in step.
//
// One goroutine serves every zone, one request at a time. That is the point:
// what this replaces is two writers each replacing the whole CDS RRset from their
// own view. A request may wait up to UpdateApplyTimeout on the zone updater.
func (kdb *KeyDB) DSEngine(ctx context.Context) error {
	lgDSEngine.Info("DSEngine: starting")
	wake := kdb.dsWake()
	for {
		select {
		case <-ctx.Done():
			lgDSEngine.Info("DSEngine: terminating")
			return nil
		case <-wake:
			for _, zd := range kdb.takeDSDirty() {
				kdb.followKeysWithCDS(ctx, zd)
			}
		case req, ok := <-kdb.DSEngineQ:
			if !ok {
				lgDSEngine.Info("DSEngine: queue closed, terminating")
				return nil
			}
			if req.ctx != nil && req.ctx.Err() != nil {
				// Nobody is waiting for the answer any more, and the requester has
				// already reported the attempt as failed: publishing or withdrawing
				// a CDS now would be work its owner does not know happened.
				lgDSEngine.Debug("skipping a request whose requester stopped waiting",
					"cmd", int(req.cmd), "zone", dsRequestZone(req))
				continue
			}
			res := kdb.serveDSEngineRequest(ctx, req)
			if req.resp != nil {
				// resp has room for exactly this answer, so this never waits on a
				// requester that has given up.
				select {
				case req.resp <- res:
				default:
				}
			}
		}
	}
}

func dsRequestZone(req DSEngineRequest) string {
	if req.zd == nil {
		return ""
	}
	return req.zd.ZoneName
}

// askDSEngine hands req to the DS engine and waits for its answer.
//
// Bounded at both ends: an engine that is missing or wedged must fail the
// requester -- a rollover tick, or the delegation syncher, each serving every
// zone -- rather than stall it. The request is cancelled when this returns, so
// one still queued is skipped instead of served for nobody.
func (kdb *KeyDB) askDSEngine(ctx context.Context, req DSEngineRequest) dsEngineResult {
	if kdb == nil || kdb.DSEngineQ == nil {
		return dsEngineResult{err: errDSEngineNotRunning}
	}
	reqCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	req.ctx = reqCtx
	req.resp = make(chan dsEngineResult, 1)
	select {
	case kdb.DSEngineQ <- req:
	case <-reqCtx.Done():
		return dsEngineResult{err: fmt.Errorf("handing a request to the DS engine: %w", reqCtx.Err())}
	case <-time.After(dsEngineEnqueueTimeout):
		return dsEngineResult{err: fmt.Errorf("%w: its queue took nothing for %s",
			errDSEngineNotRunning, dsEngineEnqueueTimeout)}
	}
	select {
	case res := <-req.resp:
		return res
	case <-reqCtx.Done():
		return dsEngineResult{err: fmt.Errorf("waiting for the DS engine: %w", reqCtx.Err())}
	case <-time.After(dsEngineReplyTimeout):
		return dsEngineResult{err: fmt.Errorf("the DS engine did not answer within %s", dsEngineReplyTimeout)}
	}
}

// dsEngineKeysChanged records that zd's KSK set changed, for the DS engine to
// bring its CDS back in step.
//
// Called from the signing path with zd.mu held, so it must not block, and it must
// not lose the change either: a CDS left out of step with the keys is the case
// this exists for. So it marks the zone rather than queueing a request. A zone is
// marked once however many times it changes before the engine looks, and the
// wake-up signal has room for one, so neither can fill up.
func (kdb *KeyDB) dsEngineKeysChanged(zd *ZoneData) {
	if kdb == nil || kdb.DSEngineQ == nil || zd == nil {
		return
	}
	kdb.dsDirtyMu.Lock()
	if kdb.dsDirty == nil {
		kdb.dsDirty = make(map[string]*ZoneData)
	}
	kdb.dsDirty[zd.ZoneName] = zd
	wake := kdb.dsWakeLocked()
	kdb.dsDirtyMu.Unlock()
	select {
	case wake <- struct{}{}:
	default: // already signalled; the engine will find this zone marked
	}
}

func (kdb *KeyDB) dsWake() chan struct{} {
	kdb.dsDirtyMu.Lock()
	defer kdb.dsDirtyMu.Unlock()
	return kdb.dsWakeLocked()
}

func (kdb *KeyDB) dsWakeLocked() chan struct{} {
	if kdb.dsWakeCh == nil {
		kdb.dsWakeCh = make(chan struct{}, 1)
	}
	return kdb.dsWakeCh
}

// takeDSDirty returns the zones marked by dsEngineKeysChanged, in name order, and
// clears the marks.
func (kdb *KeyDB) takeDSDirty() []*ZoneData {
	kdb.dsDirtyMu.Lock()
	defer kdb.dsDirtyMu.Unlock()
	out := make([]*ZoneData, 0, len(kdb.dsDirty))
	for _, zd := range kdb.dsDirty {
		out = append(out, zd)
	}
	kdb.dsDirty = nil
	sort.Slice(out, func(i, j int) bool { return out[i].ZoneName < out[j].ZoneName })
	return out
}

func (kdb *KeyDB) serveDSEngineRequest(ctx context.Context, req DSEngineRequest) dsEngineResult {
	if req.zd == nil {
		return dsEngineResult{err: errors.New("DS engine request without a zone")}
	}
	switch req.cmd {
	case dsCmdPublishRolloverCDS:
		return kdb.publishRolloverCDS(ctx, req.zd, req.snapshot, false)
	case dsCmdReleaseRolloverCDS:
		return dsEngineResult{err: kdb.releaseRolloverCDS(ctx, req.zd)}
	case dsCmdEnsureCDS:
		return kdb.ensureCDS(ctx, req.zd)
	}
	return dsEngineResult{err: fmt.Errorf("unknown DS engine command %d", req.cmd)}
}

// publishRolloverCDS publishes the CDS for the multi-DS rollover target, waits
// until the zone serves it, and records the target's index range as the
// rollover engine's claim on it, which its cleanup triggers compare against.
//
// snap is the rollover's own snapshot of its target keys, so that a NOTIFY push
// describes the same set as the UPDATE push running beside it; nil recomputes it.
//
// requireRange refuses a target with keys that have no rollover index. The
// rollover itself publishes such a target anyway and records no claim, as it
// always has; published on delegation sync's behalf it would be a CDS nothing
// ever removes.
func (kdb *KeyDB) publishRolloverCDS(ctx context.Context, zd *ZoneData, snap *RolloverTargetKeySnapshot, requireRange bool) dsEngineResult {
	child := dns.Fqdn(zd.ZoneName)
	var (
		cds       []dns.RR
		low, high int
		idxOK     bool
		err       error
	)
	if snap != nil {
		cds, low, high, idxOK, err = cdsSetFromSnapshot(snap, child)
	} else {
		cds, low, high, idxOK, err = ComputeTargetCDSSetForZone(kdb, child)
	}
	if err != nil {
		return dsEngineResult{err: err}
	}
	if len(cds) == 0 {
		return dsEngineResult{err: fmt.Errorf("no CDS records to publish for zone %s", child)}
	}
	if requireRange && !idxOK {
		return dsEngineResult{err: fmt.Errorf("zone %s: the rollover target has keys without a rollover index,"+
			" so the rollover engine could never clean up a CDS published for it", child)}
	}
	if err := zd.publishCDSAndWait(ctx, kdb, cds); err != nil {
		return dsEngineResult{err: err}
	}
	// The claim is recorded after the publish and before anyone is told to fetch
	// the CDS. Not before the publish: a publish that then failed would leave the
	// previous CDS served under a claim that no longer describes it, and nothing
	// would ever remove it. A CDS whose claim cannot be recorded is taken back
	// down instead, for the same reason.
	if idxOK {
		if err := setPublishedCdsRange(kdb, child, low, high); err != nil {
			return dsEngineResult{err: zd.withdrawUnclaimedCDS(ctx, kdb, fmt.Errorf("persist CDS range: %w", err))}
		}
	} else if err := clearPublishedCdsRange(kdb, child); err != nil {
		return dsEngineResult{err: fmt.Errorf("clear CDS range: %w", err)}
	}
	lgDSEngine.Debug("published the rollover target's CDS", "zone", child, "keyids", cdsKeyids(cds),
		"index_low", low, "index_high", high, "index_known", idxOK)
	return dsEngineResult{cds: cds, low: low, high: high, rangeKnown: idxOK}
}

// withdrawUnclaimedCDS takes down a CDS just published whose claim could not be
// recorded, and returns cause, with the withdrawal's own failure if it had one.
func (zd *ZoneData) withdrawUnclaimedCDS(ctx context.Context, kdb *KeyDB, cause error) error {
	if uerr := zd.unpublishCDSAndWait(ctx, kdb); uerr != nil {
		return fmt.Errorf("%w; the CDS it was for is still published: %v", cause, uerr)
	}
	return fmt.Errorf("%w; the CDS it was for has been withdrawn", cause)
}

// ensureCDS makes the zone serve the CDS its DS model says the parent should
// hold now, for delegation sync's NOTIFY(CDS).
//
// An error means there is no CDS to point the parent at, and the NOTIFY must not
// go out: a parent that scans and finds nothing concludes there is nothing to do,
// both ends report success, and the plan never tries UPDATE or API.
func (kdb *KeyDB) ensureCDS(ctx context.Context, zd *ZoneData) dsEngineResult {
	model := dsModelForZone(zd)
	var cds []dns.RR
	switch model {
	case DSModelMultiDS:
		// The rollover engine keeps this model's DS. While a phase is busy it is
		// pushing it right now, and its own NOTIFY carries its own CDS.
		if zd.rolloverOwnsDS() {
			return dsEngineResult{deferred: "the KSK rollover engine is pushing this zone's DS"}
		}
		return kdb.publishRolloverCDS(ctx, zd, nil, true)
	case DSModelDoubleSignature:
		return dsEngineResult{err: fmt.Errorf("zone %s: %w: %s", zd.ZoneName, errDSModelNotImplemented, model)}
	case DSModelMultiProvider:
		synth, err := zd.SynthesizeCdsRRs()
		if err != nil {
			return dsEngineResult{err: err}
		}
		cds = synth
	default:
		intent, err := DSIntentForZone(kdb, zd.ZoneName, dns.SHA256)
		if err != nil {
			return dsEngineResult{err: err}
		}
		if !intent.Known {
			// tdns does not manage this zone's keys, so the CDS is not ours to
			// write. Whoever signs the zone may publish one, though, and then a
			// NOTIFY(CDS) points the parent at something real.
			served, err := servedCDSRRs(zd)
			if err != nil {
				return dsEngineResult{err: err}
			}
			if len(served) > 0 {
				return dsEngineResult{cds: served}
			}
			return dsEngineResult{err: fmt.Errorf("zone %s: tdns does not manage this zone's keys"+
				" and the zone serves no CDS, so there is no CDS to point the parent at", zd.ZoneName)}
		}
		cds = cdsFromDS(zd.ZoneName, intent.Set)
	}
	if len(cds) == 0 {
		return dsEngineResult{err: fmt.Errorf("zone %s: no key warrants a DS; withdrawing the DS through CDS"+
			" needs an RFC 8078 delete CDS, which is not published", zd.ZoneName)}
	}
	if err := zd.publishCDSAndWait(ctx, kdb, cds); err != nil {
		return dsEngineResult{err: err}
	}
	lgDSEngine.Info("CDS published for delegation sync", "zone", zd.ZoneName, "model", model.String(),
		"keyids", cdsKeyids(cds))
	return dsEngineResult{cds: cds}
}

// followKeysWithCDS brings a published CDS back in step with the zone's keys,
// under the none model.
//
// Once delegation sync has asked for a CDS it stays published, and a CDS that no
// longer matches the keys is the dangerous leftover: a parent that polls CDS
// would point the DS at keys the zone has stopped using. A zone serving no CDS is
// left alone -- a CDS appears only when delegation sync asks for one -- and so is
// a zone whose keys tdns does not manage, whose CDS is not ours. Under multi-DS
// the rollover engine's cleanup triggers look after its CDS; the other models are
// not followed here.
func (kdb *KeyDB) followKeysWithCDS(ctx context.Context, zd *ZoneData) {
	if dsModelForZone(zd) != DSModelNone {
		return
	}
	current, err := currentCdsTuples(zd)
	if err != nil {
		lgDSEngine.Warn("could not read the published CDS", "zone", zd.ZoneName, "err", err)
		return
	}
	if len(current) == 0 {
		return
	}
	intent, err := DSIntentForZone(kdb, zd.ZoneName, dns.SHA256)
	if err != nil {
		lgDSEngine.Warn("could not determine the DS intent; leaving the CDS as it is",
			"zone", zd.ZoneName, "err", err)
		return
	}
	if !intent.Known {
		return
	}
	if len(intent.Set) == 0 {
		if err := zd.unpublishCDSAndWait(ctx, kdb); err != nil {
			lgDSEngine.Warn("could not withdraw the CDS of a zone whose keys warrant no DS",
				"zone", zd.ZoneName, "err", err)
			return
		}
		lgDSEngine.Info("CDS withdrawn: no key warrants a DS any more", "zone", zd.ZoneName)
		return
	}
	want := cdsFromDS(zd.ZoneName, intent.Set)
	if cdsTupleSetsEqual(cdsTuplesOf(want), current) {
		return
	}
	if err := zd.publishCDSAndWait(ctx, kdb, want); err != nil {
		lgDSEngine.Warn("could not bring the CDS back in step with the keys", "zone", zd.ZoneName, "err", err)
		return
	}
	lgDSEngine.Info("CDS brought back in step with the keys", "zone", zd.ZoneName,
		"was", tupleKeyids(current), "now", cdsKeyids(want))
}

// publishCDSAndWait replaces the zone's CDS RRset with cds, and returns once the
// zone serves exactly that RRset.
//
// Delete then add, in one update, so the apex never holds a mixture of old and
// new. And the postcondition is checked rather than inferred from the reply: the
// zone updater answers "not applied" both for an identical republish, where the
// CDS is there, and for an update it declined, where it is not -- the lesson of
// PublishCsyncRRAndWait.
func (zd *ZoneData) publishCDSAndWait(ctx context.Context, kdb *KeyDB, cds []dns.RR) error {
	actions := make([]dns.RR, 0, 1+len(cds))
	actions = append(actions, cdsDeleteRR(zd.ZoneName))
	actions = append(actions, cds...)
	if err := kdb.applyInternalUpdateAndWait(ctx, zd, actions); err != nil {
		return fmt.Errorf("publishing the CDS for %s: %w", zd.ZoneName, err)
	}
	got, err := currentCdsTuples(zd)
	if err != nil {
		return fmt.Errorf("publishing the CDS for %s: reading it back: %w", zd.ZoneName, err)
	}
	if !cdsTupleSetsEqual(cdsTuplesOf(cds), got) {
		return fmt.Errorf("publishing the CDS for %s: the update was accepted but the zone serves"+
			" CDS for keyids %v, not the requested %v", zd.ZoneName, tupleKeyids(got), cdsKeyids(cds))
	}
	return nil
}

// unpublishCDSAndWait removes the zone's CDS RRset and returns once the zone
// serves none.
func (zd *ZoneData) unpublishCDSAndWait(ctx context.Context, kdb *KeyDB) error {
	if err := kdb.applyInternalUpdateAndWait(ctx, zd, []dns.RR{cdsDeleteRR(zd.ZoneName)}); err != nil {
		return fmt.Errorf("withdrawing the CDS for %s: %w", zd.ZoneName, err)
	}
	got, err := currentCdsTuples(zd)
	if err != nil {
		return fmt.Errorf("withdrawing the CDS for %s: reading it back: %w", zd.ZoneName, err)
	}
	if len(got) != 0 {
		return fmt.Errorf("withdrawing the CDS for %s: the update was accepted but the zone still serves"+
			" CDS for keyids %v", zd.ZoneName, tupleKeyids(got))
	}
	return nil
}

// applyInternalUpdateAndWait queues an internal ZONE-UPDATE and waits for the
// zone updater to apply it.
func (kdb *KeyDB) applyInternalUpdateAndWait(ctx context.Context, zd *ZoneData, actions []dns.RR) error {
	if kdb.UpdateQ == nil {
		return errors.New("no zone updater queue")
	}
	resp := make(chan ZoneUpdateResult, 1)
	select {
	case kdb.UpdateQ <- UpdateRequest{
		Cmd:            "ZONE-UPDATE",
		ZoneName:       zd.ZoneName,
		Actions:        actions,
		InternalUpdate: true,
		Resp:           resp,
	}:
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(dsEngineEnqueueTimeout):
		return fmt.Errorf("the zone updater's queue took nothing for %s", dsEngineEnqueueTimeout)
	}
	select {
	case res := <-resp:
		return res.Err
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(UpdateApplyTimeout):
		return fmt.Errorf("timed out after %s waiting for the update to be applied", UpdateApplyTimeout)
	}
}

// cdsDeleteRR is the class-ANY record that removes the whole CDS RRset at
// zone's apex (RFC 2136 section 2.5.2).
func cdsDeleteRR(zone string) dns.RR {
	anti := &dns.CDS{}
	anti.Hdr = dns.RR_Header{
		Name:   dns.Fqdn(zone),
		Rrtype: dns.TypeCDS,
		Class:  dns.ClassANY,
		Ttl:    0,
	}
	return anti
}

// cdsFromDS is the CDS RRset asking the parent for dsSet.
func cdsFromDS(zone string, dsSet []dns.RR) []dns.RR {
	out := make([]dns.RR, 0, len(dsSet))
	for _, rr := range dsSet {
		ds, ok := rr.(*dns.DS)
		if !ok {
			continue
		}
		c := &dns.CDS{DS: *ds}
		c.Hdr = dns.RR_Header{
			Name:   dns.Fqdn(zone),
			Rrtype: dns.TypeCDS,
			Class:  dns.ClassINET,
			Ttl:    120,
		}
		out = append(out, c)
	}
	return out
}

// servedCDSRRs returns the CDS RRset the zone serves at its apex, if any.
func servedCDSRRs(zd *ZoneData) ([]dns.RR, error) {
	apex, err := zd.GetOwner(zd.ZoneName)
	if err != nil {
		return nil, fmt.Errorf("zone %s: reading the served CDS: %w", zd.ZoneName, err)
	}
	if apex == nil || apex.RRtypes == nil {
		return nil, nil
	}
	return apex.RRtypes.GetOnlyRRSet(dns.TypeCDS).RRs, nil
}

// cdsTuplesOf is the comparison set of a CDS RRset (see cdsTuple).
func cdsTuplesOf(rrs []dns.RR) map[cdsTuple]struct{} {
	out := make(map[cdsTuple]struct{}, len(rrs))
	for _, rr := range rrs {
		c, ok := rr.(*dns.CDS)
		if !ok {
			continue
		}
		out[cdsTuple{
			KeyTag:     c.DS.KeyTag,
			Algorithm:  c.DS.Algorithm,
			DigestType: c.DS.DigestType,
			Digest:     c.DS.Digest,
		}] = struct{}{}
	}
	return out
}

// tupleKeyids lists the key tags in a CDS comparison set, sorted, for logs and
// errors.
func tupleKeyids(set map[cdsTuple]struct{}) []uint16 {
	out := make([]uint16, 0, len(set))
	for t := range set {
		out = append(out, t.KeyTag)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// sepKeyIdentities is the set of SEP DNSKEYs in rrs, keyed on what makes a key
// that key: flags, protocol, algorithm and public key. TTL and owner case do not.
func sepKeyIdentities(rrs []dns.RR) map[string]struct{} {
	out := make(map[string]struct{})
	for _, rr := range rrs {
		dk, ok := rr.(*dns.DNSKEY)
		if !ok || dk.Flags&dns.SEP == 0 {
			continue
		}
		out[fmt.Sprintf("%d %d %d %s", dk.Flags, dk.Protocol, dk.Algorithm, dk.PublicKey)] = struct{}{}
	}
	return out
}

func sameKeyIdentities(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}
