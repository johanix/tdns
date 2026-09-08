/*
 * Copyright (c) 2024 Johan Stenstam, johani@johani.org
 */
package tdns

import (
	"fmt"
	"time"

	core "github.com/johanix/tdns/v2/core"
	"github.com/miekg/dns"
)

// renewalTarget is one RRset the periodic pass has found due, together with
// where it lives. NSEC is not an RRtypes entry, so which staging helper applies
// is a property of the target rather than something derivable from the record.
type renewalTarget struct {
	name   string
	rrtype uint16
	rrset  core.RRset
	isNsec bool
}

// RenewZoneSignatures re-signs the RRsets whose signatures are approaching
// expiry, and nothing else.
//
// It does not rebuild the NSEC chain: restitchNsecLocked maintains that on every
// publish, scoped to the names whose data actually changed. It does not
// reassemble the DNSKEY RRset: key-state changes reach the zone through
// ResignZone. Rebuilding either here would not merely waste work, it would hide
// a failure in the path that owns it -- which is what the once-a-minute
// SignZone(force=false) it replaces was doing.
//
// Returns the number of RRsets whose signatures were renewed. Zero means the
// zone was left exactly as it was: nothing staged, nothing published, no serial
// bump, no NOTIFY.
func (zd *ZoneData) RenewZoneSignatures(kdb *KeyDB) (int, error) {
	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return 0, fmt.Errorf("RenewZoneSignatures: zone %s should not be signed here (neither online-signing nor inline-signing)", zd.ZoneName)
	}
	if zd.HasError(DnssecError) {
		return 0, fmt.Errorf("RenewZoneSignatures: zone %s has DNSSEC error: %s", zd.ZoneName, zd.ErrorMsg)
	}

	// Keys and clamp are resolved before the lock, as SignZone does, and then
	// passed down: SignRRset reached with a nil dak resolves them itself with
	// zdLocked=false, which would re-take zd.mu and deadlock under the lock
	// taken below.
	dak, err := zd.EnsureActiveDnssecKeys(kdb, false)
	if err != nil {
		lgSigner.Error("RenewZoneSignatures: failed to ensure active DNSSEC keys", "zone", zd.ZoneName, "err", err)
		return 0, err
	}

	var clamp *ClampParams
	if zd.DnssecPolicy != nil {
		clamp, err = ClampParamsForZone(kdb, zd.ZoneName, zd.DnssecPolicy, time.Now())
		if err != nil {
			lgSigner.Error("RenewZoneSignatures: ClampParamsForZone failed; refusing to sign", "zone", zd.ZoneName, "err", err)
			return 0, fmt.Errorf("RenewZoneSignatures: ClampParamsForZone for zone %s: %w", zd.ZoneName, err)
		}
	}

	// One lock around the whole decide-and-sign. Walking unlocked and taking
	// zd.mu only once something turned out to be due would let a concurrent
	// publish replace the snapshot in between, leaving the collected RRsets a
	// decision about a zone version that is no longer served. The price is that
	// a pass with nothing to do holds the lock for a read-only walk.
	zd.mu.Lock()
	defer zd.mu.Unlock()

	snap := zd.snapshot.Load()
	if snap == nil {
		// Nothing published yet, so there are no signatures to renew.
		// Producing the first signed version is SignZone's job.
		return 0, nil
	}

	// Renewal is decided against the version that will be served NEXT: a staged
	// working set when a writer has left one, the published snapshot otherwise.
	//
	// Deciding from the snapshot while a change is staged, and then staging the
	// result, would silently revert that change -- stageRRsetLocked would put a
	// re-signed copy of the published version over the pending one. Declining to
	// run at all while a working set exists is worse: a zone update that is
	// rejected still leaves one behind (ensureWorkingSet runs before the
	// `updated` check in ApplyZoneUpdateToZoneData), and on a zone that is not
	// updated again there would be no next publish to clear it. Renewal would
	// stop for good, and the signatures would expire.
	// A leftover from a rejected or no-op zone update is not a pending change,
	// and treating it as one keeps this zone's schedule permanently unknown --
	// which drags the whole watchlist down to the floor (nextResignWake). Drop
	// it here rather than walk it: it is identical to the snapshot anyway.
	if zd.dropBareWorkingSetLocked() {
		lgSigner.Debug("RenewZoneSignatures: dropped a working set carrying nothing",
			"zone", zd.ZoneName)
	}

	pending := zd.workingSet != nil
	source := snap.Data
	if pending {
		source = zd.workingSet
	}

	due, nextDue, publishOwned := zd.collectAgeingSignaturesLocked(source)
	if pending {
		// The estimate describes a version that is not published, so it is not
		// something the resigner may sleep on.
		zd.setResignSchedule(time.Time{}, 0)
	} else {
		zd.setResignSchedule(nextDue, snap.Serial)
	}
	if len(due) == 0 && publishOwned == 0 {
		return 0, nil
	}

	// Sign clones, off to the side. The working set is not even created until
	// at least one signature has actually been written, which is what keeps a
	// pass that renews nothing from bumping the serial -- and what keeps this
	// pass from writing through to the snapshot that is being served right now.
	// ensureWorkingSet is a SHALLOW copy and SignRRset rewrites TTLs in place
	// without rolling them back on the success path, so an RRset that shares
	// storage with the snapshot must never be handed to it.
	signed := make([]renewalTarget, 0, len(due))
	for _, t := range due {
		rs := cloneRRset(t.rrset)
		resigned, err := zd.SignRRset(&rs, zd.ZoneName, dak, false, clamp)
		if err != nil {
			// A failure here is a property of the zone -- key material, the
			// clamp -- rather than of one RRset, so there is nothing to be
			// gained by carrying on and publishing half a renewal. Nothing has
			// been staged yet, so returning leaves the zone exactly as it was
			// and the next pass retries.
			return 0, fmt.Errorf("RenewZoneSignatures: %s %s: %w",
				t.name, dns.TypeToString[t.rrtype], err)
		}
		if !resigned {
			// Collected as due, declined by SignRRset: the ageing signature is
			// by a key that is no longer active, or the clamp lowered the TTL
			// enough to move the threshold back below the remaining validity.
			// Either way it is not this pass's business to force it.
			continue
		}
		t.rrset = rs
		signed = append(signed, t)
	}
	if len(signed) == 0 && publishOwned == 0 {
		return 0, nil
	}

	zd.ensureWorkingSet()
	for _, t := range signed {
		if t.isNsec {
			zd.stageNsecLocked(t.name, t.rrset)
			continue
		}
		zd.stageRRsetLocked(t.name, t.rrset)
	}

	// A publish here is wanted: new signatures should reach downstreams, and the
	// serial bump is how they learn. The publish also re-signs the SOA over the
	// new serial and recomputes the ZONEMD -- which is why a publish-owned
	// signature coming due is on its own a reason to publish, with nothing
	// staged at all.
	zd.publishLocked(zd.generation.Load())

	// A publish that did not renew what it owns would put this pass in a loop,
	// publishing and bumping the serial on every tick because the same
	// signature is still due -- the storm, rebuilt from the other end. The gate
	// on publishOwned is meant to make that impossible; say so loudly rather
	// than quietly spin if it ever is not.
	//
	// The recompute has to happen anyway: the signatures just written moved the
	// zone's next renewal. Wholesale from what is now published rather than
	// lowered incrementally -- an RRset that held the minimum can have been
	// replaced or removed, and an estimate that only ever decreases would leave
	// a wake scheduled for a signature that no longer exists. Early is
	// harmless; late is not.
	if newSnap := zd.snapshot.Load(); newSnap != nil {
		_, nextDue, stillDue := zd.collectAgeingSignaturesLocked(newSnap.Data)
		zd.setResignSchedule(nextDue, newSnap.Serial)
		if publishOwned > 0 && stillDue > 0 {
			lgSigner.Error("RenewZoneSignatures: published to renew the SOA or ZONEMD signature"+
				" and it is STILL due; the publish did not re-sign what it owns",
				"zone", zd.ZoneName, "still_due", stillDue)
		}
	}

	// Publish-owned RRsets were renewed too, by the publish rather than by the
	// loop above, and the caller counts renewed RRsets.
	return len(signed) + publishOwned, nil
}

// collectAgeingSignaturesLocked walks one version of the zone and returns the
// RRsets whose signatures have aged into the renewal window.
//
// Read-only. The RRsets it returns share storage with the published snapshot --
// the RRset struct is copied by value but its RRs and RRSIGs slices are not, and
// a working set is a shallow copy of the snapshot -- so every one of them MUST
// be cloned before it is signed.
//
// It also returns when the zone's earliest-crossing signature next enters that
// window, over every RRset it considered -- due or not. That is the value the
// resigner sleeps on, and it is computed here because this walk already visits
// exactly the right set: the RRsets this pass is responsible for, and no others.
// A zero time means the zone has no signature to schedule against.
//
// The third return counts the PUBLISH-OWNED signatures that are due: the apex
// SOA and a managed ZONEMD, which are not collected because signing them here
// would be thrown away by the publish, and which are therefore renewed only by a
// publish happening at all. Their due times feed nextDue like any other, so the
// resigner wakes for them -- without that, a zone whose SOA is the earliest to
// cross would be scheduled past it.
func (zd *ZoneData) collectAgeingSignaturesLocked(source map[string]*OwnerData) ([]renewalTarget, time.Time, int) {
	if source == nil {
		return nil, time.Time{}, 0
	}

	// Whether a publish would actually renew what it owns. Exactly
	// resignWorkingSetSOAIfSigned's gate: a zone that may not originate content
	// is mirroring an upstream SOA that is not ours to re-sign, and an unbound
	// policy gives the publish nothing to sign under. In neither case would
	// publishing renew the signature, so in neither case is it a reason to
	// publish -- doing it anyway would bump the serial once a tick forever.
	publishRenewsWhatItOwns := zoneMayOriginateContent(zd) && zd.DnssecPolicy != nil

	// The delegations first, because the glue test below needs the complete set
	// and the walk reaches each owner once.
	var delegations []string
	for name, owner := range source {
		if owner == nil || core.EqualNames(name, zd.ZoneName) {
			continue
		}
		if _, exist := owner.RRtypes.Get(dns.TypeNS); exist {
			delegations = append(delegations, name)
		}
	}

	managesZonemd := zd.zoneManagesZonemd()

	var due []renewalTarget
	var nextDue time.Time
	publishOwned := 0
	note := func(rrset core.RRset) bool {
		at, ok := renewalDueAt(rrset)
		if !ok {
			return false
		}
		if nextDue.IsZero() || at.Before(nextDue) {
			nextDue = at
		}
		return time.Now().After(at)
	}

	for name, owner := range source {
		if owner == nil {
			continue
		}
		isApex := core.EqualNames(name, zd.ZoneName)

		for _, rrt := range owner.RRtypes.Keys() {
			switch {
			case rrt == dns.TypeRRSIG:
				// Signatures are not themselves signed.
				continue
			case isApex && rrt == dns.TypeSOA:
				// The publish bumps the serial and resignWorkingSetSOAIfSigned
				// re-signs the SOA afterwards. Signing it here would sign the
				// serial that publish is about to replace and throw the work
				// away.
				//
				// But an ageing SOA signature still has to be renewed, and the
				// only thing that renews it is a publish. Counted rather than
				// collected, so a zone whose SOA is the only thing due
				// publishes instead of returning "nothing to do" and letting
				// the signature expire -- with the whole zone going BOGUS,
				// since every answer needs a valid SOA on the denial path.
				if publishRenewsWhatItOwns && note(owner.RRtypes.GetOnlyRRSet(rrt)) {
					publishOwned++
				}
				continue
			case managesZonemd && isApex && rrt == dns.TypeZONEMD:
				// The publish recomputes the digest -- over the chain it is
				// about to restitch -- and signs the result. Same reason
				// SignZone skips it, and the same reason as the SOA above for
				// counting it: publishing is the only thing that renews it.
				if publishRenewsWhatItOwns && note(owner.RRtypes.GetOnlyRRSet(rrt)) {
					publishOwned++
				}
				continue
			case rrt == dns.TypeNS && !isApex:
				// A delegation's NS is the child's, not ours to sign.
				continue
			case (rrt == dns.TypeA || rrt == dns.TypeAAAA) && isGlueUnderDelegation(name, delegations):
				continue
			}
			rrset := owner.RRtypes.GetOnlyRRSet(rrt)
			if !note(rrset) {
				continue
			}
			due = append(due, renewalTarget{name: name, rrtype: rrt, rrset: rrset})
		}

		// The NSEC property is not an RRtypes entry, so the walk above never
		// reaches it -- and an ageing NSEC signature is exactly this pass's job.
		// The record itself is not regenerated: restitchNsecLocked owns the
		// chain's shape, and a maintenance pass that rebuilt it would hide a
		// defect there.
		if note(owner.NSEC) {
			due = append(due, renewalTarget{
				name: name, rrtype: dns.TypeNSEC, rrset: owner.NSEC, isNsec: true,
			})
		}
	}
	return due, nextDue, publishOwned
}

// resignScanInterval is the resigner's own cadence, clamped, and the look-ahead
// NeedsResigning builds into its threshold.
//
// Shared between the check and the schedule on purpose: a wake computed from a
// different look-ahead than the check it is aiming at could land after it.
//
// resignerengine.interval comes from the immutable RuntimeConfig snapshot
// (ConfLive), not the non-thread-safe global viper -- this runs in the signing
// hot path concurrent with config reload.
func resignScanInterval() time.Duration {
	scanInterval := time.Duration(ConfLive().ResignerInterval) * time.Second
	if scanInterval < 60*time.Second {
		scanInterval = 60 * time.Second
	}
	if scanInterval > 3600*time.Second {
		scanInterval = 3600 * time.Second
	}
	return scanInterval
}

// renewalDueAt returns the moment rrset's earliest-crossing signature enters the
// renewal window: its expiration less the served TTL, the propagation delay and
// one scan interval. That is exactly the threshold NeedsResigning applies, so
// the two can never disagree about whether an RRset is due.
//
// ok is false for an RRset carrying NO signature: there is nothing to renew and
// nothing to schedule. Renewal renews; it does not repair. A missing signature
// means a build path failed, and healing it here would hide that -- repair is
// SignZone, reached through the API, a policy apply or a reload.
func renewalDueAt(rrset core.RRset) (time.Time, bool) {
	if len(rrset.RRs) == 0 || len(rrset.RRSIGs) == 0 {
		return time.Time{}, false
	}
	threshold := time.Duration(rrset.RRs[0].Header().Ttl)*time.Second +
		Conf.KaspPropagationDelay() + resignScanInterval()

	var earliest time.Time
	for _, sig := range rrset.RRSIGs {
		rrsig, ok := sig.(*dns.RRSIG)
		if !ok {
			continue
		}
		due := time.Unix(int64(rrsig.Expiration), 0).Add(-threshold)
		if earliest.IsZero() || due.Before(earliest) {
			earliest = due
		}
	}
	if earliest.IsZero() {
		return time.Time{}, false
	}
	return earliest, true
}

// resignSchedule is a zone's cached answer to "when does anything here next need
// renewing?", together with the serial it was computed from.
//
// The serial is what makes it safe to sleep on. Every publish stores a new
// snapshot with a new serial, and a publish is exactly when signatures may have
// been rewritten -- by another path, with a different validity. An estimate
// computed from a version that is no longer published says nothing about the one
// that is, so it is discarded rather than trusted.
type resignSchedule struct {
	due    time.Time
	serial uint32
}

// setResignSchedule records when this zone next needs a renewal pass. A zero
// time clears it: unknown, which the resigner reads as "use the coarse tick".
func (zd *ZoneData) setResignSchedule(due time.Time, serial uint32) {
	if due.IsZero() {
		zd.nextResign.Store(nil)
		return
	}
	zd.nextResign.Store(&resignSchedule{due: due, serial: serial})
}

// resignDue reports when this zone next needs a renewal pass. ok is false when
// the answer is unknown -- never walked, or computed from a version that is no
// longer published -- and the caller must fall back to its coarse tick rather
// than sleep on it.
func (zd *ZoneData) resignDue() (time.Time, bool) {
	sched := zd.nextResign.Load()
	if sched == nil {
		return time.Time{}, false
	}
	snap := zd.snapshot.Load()
	if snap == nil || snap.Serial != sched.serial {
		return time.Time{}, false
	}
	return sched.due, true
}

// markResignPending records that this zone needs its signatures replaced.
//
// triggerResign hands the zone to the resigner for an immediate pass, but that
// send can be dropped (a full queue) and the pass itself can fail. Either way
// the zone keeps serving signatures by keys that are no longer active, and the
// renewal ticker will not notice: those signatures are VALID, so NeedsResigning
// short-circuits and nothing is ever found due. The flag is what makes
// triggerResign's "re-sign will happen on next cycle" true rather than a
// reassuring log line.
func (zd *ZoneData) markResignPending() {
	zd.resignPending.Store(true)
}

// takeResignPending claims a pending replace, reporting whether there was one.
//
// Claiming rather than reading: the resigner is not the only possible caller,
// and two passes replacing the same signatures concurrently is wasted work on
// a zone that is already behind. A failed replace re-marks.
func (zd *ZoneData) takeResignPending() bool {
	return zd.resignPending.CompareAndSwap(true, false)
}

// resignPendingSet reports whether a replace is still owed, without claiming
// it. For the scheduler, which only needs to know not to sleep long.
func (zd *ZoneData) resignPendingSet() bool {
	return zd.resignPending.Load()
}

// isGlueUnderDelegation reports whether name's addresses are glue for one of the
// zone's delegations rather than authoritative data of our own.
func isGlueUnderDelegation(name string, delegations []string) bool {
	for _, del := range delegations {
		if !core.EqualNames(name, del) && dns.IsSubDomain(del, name) {
			return true
		}
	}
	return false
}
