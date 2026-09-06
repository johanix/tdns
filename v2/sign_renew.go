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

	// Staged-but-unpublished changes are another writer's pending version of
	// this zone. Renewing from the snapshot and staging the result on top would
	// silently revert what they staged; renewing from their working set would
	// publish it early. Neither is this pass's call to make, and it does not
	// have to be: NeedsResigning fires a served TTL plus a propagation delay
	// plus a scan interval ahead of expiry, so the next pass will find the same
	// signatures due against a zone that has settled.
	if zd.workingSet != nil {
		lgSigner.Debug("RenewZoneSignatures: a publish is pending, deferring to the next pass",
			"zone", zd.ZoneName)
		return 0, nil
	}

	due, publishOwned := zd.collectAgeingSignaturesLocked(snap)
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
	if publishOwned > 0 {
		if _, stillDue := zd.collectAgeingSignaturesLocked(zd.snapshot.Load()); stillDue > 0 {
			lgSigner.Error("RenewZoneSignatures: published to renew the SOA or ZONEMD signature"+
				" and it is STILL due; the publish did not re-sign what it owns",
				"zone", zd.ZoneName, "still_due", stillDue)
		}
	}

	// Publish-owned RRsets were renewed too, by the publish rather than by the
	// loop above, and the caller counts renewed RRsets.
	return len(signed) + publishOwned, nil
}

// collectAgeingSignaturesLocked walks the published snapshot and returns the
// RRsets whose signatures have aged into the renewal window.
//
// Read-only. The RRsets it returns share storage with the snapshot -- the
// RRset struct is copied by value but its RRs and RRSIGs slices are not -- so
// every one of them MUST be cloned before it is signed.
func (zd *ZoneData) collectAgeingSignaturesLocked(snap *zoneSnapshot) ([]renewalTarget, int) {
	if snap == nil {
		return nil, 0
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
	for name, owner := range snap.Data {
		if owner == nil || core.EqualNames(name, zd.ZoneName) {
			continue
		}
		if _, exist := owner.RRtypes.Get(dns.TypeNS); exist {
			delegations = append(delegations, name)
		}
	}

	managesZonemd := zd.zoneManagesZonemd()

	var due []renewalTarget
	publishOwned := 0
	for name, owner := range snap.Data {
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
				if publishRenewsWhatItOwns && rrsetNeedsRenewal(owner.RRtypes.GetOnlyRRSet(rrt)) {
					publishOwned++
				}
				continue
			case managesZonemd && isApex && rrt == dns.TypeZONEMD:
				// The publish recomputes the digest -- over the chain it is
				// about to restitch -- and signs the result. Same reason
				// SignZone skips it, and the same reason as the SOA above for
				// counting it: publishing is the only thing that renews it.
				if publishRenewsWhatItOwns && rrsetNeedsRenewal(owner.RRtypes.GetOnlyRRSet(rrt)) {
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
			if !rrsetNeedsRenewal(rrset) {
				continue
			}
			due = append(due, renewalTarget{name: name, rrtype: rrt, rrset: rrset})
		}

		// The NSEC property is not an RRtypes entry, so the walk above never
		// reaches it -- and an ageing NSEC signature is exactly this pass's job.
		// The record itself is not regenerated: restitchNsecLocked owns the
		// chain's shape, and a maintenance pass that rebuilt it would hide a
		// defect there.
		if rrsetNeedsRenewal(owner.NSEC) {
			due = append(due, renewalTarget{
				name: name, rrtype: dns.TypeNSEC, rrset: owner.NSEC, isNsec: true,
			})
		}
	}
	return due, publishOwned
}

// rrsetNeedsRenewal reports whether any signature on rrset has aged into the
// renewal window NeedsResigning defines.
//
// An RRset carrying NO signature is not due. Renewal renews; it does not repair.
// A missing signature means a build path failed, and healing it here would hide
// that -- repair is SignZone, reached through the API, a policy apply or a
// reload.
func rrsetNeedsRenewal(rrset core.RRset) bool {
	if len(rrset.RRs) == 0 || len(rrset.RRSIGs) == 0 {
		return false
	}
	servedTTL := rrset.RRs[0].Header().Ttl
	for _, sig := range rrset.RRSIGs {
		rrsig, ok := sig.(*dns.RRSIG)
		if !ok {
			continue
		}
		if NeedsResigning(rrsig, servedTTL) {
			return true
		}
	}
	return false
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
