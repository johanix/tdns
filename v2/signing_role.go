/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * A signing role learned while the daemon runs (johanix/tdns-mp#160, #146).
 *
 * A derived app that relays some zones and signs others may learn which is
 * which only after a zone has loaded, and tdns binds a zone's DNSSEC policy at
 * its first load with a signing option on, and at no other time. These are the
 * calls such an app makes instead, for the four things it can know about a zone:
 *
 *   - nothing yet: Withhold, at the zone's first load. The zone is kept up to
 *     date and offered to nobody. Going Ready on an unsigned copy would be
 *     bogus for as long as the parent holds a DS for the zone.
 *   - it does not sign: ReleaseWithheld. The zone relays its copy.
 *   - it will sign, but not yet: BindPolicyWithoutSigning. The app can run the
 *     zone's keys and have them published by the other signers, while the zone
 *     relays its copy with none of its own signatures on it. The signatures
 *     have to wait until the parent's DS and every cache allow them.
 *   - it signs: StartSigning, which ends both of the others.
 */

package tdns

import (
	"context"
	"fmt"
)

// Withhold keeps a zone that is not yet served from being served: it stays not
// Ready, whatever its copy holds, until ReleaseWithheld or StartSigning. Not
// Ready is what refuses queries and transfers and holds back NOTIFYs. Nothing
// else about the zone changes: its refreshes go on, so a release serves the
// upstream's current copy. A zone already served is refused, since taking a zone
// off the air is not what this is for.
//
// For a derived app that does not know yet what the zone is to it, from its
// first load's OnZonePreRefresh, before the first publish.
func (zd *ZoneData) Withhold() error {
	if zd == nil {
		return fmt.Errorf("withhold: no zone")
	}
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.Ready {
		return fmt.Errorf("withhold: zone %s is already served", zd.ZoneName)
	}
	if !zd.withheld {
		lg.Info("the zone is withheld until its daemon knows its role", "zone", zd.ZoneName)
	}
	zd.withheld = true
	return nil
}

// Withheld reports whether the zone is withheld (Withhold). Such a zone is not
// Ready and will not become so by itself, so a caller that waits for a loaded
// zone asks this as well as Ready.
func (zd *ZoneData) Withheld() bool {
	if zd == nil {
		return false
	}
	zd.mu.Lock()
	defer zd.mu.Unlock()
	return zd.withheld
}

// ReleaseWithheld ends Withhold: a zone with servable content goes Ready now,
// with its one NOTIFY, and what the withholding held back runs, in the order a
// first load runs it. Releasing a zone that is not withheld does nothing.
func (zd *ZoneData) ReleaseWithheld() {
	if zd == nil {
		return
	}
	zd.mu.Lock()
	if !zd.withheld {
		zd.mu.Unlock()
		return
	}
	zd.withheld = false
	zd.markReadyIfServableLocked(zd.snapshot.Load())
	ready := zd.Ready
	zd.mu.Unlock()
	lg.Info("the zone is no longer withheld", "zone", zd.ZoneName, "ready", ready)
	// A zone with nothing servable yet keeps them owed: its load, or the first
	// publish that makes it servable and the ticker after it, runs them.
	if ready {
		zd.runOwedPostRefreshCallbacks()
		drainAndRunOnFirstLoad(zd)
	}
}

// intendedPolicy is the policy a first load would bind to the zone: the CLI
// override if there is one, else the name from its configuration.
func (zd *ZoneData) intendedPolicy() (*DnssecPolicy, string, error) {
	name, pol, _, _, _, err := resolvePolicyPair(zd.KeyDB, zd.ZoneName, zd.DnssecPolicyName)
	switch {
	case err != nil:
		return nil, "", fmt.Errorf("resolve the DNSSEC policy of zone %s: %w", zd.ZoneName, err)
	case name == "":
		return nil, "", fmt.Errorf("zone %s names no DNSSEC policy", zd.ZoneName)
	case pol == nil:
		return nil, "", fmt.Errorf("DNSSEC policy %q of zone %s does not exist", name, zd.ZoneName)
	case pol.Error != "":
		return nil, "", fmt.Errorf("DNSSEC policy %q of zone %s is broken: %s", name, zd.ZoneName, pol.Error)
	}
	return pol, name, nil
}

// BindPolicyWithoutSigning binds the zone's DNSSEC policy to a zone that does
// not sign, and does nothing else: no key is made, nothing is signed, the zone
// goes on relaying its copy at its upstream's serial, and no last-applied record
// is written, since that says what the zone was signed under. A key lifecycle
// owner can then run the zone's keys by the policy. tdns's own key paths ask for
// a signing option and leave such a zone alone.
//
// SetZonePolicyForOwner is not this call: it is the operator's, on a signing
// zone. It refuses a zone that does not sign or is not owned, and on an owned
// zone with no keys its sign fails and undoes the binding.
//
// A zone that signs is refused: its policy goes through the policy paths.
func (zd *ZoneData) BindPolicyWithoutSigning() error {
	if zd == nil || zd.KeyDB == nil {
		return fmt.Errorf("bind a DNSSEC policy: no zone or no keystore")
	}
	zd.policyApplyMu.Lock()
	defer zd.policyApplyMu.Unlock()
	if zd.signsItsOwnContent() {
		return fmt.Errorf("bind a DNSSEC policy: zone %s signs; its policy paths apply", zd.ZoneName)
	}
	pol, name, err := zd.intendedPolicy()
	if err != nil {
		return fmt.Errorf("bind a DNSSEC policy: %w", err)
	}
	zd.mu.Lock()
	zd.DnssecPolicy = pol
	zd.DnssecPolicyName = name
	zd.mu.Unlock()
	lgSigner.Info("DNSSEC policy bound; the zone does not sign yet", "zone", zd.ZoneName, "policy", name)
	return nil
}

// StartSigning has a running zone serve its own signatures: inline-signing on,
// the policy bound if it is not yet, and the zone signed and published before it
// returns. That needs no restart, and the zone serves either what it served
// before or the signed copy, nothing in between.
//
// The copy's signatures are replaced, not added to. A relayed copy can carry its
// upstream's, and by every "is it signed yet" test in tdns that is a signed zone:
// the first-load path would leave it as it is.
//
// minSerial is a serial the zone's servers may have served from elsewhere; the
// signed copy lands above it, and above what the zone served, or they would not
// take it. 0 says there is none.
//
// A zone nobody owns gets its first keys here, as at a first load. An owned zone
// without an active key of every role is refused with ErrKeyGenerationDeferred:
// the owner makes its keys, and this waits for them. On any refusal or failure
// the zone goes on exactly as before, relaying or withheld. A zone that signs
// already, with its policy bound, is left alone.
//
// It takes the zone's lock and can sign a whole zone, so a caller holds no lock
// of its own across it. A derived app switches inline-signing on through this,
// not through SetRuntimeOption: with the option on and no policy bound, the next
// publish is unsigned over the copy the zone was serving.
func (zd *ZoneData) StartSigning(ctx context.Context, minSerial uint32) error {
	if err := zd.startSigning(ctx, minSerial); err != nil {
		return err
	}
	// After the lock of startSigning: the release runs the zone's callbacks.
	// The signed copy is what it goes Ready on.
	zd.ReleaseWithheld()
	return nil
}

func (zd *ZoneData) startSigning(ctx context.Context, minSerial uint32) error {
	if zd == nil || zd.KeyDB == nil {
		return fmt.Errorf("start signing: no zone or no keystore")
	}
	zd.policyApplyMu.Lock()
	defer zd.policyApplyMu.Unlock()

	zd.mu.Lock()
	oldPol, oldName, oldSerial := zd.DnssecPolicy, zd.DnssecPolicyName, zd.CurrentSerial
	oldErrs := zd.snapshotErrorsLocked(DnssecError, DnssecPolicyWarning)
	zd.mu.Unlock()
	if oldPol != nil && zd.signsItsOwnContent() {
		return nil
	}

	pol, name := oldPol, oldName
	if pol == nil {
		var err error
		if pol, name, err = zd.intendedPolicy(); err != nil {
			return fmt.Errorf("start signing: %w", err)
		}
	}
	if zoneOwned(zd) {
		dak, err := zd.KeyDB.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
		if err != nil {
			return fmt.Errorf("start signing: zone %s: %w", zd.ZoneName, err)
		}
		if len(dak.KSKs) == 0 || len(dak.ZSKs) == 0 {
			return fmt.Errorf("start signing: zone %s: %w", zd.ZoneName, ErrKeyGenerationDeferred)
		}
	}

	wasOn := zd.Options[OptInlineSigning]
	before := zd.snapshot.Load()
	// The policy before the option: the publish of a refresh that arrives
	// between them signs, rather than going out unsigned.
	zd.mu.Lock()
	zd.DnssecPolicy, zd.DnssecPolicyName = pol, name
	if minSerial != 0 && serialNewer(minSerial, zd.CurrentSerial) {
		zd.CurrentSerial = minSerial
	}
	zd.mu.Unlock()
	zd.SetRuntimeOption(OptInlineSigning, true)
	UpdateSigValidityFloor(zd, pol, Conf.KaspPropagationDelay(), 0, false, Conf.IsLargeAlgorithm, false)

	newRRSIGs, err := zd.ResignZone(ctx, zd.KeyDB)
	if err == nil {
		err = zd.publishStagedSignatures(before)
	}
	if err != nil {
		zd.mu.Lock()
		// What the pass staged is signed by keys the zone is not going to
		// serve, and an open transaction's commit is not this to take back.
		if !zd.txHeldLocked() {
			zd.workingSet, zd.wsSignalSynth = nil, nil
			zd.publishWorkingSetLocked(zd.generation.Load(), false) // clears the staging flags, answers any waiter
		}
		zd.DnssecPolicy, zd.DnssecPolicyName = oldPol, oldName
		zd.CurrentSerial = oldSerial
		zd.restoreErrorsLocked(oldErrs, DnssecError, DnssecPolicyWarning)
		zd.mu.Unlock()
		if !wasOn {
			zd.SetRuntimeOption(OptInlineSigning, false)
		}
		return fmt.Errorf("start signing: zone %s under policy %q: %w", zd.ZoneName, name, err)
	}

	reconcileDsAfterBind(zd.KeyDB, zd, oldPol)
	// As in the policy apply: the zone is signed, a failure to record that does
	// not undo it, and a restart works it out again.
	if perr := SetZoneAppliedPolicy(zd.KeyDB, zd.ZoneName, name, string(PolicyApplySourceConfig)); perr != nil {
		lgSigner.Error("the zone is signed but persisting its applied DNSSEC policy failed", "zone", zd.ZoneName, "policy", name, "err", perr)
	}
	// Only a first load registers a zone for renewal, and this zone's first load
	// did not sign.
	if q := Conf.Internal.ResignQ; q != nil {
		if rerr := zd.registerForPeriodicResign(ctx, q); rerr != nil {
			lgSigner.Error("the zone is signed but not registered for renewal", "zone", zd.ZoneName, "err", rerr)
		}
	}
	lgSigner.Info("the zone now serves its own signatures", "zone", zd.ZoneName, "policy", name, "new_rrsigs", newRRSIGs, "serial", zd.publishedSerial())
	return nil
}

// publishStagedSignatures publishes what a signing pass left staged, now: the
// pass goes through the publish gate, which queues the work of a busy zone. A
// publish that was refused is an error, and before is the snapshot that shows it.
// Under an open transaction the commit carries the signatures.
func (zd *ZoneData) publishStagedSignatures(before *zoneSnapshot) error {
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.txHeldLocked() {
		return nil
	}
	if zd.workingSet != nil {
		zd.publishLocked(zd.generation.Load())
	}
	if zd.snapshot.Load() == before {
		return fmt.Errorf("the signed copy was not published")
	}
	return nil
}

// publishedSerial is the serial of the snapshot served, for a log line.
func (zd *ZoneData) publishedSerial() uint32 {
	if snap := zd.snapshot.Load(); snap != nil {
		return snap.Serial
	}
	return 0
}
