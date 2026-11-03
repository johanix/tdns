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
 *     date and offered to nobody: no answers, no transfers, no NOTIFY. Serving
 *     an unsigned copy would be bogus for as long as the parent holds a DS for
 *     the zone.
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
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// Withhold keeps a zone that is not yet served from being served, whatever its
// copy holds, until ReleaseWithheld or StartSigning. A query, or an UPDATE, gets
// SERVFAIL, as from a zone with nothing to answer from. And it stays not Ready,
// which is what refuses transfers and holds back NOTIFYs; Ready is not what
// answers queries, a published copy is. Nothing else about the zone changes: its
// refreshes go on, so a release serves the upstream's current copy. A zone
// already served, Ready or with a copy published, is refused, since taking a zone
// off the air is not what this is for. One withheld already stays so, and that is
// no refusal.
//
// It does not decide what the zone signs. The promise of no policy and no keys is
// inline-signing's being off: a zone with a signing option on binds and signs at
// its first load as ever, and stays not Ready.
//
// For a derived app that does not know yet what the zone is to it, from its
// first load's OnZonePreRefresh, before the first publish.
func (zd *ZoneData) Withhold() error {
	if zd == nil {
		return fmt.Errorf("withhold: no zone")
	}
	zd.mu.Lock()
	defer zd.mu.Unlock()
	if zd.withheld {
		return nil
	}
	if zd.Ready || zd.snapshot.Load() != nil {
		return fmt.Errorf("withhold: zone %s is already served", zd.ZoneName)
	}
	lg.Info("the zone is withheld until its daemon knows its role", "zone", zd.ZoneName)
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

// ErrSigningHeld: StartSigning found an open transaction on the zone, or changes
// staged and waiting to be published. They are not signed into the role change
// and it does not wait for them: nothing has changed, and the caller tries again
// shortly.
var ErrSigningHeld = errors.New("the zone has an open transaction or staged changes")

// StartSigning has a running zone serve its own signatures: inline-signing on,
// the policy bound if it is not yet, and the zone signed and published before it
// returns. That needs no restart. It is one step under the zone's lock: a refresh
// or a publish comes before it, on the copy as it was, or after it, signing, and
// the zone serves either what it served before or the signed copy.
//
// The copy's signatures are replaced, not added to. A relayed copy can carry its
// upstream's, and by every "is it signed yet" test in tdns that is a signed zone:
// the first-load path would leave it as it is.
//
// minSerial is a serial the zone's servers may have served from elsewhere; the
// signed copy lands above it, and above what the zone served, or they would not
// take it. 0 says there is none.
//
// A zone nobody owns gets its first keys here, as at a first load. Two refusals
// are for the caller to try again: an owned zone without an active key of every
// role, ErrKeyGenerationDeferred, since the owner makes its keys and this waits
// for them; and ErrSigningHeld. On those and on any failure the zone goes on as
// it was, relaying or withheld. A zone that serves its own signatures, with its
// policy bound, is left alone. The option and the binding do not say that it does:
// a copy from upstream can arrive with them on, and it gets signed here.
//
// It holds the zone's lock across a whole zone's signing, as ResignZone does, so
// a caller holds no lock of its own across it. A derived app switches
// inline-signing on through this, not through SetRuntimeOption: with the option
// on and no policy bound, the next publish is unsigned over the copy the zone was
// serving.
func (zd *ZoneData) StartSigning(ctx context.Context, minSerial uint32) error {
	if err := zd.startSigning(ctx, minSerial); err != nil {
		return err
	}
	// After the locks of startSigning: the release runs the zone's callbacks.
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
	if zd.servesItsOwnSignaturesLocked() {
		zd.mu.Unlock()
		return nil
	}
	oldPol := zd.DnssecPolicy
	name, newRRSIGs, err := zd.switchToSigningLocked(ctx, minSerial)
	serial := zd.CurrentSerial
	zd.mu.Unlock()
	if err != nil {
		return fmt.Errorf("start signing: zone %s: %w", zd.ZoneName, err)
	}

	reconcileDsAfterBind(zd.KeyDB, zd, oldPol)
	// As in the policy apply: the zone is signed, a failure to record that does
	// not undo it, and a restart works it out again.
	if perr := SetZoneAppliedPolicy(zd.KeyDB, zd.ZoneName, name, string(PolicyApplySourceConfig)); perr != nil {
		lgSigner.Error("the zone is signed but persisting its applied DNSSEC policy failed", "zone", zd.ZoneName, "policy", name, "err", perr)
	}
	// Only a first load registers a zone for renewal, and this zone's first load
	// did not sign. Not under the zone's lock: the send can wait on a full queue.
	if q := Conf.Internal.ResignQ; q != nil {
		if rerr := zd.registerForPeriodicResign(ctx, q); rerr != nil {
			lgSigner.Error("the zone is signed but not registered for renewal", "zone", zd.ZoneName, "err", rerr)
		}
	}
	lgSigner.Info("the zone now serves its own signatures", "zone", zd.ZoneName, "policy", name, "new_rrsigs", newRRSIGs, "serial", serial)
	return nil
}

// servesItsOwnSignaturesLocked reports whether the zone has started signing: it
// signs, its policy is bound, and the SOA it serves carries a signature that
// verifies under one of its keys. A key tag says less: 16 bits, and an upstream's
// can be the same. A key that has rolled since reads as no, and a start signs
// again, which is what it would be asked to do. Caller holds zd.mu.
func (zd *ZoneData) servesItsOwnSignaturesLocked() bool {
	if zd.DnssecPolicy == nil || !zd.signsItsOwnContent() {
		return false
	}
	snap := zd.snapshot.Load()
	if snap == nil || snap.Apex == nil {
		return false
	}
	dak, err := zd.KeyDB.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
	if err != nil {
		return false // the start meets it too, and says so
	}
	soa := zd.soaForResponseFrom(snap, snap.Apex)
	for _, rr := range soa.RRSIGs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		for _, k := range dak.ZSKs {
			if sig.Verify(&k.DnskeyRR, soa.RRs) == nil {
				return true
			}
		}
	}
	return false
}

// switchToSigningLocked is the step itself: nothing that takes the zone's lock
// sees it half way, and a failure puts back everything it changed. It returns
// the policy's name and the RRSIGs written. Caller holds zd.mu.
func (zd *ZoneData) switchToSigningLocked(ctx context.Context, minSerial uint32) (string, int, error) {
	if zd.txHeldLocked() || zd.workingSet != nil {
		return "", 0, ErrSigningHeld
	}
	pol, name := zd.DnssecPolicy, zd.DnssecPolicyName
	if pol == nil {
		var err error
		if pol, name, err = zd.intendedPolicy(); err != nil {
			return "", 0, err
		}
	}
	if zoneOwned(zd) {
		dak, err := zd.KeyDB.GetDnssecKeys(zd.ZoneName, DnskeyStateActive)
		if err != nil {
			return "", 0, err
		}
		if len(dak.KSKs) == 0 || len(dak.ZSKs) == 0 {
			return "", 0, ErrKeyGenerationDeferred
		}
	}

	oldPol, oldName, oldSerial := zd.DnssecPolicy, zd.DnssecPolicyName, zd.CurrentSerial
	oldErrs := zd.snapshotErrorsLocked(DnssecError, DnssecPolicyWarning)
	oldOptions := zd.Options
	oldWord, hadWord := zd.runtimeOptions[OptInlineSigning]
	before := zd.snapshot.Load()

	zd.DnssecPolicy, zd.DnssecPolicyName = pol, name
	if minSerial != 0 && serialNewer(minSerial, zd.CurrentSerial) {
		zd.CurrentSerial = minSerial
	}
	zd.setRuntimeOptionLocked(OptInlineSigning, true)
	UpdateSigValidityFloor(zd, pol, Conf.KaspPropagationDelay(), 0, false, Conf.IsLargeAlgorithm, true)

	newRRSIGs, err := zd.signWholeCopyLocked(ctx)
	if err == nil {
		// Not through the publish gate, which queues the work of a busy zone:
		// the caller goes on to say that the zone has switched.
		zd.publishLocked(zd.generation.Load())
		if zd.snapshot.Load() == before {
			err = errors.New("the signed copy was not published")
		}
	}
	if err != nil {
		// What the pass staged is signed by keys the zone is not going to serve.
		zd.workingSet, zd.wsSignalSynth = nil, nil
		zd.publishWorkingSetLocked(zd.generation.Load(), false) // nothing staged: clears the staging flags, answers any waiter
		zd.DnssecPolicy, zd.DnssecPolicyName = oldPol, oldName
		zd.CurrentSerial = oldSerial
		zd.restoreErrorsLocked(oldErrs, DnssecError, DnssecPolicyWarning)
		// The daemon's word as it stood, or none. A word left behind would overrule
		// the configuration at every config update from here on.
		zd.Options = oldOptions
		if hadWord {
			zd.runtimeOptions[OptInlineSigning] = oldWord
		} else {
			delete(zd.runtimeOptions, OptInlineSigning)
		}
		return "", 0, fmt.Errorf("under policy %q: %w", name, err)
	}
	return name, newRRSIGs, nil
}

// signWholeCopyLocked stages the zone signed by its own keys and by no others:
// ResignZone's pass, with its checks, with zd.mu already held.
func (zd *ZoneData) signWholeCopyLocked(ctx context.Context) (int, error) {
	if _, bad := zd.Errors[DnssecError]; bad {
		return 0, fmt.Errorf("the zone has a DNSSEC error: %s", zd.ErrorMsg)
	}
	dak, err := zd.EnsureActiveDnssecKeys(zd.KeyDB, true)
	if err != nil {
		return 0, err
	}
	clamp, err := ClampParamsForZone(zd.KeyDB, zd.ZoneName, zd.DnssecPolicy, time.Now())
	if err != nil {
		return 0, fmt.Errorf("resolving the TTL clamp: %w", err)
	}
	return zd.resignWorkingSetLocked(ctx, dak, clamp)
}
