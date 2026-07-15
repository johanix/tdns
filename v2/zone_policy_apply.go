/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Transactional DNSSEC-policy apply core (P0-2 / Plan B).
 *
 * A single place that rebinds a zone to a DNSSEC policy, re-signs, and — only
 * on success — persists the last-applied record, reverting the in-memory
 * binding if the re-sign fails. The CLI path (policy-set / change-policy) and
 * the config reload/restart path both call this so they cannot drift.
 *
 * Design lock (see docs/2026-07-15-transactional-policy-reload-plan.md):
 *   ① Classification is ALWAYS applied-from-DB vs intent, never the current
 *      in-memory binding: on restart the binding is freshly loaded from config
 *      and equals intent, which would hide a pending change.
 *   ② When no applied record exists yet (first post-upgrade reload of a
 *      config-only zone), backfill applied = intent WITHOUT a forced re-sign
 *      when the zone is already signed under intent — avoiding a thundering-herd
 *      re-sign. The backfill branch is reachable independently of intent==applied.
 */

package tdns

import (
	"context"
	"fmt"
)

// PolicyApplySource records why a policy was applied, and is persisted as
// applied_source. 'command' additionally persists a CLI override (intent);
// 'config' does not.
type PolicyApplySource string

const (
	PolicyApplySourceConfig  PolicyApplySource = "config"
	PolicyApplySourceCommand PolicyApplySource = "command"
)

// PolicyChangeClass is the result of comparing a zone's last-applied policy
// against its intent (operator-desired) policy.
type PolicyChangeClass int

const (
	// PolicyChangeNone: same name, same effective algorithms — nothing to do.
	// An internals-only edit (lifetimes/sigvalidity/ttls/rollover) under the
	// same name also lands here and converges via the resigner; there is no
	// separate "benign internals" class. Finding A: resolvePolicyPair resolves
	// applied and intent from the SAME ConfLive() snapshot by NAME, so a
	// "same name, changed internals" delta is unreachable at classify time.
	PolicyChangeNone PolicyChangeClass = iota
	// PolicyChangeCompatibleName: different name, same KSK+ZSK algorithms —
	// apply transactionally.
	PolicyChangeCompatibleName
	// PolicyChangeIncompatibleAlg: KSK or ZSK effective algorithm differs — a
	// key rollover that is not built (v1 refuses on the config path).
	PolicyChangeIncompatibleAlg
)

func (c PolicyChangeClass) String() string {
	switch c {
	case PolicyChangeNone:
		return "none"
	case PolicyChangeCompatibleName:
		return "compatible-name"
	case PolicyChangeIncompatibleAlg:
		return "incompatible-alg"
	default:
		return fmt.Sprintf("PolicyChangeClass(%d)", int(c))
	}
}

// classifyPolicyChange compares the LAST-APPLIED policy (from the DB, resolved
// to a struct via ConfLive().DnssecPolicies) against INTENT (what the operator
// wants). It MUST NOT be called with the zone's current in-memory binding as
// the "applied" side — on restart the binding equals intent and the change is
// hidden (blocking ①). Precondition: both structs non-nil; the applied-missing
// case is resolved by backfillAppliedIfEligible / a first apply BEFORE the
// classifier runs.
//
// The effective algorithms are DnssecPolicy.KSKAlgorithm / .ZSKAlgorithm — the
// same fields SignZone, set-policy, and the old applyReloadedPolicyLocked guard
// compare against the active keys.
func classifyPolicyChange(
	appliedPol *DnssecPolicy, appliedName string,
	intentPol *DnssecPolicy, intentName string,
) PolicyChangeClass {
	// Defensive: a nil on either side means we cannot prove sameness — treat it
	// as a name change so the caller drives a transactional apply toward intent
	// (the SignZone algorithm backstop still refuses an unsafe swap).
	if appliedPol == nil || intentPol == nil {
		return PolicyChangeCompatibleName
	}
	if appliedPol.KSKAlgorithm != intentPol.KSKAlgorithm ||
		appliedPol.ZSKAlgorithm != intentPol.ZSKAlgorithm {
		return PolicyChangeIncompatibleAlg
	}
	if appliedName != intentName {
		return PolicyChangeCompatibleName
	}
	// Same name, same effective algorithms → nothing to do. Any internals-only
	// edit under the same name converges via the resigner (Finding A), so there
	// is deliberately no separate class for it.
	return PolicyChangeNone
}

// resolvePolicyPair loads a zone's intent (via EffectiveDnssecPolicyName: CLI
// override if set, else the config base) and its last-applied record (via
// GetZoneAppliedPolicy), then resolves both policy structs from the ConfLive()
// snapshot (lock-free — no confMu).
//
// appliedOK reports whether a last-applied record exists in the DB. appliedPol
// may be nil even when appliedOK is true if the applied policy name is no longer
// defined in config (§5.6 deleted-policy case) — callers handle that before
// dereferencing. Likewise intentPol is nil when intent names a policy absent
// from config.
func resolvePolicyPair(kdb *KeyDB, zone, configPolicyName string) (
	intentName string, intentPol *DnssecPolicy,
	appliedName string, appliedPol *DnssecPolicy, appliedOK bool,
	err error,
) {
	intentName, _, err = EffectiveDnssecPolicyName(kdb, zone, configPolicyName)
	if err != nil {
		// EffectiveDnssecPolicyName still returns a usable config-base name on a
		// DB error; surface the error but keep resolving what we can.
		return intentName, nil, "", nil, false, err
	}
	an, _, ok, gerr := GetZoneAppliedPolicy(kdb, zone)
	if gerr != nil {
		return intentName, nil, "", nil, false, gerr
	}
	appliedName, appliedOK = an, ok

	live := ConfLive()
	if intentName != "" {
		if p, exists := live.DnssecPolicies[intentName]; exists {
			ip := p
			intentPol = &ip
		}
	}
	if appliedOK && appliedName != "" {
		if p, exists := live.DnssecPolicies[appliedName]; exists {
			ap := p
			appliedPol = &ap
		}
	}
	return intentName, intentPol, appliedName, appliedPol, appliedOK, nil
}

// applyZonePolicyTransactional rebinds a signed zone to newPol, re-signs, and —
// only on success — persists the last-applied record. On SignZone failure it
// reverts the in-memory binding and returns an error without touching applied_*.
// When source is PolicyApplySourceCommand it also persists a CLI override
// (intent) on success.
//
// The old binding is snapshotted for REVERT ONLY; it is never used to classify
// the change (blocking ①). Caller is responsible for having classified/refused
// before calling this.
//
// It serializes concurrent applies on the same zone via zd.policyApplyMu.
// Callers that must serialize extra steps together with the apply — policy-reset
// drops and regenerates the zone's keys before the re-sign — hold
// zd.policyApplyMu themselves and call applyZonePolicyTransactionalLocked.
//
// ctx is threaded as the first parameter per the house convention and to carry
// cancellation once SignZone and the applied-policy DB writes become ctx-aware;
// those downstream calls do not yet consume it.
func applyZonePolicyTransactional(
	ctx context.Context,
	zd *ZoneData,
	kdb *KeyDB,
	newPol *DnssecPolicy,
	newName string,
	source PolicyApplySource,
) (newRRSIGs int, err error) {
	zd.policyApplyMu.Lock()
	defer zd.policyApplyMu.Unlock()
	return applyZonePolicyTransactionalLocked(ctx, zd, kdb, newPol, newName, source)
}

// applyZonePolicyTransactionalLocked is applyZonePolicyTransactional WITHOUT
// acquiring zd.policyApplyMu. The caller MUST already hold zd.policyApplyMu for
// this zone; use it only when the apply is one step of a larger critical
// section that already holds the mutex (policy-reset). Otherwise call
// applyZonePolicyTransactional.
func applyZonePolicyTransactionalLocked(
	ctx context.Context,
	zd *ZoneData,
	kdb *KeyDB,
	newPol *DnssecPolicy,
	newName string,
	source PolicyApplySource,
) (newRRSIGs int, err error) {
	_ = ctx // reserved: no ctx-aware downstream call yet (see doc comment)
	if newPol == nil {
		return 0, fmt.Errorf("applyZonePolicyTransactional: nil policy %q for zone %s", newName, zd.ZoneName)
	}
	if newPol.Error != "" {
		return 0, fmt.Errorf("applyZonePolicyTransactional: DNSSEC policy %q is broken: %s", newName, newPol.Error)
	}
	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return 0, fmt.Errorf("applyZonePolicyTransactional: zone %s is not signed (neither online-signing nor inline-signing)", zd.ZoneName)
	}

	// Snapshot the current binding for revert-on-failure ONLY.
	zd.mu.Lock()
	oldPol := zd.DnssecPolicy
	oldName := zd.DnssecPolicyName
	zd.DnssecPolicy = newPol
	zd.DnssecPolicyName = newName
	zd.mu.Unlock()

	UpdateSigValidityFloor(zd, newPol, Conf.KaspPropagationDelay(), 0, false, Conf.IsLargeAlgorithm, false)

	newRRSIGs, err = zd.SignZone(kdb, true)
	if err != nil {
		zd.mu.Lock()
		zd.DnssecPolicy = oldPol
		zd.DnssecPolicyName = oldName
		zd.mu.Unlock()
		return 0, fmt.Errorf("re-sign zone %s under policy %q: %w", zd.ZoneName, newName, err)
	}

	// Zone is now signed under newPol. Persist the last-applied record. A
	// persistence failure does NOT revert the binding (the zone IS correctly
	// signed); it is surfaced so the caller logs it. On restart the zone
	// re-derives intent and re-converges.
	if perr := SetZoneAppliedPolicy(kdb, zd.ZoneName, newName, string(source)); perr != nil {
		return newRRSIGs, fmt.Errorf("zone %s re-signed under %q but persisting applied policy failed: %w", zd.ZoneName, newName, perr)
	}

	if source == PolicyApplySourceCommand {
		if perr := SetZonePolicyOverride(kdb, zd.ZoneName, newName); perr != nil {
			return newRRSIGs, fmt.Errorf("zone %s re-signed under %q but persisting the CLI override failed (the change will not survive restart): %w", zd.ZoneName, newName, perr)
		}
	}
	return newRRSIGs, nil
}

// backfillAppliedIfEligible records applied = intent WITHOUT a forced re-sign
// when a zone has no applied record yet but is ALREADY correctly signed under
// intent — its active keys' algorithms match intent's KSK/ZSK algorithms
// (blocking ②). This is the first-post-upgrade path for config-only signed
// zones; it avoids re-signing every already-correct zone.
//
// Precondition: caller has established that no applied record exists. Returns
// true when a backfill was written (caller then skips the re-sign for policy
// purposes). Returns false — without error — when the zone is not eligible
// (unsigned, no intent, or active-key algorithms differ from intent); the
// caller then drives a genuine transactional apply toward intent, whose
// SignZone algorithm backstop refuses an unsafe swap.
func backfillAppliedIfEligible(kdb *KeyDB, zd *ZoneData, intentName string, intentPol *DnssecPolicy) (backfilled bool, err error) {
	if intentPol == nil || intentName == "" {
		return false, nil
	}
	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return false, nil
	}
	match, err := zoneActiveKeysMatchAlgs(kdb, zd.ZoneName, intentPol)
	if err != nil {
		return false, err
	}
	if !match {
		return false, nil
	}
	if err := SetZoneAppliedPolicy(kdb, zd.ZoneName, intentName, string(PolicyApplySourceConfig)); err != nil {
		return false, err
	}
	return true, nil
}

// zoneActiveKeysMatchAlgs reports whether the zone's ACTIVE keys already provide
// the algorithms pol requires: for a split policy, an active KSK of
// pol.KSKAlgorithm AND an active ZSK of pol.ZSKAlgorithm; for a CSK policy, a
// single active SEP key of pol.KSKAlgorithm (which equals pol.ZSKAlgorithm). The
// SEP bit (flags & 1) distinguishes a KSK/CSK from a ZSK — the same convention
// the signer and the standby→published migration use.
func zoneActiveKeysMatchAlgs(kdb *KeyDB, zone string, pol *DnssecPolicy) (bool, error) {
	active, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
	if err != nil {
		return false, err
	}
	if pol.Mode == DnssecPolicyModeCSK {
		for _, k := range active {
			if k.Flags&0x0001 == 0x0001 && k.Algorithm == pol.KSKAlgorithm {
				return true, nil
			}
		}
		return false, nil
	}
	var haveKSK, haveZSK bool
	for _, k := range active {
		if k.Flags&0x0001 == 0x0001 {
			if k.Algorithm == pol.KSKAlgorithm {
				haveKSK = true
			}
		} else if k.Algorithm == pol.ZSKAlgorithm {
			haveZSK = true
		}
	}
	return haveKSK && haveZSK, nil
}
