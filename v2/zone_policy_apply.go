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
	"strings"

	"github.com/miekg/dns"
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
// intent — its active keys' algorithms match intent's KSK/ZSK algorithms AND
// it serves an apex SOA RRSIG by an intent signing algorithm (blocking ② /
// PR-2 GATE). This is the first-post-upgrade path for config-only signed
// zones; it avoids re-signing every already-correct zone.
//
// Precondition: caller has established that no applied record exists. The
// served-RRSIG check reads Ready MapZone data via GetRRset — call only AFTER
// InstallInitialSnapshot (or on an already-Ready reload path). Returns true
// when a backfill was written (caller then skips the re-sign for policy
// purposes). Returns false — without error — when the zone is not eligible
// (unsigned, no intent, keystore mismatch, or no matching served SOA RRSIG);
// the caller then drives a genuine transactional apply toward intent.
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
	if !zoneServesIntentSOASig(zd, intentPol) {
		return false, nil
	}
	if err := SetZoneAppliedPolicy(kdb, zd.ZoneName, intentName, string(PolicyApplySourceConfig)); err != nil {
		return false, err
	}
	return true, nil
}

// zoneServesIntentSOASig reports whether the zone's published apex SOA RRset
// carries an RRSIG whose Algorithm matches intent's ZSK algorithm (CSK:
// KSKAlgorithm). Fail-closed: not Ready, not MapZone, missing SOA, or no
// matching signature → false. soa.RRSIGs is []dns.RR — type-assert before use.
func zoneServesIntentSOASig(zd *ZoneData, intentPol *DnssecPolicy) bool {
	if zd == nil || intentPol == nil || !zd.Ready {
		return false
	}
	soa, err := zd.GetRRset(zd.ZoneName, dns.TypeSOA)
	if err != nil || soa == nil {
		return false
	}
	want := intentPol.ZSKAlgorithm
	if intentPol.Mode == DnssecPolicyModeCSK {
		want = intentPol.KSKAlgorithm
	}
	for _, rr := range soa.RRSIGs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok || sig == nil {
			continue
		}
		if sig.Algorithm == want {
			return true
		}
	}
	return false
}

// zoneActiveKeysMatchAlgs reports whether the zone's ACTIVE keys already provide
// the algorithms pol requires: for a split policy, an active KSK of
// pol.KSKAlgorithm AND an active ZSK of pol.ZSKAlgorithm; for a CSK policy, a
// single active SEP key of pol.KSKAlgorithm (which equals pol.ZSKAlgorithm). The
// SEP bit (flags & 1) distinguishes a KSK/CSK from a ZSK — the same convention
// the signer and the standby→published migration use.
//
// NOTE (§5.5): this proves the KEYSTORE holds matching active keys, NOT that the
// zone is actually signed under them. Combined with zoneServesIntentSOASig it
// forms the backfill eligibility predicate.
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

// syncZoneDnssecPolicyFromConfig is the refresh-engine policy path (plan §6.2):
// resolve applied vs intent → Branch 0 backfill/first-apply → classify →
// cheap rebind / skip-in-flight / transactional apply / refuse. Config source
// only — never writes a CLI override.
//
// Branch 0 (backfill) requires a Ready MapZone so the served-SOA-RRSIG GATE can
// succeed; callers on first-bind must InstallInitialSnapshot before this.
// Classify (Branches 1–3) reads only DB + ConfLive and does not need Ready.
//
// §5.6: when appliedOK but appliedPol is nil (YAML deleted the applied name):
// keep an existing in-memory binding + DnssecPolicyWarning; on first-bind with
// no binding yet, proceed toward intent when resolvable, else quarantine.
func syncZoneDnssecPolicyFromConfig(ctx context.Context, zd *ZoneData, kdb *KeyDB, conf *Config, configPolicyName string) error {
	if zd == nil || kdb == nil {
		return fmt.Errorf("syncZoneDnssecPolicyFromConfig: nil zone or keydb")
	}
	if !zd.Options[OptOnlineSigning] && !zd.Options[OptInlineSigning] {
		return nil
	}

	intentName, intentPol, appliedName, appliedPol, appliedOK, err := resolvePolicyPair(kdb, zd.ZoneName, configPolicyName)
	if err != nil {
		return fmt.Errorf("resolve DNSSEC policy pair for zone %s: %w", zd.ZoneName, err)
	}

	// Intent unresolvable with a non-empty name → quarantine (existing behaviour).
	if intentName != "" && intentPol == nil {
		lgEngine.Error("zone has unknown effective DNSSEC policy, will not be signed",
			"zone", zd.ZoneName, "policy", intentName, "config_policy", configPolicyName)
		zd.SetError(DnssecError, "DNSSEC policy %q does not exist", intentName)
		zd.mu.Lock()
		zd.DnssecPolicy = &DnssecPolicy{}
		zd.DnssecPolicyName = ""
		zd.mu.Unlock()
		return nil
	}
	if intentPol == nil {
		return nil // no DNSSEC policy configured
	}
	if intentPol.Error != "" {
		lgEngine.Warn("intent DNSSEC policy is broken; not binding it",
			"zone", zd.ZoneName, "policy", intentName, "policy_error", intentPol.Error)
		if zd.DnssecPolicy != nil && zd.DnssecPolicy.Error == "" {
			zd.SetError(DnssecPolicyWarning, "intent DNSSEC policy %q is broken (%s); keeping bound policy %q",
				intentName, intentPol.Error, zd.DnssecPolicyName)
			return nil
		}
		zd.SetError(DnssecError, "DNSSEC policy %q is broken: %s", intentName, intentPol.Error)
		zd.mu.Lock()
		zd.DnssecPolicy = &DnssecPolicy{}
		zd.DnssecPolicyName = ""
		zd.mu.Unlock()
		return nil
	}

	// Branch 0 — no applied row yet.
	if !appliedOK {
		backfilled, berr := backfillAppliedIfEligible(kdb, zd, intentName, intentPol)
		if berr != nil {
			return fmt.Errorf("backfill applied for zone %s: %w", zd.ZoneName, berr)
		}
		if backfilled {
			zd.mu.Lock()
			zd.DnssecPolicy = intentPol
			zd.DnssecPolicyName = intentName
			zd.mu.Unlock()
			UpdateSigValidityFloor(zd, intentPol, conf.KaspPropagationDelay(), 0, false, conf.IsLargeAlgorithm, false)
			lgEngine.Info("backfilled applied DNSSEC policy without re-sign",
				"zone", zd.ZoneName, "policy", intentName)
			return nil
		}
		if _, aerr := applyZonePolicyTransactional(ctx, zd, kdb, intentPol, intentName, PolicyApplySourceConfig); aerr != nil {
			lgEngine.Warn("first config apply of DNSSEC policy failed; binding reverted",
				"zone", zd.ZoneName, "policy", intentName, "err", aerr)
			return aerr
		}
		return nil
	}

	// appliedOK — §5.6 deleted applied policy name, or applied struct is broken
	// (cannot classify/refuse against it; treat like missing appliedPol).
	if appliedPol != nil && appliedPol.Error != "" {
		lgEngine.Warn("applied DNSSEC policy is broken; ignoring it for classify",
			"zone", zd.ZoneName, "applied", appliedName, "policy_error", appliedPol.Error)
		appliedPol = nil
	}
	if appliedPol == nil {
		if zd.DnssecPolicy != nil && zd.DnssecPolicyName != "" && zd.DnssecPolicy.Error == "" {
			lgEngine.Warn("applied DNSSEC policy unavailable; keeping current binding",
				"zone", zd.ZoneName, "applied", appliedName, "bound", zd.DnssecPolicyName, "intent", intentName)
			zd.SetError(DnssecPolicyWarning, "applied DNSSEC policy %q is unavailable; keeping bound policy %q",
				appliedName, zd.DnssecPolicyName)
			return nil
		}
		// First-bind: no healthy binding to keep — proceed toward intent.
		if _, aerr := applyZonePolicyTransactional(ctx, zd, kdb, intentPol, intentName, PolicyApplySourceConfig); aerr != nil {
			lgEngine.Warn("config apply toward intent after unavailable applied policy failed",
				"zone", zd.ZoneName, "policy", intentName, "err", aerr)
			return aerr
		}
		return nil
	}

	class := classifyPolicyChange(appliedPol, appliedName, intentPol, intentName)

	// Branch 1 — same name, same algs (incl. internals-only edits).
	if intentName == appliedName && class == PolicyChangeNone {
		zd.mu.Lock()
		zd.DnssecPolicy = intentPol
		zd.DnssecPolicyName = intentName
		zd.mu.Unlock()
		UpdateSigValidityFloor(zd, intentPol, conf.KaspPropagationDelay(), 0, false, conf.IsLargeAlgorithm, false)
		zd.ClearError(DnssecPolicyWarning)
		return nil
	}

	// Branch 1b — in-flight ZSK algorithm roll: do not clobber with config apply.
	st, ierr := zskAlgRollInFlight(kdb, zd.ZoneName, appliedPol.ZSKAlgorithm)
	if ierr != nil {
		return fmt.Errorf("check ZSK algorithm rollover for zone %s: %w", zd.ZoneName, ierr)
	}
	if st.InFlight {
		lgEngine.Debug("skipping config DNSSEC policy apply; ZSK algorithm roll in flight",
			"zone", zd.ZoneName, "applied", appliedName, "intent", intentName)
		return nil
	}

	switch class {
	case PolicyChangeCompatibleName:
		if _, aerr := applyZonePolicyTransactional(ctx, zd, kdb, intentPol, intentName, PolicyApplySourceConfig); aerr != nil {
			lgEngine.Warn("compatible DNSSEC policy rename apply failed; binding reverted",
				"zone", zd.ZoneName, "from", appliedName, "to", intentName, "err", aerr)
			return aerr
		}
		zd.ClearError(DnssecPolicyWarning)
		return nil

	case PolicyChangeIncompatibleAlg:
		refuseIncompatiblePolicyChange(zd, intentName, appliedName, appliedPol)
		return nil

	default:
		// Defensive: treat unknown as compatible apply.
		if _, aerr := applyZonePolicyTransactional(ctx, zd, kdb, intentPol, intentName, PolicyApplySourceConfig); aerr != nil {
			return aerr
		}
		return nil
	}
}

// refuseIncompatiblePolicyChange keeps the zone signing under appliedPol
// (rebind when needed) and logs a warning. Used when classify reports
// PolicyChangeIncompatibleAlg on the config path (rollover not implemented).
// Does not bind a policy whose Error field is set.
func refuseIncompatiblePolicyChange(zd *ZoneData, intentName, appliedName string, appliedPol *DnssecPolicy) {
	if appliedPol == nil || appliedPol.Error != "" {
		return
	}
	zd.mu.Lock()
	zd.DnssecPolicy = appliedPol
	zd.DnssecPolicyName = appliedName
	zd.mu.Unlock()
	lgEngine.Warn("refused incompatible DNSSEC algorithm change on reload; keeping applied policy",
		"zone", zd.ZoneName,
		"applied_policy", appliedName,
		"config_policy", intentName,
		"applied_ksk_alg", dns.AlgorithmToString[appliedPol.KSKAlgorithm],
		"config_intent", intentName,
		"applied_zsk_alg", dns.AlgorithmToString[appliedPol.ZSKAlgorithm],
		"reason", "algorithm change requires a key rollover (not implemented)")
}

// zoneActiveKeyRoleChanges reports, per role, whether the zone's ACTIVE keys must
// be dropped and regenerated to match pol's algorithms — the per-role decision
// that lets policy-reset be surgical (keep the role whose algorithm is already
// correct; roll only the one that changed). A role is UNCHANGED only when it has
// at least one active key of the target algorithm AND no active key of a wrong
// algorithm; otherwise it is CHANGED (missing the right algorithm, or carrying a
// wrong-alg key mid-rollover — both need the abrupt hard-flip that drops the role
// and regenerates one clean active key). `kskChanged` implies the parent DS
// breaks (the KSK keytag changes); `zskChanged` alone keeps the DS intact.
//
// Mode handling: a genuine split↔CSK mode change is a conservative FULL reset
// (both roles). It is detected by comparing the RELIABLE policy Mode fields —
// currentMode (the zone's currently-bound policy Mode) vs pol.Mode (the config
// target) — NOT by inferring mode from key shape. Inferring "only SEP keys ⇒
// CSK" would misread a split zone transiently missing its ZSK as a mode change
// and wrongly drop the healthy KSK, breaking the parent DS. currentMode is
// always "ksk-zsk" or "csk" for a bound policy (FinishDnssecPolicy normalizes
// it); "" means unknown → skip the mode check. In CSK mode the single SEP key is
// the only role and zskChanged is always false.
func zoneActiveKeyRoleChanges(kdb *KeyDB, zone string, pol *DnssecPolicy, currentMode string) (kskChanged, zskChanged bool, err error) {
	if currentMode != "" && currentMode != pol.Mode {
		return true, true, nil
	}

	active, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
	if err != nil {
		return false, false, err
	}
	var sepGood, sepBad bool // SEP bit set = KSK/CSK role
	var zskGood, zskBad bool // SEP bit clear = ZSK role
	for _, k := range active {
		if k.Flags&0x0001 == 0x0001 {
			if k.Algorithm == pol.KSKAlgorithm {
				sepGood = true
			} else {
				sepBad = true
			}
		} else if k.Algorithm == pol.ZSKAlgorithm {
			zskGood = true
		} else {
			zskBad = true
		}
	}

	if pol.Mode == DnssecPolicyModeCSK {
		// Single SEP (CSK) role; wrong-alg or missing CSK key → changed.
		return !sepGood || sepBad, false, nil
	}
	// Split: each role changed iff it lacks a right-alg active key or carries a
	// wrong-alg one. A missing role (no active key) → changed → regenerate.
	return !sepGood || sepBad, !zskGood || zskBad, nil
}

// policyResetDSWarning is the chain-of-trust break notice, emitted only when the
// KSK algorithm actually changed (the parent DS no longer matches the new KSK).
const policyResetDSWarning = "WARNING: this was an ABRUPT switch that BREAKS the chain of trust - the parent DS no longer matches the new KSK.\n" +
	"NOTE: validators will go BOGUS until the new DS is published at the parent (via the auto-rollover engine or a manual DS update)."

// policyResetReport builds the operator-facing message for a completed
// policy-reset. mode is the config policy's Mode ("ksk-zsk" | "csk"), used to
// report a CSK replacement as such rather than as a KSK/ZSK split roll. The
// DS-break warning fires ONLY when the KSK algorithm changed (kskChanged); when
// the KSK is untouched the report states the parent DS is unchanged.
func policyResetReport(zone, configName, mode string, kskChanged, zskChanged bool, newRRSIGs int) string {
	var b strings.Builder
	switch {
	case !kskChanged && !zskChanged:
		fmt.Fprintf(&b, "Zone %s: DNSSEC policy reset to config policy %q; active keys already matched - no key roll. Re-signed (%d RRSIGs) and recorded applied=config.\n", zone, configName, newRRSIGs)
		b.WriteString("KSK and parent DS unchanged.")
	case mode == DnssecPolicyModeCSK:
		// CSK: a single key does both roles, so a change is a CSK replacement
		// (KSK-level → DS breaks), never a "ZSK kept" split roll.
		fmt.Fprintf(&b, "Zone %s: DNSSEC policy reset to config policy %q; CSK algorithm rolled (dropped and regenerated the CSK). Re-signed (%d RRSIGs).\n", zone, configName, newRRSIGs)
		b.WriteString(policyResetDSWarning)
	case !kskChanged && zskChanged:
		fmt.Fprintf(&b, "Zone %s: DNSSEC policy reset to config policy %q; ZSK algorithm rolled (dropped and regenerated the ZSK), KSK kept. Re-signed under the new ZSK (%d RRSIGs).\n", zone, configName, newRRSIGs)
		b.WriteString("KSK and parent DS unchanged - no DS update needed.")
	case kskChanged && !zskChanged:
		fmt.Fprintf(&b, "Zone %s: DNSSEC policy reset to config policy %q; KSK algorithm rolled (dropped and regenerated the KSK), ZSK kept. Re-signed (%d RRSIGs).\n", zone, configName, newRRSIGs)
		b.WriteString(policyResetDSWarning)
	default: // split: both roles changed (incl. a csk→split full reset)
		fmt.Fprintf(&b, "Zone %s: DNSSEC policy reset to config policy %q; both KSK and ZSK algorithms rolled (dropped and regenerated both). Re-signed (%d RRSIGs).\n", zone, configName, newRRSIGs)
		b.WriteString(policyResetDSWarning)
	}
	return b.String()
}

// policyResetDryRunConfirm is the suffix for a dry-run preview whose apply is
// destructive (a key roll): tells the operator how to actually run it.
const policyResetDryRunConfirm = "Re-run with --confirm to apply."

// policyResetDryRunDSBreak is the DS-break line for a dry-run preview whose
// apply would roll the KSK (or CSK), plus the confirm prompt.
const policyResetDryRunDSBreak = "  * !! BREAK the chain of trust: the parent DS would no longer match the new KSK, and validators would go BOGUS until you re-publish the DS.\n" +
	policyResetDryRunConfirm

// policyResetDryRunReport describes what a policy-reset WOULD do, WITHOUT making
// any change — the preview shown when --confirm is absent. It mirrors
// policyResetReport's per-role classification in the conditional tense, states
// whether the parent DS would break, and tells the operator to add --confirm to
// proceed. mode is the config policy's Mode ("ksk-zsk" | "csk").
func policyResetDryRunReport(zone, configName, mode string, kskChanged, zskChanged bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "DRY RUN - policy-reset of zone %s to config policy %q would:\n", zone, configName)
	switch {
	case !kskChanged && !zskChanged:
		b.WriteString("  * roll NO keys - the active keys already match config; it would only re-sign and record applied=config.\n")
		b.WriteString("  * leave the KSK and parent DS UNCHANGED.\n")
		b.WriteString("This is safe (a no-op key-wise). " + policyResetDryRunConfirm)
	case mode == DnssecPolicyModeCSK:
		b.WriteString("  * drop and regenerate the CSK (the single combined-signing key).\n")
		b.WriteString(policyResetDryRunDSBreak)
	case !kskChanged && zskChanged:
		b.WriteString("  * roll the ZSK algorithm (drop and regenerate the ZSK), keeping the KSK.\n")
		b.WriteString("  * leave the KSK and parent DS UNCHANGED - no DS update needed.\n")
		b.WriteString(policyResetDryRunConfirm)
	case kskChanged && !zskChanged:
		b.WriteString("  * roll the KSK algorithm (drop and regenerate the KSK), keeping the ZSK.\n")
		b.WriteString(policyResetDryRunDSBreak)
	default: // both roles changed
		b.WriteString("  * roll BOTH the KSK and ZSK algorithms (drop and regenerate both).\n")
		b.WriteString(policyResetDryRunDSBreak)
	}
	return b.String()
}
