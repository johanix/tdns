/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Config-reload DNSSEC-policy-change guardrail (guardrail-plan PR-B,
 * docs/2026-07-17-config-reload-policy-guardrail-plan.md).
 *
 * The transactional-reload classifier (classifyPolicyChange, zone_policy_apply.go)
 * resolves BOTH the applied and the intent policy BY NAME from the same live
 * snapshot, so a SAME-NAME algorithm edit — the operator changes policy FOO's KSK
 * algorithm Ed25519->FALCON512 in the YAML while a zone stays bound to FOO — is
 * invisible to it: applied and intent both resolve to the *new* FOO, classify
 * returns None, and the zone is silently rebound WITHOUT a re-sign or key roll.
 * The mismatch only surfaces later, at the next sign, where
 * reconcileActiveKeyAlgorithms (sign.go) REFUSES (no automatic KSK/ZSK-algorithm
 * rollover exists) — the zone keeps serving its now-frozen signatures until they
 * expire, then goes BOGUS. This is the Finding-A blind spot.
 *
 * This guardrail closes it at the reload HANDLER: before any live config is
 * mutated it dry-parses the incoming DNSSEC policies into a throwaway Config and
 * correlates them against the running signed zones' ACTIVE keys — the same
 * comparison reconcileActiveKeyAlgorithms makes, run as a read-only dry-run. When
 * a would-strand algorithm change is found it refuses the WHOLE reload atomically
 * (nothing is mutated) unless the operator passes confirm=true. Governing axiom:
 * "YAML is truth; converge, not refuse — behind an explicit confirm gate." The
 * gate lives server-side (not in tdns-cli) so a SIGHUP or a direct API reload hits
 * it too: neither can set confirm=true, so a dangerous converge is held-and-logged
 * automatically ("free SIGHUP coverage").
 *
 * NOTE: this PR keeps the reconcile REFUSE. Turning the confirmed path into an
 * abrupt drop-and-regenerate converge (+ auto-CDS to bound the DS-break window) is
 * PR-C, deliberately sequenced AFTER this gate — a naked converge is a DS footgun
 * without it.
 */

package tdns

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mitchellh/mapstructure"
)

// ---------------------------------------------------------------------------
// Pure dry-run of reconcileActiveKeyAlgorithms
// ---------------------------------------------------------------------------

// policyRoleAlgs is the algorithm set a DNSSEC policy requires, by role. Codepoints
// (uint8), not names: the guardrail runs entirely in-process, so the policy and
// the active keys share this deployment's codepoint assignments — no name-mapping
// dance (that is only needed across the CLI/daemon boundary in config_check_cmds.go).
type policyRoleAlgs struct {
	mode string // DnssecPolicyModeCSK | DnssecPolicyModeKSKZSK
	ksk  uint8  // KSK (split) or CSK (csk mode) algorithm
	zsk  uint8  // ZSK algorithm (split mode only)
}

// zoneActiveAlgs is a zone's active-key algorithm codepoints, split by the SEP bit
// (flags & 1): ksk = SEP-set keys (KSK/CSK), zsk = SEP-clear keys (ZSK). Same
// convention the signer and the backfill predicate (zoneActiveKeysMatchAlgs) use.
type zoneActiveAlgs struct {
	ksk map[uint8]bool
	zsk map[uint8]bool
}

// policyAlgMiss is one role whose new-policy algorithm no active key of that role
// provides — the roles a reload would strand.
type policyAlgMiss struct {
	role    string // "KSK" | "ZSK" | "CSK"
	wantAlg uint8
	have    []uint8
}

// policyAlgStrandsActiveKeys is the pure dry-run of reconcileActiveKeyAlgorithms
// (sign.go): it reports the roles whose NEW policy algorithm the zone's current
// ACTIVE keys cannot provide, i.e. the roles a reload would strand (the signer
// then refuses to re-sign and the zone eventually goes bogus).
//
// Lenient, matching the operator-facing `config check` predictor
// (cli.missingRoleAlgs): a role is a miss only when it HAS active keys but NONE
// carries the wanted algorithm. Two deliberate non-findings:
//   - zero active keys for a role -> not a miss: the signer generates fresh keys of
//     the policy algorithm on first sign, it does not refuse.
//   - the wanted algorithm present alongside a wrong-algorithm key (mid-rollover,
//     both old+new active) -> not a miss: the zone can already sign under the new
//     algorithm.
//
// relaxed reflects the NEW dnssec.completeness: a ZSK algorithm change in relaxed
// mode is carried by the gradual FIFO ZSK roll (reconcile no-ops on it), so it is
// NOT a strand and is not flagged — flagging it would refuse a supported, safe
// transition. A KSK/CSK algorithm change is a strand in either mode (no automatic
// KSK-algorithm rollover exists). Pure and dependency-free so it is unit-testable.
func policyAlgStrandsActiveKeys(want policyRoleAlgs, active zoneActiveAlgs, relaxed bool) []policyAlgMiss {
	var miss []policyAlgMiss
	check := func(role string, wantAlg uint8, have map[uint8]bool) {
		if wantAlg == 0 || len(have) == 0 || have[wantAlg] {
			return
		}
		miss = append(miss, policyAlgMiss{role: role, wantAlg: wantAlg, have: sortedAlgs(have)})
	}
	if want.mode == DnssecPolicyModeCSK {
		check("CSK", want.ksk, active.ksk)
		return miss
	}
	check("KSK", want.ksk, active.ksk)
	if !relaxed {
		check("ZSK", want.zsk, active.zsk)
	}
	return miss
}

func sortedAlgs(m map[uint8]bool) []uint8 {
	out := make([]uint8, 0, len(m))
	for a := range m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// (algName is defined in api_structs.go.)

// ---------------------------------------------------------------------------
// Correlation: new policies vs running zones' active keys
// ---------------------------------------------------------------------------

// loadZoneActiveAlgs reads a zone's active DNSSEC keys and returns their algorithm
// codepoints split by SEP bit.
func loadZoneActiveAlgs(kdb *KeyDB, zone string) (zoneActiveAlgs, error) {
	out := zoneActiveAlgs{ksk: map[uint8]bool{}, zsk: map[uint8]bool{}}
	keys, err := GetDnssecKeysByState(kdb, zone, DnskeyStateActive)
	if err != nil {
		return out, err
	}
	for _, k := range keys {
		if k.Flags&0x0001 == 0x0001 { // SEP set -> KSK/CSK
			out.ksk[k.Algorithm] = true
		} else {
			out.zsk[k.Algorithm] = true
		}
	}
	return out, nil
}

// detectStrandingPolicyChanges is the guardrail correlation (plan §5.2): a
// read-only loop over the running Zones. For each live SIGNED zone it looks up the
// NEW policy under the zone's CURRENT bound name (newPolicies[zd.DnssecPolicyName])
// and dry-runs the reconcile against the zone's active keys. A binding-name change
// (zone rebound FOO->BAR) is deliberately out of scope — the transactional
// classifier already detects and refuses that (PolicyChangeIncompatibleAlg); this
// guardrail targets the same-name blind spot the classifier is structurally blind
// to. relaxed is the NEW dnssec.completeness mode (from the dry-parse).
//
// Never mutates anything. Returns the zones a reload would strand, sorted by name.
func (conf *Config) detectStrandingPolicyChanges(newPolicies map[string]DnssecPolicy, relaxed bool) ([]ReloadGuardrailZone, error) {
	kdb := conf.Internal.KeyDB
	if kdb == nil || len(newPolicies) == 0 {
		return nil, nil
	}

	var findings []ReloadGuardrailZone
	for _, zname := range Zones.Keys() {
		zd, ok := Zones.Get(zname)
		if !ok || zd == nil {
			continue
		}
		zd.mu.Lock()
		signed := zd.Options[OptOnlineSigning] || zd.Options[OptInlineSigning]
		polName := zd.DnssecPolicyName
		zd.mu.Unlock()
		if !signed || polName == "" {
			continue
		}

		newPol, ok := newPolicies[polName]
		if !ok || newPol.Error != "" {
			// The bound policy name was removed from the YAML, or the new
			// definition is broken. Those are the deleted-policy / broken-policy
			// cases the parse fail-closed and keepBindingOrQuarantineForBadIntent
			// paths already handle; they are not an algorithm-change strand, so the
			// guardrail leaves them alone.
			continue
		}

		active, err := loadZoneActiveAlgs(kdb, zd.ZoneName)
		if err != nil {
			return nil, fmt.Errorf("guardrail: list active keys for zone %s: %w", zd.ZoneName, err)
		}

		want := policyRoleAlgs{mode: newPol.Mode, ksk: newPol.KSKAlgorithm, zsk: newPol.ZSKAlgorithm}
		if want.mode == "" {
			want.mode = DnssecPolicyModeKSKZSK
		}
		miss := policyAlgStrandsActiveKeys(want, active, relaxed)
		if len(miss) == 0 {
			continue
		}
		findings = append(findings, ReloadGuardrailZone{
			Zone:       zd.ZoneName,
			PolicyName: polName,
			Roles:      missesToRoles(miss),
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Zone < findings[j].Zone })
	return findings, nil
}

func missesToRoles(miss []policyAlgMiss) []ReloadGuardrailRole {
	roles := make([]ReloadGuardrailRole, 0, len(miss))
	for _, m := range miss {
		have := make([]string, 0, len(m.have))
		for _, a := range m.have {
			have = append(have, algName(a))
		}
		roles = append(roles, ReloadGuardrailRole{Role: m.role, WantAlg: algName(m.wantAlg), HaveAlgs: have})
	}
	return roles
}

// ---------------------------------------------------------------------------
// Dry-parse of the incoming DNSSEC policies (no side effects)
// ---------------------------------------------------------------------------

// dryParseDnssecPolicies re-reads the dnssec: block from the config file into a
// throwaway scratch Config and parses it, WITHOUT touching the live conf. It
// returns the would-be-new policy set and whether the new dnssec.completeness is
// relaxed, so the guardrail can correlate the incoming policies against the running
// zones' active keys before any live state is mutated. ok=false — a nil file
// (embedded use), an unreadable file, or a parse error — means the caller skips the
// guardrail and lets the normal reload path surface any error. Mirrors
// reloadDnssecFromFile's read+decode, but into a scratch receiver.
func (conf *Config) dryParseDnssecPolicies() (policies map[string]DnssecPolicy, relaxed bool, ok bool) {
	cfgfile := conf.Internal.CfgFile
	if cfgfile == "" {
		return nil, false, false
	}
	configMap, _, err := processConfigFile(cfgfile, filepath.Dir(cfgfile), 0)
	if err != nil {
		lgConfig.Warn("reload guardrail: could not read config for dry-run; skipping guardrail", "err", err)
		return nil, false, false
	}
	var partial struct {
		Dnssec DnssecConf `yaml:"dnssec"`
	}
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{TagName: "yaml", Result: &partial})
	if err != nil {
		lgConfig.Warn("reload guardrail: decoder init failed; skipping guardrail", "err", err)
		return nil, false, false
	}
	if err := decoder.Decode(configMap); err != nil {
		lgConfig.Warn("reload guardrail: could not decode dnssec block; skipping guardrail", "err", err)
		return nil, false, false
	}
	scratch := &Config{}
	scratch.Dnssec = partial.Dnssec
	if err := scratch.parseDnssecConfig(); err != nil {
		lgConfig.Warn("reload guardrail: could not parse dnssec policies; skipping guardrail", "err", err)
		return nil, false, false
	}
	return scratch.Internal.DnssecPolicies, scratch.Internal.Completeness == CompletenessRelaxed, true
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

// ReloadGuardrailError is returned by a reload handler when the DNSSEC
// policy-algorithm guardrail refuses the reload. It carries the per-zone findings
// so the API handler can surface them structurally (ConfigResponse.GuardrailZones)
// and the CLI can render a rich message plus the --confirm hint.
type ReloadGuardrailError struct {
	Zones []ReloadGuardrailZone
}

func (e *ReloadGuardrailError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "config reload refused: %d signed zone(s) would be stranded by a DNSSEC policy algorithm change that no key rollover handles:\n", len(e.Zones))
	for _, z := range e.Zones {
		for _, r := range z.Roles {
			have := strings.Join(r.HaveAlgs, ", ")
			if have == "" {
				have = "none"
			}
			fmt.Fprintf(&b, "  - zone %s (policy %q): %s algorithm changed to %s, but the zone's active %s key(s) are [%s]\n",
				z.Zone, z.PolicyName, r.Role, r.WantAlg, r.Role, have)
		}
	}
	b.WriteString("These zones would keep serving their current signatures until expiry, then go BOGUS.\n")
	b.WriteString("Re-run with confirm=true (CLI: --confirm) to apply anyway, roll the key deliberately via the auto-rollover engine, or on a test zone run `tdns-cli auth zone dnssec policy-reset`.")
	return b.String()
}

// applyReloadGuardrail surfaces a reload guardrail refusal structurally on the
// API response: when err is a *ReloadGuardrailError it sets GuardrailBlocked and
// copies the per-zone findings so the CLI can render them and prompt for --confirm.
// A no-op for any other error.
func applyReloadGuardrail(resp *ConfigResponse, err error) {
	var ge *ReloadGuardrailError
	if errors.As(err, &ge) {
		resp.GuardrailBlocked = true
		resp.GuardrailZones = ge.Zones
	}
}

// reloadGuardrailDecision gates a reload on the guardrail findings: a
// *ReloadGuardrailError when there are findings and the operator did NOT confirm,
// nil otherwise (no findings, or confirm=true). Pure — the testable seam for the
// confirm gate.
func reloadGuardrailDecision(findings []ReloadGuardrailZone, confirm bool) error {
	if len(findings) == 0 || confirm {
		return nil
	}
	return &ReloadGuardrailError{Zones: findings}
}

// checkReloadPolicyGuardrail runs the DNSSEC policy-algorithm reload guardrail: it
// dry-parses the incoming policies, correlates them against the running signed
// zones' active keys, and returns a *ReloadGuardrailError when a same-name
// algorithm change would strand a zone and the operator did not confirm. Returns
// nil — the reload proceeds — when there is nothing to guard, when confirm is set,
// when the dry-run could not run (the normal reload path then surfaces any parse
// error), or when the correlation itself failed (fail-open: additive safety net,
// never worse than the pre-guardrail behavior).
//
// MUST be called under confMu, BEFORE any live config is mutated, so a refusal
// leaves the running server completely untouched (atomic refuse). The signer keeps
// its REFUSE on the same mismatch, so a confirmed reload does not silently converge
// (that is PR-C).
func (conf *Config) checkReloadPolicyGuardrail(confirm bool) error {
	newPolicies, relaxed, ok := conf.dryParseDnssecPolicies()
	if !ok {
		return nil
	}
	findings, err := conf.detectStrandingPolicyChanges(newPolicies, relaxed)
	if err != nil {
		// Fail-open: the guardrail is an additive safety net, never worse than the
		// pre-guardrail behavior. But a safety control that silently fails open must
		// not slip by unnoticed, and tdns has no metrics endpoint to count it, so log
		// this loudly at Error rather than Warn.
		lgConfig.Error("reload guardrail FAILED OPEN: correlation error; reload allowed WITHOUT the same-name DNSSEC algorithm-change safety check — investigate", "err", err)
		return nil
	}
	if derr := reloadGuardrailDecision(findings, confirm); derr != nil {
		lgConfig.Error("reload guardrail: refusing config reload (dangerous DNSSEC policy algorithm change)",
			"zones", len(findings))
		return derr
	}
	if len(findings) > 0 {
		lgConfig.Warn("reload guardrail: applying CONFIRMED dangerous DNSSEC policy algorithm change; the signer will still refuse to re-sign until the key is rolled",
			"zones", len(findings))
	}
	return nil
}
