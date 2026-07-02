package tdns

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

// parseExtendedDuration parses a Go duration string with one extension:
// a single trailing "d" (days) or "w" (weeks) suffix on a plain integer,
// e.g. "14d" or "2w". Everything else falls through to time.ParseDuration,
// so "168h", "30m", "1h30m" keep working. Days = 24h, weeks = 168h. Operators
// express key lifetimes and signature validity in days/weeks; the stdlib
// parser stops at hours.
func parseExtendedDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		unit := s[len(s)-1]
		if unit == 'd' || unit == 'w' {
			n, err := strconv.Atoi(s[:len(s)-1])
			if err == nil && n >= 0 {
				per := 24 * time.Hour
				if unit == 'w' {
					per = 7 * 24 * time.Hour
				}
				return time.Duration(n) * per, nil
			}
			// Not a non-negative "<int>d/w" (e.g. "1.5d" or "-7d") — fall
			// through and let ParseDuration give the canonical error. ("1h30m"
			// has no d/w tail anyway.)
		}
	}
	return time.ParseDuration(s)
}

const (
	DnssecPolicyModeKSKZSK = "ksk-zsk"
	DnssecPolicyModeCSK    = "csk"
)

type RolloverMethod int

const (
	RolloverMethodNone RolloverMethod = iota
	RolloverMethodMultiDS
	RolloverMethodDoubleSignature
)

// String returns the YAML/config name for the rollover method.
func (m RolloverMethod) String() string {
	switch m {
	case RolloverMethodNone:
		return "none"
	case RolloverMethodMultiDS:
		return "multi-ds"
	case RolloverMethodDoubleSignature:
		return "double-signature"
	}
	return fmt.Sprintf("unknown(%d)", int(m))
}

type RolloverPolicy struct {
	Method             RolloverMethod
	NumDS              int
	ParentAgent        string
	ConfirmInitialWait time.Duration
	ConfirmPollMax     time.Duration
	ConfirmTimeout     time.Duration
	DsyncRequired      bool

	// Softfail state machine (rollover-overhaul). DsPublishDelay
	// drives the defaults of ConfirmPollMax and ConfirmTimeout when
	// those are not set explicitly: poll-max = clamp(delay/10, 30s,
	// 5m), timeout = delay × 1.2. Operator declares one number,
	// engine picks reasonable cadences for the rest.
	DsPublishDelay           time.Duration
	MaxAttemptsBeforeBackoff int
	SoftfailDelay            time.Duration

	// DsyncSchemePreference is one of the DsyncSchemePreference*
	// constants below. Default is DsyncSchemePreferenceAuto.
	DsyncSchemePreference string

	// ParentCdsPollEstimate is the operator's estimate of parent CDS
	// fetch latency. Used by E10 when NOTIFY is the sole viable scheme.
	// Defaults to 1m. See DnssecPolicyRolloverConf.ParentCdsPollEstimate.
	ParentCdsPollEstimate time.Duration

	// StandbyTime is the pause between standby and active states.
	// Defaults to 1m. See DnssecPolicyRolloverConf.StandbyTime.
	StandbyTime time.Duration
}

// DSYNC scheme preference values for RolloverPolicy.DsyncSchemePreference.
const (
	DsyncSchemePreferenceAuto         = "auto"
	DsyncSchemePreferencePreferUpdate = "prefer-update"
	DsyncSchemePreferencePreferNotify = "prefer-notify"
	DsyncSchemePreferenceForceUpdate  = "force-update"
	DsyncSchemePreferenceForceNotify  = "force-notify"
	defaultDsyncSchemePreference      = DsyncSchemePreferenceAuto
)

type ClampingPolicy struct {
	Enabled bool
	Margin  time.Duration
}

const (
	defaultConfirmInitialWait       = 2 * time.Second
	defaultConfirmPollMax           = 60 * time.Second
	defaultConfirmTimeout           = time.Hour
	defaultMultiDSNumDS             = 3
	defaultClampingMargin           = 15 * time.Minute
	defaultDsPublishDelay           = 5 * time.Minute
	defaultMaxAttemptsBeforeBackoff = 5
	defaultSoftfailDelayMinimum     = time.Hour
	defaultParentCdsPollEstimate    = time.Minute
	defaultStandbyTime              = time.Minute
)

// derivedPollMax returns clamp(dsDelay/10, 30s, 5m). Used as the
// default for ConfirmPollMax when YAML doesn't set it explicitly:
// polling faster than dsDelay/10 brings no new information from a
// parent that publishes on a slower cycle.
func derivedPollMax(dsDelay time.Duration) time.Duration {
	if dsDelay <= 0 {
		return 30 * time.Second
	}
	v := dsDelay / 10
	if v < 30*time.Second {
		return 30 * time.Second
	}
	if v > 5*time.Minute {
		return 5 * time.Minute
	}
	return v
}

// derivedAttemptTimeout returns dsDelay × 1.2 — the per-attempt
// observation budget before declaring this attempt failed. The 20%
// safety margin lets a parent that's just barely outside its normal
// cycle still confirm before we give up on the attempt.
func derivedAttemptTimeout(dsDelay time.Duration) time.Duration {
	if dsDelay <= 0 {
		return time.Hour
	}
	return dsDelay * 12 / 10
}

// derivedSoftfailDelay returns max(1h, dsDelay). The long-term-mode
// probe interval should never be shorter than the parent's natural
// publish cycle: probing more often than the parent can possibly
// publish wastes UPDATEs.
func derivedSoftfailDelay(dsDelay time.Duration) time.Duration {
	if dsDelay > defaultSoftfailDelayMinimum {
		return dsDelay
	}
	return defaultSoftfailDelayMinimum
}

// FinishDnssecPolicy fills Mode, Rollover, TTLS, and Clamping on out from conf and KSK/ZSK lifetimes.
// out must already carry Name, Algorithm, KSK, ZSK, CSK from the caller.
func FinishDnssecPolicy(policyName string, conf *DnssecPolicyConf, out *DnssecPolicy) error {
	if conf == nil {
		return fmt.Errorf("dnssec policy %q: nil conf", policyName)
	}
	mode := strings.TrimSpace(strings.ToLower(conf.Mode))
	switch mode {
	case "":
		out.Mode = DnssecPolicyModeKSKZSK
	case DnssecPolicyModeKSKZSK, DnssecPolicyModeCSK:
		out.Mode = mode
	default:
		return fmt.Errorf("dnssec policy %q: invalid mode %q (want %q or %q)", policyName, conf.Mode, DnssecPolicyModeKSKZSK, DnssecPolicyModeCSK)
	}

	m, err := parseRolloverMethod(conf.Rollover.Method)
	if err != nil {
		return fmt.Errorf("dnssec policy %q: %w", policyName, err)
	}
	out.Rollover.Method = m

	switch m {
	case RolloverMethodNone:
		out.Rollover.NumDS = 0
		out.Rollover.ParentAgent = ""
		out.Rollover.ConfirmInitialWait = 0
		out.Rollover.ConfirmPollMax = 0
		out.Rollover.ConfirmTimeout = 0
		out.Rollover.DsyncRequired = false
		out.Rollover.DsPublishDelay = 0
		out.Rollover.MaxAttemptsBeforeBackoff = 0
		out.Rollover.SoftfailDelay = 0
		out.Rollover.DsyncSchemePreference = ""
	case RolloverMethodMultiDS:
		n := conf.Rollover.NumDS
		if n == 0 {
			n = defaultMultiDSNumDS
		}
		if n < 1 {
			return fmt.Errorf("dnssec policy %q: rollover.num-ds must be >= 1 for multi-ds", policyName)
		}
		out.Rollover.NumDS = n
		if err := fillRolloverDurations(policyName, conf, out); err != nil {
			return err
		}
		agent, err := parseParentAgent(policyName, conf.Rollover.ParentAgent)
		if err != nil {
			return err
		}
		out.Rollover.ParentAgent = agent
		dsync := true
		if conf.Rollover.DsyncRequired != nil {
			dsync = *conf.Rollover.DsyncRequired
		}
		out.Rollover.DsyncRequired = dsync
	case RolloverMethodDoubleSignature:
		n := conf.Rollover.NumDS
		if n == 0 {
			n = 2
		}
		if n != 2 {
			return fmt.Errorf("dnssec policy %q: rollover.num-ds must be 2 for double-signature (got %d)", policyName, n)
		}
		out.Rollover.NumDS = n
		if err := fillRolloverDurations(policyName, conf, out); err != nil {
			return err
		}
		agent, err := parseParentAgent(policyName, conf.Rollover.ParentAgent)
		if err != nil {
			return err
		}
		out.Rollover.ParentAgent = agent
		dsync := true
		if conf.Rollover.DsyncRequired != nil {
			dsync = *conf.Rollover.DsyncRequired
		}
		out.Rollover.DsyncRequired = dsync
	}

	if strings.TrimSpace(conf.Ttls.DNSKEY) != "" {
		d, err := parseExtendedDuration(strings.TrimSpace(conf.Ttls.DNSKEY))
		if err != nil {
			return fmt.Errorf("dnssec policy %q: ttls.dnskey: %w", policyName, err)
		}
		if d < 0 {
			return fmt.Errorf("dnssec policy %q: ttls.dnskey must be non-negative", policyName)
		}
		out.TTLS.DNSKEY = uint32(d.Seconds())
	}

	out.Clamping.Enabled = conf.Clamping.Enabled
	if out.Clamping.Enabled {
		// 4D: when clamping is enabled, margin is required. It is both the
		// floor TTL near rollover and the retired-KSK hold time, and it
		// has no safe default — too short and the clamp is finer than
		// clock skew, too long and rollovers stall. Fail closed at parse.
		marginStr := strings.TrimSpace(conf.Clamping.Margin)
		if marginStr == "" {
			return fmt.Errorf("dnssec policy %q: clamping.margin is required when clamping.enabled: true", policyName)
		}
		d, err := parseExtendedDuration(marginStr)
		if err != nil {
			return fmt.Errorf("dnssec policy %q: clamping.margin: %w", policyName, err)
		}
		if d <= 0 {
			return fmt.Errorf("dnssec policy %q: clamping.margin must be positive", policyName)
		}
		out.Clamping.Margin = d
	} else {
		// clamping.enabled: false (or omitted): policy is valid; margin is
		// not required and defaults to 0. The rollover worker will fall
		// back to effective_margin = max(0, max_observed_ttl) for the
		// retired-KSK hold time.
		out.Clamping.Margin = 0
	}

	if s := strings.TrimSpace(conf.Ttls.ParentDS); s != "" {
		d, err := parseExtendedDuration(s)
		if err != nil {
			return fmt.Errorf("dnssec policy %q: ttls.parent-ds: %w", policyName, err)
		}
		if d < 0 {
			return fmt.Errorf("dnssec policy %q: ttls.parent-ds must be non-negative", policyName)
		}
		out.TTLS.ParentDS = uint32(d.Seconds())
	}

	if s := strings.TrimSpace(conf.Ttls.DS); s != "" {
		d, err := parseExtendedDuration(s)
		if err != nil {
			return fmt.Errorf("dnssec policy %q: ttls.ds: %w", policyName, err)
		}
		if d < 0 {
			return fmt.Errorf("dnssec policy %q: ttls.ds must be non-negative", policyName)
		}
		out.TTLS.DS = uint32(d.Seconds())
	}

	sv, err := parsePolicySigValidity(policyName, conf.SigValidity)
	if err != nil {
		return err
	}
	out.SigValidity = sv

	// max_served must be parsed AFTER clamping so the cross-check against
	// clamping.margin sees the resolved margin value.
	if s := strings.TrimSpace(conf.Ttls.MaxServed); s != "" {
		d, err := parseExtendedDuration(s)
		if err != nil {
			return fmt.Errorf("dnssec policy %q: ttls.max_served: %w", policyName, err)
		}
		// Floor at 60s with a warning. Below clock-skew the value is
		// nonsense in practice but it's not security-relevant to clamp
		// TTLs aggressively, so bump-and-warn rather than reject.
		if d < 60*time.Second {
			lgConfig.Warn("dnssec policy: ttls.max_served below 60s clock-skew floor; raised to 60s",
				"policy", policyName, "configured", d.String())
			d = 60 * time.Second
		}
		// Reject when max_served < clamping.margin and clamping is enabled.
		// The math still works (max_served wins as the always-on ceiling),
		// but it makes no operational sense: the steady-state ceiling is
		// stricter than the rollover-time floor. Almost certainly a
		// misconfiguration — fail closed so the operator notices.
		if out.Clamping.Enabled && out.Clamping.Margin > 0 && d < out.Clamping.Margin {
			return fmt.Errorf("dnssec policy %q: ttls.max_served (%s) must be >= clamping.margin (%s); "+
				"the always-on TTL ceiling cannot be stricter than the rollover-time floor",
				policyName, d, out.Clamping.Margin)
		}
		out.TTLS.MaxServed = uint32(d.Seconds())
	}

	warnDnssecPolicyCoupling(policyName, out)
	return nil
}

func parsePolicySigValidity(policyName string, conf DnssecPolicySigValidityConf) (PolicySigValidity, error) {
	defaultStr := strings.TrimSpace(conf.Default)
	if defaultStr == "" {
		return PolicySigValidity{}, fmt.Errorf("dnssec policy %q: sigvalidity.default is required", policyName)
	}
	defaultDur, err := parseExtendedDuration(defaultStr)
	if err != nil {
		return PolicySigValidity{}, fmt.Errorf("dnssec policy %q: sigvalidity.default: %w", policyName, err)
	}
	if defaultDur <= 0 {
		return PolicySigValidity{}, fmt.Errorf("dnssec policy %q: sigvalidity.default must be positive", policyName)
	}
	out := PolicySigValidity{Default: uint32(defaultDur.Seconds())}

	dnskeyStr := strings.TrimSpace(conf.Dnskey)
	if dnskeyStr == "" {
		out.DNSKEY = out.Default
	} else {
		d, err := parseExtendedDuration(dnskeyStr)
		if err != nil {
			return PolicySigValidity{}, fmt.Errorf("dnssec policy %q: sigvalidity.dnskey: %w", policyName, err)
		}
		if d <= 0 {
			return PolicySigValidity{}, fmt.Errorf("dnssec policy %q: sigvalidity.dnskey must be positive", policyName)
		}
		out.DNSKEY = uint32(d.Seconds())
	}

	dsStr := strings.TrimSpace(conf.Ds)
	if dsStr == "" {
		out.DS = out.Default
	} else {
		d, err := parseExtendedDuration(dsStr)
		if err != nil {
			return PolicySigValidity{}, fmt.Errorf("dnssec policy %q: sigvalidity.ds: %w", policyName, err)
		}
		if d <= 0 {
			return PolicySigValidity{}, fmt.Errorf("dnssec policy %q: sigvalidity.ds must be positive", policyName)
		}
		out.DS = uint32(d.Seconds())
	}
	return out, nil
}

// applyChildDSFallbackTTL sets hdr.Ttl from policy ttls.ds when the child
// has not expressed a TTL (zero header). Child-driven TTLs are never changed.
func applyChildDSFallbackTTL(hdr *dns.RR_Header, pol *DnssecPolicy) {
	if hdr == nil || hdr.Ttl != 0 || pol == nil {
		return
	}
	if pol.TTLS.DS > 0 {
		hdr.Ttl = pol.TTLS.DS
	}
}

func parseRolloverMethod(s string) (RolloverMethod, error) {
	switch strings.TrimSpace(strings.ToLower(s)) {
	case "", "none":
		return RolloverMethodNone, nil
	case "multi-ds":
		return RolloverMethodMultiDS, nil
	case "double-signature":
		return RolloverMethodDoubleSignature, nil
	default:
		return 0, fmt.Errorf("invalid rollover.method %q (want none, multi-ds, or double-signature)", s)
	}
}

func fillRolloverDurations(policyName string, conf *DnssecPolicyConf, out *DnssecPolicy) error {
	parseDur := func(field, val string, def time.Duration) (time.Duration, error) {
		val = strings.TrimSpace(val)
		if val == "" {
			return def, nil
		}
		d, err := parseExtendedDuration(val)
		if err != nil {
			return 0, fmt.Errorf("rollover.%s: %w", field, err)
		}
		if d < 0 {
			return 0, fmt.Errorf("rollover.%s must be non-negative", field)
		}
		return d, nil
	}
	var err error
	// Parse ds-publish-delay first; the others derive from it when
	// YAML doesn't set them explicitly.
	if out.Rollover.DsPublishDelay, err = parseDur("ds-publish-delay", conf.Rollover.DsPublishDelay, defaultDsPublishDelay); err != nil {
		return fmt.Errorf("dnssec policy %q: %w", policyName, err)
	}
	if out.Rollover.ConfirmInitialWait, err = parseDur("confirm-initial-wait", conf.Rollover.ConfirmInitialWait, defaultConfirmInitialWait); err != nil {
		return fmt.Errorf("dnssec policy %q: %w", policyName, err)
	}
	if out.Rollover.ConfirmPollMax, err = parseDur("confirm-poll-max", conf.Rollover.ConfirmPollMax, derivedPollMax(out.Rollover.DsPublishDelay)); err != nil {
		return fmt.Errorf("dnssec policy %q: %w", policyName, err)
	}
	if out.Rollover.ConfirmTimeout, err = parseDur("confirm-timeout", conf.Rollover.ConfirmTimeout, derivedAttemptTimeout(out.Rollover.DsPublishDelay)); err != nil {
		return fmt.Errorf("dnssec policy %q: %w", policyName, err)
	}
	if out.Rollover.SoftfailDelay, err = parseDur("softfail-delay", conf.Rollover.SoftfailDelay, derivedSoftfailDelay(out.Rollover.DsPublishDelay)); err != nil {
		return fmt.Errorf("dnssec policy %q: %w", policyName, err)
	}
	if out.Rollover.ParentCdsPollEstimate, err = parseDur("parent-cds-poll-estimate", conf.Rollover.ParentCdsPollEstimate, defaultParentCdsPollEstimate); err != nil {
		return fmt.Errorf("dnssec policy %q: %w", policyName, err)
	}
	if out.Rollover.StandbyTime, err = parseDur("standby-time", conf.Rollover.StandbyTime, defaultStandbyTime); err != nil {
		return fmt.Errorf("dnssec policy %q: %w", policyName, err)
	}
	out.Rollover.MaxAttemptsBeforeBackoff = conf.Rollover.MaxAttemptsBeforeBackoff
	if out.Rollover.MaxAttemptsBeforeBackoff == 0 {
		out.Rollover.MaxAttemptsBeforeBackoff = defaultMaxAttemptsBeforeBackoff
	}

	pref := strings.TrimSpace(strings.ToLower(conf.Rollover.DsyncSchemePreference))
	switch pref {
	case "":
		out.Rollover.DsyncSchemePreference = defaultDsyncSchemePreference
	case DsyncSchemePreferenceAuto,
		DsyncSchemePreferencePreferUpdate,
		DsyncSchemePreferencePreferNotify,
		DsyncSchemePreferenceForceUpdate,
		DsyncSchemePreferenceForceNotify:
		out.Rollover.DsyncSchemePreference = pref
	default:
		return fmt.Errorf("dnssec policy %q: rollover.dsync-scheme-preference %q invalid (want auto, prefer-update, prefer-notify, force-update, or force-notify)",
			policyName, conf.Rollover.DsyncSchemePreference)
	}

	// Cross-field validation. These constraints catch configurations
	// that would behave nonsensically: a per-attempt timeout shorter
	// than the parent's expected publish cycle would always declare
	// failure on a healthy parent; a softfail-delay shorter than the
	// per-attempt timeout means the long-term-mode probe interval is
	// shorter than a single attempt window.
	if out.Rollover.MaxAttemptsBeforeBackoff < 1 {
		return fmt.Errorf("dnssec policy %q: rollover.max-attempts-before-backoff must be >= 1", policyName)
	}
	if out.Rollover.ConfirmTimeout < out.Rollover.DsPublishDelay {
		return fmt.Errorf("dnssec policy %q: rollover.confirm-timeout (%s) must be >= rollover.ds-publish-delay (%s)",
			policyName, out.Rollover.ConfirmTimeout, out.Rollover.DsPublishDelay)
	}
	if out.Rollover.SoftfailDelay < out.Rollover.DsPublishDelay {
		return fmt.Errorf("dnssec policy %q: rollover.softfail-delay (%s) must be >= rollover.ds-publish-delay (%s)",
			policyName, out.Rollover.SoftfailDelay, out.Rollover.DsPublishDelay)
	}
	return nil
}

// NormalizeParentAgentAddr parses rollover.parent-agent or CLI --parent-agent into host:port (default port 53).
func NormalizeParentAgentAddr(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty parent-agent address")
	}
	host, port, err := net.SplitHostPort(raw)
	if err == nil {
		return net.JoinHostPort(host, port), nil
	}
	return net.JoinHostPort(raw, "53"), nil
}

func parseParentAgent(policyName, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("dnssec policy %q: rollover.parent-agent is required when rollover.method is multi-ds or double-signature", policyName)
	}
	a, err := NormalizeParentAgentAddr(raw)
	if err != nil {
		return "", fmt.Errorf("dnssec policy %q: rollover.parent-agent: %w", policyName, err)
	}
	return a, nil
}

// CollectDnssecPolicyCouplingWarnings returns rule-of-thumb concerns
// about a parsed policy that aren't §4 cache-flush invariants but
// still merit operator attention. Pure function — no side effects.
// Used by the `auto-rollover validate` CLI to fold them into its
// structured report alongside E5/E10/E11 results. The daemon path
// calls warnDnssecPolicyCoupling (logger wrapper) at config load.
func CollectDnssecPolicyCouplingWarnings(out *DnssecPolicy, isLarge func(uint8) bool) []string {
	var warnings []string
	if msg := largeAlgBulkWarningMsg(out, isLarge); msg != "" {
		warnings = append(warnings, msg)
	}
	kskL := time.Duration(out.KSK.Lifetime) * time.Second
	if kskL > 0 && out.TTLS.DNSKEY > 0 {
		maxTTL := time.Duration(out.TTLS.DNSKEY) * time.Second
		if maxTTL > kskL/4 {
			warnings = append(warnings,
				fmt.Sprintf("ttls.dnskey (%s) exceeds ksk.lifetime/4 (%s) — rapid rollover coupling",
					maxTTL, kskL/4))
		}
	}
	if out.Clamping.Enabled && out.Clamping.Margin > 0 && out.Clamping.Margin < 60*time.Second {
		warnings = append(warnings,
			fmt.Sprintf("clamping.margin (%s) below 60s spec guidance for clock skew",
				out.Clamping.Margin))
	}
	return warnings
}

func warnDnssecPolicyCoupling(policyName string, out *DnssecPolicy) {
	if out.suppressLoadWarnings {
		return
	}
	for _, w := range CollectDnssecPolicyCouplingWarnings(out, nil) {
		lgConfig.Warn("dnssec policy: "+w, "policy", policyName)
	}

	// W6: when force-notify is set, the rollover engine never falls back
	// to DNS UPDATE — the parent's CDS-fetch latency directly bounds
	// T_DS_pub_n. Surface the operator's parent-cds-poll-estimate at
	// load time so they can spot a surprising default before the first
	// rollover fires. INFO not WARN; not folded into the validate report.
	if out.Rollover.DsyncSchemePreference == DsyncSchemePreferenceForceNotify {
		lgConfig.Info("dnssec policy: force-notify selected; parent-cds-poll-estimate folded into E10 lead-time budget",
			"policy", policyName,
			"parent_cds_poll_estimate", out.Rollover.ParentCdsPollEstimate.String(),
			"ds_publish_delay", out.Rollover.DsPublishDelay.String())
	}
}

// dnssecPoliciesYAML is the top-level shape for `tdns zone keystore dnssec policy validate --file`.
// Mirrors the daemon config: policies and the split_algorithms allowlist
// both live under the dnssec: block.
type dnssecPoliciesYAML struct {
	Dnssec struct {
		Templates       map[string]DnssecPolicyConf `yaml:"templates"`
		Policies        map[string]DnssecPolicyConf `yaml:"policies"`
		SplitAlgorithms map[string][]string         `yaml:"split_algorithms"`
	} `yaml:"dnssec"`
}

// ParseDnssecPolicyConf parses a single DnssecPolicyConf into the
// runtime DnssecPolicy. Same logic as ValidateDnssecPoliciesFromFile's
// per-policy block; exposed for the `auto-rollover validate` CLI which
// needs to re-parse one policy from an offline YAML.
//
// Side-effect note: this calls FinishDnssecPolicy → warnDnssecPolicyCoupling
// which logs via lgConfig. Callers that want to suppress those logs
// (e.g. the validate CLI) should use ParseDnssecPolicyConfQuiet instead.
func ParseDnssecPolicyConf(name string, dp *DnssecPolicyConf) (*DnssecPolicy, error) {
	return parseDnssecPolicyConfImpl(name, dp, false, nil)
}

// ParseDnssecPolicyConfQuiet is the silent counterpart of
// ParseDnssecPolicyConf: it skips the warnDnssecPolicyCoupling
// log calls so a CLI tool can re-parse the daemon's policy without
// the user seeing logger lines that the daemon already emitted at
// startup. The caller can call CollectDnssecPolicyCouplingWarnings
// on the returned policy to render the same warnings as structured
// output.
func ParseDnssecPolicyConfQuiet(name string, dp *DnssecPolicyConf) (*DnssecPolicy, error) {
	return parseDnssecPolicyConfImpl(name, dp, true, nil)
}

// parseDnssecPolicyConfImpl resolves and validates one policy. splitAllowed
// is the KSK/ZSK pairing allowlist (kskAlg -> permitted zskAlgs); nil means
// only same-algorithm policies pass (fail closed).
func parseDnssecPolicyConfImpl(name string, dp *DnssecPolicyConf, quiet bool, splitAllowed map[uint8]map[uint8]bool) (*DnssecPolicy, error) {
	dp.Name = name
	alg, kskAlg, zskAlg, err := resolvePolicyRoleAlgorithms(name, dp)
	if err != nil {
		return nil, err
	}
	if err := validateSplitAlgorithm(name, kskAlg, zskAlg, splitAllowed); err != nil {
		return nil, err
	}
	kskLT, err := GenKeyLifetime(dp.KSK.Lifetime)
	if err != nil {
		return nil, fmt.Errorf("policy %q: %w", name, err)
	}
	zskLT, err := GenKeyLifetime(dp.ZSK.Lifetime)
	if err != nil {
		return nil, fmt.Errorf("policy %q: %w", name, err)
	}
	cskLT, err := GenKeyLifetime(dp.CSK.Lifetime)
	if err != nil {
		return nil, fmt.Errorf("policy %q: %w", name, err)
	}
	out := &DnssecPolicy{
		Name:         name,
		Algorithm:    alg,
		KSKAlgorithm: kskAlg,
		ZSKAlgorithm: zskAlg,
		KSK:          kskLT,
		ZSK:          zskLT,
		CSK:          cskLT,
	}
	if quiet {
		// Mark the policy so FinishDnssecPolicy / warnDnssecPolicyCoupling
		// suppress their lgConfig.Warn/Info calls for this parse.
		// CLI tools (validate) read the same warnings via
		// CollectDnssecPolicyCouplingWarnings and render them as
		// structured output instead of logger noise.
		out.suppressLoadWarnings = true
	}
	if err := FinishDnssecPolicy(name, dp, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ValidateDnssecPoliciesFromFile parses a YAML file with a dnssec.policies: map
// and validates every policy the same way as runtime config loading.
func ValidateDnssecPoliciesFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var root dnssecPoliciesYAML
	if err := yaml.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("yaml: %w", err)
	}
	if len(root.Dnssec.Policies) == 0 {
		return errors.New("no dnssec.policies: block found (policies live under the dnssec: key)")
	}
	splitAllowed := buildSplitAlgorithmSet(root.Dnssec.SplitAlgorithms)
	var errs []error
	for name, dp := range root.Dnssec.Policies {
		dp.Name = name
		expanded, terr := resolveDnssecPolicyTemplate(dp, root.Dnssec.Templates)
		if terr != nil {
			errs = append(errs, fmt.Errorf("policy %q: %w", name, terr))
			continue
		}
		dp = expanded
		alg, kskAlg, zskAlg, err := resolvePolicyRoleAlgorithms(name, &dp)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := validateSplitAlgorithm(name, kskAlg, zskAlg, splitAllowed); err != nil {
			errs = append(errs, err)
			continue
		}
		kskLT, err := GenKeyLifetime(dp.KSK.Lifetime)
		if err != nil {
			errs = append(errs, fmt.Errorf("policy %q: %w", name, err))
			continue
		}
		zskLT, err := GenKeyLifetime(dp.ZSK.Lifetime)
		if err != nil {
			errs = append(errs, fmt.Errorf("policy %q: %w", name, err))
			continue
		}
		cskLT, err := GenKeyLifetime(dp.CSK.Lifetime)
		if err != nil {
			errs = append(errs, fmt.Errorf("policy %q: %w", name, err))
			continue
		}
		tmp := DnssecPolicy{
			Name:         name,
			Algorithm:    alg,
			KSKAlgorithm: kskAlg,
			ZSKAlgorithm: zskAlg,
			KSK:          kskLT,
			ZSK:          zskLT,
			CSK:          cskLT,
		}
		if err := FinishDnssecPolicy(name, &dp, &tmp); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
