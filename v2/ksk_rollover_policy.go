package tdns

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

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

type RolloverPolicy struct {
	Method             RolloverMethod
	NumDS              int
	ParentAgent        string
	ConfirmInitialWait time.Duration
	ConfirmPollMax     time.Duration
	ConfirmTimeout     time.Duration
	DsyncRequired      bool
}

type ClampingPolicy struct {
	Enabled bool
	Margin  time.Duration
}

const (
	defaultConfirmInitialWait = 2 * time.Second
	defaultConfirmPollMax     = 60 * time.Second
	defaultConfirmTimeout     = time.Hour
	defaultMultiDSNumDS       = 3
	defaultClampingMargin     = 15 * time.Minute
)

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
		d, err := time.ParseDuration(strings.TrimSpace(conf.Ttls.DNSKEY))
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
		d, err := time.ParseDuration(marginStr)
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

	// max_served must be parsed AFTER clamping so the cross-check against
	// clamping.margin sees the resolved margin value.
	if s := strings.TrimSpace(conf.Ttls.MaxServed); s != "" {
		d, err := time.ParseDuration(s)
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

	warnDnssecPolicyCoupling(policyName, out, conf)
	return nil
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
		d, err := time.ParseDuration(val)
		if err != nil {
			return 0, fmt.Errorf("rollover.%s: %w", field, err)
		}
		if d < 0 {
			return 0, fmt.Errorf("rollover.%s must be non-negative", field)
		}
		return d, nil
	}
	var err error
	if out.Rollover.ConfirmInitialWait, err = parseDur("confirm-initial-wait", conf.Rollover.ConfirmInitialWait, defaultConfirmInitialWait); err != nil {
		return fmt.Errorf("dnssec policy %q: %w", policyName, err)
	}
	if out.Rollover.ConfirmPollMax, err = parseDur("confirm-poll-max", conf.Rollover.ConfirmPollMax, defaultConfirmPollMax); err != nil {
		return fmt.Errorf("dnssec policy %q: %w", policyName, err)
	}
	if out.Rollover.ConfirmTimeout, err = parseDur("confirm-timeout", conf.Rollover.ConfirmTimeout, defaultConfirmTimeout); err != nil {
		return fmt.Errorf("dnssec policy %q: %w", policyName, err)
	}
	return nil
}

// parseParentAgent normalizes rollover.parent-agent to host:port (default port 53).
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

func warnDnssecPolicyCoupling(policyName string, out *DnssecPolicy, conf *DnssecPolicyConf) {
	kskL := time.Duration(out.KSK.Lifetime) * time.Second
	sigV := time.Duration(out.KSK.SigValidity) * time.Second
	if kskL > 0 && out.TTLS.DNSKEY > 0 {
		maxTTL := time.Duration(out.TTLS.DNSKEY) * time.Second
		if maxTTL > kskL/4 {
			lgConfig.Warn("dnssec policy: ttls.dnskey exceeds ksk.lifetime/4 (rapid rollover coupling)",
				"policy", policyName, "dnskey_ttl", maxTTL.String(), "ksk_lifetime", kskL.String())
		}
	}
	if kskL > 0 && sigV > kskL {
		lgConfig.Warn("dnssec policy: ksk.sig-validity exceeds ksk.lifetime",
			"policy", policyName, "sig_validity", sigV.String(), "ksk_lifetime", kskL.String())
	}
	if out.Clamping.Enabled && out.Clamping.Margin > 0 && out.Clamping.Margin < 60*time.Second {
		lgConfig.Warn("dnssec policy: clamping.margin below 60s (spec guidance for skew)",
			"policy", policyName, "margin", out.Clamping.Margin.String())
	}
	_ = conf
}

// dnssecPoliciesYAML is the top-level shape for `tdns zone keystore dnssec policy validate --file`.
type dnssecPoliciesYAML struct {
	DnssecPolicies map[string]DnssecPolicyConf `yaml:"dnssecpolicies"`
}

// ValidateDnssecPoliciesFromFile parses a YAML file with a top-level dnssecpolicies: map
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
	if len(root.DnssecPolicies) == 0 {
		return errors.New("no dnssecpolicies: block found (top-level key must be dnssecpolicies)")
	}
	var errs []error
	for name, dp := range root.DnssecPolicies {
		dp.Name = name
		alg := dns.StringToAlgorithm[strings.TrimSpace(strings.ToUpper(dp.Algorithm))]
		if alg == 0 {
			errs = append(errs, fmt.Errorf("policy %q: unknown algorithm %q", name, dp.Algorithm))
			continue
		}
		tmp := DnssecPolicy{
			Name:      name,
			Algorithm: alg,
			KSK:       GenKeyLifetime(dp.KSK.Lifetime, dp.KSK.SigValidity),
			ZSK:       GenKeyLifetime(dp.ZSK.Lifetime, dp.ZSK.SigValidity),
			CSK:       GenKeyLifetime(dp.CSK.Lifetime, dp.CSK.SigValidity),
		}
		if err := FinishDnssecPolicy(name, &dp, &tmp); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
