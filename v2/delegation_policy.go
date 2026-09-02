package tdns

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// DelegationPolicyConf is the YAML form of a named delegationsync.policies.*
// entry. Compiled to DelegationPolicy at config install.
type DelegationPolicyConf struct {
	Bootstrap DelegationBootstrapConf `yaml:"bootstrap" mapstructure:"bootstrap"`
}

type DelegationBootstrapConf struct {
	Mechanisms             []string            `yaml:"mechanisms" mapstructure:"mechanisms"`
	RequireDnssec          *bool               `yaml:"require-dnssec" mapstructure:"require-dnssec"`
	Manual                 bool                `yaml:"manual" mapstructure:"manual"`
	AllowUnvalidatedUpload bool                `yaml:"allow-unvalidated-upload" mapstructure:"allow-unvalidated-upload"`
	Retry                  DelegationRetryConf `yaml:"retry" mapstructure:"retry"`
}

type DelegationRetryConf struct {
	MaxAttempts int           `yaml:"max-attempts" mapstructure:"max-attempts"`
	Interval    time.Duration `yaml:"interval" mapstructure:"interval"`
}

// DelegationPolicy is the bound runtime policy: how a child's SIG(0) key
// becomes trusted. Empty Mechanisms means do not verify (locked-down), not
// today's VerifyChildKey default-fill.
type DelegationPolicy struct {
	Name                   string
	Mechanisms             []string
	RequireDnssec          bool
	Manual                 bool
	AllowUnvalidatedUpload bool
	RetryMaxAttempts       int
	RetryInterval          time.Duration
}

func DefaultDelegationPolicy() DelegationPolicy {
	return DelegationPolicy{
		Name:                   "default",
		Mechanisms:             []string{"at-apex", "at-ns"},
		RequireDnssec:          true,
		Manual:                 false,
		AllowUnvalidatedUpload: false,
		RetryMaxAttempts:       5,
		RetryInterval:          10 * time.Second,
	}
}

var (
	validParentMechanisms = map[string]bool{"at-apex": true, "at-ns": true}
	validChildMethods     = map[string]bool{"at-apex": true, "at-ns": true, "unsigned": true, "manual": true}
)

func validateConfigTokens(tokens []string, allowed map[string]bool, what string) error {
	var bad []string
	for _, t := range tokens {
		if !allowed[t] {
			bad = append(bad, t)
		}
	}
	if len(bad) > 0 {
		var names []string
		for n := range allowed {
			names = append(names, n)
		}
		sort.Strings(names)
		return fmt.Errorf("unknown %s %q (allowed: %s)", what, bad, strings.Join(names, ", "))
	}
	return nil
}

func compileDelegationPolicies(raw map[string]DelegationPolicyConf) (map[string]DelegationPolicy, error) {
	out := make(map[string]DelegationPolicy, len(raw)+1)
	for name, conf := range raw {
		p, err := compileDelegationPolicy(name, conf)
		if err != nil {
			return nil, err
		}
		out[name] = p
	}
	if _, ok := out["default"]; !ok {
		out["default"] = DefaultDelegationPolicy()
	}
	return out, nil
}

func compileDelegationPolicy(name string, conf DelegationPolicyConf) (DelegationPolicy, error) {
	p := DefaultDelegationPolicy()
	p.Name = name
	if conf.Bootstrap.Mechanisms != nil {
		if err := validateConfigTokens(conf.Bootstrap.Mechanisms, validParentMechanisms, "bootstrap mechanism"); err != nil {
			return DelegationPolicy{}, fmt.Errorf("delegationpolicy %q: %w", name, err)
		}
		p.Mechanisms = conf.Bootstrap.Mechanisms
	}
	if conf.Bootstrap.RequireDnssec != nil {
		p.RequireDnssec = *conf.Bootstrap.RequireDnssec
	}
	p.Manual = conf.Bootstrap.Manual
	p.AllowUnvalidatedUpload = conf.Bootstrap.AllowUnvalidatedUpload
	if conf.Bootstrap.Retry.MaxAttempts > 0 {
		p.RetryMaxAttempts = conf.Bootstrap.Retry.MaxAttempts
	}
	if conf.Bootstrap.Retry.Interval > 0 {
		p.RetryInterval = conf.Bootstrap.Retry.Interval
	}
	return p, nil
}

func compileChildBootstrapMethods(methods []string) ([]string, error) {
	if methods == nil {
		return []string{"at-apex", "at-ns"}, nil
	}
	if err := validateConfigTokens(methods, validChildMethods, "child.update.bootstrap.methods"); err != nil {
		return nil, err
	}
	return methods, nil
}

func lookupDelegationPolicy(name string) (DelegationPolicy, bool) {
	if name == "" {
		name = "default"
	}
	if p, ok := DelegationSyncConfig().CompiledPolicies[name]; ok {
		return p, true
	}
	if name == "default" {
		return DefaultDelegationPolicy(), true
	}
	return DelegationPolicy{}, false
}

func bindDelegationPolicy(zconf *ZoneConf) (*DelegationPolicy, error) {
	name := zconf.DelegationPolicy
	p, ok := lookupDelegationPolicy(name)
	if !ok {
		return nil, fmt.Errorf("unknown delegationpolicy %q", name)
	}
	return &p, nil
}

func compiledDefaultDelegationPolicy() DelegationPolicy {
	p, _ := lookupDelegationPolicy("default")
	return p
}

func (zd *ZoneData) boundDelegationPolicy() DelegationPolicy {
	if zd != nil && zd.DelegationPolicy != nil {
		return *zd.DelegationPolicy
	}
	return compiledDefaultDelegationPolicy()
}

// rebindLiveDelegationPolicies copies the freshly compiled policy of the same
// name onto every serving zone. bindDelegationPolicy stores a snapshot, so a
// config reload that only swaps CompiledPolicies would otherwise leave
// verification, upload gates, and SVCB advertisement on the old copy until
// ParseZones ran.
func rebindLiveDelegationPolicies() {
	for _, zd := range Zones.Items() {
		if zd == nil || zd.DelegationPolicy == nil {
			continue
		}
		name := zd.DelegationPolicy.Name
		p, ok := lookupDelegationPolicy(name)
		if !ok {
			lgConfig.Warn("delegationpolicy gone after reload; keeping previous snapshot",
				"zone", zd.ZoneName, "policy", name)
			continue
		}
		cp := p
		zd.DelegationPolicy = &cp
	}
}

func parentDelegationPolicy(childZone string) DelegationPolicy {
	parent := FindParentZone(childZone)
	if parent == nil {
		return compiledDefaultDelegationPolicy()
	}
	return parent.boundDelegationPolicy()
}

func zoneAllowsUnvalidatedUpload(zd *ZoneData) bool {
	return zd.boundDelegationPolicy().AllowUnvalidatedUpload
}

// BootstrapSVCBMethods is the §4.1 advertisement: what the parent claims on
// the wire. Empty means publish no bootstrap SVCB.
func (p DelegationPolicy) BootstrapSVCBMethods() []string {
	var out []string
	if p.RequireDnssec {
		for _, m := range p.Mechanisms {
			if m == "at-apex" || m == "at-ns" {
				out = append(out, m)
			}
		}
	} else if len(p.Mechanisms) > 0 {
		out = append(out, "unsigned")
	}
	if p.Manual {
		out = append(out, "manual")
	}
	return out
}

func (p DelegationPolicy) bootstrapSVCBData() string {
	return strings.Join(p.BootstrapSVCBMethods(), ",")
}
