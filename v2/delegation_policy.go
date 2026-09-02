package tdns

import (
	"fmt"
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

func compileDelegationPolicies(raw map[string]DelegationPolicyConf) map[string]DelegationPolicy {
	out := make(map[string]DelegationPolicy, len(raw)+1)
	for name, conf := range raw {
		out[name] = compileDelegationPolicy(name, conf)
	}
	if _, ok := out["default"]; !ok {
		out["default"] = DefaultDelegationPolicy()
	}
	return out
}

func compileDelegationPolicy(name string, conf DelegationPolicyConf) DelegationPolicy {
	p := DefaultDelegationPolicy()
	p.Name = name
	if conf.Bootstrap.Mechanisms != nil {
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
	return p
}

func lookupDelegationPolicy(name string) (DelegationPolicy, bool) {
	if name == "" {
		name = "default"
	}
	p, ok := DelegationSyncConfig().CompiledPolicies[name]
	return p, ok
}

func bindDelegationPolicy(zconf *ZoneConf) (*DelegationPolicy, error) {
	name := zconf.DelegationPolicy
	p, ok := lookupDelegationPolicy(name)
	if !ok {
		return nil, fmt.Errorf("unknown delegationpolicy %q", name)
	}
	return &p, nil
}

func (zd *ZoneData) boundDelegationPolicy() DelegationPolicy {
	if zd != nil && zd.DelegationPolicy != nil {
		return *zd.DelegationPolicy
	}
	return DefaultDelegationPolicy()
}

func parentDelegationPolicy(childZone string) DelegationPolicy {
	parent := FindZone(childZone)
	if parent == nil {
		return DefaultDelegationPolicy()
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
