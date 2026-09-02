/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Tests for the delegationsync: half of `tdns-cli <role> config check`: the
 * typed decode that replaced a viper read, and the two startup failures the
 * check now predicts (a config the daemon refuses outright, and a
 * delegationpolicy: reference that quarantines a zone).
 */
package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/johanix/tdns/v2"
	"github.com/spf13/viper"
)

// The whole viper-to-typed change rests on this: `config check` decodes the
// config file with v.Unmarshal into a tdns.Config, and the delegationsync
// structs must arrive POPULATED through that path.
//
// They carry both `yaml:` and `mapstructure:` tags -- the daemon's decoder runs
// with TagName "yaml", viper's runs with the default "mapstructure". If a
// mapstructure tag goes missing the check silently reports "schemes is empty"
// against a config that sets them, which is worse than the viper read it
// replaced. Hence a test that reads real YAML rather than setting struct
// fields directly.
//
// Which tags actually carry, established by dropping each one and re-running:
// only the HYPHENATED keys. mapstructure falls back to case-insensitive field
// NAME matching, so `mechanisms`, `manual` and `interval` decode into
// Mechanisms/Manual/Interval with no tag at all -- dropping those is harmless.
// `require-dnssec`, `max-attempts` and `allow-unvalidated-upload` have no such
// fallback, and this test fails if any of the three loses its tag. Do not
// "strengthen" it to chase the other three: there is nothing there to catch.
func TestConfigCheckDecodesDelegationSyncTyped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tdns.yaml")
	// EVERY value here is deliberately the OPPOSITE of what
	// compileDelegationPolicy fills in from DefaultDelegationPolicy(). That is
	// the whole point: compile gap-fills zero values, so a field asserted
	// against its own default proves nothing -- a dropped mapstructure tag
	// leaves the field zero, compile substitutes the default, and the
	// assertion passes on a decode that never happened. require-dnssec is
	// false (default true), manual true (false), the retry pair 3/7s (5/10s),
	// and default's mechanisms are at-ns alone (at-apex + at-ns).
	body := `
delegationsync:
   policies:
      default:
         bootstrap:
            mechanisms:      [ at-ns ]
            require-dnssec:  false
            manual:          true
            allow-unvalidated-upload: true
            retry:
               max-attempts: 3
               interval:     7s
      locked-down:
         bootstrap:
            mechanisms: [ ]
            manual:     true
   parent:
      schemes: [ notify, update ]
   child:
      schemes: [ notify, update ]
      update:
         bootstrap:
            methods: [ at-apex ]
`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}

	v := viper.New()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	var cfg tdns.Config
	if err := v.Unmarshal(&cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got := cfg.DelegationSync.Child.Schemes; len(got) != 2 || got[0] != "notify" || got[1] != "update" {
		t.Fatalf("child.schemes decoded as %v; the typed check would report it empty", got)
	}
	if got := cfg.DelegationSync.Parent.Schemes; len(got) != 2 {
		t.Fatalf("parent.schemes decoded as %v", got)
	}
	if got := cfg.DelegationSync.Child.Update.Bootstrap.Methods; len(got) != 1 || got[0] != "at-apex" {
		t.Fatalf("child bootstrap methods decoded as %v", got)
	}

	// An explicitly empty list must survive as a NON-NIL empty slice: compile
	// only overrides Mechanisms when the decoded value is non-nil, so if YAML
	// `[ ]` arrived as nil, locked-down would silently compile to
	// [at-apex, at-ns] and advertise them -- the advertisement lying about the
	// policy, which is the defect §4.1 exists to close.
	if m := cfg.DelegationSync.Policies["locked-down"].Bootstrap.Mechanisms; m == nil {
		t.Fatal("locked-down mechanisms decoded as nil; an explicit empty list must stay empty")
	}

	compiled, methods, err := tdns.CompileDelegationSyncPolicies(cfg.DelegationSync)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(methods) != 1 || methods[0] != "at-apex" {
		t.Fatalf("compiled child methods = %v", methods)
	}

	def, ok := compiled["default"]
	if !ok {
		t.Fatal("default policy missing after compile")
	}
	if def.RequireDnssec {
		t.Error("require-dnssec: false did not survive; the pointer-bool tag is not carrying")
	}
	if !def.Manual {
		t.Error("manual: true did not survive")
	}
	if !def.AllowUnvalidatedUpload {
		t.Error("allow-unvalidated-upload: true did not survive")
	}
	if def.RetryMaxAttempts != 3 {
		t.Errorf("retry max-attempts = %d, want 3", def.RetryMaxAttempts)
	}
	if def.RetryInterval != 7*time.Second {
		t.Errorf("retry interval = %s, want 7s; the duration hook or its tag is not carrying", def.RetryInterval)
	}
	if !reflect.DeepEqual(def.Mechanisms, []string{"at-ns"}) {
		t.Errorf("default mechanisms = %v, want [at-ns]", def.Mechanisms)
	}

	locked, ok := compiled["locked-down"]
	if !ok {
		t.Fatal("locked-down policy missing after compile")
	}
	if len(locked.Mechanisms) != 0 {
		t.Errorf("locked-down mechanisms = %v, want empty", locked.Mechanisms)
	}
	if !locked.Manual {
		t.Error("locked-down manual: true did not survive")
	}
	// The observable consequence of the two lines above.
	if got := locked.BootstrapSVCBMethods(); len(got) != 1 || got[0] != "manual" {
		t.Errorf("locked-down advertises %v, want [manual]", got)
	}
	if !tdns.DelegationPolicyResolves(compiled, "locked-down") {
		t.Fatal("locked-down did not survive the decode+compile round trip")
	}
}

// An unknown mechanism token makes SetDelegationSyncConfig fail, which makes
// ParseConfig fail, which means the daemon does not start at all. `config
// check` must say so rather than passing the file.
func TestCheckDelegationSyncRejectsUnknownToken(t *testing.T) {
	var cfg tdns.Config
	cfg.DelegationSync.Policies = map[string]tdns.DelegationPolicyConf{
		"typo": {Bootstrap: tdns.DelegationBootstrapConf{Mechanisms: []string{"at-apx"}}},
	}
	rep := newCCReport()
	checkDelegationSync(&cfg, rep)

	if !hasLevel(rep, "Delegation sync", "delegationsync", ccFAIL) {
		t.Fatalf("unknown mechanism must FAIL, got %+v", rep.byGroup["Delegation sync"])
	}
}

// A delegationpolicy: that does not resolve quarantines the zone at startup.
// Checked on the zone, on the template it may be inherited from, and NOT
// flagged when omitted (omission binds "default").
func TestCheckDelegationSyncResolvesPolicyReferences(t *testing.T) {
	var cfg tdns.Config
	cfg.DelegationSync.Policies = map[string]tdns.DelegationPolicyConf{
		"manual": {Bootstrap: tdns.DelegationBootstrapConf{Manual: true}},
	}
	cfg.Templates = []tdns.ZoneConf{
		{Name: "good-tmpl", Type: "primary", DelegationPolicy: "manual"},
		{Name: "bad-tmpl", Type: "primary", DelegationPolicy: "nosuch"},
	}
	cfg.Zones = []tdns.ZoneConf{
		{Name: "omitted.example.", Type: "primary"},
		{Name: "explicit.example.", Type: "primary", DelegationPolicy: "manual"},
		{Name: "unknown.example.", Type: "primary", DelegationPolicy: "typo-here"},
		{Name: "inherits-bad.example.", Type: "primary", Template: "bad-tmpl"},
		{Name: "inherits-good.example.", Type: "primary", Template: "good-tmpl"},
	}

	rep := newCCReport()
	checkDelegationSync(&cfg, rep)

	for _, ok := range []string{"omitted.example.", "explicit.example.", "inherits-good.example."} {
		if got := levelsFor(rep, "Delegation sync", ok); len(got) != 0 {
			t.Errorf("%s should produce no finding, got %v", ok, got)
		}
	}
	for _, bad := range []string{"unknown.example.", "inherits-bad.example."} {
		if !hasLevel(rep, "Delegation sync", bad, ccFAIL) {
			t.Errorf("%s must FAIL on an unresolvable delegationpolicy", bad)
		}
	}
	// The template is named in its own right, so the operator is told where the
	// bad name lives rather than only which zones it poisoned.
	if !hasLevel(rep, "Delegation sync", "template bad-tmpl", ccFAIL) {
		t.Errorf("the offending template must be named: %+v", rep.byGroup["Delegation sync"])
	}
}

// The same source-level guard the tdns package carries
// (TestNoViperReadsOfTheDelegationsyncBlock), extended to this package and to
// any receiver name.
//
// The CLI is where the rule is easiest to break: unlike the daemons it DOES
// have a populated viper, so a viper read here appears to work on the
// developer's machine and then disagrees with the daemon on the two things
// viper cannot represent -- a dotted key, and the yaml-vs-mapstructure tag.
// `config check` exists to predict the daemon; reading the config differently
// from the daemon is the one bug it must not have.
func TestNoViperReadsOfTheDelegationsyncBlockInCLI(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	pat := regexp.MustCompile(`\.Get[A-Za-z]*\("delegationsync\.`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if pat.MatchString(line) {
				t.Errorf("%s:%d reads the delegationsync block from viper: %s\n"+
					"    Use the typed cfg.DelegationSync (config check decodes it with"+
					" v.Unmarshal) so the check reads the config exactly as the daemon does.",
					f, i+1, strings.TrimSpace(line))
			}
		}
	}
}
