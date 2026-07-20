/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Tests for the agent-specific config checks and the role plumbing shared by
 * the auth/agent `config check`.
 */
package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/johanix/tdns/v2"
	"github.com/spf13/viper"
)

// levelsFor returns the levels recorded under group for the given check name.
func levelsFor(rep *ccReport, group, check string) []ccLevel {
	var out []ccLevel
	for _, r := range rep.byGroup[group] {
		if r.check == check {
			out = append(out, r.level)
		}
	}
	return out
}

func hasLevel(rep *ccReport, group, check string, want ccLevel) bool {
	for _, l := range levelsFor(rep, group, check) {
		if l == want {
			return true
		}
	}
	return false
}

func TestRolePlumbing(t *testing.T) {
	tests := []struct {
		role        string
		wantCfg     string
		wantType    tdns.AppType
		wantHasPath bool
	}{
		{"auth", tdns.DefaultAuthCfgFile, tdns.AppTypeAuth, true},
		{"agent", tdns.DefaultAgentCfgFile, tdns.AppTypeAgent, false},
		{"imr", tdns.DefaultImrCfgFile, tdns.AppTypeImr, false},
		// Unknown roles fall back to auth rather than producing an empty path.
		{"nosuchrole", tdns.DefaultAuthCfgFile, tdns.AppTypeAuth, false},
	}
	for _, tc := range tests {
		t.Run(tc.role, func(t *testing.T) {
			if got := defaultCfgFileForRole(tc.role); got != tc.wantCfg {
				t.Errorf("defaultCfgFileForRole(%q) = %q, want %q", tc.role, got, tc.wantCfg)
			}
			if got := appTypeForRole(tc.role); got != tc.wantType {
				t.Errorf("appTypeForRole(%q) = %v, want %v", tc.role, got, tc.wantType)
			}
			if got := roleHasConfigPaths(tc.role); got != tc.wantHasPath {
				t.Errorf("roleHasConfigPaths(%q) = %v, want %v", tc.role, got, tc.wantHasPath)
			}
		})
	}
}

// A standalone tdns-agent cannot parse multi-provider:, so its presence must be
// reported rather than silently ignored.
func TestCheckAgentInertConfig_MultiProvider(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		v := viper.New()
		v.Set("multi-provider", map[string]interface{}{"role": "agent"})
		rep := newCCReport()
		checkAgentInertConfig(&tdns.Config{}, v, rep)
		if !hasLevel(rep, "Agent-specific", "multi-provider", ccWARN) {
			t.Fatalf("expected a WARN for an inert multi-provider block, got %+v", rep.byGroup["Agent-specific"])
		}
	})

	t.Run("absent", func(t *testing.T) {
		rep := newCCReport()
		checkAgentInertConfig(&tdns.Config{}, viper.New(), rep)
		if len(levelsFor(rep, "Agent-specific", "multi-provider")) != 0 {
			t.Fatalf("expected no multi-provider finding, got %+v", rep.byGroup["Agent-specific"])
		}
	})
}

// The agent parses dnssec: but never signs; that is INFO, not a warning.
func TestCheckAgentInertConfig_DnssecIsInfo(t *testing.T) {
	cfg := &tdns.Config{}
	cfg.Dnssec.Policies = map[string]tdns.DnssecPolicyConf{"default": {}}
	rep := newCCReport()
	checkAgentInertConfig(cfg, viper.New(), rep)
	if !hasLevel(rep, "Agent-specific", "dnssec", ccINFO) {
		t.Fatalf("expected INFO for dnssec policies on agent, got %+v", rep.byGroup["Agent-specific"])
	}
	if fails, warns := rep.counts(); fails != 0 || warns != 0 {
		t.Fatalf("dnssec policies on an agent must not FAIL or WARN, got %d/%d", fails, warns)
	}
}

func TestCheckAgentZoneOptions(t *testing.T) {
	tests := []struct {
		name       string
		zone       tdns.ZoneConf
		schemes    []string
		wantLevel  ccLevel
		wantNoFind bool
	}{
		{
			name:       "proxy on secondary is fine",
			zone:       tdns.ZoneConf{Name: "ok.example.", Type: "secondary", OptionsStrs: []string{"delegation-sync-proxy"}},
			wantNoFind: true,
		},
		{
			name:      "proxy on primary is quarantined",
			zone:      tdns.ZoneConf{Name: "bad.example.", Type: "primary", OptionsStrs: []string{"delegation-sync-proxy"}},
			wantLevel: ccFAIL,
		},
		{
			// On the agent the delegation-sync-child setup block only runs when
			// the zone also carries multi-provider; without it the option is
			// silently inert, which is a warning rather than a failure.
			name:      "child without multi-provider is inert",
			zone:      tdns.ZoneConf{Name: "inert.example.", Type: "secondary", OptionsStrs: []string{"delegation-sync-child"}},
			schemes:   []string{"notify"},
			wantLevel: ccWARN,
		},
		{
			name:      "child with multi-provider but no schemes is quarantined",
			zone:      tdns.ZoneConf{Name: "noschemes.example.", Type: "secondary", OptionsStrs: []string{"delegation-sync-child", "multi-provider"}},
			schemes:   nil,
			wantLevel: ccFAIL,
		},
		{
			name:       "child with multi-provider and schemes is fine",
			zone:       tdns.ZoneConf{Name: "good.example.", Type: "secondary", OptionsStrs: []string{"delegation-sync-child", "multi-provider"}},
			schemes:    []string{"notify", "update"},
			wantNoFind: true,
		},
		{
			name:       "unrelated options are ignored",
			zone:       tdns.ZoneConf{Name: "plain.example.", Type: "secondary", OptionsStrs: []string{"fold-case"}},
			wantNoFind: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := viper.New()
			if tc.schemes != nil {
				v.Set("delegationsync.child.schemes", tc.schemes)
			}
			cfg := &tdns.Config{Zones: []tdns.ZoneConf{tc.zone}}
			rep := newCCReport()
			checkAgentZoneOptions(cfg, v, rep)

			got := levelsFor(rep, "Agent-specific", tc.zone.Name)
			if tc.wantNoFind {
				if len(got) != 0 {
					t.Fatalf("expected no finding, got %+v", rep.byGroup["Agent-specific"])
				}
				return
			}
			if len(got) != 1 || got[0] != tc.wantLevel {
				t.Fatalf("expected one %v, got %v (%+v)", tc.wantLevel.label(), got, rep.byGroup["Agent-specific"])
			}
		})
	}
}

// A zone with no name must not produce a phantom finding.
func TestCheckAgentZoneOptions_SkipsUnnamedZone(t *testing.T) {
	cfg := &tdns.Config{Zones: []tdns.ZoneConf{{Type: "primary", OptionsStrs: []string{"delegation-sync-proxy"}}}}
	rep := newCCReport()
	checkAgentZoneOptions(cfg, viper.New(), rep)
	if fails, warns := rep.counts(); fails != 0 || warns != 0 {
		t.Fatalf("unnamed zone should be skipped, got %d FAIL / %d WARN", fails, warns)
	}
}

// SetupLogging reads the main config file before include: is resolved, so a
// log: block reachable only through an include is a startup failure even though
// the merged view looks complete.
func TestCheckLogSection(t *testing.T) {
	write := func(t *testing.T, dir, name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("log in main file passes", func(t *testing.T) {
		dir := t.TempDir()
		main := write(t, dir, "tdns-agent.yaml", "log:\n   file: /tmp/x.log\n")
		v := viper.New()
		v.SetConfigFile(main)
		if err := v.ReadInConfig(); err != nil {
			t.Fatal(err)
		}
		rep := newCCReport()
		checkLogSection(v, main, rep)
		if fails, _ := rep.counts(); fails != 0 {
			t.Fatalf("top-level log: must not FAIL, got %+v", rep.byGroup["Config file"])
		}
	})

	t.Run("log only in include fails", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "logging.yaml", "log:\n   file: /tmp/x.log\n")
		main := write(t, dir, "tdns-agent.yaml", "include:\n  - logging.yaml\nservice:\n   name: TDNS-AGENT\n")

		// Merged view (what loadConfigViper produces) does see log.file.
		v := viper.New()
		v.SetConfigFile(main)
		if err := v.ReadInConfig(); err != nil {
			t.Fatal(err)
		}
		v.SetConfigFile(filepath.Join(dir, "logging.yaml"))
		if err := v.MergeInConfig(); err != nil {
			t.Fatal(err)
		}
		if v.GetString("log.file") == "" {
			t.Fatal("test setup: merged view should see log.file")
		}

		rep := newCCReport()
		checkLogSection(v, main, rep)
		if !hasLevel(rep, "Config file", "log", ccFAIL) {
			t.Fatalf("expected FAIL for include-only log:, got %+v", rep.byGroup["Config file"])
		}
	})

	t.Run("no log anywhere is left to the required-field check", func(t *testing.T) {
		dir := t.TempDir()
		main := write(t, dir, "tdns-agent.yaml", "service:\n   name: TDNS-AGENT\n")
		v := viper.New()
		v.SetConfigFile(main)
		if err := v.ReadInConfig(); err != nil {
			t.Fatal(err)
		}
		rep := newCCReport()
		checkLogSection(v, main, rep)
		if fails, warns := rep.counts(); fails != 0 || warns != 0 {
			t.Fatalf("missing log: is the required-field check's job, got %d/%d", fails, warns)
		}
	})
}
