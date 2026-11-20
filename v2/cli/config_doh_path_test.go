/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"strings"
	"testing"

	"github.com/johanix/tdns/v2"
)

// `config check` reports the path DoH will answer on, for both the auth/agent
// listeners check and the imr one, and warns about a doh-path that nothing
// will serve.
func TestConfigCheckDoHPath(t *testing.T) {
	checks := map[string]func(*tdns.Config, *ccReport){
		"Listeners":  checkListeners,
		"IMR engine": checkImrEngine,
	}
	for group, check := range checks {
		t.Run(group, func(t *testing.T) {
			for _, tc := range []struct {
				name       string
				transports []string
				path       string
				want       ccLevel
				wantInMsg  string
			}{
				{"doh, default path", []string{"do53", "doh"}, "", ccPASS, tdns.DefaultDoHPath},
				{"doh, configured path", []string{"DoH"}, "/resolve/v1", ccPASS, "/resolve/v1"},
				{"path without doh", []string{"do53", "dot"}, "/resolve/v1", ccWARN, "not in listeners.transports"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					cfg := &tdns.Config{}
					cfg.Listeners.Addresses = []string{"127.0.0.1:53"}
					cfg.Listeners.Transports = tc.transports
					cfg.Listeners.DoHPath = tc.path
					rep := newCCReport()
					check(cfg, rep)
					if !hasLevel(rep, group, "doh-path", tc.want) {
						t.Fatalf("want %s for doh-path, got %+v", tc.want.label(), rep.byGroup[group])
					}
					for _, r := range rep.byGroup[group] {
						if r.check == "doh-path" && !strings.Contains(r.msg, tc.wantInMsg) {
							t.Errorf("doh-path message %q does not mention %q", r.msg, tc.wantInMsg)
						}
					}
				})
			}

			// No doh and no path: nothing to say.
			cfg := &tdns.Config{}
			cfg.Listeners.Addresses = []string{"127.0.0.1:53"}
			cfg.Listeners.Transports = []string{"do53"}
			rep := newCCReport()
			check(cfg, rep)
			if got := levelsFor(rep, group, "doh-path"); len(got) != 0 {
				t.Errorf("do53 only, no doh-path: want no doh-path finding, got %v", got)
			}
		})
	}
}

// A running server that predates doh-path reports none and serves the
// default, so it matches a config without the key and differs from one with
// another path.
func TestCorrelateStatusDoHPath(t *testing.T) {
	for _, tc := range []struct {
		name          string
		cfg, running  string
		wantDifferent bool
	}{
		{"both unset", "", "", false},
		{"explicit default vs unset", tdns.DefaultDoHPath, "", false},
		{"same custom", "/resolve/v1", "/resolve/v1", false},
		{"config changed, not restarted", "/resolve/v1", "", true},
		{"config reverted, not restarted", "", "/resolve/v1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tdns.Config{}
			cfg.Listeners.DoHPath = tc.cfg
			var resp tdns.ConfigResponse
			resp.Listeners.DoHPath = tc.running
			rep := newCCReport()
			correlateStatus(cfg, resp, "", rep, "Running server")
			if got := hasLevel(rep, "Running server", "listeners-doh-path", ccWARN); got != tc.wantDifferent {
				t.Fatalf("warned = %v, want %v; report %+v", got, tc.wantDifferent, rep.byGroup["Running server"])
			}
		})
	}
}

// `config check` warns when a test-harness switch is set.
func TestConfigCheckImrTestingPriming(t *testing.T) {
	on, off := true, false
	for _, tc := range []struct {
		name    string
		priming *bool
		warn    bool
	}{{"unset", nil, false}, {"true", &on, false}, {"false", &off, true}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tdns.Config{}
			cfg.Listeners.Addresses = []string{"127.0.0.1:53"}
			cfg.Listeners.Transports = []string{"do53"}
			cfg.Imr.Testing.Priming = tc.priming
			rep := newCCReport()
			checkImrEngine(cfg, rep)
			warned := false
			for _, r := range rep.byGroup["IMR engine"] {
				if r.check == "testing" && r.level == ccWARN {
					warned = true
				}
			}
			if warned != tc.warn {
				t.Errorf("priming=%v: warned=%v, want %v", tc.priming, warned, tc.warn)
			}
		})
	}
}

// An online config check reports debug-do53-queries-refused when the file and
// the running server differ: the option takes effect only at a restart.
func TestConfigCheckDo53QueriesRefusedDrift(t *testing.T) {
	for _, tc := range []struct {
		name          string
		cfg           bool
		running, warn bool
	}{
		{"both off", false, false, false},
		{"both on", true, true, false},
		{"turned on, not restarted", true, false, true},
		{"turned off, not restarted", false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tdns.Config{}
			if tc.cfg {
				cfg.AuthEngine.OptionsStrs = []string{"debug-do53-queries-refused"}
			}
			resp := tdns.ConfigResponse{Do53QueriesRefused: tc.running}
			rep := newCCReport()
			correlateStatus(cfg, resp, "", rep, "Running server")
			if got := hasLevel(rep, "Running server", "debug-do53-queries-refused", ccWARN); got != tc.warn {
				t.Fatalf("warned = %v, want %v; report %+v", got, tc.warn, rep.byGroup["Running server"])
			}
		})
	}
}

// tdns-agent refuses debug-do53-queries-refused whatever its value, "false"
// included, so config check fails it for an agent whenever the key is
// present. tdns-auth takes "false" and says nothing.
func TestConfigCheckDo53QueriesRefusedOnAgent(t *testing.T) {
	for _, tc := range []struct {
		name  string
		opts  []string
		agent bool
		fail  bool
	}{
		{"agent, absent", nil, true, false},
		{"agent, on", []string{"debug-do53-queries-refused"}, true, true},
		{"agent, false", []string{"debug-do53-queries-refused:false"}, true, true},
		{"auth, false", []string{"debug-do53-queries-refused:false"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tdns.Config{}
			cfg.AuthEngine.OptionsStrs = tc.opts
			rep := newCCReport()
			checkDo53QueriesRefused(cfg, rep, tc.agent)
			if got := hasLevel(rep, "Listeners", "debug-do53-queries-refused", ccFAIL); got != tc.fail {
				t.Fatalf("failed = %v, want %v; report %+v", got, tc.fail, rep.byGroup["Listeners"])
			}
		})
	}
}
