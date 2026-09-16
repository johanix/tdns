/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * The config generators (`tdns-cli <role> config mwe`) must write the current
 * childsync:/parentsync: schema.
 */
package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/johanix/tdns/v2"
)

// A generated config is where an operator starts. One written with the retired
// delegationsync: block loads with deprecation warnings, and adding a top-level
// parentsync: or childsync: to it gives a config the daemon refuses, because
// both spellings of one side are set.
func TestMweConfigsUseCurrentDelegationSyncSchema(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "tdns.crt"), filepath.Join(dir, "tdns.key")
	cases := []struct {
		role  string
		body  string
		check func(t *testing.T, cfg *tdns.Config)
	}{
		{
			role: "auth",
			body: renderMweConfig("auth", dir, filepath.Join(dir, "zones"), cert, key, "apikey", "8990", "5354"),
			check: func(t *testing.T, cfg *tdns.Config) {
				if len(cfg.ChildSync.Schemes) == 0 {
					t.Error("childsync.schemes decoded empty")
				}
				if _, ok := cfg.ChildSync.Policies["default"]; !ok {
					t.Error("childsync.policies has no default policy")
				}
			},
		},
		{
			role: "agent",
			body: renderAgentMweConfig("agent", dir, cert, key, "apikey", "8990", "5354"),
			check: func(t *testing.T, cfg *tdns.Config) {
				if len(cfg.ParentSync.Schemes) == 0 {
					t.Error("parentsync.schemes decoded empty")
				}
				if len(cfg.ParentSync.Update.Bootstrap.Methods) == 0 {
					t.Error("parentsync.update.bootstrap.methods decoded empty")
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.role, func(t *testing.T) {
			path := filepath.Join(dir, "tdns-"+tc.role+".yaml")
			if err := os.WriteFile(path, []byte(tc.body), 0644); err != nil {
				t.Fatal(err)
			}
			// The same load and decode `config check` runs on this file.
			v, err := loadConfigViper(path, nil)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if v.IsSet("delegationsync") {
				t.Fatalf("the %s config writes the deprecated delegationsync: block", tc.role)
			}
			var cfg tdns.Config
			if err := v.Unmarshal(&cfg); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			tc.check(t, &cfg)
		})
	}
}
