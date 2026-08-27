/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// writeInclusionFixture lays out a main config that include:s one other file,
// where BOTH define dnssec.policies and zones:.
func writeInclusionFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	main := filepath.Join(dir, "main.yaml")
	if err := os.WriteFile(main, []byte(`
include:
  - inc.yaml
dnssec:
  completeness: relaxed
  policies:
    alpha:
      algorithm: ED25519
zones:
  - name: a.example.
`), 0644); err != nil {
		t.Fatalf("write main: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "inc.yaml"), []byte(`
dnssec:
  policies:
    beta:
      algorithm: ED25519
zones:
  - name: b.example.
`), 0644); err != nil {
		t.Fatalf("write inc: %v", err)
	}
	return main
}

func sortedMapKeys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestConfigCheckMatchesDaemonIncludeMerge is the regression test for a
// divergence that shipped for a long time: `config check` resolved include:
// with viper's MergeInConfig, which DEEP-merges maps, while the daemon's
// processConfigFile replaces a nested map wholesale.
//
// The visible consequence was that a zone referencing a policy defined only in
// the main config passed `config check` and then failed at startup, because
// the daemon never loaded that policy. Measured before the fix:
//
//	dnssec.policies    daemon = [beta]    config check = [alpha beta]
//
// The check is not "policies == [beta]" -- that would pin today's merge
// semantics, which are the subject of a separate change. It is that the two
// loaders agree, whatever they agree on.
func TestConfigCheckMatchesDaemonIncludeMerge(t *testing.T) {
	main := writeInclusionFixture(t)

	raw, _, err := tdns.LoadRawConfigMap(main)
	if err != nil {
		t.Fatalf("LoadRawConfigMap: %v", err)
	}
	v, err := loadConfigViper(main, newCCReport())
	if err != nil {
		t.Fatalf("loadConfigViper: %v", err)
	}

	daemonPolicies := sortedMapKeys(raw["dnssec"].(map[string]interface{})["policies"].(map[string]interface{}))
	checkPolicies := sortedMapKeys(v.Get("dnssec.policies").(map[string]interface{}))
	if !reflect.DeepEqual(daemonPolicies, checkPolicies) {
		t.Errorf("dnssec.policies disagree:\n  daemon       = %v\n  config check = %v",
			daemonPolicies, checkPolicies)
	}

	daemonZones := len(raw["zones"].([]interface{}))
	checkZoneList, _ := v.Get("zones").([]interface{})
	if daemonZones != len(checkZoneList) {
		t.Errorf("zones disagree: daemon n=%d, config check n=%d", daemonZones, len(checkZoneList))
	}

	// Sibling keys of a replaced nested map must survive in both views.
	if got := v.GetString("dnssec.completeness"); got != "relaxed" {
		t.Errorf("dnssec.completeness = %q, want relaxed", got)
	}
}

// TestConfigCheckSeesNestedIncludes is one of the two alignments the fix brings
// with it: viper's loop was single-level, while processConfigFile recurses.
// A config whose include includes something else was previously invisible to
// every check that reads the merged viper view.
func TestConfigCheckSeesNestedIncludes(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "main.yaml")
	os.WriteFile(main, []byte("include:\n  - mid.yaml\nservice:\n  name: TEST\n"), 0644)
	os.WriteFile(filepath.Join(dir, "mid.yaml"), []byte("include:\n  - leaf.yaml\n"), 0644)
	os.WriteFile(filepath.Join(dir, "leaf.yaml"), []byte("db:\n  file: /var/db/from-leaf.db\n"), 0644)

	v, err := loadConfigViper(main, newCCReport())
	if err != nil {
		t.Fatalf("loadConfigViper: %v", err)
	}
	if got := v.GetString("db.file"); got != "/var/db/from-leaf.db" {
		t.Errorf("db.file from a nested include = %q, want /var/db/from-leaf.db", got)
	}
}

// TestConfigCheckMissingIncludeIsAnError is the other alignment. The daemon
// refuses to load a config naming an include that is not there; config check
// used to WARN and carry on, which meant it could pass a config that cannot
// start. ValidateConfig failed on it later anyway, so the WARN was the
// misleading half.
func TestConfigCheckMissingIncludeIsAnError(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "main.yaml")
	os.WriteFile(main, []byte("include:\n  - nope.yaml\nservice:\n  name: TEST\n"), 0644)

	if _, err := loadConfigViper(main, newCCReport()); err == nil {
		t.Error("a missing include must fail the load, as it does for the daemon")
	}
}

// TestCheckDuplicateNames covers the reporting step that has to land before
// anything enforces duplicates, since enforcement turns a silently-last-wins
// zone into one that is not served at all.
//
// It drives BOTH checks that can report a duplicate -- checkZones for zones,
// checkDuplicateTemplates for templates -- and counts only the duplicate
// findings among everything else checkZones emits. Counting across both is the
// point: the two used to overlap, so an exact duplicate produced two FAIL lines
// for one defect while each check separately missed a spelling the other caught.
// wantFails pins one report per defect, not merely "at least one".
func TestCheckDuplicateNames(t *testing.T) {
	cases := []struct {
		name      string
		cfg       tdns.Config
		wantFails int
		wantIn    string
	}{
		{
			name: "no duplicates",
			cfg: tdns.Config{Zones: []tdns.ZoneConf{{Name: "a.example."}, {Name: "b.example."}},
				Templates: []tdns.ZoneConf{{Name: "signing-primary"}}},
		},
		{
			name:      "same zone twice",
			cfg:       tdns.Config{Zones: []tdns.ZoneConf{{Name: "a.example."}, {Name: "a.example."}}},
			wantFails: 1,
			wantIn:    "duplicate zone declaration (entries 1 and 2)",
		},
		{
			// The case comparing raw strings would miss: ParseZones fqdn-ifies
			// first, so these are already one zone to the daemon.
			name:      "trailing dot is not a distinction",
			cfg:       tdns.Config{Zones: []tdns.ZoneConf{{Name: "a.example"}, {Name: "a.example."}}},
			wantFails: 1,
			wantIn:    "duplicate zone declaration",
		},
		{
			// DNS names are case-insensitive (RFC 4343), so these are one zone --
			// but Zones is a case-sensitive Cmap, so the daemon would build two
			// entries and serve whichever one the query's case happened to match.
			name:      "case is not a distinction",
			cfg:       tdns.Config{Zones: []tdns.ZoneConf{{Name: "A.Example."}, {Name: "a.example."}}},
			wantFails: 1,
			wantIn:    "duplicate zone declaration",
		},
		{
			// Both normalizations at once, in one pair.
			name:      "case and trailing dot together",
			cfg:       tdns.Config{Zones: []tdns.ZoneConf{{Name: "A.EXAMPLE"}, {Name: "a.example."}}},
			wantFails: 1,
			wantIn:    "duplicate zone declaration",
		},
		{
			name: "same template twice",
			cfg: tdns.Config{Templates: []tdns.ZoneConf{
				{Name: "signing-primary"}, {Name: "signing-primary"}}},
			wantFails: 1,
			wantIn:    `template "signing-primary" is defined twice`,
		},
		{
			name: "template case is not a distinction",
			cfg: tdns.Config{Templates: []tdns.ZoneConf{
				{Name: "Signing-Primary"}, {Name: "signing-primary"}}},
			wantFails: 1,
			wantIn:    "is defined twice",
		},
		{
			name: "three of the same zone reports each repeat",
			cfg: tdns.Config{Zones: []tdns.ZoneConf{
				{Name: "a.example."}, {Name: "a.example."}, {Name: "a.example."}}},
			wantFails: 2,
		},
	}

	// Indexed, not ranged: tdns.Config embeds a sync.Once, so a range copy is
	// a lock copy and go vet rightly objects.
	for i := range cases {
		tc := &cases[i]
		t.Run(tc.name, func(t *testing.T) {
			rep := newCCReport()
			checkZones(&tc.cfg, rep, false, "server")
			checkDuplicateTemplates(&tc.cfg, rep)

			// checkZones reports plenty besides duplicates on these skeletal
			// zones (no type, no store, no zonefile). Only duplicates are ours.
			var dupFails []string
			for _, results := range rep.byGroup {
				for _, res := range results {
					if res.level == ccFAIL && strings.Contains(res.check+res.msg, "duplicat") {
						dupFails = append(dupFails, res.check+": "+res.msg)
					}
				}
			}
			if len(dupFails) != tc.wantFails {
				t.Errorf("duplicate fails = %d, want %d: %v", len(dupFails), tc.wantFails, dupFails)
			}
			if tc.wantIn != "" {
				var found bool
				for _, f := range dupFails {
					if strings.Contains(f, tc.wantIn) {
						found = true
					}
				}
				if !found {
					t.Errorf("no duplicate finding contained %q: %v", tc.wantIn, dupFails)
				}
			}
		})
	}
}
