/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */
package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
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
	v, err := loadConfigViper(main, &ccReport{})
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

	v, err := loadConfigViper(main, &ccReport{})
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

	if _, err := loadConfigViper(main, &ccReport{}); err == nil {
		t.Error("a missing include must fail the load, as it does for the daemon")
	}
}
