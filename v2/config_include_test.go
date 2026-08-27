/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	core "github.com/johanix/tdns/v2/core"
)

// writeFiles lays out a config tree and returns the path of the first file.
func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	var main string
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if name == "main.yaml" {
			main = p
		}
	}
	if main == "" {
		t.Fatal("fixture has no main.yaml")
	}
	return main
}

func loadWith(t *testing.T, main string) (map[string]interface{}, *mergeState) {
	t.Helper()
	st := newMergeState()
	cfg, _, err := processConfigFile(main, filepath.Dir(main), 0, st)
	if err != nil {
		t.Fatalf("processConfigFile: %v", err)
	}
	return cfg, st
}

func zoneNames(t *testing.T, cfg map[string]interface{}) []string {
	t.Helper()
	raw, ok := cfg["zones"].([]interface{})
	if !ok {
		return nil
	}
	var out []string
	for _, z := range raw {
		out = append(out, itemName(z))
	}
	return out
}

// TestIncludeBareStringStillReplaces is the compatibility guarantee: every
// config written before opt-in existed keeps its exact behaviour.
func TestIncludeBareStringStillReplaces(t *testing.T) {
	main := writeFiles(t, map[string]string{
		"main.yaml": "include:\n  - inc.yaml\nzones:\n  - name: a.example.\n",
		"inc.yaml":  "zones:\n  - name: b.example.\n",
	})
	cfg, st := loadWith(t, main)

	if got := zoneNames(t, cfg); len(got) != 1 || got[0] != "b.example." {
		t.Fatalf("a bare include must still replace, got %v", got)
	}
	if len(st.Clobbers()) != 1 {
		t.Errorf("the replace must be recorded so it is no longer silent: %+v", st.Clobbers())
	}
}

// TestIncludeOptInMerges is the case that motivated the whole change: a
// generated file contributing zones and dnssec blocks, included rather than
// spliced in by hand.
func TestIncludeOptInMerges(t *testing.T) {
	main := writeFiles(t, map[string]string{
		"main.yaml": `
include:
  - file: generated.yaml
    merge: true
zones:
  - name: existing.example.
dnssec:
  completeness: relaxed
  policies:
    house:
      algorithm: ED25519
  large_algorithms: [ MLDSA87 ]
  split_algorithms:
    MLDSA87: [ ED25519 ]
`,
		"generated.yaml": `
zones:
  - name: gen1.example.
  - name: gen2.example.
dnssec:
  policies:
    generated:
      algorithm: ED25519
  large_algorithms: [ MLDSA87, FALCON512 ]
  split_algorithms:
    MLDSA87: [ FALCON512 ]
    MLDSA44: [ ED25519 ]
`,
	})
	cfg, st := loadWith(t, main)

	if got := zoneNames(t, cfg); len(got) != 3 {
		t.Fatalf("zones should be the union of both files, got %v", got)
	}
	d := cfg["dnssec"].(map[string]interface{})
	if pol := d["policies"].(map[string]interface{}); len(pol) != 2 {
		t.Errorf("policies should merge by name, got %v", sortedStringKeys(pol))
	}
	if d["completeness"] != "relaxed" {
		t.Errorf("a sibling key must survive the nested merge: %v", d["completeness"])
	}
	if la := d["large_algorithms"].([]interface{}); len(la) != 2 {
		t.Errorf("large_algorithms should union to {MLDSA87, FALCON512}, got %v", la)
	}
	split := d["split_algorithms"].(map[string]interface{})
	if m87 := split["MLDSA87"].([]interface{}); len(m87) != 2 {
		t.Errorf("a KSK in both files should end up allowing both ZSKs, got %v", m87)
	}
	if split["MLDSA44"] == nil {
		t.Error("a KSK from only the generated file should survive")
	}
	if len(st.Clobbers()) != 0 || len(st.Collisions()) != 0 {
		t.Errorf("a clean merge should report nothing: %+v %+v", st.Clobbers(), st.Collisions())
	}
}

// The mixed-list footgun: a merge include followed by a bare one. The bare
// include still replaces -- including the merged result -- and that has to be
// reported, or the operator sees a config that silently lost everything.
func TestReplaceAfterMergeWipesTheConcat(t *testing.T) {
	main := writeFiles(t, map[string]string{
		"main.yaml":  "include:\n  - {file: gen.yaml, merge: true}\n  - other.yaml\nzones:\n  - name: a.example.\n",
		"gen.yaml":   "zones:\n  - name: gen.example.\n",
		"other.yaml": "zones:\n  - name: other.example.\n",
	})
	cfg, st := loadWith(t, main)

	got := zoneNames(t, cfg)
	if len(got) != 1 || got[0] != "other.example." {
		t.Fatalf("the trailing bare include replaces everything, got %v", got)
	}
	if len(st.Clobbers()) != 1 || st.Clobbers()[0].Lost != 2 {
		t.Errorf("the clobber must say how much was dropped: %+v", st.Clobbers())
	}
}

func TestIncludeMapFormSpec(t *testing.T) {
	cases := []struct {
		name, include string
		wantErr       string
	}{
		{"merge omitted means replace", "  - {file: inc.yaml}", ""},
		{"merge false means replace", "  - {file: inc.yaml, merge: false}", ""},
		{"unknown key", "  - {file: inc.yaml, mrege: true}", "unknown key"},
		{"missing file", "  - {merge: true}", "no file"},
		{"merge not a bool", "  - {file: inc.yaml, merge: yes-please}", "must be true or false"},
		{"entry is a number", "  - 42", "must be a path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			main := writeFiles(t, map[string]string{
				"main.yaml": "include:\n" + tc.include + "\nzones:\n  - name: a.example.\n",
				"inc.yaml":  "zones:\n  - name: b.example.\n",
			})
			st := newMergeState()
			_, _, err := processConfigFile(main, filepath.Dir(main), 0, st)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// Provenance has to survive nesting: a collision between the main file and a
// LEAF include must name the leaf, not the file in the middle that merged it.
func TestCollisionNamesTheLeafNotTheIntermediate(t *testing.T) {
	main := writeFiles(t, map[string]string{
		"main.yaml": "include:\n  - {file: mid.yaml, merge: true}\nzones:\n  - name: dup.example.\n",
		"mid.yaml":  "include:\n  - {file: leaf.yaml, merge: true}\n",
		"leaf.yaml": "zones:\n  - name: dup.example.\n",
	})
	_, st := loadWith(t, main)

	if len(st.Collisions()) != 1 {
		t.Fatalf("collisions = %+v, want 1", st.Collisions())
	}
	c := st.Collisions()[0]
	if !strings.HasSuffix(c.First, "leaf.yaml") && !strings.HasSuffix(c.Again, "leaf.yaml") {
		t.Errorf("the leaf file must be named, got first=%s again=%s", c.First, c.Again)
	}
	if strings.HasSuffix(c.First, "mid.yaml") || strings.HasSuffix(c.Again, "mid.yaml") {
		t.Errorf("the intermediate file must NOT be blamed, got first=%s again=%s", c.First, c.Again)
	}
}

func TestTypeMismatchAcrossFilesIsFatal(t *testing.T) {
	main := writeFiles(t, map[string]string{
		"main.yaml": "include:\n  - {file: inc.yaml, merge: true}\nzones:\n  - name: a.example.\n",
		"inc.yaml":  "zones:\n  a.example.:\n    type: primary\n",
	})
	st := newMergeState()
	if _, _, err := processConfigFile(main, filepath.Dir(main), 0, st); err == nil {
		t.Error("a list/mapping disagreement across files must be fatal")
	}
}

// TestDuplicateZoneIsQuarantined covers the single-file case that has been
// silently last-wins for as long as the loader has existed: two entries of one
// name, no include: anywhere. Neither is served now, and both the zone list and
// the broken list say so.
func TestDuplicateZoneIsQuarantined(t *testing.T) {
	Zones = core.NewCmap[*ZoneData]()
	conf := &Config{Zones: []ZoneConf{
		{Name: "dup.example.", Type: "primary", Store: "map", Zonefile: "/nonexistent"},
		{Name: "dup.example.", Type: "primary", Store: "map", Zonefile: "/nonexistent"},
		{Name: "fine.example.", Type: "primary", Store: "map", Zonefile: "/nonexistent"},
	}}
	// The healthy zone reaches the refresh enqueue, which needs a channel.
	conf.Internal.RefreshZoneCh = make(chan ZoneRefresher, 10)

	all, broken, err := conf.ParseZones(context.Background(), false)
	if err != nil {
		t.Fatalf("ParseZones: %v", err)
	}

	var brokenDup bool
	for _, z := range broken {
		if z == "dup.example." {
			brokenDup = true
		}
	}
	if !brokenDup {
		t.Errorf("the duplicated zone should be broken, got broken=%v", broken)
	}
	zd, ok := Zones.Get("dup.example.")
	if !ok {
		t.Fatal("the duplicated zone should still be visible in the zone list")
	}
	if zd.Error == false || !strings.Contains(zd.ErrorMsg, "more than once") {
		t.Errorf("the zone should carry a duplicate error, got err=%v msg=%q", zd.Error, zd.ErrorMsg)
	}
	if len(all) == 0 {
		t.Errorf("all_zones should still list something, got %v", all)
	}
}

// The FQDN case: two spellings of one name are one zone to the daemon, so they
// are a duplicate even though the strings differ.
func TestDuplicateZoneComparesFqdn(t *testing.T) {
	Zones = core.NewCmap[*ZoneData]()
	conf := &Config{Zones: []ZoneConf{
		{Name: "dup.example", Type: "primary", Store: "map", Zonefile: "/nonexistent"},
		{Name: "dup.example.", Type: "primary", Store: "map", Zonefile: "/nonexistent"},
	}}
	_, broken, err := conf.ParseZones(context.Background(), false)
	if err != nil {
		t.Fatalf("ParseZones: %v", err)
	}
	if len(broken) == 0 || broken[0] != "dup.example." {
		t.Errorf("dup.example and dup.example. are one zone; broken=%v", broken)
	}
}

// TestGeneratedConfigCanBeIncluded is the case this whole change exists for: a
// generator emits the zones and dnssec blocks its zones need, and the operator
// includes that file instead of splicing its contents into the server config
// by hand. The fixture mirrors what tdns-zonegen writes.
func TestGeneratedConfigCanBeIncluded(t *testing.T) {
	main := writeFiles(t, map[string]string{
		"main.yaml": `
include:
  - file: auth-pq-zones.yaml
    merge: true
dnssec:
  completeness: relaxed
  policies:
    default:
      algorithm: ED25519
      mode: ksk-zsk
zones:
  - name: house.example.
    type: primary
    dnssecpolicy: default
`,
		// As emitted: a policy per algorithm pair, the split_algorithms those
		// pairs require, the derived large_algorithms, one zone per pair.
		"auth-pq-zones.yaml": `
dnssec:
  large_algorithms: [ MLDSA87, FALCON512 ]
  split_algorithms:
    MLDSA87: [ ED25519 ]
  policies:
    mldsa87-ed25519:
      algorithm: ED25519
      mode: ksk-zsk
      ksk:
        algorithm: MLDSA87
    falcon512-falcon512:
      algorithm: FALCON512
      mode: ksk-zsk
zones:
  - name: pq.example.
    type: primary
    dnssecpolicy: ed25519-ed25519
  - name: mldsa87-ed25519.pq.example.
    type: primary
    dnssecpolicy: mldsa87-ed25519
  - name: falcon512-falcon512.pq.example.
    type: primary
    dnssecpolicy: falcon512-falcon512
`,
	})
	cfg, st := loadWith(t, main)

	names := zoneNames(t, cfg)
	if len(names) != 4 {
		t.Fatalf("the server's own zone plus the three generated ones = 4, got %v", names)
	}
	var haveHouse bool
	for _, n := range names {
		if n == "house.example." {
			haveHouse = true
		}
	}
	if !haveHouse {
		t.Error("the server's pre-existing zone must survive being added to")
	}

	d := cfg["dnssec"].(map[string]interface{})
	pol := d["policies"].(map[string]interface{})
	if len(pol) != 3 {
		t.Errorf("the hand-written policy and both generated ones should coexist: %v",
			sortedStringKeys(pol))
	}
	if d["completeness"] != "relaxed" {
		t.Error("a deployment-wide dnssec setting must not be lost to the include")
	}
	if len(st.Collisions()) != 0 || len(st.Clobbers()) != 0 {
		t.Errorf("nothing should be reported for a clean generated include: %+v %+v",
			st.Collisions(), st.Clobbers())
	}
}
