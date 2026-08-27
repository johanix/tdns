/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
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
		// wantZones is what zones: must hold afterwards, for the cases that
		// succeed. Asserting only err == nil would pass just as happily if the
		// map form silently MERGED by default, which is the one thing the
		// spec says it must not do.
		wantZones []string
	}{
		{"merge omitted means replace", "  - {file: inc.yaml}", "", []string{"b.example."}},
		{"merge false means replace", "  - {file: inc.yaml, merge: false}", "", []string{"b.example."}},
		{"merge true unions", "  - {file: inc.yaml, merge: true}", "", []string{"a.example.", "b.example."}},
		{"unknown key", "  - {file: inc.yaml, mrege: true}", "unknown key", nil},
		{"missing file", "  - {merge: true}", "no file", nil},
		{"merge not a bool", "  - {file: inc.yaml, merge: yes-please}", "must be true or false", nil},
		{"entry is a number", "  - 42", "must be a path", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			main := writeFiles(t, map[string]string{
				"main.yaml": "include:\n" + tc.include + "\nzones:\n  - name: a.example.\n",
				"inc.yaml":  "zones:\n  - name: b.example.\n",
			})
			st := newMergeState()
			cfg, _, err := processConfigFile(main, filepath.Dir(main), 0, st)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				var got []string
				for _, z := range cfg["zones"].([]interface{}) {
					got = append(got, z.(map[string]interface{})["name"].(string))
				}
				sort.Strings(got)
				if strings.Join(got, ",") != strings.Join(tc.wantZones, ",") {
					t.Errorf("zones = %v, want %v", got, tc.wantZones)
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

// The case half: DNS names are case-insensitive (RFC 4343), so these are one
// zone written twice. Zones is a case-SENSITIVE Cmap, so without folding the
// comparison the loader would build two entries and answer from whichever one
// the query's case happened to match -- the same silent last-wins this change
// exists to end, just spelled differently. Both entries must be quarantined.
func TestDuplicateZoneComparesCaseInsensitively(t *testing.T) {
	Zones = core.NewCmap[*ZoneData]()
	conf := &Config{Zones: []ZoneConf{
		{Name: "Dup.Example.", Type: "primary", Store: "map", Zonefile: "/nonexistent"},
		{Name: "dup.example.", Type: "primary", Store: "map", Zonefile: "/nonexistent"},
	}}
	_, broken, err := conf.ParseZones(context.Background(), false)
	if err != nil {
		t.Fatalf("ParseZones: %v", err)
	}
	want := map[string]bool{"Dup.Example.": false, "dup.example.": false}
	for _, z := range broken {
		if _, ok := want[z]; ok {
			want[z] = true
		}
	}
	for z, got := range want {
		if !got {
			t.Errorf("%s differs from its twin only in case; it must be quarantined too. broken=%v", z, broken)
		}
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

// TestProvenanceWhenTheMainFileLacksTheKey covers the hole the nested-collision
// test above cannot reach.
//
// That test puts zones: on main, so the merge takes the "destination already
// has this key" path. When main does NOT carry the key -- the common shape of a
// config that delegates a whole section to an include -- the assign path runs
// instead, and it used to stamp the file doing the merging rather than the file
// the item was read from. The result was a collision report blaming the
// intermediate file, which contains nothing.
func TestProvenanceWhenTheMainFileLacksTheKey(t *testing.T) {
	main := writeFiles(t, map[string]string{
		"main.yaml": "include:\n  - {file: mid.yaml, merge: true}\nservice:\n  name: T\n",
		"mid.yaml":  "include:\n  - {file: leaf.yaml, merge: true}\n",
		"leaf.yaml": "zones:\n  - name: a.example.\n",
	})
	st := newMergeState()
	if _, _, err := processConfigFile(main, filepath.Dir(main), 0, st); err != nil {
		t.Fatalf("load: %v", err)
	}
	got, ok := st.OriginOf("zones", "a.example.")
	if !ok {
		t.Fatal("no origin recorded for the zone at all")
	}
	if filepath.Base(got) != "leaf.yaml" {
		t.Errorf("origin = %s, want leaf.yaml -- the intermediate file defines no zones",
			filepath.Base(got))
	}
}

// TestAllowlistSpellingMatchesTheConfigStruct is a tripwire for a rename that
// would otherwise break this feature in total silence.
//
// The allowlist is a set of YAML key PATHS. tdns#406 respells every config key
// with hyphens -- dnssec.large_algorithms becomes dnssec.large-algorithms --
// and keeps no alias. Nothing in the merge would complain: an allowlist entry
// naming a path that no longer exists simply never matches, so an opted-in
// include quietly goes back to replacing, which is the exact behaviour this
// whole change exists to fix. Green tests written against the old spelling
// would stay green.
//
// So: every allowlisted path must resolve to a real yaml key on Config. When
// #406 lands, this goes red until the allowlist is updated to match.
func TestAllowlistSpellingMatchesTheConfigStruct(t *testing.T) {
	for path := range mergeAllowlist {
		if !yamlPathExists(reflect.TypeOf(Config{}), strings.Split(path, ".")) {
			t.Errorf("allowlist path %q does not exist as a yaml key on Config; "+
				"if a config key was renamed, the allowlist must be renamed with it "+
				"or opted-in merging silently reverts to replace", path)
		}
	}
}

// yamlPathExists walks a dotted yaml path through a struct's yaml tags.
func yamlPathExists(t reflect.Type, parts []string) bool {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if len(parts) == 0 {
		return true
	}
	if t.Kind() != reflect.Struct {
		// A map-valued node (dnssec.policies) has no further struct to walk;
		// reaching it means the path exists.
		return t.Kind() == reflect.Map
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if tag == "" {
			tag = strings.ToLower(f.Name)
		}
		if tag != parts[0] {
			continue
		}
		ft := f.Type
		for ft.Kind() == reflect.Ptr {
			ft = ft.Elem()
		}
		if len(parts) == 1 {
			return true
		}
		return yamlPathExists(ft, parts[1:])
	}
	return false
}

// TestCollisionComparesZoneNamesLikeTheDaemon closes the gap between what the
// merge calls a collision and what ParseZones calls a duplicate.
//
// The merge compared the raw YAML strings, so "example.com" in one file and
// "example.com." in another looked like two different zones and no collision
// was reported. The pre-pass then compared them with zoneNameKey, saw one zone
// declared twice, and quarantined it. The operator was told the zone is broken
// and never told which two files it came from -- the one piece of information
// the merge is uniquely able to supply, since after merging nothing remembers.
func TestCollisionComparesZoneNamesLikeTheDaemon(t *testing.T) {
	for _, tc := range []struct{ name, mainZone, incZone string }{
		{"trailing dot", "example.com", "example.com."},
		{"case", "Example.com.", "example.com."},
		{"both", "EXAMPLE.COM", "example.com."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			main := writeFiles(t, map[string]string{
				"main.yaml": "include:\n  - {file: inc.yaml, merge: true}\nzones:\n  - name: " + tc.mainZone + "\n",
				"inc.yaml":  "zones:\n  - name: " + tc.incZone + "\n",
			})
			st := newMergeState()
			if _, _, err := processConfigFile(main, filepath.Dir(main), 0, st); err != nil {
				t.Fatalf("load: %v", err)
			}
			cols := st.Collisions()
			if len(cols) != 1 {
				t.Fatalf("%q and %q are one zone to the daemon; want 1 collision, got %d",
					tc.mainZone, tc.incZone, len(cols))
			}
			// And it must name both files, which is the useful half.
			if filepath.Base(cols[0].First) != "main.yaml" || filepath.Base(cols[0].Again) != "inc.yaml" {
				t.Errorf("collision should name both files, got %s and %s",
					filepath.Base(cols[0].First), filepath.Base(cols[0].Again))
			}
		})
	}
}
