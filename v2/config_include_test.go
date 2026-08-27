/*
 * Copyright (c) 2026 Johan Stenstam, johani@johani.org
 */

package tdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
