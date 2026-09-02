/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// writeInclCfg writes main.yaml plus any named extra files, and returns the
// path to main.yaml.
func writeInclCfg(t *testing.T, main string, extra map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range extra {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "main.yaml")
	if err := os.WriteFile(path, []byte(main), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func readWithIncludes(t *testing.T, cfg string) (*viper.Viper, error) {
	t.Helper()
	v := viper.New()
	v.SetConfigFile(cfg)
	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("ReadInConfig: %v", err)
	}
	return v, MergeViperIncludes(v, cfg)
}

// TestMergeViperIncludesBothForms is #452: the map form has to work, because
// it is the only way to ask for merging and therefore the only form a
// deployment whose zones come from two files can use. Reading it with
// GetStringSlice yielded an empty path per entry, which resolved to the
// config's own DIRECTORY and produced "Unsupported Config Type" naming a
// directory nobody wrote in the config.
func TestMergeViperIncludesBothForms(t *testing.T) {
	for _, tc := range []struct {
		name    string
		include string
	}{
		{"bare string", "include:\n   - extra.yaml\n"},
		{"map form", "include:\n   - file: extra.yaml\n     merge: true\n"},
		{"map form without merge", "include:\n   - file: extra.yaml\n"},
		{"both forms mixed", "include:\n   - other.yaml\n   - file: extra.yaml\n     merge: true\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := writeInclCfg(t, tc.include+"cli:\n   local: yes\n", map[string]string{
				"extra.yaml": "apiserver:\n   apikey: from-extra\n",
				"other.yaml": "cli:\n   other: yes\n",
			})
			v, err := readWithIncludes(t, cfg)
			if err != nil {
				t.Fatalf("MergeViperIncludes: %v", err)
			}
			if got := v.GetString("apiserver.apikey"); got != "from-extra" {
				t.Errorf("apiserver.apikey = %q, want the included value", got)
			}
			if got := v.GetString("cli.local"); got != "yes" {
				t.Errorf("including dropped the main config: cli.local = %q", got)
			}
		})
	}
}

// TestMergeViperIncludesRestoresConfigFile: merging moves viper's idea of the
// config file to the last include, which would send a later ReadInConfig at
// the wrong file.
func TestMergeViperIncludesRestoresConfigFile(t *testing.T) {
	cfg := writeInclCfg(t, "include:\n   - file: extra.yaml\n", map[string]string{
		"extra.yaml": "apiserver:\n   apikey: from-extra\n",
	})
	v, err := readWithIncludes(t, cfg)
	if err != nil {
		t.Fatalf("MergeViperIncludes: %v", err)
	}
	if got := v.ConfigFileUsed(); got != cfg {
		t.Errorf("ConfigFileUsed() = %q, want the main config %q", got, cfg)
	}
}

// TestMergeViperIncludesErrors: what is left must fail with a message naming
// the actual problem, not a directory.
func TestMergeViperIncludesErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		include string
		want    string
	}{
		{"entry with no file", "include:\n   - merge: true\n", "no file"},
		{"unknown key", "include:\n   - file: extra.yaml\n     mrge: true\n", "unknown key"},
		{"non-bool merge", "include:\n   - file: extra.yaml\n     merge: sometimes\n", "merge must be"},
		{"wrong type", "include:\n   - 17\n", "must be a path or {file, merge}"},
		{"not a list", "include: extra.yaml\n", "must be a list"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := writeInclCfg(t, tc.include, map[string]string{
				"extra.yaml": "apiserver:\n   apikey: from-extra\n",
			})
			_, err := readWithIncludes(t, cfg)
			if err == nil {
				t.Fatalf("accepted a broken include")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "Unsupported Config Type") {
				t.Errorf("still reporting viper's directory error: %v", err)
			}
		})
	}
}

// TestMergeViperIncludesMissingIsSkipped: an optional overlay that is not
// installed yet must not be fatal — the behaviour all three copies had.
func TestMergeViperIncludesMissingIsSkipped(t *testing.T) {
	cfg := writeInclCfg(t, "include:\n   - file: absent.yaml\n     merge: true\ncli:\n   local: yes\n", nil)
	v, err := readWithIncludes(t, cfg)
	if err != nil {
		t.Fatalf("a missing include was fatal: %v", err)
	}
	if got := v.GetString("cli.local"); got != "yes" {
		t.Errorf("cli.local = %q, want the main config to survive", got)
	}
}
