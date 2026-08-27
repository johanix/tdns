package tdns

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// walkConfigFields visits every struct field reachable from t, reporting each
// as "Path.Field" with its yaml and mapstructure tags.
func walkConfigFields(t reflect.Type, path string, seen map[reflect.Type]bool, visit func(where string, f reflect.StructField)) {
	for t.Kind() == reflect.Ptr || t.Kind() == reflect.Slice || t.Kind() == reflect.Array || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || seen[t] {
		return
	}
	seen[t] = true
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		visit(path+"."+t.Name()+"."+f.Name, f)
		walkConfigFields(f.Type, path+"."+t.Name(), seen, visit)
	}
}

func tagName(f reflect.StructField, key string) (string, bool) {
	v, ok := f.Tag.Lookup(key)
	if !ok {
		return "", false
	}
	return strings.Split(v, ",")[0], true
}

// A config key is only reachable if mapstructure can map it: the daemons load
// Config with viper.Unmarshal, which reads mapstructure and ignores yaml.
// mapstructure falls back to the field name, so a yaml key that differs from
// the lowercased field name and carries no mapstructure tag is silently
// dropped -- no error, no warning, the zero value.
//
// That is exactly how imrengine.trust-anchor-ds, trust-anchor-dnskey and
// trust-anchor-file parsed to "" no matter what the config said, leaving the
// resolver validating against an empty anchor set. This test exists so that
// class of bug cannot come back by way of a new field.
func TestConfigYamlKeysAreMappableByViper(t *testing.T) {
	var problems []string
	walkConfigFields(reflect.TypeOf(Config{}), "", map[reflect.Type]bool{}, func(where string, f reflect.StructField) {
		y, hasYaml := tagName(f, "yaml")
		if !hasYaml || y == "" || y == "-" {
			return
		}
		ms, hasMS := tagName(f, "mapstructure")
		switch {
		case hasMS && ms == "-":
			return
		case !hasMS && !strings.EqualFold(y, f.Name):
			problems = append(problems, fmt.Sprintf(
				"%s: yaml:%q differs from the field name and has no mapstructure tag — viper will silently ignore it", where, y))
		case hasMS && !strings.EqualFold(ms, y):
			problems = append(problems, fmt.Sprintf(
				"%s: yaml:%q and mapstructure:%q disagree — the key means different things to yaml.Unmarshal and viper", where, y, ms))
		}
	})
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// Config keys are spelled with hyphens, never underscores (2026-08-27 rename).
// Keys that predate the rename are recognised via snakeCaseConfigKeys so an
// old config gets migration advice rather than a silent drop.
func TestConfigYamlKeysUseHyphensNotUnderscores(t *testing.T) {
	var problems []string
	walkConfigFields(reflect.TypeOf(Config{}), "", map[reflect.Type]bool{}, func(where string, f reflect.StructField) {
		for _, key := range []string{"yaml", "mapstructure"} {
			if n, ok := tagName(f, key); ok && strings.Contains(n, "_") {
				problems = append(problems, fmt.Sprintf("%s: %s:%q uses underscores; config keys use hyphens", where, key, n))
			}
		}
	})
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// Every renamed key must carry migration advice, or an operator's existing
// config breaks in silence.
func TestSnakeCaseKeysHaveMigrationAdvice(t *testing.T) {
	for _, old := range snakeCaseConfigKeys {
		dep, unknown := classifyUnusedConfigKeys([]string{"someblock." + old})
		if len(dep) != 1 || len(unknown) != 0 {
			t.Errorf("%q: got %d deprecated / %d unknown, want migration advice", old, len(dep), len(unknown))
			continue
		}
		if want := strings.ReplaceAll(old, "_", "-"); !strings.Contains(dep[0].advice, want) {
			t.Errorf("%q: advice does not name the new spelling %q: %s", old, want, dep[0].advice)
		}
	}
}

// loadDnssecPoliciesYAML is a plain yaml.Unmarshal, so it never reaches the
// deprecatedConfigKeys registry that covers the daemon's viper load. Without
// its own check, a policy file still using split_algorithms would have its
// allowlist silently dropped and a valid mixed-algorithm pair reported broken.
func TestLoadDnssecPoliciesYAMLReportsOldSpellings(t *testing.T) {
	write := func(body string) string {
		p := filepath.Join(t.TempDir(), "policies.yaml")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	const current = `
dnssec:
   split-algorithms:
      mixed: [ ED25519, RSASHA256 ]
   policies:
      p1:
         algorithm: ED25519
         ttls:
            max-served: 8h
`
	if _, err := loadDnssecPoliciesYAML(write(current)); err != nil {
		t.Errorf("current spelling should load, got: %v", err)
	}

	for _, tc := range []struct{ name, body, want string }{
		{"split_algorithms", `
dnssec:
   split_algorithms:
      mixed: [ ED25519, RSASHA256 ]
   policies:
      p1:
         algorithm: ED25519
`, "split-algorithms"},
		{"ttls.max_served", `
dnssec:
   policies:
      p1:
         algorithm: ED25519
         ttls:
            max_served: 8h
`, "max-served"},
	} {
		_, err := loadDnssecPoliciesYAML(write(tc.body))
		if err == nil {
			t.Errorf("%s: expected an error naming the new spelling, got none", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error does not name %q: %v", tc.name, tc.want, err)
			continue
		}
		t.Logf("%-18s -> %v", tc.name, err)
	}
}
