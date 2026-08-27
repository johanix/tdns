package tdns

import (
	"fmt"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
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

// Config is decoded by two different tag conventions, and a key is only fully
// reachable if BOTH see it:
//
//   - the daemon's decodeConfigMap sets mapstructure's TagName to "yaml";
//   - viper.Unmarshal -- config check and the CLI roots -- uses mapstructure
//     tags, falling back to the field name when there is none.
//
// So a yaml key that differs from its lowercased field name and carries no
// mapstructure tag is read by the daemon and silently missed by everything on
// the viper path. That is what the three imrengine trust-anchor keys did: the
// running resolver had its anchor, while checkImrTrustAnchors read "" and
// reported "no trust anchor configured". This test exists so that class of
// divergence cannot come back by way of a new field.
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

	// A walk that stops reaching fields -- a renamed type, a recursion guard
	// that fires too early -- would make every check above pass vacuously.
	n := 0
	walkConfigFields(reflect.TypeOf(Config{}), "", map[reflect.Type]bool{}, func(string, reflect.StructField) { n++ })
	if n < 400 {
		t.Errorf("walk reached only %d fields; it should cover the whole Config tree (~540)", n)
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

// The two decoders must agree. Running both over the same document is the only
// check that cannot drift from reality: the tag rules above are a proxy for
// this, and a proxy can be wrong.
func TestBothDecodersSeeTheSameTrustAnchors(t *testing.T) {
	const doc = `
imrengine:
   trust-anchor-ds: ". IN DS 56910 15 2 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
   trust-anchor-dnskey: ". IN DNSKEY 257 3 15 dem0H2M22a8CDAe0PDZoGBBCBB2fHJ1fe39FkhNToAA="
   trust-anchor-file: /some/root.key
`
	var raw map[string]any
	if err := yaml.Unmarshal([]byte(doc), &raw); err != nil {
		t.Fatalf("yaml: %v", err)
	}

	// Daemon path: decodeConfigMap, TagName "yaml".
	var viaDaemon Config
	if err := decodeConfigMap(raw, &viaDaemon, nil); err != nil {
		t.Fatalf("decodeConfigMap: %v", err)
	}

	// config check / CLI path: viper, mapstructure tags.
	f := filepath.Join(t.TempDir(), "imr.yaml")
	if err := os.WriteFile(f, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	v := viper.New()
	v.SetConfigFile(f)
	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("ReadInConfig: %v", err)
	}
	var viaViper Config
	if err := v.Unmarshal(&viaViper); err != nil {
		t.Fatalf("viper.Unmarshal: %v", err)
	}

	for _, tc := range []struct{ name, daemon, viper string }{
		{"trust-anchor-ds", viaDaemon.Imr.TrustAnchorDS, viaViper.Imr.TrustAnchorDS},
		{"trust-anchor-dnskey", viaDaemon.Imr.TrustAnchorDNSKEY, viaViper.Imr.TrustAnchorDNSKEY},
		{"trust-anchor-file", viaDaemon.Imr.TrustAnchorFile, viaViper.Imr.TrustAnchorFile},
	} {
		switch {
		case tc.daemon == "":
			t.Errorf("%s: daemon decoder (TagName yaml) read nothing", tc.name)
		case tc.viper == "":
			t.Errorf("%s: viper decoder (mapstructure) read nothing — config check would report no anchor", tc.name)
		case tc.daemon != tc.viper:
			t.Errorf("%s: decoders disagree: daemon %q vs viper %q", tc.name, tc.daemon, tc.viper)
		}
	}
}
