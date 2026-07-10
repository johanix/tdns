package tdns

import (
	"os"
	"strings"
	"testing"

	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v3"
)

// The shipped sample configs are the config reference the guide points at, so
// they must decode exactly the way ParseConfig decodes a real config file.
// These tests run that same yaml -> map -> mapstructure(+hooks) pipeline.
//
// They exist because every one of the following shipped in a "working" sample
// at some point, and none was caught by a YAML-syntax check:
//   - templates: written as a map (Config.Templates is []ZoneConf) -> whole
//     config load fails with "source data must be an array or slice, got map"
//   - dnssec_policy: / multi_signer: instead of dnssecpolicy: / multisigner:
//     -> silently dropped, so online-signing then fails validation
//   - bare-string notify:/downstreams: entries -> zone quarantined to ERROR
//   - an options: value that no longer parses -> zone quarantined to ERROR

// decodeSample runs the shipped decode pipeline over one sample file and
// returns the mapstructure metadata so a caller can assert on dropped keys.
func decodeSample(t *testing.T, path string, result interface{}) mapstructure.Metadata {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("checked-in sample not found (%v)", err)
	}
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("%s is not valid YAML: %v", path, err)
	}
	var md mapstructure.Metadata
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName:  "yaml",
		Result:   result,
		Metadata: &md,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			stringToPeerConfHook(),
			stringToAclEntryHook(),
		),
	})
	if err != nil {
		t.Fatalf("decoder: %v", err)
	}
	if err := decoder.Decode(raw); err != nil {
		t.Fatalf("%s failed to decode: %v", path, err)
	}
	return md
}

// internalOnlyZoneOptions are valid ZoneOption values that are set
// programmatically and REJECTED when they appear in a config file: they have no
// case in the parseZoneOptions switch, so they fall to its default arm and put
// the zone in ERROR state. Keep in sync with v2/parseoptions.go.
var internalOnlyZoneOptions = map[string]bool{
	"dirty":            true,
	"frozen":           true,
	"automatic-zone":   true,
	"api-managed-zone": true,
	"multi-signer":     true,
	"dont-publish-jwk": true,
}

// checkZoneConf asserts one decoded zone/template entry is loadable: no legacy
// bare-string peers or ACL entries, every ACL prefix parses, and every option is
// one a config file may actually set.
func checkZoneConf(t *testing.T, what string, z ZoneConf) {
	t.Helper()
	for _, p := range z.Primaries {
		if p.Legacy != "" {
			t.Errorf("%s %s: legacy bare-string primary %q (migrate to {addr, key})", what, z.Name, p.Legacy)
		}
	}
	for _, n := range z.Notify {
		if n.Legacy != "" {
			t.Errorf("%s %s: legacy bare-string notify %q (migrate to {addr, key})", what, z.Name, n.Legacy)
		}
	}
	for _, acl := range [][]AclEntry{z.Downstreams, z.AllowNotify} {
		for _, e := range acl {
			if e.Legacy != "" {
				t.Errorf("%s %s: legacy bare-string ACL entry %q (migrate to {prefix, key})", what, z.Name, e.Legacy)
			}
			if e.Legacy == "" && e.Prefix == "" {
				t.Errorf("%s %s: ACL entry with empty prefix (did you write `addr:` instead of `prefix:`?)", what, z.Name)
			}
			if e.Prefix != "" {
				if err := ValidateIPSpec(e.Prefix); err != nil {
					t.Errorf("%s %s: bad ACL prefix %q: %v", what, z.Name, e.Prefix, err)
				}
			}
			if e.Key == "" {
				t.Errorf("%s %s: ACL entry %q has no key (use a TSIG key name, NOKEY, or BLOCKED)", what, z.Name, e.Prefix)
			}
		}
	}
	for _, o := range z.OptionsStrs {
		opt := strings.ToLower(strings.TrimSpace(o))
		if _, ok := StringToZoneOption[opt]; !ok {
			t.Errorf("%s %s: unknown zone option %q", what, z.Name, o)
			continue
		}
		if internalOnlyZoneOptions[opt] {
			t.Errorf("%s %s: option %q is set programmatically and is rejected from config", what, z.Name, o)
		}
	}
	// A signing option without a policy is dropped and the zone goes to ERROR.
	// Templates are exempt: a template may supply the option and let the zone
	// supply the policy (or vice versa).
	if what == "zone" {
		signing := false
		for _, o := range z.OptionsStrs {
			switch strings.ToLower(strings.TrimSpace(o)) {
			case "online-signing", "inline-signing":
				signing = true
			}
		}
		if signing && z.DnssecPolicy == "" && z.Template == "" {
			t.Errorf("zone %s: has a signing option but no dnssecpolicy: and no template:", z.Name)
		}
	}
}

func TestSampleZonesConfigDecodes(t *testing.T) {
	var result struct {
		Zones []ZoneConf `yaml:"zones"`
	}
	md := decodeSample(t, "../cmdv2/auth/auth-zones.sample.yaml", &result)

	if len(result.Zones) == 0 {
		t.Fatal("no zones decoded from sample")
	}
	if len(md.Unused) > 0 {
		t.Errorf("sample has config keys the loader silently drops: %v", md.Unused)
	}
	sawPrimaries, sawDownstreams, sawTsigAcl := false, false, false
	for _, z := range result.Zones {
		checkZoneConf(t, "zone", z)
		if len(z.Primaries) > 0 {
			sawPrimaries = true
		}
		for _, e := range z.Downstreams {
			sawDownstreams = true
			if e.Key != NOKEY && e.Key != BLOCKED {
				sawTsigAcl = true
			}
		}
	}
	if !sawPrimaries {
		t.Error("expected at least one zone with a primaries: list in the sample")
	}
	if !sawDownstreams {
		t.Error("expected at least one zone with a downstreams: ACL in the sample")
	}
	if !sawTsigAcl {
		t.Error("expected at least one downstreams: entry naming a real TSIG key in the sample")
	}
}

// TestSampleTemplatesConfigDecodes guards the templates sample against the
// shape it shipped with for a long time: a map keyed by template name, which
// cannot decode into Config.Templates ([]ZoneConf).
func TestSampleTemplatesConfigDecodes(t *testing.T) {
	var result struct {
		Templates []ZoneConf `yaml:"templates"`
	}
	md := decodeSample(t, "../cmdv2/auth/auth-templates.sample.yaml", &result)

	if len(result.Templates) == 0 {
		t.Fatal("no templates decoded from sample (is templates: a list of {name: ...} entries?)")
	}
	if len(md.Unused) > 0 {
		t.Errorf("templates sample has config keys the loader silently drops: %v", md.Unused)
	}
	seen := map[string]bool{}
	for _, tmpl := range result.Templates {
		if tmpl.Name == "" {
			t.Error("template with no name: (buildTemplateMap requires one)")
			continue
		}
		if seen[tmpl.Name] {
			t.Errorf("duplicate template name %q", tmpl.Name)
		}
		seen[tmpl.Name] = true
		checkZoneConf(t, "template", tmpl)
	}
}

// TestSampleZonesReferenceDefinedTemplates ties the two samples together: every
// template: named by a sample zone must exist in the templates sample, or the
// zone is quarantined with "template %q does not exist".
func TestSampleZonesReferenceDefinedTemplates(t *testing.T) {
	var zres struct {
		Zones []ZoneConf `yaml:"zones"`
	}
	decodeSample(t, "../cmdv2/auth/auth-zones.sample.yaml", &zres)
	var tres struct {
		Templates []ZoneConf `yaml:"templates"`
	}
	decodeSample(t, "../cmdv2/auth/auth-templates.sample.yaml", &tres)

	defined := map[string]bool{}
	for _, tmpl := range tres.Templates {
		defined[tmpl.Name] = true
	}
	for _, z := range zres.Zones {
		if z.Template != "" && !defined[z.Template] {
			t.Errorf("zone %s references undefined template %q", z.Name, z.Template)
		}
	}
}
