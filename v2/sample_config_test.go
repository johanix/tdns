package tdns

import (
	"os"
	"testing"

	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v3"
)

// TestSampleZonesConfigDecodes guards the shipped auth-zones sample against
// drifting out of sync with the PeerConf struct form. It runs the same
// yaml -> map -> mapstructure(+hook) pipeline ParseConfig uses and asserts no
// bare-string (Legacy) primaries/notify entries survive — a legacy entry would
// quarantine the example zone, making the sample a broken example.
func TestSampleZonesConfigDecodes(t *testing.T) {
	data, err := os.ReadFile("../cmdv2/auth/auth-zones.sample.yaml")
	if err != nil {
		t.Skipf("sample not found (%v)", err)
	}
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("sample is not valid YAML: %v", err)
	}
	var result struct {
		Zones []ZoneConf `yaml:"zones"`
	}
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName:    "yaml",
		Result:     &result,
		DecodeHook: stringToPeerConfHook(),
	})
	if err != nil {
		t.Fatalf("decoder: %v", err)
	}
	if err := decoder.Decode(raw); err != nil {
		t.Fatalf("sample failed to decode: %v", err)
	}
	if len(result.Zones) == 0 {
		t.Fatal("no zones decoded from sample")
	}
	sawPrimaries := false
	for _, z := range result.Zones {
		if len(z.Primaries) > 0 {
			sawPrimaries = true
		}
		for _, p := range z.Primaries {
			if p.Legacy != "" {
				t.Errorf("zone %s: legacy bare-string primary %q (migrate to {addr, key})", z.Name, p.Legacy)
			}
		}
		for _, n := range z.Notify {
			if n.Legacy != "" {
				t.Errorf("zone %s: legacy bare-string notify %q (migrate to {addr, key})", z.Name, n.Legacy)
			}
		}
	}
	if !sawPrimaries {
		t.Error("expected at least one zone with a primaries: list in the sample")
	}
}

// TestSampleTemplatesConfigIsValidYAML is a syntactic guard for the templates
// sample (its template entries are a map, decoded separately at runtime).
func TestSampleTemplatesConfigIsValidYAML(t *testing.T) {
	data, err := os.ReadFile("../cmdv2/auth/auth-templates.sample.yaml")
	if err != nil {
		t.Skipf("sample not found (%v)", err)
	}
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("templates sample is not valid YAML: %v", err)
	}
}
