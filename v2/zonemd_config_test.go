package tdns

import (
	"fmt"
	"strings"
	"testing"

	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v3"
)

// The `zonemd:` block is the operator-facing half of the feature, and it
// reaches ZoneConf through two decoders in sequence: YAML into a generic map,
// then mapstructure into the struct with TagName "yaml". A field that decodes
// under one and not the other looks fine in review and silently ignores the
// operator's configuration -- so exercise the actual pair.
func decodeZonesYAML(t *testing.T, doc string) []ZoneConf {
	t.Helper()
	var raw map[string]interface{}
	if err := yaml.Unmarshal([]byte(doc), &raw); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	var out struct {
		Zones []ZoneConf `yaml:"zones"`
	}
	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName: "yaml", Result: &out, ZeroFields: true,
	})
	if err != nil {
		t.Fatalf("decoder: %v", err)
	}
	if err := dec.Decode(raw); err != nil {
		t.Fatalf("mapstructure: %v", err)
	}
	return out.Zones
}

func TestZonemdBlockDecodesFromYAML(t *testing.T) {
	zones := decodeZonesYAML(t, `
zones:
   - name:     example.com.
     type:     primary
     options:  [ publish-zonemd ]
     zonemd:
        algorithms: [ 1, 2 ]
        scheme:     1
   - name:     plain.example.
     type:     primary
`)
	if len(zones) != 2 {
		t.Fatalf("expected two zones, got %d", len(zones))
	}

	got := zones[0].Zonemd
	if fmt.Sprint(got.Algorithms) != "[1 2]" {
		t.Errorf("algorithms did not decode: %v", got.Algorithms)
	}
	if got.Scheme != 1 {
		t.Errorf("scheme did not decode: %d", got.Scheme)
	}
	set, err := resolveZonemdConf(got)
	if err != nil {
		t.Fatalf("the decoded block does not resolve: %v", err)
	}
	if set.Scheme != 1 || fmt.Sprint(set.Algorithms) != "[1 2]" {
		t.Errorf("resolved to scheme %d algorithms %v", set.Scheme, set.Algorithms)
	}

	// A zone with no block resolves to the defaults rather than failing.
	set, err = resolveZonemdConf(zones[1].Zonemd)
	if err != nil {
		t.Fatalf("an absent block does not resolve: %v", err)
	}
	if set.Scheme != ZonemdSchemeSimple || fmt.Sprint(set.Algorithms) != "[1]" {
		t.Errorf("an absent block resolved to scheme %d algorithms %v",
			set.Scheme, set.Algorithms)
	}
}

// A template carries the block for a whole class of zones; the generic
// gap-fill in ExpandTemplate is what has to copy it, and a zone that sets its
// own wins.
func TestZonemdBlockIsInheritedFromATemplate(t *testing.T) {
	tmpl := &ZoneConf{
		Name:        "signed-primary",
		Type:        "primary",
		OptionsStrs: []string{"publish-zonemd"},
		Zonemd:      ZonemdConf{Algorithms: []uint8{2}},
	}

	inherited, err := ExpandTemplate(ZoneConf{Name: "a.example.", Template: "signed-primary"},
		tmpl, AppTypeAuth)
	if err != nil {
		t.Fatalf("ExpandTemplate: %v", err)
	}
	if fmt.Sprint(inherited.Zonemd.Algorithms) != "[2]" {
		t.Errorf("the template's zonemd block was not inherited: %+v", inherited.Zonemd)
	}
	if len(inherited.OptionsStrs) != 1 || inherited.OptionsStrs[0] != "publish-zonemd" {
		t.Errorf("the template's option was not inherited: %v", inherited.OptionsStrs)
	}

	own, err := ExpandTemplate(ZoneConf{
		Name: "b.example.", Template: "signed-primary",
		Zonemd: ZonemdConf{Algorithms: []uint8{1}},
	}, tmpl, AppTypeAuth)
	if err != nil {
		t.Fatalf("ExpandTemplate: %v", err)
	}
	if fmt.Sprint(own.Zonemd.Algorithms) != "[1]" {
		t.Errorf("the zone's own zonemd block was overwritten by the template: %+v",
			own.Zonemd)
	}
}

// A block the server cannot make sense of drops the OPTION, not the zone: an
// undigested zone is degraded, an unserved one is down.
func TestBadZonemdBlockDropsTheOptionAndReportsIt(t *testing.T) {
	zd := &ZoneData{ZoneName: "example."}
	zconf := &ZoneConf{
		Name:        "example.",
		Type:        "primary",
		OptionsStrs: []string{"publish-zonemd"},
		Zonemd:      ZonemdConf{Algorithms: []uint8{9}},
	}
	opts := parseZoneOptions(&Config{}, "example.", zconf, zd)

	if opts[OptPublishZonemd] {
		t.Error("an invalid zonemd block still enabled publish-zonemd")
	}
	var found bool
	for _, e := range zd.ErrorList() {
		if e.Type == ConfigError && strings.Contains(e.Msg, "zonemd") {
			found = true
		}
	}
	if !found {
		t.Errorf("the operator is not told why the option was dropped: %+v", zd.ErrorList())
	}
}
