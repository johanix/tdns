package tdns

import (
	"context"
	"strings"
	"testing"

	"github.com/mitchellh/mapstructure"
)

// TestLegacyDynamicAllowedHook_BoolIsConfigError verifies the hard cutover:
// a legacy bool value for dynamiczones.dynamic.allowed fails the decode with
// an error naming the new list syntax, while the list form decodes cleanly.
func TestLegacyDynamicAllowedHook_BoolIsConfigError(t *testing.T) {
	decode := func(raw map[string]interface{}) (DynamicZonesConf, error) {
		var dzc DynamicZonesConf
		dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			TagName:    "yaml",
			Result:     &dzc,
			DecodeHook: legacyDynamicAllowedHook(),
		})
		if err != nil {
			t.Fatalf("NewDecoder: %v", err)
		}
		return dzc, dec.Decode(raw)
	}

	// Legacy bool -> hard error naming the new syntax.
	_, err := decode(map[string]interface{}{
		"dynamic": map[string]interface{}{"allowed": true},
	})
	if err == nil {
		t.Fatal("expected legacy bool allowed: to be a config error")
	}
	if !strings.Contains(err.Error(), "allowed: [secondary]") {
		t.Errorf("error should name the new syntax, got: %v", err)
	}

	// List form decodes.
	dzc, err := decode(map[string]interface{}{
		"dynamic": map[string]interface{}{"allowed": []interface{}{"secondary", "primary"}},
	})
	if err != nil {
		t.Fatalf("list form failed to decode: %v", err)
	}
	if len(dzc.Dynamic.Allowed) != 2 {
		t.Errorf("allowed list = %v, want [secondary primary]", dzc.Dynamic.Allowed)
	}

	// The hook must not touch the catalog blocks' bool allowed:.
	dzc, err = decode(map[string]interface{}{
		"catalog_zones": map[string]interface{}{"allowed": true},
	})
	if err != nil {
		t.Fatalf("catalog_zones bool allowed: must still decode: %v", err)
	}
	if !dzc.CatalogZones.Allowed {
		t.Error("catalog_zones.allowed lost its value")
	}
}

func TestDynamicZonesConfValidate(t *testing.T) {
	var d DynamicZonesConf
	if err := d.Validate(); err != nil {
		t.Errorf("empty allowed list must validate: %v", err)
	}
	d.Dynamic.Allowed = ZoneTypeList{"secondary", "Primary"}
	if err := d.Validate(); err != nil {
		t.Errorf("valid (case-insensitive) values must validate: %v", err)
	}
	d.Dynamic.Allowed = ZoneTypeList{"secondary", "tertiary"}
	if err := d.Validate(); err == nil {
		t.Error("unknown zone type in allowed: must be a config error")
	}
}

func TestDynamicApiZoneConfAllows(t *testing.T) {
	var c DynamicApiZoneConf
	if c.Allows(Primary) || c.Allows(Secondary) {
		t.Error("empty allowed list must deny all")
	}
	c.Allowed = ZoneTypeList{"SECONDARY"}
	if !c.Allows(Secondary) {
		t.Error("allowed match must be case-insensitive")
	}
	if c.Allows(Primary) {
		t.Error("primary must not be allowed by [secondary]")
	}
}

// TestProvisionDynamicZone_TypeGateMatrix drives the per-type allowed: gate
// through the add core: each type is admitted iff listed.
func TestProvisionDynamicZone_TypeGateMatrix(t *testing.T) {
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)

	// allowed: [secondary] -> primary add refused at the gate.
	conf.DynamicZones.Dynamic.Allowed = ZoneTypeList{"secondary"}
	prim := DynamicZoneInput{Name: "gate1.example", Type: Primary, Template: "whatever"}
	if _, err := conf.ProvisionDynamicZone(context.Background(), prim, true); err == nil {
		t.Error("primary add must be refused when allowed: [secondary]")
	}

	// allowed: [primary] -> secondary add refused at the gate.
	conf.DynamicZones.Dynamic.Allowed = ZoneTypeList{"primary"}
	sec := DynamicZoneInput{Name: "gate2.example", Type: Secondary, Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}}}
	if _, err := conf.ProvisionDynamicZone(context.Background(), sec, true); err == nil {
		t.Error("secondary add must be refused when allowed: [primary]")
	}

	// primary allowed but no template -> refused (template REQUIRED in v1).
	noTmpl := DynamicZoneInput{Name: "gate3.example", Type: Primary}
	if _, err := conf.ProvisionDynamicZone(context.Background(), noTmpl, true); err == nil {
		t.Error("primary add without a template must be refused")
	} else if !strings.Contains(err.Error(), "template") {
		t.Errorf("refusal should mention the template requirement, got: %v", err)
	}
}
