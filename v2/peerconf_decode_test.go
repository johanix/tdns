package tdns

import (
	"testing"

	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v3"
)

// TestStringToPeerConfHook_ResilientDecode is the B0a regression guard: a
// config carrying a legacy bare-string primary:/notify: among modern struct
// entries must decode the WHOLE file successfully (no abort), with the legacy
// values captured as PeerConf{Legacy: ...} markers that per-zone validation
// later quarantines — rather than failing the entire decode on the
// string->struct type mismatch. This is the property that keeps a single
// un-migrated zone from taking down every zone (resilient-startup rule).
//
// It exercises the real decode pipeline (yaml.Unmarshal -> map -> mapstructure
// with the DecodeHook), the same one ParseConfig uses. A yaml.Unmarshaler on
// PeerConf would NOT be exercised by this path, which is exactly why the fix is
// a mapstructure decode hook.
func TestStringToPeerConfHook_ResilientDecode(t *testing.T) {
	const cfg = `
zones:
  modern.example.:
    type: secondary
    primary:
      addr: 192.0.2.1:53
      key: NOKEY
  legacy-primary.example.:
    type: secondary
    primary: 192.0.2.2:53
  legacy-notify.example.:
    type: primary
    notify:
      - addr: 192.0.2.3:53
        key: NOKEY
      - 192.0.2.4:53
`

	var raw map[string]interface{}
	if err := yaml.Unmarshal([]byte(cfg), &raw); err != nil {
		t.Fatalf("yaml.Unmarshal failed: %v", err)
	}

	type zonesOnly struct {
		Zones map[string]ZoneConf `yaml:"zones" mapstructure:"zones"`
	}
	var result zonesOnly
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName:    "yaml",
		Result:     &result,
		DecodeHook: stringToPeerConfHook(),
	})
	if err != nil {
		t.Fatalf("NewDecoder failed: %v", err)
	}

	// The whole-file decode must SUCCEED despite the bare-string entries.
	if err := decoder.Decode(raw); err != nil {
		t.Fatalf("decode aborted on legacy bare-string (resilient-startup broken): %v", err)
	}

	// Modern zone: real PeerConf, no Legacy marker.
	mod := result.Zones["modern.example."].Primary
	if mod.Legacy != "" {
		t.Errorf("modern primary wrongly flagged legacy: %+v", mod)
	}
	if mod.Addr != "192.0.2.1:53" || mod.Key != "NOKEY" {
		t.Errorf("modern primary mis-decoded: got %+v", mod)
	}

	// Legacy bare-string primary: captured as a Legacy marker (validation will
	// quarantine this zone to ERROR), Addr/Key empty.
	leg := result.Zones["legacy-primary.example."].Primary
	if leg.Legacy != "192.0.2.2:53" {
		t.Errorf("legacy primary not captured as marker: got %+v", leg)
	}
	if leg.Addr != "" || leg.Key != "" {
		t.Errorf("legacy primary should have empty Addr/Key: got %+v", leg)
	}

	// Notify list with a mixed modern + bare-string element: the hook fires
	// element-wise, so the bare element becomes a Legacy marker while the
	// struct element decodes normally.
	notify := result.Zones["legacy-notify.example."].Notify
	if len(notify) != 2 {
		t.Fatalf("expected 2 notify entries, got %d: %+v", len(notify), notify)
	}
	if notify[0].Addr != "192.0.2.3:53" || notify[0].Key != "NOKEY" || notify[0].Legacy != "" {
		t.Errorf("modern notify element mis-decoded: %+v", notify[0])
	}
	if notify[1].Legacy != "192.0.2.4:53" || notify[1].Addr != "" {
		t.Errorf("legacy notify element not captured as marker: %+v", notify[1])
	}
}
