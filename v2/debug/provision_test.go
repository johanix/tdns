package debug

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// TestConfigSnippetIsAZoneList guards the map-vs-list regression: tdns-auth's
// zones: is a LIST of entries each with a `name:` field. Emitting a map keyed
// by zone name instead produced an entry with no name → the zone loaded under
// the apex "." with the right zonefile (the bug seen 2026-07-13).
func TestConfigSnippetIsAZoneList(t *testing.T) {
	const zone = "test001.test.axfr.net."
	snip := configSnippet(zone, "test001", "20s", "/tmp/x/test001.zone")

	var parsed struct {
		Zones []map[string]any `yaml:"zones"`
	}
	if err := yaml.Unmarshal([]byte(snip), &parsed); err != nil {
		t.Fatalf("snippet is not valid YAML: %v\n%s", err, snip)
	}
	if len(parsed.Zones) != 1 {
		t.Fatalf("expected zones: to be a 1-element list, got %d entries (map-key format?)\n%s", len(parsed.Zones), snip)
	}
	if name, _ := parsed.Zones[0]["name"].(string); name != zone {
		t.Fatalf("zone entry name = %q, want %q — the list item needs a `name:` field\n%s", name, zone, snip)
	}
	if got := parsed.Zones[0]["zonefile"]; got != "/tmp/x/test001.zone" {
		t.Errorf("zonefile not carried through: %v", got)
	}
	// update-policy must survive as a nested map, not get flattened.
	if _, ok := parsed.Zones[0]["update-policy"].(map[string]any); !ok {
		t.Errorf("update-policy missing or not a nested map: %v", parsed.Zones[0]["update-policy"])
	}
}
