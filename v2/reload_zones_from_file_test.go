/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * Regression test for the reload-zones bug (config.go longstanding "must get the
 * zones config file from outside"): ReloadZoneConfig iterated the stale startup
 * conf.Zones, so a config-file edit to the zone set (add/remove zone, changed
 * dnssecpolicy) needed a restart. reloadZonesFromFile re-reads the zones: block.
 */

package tdns

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReloadZonesFromFile_RereadsAndReplaces(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "tdns-auth.yaml")
	yaml := `zones:
   - name: a.example.
     type: primary
     zonefile: /tmp/a.zone
     dnssecpolicy: polA
   - name: b.example.
     type: secondary
     primaries:
        - { addr: 192.0.2.1:53, key: NOKEY }
`
	if err := os.WriteFile(cfg, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	conf := &Config{}
	conf.Internal.CfgFile = cfg
	// Seed a STALE in-memory zone set to prove the re-read REPLACES it — the whole
	// bug was that ReloadZoneConfig kept using this stale set instead of the file.
	conf.Zones = []ZoneConf{{Name: "stale.example.", Type: "primary"}}

	if err := conf.reloadZonesFromFile(); err != nil {
		t.Fatalf("reloadZonesFromFile: %v", err)
	}

	byName := map[string]ZoneConf{}
	for _, z := range conf.Zones {
		byName[z.Name] = z
	}
	if len(conf.Zones) != 2 {
		t.Fatalf("expected 2 zones from file, got %d: %+v", len(conf.Zones), conf.Zones)
	}
	if _, stale := byName["stale.example."]; stale {
		t.Error("stale in-memory zone survived the re-read (should be replaced by file contents)")
	}
	a, ok := byName["a.example."]
	if !ok {
		t.Fatal("a.example. missing after re-read (add/change not picked up)")
	}
	if a.Type != "primary" || a.DnssecPolicy != "polA" || a.Zonefile != "/tmp/a.zone" {
		t.Errorf("a.example. decoded wrong: type=%q policy=%q zonefile=%q", a.Type, a.DnssecPolicy, a.Zonefile)
	}
	if _, ok := byName["b.example."]; !ok {
		t.Fatal("b.example. (secondary with primaries) missing after re-read")
	}
}
