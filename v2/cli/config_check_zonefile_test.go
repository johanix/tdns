/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// writeDoubledZone writes a zone file for r1.test. whose delegation's NS
// target is missing its trailing dot.
func writeDoubledZone(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "r1.test.zone")
	if err := os.WriteFile(path, []byte(`$TTL 300
@	IN SOA	ns hostmaster 1 600 600 604800 600
@	IN NS	ns
ns	IN A	192.0.2.53
sub	IN NS	ns1.sub.r1.test
`), 0644); err != nil {
		t.Fatalf("write zone: %v", err)
	}
	return path
}

// config check parses a zone file as the server's loader does: a name whose
// trailing dot is missing fails here too, unless the zone allows doubled
// suffixes (#1009).
func TestConfigCheckRefusesADoubledSuffixAsTheLoaderDoes(t *testing.T) {
	path := writeDoubledZone(t)
	err := parseZonefile(path, "r1.test", false)
	if err == nil || !strings.Contains(err.Error(), "trailing dot is probably missing") {
		t.Errorf("config check passed a file the loader refuses: %v", err)
	}
	if err := parseZonefile(path, "r1.test", true); err != nil {
		t.Errorf("with allow-doubled-suffix the file should parse: %v", err)
	}
}

// The option reaches the zone file check through checkZones, set on the zone
// or inherited from its template.
func TestCheckZonesHonoursAllowDoubledSuffix(t *testing.T) {
	path := writeDoubledZone(t)
	allow := []string{"allow-doubled-suffix"}
	for _, tc := range []struct {
		name      string
		zone      tdns.ZoneConf
		templates []tdns.ZoneConf
		wantFail  bool
	}{
		{"absent", tdns.ZoneConf{Name: "r1.test.", Type: "primary", Zonefile: path}, nil, true},
		{"on the zone", tdns.ZoneConf{Name: "r1.test.", Type: "primary", Zonefile: path, OptionsStrs: allow}, nil, false},
		{"on its template", tdns.ZoneConf{Name: "r1.test.", Type: "primary", Zonefile: path, Template: "t1"},
			[]tdns.ZoneConf{{Name: "t1", OptionsStrs: allow}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tdns.Config{}
			cfg.Zones = []tdns.ZoneConf{tc.zone}
			cfg.Templates = tc.templates
			rep := newCCReport()
			checkZones(cfg, rep, false, "auth")
			var failed, parsed bool
			for _, f := range rep.byGroup["Zones"] {
				failed = failed || (f.level == ccFAIL && strings.Contains(f.msg, "failed to parse"))
				parsed = parsed || strings.Contains(f.msg, "exists and parses")
			}
			if failed != tc.wantFail || parsed == tc.wantFail {
				t.Errorf("parse failure reported %v, success reported %v; want failure %v", failed, parsed, tc.wantFail)
			}
		})
	}
}
