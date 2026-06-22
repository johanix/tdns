package tdns

import "testing"

// P-1: the delegation-sync-proxy zone option round-trips through the
// string<->enum maps and is accepted by the option parser (it must NOT fall
// into parseZoneOptions' default "unknown option" case, which would reject it
// with a config error).

func TestDelSyncProxyOptionMapping(t *testing.T) {
	const name = "delegation-sync-proxy"

	opt, ok := StringToZoneOption[name]
	if !ok {
		t.Fatalf("StringToZoneOption has no entry for %q", name)
	}
	if opt != OptDelSyncProxy {
		t.Fatalf("StringToZoneOption[%q] = %d, want OptDelSyncProxy (%d)", name, opt, OptDelSyncProxy)
	}
	if got := ZoneOptionToString[OptDelSyncProxy]; got != name {
		t.Fatalf("ZoneOptionToString[OptDelSyncProxy] = %q, want %q", got, name)
	}
}

// parseZoneOptions must enable the option (the simple-enable switch case),
// not reject it as unknown. A zone with the option set should come back with
// options[OptDelSyncProxy] == true and no ConfigError recorded for it.
func TestParseZoneOptionsAcceptsDelSyncProxy(t *testing.T) {
	zd := &ZoneData{ZoneName: "child.example."}
	zconf := &ZoneConf{
		Name:        "child.example.",
		Type:        "secondary",
		OptionsStrs: []string{"delegation-sync-proxy"},
	}

	options := parseZoneOptions(nil, "child.example.", zconf, zd)

	if !options[OptDelSyncProxy] {
		t.Fatalf("parseZoneOptions did not enable OptDelSyncProxy; got %v", options)
	}
	for _, e := range zd.ErrorList() {
		if e.Type == ConfigError {
			t.Fatalf("unexpected ConfigError after parsing a valid option: %q", e.Msg)
		}
	}
}
