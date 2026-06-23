package tdns

import (
	"log"
	"os"
	"testing"
)

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

// Regression (CodeRabbit PR #265): SetupZoneSync's wantsSync early-exit must NOT
// skip a proxy-only zone, or the proxy validation gate is unreachable. A proxy
// option on a non-agent / non-secondary zone must be REJECTED (the gate runs);
// on an agent secondary it must be accepted (the gate passes).
func TestSetupZoneSyncProxyGateReachable(t *testing.T) {
	prevApp := Globals.App.Type
	t.Cleanup(func() { Globals.App.Type = prevApp })

	// Wrong app type (auth) with a proxy-only zone: the gate must fire and reject.
	Globals.App.Type = AppTypeAuth
	zdAuth := &ZoneData{
		ZoneName: "child.example.",
		ZoneType: Secondary,
		Options:  map[ZoneOption]bool{OptDelSyncProxy: true},
		Logger:   log.New(os.Stderr, "", 0),
	}
	if err := zdAuth.SetupZoneSync(nil); err == nil {
		t.Fatal("proxy on a non-agent zone must be rejected (gate must be reachable, not skipped by wantsSync)")
	}

	// Wrong zone type (primary) on an agent: rejected.
	Globals.App.Type = AppTypeAgent
	zdPrimary := &ZoneData{
		ZoneName: "child.example.",
		ZoneType: Primary,
		Options:  map[ZoneOption]bool{OptDelSyncProxy: true},
		Logger:   log.New(os.Stderr, "", 0),
	}
	if err := zdPrimary.SetupZoneSync(nil); err == nil {
		t.Fatal("proxy on a primary zone must be rejected")
	}

	// Correct: agent + secondary + proxy-only ⇒ accepted (gate passes, no error).
	zdOK := &ZoneData{
		ZoneName: "child.example.",
		ZoneType: Secondary,
		Options:  map[ZoneOption]bool{OptDelSyncProxy: true},
		Logger:   log.New(os.Stderr, "", 0),
	}
	if err := zdOK.SetupZoneSync(nil); err != nil {
		t.Fatalf("agent secondary proxy zone must be accepted, got: %v", err)
	}
}
