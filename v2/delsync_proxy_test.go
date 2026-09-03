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
	// New canonical name.
	const canonical = "parentsync-proxy"

	opt, ok := StringToZoneOption[canonical]
	if !ok {
		t.Fatalf("StringToZoneOption has no entry for %q", canonical)
	}
	if opt != OptDelSyncProxy {
		t.Fatalf("StringToZoneOption[%q] = %d, want OptDelSyncProxy (%d)", canonical, opt, OptDelSyncProxy)
	}
	if got := ZoneOptionToString[OptDelSyncProxy]; got != canonical {
		t.Fatalf("ZoneOptionToString[OptDelSyncProxy] = %q, want %q", got, canonical)
	}

	// Deprecated alias must still resolve.
	const deprecated = "delegation-sync-proxy"
	optAlias, ok := StringToZoneOption[deprecated]
	if !ok {
		t.Fatalf("StringToZoneOption has no entry for deprecated alias %q", deprecated)
	}
	if optAlias != OptDelSyncProxy {
		t.Fatalf("StringToZoneOption[%q] (deprecated alias) = %d, want OptDelSyncProxy (%d)", deprecated, optAlias, OptDelSyncProxy)
	}
}

// parseZoneOptions must enable the option (the simple-enable switch case),
// not reject it as unknown. A zone with the option set should come back with
// options[OptDelSyncProxy] == true and no ConfigError recorded for it.
func TestParseZoneOptionsAcceptsDelSyncProxy(t *testing.T) {
	// New canonical name.
	zd := &ZoneData{ZoneName: "child.example."}
	zconf := &ZoneConf{
		Name:        "child.example.",
		Type:        "secondary",
		OptionsStrs: []string{"parentsync-proxy"},
	}

	options := parseZoneOptions(nil, "child.example.", zconf, zd)

	if !options[OptDelSyncProxy] {
		t.Fatalf("parseZoneOptions did not enable OptDelSyncProxy with canonical name; got %v", options)
	}
	for _, e := range zd.ErrorList() {
		if e.Type == ConfigError {
			t.Fatalf("unexpected ConfigError after parsing a valid option: %q", e.Msg)
		}
	}

	// Deprecated alias: still accepted (no ConfigError), but a warning is expected.
	zdAlias := &ZoneData{ZoneName: "child2.example."}
	zconfAlias := &ZoneConf{
		Name:        "child2.example.",
		Type:        "secondary",
		OptionsStrs: []string{"delegation-sync-proxy"},
	}
	optionsAlias := parseZoneOptions(nil, "child2.example.", zconfAlias, zdAlias)
	if !optionsAlias[OptDelSyncProxy] {
		t.Fatalf("parseZoneOptions did not enable OptDelSyncProxy with deprecated alias; got %v", optionsAlias)
	}
	for _, e := range zdAlias.ErrorList() {
		if e.Type == ConfigError {
			t.Fatalf("unexpected ConfigError after parsing deprecated alias: %q", e.Msg)
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

// parentsync and parentsync-proxy are mutually exclusive: one server syncing
// to the parent AS the child and the same server syncing on BEHALF of a
// DSYNC-unaware primary are two different roles, and a zone claiming both has
// no defined behaviour. parseZoneOptions records a ConfigError so the zone is
// quarantined rather than picking one silently (#493).
func TestParseZoneOptionsRefusesParentSyncPlusProxy(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []string
	}{
		{"canonical names", []string{"parentsync", "parentsync-proxy"}},
		{"deprecated spellings", []string{"delegation-sync-child", "delegation-sync-proxy"}},
		{"one of each", []string{"parentsync", "delegation-sync-proxy"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zd := &ZoneData{ZoneName: "child.example."}
			zconf := &ZoneConf{Name: "child.example.", Type: "secondary", OptionsStrs: tc.opts}

			parseZoneOptions(nil, "child.example.", zconf, zd)

			var found bool
			for _, e := range zd.ErrorList() {
				if e.Type == ConfigError {
					found = true
				}
			}
			if !found {
				t.Errorf("no ConfigError for %v; the zone would serve with both roles set", tc.opts)
			}
		})
	}
}

// Each option on its own is fine -- the check must not fire on one of them.
func TestParseZoneOptionsAllowsEitherParentSyncOptionAlone(t *testing.T) {
	for _, opt := range []string{"parentsync", "parentsync-proxy"} {
		t.Run(opt, func(t *testing.T) {
			zd := &ZoneData{ZoneName: "child.example."}
			zconf := &ZoneConf{Name: "child.example.", Type: "secondary", OptionsStrs: []string{opt}}
			parseZoneOptions(nil, "child.example.", zconf, zd)
			for _, e := range zd.ErrorList() {
				if e.Type == ConfigError {
					t.Errorf("unexpected ConfigError for %q alone: %s", opt, e.Msg)
				}
			}
		})
	}
}
