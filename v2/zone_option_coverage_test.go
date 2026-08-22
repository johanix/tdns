package tdns

import (
	"strings"
	"testing"
)

// A zone option lives in two places that have to agree: the string<->enum maps
// in enums.go, and the switch in parseZoneOptions. Adding it to the maps alone
// compiles, passes review, and then falls into the switch's default case at
// runtime -- which does not ignore the option, it puts the ZONE INTO A CONFIG
// ERROR STATE and stops it answering queries.
//
// That has now happened twice on different options, so test the invariant
// rather than each option: every name the maps accept must be handled by the
// switch. An option that is genuinely conditional (inline-signing without a
// policy, a catalog option on a non-catalog zone) is free to reject its zone
// with its OWN message; what must never appear is "unknown config option",
// which means nobody wrote a case at all.
func TestEveryKnownZoneOptionIsHandledByTheSwitch(t *testing.T) {
	// Not every name in the map is an operator's to set. These four are runtime
	// state the server maintains itself -- dynamic_zones.go strips exactly this
	// set when it writes a zone's options back out -- so refusing them from a
	// config file is right, even if "unknown config option" undersells why.
	internal := map[ZoneOption]bool{
		OptDirty: true, OptFrozen: true, OptAutomaticZone: true, OptApiManagedZone: true,
	}
	// And these two are names with no implementation behind them anywhere in
	// the tree. Listing them here keeps the test honest: it is recording that
	// they are unhandled, not claiming they work.
	unimplemented := map[string]bool{"multi-signer": true, "dont-publish-jwk": true}

	for name, opt := range StringToZoneOption {
		if internal[opt] || unimplemented[name] {
			continue
		}
		t.Run(name, func(t *testing.T) {
			zd := &ZoneData{ZoneName: "example."}
			zconf := &ZoneConf{
				Name:        "example.",
				Type:        "primary",
				OptionsStrs: []string{name},
			}

			parseZoneOptions(&Config{}, "example.", zconf, zd)

			for _, e := range zd.ErrorList() {
				if strings.Contains(e.Msg, "unknown config option") {
					t.Fatalf("option %q (enum %d) is in StringToZoneOption but has no case in"+
						" parseZoneOptions, so setting it takes the zone off the air: %q",
						name, opt, e.Msg)
				}
			}
		})
	}
}

// The conflict-resolution pair specifically: these are the only operator
// control the zone-file/journal reconciliation has, and the documented way to
// choose a policy is to name one of them in the zone's options.
func TestConflictOptionsSurviveParsing(t *testing.T) {
	for _, tc := range []struct {
		name string
		want ZoneOption
	}{
		{"on-conflict-db-wins", OptOnConflictDBWins},
		{"on-conflict-zonefile-wins", OptOnConflictZonefileWins},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zd := &ZoneData{ZoneName: "example."}
			zconf := &ZoneConf{
				Name:        "example.",
				Type:        "primary",
				OptionsStrs: []string{tc.name},
			}

			options := parseZoneOptions(&Config{}, "example.", zconf, zd)

			if !options[tc.want] {
				t.Fatalf("parseZoneOptions dropped %q; activateUpdatePolicy runs afterwards and"+
					" would never see it, so the zone would silently resolve conflicts the"+
					" other way", tc.name)
			}
			for _, e := range zd.ErrorList() {
				if e.Type == ConfigError {
					t.Fatalf("setting %q put the zone in a config error state: %q", tc.name, e.Msg)
				}
			}
		})
	}
}
