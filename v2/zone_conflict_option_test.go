/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"strings"
	"testing"
)

// TestConflictPolicyDefaultIsMaterialised. The default is not a fallback read
// at each decision point -- the parser SETS it. A code-level default has to be
// remembered everywhere it is asked, and the day one site forgets, a zone
// quietly resolves conflicts the other way.
func TestConflictPolicyDefaultIsMaterialised(t *testing.T) {
	zconf := &ZoneConf{Name: "example."}
	options := map[ZoneOption]bool{}

	if _, err := activateUpdatePolicy(zconf, options); err != nil {
		t.Fatalf("activateUpdatePolicy: %v", err)
	}
	if !options[OptOnConflictDBWins] {
		t.Fatal("db-wins was not set on a zone that named neither option")
	}
	if options[OptOnConflictZonefileWins] {
		t.Fatal("zonefile-wins was set on a zone that did not ask for it")
	}
}

// And an explicit zonefile-wins must not be overwritten by the default.
func TestConflictPolicyExplicitZonefileWinsSurvives(t *testing.T) {
	zconf := &ZoneConf{Name: "example."}
	options := map[ZoneOption]bool{OptOnConflictZonefileWins: true}

	if _, err := activateUpdatePolicy(zconf, options); err != nil {
		t.Fatalf("activateUpdatePolicy: %v", err)
	}
	if options[OptOnConflictDBWins] {
		t.Fatal("the default overwrote an explicit zonefile-wins")
	}
	if !options[OptOnConflictZonefileWins] {
		t.Fatal("explicit zonefile-wins was lost")
	}
}

// Both together is a contradiction, not a preference order.
func TestConflictPolicyBothIsAConfigError(t *testing.T) {
	zconf := &ZoneConf{Name: "example."}
	options := map[ZoneOption]bool{
		OptOnConflictDBWins:       true,
		OptOnConflictZonefileWins: true,
	}

	_, err := activateUpdatePolicy(zconf, options)
	if err == nil {
		t.Fatal("both conflict options together was accepted")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error does not say why: %v", err)
	}
}

// The option names must survive the round trip through the string maps, or a
// config naming them would silently do nothing.
func TestConflictPolicyOptionNamesRoundTrip(t *testing.T) {
	for name, want := range map[string]ZoneOption{
		"on-conflict-db-wins":       OptOnConflictDBWins,
		"on-conflict-zonefile-wins": OptOnConflictZonefileWins,
	} {
		got, ok := StringToZoneOption[name]
		if !ok {
			t.Errorf("%q is not a recognised zone option", name)
			continue
		}
		if got != want {
			t.Errorf("%q maps to %v, want %v", name, got, want)
		}
		if back := ZoneOptionToString[want]; back != name {
			t.Errorf("%v renders as %q, want %q", want, back, name)
		}
	}
}

// TestZoneConflictPolicyReadsTheZone connects the option to the merge.
func TestZoneConflictPolicyReadsTheZone(t *testing.T) {
	zd := &ZoneData{ZoneName: "example.", Options: map[ZoneOption]bool{}}
	if got := zoneConflictPolicy(zd); got != ConflictDBWins {
		t.Fatalf("policy with no options = %v, want db-wins", got)
	}
	zd.Options[OptOnConflictZonefileWins] = true
	if got := zoneConflictPolicy(zd); got != ConflictZonefileWins {
		t.Fatalf("policy = %v, want zonefile-wins", got)
	}
}
