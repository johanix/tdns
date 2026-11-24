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

// The conflict policy decides a contest between the zone file and the journal
// of THIS server's changes. A tdns-auth secondary that may not originate content
// makes none, so the parser must not give it a policy: `zone list` showed
// on-conflict-db-wins on every mirror, and a dynamic zone persisted it.
func TestConflictPolicyNotMaterialisedOnPlainAuthSecondary(t *testing.T) {
	withAppType(t, AppTypeAuth)
	zconf := &ZoneConf{Name: "split.example.", Type: "secondary"}
	options := map[ZoneOption]bool{OptAddTransportSignal: true}

	if _, err := activateUpdatePolicy(zconf, options); err != nil {
		t.Fatalf("activateUpdatePolicy: %v", err)
	}
	if options[OptOnConflictDBWins] || options[OptOnConflictZonefileWins] {
		t.Fatalf("a secondary that may not originate content was given a conflict policy: %v", options)
	}
	if !options[OptAddTransportSignal] {
		t.Fatal("an unrelated option was lost")
	}
}

// A dynamic zone's persisted config carries the db-wins the parser used to
// materialise, as if the operator had written it. It is dropped, without the
// origination warning, and it must not come back from the as-configured set.
func TestConflictPolicyPersistedDBWinsDroppedOnPlainAuthSecondary(t *testing.T) {
	withAppType(t, AppTypeAuth)
	zconf := &ZoneConf{Name: "split.example.", Type: "secondary"}
	options := map[ZoneOption]bool{OptOnConflictDBWins: true}

	_, _, suppressed, msg := normalizeOptionsForRole(AppTypeAuth, Secondary, options, "")
	if suppressed[OptOnConflictDBWins] || msg != "" {
		t.Fatalf("db-wins on a secondary drew an origination warning (%q); an older config"+
			" file carries it without the operator having written it", msg)
	}
	if _, err := activateUpdatePolicy(zconf, options); err != nil {
		t.Fatalf("activateUpdatePolicy: %v", err)
	}
	if options[OptOnConflictDBWins] {
		t.Fatal("db-wins stayed on a secondary that may not originate content")
	}
}

// A tdns-agent secondary is a mirror unless its options say otherwise. The
// origination rule does not apply to tdns-agent (every zone MAY originate there),
// so the normalizer leaves it alone and its origination is the options it has.
// Neither a bare secondary nor a proxy (parentsync-proxy and childsync-proxy
// publish nothing into the agent's own copy) has changes to contest a file with.
func TestConflictPolicyNotMaterialisedOnPlainAgentSecondary(t *testing.T) {
	withAppType(t, AppTypeAgent)
	for name, options := range map[string]map[ZoneOption]bool{
		"no options":       {},
		"parentsync-proxy": {OptParentSyncProxy: true},
		"childsync-proxy":  {OptChildSyncProxy: true},
	} {
		zconf := &ZoneConf{Name: "mirror.example.", Type: "secondary"}
		if _, err := activateUpdatePolicy(zconf, options); err != nil {
			t.Fatalf("%s: activateUpdatePolicy: %v", name, err)
		}
		if options[OptOnConflictDBWins] || options[OptOnConflictZonefileWins] {
			t.Errorf("%s: a tdns-agent secondary with no changes of its own was given a conflict policy: %v",
				name, options)
		}
	}
}

// A persisted db-wins on such a secondary is dropped too, quietly: tdns-agent
// has no normalizer to warn about it, and nobody wrote it.
func TestConflictPolicyPersistedDBWinsDroppedOnPlainAgentSecondary(t *testing.T) {
	withAppType(t, AppTypeAgent)
	zconf := &ZoneConf{Name: "mirror.example.", Type: "secondary"}
	options := map[ZoneOption]bool{OptOnConflictDBWins: true, OptParentSyncProxy: true}

	if _, err := activateUpdatePolicy(zconf, options); err != nil {
		t.Fatalf("activateUpdatePolicy: %v", err)
	}
	if options[OptOnConflictDBWins] {
		t.Fatal("db-wins stayed on a tdns-agent secondary with no changes of its own")
	}
	if !options[OptParentSyncProxy] {
		t.Fatal("an unrelated option was lost")
	}
}

// A tdns-agent secondary that DOES change its copy keeps the policy: any
// origination option says it may, as does multi-provider. An explicit
// zonefile-wins is the operator's own choice of policy and is kept, with no
// db-wins beside it.
func TestConflictPolicyKeptOnAgentSecondaryThatChangesItsCopy(t *testing.T) {
	withAppType(t, AppTypeAgent)
	for _, opt := range append([]ZoneOption{OptMultiProvider}, originationOptions...) {
		if !optionsChangeTheZone(AppTypeAgent, Secondary, map[ZoneOption]bool{opt: true}) {
			t.Errorf("%s: an agent secondary carrying it was taken for a mirror", ZoneOptionToString[opt])
		}
	}
	for _, opt := range []ZoneOption{OptMultiProvider, OptAllowUpdates, OptChildSync, OptOnConflictZonefileWins} {
		zconf := &ZoneConf{Name: "example.", Type: "secondary"}
		options := map[ZoneOption]bool{opt: true}
		if _, err := activateUpdatePolicy(zconf, options); err != nil {
			t.Fatalf("%s: activateUpdatePolicy: %v", ZoneOptionToString[opt], err)
		}
		if opt == OptOnConflictZonefileWins {
			if options[OptOnConflictDBWins] || !options[OptOnConflictZonefileWins] {
				t.Errorf("explicit zonefile-wins was not left alone: %v", options)
			}
			continue
		}
		if !options[OptOnConflictDBWins] {
			t.Errorf("%s: db-wins was not materialised: %v", ZoneOptionToString[opt], options)
		}
	}
}

// Every zone that may originate content keeps the materialised default: a
// primary, an inline-signing secondary (the sanctioned exception), and any zone
// of an app the origination rule does not apply to.
func TestConflictPolicyMaterialisedWhereZoneMayOriginate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		app     AppType
		ztype   string
		options map[ZoneOption]bool
	}{
		{"auth primary", AppTypeAuth, "primary", map[ZoneOption]bool{}},
		{"auth inline-signing secondary", AppTypeAuth, "secondary",
			map[ZoneOption]bool{OptInlineSigning: true}},
		// A derived app (the tdns-mp range) may change a zone it holds as a
		// secondary, and nothing in the options says so.
		{"derived app secondary", TdnsAppTypeMax + 1, "secondary", map[ZoneOption]bool{}},
		// Only a zone KNOWN to be a secondary is treated as one.
		{"auth, type unset", AppTypeAuth, "", map[ZoneOption]bool{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withAppType(t, tc.app)
			zconf := &ZoneConf{Name: "example.", Type: tc.ztype}
			if _, err := activateUpdatePolicy(zconf, tc.options); err != nil {
				t.Fatalf("activateUpdatePolicy: %v", err)
			}
			if !tc.options[OptOnConflictDBWins] {
				t.Fatalf("db-wins was not materialised: %v", tc.options)
			}
		})
	}
}

// An explicit zonefile-wins is a real choice, so on a secondary that may not
// originate it is a mistake to say so, and it must not leave a policy behind.
// The normalizer runs before activateUpdatePolicy, exactly as in ParseZones.
func TestConflictPolicyExplicitZonefileWinsStrippedOnPlainAuthSecondary(t *testing.T) {
	withAppType(t, AppTypeAuth)
	zconf := &ZoneConf{Name: "split.example.", Type: "secondary"}
	options := map[ZoneOption]bool{OptOnConflictZonefileWins: true}

	effective, _, suppressed, msg := normalizeOptionsForRole(AppTypeAuth, Secondary, options, "")
	if !suppressed[OptOnConflictZonefileWins] {
		t.Fatal("zonefile-wins was not suppressed on a secondary that may not originate")
	}
	if !strings.Contains(msg, "on-conflict-zonefile-wins") {
		t.Fatalf("the warning does not name the option: %q", msg)
	}
	if _, err := activateUpdatePolicy(zconf, effective); err != nil {
		t.Fatalf("activateUpdatePolicy: %v", err)
	}
	if effective[OptOnConflictDBWins] || effective[OptOnConflictZonefileWins] {
		t.Fatalf("the secondary still has a conflict policy: %v", effective)
	}
	if !options[OptOnConflictZonefileWins] {
		t.Fatal("the caller's map was mutated")
	}
}

// And a zone that may originate keeps an explicit zonefile-wins untouched.
func TestConflictPolicyExplicitZonefileWinsKeptWhereZoneMayOriginate(t *testing.T) {
	withAppType(t, AppTypeAuth)
	for name, tc := range map[string]struct {
		ztype ZoneType
		opts  map[ZoneOption]bool
	}{
		"primary":                  {Primary, map[ZoneOption]bool{OptOnConflictZonefileWins: true}},
		"inline-signing secondary": {Secondary, map[ZoneOption]bool{OptOnConflictZonefileWins: true, OptInlineSigning: true}},
	} {
		_, _, suppressed, msg := normalizeOptionsForRole(AppTypeAuth, tc.ztype, tc.opts, "")
		if suppressed[OptOnConflictZonefileWins] || msg != "" {
			t.Errorf("%s: zonefile-wins was suppressed (%q)", name, msg)
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
