/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */

package tdns

import (
	"strings"
	"testing"
)

// TestDirectOnSecondaryIsRefused: a secondary's content belongs to its primary,
// so direct's edits are overwritten at the next transfer.
func TestDirectOnSecondaryIsRefused(t *testing.T) {
	withAppType(t, AppTypeAuth)
	err := validateDelegationBackendCombination(
		&ZoneConf{Name: "example.", Type: "secondary", DelegationBackend: "direct"},
		map[ZoneOption]bool{OptOnConflictDBWins: true})
	if err == nil {
		t.Fatal("direct on a secondary was accepted")
	}
	if !strings.Contains(err.Error(), "belongs") || !strings.Contains(err.Error(), "db") {
		t.Fatalf("the error does not say why or what to do instead: %v", err)
	}
}

// ...but only for tdns-auth. a derived app such as tdns-mpcombiner edits zones as a secondary, and
// that is its whole job; imposing tdns-auth's invariant on every app that
// embeds this library is how a derived app breaks at its next pin bump.
func TestDirectOnSecondaryIsAllowedForOtherApps(t *testing.T) {
	withAppType(t, AppTypeAgent)
	if err := validateDelegationBackendCombination(
		&ZoneConf{Name: "example.", Type: "secondary", DelegationBackend: "direct"},
		map[ZoneOption]bool{OptOnConflictDBWins: true}); err != nil {
		t.Fatalf("direct on a secondary was refused for a non-auth app: %v", err)
	}
}

// TestPrimaryDBWinsRequiresDirect is the rule proper: db-wins says this
// server's data beats the zone file, a handoff backend says someone else
// authors that file. Both cannot be true.
func TestPrimaryDBWinsRequiresDirect(t *testing.T) {
	for _, backend := range []string{"db", "zonefile-backend"} {
		err := validateDelegationBackendCombination(
			&ZoneConf{Name: "example.", Type: "primary", DelegationBackend: backend},
			map[ZoneOption]bool{OptOnConflictDBWins: true})
		if err == nil {
			t.Fatalf("primary + db-wins + %q was accepted", backend)
		}
		// The error must name BOTH ways out, since either may be what was meant.
		for _, want := range []string{"delegationbackend: direct", "on-conflict-zonefile-wins"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("backend %q: error does not offer %q: %v", backend, want, err)
			}
		}
	}
}

// The same primary is fine once it declares that the file is generated
// elsewhere -- which is the deployment a handoff backend implies.
func TestPrimaryZonefileWinsAllowsAHandoffBackend(t *testing.T) {
	if err := validateDelegationBackendCombination(
		&ZoneConf{Name: "example.", Type: "primary", DelegationBackend: "db"},
		map[ZoneOption]bool{OptOnConflictZonefileWins: true}); err != nil {
		t.Fatalf("primary + zonefile-wins + db was refused: %v", err)
	}
}

// And a primary that owns its own zone is fine with direct under either policy:
// direct writes the file itself, so "the file wins if someone edits it behind
// me" is a legitimate conservative preference, not a contradiction.
func TestPrimaryDirectIsFineUnderEitherPolicy(t *testing.T) {
	for _, opts := range []map[ZoneOption]bool{
		{OptOnConflictDBWins: true},
		{OptOnConflictZonefileWins: true},
	} {
		if err := validateDelegationBackendCombination(
			&ZoneConf{Name: "example.", Type: "primary", DelegationBackend: "direct"}, opts); err != nil {
			t.Fatalf("primary + direct was refused: %v", err)
		}
	}
}

// The agent case, which is the reason the handoff backends exist: a zone this
// instance does not serve as primary, handing approved updates onward.
func TestAgentSecondaryWithHandoffBackendIsFine(t *testing.T) {
	withAppType(t, AppTypeAuth)
	if err := validateDelegationBackendCombination(
		&ZoneConf{Name: "example.", Type: "secondary", DelegationBackend: "db"},
		map[ZoneOption]bool{OptOnConflictDBWins: true, OptAllowChildUpdates: true}); err != nil {
		t.Fatalf("secondary + db was refused: %v", err)
	}
}

// No backend at all is governed by the separate allow-child-updates rule, not
// by this one.
func TestNoBackendIsNotThisRulesProblem(t *testing.T) {
	if err := validateDelegationBackendCombination(
		&ZoneConf{Name: "example.", Type: "primary"},
		map[ZoneOption]bool{OptOnConflictDBWins: true}); err != nil {
		t.Fatalf("a zone with no backend was refused here: %v", err)
	}
}

// TestBackendWithoutChildUpdatesWarns: not an error, but almost always a
// mistake -- the operator believes child updates are on and they are not.
func TestBackendWithoutChildUpdatesWarns(t *testing.T) {
	msg := delegationBackendUnusedWarning(
		&ZoneConf{Name: "example.", Type: "primary", DelegationBackend: "db"},
		map[ZoneOption]bool{})
	if msg == "" {
		t.Fatal("a backend with no allow-child-updates produced no warning")
	}
	if delegationBackendUnusedWarning(
		&ZoneConf{Name: "example.", DelegationBackend: "db"},
		map[ZoneOption]bool{OptAllowChildUpdates: true}) != "" {
		t.Fatal("warned about a backend that is actually used")
	}
}

// TestHandoffContractIsStated. Whether a downstream consumer exists is a
// property of the deployment, not the config, so it cannot be validated -- but
// the consequence can be said out loud.
func TestHandoffContractIsStated(t *testing.T) {
	msg := delegationBackendContract(
		&ZoneConf{Name: "example.", Type: "primary", DelegationBackend: "db"},
		map[ZoneOption]bool{OptAllowChildUpdates: true, OptOnConflictZonefileWins: true})
	if !strings.Contains(msg, "will NOT appear in the served zone") {
		t.Fatalf("the contract line does not state the consequence: %q", msg)
	}
	// direct puts updates straight into the zone, so there is no contract to state.
	if delegationBackendContract(
		&ZoneConf{Name: "example.", Type: "primary", DelegationBackend: "direct"},
		map[ZoneOption]bool{OptAllowChildUpdates: true}) != "" {
		t.Fatal("stated a handoff contract for the direct backend")
	}
}
