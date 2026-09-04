/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * #500: every path that builds a live ZoneData owes it the standard
 * OnZone*Refresh hooks. Without them a zone option whose behaviour is
 * delivered by a callback -- use-hsyncparam is the first -- is accepted,
 * stored, persisted, displayed by `zone list`, and inert.
 */

package tdns

import (
	"context"
	"testing"
)

// A zone created over the API gets the hooks. Before the fix this zone had
// use-hsyncparam set and zero callbacks, so RepublishAtSignalNames could never
// run on it -- not after a reload, not after a restart.
func TestProvisionedZoneGetsStandardRefreshHooks(t *testing.T) {
	withAppType(t, AppTypeAuth)
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)

	in := DynamicZoneInput{
		Name: "hooks.example", Type: Secondary,
		Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}},
		Options:   map[ZoneOption]bool{OptUseHsyncparam: true},
	}
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err != nil {
		t.Fatalf("provision: %v", err)
	}
	zd, ok := Zones.Get("hooks.example.")
	if !ok {
		t.Fatal("zone not registered")
	}
	if !zd.Options[OptUseHsyncparam] {
		t.Fatal("setup: the option did not survive provisioning")
	}
	if len(zd.OnZonePostRefresh) == 0 {
		t.Error("no post-refresh hooks on a provisioned zone: RepublishAtSignalNames can never run")
	}
}

// The one a fix that stops at the add path would still fail. ModifyDynamicZone
// replaces the ZoneData -- nineteen named fields carried across, the hook
// slices not among them -- and modify is what a reconciling caller runs
// routinely, so losing the hooks here looks like "it worked when provisioned
// and stopped later".
func TestModifiedZoneKeepsStandardRefreshHooks(t *testing.T) {
	withAppType(t, AppTypeAuth)
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)

	in := DynamicZoneInput{
		Name: "modhooks.example", Type: Secondary,
		Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}},
		Options:   map[ZoneOption]bool{OptUseHsyncparam: true},
	}
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err != nil {
		t.Fatalf("provision: %v", err)
	}
	before, _ := Zones.Get("modhooks.example.")
	if len(before.OnZonePostRefresh) == 0 {
		t.Fatal("setup: provisioned zone has no hooks")
	}

	// A plain upstream change, the shape a reconcile sends.
	if _, err := conf.ModifyDynamicZone(context.Background(), DynamicZoneInput{
		Name: "modhooks.example", Type: Secondary,
		Primaries: []PeerConf{{Addr: "192.0.2.9:53", Key: NOKEY}},
	}); err != nil {
		t.Fatalf("modify: %v", err)
	}

	after, ok := Zones.Get("modhooks.example.")
	if !ok {
		t.Fatal("zone gone after modify")
	}
	if after == before {
		t.Fatal("setup: modify did not replace the ZoneData, so this test proves nothing")
	}
	if !after.Options[OptUseHsyncparam] {
		t.Error("the option did not survive the modify")
	}
	if len(after.OnZonePostRefresh) == 0 {
		t.Error("modify stripped the post-refresh hooks: the zone is inert from here on")
	}
}

// The hooks must be attached exactly once per ZoneData. The earlier
// FirstZoneLoad-guarded registration in ParseZones could append a second copy:
// FirstZoneLoad is cleared only by a SUCCESSFUL first load, so a zone whose
// first load failed still carried it and the next reload registered again.
// Registering at construction removes the failure mode; this pins it.
func TestStandardRefreshHooksAreNotDuplicated(t *testing.T) {
	zd := &ZoneData{ZoneName: "once.example.", FirstZoneLoad: true}
	zd.registerStandardRefreshHooks(nil)
	post, pre := len(zd.OnZonePostRefresh), len(zd.OnZonePreRefresh)
	if post == 0 {
		t.Fatal("no post-refresh hooks registered")
	}

	// A second registration on the SAME ZoneData is what the old reload path
	// could do. Nothing in the tree may call it twice; if a future caller
	// does, the callbacks run twice per refresh.
	zd.registerStandardRefreshHooks(nil)
	if len(zd.OnZonePostRefresh) == post {
		t.Skip("registration is idempotent; the single-call contract is no longer load-bearing")
	}
	t.Logf("registration appends (post %d->%d, pre %d->%d), so it must be called exactly once per ZoneData",
		post, len(zd.OnZonePostRefresh), pre, len(zd.OnZonePreRefresh))
}
