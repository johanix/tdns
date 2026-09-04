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
	"os"
	"path/filepath"
	"strings"
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
	// The proxy hook rides the same registration; assert both so a partial
	// wiring cannot pass.
	if len(zd.OnZonePreRefresh) == 0 {
		t.Error("no pre-refresh hooks on a provisioned zone")
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
	if len(after.OnZonePreRefresh) == 0 {
		t.Error("modify stripped the pre-refresh hooks")
	}
}

// Exactly once per ZoneData, asserted at a real call site rather than by
// calling the helper twice by hand. The earlier FirstZoneLoad-guarded
// registration in ParseZones could append a second copy: FirstZoneLoad is
// cleared only by a SUCCESSFUL first load, so a zone whose first load failed
// still carried it and the next reload registered again -- every callback then
// running twice per refresh.
func TestStandardRefreshHooksRegisteredExactlyOnce(t *testing.T) {
	withAppType(t, AppTypeAuth)
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)

	// What one registration yields, measured rather than hard-coded, so the
	// test does not need updating when a hook is added.
	ref := &ZoneData{ZoneName: "ref.example."}
	ref.registerStandardRefreshHooks(nil)
	wantPost, wantPre := len(ref.OnZonePostRefresh), len(ref.OnZonePreRefresh)
	if wantPost == 0 || wantPre == 0 {
		t.Fatalf("setup: one registration gave post=%d pre=%d, want both non-zero", wantPost, wantPre)
	}

	in := DynamicZoneInput{
		Name: "once.example", Type: Secondary,
		Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}},
	}
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err != nil {
		t.Fatalf("provision: %v", err)
	}
	// A modify replaces the ZoneData; the replacement must also carry exactly
	// one set, not the old one's plus a fresh one.
	if _, err := conf.ModifyDynamicZone(context.Background(), DynamicZoneInput{
		Name: "once.example", Type: Secondary,
		Primaries: []PeerConf{{Addr: "192.0.2.9:53", Key: NOKEY}},
	}); err != nil {
		t.Fatalf("modify: %v", err)
	}

	zd, ok := Zones.Get("once.example.")
	if !ok {
		t.Fatal("zone gone")
	}
	if got := len(zd.OnZonePostRefresh); got != wantPost {
		t.Errorf("post-refresh hooks = %d, want %d (a duplicate registration runs every callback twice per refresh)", got, wantPost)
	}
	if got := len(zd.OnZonePreRefresh); got != wantPre {
		t.Errorf("pre-refresh hooks = %d, want %d", got, wantPre)
	}
}

// Every Zones.Set in the tree either registers the standard hooks first or
// says why it does not. This is the test that generalizes #500: the bug was
// never about use-hsyncparam, it was that a creation path can be added without
// anyone remembering the hooks, and nothing noticed. A source check is the only
// thing that covers a path that does not exist yet.
//
// It also found two sites the reviews missed -- catalog member creation and
// the dynamic-primary add -- so the exemption markers carry reasons rather
// than just silencing it.
func TestEveryZonesSetRegistersHooksOrSaysWhyNot(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	// Budgeted in CODE lines, not raw lines: the registration and the
	// Zones.Set it guards are routinely separated by a comment explaining
	// one or the other, and a raw-line window would false-fail on a long one
	// while a generous window would stop meaning "adjacent".
	const codeLookback = 8

	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if !strings.Contains(line, "Zones.Set(") {
				continue
			}
			satisfied, code := false, 0
			for j := i - 1; j >= 0 && code < codeLookback; j-- {
				trimmed := strings.TrimSpace(lines[j])
				if strings.Contains(lines[j], "registerStandardRefreshHooks") ||
					strings.Contains(lines[j], "no-refresh-hooks:") {
					satisfied = true
					break
				}
				// Never look past the top of the enclosing function.
				if strings.HasPrefix(lines[j], "func ") {
					break
				}
				if trimmed == "" || strings.HasPrefix(trimmed, "//") {
					continue // comments and blanks are free
				}
				code++
			}
			if satisfied {
				continue
			}
			t.Errorf("%s:%d publishes a zone without registering the standard refresh hooks.\n"+
				"    Call zd.registerStandardRefreshHooks(<delegation-sync queue>) BEFORE this line,\n"+
				"    or, if this Zones.Set republishes an existing ZoneData or a zone that never\n"+
				"    refreshes, mark it with a `// no-refresh-hooks: <reason>` comment.\n"+
				"    %s", f, i+1, strings.TrimSpace(line))
		}
	}
}
