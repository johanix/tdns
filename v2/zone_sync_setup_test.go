/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 *
 * #1151: a zone created while the server runs gets SetupZoneSync, as a static
 * zone does at its first load. A zone added through the agent's API with
 * parentsync-proxy transferred and proxied transfers, but never got its
 * PROXY-UPDATE-SETUP (the proxy startup reconcile), at the add or after a
 * restart.
 */

package tdns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// countSyncRequests reads q for wait and counts the requests with command cmd
// for zone. It stops early once it has seen want of them; want < 0 never
// stops early.
func countSyncRequests(q chan DelegationSyncRequest, cmd, zone string, want int, wait time.Duration) int {
	n := 0
	deadline := time.After(wait)
	for {
		if want >= 0 && n >= want {
			return n
		}
		select {
		case req := <-q:
			if req.Command == cmd && req.ZoneName == zone {
				n++
			}
		case <-deadline:
			return n
		}
	}
}

// startSyncTestEngine starts a refresh engine on conf and returns the function
// that stops it and removes zone from Zones, which the test also runs at the
// end. What a restart throws away.
func startSyncTestEngine(t *testing.T, conf *Config, zone string) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); RefreshEngine(ctx, conf) }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("RefreshEngine did not shut down")
		}
		if zd, ok := Zones.Get(zone); ok {
			zd.stopPublisher()
			Zones.Remove(zone)
		}
	}
	t.Cleanup(stop)
	return stop
}

// waitLoaded waits for zone to be in Zones and to have published.
func waitLoaded(t *testing.T, zone string) *ZoneData {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if zd, ok := Zones.Get(zone); ok && zd.publishedSnapshot() != nil {
			return zd
		}
		if time.Now().After(deadline) {
			t.Fatalf("zone %s did not load", zone)
		}
	}
}

// refreshAndWait runs the refresh a NOTIFY starts and waits for its answer.
//
// A refresh the engine is still running (the first transfer's, or one a
// NOTIFY started) makes it refuse a second one rather than queue it; that
// is the engine's rule, not a failure, so this asks again until it runs.
func refreshAndWait(t *testing.T, conf *Config, zone string) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		resp := make(chan RefresherResponse, 1)
		conf.Internal.RefreshZoneCh <- ZoneRefresher{Name: zone, ZoneStore: MapZone, Wait: true, Response: resp}
		select {
		case r := <-resp:
			if r.Error && strings.HasPrefix(r.ErrorMsg, "refresh already in progress") {
				time.Sleep(20 * time.Millisecond)
				continue
			}
			if r.Error {
				t.Fatalf("refresh: %s", r.ErrorMsg)
			}
			return
		case <-deadline:
			t.Fatal("the refresh was not answered")
		}
	}
}

// The case #1151 was filed on, from the add through a restart. A tdns-agent
// secondary added through the API with parentsync-proxy and no template gets
// one PROXY-UPDATE-SETUP after its first transfer, and none from the refreshes
// after it. Restarted from the dynamic config file the add wrote, it gets one
// again after its first load, and again only one.
func TestAZoneAddedThroughTheAPIGetsItsSyncSetupAtTheAddAndAfterARestart(t *testing.T) {
	withAppType(t, AppTypeAgent)
	resetZonesForTest()
	t.Cleanup(resetZonesForTest)
	up := startRelayUpstream(t, 1)

	conf, _ := newTestConfigForCores(t)
	conf.Internal.KeyDB = newTestKeyDB(t)
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	q := make(chan DelegationSyncRequest, 64)
	conf.Internal.DelegationSyncQ = q
	dir := t.TempDir()
	conf.DynamicZones.ConfigFile = filepath.Join(dir, "dynamic-zones.yaml")
	conf.DynamicZones.ZoneDirectory = dir
	conf.DynamicZones.Dynamic.Storage = "persistent"

	// The add.
	stop := startSyncTestEngine(t, conf, ovZone)
	in := DynamicZoneInput{
		Name: ovZone, Type: Secondary,
		Primaries: []PeerConf{{Addr: up.addr, Key: NOKEY}},
		Options:   map[ZoneOption]bool{OptParentSyncProxy: true},
	}
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err != nil {
		t.Fatalf("provision: %v", err)
	}
	waitLoaded(t, ovZone)
	if n := countSyncRequests(q, "PROXY-UPDATE-SETUP", ovZone, 1, 5*time.Second); n != 1 {
		t.Fatalf("after the add's first transfer: %d PROXY-UPDATE-SETUP, want 1", n)
	}
	// A refresh that transfers and publishes again runs the post-refresh
	// callbacks again. The setup is not among them a second time.
	up.publish(t, 2)
	refreshAndWait(t, conf, ovZone)
	if n := countSyncRequests(q, "PROXY-UPDATE-SETUP", ovZone, -1, 500*time.Millisecond); n != 0 {
		t.Errorf("a later refresh queued %d more PROXY-UPDATE-SETUP, want 0", n)
	}

	// The restart: the engine and the zone are gone, and the zone comes back
	// from the dynamic config file.
	stop()
	if _, err := os.Stat(conf.DynamicZones.ConfigFile); err != nil {
		t.Fatalf("setup: the add did not persist the zone: %v", err)
	}
	countSyncRequests(q, "", "", -1, 10*time.Millisecond) // drain
	startSyncTestEngine(t, conf, ovZone)
	if err := conf.LoadDynamicZoneFiles(context.Background()); err != nil {
		t.Fatalf("LoadDynamicZoneFiles: %v", err)
	}
	zd := waitLoaded(t, ovZone)
	if !zd.Options[OptParentSyncProxy] {
		t.Fatal("setup: the restored zone lost parentsync-proxy")
	}
	if zd.Template != "" {
		t.Fatalf("setup: the restored zone has template %q, want none", zd.Template)
	}
	if n := countSyncRequests(q, "PROXY-UPDATE-SETUP", ovZone, 1, 5*time.Second); n != 1 {
		t.Fatalf("after the restart's first load: %d PROXY-UPDATE-SETUP, want 1", n)
	}
	up.publish(t, 3)
	refreshAndWait(t, conf, ovZone)
	if n := countSyncRequests(q, "PROXY-UPDATE-SETUP", ovZone, -1, 500*time.Millisecond); n != 0 {
		t.Errorf("a refresh after the restart queued %d more PROXY-UPDATE-SETUP, want 0", n)
	}
}

// The restart path for parentsync, which the template requirement also
// skipped: a dynamic primary without a template (a hand-written entry in the
// dynamic config file) gets its DELEGATION-SYNC-SETUP at its first load, once.
func TestATemplatelessDynamicPrimaryGetsItsParentSyncSetupAtStartup(t *testing.T) {
	authApp(t)
	resetZonesForTest()
	t.Cleanup(resetZonesForTest)
	oldSync := delegationSyncConf.Load()
	delegationSyncConf.Store(&delegationSyncRuntime{ParentSync: ParentSyncConf{Schemes: []string{"update"}}})
	t.Cleanup(func() { delegationSyncConf.Store(oldSync) })

	const zone = "child.p.test."
	dir := t.TempDir()
	zonefile := filepath.Join(dir, "child.p.test.zone")
	zoneText := "child.p.test. 3600 IN SOA ns.child.p.test. hostmaster.child.p.test. 1 7200 1800 604800 7200\n" +
		"child.p.test. 3600 IN NS ns.child.p.test.\n" +
		"ns.child.p.test. 3600 IN A 192.0.2.1\n"
	if err := os.WriteFile(zonefile, []byte(zoneText), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := "zones:\n" +
		"  - name: " + zone + "\n" +
		"    type: primary\n" +
		"    store: map\n" +
		"    zonefile: " + zonefile + "\n" +
		"    options: [parentsync]\n"
	dynCfg := filepath.Join(dir, "dynamic-zones.yaml")
	if err := os.WriteFile(dynCfg, []byte(cfg), 0644); err != nil {
		t.Fatal(err)
	}

	conf, _ := newTestConfigForCores(t)
	conf.Internal.KeyDB = Conf.Internal.KeyDB
	conf.Internal.BumpZoneCh = make(chan BumperData, 1)
	q := make(chan DelegationSyncRequest, 64)
	conf.Internal.DelegationSyncQ = q
	conf.DynamicZones.ConfigFile = dynCfg
	conf.DynamicZones.ZoneDirectory = dir

	startSyncTestEngine(t, conf, zone)
	if err := conf.LoadDynamicZoneFiles(context.Background()); err != nil {
		t.Fatalf("LoadDynamicZoneFiles: %v", err)
	}
	waitLoaded(t, zone)
	if n := countSyncRequests(q, "DELEGATION-SYNC-SETUP", zone, 1, 5*time.Second); n != 1 {
		t.Fatalf("after the first load: %d DELEGATION-SYNC-SETUP, want 1", n)
	}
	if n := countSyncRequests(q, "DELEGATION-SYNC-SETUP", zone, -1, 300*time.Millisecond); n != 0 {
		t.Errorf("%d more DELEGATION-SYNC-SETUP, want 0", n)
	}
}

// A modify builds a new ZoneData. The new one owes the setup for its own
// options; the one it replaced owes nothing, even if its first refresh was
// still in flight and publishes after the modify.
func TestAModifiedZoneOwesItsSyncSetupAndTheReplacedOneDoesNot(t *testing.T) {
	withAppType(t, AppTypeAgent)
	resetZonesForTest()
	t.Cleanup(resetZonesForTest)
	conf, _ := newTestConfigForCores(t)
	q := make(chan DelegationSyncRequest, 16)
	conf.Internal.DelegationSyncQ = q

	in := DynamicZoneInput{
		Name: "mod.p.test", Type: Secondary,
		Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}},
		Options:   map[ZoneOption]bool{OptParentSyncProxy: true},
	}
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err != nil {
		t.Fatalf("provision: %v", err)
	}
	old, _ := Zones.Get("mod.p.test.")
	if _, err := conf.ModifyDynamicZone(context.Background(), DynamicZoneInput{
		Name: "mod.p.test", Type: Secondary,
		Primaries: []PeerConf{{Addr: "192.0.2.9:53", Key: NOKEY}},
		Options:   map[ZoneOption]bool{OptParentSyncProxy: true},
	}); err != nil {
		t.Fatalf("modify: %v", err)
	}
	cur, _ := Zones.Get("mod.p.test.")
	if cur == old {
		t.Fatal("setup: modify did not replace the ZoneData, so this test proves nothing")
	}

	// What a refresh that published runs. The zones are empty, which the
	// standard hooks treat as nothing to do.
	old.runPostRefreshCallbacks(false)
	if n := countSyncRequests(q, "PROXY-UPDATE-SETUP", "mod.p.test.", -1, 300*time.Millisecond); n != 0 {
		t.Errorf("the replaced ZoneData queued %d PROXY-UPDATE-SETUP, want 0", n)
	}
	cur.runPostRefreshCallbacks(false)
	cur.runPostRefreshCallbacks(false)
	if n := countSyncRequests(q, "PROXY-UPDATE-SETUP", "mod.p.test.", -1, 500*time.Millisecond); n != 1 {
		t.Errorf("the modified zone queued %d PROXY-UPDATE-SETUP over two refreshes, want 1", n)
	}
}

// A modify that fails to persist puts the old ZoneData back. If the old zone's
// first refresh published while the replacement was in Zones, its callback
// passed it over. The setup must still be owed, and the rollback dispatches
// it: an unchanged upstream serial would never publish again to run the
// callback. Found by review on #1153.
func TestARolledBackModifyKeepsTheOldZonesSyncSetup(t *testing.T) {
	withAppType(t, AppTypeAgent)
	resetZonesForTest()
	t.Cleanup(resetZonesForTest)
	conf, _ := newTestConfigForCores(t)
	q := make(chan DelegationSyncRequest, 16)
	conf.Internal.DelegationSyncQ = q
	dir := t.TempDir()
	conf.DynamicZones.ConfigFile = filepath.Join(dir, "dynamic-zones.yaml")
	conf.DynamicZones.ZoneDirectory = dir
	conf.DynamicZones.Dynamic.Storage = "persistent"

	const zone = "rb.p.test."
	in := DynamicZoneInput{
		Name: zone, Type: Secondary,
		Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}},
		Options:   map[ZoneOption]bool{OptParentSyncProxy: true},
	}
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err != nil {
		t.Fatalf("provision: %v", err)
	}
	old, _ := Zones.Get(zone)

	// Hold the dynamic config file's lock, so the modify stops at its
	// persist with the replacement in Zones. That is the window.
	dynamicConfigMutex.Lock()
	locked := true
	unlock := func() {
		if locked {
			locked = false
			dynamicConfigMutex.Unlock()
		}
	}
	t.Cleanup(func() {
		unlock()
		dynamicConfigMutex.Lock()
		dynamicConfigBroken = false
		dynamicConfigMutex.Unlock()
	})
	errc := make(chan error, 1)
	go func() {
		_, err := conf.ModifyDynamicZone(context.Background(), DynamicZoneInput{
			Name: zone, Type: Secondary,
			Primaries: []PeerConf{{Addr: "192.0.2.9:53", Key: NOKEY}},
			Options:   map[ZoneOption]bool{OptParentSyncProxy: true},
		})
		errc <- err
	}()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if cur, ok := Zones.Get(zone); ok && cur != old {
			break
		}
		if time.Now().After(deadline) {
			unlock()
			t.Fatal("setup: the modify never put its replacement into Zones")
		}
	}

	// The old zone's first refresh publishes now: a publish makes it Ready and
	// runs its post-refresh callbacks. It is not the zone in Zones, so it gets
	// no setup.
	old.mu.Lock()
	old.Ready = true
	old.mu.Unlock()
	old.runPostRefreshCallbacks(false)
	if n := countSyncRequests(q, "PROXY-UPDATE-SETUP", zone, -1, 300*time.Millisecond); n != 0 {
		t.Fatalf("the replaced ZoneData queued %d PROXY-UPDATE-SETUP while out of Zones, want 0", n)
	}

	// The persist fails, and the modify rolls back.
	dynamicConfigBroken = true
	unlock()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("setup: the modify persisted, so nothing was rolled back")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the modify did not return")
	}
	if cur, _ := Zones.Get(zone); cur != old {
		t.Fatal("setup: the rollback did not put the old ZoneData back")
	}
	if n := countSyncRequests(q, "PROXY-UPDATE-SETUP", zone, 1, 3*time.Second); n != 1 {
		t.Fatalf("after the rollback: %d PROXY-UPDATE-SETUP, want 1", n)
	}
	old.runPostRefreshCallbacks(false)
	if n := countSyncRequests(q, "PROXY-UPDATE-SETUP", zone, -1, 300*time.Millisecond); n != 0 {
		t.Errorf("a later refresh queued %d more PROXY-UPDATE-SETUP, want 0", n)
	}
}

// Every option SetupZoneSync acts on makes the setup owed, on both ways a
// zone first loads; a zone with none of them owes nothing. This is the list
// the run-time paths used to get wrong.
func TestEverySyncOptionMakesTheSetupOwed(t *testing.T) {
	for _, opt := range []ZoneOption{OptChildSync, OptParentSync, OptParentSyncProxy, OptChildSyncProxy} {
		first := &ZoneData{ZoneName: "o.p.test.", FirstZoneLoad: true, Options: map[ZoneOption]bool{opt: true}}
		first.registerZoneSyncSetup(nil)
		if len(first.OnFirstLoad) != 1 || len(first.OnZonePostRefresh) != 0 {
			t.Errorf("%s, first-load zone: %d OnFirstLoad and %d post-refresh callbacks, want 1 and 0",
				ZoneOptionToString[opt], len(first.OnFirstLoad), len(first.OnZonePostRefresh))
		}
		live := &ZoneData{ZoneName: "o.p.test.", Options: map[ZoneOption]bool{opt: true}}
		live.registerZoneSyncSetup(nil)
		if len(live.OnFirstLoad) != 0 || len(live.OnZonePostRefresh) != 1 {
			t.Errorf("%s, zone loaded by a refresh: %d OnFirstLoad and %d post-refresh callbacks, want 0 and 1",
				ZoneOptionToString[opt], len(live.OnFirstLoad), len(live.OnZonePostRefresh))
		}
	}
	none := &ZoneData{ZoneName: "o.p.test.", Options: map[ZoneOption]bool{OptAllowUpdates: true}}
	none.registerZoneSyncSetup(nil)
	none.FirstZoneLoad = true
	none.registerZoneSyncSetup(nil)
	if len(none.OnFirstLoad) != 0 || len(none.OnZonePostRefresh) != 0 || none.zoneSyncSetup != nil {
		t.Errorf("a zone without a sync option got %d OnFirstLoad and %d post-refresh callbacks, want none",
			len(none.OnFirstLoad), len(none.OnZonePostRefresh))
	}
}
