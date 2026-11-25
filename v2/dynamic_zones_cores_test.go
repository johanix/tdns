package tdns

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// newTestConfigForCores builds a minimal Config with a drained RefreshZoneCh so
// the fire-and-forget enqueue in the cores never blocks, and no persistence
// (ConfigFile == "") so AddDynamicZoneToConfig is a no-op. Dynamic provisioning
// is allowed unless overridden.
func newTestConfigForCores(t *testing.T) (*Config, chan ZoneRefresher) {
	t.Helper()
	ch := make(chan ZoneRefresher, 16)
	conf := &Config{}
	conf.Internal.RefreshZoneCh = ch
	conf.DynamicZones.Dynamic.Allowed = ZoneTypeList{"secondary", "primary"}
	// A real (empty-cache) IMR so hostname primaries route through the resolver;
	// literal-IP primaries short-circuit before any lookup.
	conf.Internal.ImrEngine = newTestImr(t)
	return conf, ch
}

// resetZonesForTest clears the global Zones map between cases.
func resetZonesForTest() {
	for item := range Zones.IterBuffered() {
		Zones.Remove(item.Key)
	}
}

func TestProvisionDynamicZone_Gate(t *testing.T) {
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)
	conf.DynamicZones.Dynamic.Allowed = nil

	in := DynamicZoneInput{Name: "gated.example", Type: Secondary, Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}}}
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err == nil {
		t.Fatal("expected add to be refused when dynamic.allowed=false")
	}
	// catalog path (fromAPI=false) is not gated by dynamic.allowed.
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, false); err != nil {
		t.Fatalf("catalog path should not be gated by dynamic.allowed: %v", err)
	}
}

func TestProvisionDynamicZone_RejectsTemplatelessPrimaryAndBadKey(t *testing.T) {
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)

	// type: primary without a template is rejected on the API path (a
	// template is REQUIRED for primaries — the operator-blessed envelope).
	// Template-provisioned primaries are exercised in dynamic_primary_test.go.
	prim := DynamicZoneInput{Name: "prim.example", Type: Primary}
	if _, err := conf.ProvisionDynamicZone(context.Background(), prim, true); err == nil {
		t.Error("expected template-less primary to be rejected on API path")
	}

	// non-NOKEY key is rejected until TSIG keys exist.
	badKey := DynamicZoneInput{Name: "badkey.example", Type: Secondary, Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: "transfer-key"}}}
	if _, err := conf.ProvisionDynamicZone(context.Background(), badKey, true); err == nil {
		t.Error("expected non-NOKEY key to be rejected")
	}
}

func TestProvisionDynamicZone_HostnameNoResolve(t *testing.T) {
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)

	// The empty-cache test IMR cannot resolve a hostname, so a secondary whose
	// only primary is a name resolves to zero addresses and the add is rejected.
	in := DynamicZoneInput{Name: "hn.example", Type: Secondary, Primaries: []PeerConf{{Addr: "ns.unresolvable.invalid", Key: NOKEY}}}
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err == nil {
		t.Fatal("expected add to be rejected when no primary resolves to an address")
	}
	if _, ok := Zones.Get("hn.example."); ok {
		t.Fatal("zone should not be registered when the add is rejected")
	}
}

func TestProvisionDynamicZone_HappyPathAndDuplicate(t *testing.T) {
	resetZonesForTest()
	conf, ch := newTestConfigForCores(t)

	in := DynamicZoneInput{Name: "ok.example", Type: Secondary, Primaries: []PeerConf{{Addr: "192.0.2.1", Key: NOKEY}}}
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err != nil {
		t.Fatalf("happy-path add failed: %v", err)
	}
	zd, ok := Zones.Get("ok.example.")
	if !ok {
		t.Fatal("zone not registered in Zones map")
	}
	if zd.ZoneStore != MapZone {
		t.Errorf("zone store = %v, want MapZone (map-only)", zd.ZoneStore)
	}
	if !zd.Options[OptApiManagedZone] {
		t.Error("API-provisioned zone missing OptApiManagedZone marker")
	}
	if zd.GetStatus() != ZoneStatusPending {
		t.Errorf("fresh add status = %v, want Pending", zd.GetStatus())
	}
	if firstUpstreamAddr(zd.Upstreams) != "192.0.2.1:53" {
		t.Errorf("upstream not normalized: got %q", firstUpstreamAddr(zd.Upstreams))
	}
	// A ZoneRefresher was enqueued.
	select {
	case <-ch:
	default:
		t.Error("expected a ZoneRefresher to be enqueued")
	}

	// Duplicate add is refused.
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err == nil {
		t.Error("expected duplicate add to be refused")
	}
}

func TestRemoveDynamicZone_GuardAndGenerationBump(t *testing.T) {
	resetZonesForTest()
	conf, _ := newTestConfigForCores(t)

	// A static (non-API-managed) zone cannot be deleted here.
	static := &ZoneData{ZoneName: "static.example.", ZoneType: Secondary, Options: map[ZoneOption]bool{}}
	Zones.Set("static.example.", static)
	if _, err := conf.RemoveDynamicZone("static.example", false); err == nil {
		t.Error("expected refusal to delete a non-API-managed zone")
	}

	// An API-managed zone is deleted and its generation bumped.
	in := DynamicZoneInput{Name: "del.example", Type: Secondary, Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}}}
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err != nil {
		t.Fatalf("add failed: %v", err)
	}
	zd, _ := Zones.Get("del.example.")
	gen0 := zd.generation.Load()
	if _, err := conf.RemoveDynamicZone("del.example", false); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if _, ok := Zones.Get("del.example."); ok {
		t.Error("zone still present after delete")
	}
	if zd.generation.Load() != gen0+1 {
		t.Errorf("generation not bumped on delete: got %d, want %d", zd.generation.Load(), gen0+1)
	}

	// Deleting a missing zone errors.
	if _, err := conf.RemoveDynamicZone("nope.example", false); err == nil {
		t.Error("expected error deleting a non-existent zone")
	}
}

func TestModifyDynamicZone_ReplacesAndBumps(t *testing.T) {
	resetZonesForTest()
	conf, ch := newTestConfigForCores(t)

	in := DynamicZoneInput{Name: "mod.example", Type: Secondary, Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}}}
	if _, err := conf.ProvisionDynamicZone(context.Background(), in, true); err != nil {
		t.Fatalf("add failed: %v", err)
	}
	<-ch // drain the add's refresher
	oldZd, _ := Zones.Get("mod.example.")
	gen0 := oldZd.generation.Load()

	// Modify the upstream.
	mod := DynamicZoneInput{Name: "mod.example", Type: Secondary, Primaries: []PeerConf{{Addr: "192.0.2.9:53", Key: NOKEY}}}
	if _, err := conf.ModifyDynamicZone(context.Background(), mod); err != nil {
		t.Fatalf("modify failed: %v", err)
	}
	newZd, _ := Zones.Get("mod.example.")
	if newZd == oldZd {
		t.Error("modify should replace the ZoneData pointer (delete+re-add), not mutate in place")
	}
	if firstUpstreamAddr(newZd.Upstreams) != "192.0.2.9:53" {
		t.Errorf("modify did not apply new upstream: got %q", firstUpstreamAddr(newZd.Upstreams))
	}
	if oldZd.generation.Load() != gen0+1 {
		t.Errorf("old generation not bumped on modify: got %d, want %d", oldZd.generation.Load(), gen0+1)
	}
	if !newZd.Options[OptApiManagedZone] {
		t.Error("modified zone lost OptApiManagedZone marker")
	}
	// A forced refresher was enqueued for the new upstream.
	select {
	case zr := <-ch:
		if !zr.Force {
			t.Error("modify refresher should be Force=true")
		}
	default:
		t.Error("expected a ZoneRefresher enqueued by modify")
	}

	// Modify on a static zone is refused.
	static := &ZoneData{ZoneName: "static2.example.", ZoneType: Secondary, Options: map[ZoneOption]bool{}}
	Zones.Set("static2.example.", static)
	if _, err := conf.ModifyDynamicZone(context.Background(), DynamicZoneInput{Name: "static2.example", Type: Secondary, Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}}}); err == nil {
		t.Error("expected refusal to modify a non-API-managed zone")
	}
}

// A rewrite of the dynamic config that fails only to sync the directory
// after the rename has taken effect: the file in place names the new zone
// and its TSIG key. The add and the modify stand, instead of rolling back
// the zone, the key and a primary's zone file under a file that names
// them. A failure before the rename still rolls back.
func TestAnUnsyncedConfigRewriteKeepsTheAddAndTheModify(t *testing.T) {
	resetZonesForTest()
	t.Cleanup(resetZonesForTest)
	conf, ch := newTestConfigForCores(t)
	conf.Internal.TsigKeyStore = NewTsigKeyStore()
	dir := t.TempDir()
	conf.DynamicZones.ConfigFile = filepath.Join(dir, "dynamic.yaml")
	conf.DynamicZones.ZoneDirectory = dir
	conf.DynamicZones.Dynamic.Storage = "persistent"
	withTestTemplates(t, map[string]ZoneConf{"dyn-test": dynPrimaryTestTemplate(dir)})
	prev := syncDynamicConfigDir
	syncDynamicConfigDir = func(string) error { return errors.New("sync refused by the test") }
	t.Cleanup(func() { syncDynamicConfigDir = prev })

	persisted := func(zone string) *ZoneConf {
		t.Helper()
		cf, err := conf.loadDynamicConfigFile()
		if err != nil {
			t.Fatalf("read the dynamic config: %v", err)
		}
		for i := range cf.Zones {
			if cf.Zones[i].Name == zone {
				return &cf.Zones[i]
			}
		}
		return nil
	}

	const sec, key = "unsynced.example.", "unsynced-key."
	if _, err := conf.ProvisionDynamicZone(context.Background(), DynamicZoneInput{
		Name: sec, Type: Secondary, Primaries: []PeerConf{{Addr: "192.0.2.1:53", Key: NOKEY}},
		TsigName: key, TsigSecret: b64Secret16,
	}, true); err != nil {
		t.Fatalf("add with an unsynced rewrite: %v", err)
	}
	<-ch
	added, ok := Zones.Get(sec)
	if !ok {
		t.Fatal("the add was rolled back")
	}
	if !conf.Internal.TsigKeyStore.Has(key) {
		t.Error("the add's TSIG key was rolled back")
	}
	if persisted(sec) == nil {
		t.Fatal("the dynamic config does not name the added zone")
	}

	if _, err := conf.ModifyDynamicZone(context.Background(), DynamicZoneInput{
		Name: sec, Type: Secondary, Primaries: []PeerConf{{Addr: "192.0.2.9:53", Key: key}},
	}); err != nil {
		t.Fatalf("modify with an unsynced rewrite: %v", err)
	}
	<-ch
	modified, _ := Zones.Get(sec)
	if modified == added || firstUpstreamAddr(modified.Upstreams) != "192.0.2.9:53" {
		t.Errorf("the modify was rolled back: upstream %q", firstUpstreamAddr(modified.Upstreams))
	}
	if zc := persisted(sec); zc == nil || len(zc.Primaries) != 1 || zc.Primaries[0].Addr != "192.0.2.9:53" {
		t.Errorf("the dynamic config does not hold the modify: %+v", zc)
	}

	const prim = "unsynced-primary.example."
	if _, err := conf.ProvisionDynamicZone(context.Background(), DynamicZoneInput{
		Name: prim, Type: Primary, Template: "dyn-test",
	}, true); err != nil {
		t.Fatalf("primary add with an unsynced rewrite: %v", err)
	}
	<-ch
	if _, ok := Zones.Get(prim); !ok {
		t.Error("the primary add was rolled back")
	}
	if _, err := os.Stat(filepath.Join(dir, prim+"zone")); err != nil {
		t.Errorf("the primary's zone file was removed: %v", err)
	}
	if persisted(prim) == nil {
		t.Error("the dynamic config does not name the added primary")
	}

	// Before the rename: the rewrite did not take effect, and the modify
	// is rolled back as before.
	conf.DynamicZones.ConfigFile = filepath.Join(dir, "missing", "dynamic.yaml")
	if _, err := conf.ModifyDynamicZone(context.Background(), DynamicZoneInput{
		Name: sec, Type: Secondary, Primaries: []PeerConf{{Addr: "192.0.2.10:53", Key: key}},
	}); err == nil {
		t.Fatal("a modify whose rewrite failed before the rename succeeded")
	}
	if cur, _ := Zones.Get(sec); cur != modified {
		t.Error("a modify whose rewrite failed before the rename was not rolled back")
	}
}
